"""
Unisoc Security Bulletin Scraper
---------------------------------
Pulls the full bulletin list from Unisoc's internal JSON API
(/oweb/front/version/list), then fetches each bulletin detail page
(server-rendered HTML) and extracts per-CVE fields into a CSV.

Run with:  python3 scrape_unisoc.py
Requires:  pip install requests beautifulsoup4
"""

import re
import json
import time
import requests
from bs4 import BeautifulSoup
from pathlib import Path
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

BASE = "https://www.unisoc.com"
LISTING_URL = f"{BASE}/en/support/product-security-bulletin"
VERSION_LIST_URL = f"{BASE}/oweb/front/version/list"

# Headers for normal page loads (used to warm up the session / get cookies,
# e.g. the acw_tc anti-bot cookie set by Unisoc's WAF).
PAGE_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    )
}

# Headers for the JSON API calls, mirroring what the browser sent.
# Accept-Encoding deliberately excludes "br" (brotli) to avoid needing the
# optional `brotli` package -- gzip/deflate is enough.
API_HEADERS = {
    "Accept": "application/json, text/plain, */*",
    "Accept-Encoding": "gzip, deflate",
    "Referer": LISTING_URL,
    "User-Agent": PAGE_HEADERS["User-Agent"],
    "X-Requested-With": "XMLHttpRequest",
}

def create_session():

    retry = Retry(
        total=5,
        connect=5,
        read=5,
        backoff_factor=2,
        status_forcelist=[
            429,
            500,
            502,
            503,
            504
        ],
        allowed_methods=["GET"]
    )

    adapter = HTTPAdapter(
        max_retries=retry,
        pool_connections=20,
        pool_maxsize=20
    )

    session = requests.Session()

    session.mount(
        "https://",
        adapter
    )

    session.mount(
        "http://",
        adapter
    )

    return session
FIELD_ORDER = [
    "CVE ID", "Title", "Description", "Technology Area",
    "Vulnerability Type", "Access Vector", "CVSS Rating",
    "CVSS Score", "CVSS String", "Affected Chipsets",
    "Affected Software Versions",
]

RECORD_PATTERN = re.compile(
    r"CVE ID\s*(?P<cve_id>CVE-\d{4}-\d+)\s*"
    r"Title\s*(?P<title>.*?)\s*"
    r"Description\s*(?P<description>.*?)\s*"
    r"Technology Area\s*(?P<tech_area>.*?)\s*"
    r"Vulnerability Type\s*(?P<vuln_type>.*?)\s*"
    r"Access Vector\s*(?P<access_vector>.*?)\s*"
    r"CVSS Rating\s*(?P<cvss_rating>.*?)\s*"
    r"CVSS Score\s*(?P<cvss_score>.*?)\s*"
    r"CVSS String\s*(?P<cvss_string>.*?)\s*"
    r"Affected Chipsets\*?\s*(?P<chipsets>.*?)\s*"
    r"Affected Software Versions\s*(?P<sw_versions>.*?)"
    r"(?=\s*CVE ID|\s*\*The list|\s*Vulnerability type definition|$)",
    re.DOTALL,
)


def get_bulletin_links(session):
    """Pull every bulletin's id/title/date from the version-list API and
    build its detail page URL. Paginates through all years automatically."""
    bulletins = []
    page_index = 1
    while True:
        resp = session.get(
            VERSION_LIST_URL,
            params={"page_index": page_index, "page_size": 10},
            headers=API_HEADERS,
            timeout=20,
        )
        resp.raise_for_status()
        payload = resp.json()

        if payload.get("code") != "200000":
            raise RuntimeError(f"API returned non-success code: {payload}")

        data = payload.get("data", {})
        for year_block in data.get("records", []):
            for v in year_block.get("versions", []):
                bulletin_id = v["id"]
                bulletins.append({
                    "id": bulletin_id,
                    "title": v.get("title"),
                    "create_time": v.get("create_time"),
                    "url": f"{BASE}/en/support/product-security-bulletin/{bulletin_id}",
                })

        pages = data.get("pages", 1)
        if page_index >= pages:
            break
        page_index += 1
        time.sleep(0.5)

    return bulletins


def parse_bulletin(session, url):
    """Fetch one bulletin page and extract a list of per-CVE field dicts."""
    resp = session.get(url, headers=PAGE_HEADERS, timeout=20)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")

    for tag in soup.find_all(["nav", "footer", "script", "style"]):
        tag.decompose()

    text = soup.get_text(" ", strip=True)
    flat = re.sub(r"\s+", " ", text).strip()

    records = []
    for m in RECORD_PATTERN.finditer(flat):
        g = m.groupdict()
        records.append({
            "cve_id": g["cve_id"],
            "title": g["title"],
            "description": g["description"],
            "technology_area": g["tech_area"],
            "vulnerability_type": g["vuln_type"],
            "access_vector": g["access_vector"],
            "cvss_rating": g["cvss_rating"],
            "cvss_score": g["cvss_score"],
            "cvss_string": g["cvss_string"],
            "affected_chipsets": g["chipsets"],
            "affected_software_versions": g["sw_versions"],
            "source_url": url,
        })
    return records


def main():
    session = create_session()

    # Warm up: load the listing page first so the WAF sets its acw_tc cookie
    # before we hit the JSON API (the API may reject/redirect cold requests).
    session.get(LISTING_URL, headers=PAGE_HEADERS, timeout=20)

    bulletins = get_bulletin_links(session)
    seen = set()
    unique_bulletins = []

    for b in bulletins:

        if b["url"] in seen:
            continue

        seen.add(
            b["url"]
        )

        unique_bulletins.append(
            b
        )

    bulletins = unique_bulletins

    print(
        f"Found {len(bulletins)} unique bulletins across all years"
    )
    print(f"Found {len(bulletins)} bulletins across all years")

    all_records = []
    for b in bulletins:
        url = b["url"]
        try:
            recs = parse_bulletin(session, url)
            for r in recs:
                r["bulletin_date"] = b["create_time"]
            all_records.extend(recs)
            print(f"  [{b['create_time']}] {url}: {len(recs)} CVE record(s)")
        except Exception as e:
            print(f"  ERROR on {url}: {e}")
        time.sleep(1)  # be polite to the server

        output_dir = Path(
        "backend/app/ingestion/hardware_bulletins/hardware_output"
    )

    output_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    out_path = (
        output_dir /
        "unisoc_cves.json"
    )

    with open(
        out_path,
        "w",
        encoding="utf-8"
    ) as f:
     json.dump(all_records, f, indent=4, ensure_ascii=False)
     print(f"\nSaved {len(all_records)} CVE records to {out_path}")


if __name__ == "__main__":
    main()