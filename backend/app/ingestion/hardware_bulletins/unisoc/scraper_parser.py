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
import csv
import time
import requests
from bs4 import BeautifulSoup

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
            "CVE ID": g["cve_id"],
            "Title": g["title"],
            "Description": g["description"],
            "Technology Area": g["tech_area"],
            "Vulnerability Type": g["vuln_type"],
            "Access Vector": g["access_vector"],
            "CVSS Rating": g["cvss_rating"],
            "CVSS Score": g["cvss_score"],
            "CVSS String": g["cvss_string"],
            "Affected Chipsets": g["chipsets"],
            "Affected Software Versions": g["sw_versions"],
            "Source URL": url,
        })
    return records


def main():
    session = requests.Session()

    # Warm up: load the listing page first so the WAF sets its acw_tc cookie
    # before we hit the JSON API (the API may reject/redirect cold requests).
    session.get(LISTING_URL, headers=PAGE_HEADERS, timeout=20)

    bulletins = get_bulletin_links(session)
    print(f"Found {len(bulletins)} bulletins across all years")

    all_records = []
    for b in bulletins:
        url = b["url"]
        try:
            recs = parse_bulletin(session, url)
            for r in recs:
                r["Bulletin Date"] = b["create_time"]
            all_records.extend(recs)
            print(f"  [{b['create_time']}] {url}: {len(recs)} CVE record(s)")
        except Exception as e:
            print(f"  ERROR on {url}: {e}")
        time.sleep(1)  # be polite to the server

    out_path = "backend/output/unisoc_cves.csv"
    fieldnames = FIELD_ORDER + ["Bulletin Date", "Source URL"]
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_records)

    print(f"\nSaved {len(all_records)} CVE records to {out_path}")


if __name__ == "__main__":
    main()