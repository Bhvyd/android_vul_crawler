import re
import json
import time
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright

# ---------------------------------------------------
# CONFIG
# ---------------------------------------------------

BASE_URL = "https://docs.qualcomm.com/securitybulletin/{month}-{year}-bulletin.html"

OUTPUT_FILE = "backend/app/ingestion/hardware_bulletins/hardware_output/qualcomm_cves_2.json"

# ---------------------------------------------------
# CLEANING
# ---------------------------------------------------

def clean_text(text):
    if not text:
        return None
    return re.sub(r'\s+', ' ', text).strip()


# ---------------------------------------------------
# PATCH PARSING (ROBUST)
# ---------------------------------------------------

PATCH_PATTERNS = [
    re.compile(r"^(.*?)\s*Patch\*\*\s*(https?://\S+)", re.I),
    re.compile(r"^(.*?)\s*Patch:\s*(https?://\S+)", re.I),
    re.compile(r"^(.*?)\s*-\s*Patch\s*(https?://\S+)", re.I),
]


def parse_chipset_patch(entry):
    entry = entry.strip()

    for p in PATCH_PATTERNS:
        m = p.match(entry)
        if m:
            return m.group(1).strip(), m.group(2).strip()

    return entry, None


# ---------------------------------------------------
# CHIPSET BLOCK NORMALIZER
# ---------------------------------------------------

def normalize_block(text):
    """
    Fix broken cases like:
    WTR6955
    Patch** https://...
    """

    lines = [l.strip() for l in text.split("\n") if l.strip()]
    merged = []

    i = 0
    while i < len(lines):

        if i + 1 < len(lines):
            combined = lines[i] + " " + lines[i + 1]

            if "Patch" in lines[i + 1] or "http" in lines[i + 1]:
                merged.append(combined)
                i += 2
                continue

        merged.append(lines[i])
        i += 1

    return merged


# ---------------------------------------------------
# PARSER
# ---------------------------------------------------

def parse_bulletin(html):

    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(separator="\n")

    chunks = re.split(r'CVE ID', text)

    results = []

    for chunk in chunks[1:]:

        # ---------------- CVE ----------------
        cve = re.search(r'(CVE-\d{4}-\d+)', chunk)
        if not cve:
            continue
        cve_id = cve.group(1)

        # ---------------- TITLE ----------------
        title = None
        t = re.search(r'Title\s+(.+?)\s+(?=Description)', chunk, re.S)
        if t:
            title = clean_text(t.group(1))

        # ---------------- DESCRIPTION ----------------
        desc = None
        d = re.search(r'Description\s+(.+?)\s+(?=Technology Area|Vulnerability Type)', chunk, re.S)
        if d:
            desc = clean_text(d.group(1))

        # ---------------- TYPE ----------------
        vtype = None
        vt = re.search(r'Vulnerability Type\s+(.+?)\s+(?=Access Vector|Security Rating)', chunk, re.S)
        if vt:
            vtype = clean_text(vt.group(1))

        # ---------------- CHIPSETS ----------------
        chip_match = re.search(
            r'Affected Chipsets\*?\s+(.*?)(?=(CVE-\d{4}-\d+)|Open Source|Related|Disclaimer|\Z)',
            chunk,
            re.S
        )

        chipsets = []
        chipset_patches = []

        if chip_match:

            raw = clean_text(chip_match.group(1))

            entries = normalize_block(raw)

            for e in entries:

                chipset, patch = parse_chipset_patch(e)

                if chipset:
                    chipsets.append(chipset)

                if patch:
                    chipset_patches.append({
                        "chipset": chipset,
                        "patch_url": patch
                    })

        # ---------------- OUTPUT ----------------
        results.append({
            "cve_id": cve_id,
            "title": title,
            "description": desc,
            "vulnerability_type": vtype,

            "affected_chipsets": sorted(set(chipsets)),

            # ALWAYS POPULATED (no more empty silently)
            "chipset_patches": chipset_patches
        })

    return results


# ---------------------------------------------------
# SCRAPER
# ---------------------------------------------------

def main():

    months = [
        "january","february","march","april","may","june",
        "july","august","september","october","november","december"
    ]

    years = [2021, 2022, 2023, 2024, 2025, 2026]

    all_data = []

    with sync_playwright() as p:

        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        for year in years:
            for month in months:

                url = BASE_URL.format(month=month, year=year)
                print("Loading:", url)

                try:
                    res = page.goto(url, timeout=30000)

                    if not res or res.status == 404:
                        continue

                    page.wait_for_load_state("networkidle")

                    html = page.content()

                    data = parse_bulletin(html)

                    for d in data:
                        d["bulletin_month"] = month
                        d["bulletin_year"] = year
                        d["bulletin_id"] = f"QSB-{year}-{month[:3].upper()}"

                    all_data.extend(data)

                    print(" ->", len(data), "CVEs")

                except Exception as e:
                    print("ERROR:", e)

                time.sleep(1.5)

        browser.close()

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(all_data, f, indent=2, ensure_ascii=False)

    print("\nSaved:", len(all_data))


if __name__ == "__main__":
    main()