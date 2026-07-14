import re
import json
import time
from pathlib import Path
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright

# ---------------------------------------------------
# CONFIG
# ---------------------------------------------------

BASE_URL = "https://docs.qualcomm.com/securitybulletin/{month}-{year}-bulletin.html"

REPO_ROOT = Path(__file__).resolve().parents[5]
OUTPUT_FILE = REPO_ROOT / "backend" / "app" / "ingestion" / "hardware_bulletins" / "hardware_output" / "qualcomm_cves_2.json"

# ---------------------------------------------------
# CLEANING
# ---------------------------------------------------

def clean_text(text):
    if not text:
        return None
    return re.sub(r'\s+', ' ', text).strip()


# ---------------------------------------------------
# CHIPSET / PATCH PARSING (FIXED)
# ---------------------------------------------------
#
# The previous implementation merged a chipset line with the *next* line
# whenever that next line contained "Patch"/"http", then treated the whole
# merged string (e.g. "WCD9340, WCD9341, WCD9360 Patch** https://...") as a
# SINGLE chipset name. That silently glued multiple real chipsets into one
# fake entry and broke the 1:1 relationship between `affected_chipsets` and
# `chipset_patches`. It also couldn't handle a chipset list wrapping across
# more than two lines.
#
# Fix: normalize the whole section into one string, then scan for every
# "Patch** <url>" / "Patch: <url>" marker. Everything since the previous
# marker (or the start) is the comma-separated list of chipsets that share
# that patch URL. Each chipset name is emitted individually.

PATCH_MARKER_RE = re.compile(
    r'(.*?)(?:Patch\*\*|Patch:|-\s*Patch)\s*(https?://\S+)',
    re.S | re.I
)

# separators seen between individual chipset names inside a group
NAME_SPLIT_RE = re.compile(r',|\band\b|;', re.I)

# Qualcomm bulletins often append a disclaimer footnote after the real
# chipset list, e.g.:
#   "... WTR3925 *The list of affected chipsets may not be complete.
#    For the latest information, device OEMs can contact QTI directly
#    at https://www.qualcomm.com/support ."
# Without stripping this, the footnote sentence gets comma-split and
# treated as extra "chipset" entries. This regex trims everything from
# the "*The list of affected chipsets..." marker onward.
DISCLAIMER_RE = re.compile(
    r'\*?\s*The list of affected chipsets.*$',
    re.I | re.S
)

# Fallback safety net: if a disclaimer shows up with different wording in
# other bulletin years, drop any split "name" that clearly isn't a chipset
# code (i.e. it's disclaimer/contact-info prose instead).
FOOTNOTE_KEYWORD_RE = re.compile(
    r'(may not be complete|for the latest information|device oems|'
    r'please contact|contact qti|qualcomm\.com/support)',
    re.I
)


def _split_chipset_names(blob):
    names = []
    for piece in NAME_SPLIT_RE.split(blob):
        name = piece.strip(" -\u2022\t\n")
        if name and not FOOTNOTE_KEYWORD_RE.search(name):
            names.append(name)
    return names


def parse_chipset_section(raw):
    """
    raw: cleaned text of the 'Affected Chipsets' section for one CVE.
    Returns (chipsets: list[str], chipset_patches: list[{"chipset","patch_url"}]).
    """
    if not raw:
        return [], []

    # Drop trailing "list may not be complete / contact QTI" disclaimers
    # before any splitting happens, so they never get treated as chipsets.
    raw = DISCLAIMER_RE.sub('', raw).strip()
    if not raw:
        return [], []

    chipsets = []
    chipset_patches = []
    last_end = 0

    for m in PATCH_MARKER_RE.finditer(raw):
        group_text = m.group(1)
        patch_url = m.group(2).strip().rstrip('.,);')

        for name in _split_chipset_names(group_text):
            chipsets.append(name)
            chipset_patches.append({
                "chipset": name,
                "patch_url": patch_url
            })

        last_end = m.end()

    # Any chipsets listed after the last patch URL (no patch link given)
    remainder = raw[last_end:].strip(" -\u2022\t\n,")
    if remainder and not remainder.lower().startswith('http'):
        for name in _split_chipset_names(remainder):
            if not re.match(r'^https?://', name, re.I):
                chipsets.append(name)

    return chipsets, chipset_patches


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
            chipsets, chipset_patches = parse_chipset_section(raw)

        # ---------------- OUTPUT ----------------
        results.append({
            "cve_id": cve_id,
            "title": title,
            "description": desc,
            "vulnerability_type": vtype,

            # de-duplicated but order-preserving-ish (sorted for stability)
            "affected_chipsets": sorted(set(chipsets)),

            # ALWAYS POPULATED (no more empty silently), one entry per chipset
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

    years = [2021,2022,2023,2024, 2025, 2026]

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

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(all_data, f, indent=2, ensure_ascii=False)

    print("\nSaved:", len(all_data), "to", OUTPUT_FILE)


if __name__ == "__main__":
    main()