import re
import json
import time
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright

# Configuration
BASE_URL = "https://docs.qualcomm.com/securitybulletin/{month}-{year}-bulletin.html"
OUTPUT_FILE = "qualcomm_cves.json"

def clean_extracted_text(text):
    """Collapses multi-line text blocks and strips redundant whitespaces."""
    if not text:
        return None
    cleaned = re.sub(r'\s+', ' ', text)
    return cleaned.strip()

def parse_bulletin_html(html_content):
    """Parses the rendered HTML text using structural string boundaries."""
    soup = BeautifulSoup(html_content, "html.parser")
    page_text = soup.get_text(separator="\n")
    
    # Split the document on the label 'CVE ID' to isolate individual entries
    chunks = re.split(r'CVE ID', page_text)
    bulletin_data = []

    for chunk in chunks[1:]:
        # 1. Extract CVE ID
        cve_id_match = re.search(r'(CVE-\d{4}-\d+)', chunk)
        if not cve_id_match:
            continue
        cve_id = cve_id_match.group(1)

        # 2. Extract Title (Look up until 'Description')
        title_match = re.search(r'Title\s+(.+?)\s+(?=Description)', chunk, re.DOTALL | re.IGNORECASE)
        title = clean_extracted_text(title_match.group(1)) if title_match else None

        # 3. Extract Description (Look up until 'Technology Area' or 'Vulnerability Type')
        desc_match = re.search(r'Description\s+(.+?)\s+(?=Technology Area|Vulnerability Type)', chunk, re.DOTALL | re.IGNORECASE)
        description = clean_extracted_text(desc_match.group(1)) if desc_match else None

        # 4. Extract Vulnerability Type (Look up until 'Access Vector' or 'Security Rating')
        type_match = re.search(r'Vulnerability Type\s+(.+?)\s+(?=Access Vector|Security Rating)', chunk, re.DOTALL | re.IGNORECASE)
        vuln_type = clean_extracted_text(type_match.group(1)) if type_match else None

        # 5. Extract Affected Chipsets 
        chip_match = re.search(r'Affected Chipsets\*?\s+(.*?)(?=(?:CVE-\d{4}-\d+)|Open Source|Related|Disclaimer|\Z)', chunk, re.DOTALL | re.IGNORECASE)
        
        chipset_list = []
        if chip_match:
            raw_chips = clean_extracted_text(chip_match.group(1))
            chipset_list = [c.strip() for c in raw_chips.split(',') if c.strip()]

        bulletin_data.append({
            "cve_id": cve_id,
            "title": title,
            "description": description,
            "vulnerability_type": vuln_type,
            "affected_chipsets": chipset_list
        })

    return bulletin_data

def main():

    months = [
        "january",
        "february",
        "march",
        "april",
        "may",
        "june",
        "july",
        "august",
        "september",
        "october",
        "november",
        "december",
    ]

    years = [
        2021,
        2022,
        2023,
        2024,
        2025,
    ]

    all_vulnerabilities = []

    print("Starting Qualcomm Scraper...\n")

    with sync_playwright() as p:

        browser = p.chromium.launch(
            headless=True
        )

        context = browser.new_context(
            viewport={
                "width": 1280,
                "height": 800,
            }
        )

        page = context.new_page()

        for year in years:

            print(f"\n===== YEAR {year} =====")

            for month in months:

                url = BASE_URL.format(
                    month=month,
                    year=year,
                )

                print(f"Loading: {url}")

                try:

                    response = page.goto(
                        url,
                        timeout=30000,
                    )

                    if (
                        not response
                        or response.status == 404
                    ):
                        print(
                            f" -> [404] {month}-{year}"
                        )
                        continue

                    page.wait_for_load_state(
                        "networkidle"
                    )

                    page.wait_for_timeout(
                        3000
                    )

                    rendered_html = (
                        page.content()
                    )

                    vulnerabilities = (
                        parse_bulletin_html(
                            rendered_html
                        )
                    )

                    if not vulnerabilities:

                        print(
                            f" -> 0 CVEs"
                        )
                        continue

                    for vuln in vulnerabilities:

                        vuln[
                            "bulletin_month"
                        ] = month.capitalize()

                        vuln[
                            "bulletin_year"
                        ] = year

                        vuln[
                            "bulletin_id"
                        ] = (
                            f"QSB-{year}-{month[:3].upper()}"
                        )

                    all_vulnerabilities.extend(
                        vulnerabilities
                    )

                    print(
                        f" -> {len(vulnerabilities)} CVEs"
                    )

                except Exception as e:

                    print(
                        f" -> ERROR: {e}"
                    )

                time.sleep(1.5)

        browser.close()

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            all_vulnerabilities,
            f,
            indent=4,
            ensure_ascii=False,
        )

    print(
        f"\nSaved {len(all_vulnerabilities)} CVEs"
    )
if __name__ == "__main__":
    main()