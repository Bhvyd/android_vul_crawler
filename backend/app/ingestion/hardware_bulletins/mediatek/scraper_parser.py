import re
import json
import time
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright

BASE_URL = (
    "https://corp.mediatek.com/"
    "product-security-bulletin/"
    "{month}-{year}"
)

OUTPUT_FILE = "mediatek_cves.json"

MONTHS = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
]

YEARS = [
    2021,
    2022,
    2023,
    2024,
    2025,
    2026,

]


def clean_text(text):

    if not text:
        return None

    return re.sub(
        r"\s+",
        " ",
        text,
    ).strip()


def extract_field(
    text,
    start,
    end_markers,
):

    pattern = (
        rf"{re.escape(start)}\s*(.*?)"
        rf"(?=(?:{'|'.join(map(re.escape, end_markers))})|\Z)"
    )

    match = re.search(
        pattern,
        text,
        re.IGNORECASE | re.DOTALL,
    )

    if not match:
        return None

    return clean_text(
        match.group(1)
    )


def split_values(value):

    if not value:
        return []

    values = re.split(
        r"[,;/\n]",
        value,
    )

    return [
        v.strip()
        for v in values
        if v.strip()
    ]


def parse_bulletin(
    html,
    month,
    year,
    url,
):

    soup = BeautifulSoup(
        html,
        "html.parser",
    )

    results = []

    for table in soup.find_all("table"):

        rows = table.find_all("tr")

        if not rows:
            continue

        record = {}

        for row in rows:

            cols = row.find_all(
                ["td", "th"]
            )

            if len(cols) < 2:
                continue

            key = clean_text(
                cols[0].get_text(
                    " ",
                    strip=True
                )
            )

            value = clean_text(
                cols[1].get_text(
                    " ",
                    strip=True
                )
            )

            record[key] = value

        cve = record.get("CVE")

        if not cve:
            continue

        results.append(
            {
                "bulletin_id":
                    f"MTK-{year}-{month[:3].upper()}",
                "vendor":
                    "MediaTek",
                "bulletin_month":
                    month,
                "bulletin_year":
                    year,
                "bulletin_url":
                    url,

                "cve_id":
                    cve,

                "title":
                    record.get("Title"),

                "severity":
                    record.get("Severity"),

                "vulnerability_type":
                    record.get(
                        "Vulnerability Type"
                    ),

                "cwe":
                    record.get("CWE"),

                "description":
                    record.get(
                        "Description"
                    ),

                "affected_chipsets":
                    split_values(
                        record.get(
                            "Affected Chipsets"
                        )
                    ),

                "affected_software_versions":
                    split_values(
                        record.get(
                            "Affected Software Versions"
                        )
                    ),

                "report_source":
                    record.get(
                        "Report Source"
                    ),
            }
        )

    return results


def main():

    all_cves = []

    print(
        "\nStarting MediaTek Scraper\n"
    )

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

        for year in YEARS:

            print(
                f"\n===== YEAR {year} ====="
            )

            for month in MONTHS:

                url = BASE_URL.format(
                    month=month,
                    year=year,
                )

                print(
                    f"Checking {url}"
                )

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
                            "  Not Found"
                        )

                        continue

                    page.wait_for_load_state(
                        "networkidle"
                    )

                    page.wait_for_timeout(
                        2000
                    )

                    html = page.content()

                    vulnerabilities = (
                        parse_bulletin(
                            html,
                            month,
                            year,
                            url,
                        )
                    )

                    if not vulnerabilities:

                        print(
                            "  No CVEs"
                        )

                        continue

                    all_cves.extend(
                        vulnerabilities
                    )

                    print(
                        f"  {len(vulnerabilities)} CVEs"
                    )

                except Exception as e:

                    print(
                        f"  Error: {e}"
                    )

                time.sleep(1)

        browser.close()

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            all_cves,
            f,
            indent=2,
            ensure_ascii=False,
        )

    print(
        f"\nSaved {len(all_cves)} CVEs"
    )

    unique_cves = {
        x["cve_id"]
        for x in all_cves
    }

    print(
        f"Unique CVEs: {len(unique_cves)}"
    )


if __name__ == "__main__":
    main()