import json
import re
from datetime import datetime, timezone
from typing import Any, Optional

import requests
from bs4 import BeautifulSoup

from pathlib import Path
import sys


# ---------------------------------------------------------
# Import project schema
# ---------------------------------------------------------

INGESTION_ROOT = Path(__file__).resolve().parents[2]

if str(INGESTION_ROOT) not in sys.path:
    sys.path.insert(0, str(INGESTION_ROOT))


from vendors_bulletin.schema.cve import CVERecord


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

OUTPUT_DIR = BASE_DIR / "vendor_bulletins_output"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------
# Google Pixel Bulletin
# ---------------------------------------------------------

BASE_URL = "https://source.android.com/docs/security/bulletin/pixel"


# ---------------------------------------------------------
# Generate bulletin URLs
# ---------------------------------------------------------

def generate_month_urls(start_year: int = 2020) -> list[str]:
    """
    Generate Pixel bulletin URLs.

    2020-2025:
        /pixel/2025-12-01

    2026+:
        /pixel/2026/2026-01-01
    """

    now = datetime.now(timezone.utc)

    urls = []

    for year in range(start_year, now.year + 1):

        for month in range(1, 13):

            if year == now.year and month > now.month:
                break


            date = f"{year}-{month:02d}-01"


            # New format from 2026
            if year >= 2026:
                url = f"{BASE_URL}/{year}/{date}"

            # Old format till 2025
            else:
                url = f"{BASE_URL}/{date}"


            urls.append(url)


    return urls



# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------

def _clean_reference(raw: Optional[str]) -> Optional[str]:

    if not raw:
        return None


    first_line = raw.splitlines()[0].strip()

    first_token = (
        first_line.split()[0]
        if first_line.split()
        else first_line
    )


    return first_token.rstrip("*").strip() or None



def _find_component_heading(table) -> Optional[str]:

    for prev in table.find_all_previous(["h2", "h3"]):

        text = prev.get_text(" ", strip=True)

        if text:
            return text


    return None



# ---------------------------------------------------------
# Parse bulletin HTML
# ---------------------------------------------------------

def extract_cves_with_metadata(html: str) -> list[dict[str, Any]]:

    soup = BeautifulSoup(html, "html.parser")

    results = []


    for table in soup.find_all("table"):

        rows = table.find_all("tr")

        if not rows:
            continue



        header_cells = [
            c.get_text(" ", strip=True).lower()
            for c in rows[0].find_all(["th", "td"])
        ]


        if "cve" not in header_cells:
            continue



        def col_index(*names):

            for name in names:

                if name in header_cells:
                    return header_cells.index(name)

            return None



        idx_ref = col_index("references")
        idx_type = col_index("type")
        idx_sev = col_index("severity")
        idx_aosp = col_index("updated aosp versions")
        idx_component_col = col_index("component")
        idx_subcomponent = col_index("subcomponent")


        component_heading = _find_component_heading(table)



        for row in rows[1:]:

            cols = [
                c.get_text(" ", strip=True)
                for c in row.find_all(["td", "th"])
            ]


            if len(cols) < 2:
                continue



            row_text = " ".join(cols)


            cves = re.findall(
                r"CVE-\d{4}-\d{4,7}",
                row_text
            )


            if not cves:
                continue



            severity = "Unknown"

            if idx_sev is not None and idx_sev < len(cols):

                if cols[idx_sev]:
                    severity = cols[idx_sev].capitalize()



            vulnerability_type = None

            if idx_type is not None and idx_type < len(cols):

                vulnerability_type = (
                    cols[idx_type].upper()
                    if cols[idx_type]
                    else None
                )



            reference = None

            if idx_ref is not None and idx_ref < len(cols):

                reference = _clean_reference(
                    cols[idx_ref]
                )



            subcomponent = None


            if idx_component_col is not None:

                if idx_component_col < len(cols):
                    subcomponent = cols[idx_component_col] or None


            elif idx_subcomponent is not None:

                if idx_subcomponent < len(cols):
                    subcomponent = cols[idx_subcomponent] or None




            aosp_versions = None


            if idx_aosp is not None:

                if idx_aosp < len(cols) and cols[idx_aosp]:

                    aosp_versions = [
                        v.strip()
                        for v in re.split(
                            r"[,\s]+",
                            cols[idx_aosp]
                        )
                        if v.strip()
                    ]



            for cve in cves:

                results.append(
                    {
                        "cve_id": cve,
                        "component": component_heading,
                        "subcomponent": subcomponent,
                        "severity": severity,
                        "reference": reference,
                        "vulnerability_type": vulnerability_type,
                        "aosp_versions": aosp_versions,
                    }
                )



    return results



# ---------------------------------------------------------
# Fetch CVEs
# ---------------------------------------------------------

def fetch_google_cves(start_year: int = 2020) -> list[CVERecord]:

    records = []

    urls = generate_month_urls(start_year)



    for url in urls:

        try:

            response = requests.get(
                url,
                timeout=30,
                headers={
                    "User-Agent": "Mozilla/5.0"
                },
            )


            if response.status_code != 200:

                print(
                    f"Skipping {url}: HTTP {response.status_code}"
                )

                continue



            bulletin_date_str = (
                url.rstrip("/")
                .split("/")[-1]
            )


            bulletin_date_obj = datetime.strptime(
                bulletin_date_str,
                "%Y-%m-%d"
            ).date()



            vulnerabilities = extract_cves_with_metadata(
                response.text
            )



            for vuln in vulnerabilities:

                record = CVERecord(

                    cve_id=vuln["cve_id"],

                    vendor="google",

                    source_name="pixel_bulletin",

                    bulletin_id=(
                        f"google-{bulletin_date_str}"
                    ),

                    bulletin_url=url,

                    bulletin_date=bulletin_date_obj,

                    severity=vuln["severity"],

                    component=vuln["component"],

                    subcomponent=vuln["subcomponent"],

                    reference=vuln["reference"],

                    vulnerability_type=vuln["vulnerability_type"],

                    aosp_versions=vuln["aosp_versions"],

                )


                records.append(record)



            print(
                f"{bulletin_date_str}: "
                f"{len(vulnerabilities)} CVEs"
            )



        except Exception as e:

            print(
                f"Failed {url}: {e}"
            )



    return records



# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

if __name__ == "__main__":


    validated_cves = fetch_google_cves(
        start_year=2021
    )


    print()

    print(
        f"Collected {len(validated_cves)} validated CVE records"
    )


    json_output = [
        record.model_dump(mode="json")
        for record in validated_cves
    ]


    output_filename = (
        OUTPUT_DIR /
        "google.json"
    )


    with open(
        output_filename,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            json_output,
            f,
            indent=4,
            ensure_ascii=False
        )


    print(
        f"Successfully saved validated data to {output_filename}"
    )