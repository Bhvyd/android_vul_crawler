# scraper.py
import json
import re
from datetime import datetime, timezone
from typing import Any

import requests
from bs4 import BeautifulSoup


from vendors_bulletin.schema.cve import CVERecord

BASE_URL = "https://source.android.com/docs/security/bulletin/pixel/"


def generate_month_urls(start_year: int = 2020) -> list[str]:
    now = datetime.now(timezone.utc)
    urls = []

    for year in range(start_year, now.year + 1):
        for month in range(1, 13):
            if year == now.year and month > now.month:
                break

            urls.append(f"{BASE_URL}{year}-{month:02d}-01")

    return urls


def extract_cves_with_metadata(html: str) -> list[dict[str, Any]]:
    soup = BeautifulSoup(html, "html.parser")
    results = []
    tables = soup.find_all("table")

    for table in tables:
        rows = table.find_all("tr")

        for row in rows:
            cols = [
                c.get_text(" ", strip=True) for c in row.find_all(["td", "th"])
            ]

            if len(cols) < 2:
                continue

            row_text = " ".join(cols)
            cves = re.findall(r"CVE-\d{4}-\d{4,7}", row_text)

            if not cves:
                continue

            severity = "Unknown"
            for col in cols:
                value = col.lower()
                if value in {"critical", "high", "moderate", "low"}:
                    severity = col.capitalize()
                    break

            reference = None
            for col in cols:
                if col.startswith("A-"):
                    reference = col
                    break

            vulnerability_type = None
            for col in cols:
                if col.upper() in {"EOP", "RCE", "ID", "DOS", "N/A"}:
                    vulnerability_type = col.upper()
                    break

            subcomponent = cols[0] if cols else None

            for cve in cves:
                results.append(
                    {
                        "cve_id": cve,
                        "severity": severity,
                        "subcomponent": subcomponent,
                        "reference": reference,
                        "vulnerability_type": vulnerability_type,
                    }
                )

    return results


def fetch_google_cves(start_year: int = 2020) -> list[CVERecord]:
    records = []
    urls = generate_month_urls(start_year)

    for url in urls:
        try:
            response = requests.get(
                url,
                timeout=30,
                headers={"User-Agent": "Mozilla/5.0"},
            )

            if response.status_code != 200:
                continue

            bulletin_date_str = url.rstrip("/").split("/")[-1]
            bulletin_date_obj = datetime.strptime(
                bulletin_date_str, "%Y-%m-%d"
            ).date()

            vulnerabilities = extract_cves_with_metadata(response.text)

            for vuln in vulnerabilities:
                # Instantiate and validate using the imported schema
                record = CVERecord(
                    cve_id=vuln["cve_id"],
                    vendor="google",
                    source_name="pixel_bulletin",
                    bulletin_id=f"google-{bulletin_date_str}",
                    bulletin_url=url,
                    bulletin_date=bulletin_date_obj,
                    severity=vuln["severity"],
                    subcomponent=vuln["subcomponent"],
                    reference=vuln["reference"],
                    vulnerability_type=vuln["vulnerability_type"],
                )
                records.append(record)

            print(f"{bulletin_date_str}: {len(vulnerabilities)} CVEs")

        except Exception as e:
            print(f"Failed {url}: {e}")

    return records


if __name__ == "__main__":
    validated_cves = fetch_google_cves(start_year=2021)

    print()
    print(f"Collected {len(validated_cves)} validated CVE records")

    # Serialize using Pydantic's built-in JSON mode compatibility
    json_output = [record.model_dump(mode="json") for record in validated_cves]

    output_filename = "vendors_bulletin/vendor_bulletins_output/google.json"
    with open(output_filename, "w", encoding="utf-8") as f:
        json.dump(json_output, f, indent=4, ensure_ascii=False)

    print(f"Successfully saved validated data to {output_filename}")