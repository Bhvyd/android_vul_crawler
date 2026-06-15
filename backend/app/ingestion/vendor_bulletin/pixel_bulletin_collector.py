import re
from datetime import datetime, timezone
from bs4 import BeautifulSoup
import requests

from app.ingestion.vendor_bulletin.common import (
    CVE_REGEX,
    extract_cves_from_html,
)
from app.ingestion.schemas import RawVendorBulletin


class GoogleBulletinCollector:
    SOURCE_NAME = "pixel_bulletin"
    VENDOR = "google"
    BASE_URL = "https://source.android.com/docs/security/bulletin/pixel/"

    def generate_month_urls(self, start_year: int = 2020) -> list[str]:
        now = datetime.now(timezone.utc)
        urls = []

        for year in range(start_year, now.year + 1):
            for month in range(1, 13):
                if year == now.year and month > now.month:
                    break

                urls.append(
                    f"{self.BASE_URL}{year}-{month:02d}-01"
                )

        return urls

    def extract_cves_from_page(self, html: str) -> set[str]:
        return set(extract_cves_from_html(html))

    def extract_cves_with_severity(self, html: str) -> dict[str, str]:
        """
        Parses HTML tables to map CVE IDs to their recorded severity.
        Returns mapping: {CVE_ID: severity}
        """
        soup = BeautifulSoup(html, "html.parser")
        cve_severity_map = {}

        # Google bulletins present vulnerability details in tables
        tables = soup.find_all("table")

        for table in tables:
            rows = table.find_all("tr")

            for row in rows:
                cols = row.find_all(["td", "th"])
                text = [c.get_text(strip=True) for c in cols]

                if len(text) < 2:
                    continue

                # Find all CVEs in the row text
                cves = re.findall(r"CVE-\d{4}-\d{4,7}", " ".join(text))
                if not cves:
                    continue

                # Detect severity keyword in the row text columns
                severity = None
                for t in text:
                    if t.lower() in {"critical", "high", "moderate", "low"}:
                        severity = t.capitalize()
                        break

                if severity is None:
                    severity = "Unknown"

                for cve in cves:
                    cve_severity_map[cve] = severity

        return cve_severity_map

    def fetch_bulletins(
        self,
        months: list[str] | None = None,
        start_year: int = 2020,
    ) -> list[RawVendorBulletin]:

        fetched_at = datetime.now(timezone.utc)
        bulletins: list[RawVendorBulletin] = []

        if months:
            urls = [
                self.BASE_URL + m
                if not m.startswith("http")
                else m
                for m in months
            ]
        else:
            urls = self.generate_month_urls(start_year)

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

                bulletin_date = datetime.strptime(
                    bulletin_date_str,
                    "%Y-%m-%d",
                ).date()

                # Extract CVEs along with their respective severities
                cve_severity_map = self.extract_cves_with_severity(response.text)

                if not cve_severity_map:
                    continue

                cve_ids = sorted(cve_severity_map.keys())

                bulletins.append(
                    RawVendorBulletin(
                        vendor=self.VENDOR,
                        source_name=self.SOURCE_NAME,
                        bulletin_id=f"google-{bulletin_date_str}",
                        bulletin_date=bulletin_date,
                        bulletin_url=url,
                        cve_ids=cve_ids,
                        fetched_at=fetched_at,
                        metadata={
                            "month": bulletin_date_str,
                            "cve_severity_map": cve_severity_map,
                            "severity_counts": {
                                "Critical": sum(1 for s in cve_severity_map.values() if s == "Critical"),
                                "High": sum(1 for s in cve_severity_map.values() if s == "High"),
                                "Moderate": sum(1 for s in cve_severity_map.values() if s == "Moderate"),
                                "Low": sum(1 for s in cve_severity_map.values() if s == "Low"),
                                "Unknown": sum(1 for s in cve_severity_map.values() if s == "Unknown"),
                            }
                        },
                    )
                )

            except Exception:
                continue

        return bulletins