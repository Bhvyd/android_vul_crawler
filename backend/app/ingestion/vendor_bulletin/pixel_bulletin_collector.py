import requests
from datetime import datetime, timezone

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

                cve_ids = sorted(
                    self.extract_cves_from_page(response.text)
                )

                if not cve_ids:
                    continue

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
                        },
                    )
                )

            except Exception:
                continue

        return bulletins