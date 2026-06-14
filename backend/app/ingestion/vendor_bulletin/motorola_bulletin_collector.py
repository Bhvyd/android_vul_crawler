from datetime import date, datetime, timezone

import requests

from app.ingestion.vendor_bulletin.common import extract_cves_from_html
from app.ingestion.schemas import RawVendorBulletin


class MotorolaBulletinCollector:
    SOURCE_NAME = "motorola_bulletin"
    VENDOR = "motorola"
    BASE_URL = (
        "https://en-us.support.motorola.com/app/product-security-advisories"
    )

    def fetch_bulletins(self) -> list[RawVendorBulletin]:
        response = requests.get(
            self.BASE_URL,
            timeout=30,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        response.raise_for_status()
        cve_ids = extract_cves_from_html(response.text)
        fetched_at = datetime.now(timezone.utc)

        return [
            RawVendorBulletin(
                vendor=self.VENDOR,
                source_name=self.SOURCE_NAME,
                bulletin_id="motorola-advisories",
                bulletin_date=date.today(),
                bulletin_url=self.BASE_URL,
                cve_ids=cve_ids,
                fetched_at=fetched_at,
                metadata={"page_type": "advisory_list"},
            )
        ]
