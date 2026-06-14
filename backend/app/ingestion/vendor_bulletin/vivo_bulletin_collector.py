import requests
from datetime import date, datetime, timezone
from urllib.parse import urljoin

from app.ingestion.vendor_bulletin.common import (
    CVE_REGEX,
    extract_cves_from_html,
)
from app.ingestion.schemas import RawVendorBulletin


class VivoBulletinCollector:
    SOURCE_NAME = "vivo_bulletin"
    VENDOR = "vivo"

    LIST_URL = "https://www.vivo.com/en/support/security-advisory-list"
    API_URL = "https://www.vivo.com/en/support/safeNoticePage"
    BASE_URL = "https://www.vivo.com"

    PAGE_SIZE = 20

    def _fetch_all_advisory_ids(
        self,
        headers: dict,
        max_advisories: int | None = None,
    ) -> list[str]:
        """
        Fetch all advisory IDs from Vivo's paginated API.
        """

        all_ids: list[str] = []
        page = 1

        while True:
            response = requests.get(
                self.API_URL,
                params={
                    "pageNum": page,
                    "pageSize": self.PAGE_SIZE,
                },
                headers=headers,
                timeout=30,
            )

            response.raise_for_status()

            try:
                data = response.json()
            except Exception:
                break

            payload = data.get("data", {})
            items = payload.get("commSafeNotices", [])
            total = payload.get("total", 0)

            if not items:
                break

            for item in items:
                advisory_id = str(item.get("id", "")).strip()

                if advisory_id and advisory_id not in all_ids:
                    all_ids.append(advisory_id)

            if max_advisories is not None and len(all_ids) >= max_advisories:
                return all_ids[:max_advisories]

            if total and len(all_ids) >= total:
                break

            if len(items) < self.PAGE_SIZE:
                break

            page += 1

        return all_ids

    def fetch_bulletins(
        self,
        max_advisories: int | None = None,
    ) -> list[RawVendorBulletin]:

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0 Safari/537.36"
            )
        }

        fetched_at = datetime.now(timezone.utc)
        bulletins: list[RawVendorBulletin] = []

        advisory_ids = self._fetch_all_advisory_ids(
            headers=headers,
            max_advisories=max_advisories,
        )

        for advisory_id in advisory_ids:
            advisory_url = urljoin(
                self.BASE_URL,
                f"/en/support/security-advisory-detail?id={advisory_id}",
            )

            try:
                response = requests.get(
                    advisory_url,
                    headers=headers,
                    timeout=30,
                )

                response.raise_for_status()

            except Exception:
                continue

            html = response.text

            cve_ids = extract_cves_from_html(html)

            if not cve_ids:
                cve_ids = sorted(set(CVE_REGEX.findall(html)))

            bulletins.append(
                RawVendorBulletin(
                    vendor=self.VENDOR,
                    source_name=self.SOURCE_NAME,
                    bulletin_id=f"vivo-advisory-{advisory_id}",
                    bulletin_date=date.today(),  # replace if you later parse advisory dates
                    bulletin_url=advisory_url,
                    cve_ids=sorted(set(cve_ids)),
                    fetched_at=fetched_at,
                    metadata={
                        "advisory_id": advisory_id,
                    },
                )
            )

        # Fallback if API failed
        if not bulletins:
            response = requests.get(
                self.LIST_URL,
                headers=headers,
                timeout=30,
            )
            response.raise_for_status()

            list_cves = sorted(
                set(CVE_REGEX.findall(response.text))
            )

            bulletins.append(
                RawVendorBulletin(
                    vendor=self.VENDOR,
                    source_name=self.SOURCE_NAME,
                    bulletin_id="vivo-advisory-list",
                    bulletin_date=date.today(),
                    bulletin_url=self.LIST_URL,
                    cve_ids=list_cves,
                    fetched_at=fetched_at,
                    metadata={
                        "fallback": "list_page_only",
                    },
                )
            )

        return bulletins