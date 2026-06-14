import time
from datetime import datetime, timezone, date

import requests

from app.ingestion.vendor_bulletin.common import CVE_REGEX
from app.ingestion.schemas import RawVendorBulletin


class XiaomiBulletinCollector:
    SOURCE_NAME = "xiaomi_bulletin"
    VENDOR = "xiaomi"

    API_URL = "https://trust.mi.com/bff/security-suggestions/c"
    PAGE_SIZE = 10

    HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36"
        ),
        "Referer": "https://trust.mi.com/misrc/bulletins",
        "Accept": "application/json, text/plain, */*",
    }

    CVE_REGEX = CVE_REGEX

    def _fetch_page(self, page: int) -> dict:
        try:
            resp = requests.get(
                self.API_URL,
                params={"page": page},
                headers=self.HEADERS,
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json()

        except requests.RequestException as e:
            print(f"[ERROR] Xiaomi API page={page}: {e}")
            return {}

    def fetch_all_advisories(
        self,
        start_year: int = 2020,
    ) -> list[dict]:
        all_items: list[dict] = []

        page = 1

        data = self._fetch_page(page)

        if not data:
            return all_items

        total = data.get("count", 0)

        total_pages = -(-total // self.PAGE_SIZE)

        print(
            f"[INFO] Xiaomi bulletins: "
            f"{total} total across {total_pages} pages"
        )

        while page <= total_pages:

            if page > 1:
                data = self._fetch_page(page)

                if not data:
                    break

            items = data.get("data", [])

            if not items:
                break

            for item in items:

                pub_str = item.get("publishedAt", "")

                try:
                    pub_year = int(pub_str[:4])
                except (ValueError, TypeError):
                    continue

                if pub_year >= start_year:
                    all_items.append(item)

            print(
                f"[OK] Page {page}/{total_pages}: "
                f"{len(items)} items"
            )

            page += 1

            time.sleep(0.5)

        return all_items

    def _parse_cve_id(
        self,
        raw: str,
    ) -> str | None:

        cleaned = raw.strip()

        if self.CVE_REGEX.fullmatch(cleaned):
            return cleaned

        return None

    def _group_by_month(
        self,
        advisories: list[dict],
    ) -> dict[tuple[int, int], list[str]]:

        monthly: dict[tuple[int, int], list[str]] = {}

        for item in advisories:

            cve_id = self._parse_cve_id(
                item.get("CVECode", "")
            )

            pub_str = item.get("publishedAt", "")

            if not cve_id or not pub_str:
                continue

            try:
                pub_dt = datetime.fromisoformat(
                    pub_str.replace("Z", "+00:00")
                )
            except ValueError:
                continue

            key = (pub_dt.year, pub_dt.month)

            monthly.setdefault(key, []).append(cve_id)

        return monthly

    def fetch_bulletins(
        self,
        start_year: int = 2020,
    ) -> list[RawVendorBulletin]:

        fetched_at = datetime.now(timezone.utc)

        bulletins: list[RawVendorBulletin] = []

        advisories = self.fetch_all_advisories(
            start_year=start_year
        )

        if not advisories:
            print("[WARN] No Xiaomi advisories returned.")
            return bulletins

        monthly = self._group_by_month(advisories)

        for (year, month), cve_ids in sorted(monthly.items()):

            unique_cves = sorted(set(cve_ids))

            bulletin_date = date(
                year,
                month,
                1,
            )

            bulletins.append(
                RawVendorBulletin(
                    vendor=self.VENDOR,
                    source_name=self.SOURCE_NAME,
                    bulletin_id=(
                        f"xiaomi-{year}-{month:02d}"
                    ),
                    bulletin_date=bulletin_date,
                    bulletin_url=(
                        "https://trust.mi.com/"
                        f"misrc/bulletins?year={year}"
                    ),
                    cve_ids=unique_cves,
                    fetched_at=fetched_at,
                    metadata={
                        "year": year,
                        "month": month,
                        "cve_count": len(unique_cves),
                        "source_api": self.API_URL,
                    },
                )
            )

            print(
                f"[OK] Xiaomi {year}-{month:02d}: "
                f"{len(unique_cves)} CVEs"
            )

        return bulletins