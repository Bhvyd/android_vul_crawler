import re
from datetime import datetime, timezone

import requests


from app.ingestion.vendor_bulletin.common import CVE_REGEX, extract_cves_from_html
from app.ingestion.schemas import RawVendorBulletin



class SamsungBulletinCollector():

    SOURCE_NAME = "samsung_bulletin"
    VENDOR = "samsung"

    # Samsung renders bulletin detail pages at this URL pattern:
    # https://security.samsungmobile.com/securityUpdate.smsb
    # Individual month detail is embedded in the same page via JS,
    # but they also expose a detail endpoint:
    BASE_URL = "https://security.samsungmobile.com/securityUpdate.smsb"
    DETAIL_URL = "https://security.samsungmobile.com/securityUpdateDetail.smsb"

    # Samsung SMR labels look like: SMR-JAN-2025, SMR-MAY-2026
    MONTH_ABBREVS = [
        "JAN", "FEB", "MAR", "APR", "MAY", "JUN",
        "JUL", "AUG", "SEP", "OCT", "NOV", "DEC",
    ]

    HEADERS = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36",
        "Referer": "https://security.samsungmobile.com/securityUpdate.smsb",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    CVE_REGEX = CVE_REGEX

    def generate_month_params(self, start_year: int = 2020) -> list[dict]:
        """
        Returns list of (year, month_int) pairs up to current month.
        Samsung's detail endpoint accepts ?year=2025&month=1 style params.
        """
        now = datetime.now(timezone.utc)
        params_list = []

        for year in range(start_year, now.year + 1):
            for month in range(1, 13):
                if year == now.year and month > now.month:
                    break
                params_list.append({"year": year, "month": month})

        return params_list

    def _bulletin_id(self, year: int, month: int) -> str:
        abbrev = self.MONTH_ABBREVS[month - 1]
        return f"samsung-SMR-{abbrev}-{year}"

    def _bulletin_date(self, year: int, month: int):
        return datetime(year, month, 1, tzinfo=timezone.utc).date()

    def extract_cves_from_page(self, html: str) -> set[str]:
        return set(extract_cves_from_html(html))

    def _fetch_month_html(self, year: int, month: int) -> str | None:
        """
        Try Samsung's detail endpoint first (year+month params),
        fall back to the main listing page for the current month.
        """
        # Primary: detail page with query params
        try:
            resp = requests.get(
                self.DETAIL_URL,
                params={"year": year, "month": month},
                headers=self.HEADERS,
                timeout=30,
            )
            if resp.status_code == 200 and len(resp.text) > 500:
                return resp.text
        except requests.RequestException:
            pass

        # Fallback: main page (contains current + recent months inline)
        try:
            resp = requests.get(self.BASE_URL, headers=self.HEADERS, timeout=30)
            if resp.status_code == 200:
                return resp.text
        except requests.RequestException:
            pass

        return None

    def fetch_bulletins(
        self,
        months: list[tuple[int, int]] | None = None,
        start_year: int = 2020,
    ) -> list[RawVendorBulletin]:
        """
        months: optional list of (year, month_int) tuples, e.g. [(2025, 1), (2025, 2)]
        """
        fetched_at = datetime.now(timezone.utc)
        bulletins: list[RawVendorBulletin] = []
        errors = []

        params_list = (
            [{"year": y, "month": m} for y, m in months]
            if months
            else self.generate_month_params(start_year=start_year)
        )

        for p in params_list:
            year, month = p["year"], p["month"]
            html = self._fetch_month_html(year, month)

            if not html:
                errors.append({"year": year, "month": month, "error": "No HTML fetched"})
                continue

            cve_ids = sorted(self.extract_cves_from_page(html))
            if not cve_ids:
                print(f"[WARN] No CVEs found for Samsung {year}-{month:02d}")
                continue

            bulletin_date = self._bulletin_date(year, month)
            bulletin_id = self._bulletin_id(year, month)
            bulletin_url = f"{self.DETAIL_URL}?year={year}&month={month}"

            bulletins.append(
                RawVendorBulletin(
                    vendor=self.VENDOR,
                    source_name=self.SOURCE_NAME,
                    bulletin_id=bulletin_id,
                    bulletin_date=bulletin_date,
                    bulletin_url=bulletin_url,
                    cve_ids=cve_ids,
                    fetched_at=fetched_at,
                    metadata={"year": year, "month": month},
                )
            )

        if errors:
            print(f"[WARN] {len(errors)} Samsung months failed:")
            for err in errors:
                print(f"  {err}")

        return bulletins

    def run(self, persist: bool = True):
        if not persist:
            return

        params_list = self.generate_month_params(start_year=2020)

        for p in params_list:
            year, month = p["year"], p["month"]
            try:
                html = self._fetch_month_html(year, month)
                if not html:
                    print(f"[SKIP] No response for Samsung {year}-{month:02d}")
                    continue

                cve_ids = self.extract_cves_from_page(html)
                if not cve_ids:
                    print(f"[SKIP] No CVEs for Samsung {year}-{month:02d}")
                    continue

                bulletin_date = self._bulletin_date(year, month)

                for cve_id in cve_ids:
                    if not self.db.get(CVE, cve_id):
                        self.db.add(CVE(id=cve_id))

                    existing_patch = (
                        self.db.query(CVEPatch)
                        .filter_by(
                            cve_id=cve_id,
                            patch_level_date=bulletin_date,
                        )
                        .first()
                    )

                    if not existing_patch:
                        patch = CVEPatch(
                            cve_id=cve_id,
                            patch_level_date=bulletin_date,
                            source_type=PatchSourceType.SAMSUNG,  # add to your enum
                        )
                        self.db.add(patch)

                        timeline = CVETimelineEvent(
                            cve_id=cve_id,
                            event_type=TimelineEventType.PATCHED_SAMSUNG,  # add to your enum
                            event_date=bulletin_date,
                            notes="Patched in Samsung Security Maintenance Release (SMR)",
                        )
                        self.db.add(timeline)

                self.db.commit()
                print(f"[OK] Processed Samsung bulletin {year}-{month:02d}")

            except Exception as e:
                self.db.rollback()
                print(f"[ERROR] Failed Samsung {year}-{month:02d}: {e}")

        print("Samsung bulletin sync complete.")