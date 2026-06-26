import json
import re
import time
from datetime import datetime
from pathlib import Path

import requests

CVE_REGEX = re.compile(r"CVE-\d{4}-\d+")
from vendors_bulletin.schema.cve import CVERecord


class XiaomiBulletinCollector:
    SOURCE_NAME = "xiaomi_bulletin"
    VENDOR = "xiaomi"

    LIST_API = (
        "https://trust.mi.com/bff/security-suggestions/c"
    )

    HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36"
        ),
        "Referer": (
            "https://trust.mi.com/misrc/bulletins"
        ),
        "Accept": (
            "application/json, text/plain, */*"
        ),
    }

    PAGE_SIZE = 10

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(
            self.HEADERS
        )

    def _fetch_page(
        self,
        page: int,
    ) -> dict:

        try:
            resp = self.session.get(
                self.LIST_API,
                params={"page": page},
                timeout=30,
            )

            resp.raise_for_status()

            return resp.json()

        except requests.RequestException as e:

            print(
                f"[ERROR] Page {page}: {e}"
            )

            return {}

    def fetch_all_advisories(
        self,
        start_year: int = 2020,
    ) -> list[dict]:

        advisories = []

        first_page = self._fetch_page(1)

        if not first_page:
            return advisories

        total = first_page.get(
            "count",
            0,
        )

        total_pages = (
            total + self.PAGE_SIZE - 1
        ) // self.PAGE_SIZE

        print(
            f"[INFO] Found {total} advisories "
            f"across {total_pages} pages"
        )

        for page in range(
            1,
            total_pages + 1,
        ):

            data = (
                first_page
                if page == 1
                else self._fetch_page(page)
            )

            items = data.get(
                "data",
                [],
            )

            for item in items:

                published = item.get(
                    "publishedAt",
                    "",
                )

                try:
                    year = int(
                        published[:4]
                    )
                except Exception:
                    continue

                if year >= start_year:
                    advisories.append(item)

            print(
                f"[OK] Page "
                f"{page}/{total_pages}: "
                f"{len(items)} advisories"
            )

            time.sleep(0.2)

        return advisories

    def fetch_advisory_detail(
        self,
        advisory_id: int,
    ) -> dict:

        try:

            resp = self.session.get(
                f"{self.LIST_API}/{advisory_id}",
                timeout=30,
            )

            resp.raise_for_status()

            return resp.json()

        except requests.RequestException as e:

            print(
                f"[ERROR] Detail "
                f"{advisory_id}: {e}"
            )

            return {}

    def advisory_to_record(
        self,
        advisory: dict,
    ) -> CVERecord | None:

        cve_id = advisory.get(
            "CVECode"
        )

        if (
            not cve_id
            or not CVE_REGEX.fullmatch(
                cve_id.strip()
            )
        ):
            return None

        bulletin_date = None

        if advisory.get(
            "publishedAt"
        ):

            try:
                bulletin_date = (
                    datetime.fromisoformat(
                        advisory[
                            "publishedAt"
                        ].replace(
                            "Z",
                            "+00:00",
                        )
                    ).date()
                )
            except Exception:
                pass

        affected_versions = []
        fixed_versions = []

        products = []

        for product in advisory.get(
            "affectProductions",
            [],
        ):

            products.append(
                {
                    "product": (
                        product.get(
                            "nameTl"
                        )
                        or product.get(
                            "name"
                        )
                    ),
                    "affected_version": (
                        product.get(
                            "affectedVersion"
                        )
                    ),
                    "fixed_version": (
                        product.get(
                            "repairedVersion"
                        )
                    ),
                }
            )

            if product.get(
                "affectedVersion"
            ):
                affected_versions.append(
                    product[
                        "affectedVersion"
                    ]
                )

            if product.get(
                "repairedVersion"
            ):
                fixed_versions.append(
                    product[
                        "repairedVersion"
                    ]
                )

        return CVERecord(
            cve_id=cve_id,

            vendor=self.VENDOR,

            source_name=self.SOURCE_NAME,

            bulletin_id=advisory.get(
                "internalId"
            ),

            bulletin_url=(
                "https://trust.mi.com/"
                "misrc/bulletins/"
                f"advisory?cveId="
                f"{advisory.get('id')}"
            ),

            bulletin_date=bulletin_date,

            cvss_score=(
                float(
                    advisory[
                        "CVSSScore"
                    ]
                )
                if advisory.get(
                    "CVSSScore"
                )
                is not None
                else None
            ),

            description=(
                advisory.get(
                    "bugDescriptionTl"
                )
                or advisory.get(
                    "bugDescription"
                )
            ),

            affected_versions=(
                "; ".join(
                    sorted(
                        set(
                            affected_versions
                        )
                    )
                )
                if affected_versions
                else None
            ),

            fixed_versions=(
                "; ".join(
                    sorted(
                        set(
                            fixed_versions
                        )
                    )
                )
                if fixed_versions
                else None
            ),

            vendor_advisory=(
                advisory.get(
                    "internalId"
                )
            ),

            metadata={
                "xiaomi_id": advisory.get(
                    "id"
                ),
                "title": (
                    advisory.get(
                        "titleTl"
                    )
                    or advisory.get(
                        "title"
                    )
                ),
                "products": products,
                "thanks": (
                    advisory.get(
                        "thanksTl"
                    )
                    or advisory.get(
                        "thanks"
                    )
                ),
            },
        )

    def fetch_cves(
        self,
        start_year: int = 2020,
    ) -> list[CVERecord]:

        records = []

        advisories = (
            self.fetch_all_advisories(
                start_year
            )
        )

        print(
            f"[INFO] Fetching details "
            f"for {len(advisories)} "
            f"advisories"
        )

        for advisory in advisories:

            advisory_id = advisory.get(
                "id"
            )

            if not advisory_id:
                continue

            detail = (
                self.fetch_advisory_detail(
                    advisory_id
                )
            )

            if not detail:
                continue

            record = (
                self.advisory_to_record(
                    detail
                )
            )

            if record:

                records.append(
                    record
                )

                print(
                    f"[OK] "
                    f"{record.cve_id} "
                    f"{record.bulletin_id}"
                )

            time.sleep(0.2)

        return records


if __name__ == "__main__":

    collector = XiaomiBulletinCollector()

    records = collector.fetch_cves(
        start_year=2020
    )

    output_dir = Path("vendors_bulletin/vendor_bulletins_output")
    output_dir.mkdir(
        exist_ok=True
    )

    output_file = (
        output_dir
        / "xiaomi.json"
    )

    with open(
        output_file,
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            [
                record.model_dump(
                    mode="json"
                )
                for record in records
            ],
            f,
            indent=2,
            ensure_ascii=False,
        )

    print(
        f"\n[SUCCESS] Saved "
        f"{len(records)} CVEs to "
        f"{output_file}"
    )