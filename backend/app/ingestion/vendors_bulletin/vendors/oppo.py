import asyncio
import re
from datetime import date
from collections import Counter
import json
from pathlib import Path

from playwright.async_api import async_playwright

# Assuming this is your local schema import
from vendors_bulletin.schema.cve import CVERecord


class OppoCollector:
    VENDOR = "oppo"
    SOURCE_NAME = "oppo_bulletin"
    BASE_URL = "https://security.oppo.com/en/mend"

    async def collect(self) -> list[CVERecord]:

        records: list[CVERecord] = []
        seen = set()

        async with async_playwright() as p:

            browser = await p.chromium.launch(
                headless=True
            )

            page = await browser.new_page()

            async def handle_response(response):
                if "findSecurityUpdateDetails" not in response.url:
                    return

                try:
                    payload = await response.json()
                    data = payload.get("data")

                    if not data:
                        return

                    year_month = data.get("year_month")

                    if not year_month:
                        return

                    bulletin_date = date(
                        int(year_month[:4]),
                        int(year_month[4:6]),
                        1,
                    )

                    severity_map = {
                        "critical_patch": "Critical",
                        "high_patch": "High",
                        "moderate_patch": "Moderate",
                        "low_patch": "Low",
                    }

                    for field, severity in severity_map.items():
                        value = data.get(field) or ""

                        cves = re.findall(
                            r"CVE-\d{4}-\d+",
                            value,
                            flags=re.I,
                        )

                        for cve in cves:
                            key = (
                                cve.upper(),
                                year_month,
                            )

                            if key in seen:
                                continue

                            seen.add(key)

                            records.append(
                                CVERecord(
                                    cve_id=cve.upper(),
                                    vendor=self.VENDOR,
                                    source_name=self.SOURCE_NAME,
                                    bulletin_id=f"oppo-{year_month}",
                                    bulletin_url=response.url,
                                    bulletin_date=bulletin_date,
                                    severity=severity,
                                    metadata={
                                        "year_month": year_month,
                                    },
                                )
                            )

                except Exception as e:
                    print(f"Response parse error: {e}")

            page.on("response", handle_response)

            await page.goto(
                self.BASE_URL,
                wait_until="networkidle",
                timeout=60000,
            )

            await page.wait_for_timeout(5000)

            # click every visible month/year button
            # so Oppo fires the API calls
            years = [str(y) for y in range(2022, 2031)]
            months = [
                "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
            ]

            for year in years:
                try:
                    # Added .first to avoid strict mode violations
                    await page.get_by_text(year, exact=True).first.click(timeout=1000)
                    await page.wait_for_timeout(1000)
                except Exception as e:
                    # Log the exception instead of silently passing
                    print(f"Skipping year {year}: {e}")
                    continue

                for month in months:
                    try:
                        # Added .first to avoid strict mode violations
                        await page.get_by_text(month, exact=True).first.click(timeout=1000)
                        await page.wait_for_timeout(1000)
                    except Exception as e:
                        # Log the exception instead of silently passing
                        # Note: Expected to fail for future months in current year
                        # print(f"Skipping month {month} in {year}: {e}")
                        pass

            await page.wait_for_timeout(5000)
            await browser.close()

        return records

    def fetch_cves(self) -> list[CVERecord]:
        return asyncio.run(self.collect())


if __name__ == "__main__":
    collector = OppoCollector()
    records = collector.fetch_cves()

    print(f"Collected {len(records)} CVEs")

    for r in records:
        print(r.cve_id, r.severity, r.bulletin_id)

    # Path to project root (vendors_bulletin/)
    BASE_DIR = Path(__file__).resolve().parent.parent

    # vendors_bulletin/vendor_bulletins_output/
    output_dir = BASE_DIR / "vendor_bulletins_output"
    output_dir.mkdir(parents=True, exist_ok=True)

    output_file = output_dir / "oppo.json"

    with output_file.open("w", encoding="utf-8") as f:
        json.dump(
            [record.model_dump(mode="json") for record in records],
            f,
            indent=4,
            ensure_ascii=False,
        )

    print(f"\nSaved {len(records)} records to:")
    print(output_file.resolve())

    print(f"\nTotal records: {len(records)}")
    print(f"Unique (CVE, Bulletin): {len({(r.cve_id, r.bulletin_id) for r in records})}")

    counter = Counter(r.bulletin_id for r in records)

    print("\nCVEs per bulletin:")
    for bulletin, count in sorted(counter.items()):
        print(f"{bulletin}: {count}")