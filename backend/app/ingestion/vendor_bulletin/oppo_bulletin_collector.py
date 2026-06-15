import asyncio
import re
from datetime import date, datetime, timezone

from playwright.async_api import async_playwright

from app.ingestion.schemas import RawVendorBulletin


class OppoBulletinCollector:
    SOURCE_NAME = "oppo_bulletin"
    VENDOR = "oppo"
    BASE_URL = "https://security.oppo.com/en/mend"

    async def _scrape_bulletins(
        self,
        start_year: int = 2022,
        end_year: int | None = None,
    ) -> list[RawVendorBulletin]:

        fetched_at = datetime.now(timezone.utc)
        bulletins: list[RawVendorBulletin] = []

        current_year = datetime.now().year
        end_year = end_year or current_year

        years = [
            str(year)
            for year in range(end_year, start_year - 1, -1)
        ]

        months = [
            ("Jan", 1),
            ("Feb", 2),
            ("Mar", 3),
            ("Apr", 4),
            ("May", 5),
            ("Jun", 6),
            ("Jul", 7),
            ("Aug", 8),
            ("Sep", 9),
            ("Oct", 10),
            ("Nov", 11),
            ("Dec", 12),
        ]

        browser = None

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True
                )

                context = await browser.new_context()

                page = await context.new_page()

                print("Opening Oppo bulletin page...")

                await page.goto(
                    self.BASE_URL,
                    wait_until="domcontentloaded",
                    timeout=60000,
                )

                await page.wait_for_timeout(3000)

                for year in years:
                    print(f"\n===== YEAR {year} =====")

                    try:
                        year_btn = page.get_by_text(
                            year,
                            exact=True,
                        ).first

                        await year_btn.click()

                        await page.wait_for_timeout(1500)

                    except Exception as e:
                        print(f"Failed year {year}: {e}")
                        continue

                    for month_name, month_num in months:

                        try:
                            print(
                                f"Processing {year}-{month_name}"
                            )

                            month_btn = page.get_by_text(
                                month_name,
                                exact=True,
                            ).first

                            await month_btn.click()

                            await page.wait_for_timeout(2000)

                            html = await page.content()

                            cves = sorted(
                                set(
                                    re.findall(
                                        r"CVE-\d{4}-\d+",
                                        html,
                                    )
                                )
                            )

                            if not cves:
                                print(
                                    f"  {year}-{month_name}: no CVEs"
                                )
                                continue

                            print(
                                f"  {year}-{month_name}: "
                                f"{len(cves)} CVEs"
                            )

                            bulletins.append(
                                RawVendorBulletin(
                                    vendor=self.VENDOR,
                                    source_name=self.SOURCE_NAME,
                                    bulletin_id=(
                                        f"oppo-{year}-{month_num:02d}"
                                    ),
                                    bulletin_date=date(
                                        int(year),
                                        month_num,
                                        1,
                                    ),
                                    bulletin_url=self.BASE_URL,
                                    cve_ids=cves,
                                    fetched_at=fetched_at,
                                    metadata={
                                        "year": int(year),
                                        "month": month_num,
                                    },
                                )
                            )

                        except Exception as e:
                            print(
                                f"Failed {year}-{month_name}: {e}"
                            )
                            continue

        finally:
            if browser:
                await browser.close()

        print(
            f"\nFinished. Collected "
            f"{len(bulletins)} bulletins."
        )

        return bulletins

    def fetch_bulletins(
        self,
        start_year: int = 2022,
        end_year: int | None = None,
    ) -> list[RawVendorBulletin]:
        return asyncio.run(
            self._scrape_bulletins(
                start_year=start_year,
                end_year=end_year,
            )
        ) 