# collector/asb_collector.py

from __future__ import annotations

import json
import time
from pathlib import Path
from datetime import date, datetime, timezone

import requests


class ASBCollector:

    USER_AGENT = (
        "android-security-crawler/1.0 "
        "(ASB collection)"
    )

    def __init__(
        self,
        raw_dir: str = "storage/raw/html",
        metadata_dir: str = "storage/raw/metadata",
        timeout: int = 60,
        sleep_seconds: float = 1.0,
    ):
        self.raw_dir = Path(raw_dir)
        self.metadata_dir = Path(metadata_dir)

        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_dir.mkdir(parents=True, exist_ok=True)

        self.timeout = timeout
        self.sleep_seconds = sleep_seconds

        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": self.USER_AGENT,
            }
        )

    # --------------------------------------------------
    # URL generation
    # --------------------------------------------------

    def candidate_urls(
        self,
        year: int,
        month: int,
    ) -> list[str]:

        date_str = f"{year}-{month:02d}-01"

        return [
            # Old format
            f"https://source.android.com/docs/security/bulletin/{date_str}",

            # New format
            f"https://source.android.com/docs/security/bulletin/{year}/{date_str}",
        ]

    def generate_bulletins(
        self,
        start_year: int = 2021,
    ) -> list[dict]:

        today = date.today()

        bulletins = []

        for year in range(start_year, today.year + 1):

            last_month = 12

            if year == today.year:
                last_month = today.month

            for month in range(1, last_month + 1):

                bulletins.append(
                    {
                        "bulletin_id":
                            f"android-{year}-{month:02d}",

                        "bulletin_date":
                            f"{year}-{month:02d}-01",

                        "year":
                            year,

                        "month":
                            month,
                    }
                )

        return bulletins

    # --------------------------------------------------
    # Download
    # --------------------------------------------------

    def fetch_html(
        self,
        year: int,
        month: int,
    ) -> tuple[str, str]:

        urls = self.candidate_urls(year, month)

        for url in urls:

            try:

                response = self.session.get(
                    url,
                    timeout=self.timeout,
                )

                if response.status_code == 200:

                    return (
                        response.text,
                        url,
                    )

            except Exception:
                pass

        raise RuntimeError(
            f"No valid ASB URL found "
            f"for {year}-{month:02d}"
        )

    # --------------------------------------------------
    # Storage
    # --------------------------------------------------

    def save_html(
        self,
        bulletin_id: str,
        html: str,
    ) -> Path:

        file_path = (
            self.raw_dir /
            f"{bulletin_id}.html"
        )

        file_path.write_text(
            html,
            encoding="utf-8",
        )

        return file_path

    def save_metadata(
        self,
        bulletin_id: str,
        bulletin_date: str,
        url: str,
        html_path: Path,
    ):

        metadata = {
            "bulletin_id": bulletin_id,
            "bulletin_date": bulletin_date,
            "url": url,
            "html_file": str(html_path),
            "collected_at": datetime.now(
                timezone.utc
            ).isoformat(),
        }

        metadata_file = (
            self.metadata_dir /
            f"{bulletin_id}.json"
        )

        metadata_file.write_text(
            json.dumps(
                metadata,
                indent=2,
            ),
            encoding="utf-8",
        )

    # --------------------------------------------------
    # Collection
    # --------------------------------------------------

    def collect_bulletin(
        self,
        bulletin: dict,
    ) -> bool:

        bulletin_id = bulletin["bulletin_id"]

        try:

            print(
                f"[INFO] Downloading "
                f"{bulletin_id}"
            )

            html, url = self.fetch_html(
                bulletin["year"],
                bulletin["month"],
            )

            html_path = self.save_html(
                bulletin_id,
                html,
            )

            self.save_metadata(
                bulletin_id=bulletin_id,
                bulletin_date=bulletin["bulletin_date"],
                url=url,
                html_path=html_path,
            )

            print(
                f"[OK] {bulletin_id}"
            )

            return True

        except Exception as exc:

            print(
                f"[FAILED] "
                f"{bulletin_id}: {exc}"
            )

            return False

    def collect_all(
        self,
        start_year: int = 2021,
    ) -> dict:

        bulletins = self.generate_bulletins(
            start_year=start_year
        )

        downloaded = 0
        failed = 0

        for bulletin in bulletins:

            success = self.collect_bulletin(
                bulletin
            )

            if success:
                downloaded += 1
            else:
                failed += 1

            time.sleep(
                self.sleep_seconds
            )

        return {
            "downloaded": downloaded,
            "failed": failed,
            "total": len(bulletins),
        }


if __name__ == "__main__":

    collector = ASBCollector()

    summary = collector.collect_all(
        start_year=2021
    )

    print("\n=== SUMMARY ===")

    print(
        json.dumps(
            summary,
            indent=2,
        )
    )