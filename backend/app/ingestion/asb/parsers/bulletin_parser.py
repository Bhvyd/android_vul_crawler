# parser/bulletin_parser.py

from __future__ import annotations

import json
import re
from pathlib import Path

from bs4 import BeautifulSoup


PATCH_LEVEL_RE = re.compile(
    r"\d{4}-\d{2}-(?:01|05)"
)


class BulletinParser:

    def parse_file(
        self,
        html_file: str | Path,
    ) -> dict:

        html_file = Path(html_file)

        html = html_file.read_text(
            encoding="utf-8",
            errors="ignore",
        )

        return self.parse_html(html)

    def parse_html(
        self,
        html: str,
    ) -> dict:

        soup = BeautifulSoup(
            html,
            "lxml",
        )

        return {
            "title": self.extract_title(soup),
            "headline": self.extract_headline(soup),
            "canonical_url": self.extract_canonical_url(soup),
            "published_date": self.extract_published_date(soup),
            "updated_date": self.extract_updated_date(soup),
            "patch_levels": self.extract_patch_levels(soup),
        }

    # -----------------------------------------
    # Title
    # -----------------------------------------

    def extract_title(
        self,
        soup: BeautifulSoup,
    ) -> str | None:

        if soup.title:
            return soup.title.get_text(
                strip=True
            )

        return None

    # -----------------------------------------
    # JSON-LD headline
    # -----------------------------------------

    def extract_headline(
        self,
        soup: BeautifulSoup,
    ) -> str | None:

        scripts = soup.find_all(
            "script",
            attrs={
                "type":
                "application/ld+json"
            },
        )

        for script in scripts:

            try:

                if not script.string:
                    continue

                data = json.loads(
                    script.string
                )

                if (
                    isinstance(data, dict)
                    and data.get("@type")
                    == "Article"
                ):
                    return data.get(
                        "headline"
                    )

            except Exception:
                continue

        return None

    # -----------------------------------------
    # Canonical URL
    # -----------------------------------------

    def extract_canonical_url(
        self,
        soup: BeautifulSoup,
    ) -> str | None:

        tag = soup.find(
            "link",
            rel="canonical",
        )

        if tag:
            return tag.get(
                "href"
            )

        return None

    # -----------------------------------------
    # Published Date
    # -----------------------------------------

    def extract_published_date(
        self,
        soup: BeautifulSoup,
    ) -> str | None:

        text = soup.get_text(
            " ",
            strip=True,
        )

        match = re.search(
            r"Published\s+([A-Za-z]+\s+\d{1,2},\s+\d{4})",
            text,
            re.I,
        )

        if match:
            return match.group(1)

        return None

    # -----------------------------------------
    # Updated Date
    # -----------------------------------------

    def extract_updated_date(
        self,
        soup: BeautifulSoup,
    ) -> str | None:

        text = soup.get_text(
            " ",
            strip=True,
        )

        match = re.search(
            r"Updated\s+([A-Za-z]+\s+\d{1,2},\s+\d{4})",
            text,
            re.I,
        )

        if match:
            return match.group(1)

        return None

    # -----------------------------------------
    # Patch Levels
    # -----------------------------------------

    def extract_patch_levels(
        self,
        soup: BeautifulSoup,
    ) -> list[str]:

        text = soup.get_text(
            " ",
            strip=True,
        )

        levels = PATCH_LEVEL_RE.findall(
            text
        )

        return sorted(
            set(levels)
        )


if __name__ == "__main__":

    parser = BulletinParser()

    result = parser.parse_file(
     "backend/storage/raw/html/android-2025-09.html"    )

    print(
        json.dumps(
            result,
            indent=2,
        )
    )