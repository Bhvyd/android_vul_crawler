import json
import re
import time
from pathlib import Path

import requests


class PatchParser:
    def __init__(self):
        self.session = requests.Session()

        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        })

        self.cache_dir = Path("backend/cache/gitiles")
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _extract_repo_and_hash(self, url: str):
        if "/+/" not in url:
            return None, None

        base_part, commit_part = url.split("/+/", 1)

        repo_match = re.search(
            r"android\.googlesource\.com/(.+)$",
            base_part
        )

        repo_path = repo_match.group(1) if repo_match else None

        commit_hash = commit_part.split("/")[0]

        return repo_path, commit_hash

    def _load_cache(self, commit_hash):
        cache_file = self.cache_dir / f"{commit_hash}.json"

        if cache_file.exists():
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except:
                return None

        return None

    def _save_cache(self, commit_hash, data):
        cache_file = self.cache_dir / f"{commit_hash}.json"

        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)

    def fetch_commit_data(self, url, cve_ids):

        repo_path, commit_hash = self._extract_repo_and_hash(url)

        if not repo_path or not commit_hash:
            return None

        cached = self._load_cache(commit_hash)

        if cached:
            return {
                "url": url,
                "cve_ids": sorted(cve_ids),
                **cached
            }

        api_url = (
            f"https://android.googlesource.com/"
            f"{repo_path}/+/{commit_hash}?format=JSON"
        )

        for attempt in range(5):

            try:

                response = self.session.get(
                    api_url,
                    timeout=30
                )

                if response.status_code == 429:
                    wait = (attempt + 1) * 30

                    print(
                        f"Rate limited. Sleeping {wait}s..."
                    )

                    time.sleep(wait)
                    continue

                if response.status_code != 200:

                    print(
                        f"[{response.status_code}] {commit_hash}"
                    )

                    return None

                raw_text = response.text

                if raw_text.startswith(")]}'"):
                    raw_text = raw_text[4:].strip()

                data = json.loads(raw_text)

                author = data.get("author", {})

                changed_files = []

                for diff in data.get("tree_diff", []):

                    changed_files.append({
                        "type": diff.get("type"),
                        "old_path": diff.get("old_path"),
                        "new_path": diff.get("new_path")
                    })

                result = {
                    "repo_path": repo_path,
                    "commit_hash": data.get(
                        "commit",
                        commit_hash
                    ),
                    "author_name": author.get("name"),
                    "author_email": author.get("email"),
                    "commit_time": author.get("time"),
                    "commit_message": data.get(
                        "message",
                        ""
                    ).strip(),
                    "changed_files": changed_files
                }

                self._save_cache(
                    commit_hash,
                    result
                )

                time.sleep(1)

                return {
                    "url": url,
                    "cve_ids": sorted(cve_ids),
                    **result
                }

            except Exception as e:

                print(
                    f"Attempt {attempt+1} failed "
                    f"for {commit_hash}: {e}"
                )

                time.sleep(10)

        return None

    def process_patches(
        self,
        reference_file,
        output_file
    ):

        with open(
            reference_file,
            "r",
            encoding="utf-8"
        ) as f:
            references = json.load(f)

        url_to_cves = {}

        for ref in references:

            if (
                ref.get("type") == "aosp_patch"
                and ref.get("url")
            ):

                url = ref["url"]

                url_to_cves.setdefault(
                    url,
                    set()
                ).add(ref["cve_id"])

        print(
            f"Unique patch URLs: "
            f"{len(url_to_cves)}"
        )

        output_path = Path(output_file)

        if output_path.exists():

            try:
                with open(
                    output_path,
                    "r",
                    encoding="utf-8"
                ) as f:

                    parsed_patches = json.load(f)

            except:

                parsed_patches = []

        else:

            parsed_patches = []

        completed_urls = {
            p["url"]
            for p in parsed_patches
        }

        remaining = [
            (url, cves)
            for url, cves
            in url_to_cves.items()
            if url not in completed_urls
        ]

        print(
            f"Already done: "
            f"{len(completed_urls)}"
        )

        print(
            f"Remaining: "
            f"{len(remaining)}"
        )

        for idx, (url, cves) in enumerate(
            remaining,
            start=1
        ):

            result = self.fetch_commit_data(
                url,
                cves
            )

            if result:

                parsed_patches.append(
                    result
                )

            if idx % 25 == 0:

                with open(
                    output_path,
                    "w",
                    encoding="utf-8"
                ) as f:

                    json.dump(
                        parsed_patches,
                        f,
                        indent=2,
                        ensure_ascii=False
                    )

                print(
                    f"Checkpoint saved "
                    f"({idx}/{len(remaining)})"
                )

        with open(
            output_path,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                parsed_patches,
                f,
                indent=2,
                ensure_ascii=False
            )

        print(
            f"\nFinished. "
            f"Saved {len(parsed_patches)} patches."
        )


if __name__ == "__main__":

    INPUT_FILE = (
        "backend/output/asb_references_raw.json"
    )

    OUTPUT_FILE = (
        "backend/output/aosp_patches.json"
    )

    parser = PatchParser()

    parser.process_patches(
        INPUT_FILE,
        OUTPUT_FILE
    )