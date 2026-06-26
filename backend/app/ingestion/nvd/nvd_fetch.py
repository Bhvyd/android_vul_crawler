import json
import os
import time
import threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from tqdm import tqdm


class NVDFetcher:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(
        self,
        output_dir="storage/raw/nvd",
        max_workers=5,
        api_key=None,
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.max_workers = max_workers
        self.api_key = api_key

        # Thread-safe lock for 429 global backoff
        self._rate_limit_lock = threading.Lock()
        self._rate_limited_until = 0.0

        # Per-thread sessions (requests sessions aren't thread-safe to share)
        self._local = threading.local()

    def _get_session(self):
        """One session per thread — no cross-thread contention."""
        if not hasattr(self._local, "session"):
            session = requests.Session()

            # Only retry on network errors / 5xx — NOT 429
            # We handle 429 manually with global backoff
            retry_strategy = Retry(
                total=3,
                backoff_factor=2,
                status_forcelist=[500, 502, 503, 504],
                allowed_methods=["GET"],
                raise_on_status=False,
            )
            adapter = HTTPAdapter(
                max_retries=retry_strategy,
                pool_connections=self.max_workers,
                pool_maxsize=self.max_workers,
            )
            session.mount("https://", adapter)
            session.mount("http://", adapter)

            headers = {"User-Agent": "NVD-CVE-Fetcher/1.0"}
            if self.api_key:
                headers["apiKey"] = self.api_key

            session.headers.update(headers)
            self._local.session = session

        return self._local.session

    def _wait_if_rate_limited(self):
        """Block thread until global rate limit window has passed."""
        with self._rate_limit_lock:
            now = time.time()
            if now < self._rate_limited_until:
                wait = self._rate_limited_until - now
                return wait  # caller will sleep outside the lock
        return 0.0

    def _set_rate_limit_backoff(self, seconds=30):
        """Set a global backoff window when any thread gets 429'd."""
        with self._rate_limit_lock:
            self._rate_limited_until = time.time() + seconds

    def fetch_cve(self, cve_id: str):
        """
        Fetch a single CVE. Returns a status tuple:
            ("skip", cve_id)      — already saved
            ("ok", cve_id)        — fetched and saved
            ("not_found", cve_id) — 404, CVE doesn't exist in NVD
            ("error", cve_id, e)  — network/parse error after retries
        """
        output_file = self.output_dir / f"{cve_id}.json"

        if output_file.exists():
            return ("skip", cve_id)

        session = self._get_session()
        max_429_retries = 6

        for attempt in range(max_429_retries):

            # Respect global rate limit before sending request
            wait = self._wait_if_rate_limited()
            if wait > 0:
                time.sleep(wait)

            try:
                response = session.get(
                    self.BASE_URL,
                    params={"cveId": cve_id},
                    timeout=30,
                )

                # ── 404: CVE simply doesn't exist ──────────────────────────
                if response.status_code == 404:
                    return ("not_found", cve_id)

                # ── 429: rate limited ───────────────────────────────────────
                if response.status_code == 429:
                    backoff = 30 * (attempt + 1)  # 30, 60, 90 ...
                    self._set_rate_limit_backoff(backoff)
                    time.sleep(backoff)
                    continue

                # ── Other non-200 ───────────────────────────────────────────
                if response.status_code != 200:
                    return (
                        "error",
                        cve_id,
                        f"HTTP {response.status_code}",
                    )

                # ── 200: parse and save ─────────────────────────────────────
                data = response.json()

                # NVD returns 200 with empty vulnerabilities for unknown CVEs
                if not data.get("vulnerabilities"):
                    return ("not_found", cve_id)

                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)

                return ("ok", cve_id)

            except requests.exceptions.RequestException as e:
                if attempt == max_429_retries - 1:
                    return ("error", cve_id, str(e))
                time.sleep(10 * (attempt + 1))

        return ("error", cve_id, "Exceeded max 429 retries")

    def run(self, cve_list: list[str]):
        output_dir = Path("output")
        output_dir.mkdir(parents=True, exist_ok=True)

        not_found_file = output_dir / "nvd_not_found.txt"
        failed_file = output_dir / "nvd_failed.txt"

        # Load already-known not-found and failed so we skip them on resume
        known_not_found = self._load_set(not_found_file)
        known_failed = self._load_set(failed_file)

        todo = [
            cve for cve in cve_list
            if cve not in known_not_found and cve not in known_failed
        ]

        print(f"Total CVEs      : {len(cve_list)}")
        print(f"Already saved   : {sum(1 for c in todo if (self.output_dir / f'{c}.json').exists())}")
        print(f"Known not found : {len(known_not_found)}")
        print(f"Known failed    : {len(known_failed)}")
        print(f"To fetch        : {len(todo)}")

        counts = {"ok": 0, "skip": 0, "not_found": 0, "error": 0}

        # File locks for thread-safe appending
        nf_lock = threading.Lock()
        err_lock = threading.Lock()

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self.fetch_cve, cve): cve
                for cve in todo
            }

            with tqdm(
                as_completed(futures),
                total=len(futures),
                desc="Fetching NVD CVEs",
            ) as pbar:
                for future in pbar:
                    result = future.result()
                    status = result[0]
                    cve_id = result[1]
                    counts[status] = counts.get(status, 0) + 1

                    if status == "not_found":
                        with nf_lock:
                            with open(not_found_file, "a") as f:
                                f.write(f"{cve_id}\n")

                    elif status == "error":
                        error_msg = result[2] if len(result) > 2 else "unknown"
                        tqdm.write(f"[ERROR] {cve_id}: {error_msg}")
                        with err_lock:
                            with open(failed_file, "a") as f:
                                f.write(f"{cve_id}\n")

                    pbar.set_postfix(counts, refresh=False)

        print("\n── Summary ──────────────────────────────")
        print(f"  Fetched (new) : {counts['ok']}")
        print(f"  Skipped       : {counts['skip']}")
        print(f"  Not found     : {counts['not_found']}")
        print(f"  Errors        : {counts['error']}")
        print(f"  Saved to      : {self.output_dir}")

    @staticmethod
    def _load_set(path: Path) -> set:
        if not path.exists():
            return set()
        with open(path, "r") as f:
            return {line.strip() for line in f if line.strip()}


def load_cves(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        return data["cves"]
    return data


def main():
    api_key = os.getenv("NVD_API_KEY", "3966ec1d-63f4-40f7-ae23-a6dd3419ffca")

    if api_key == "3966ec1d-63f4-40f7-ae23-a6dd3419ffca":
        print("[WARNING] Set NVD_API_KEY env variable or replace in code.")

    cve_list = load_cves("output/master_cve_list.json")
    print(f"Loaded {len(cve_list)} CVEs from master list")

    fetcher = NVDFetcher(
        output_dir="storage/raw/nvd",
        max_workers=5,       # NVD allows ~50 req/30s with API key; 5 workers + no delay is safe
        api_key=api_key,
    )

    fetcher.run(cve_list)


if __name__ == "__main__":
    main()