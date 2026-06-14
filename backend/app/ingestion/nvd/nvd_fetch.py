import json
import os
import time
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
        max_workers=10,
        delay=0.1,
        api_key="3966ec1d-63f4-40f7-ae23-a6dd3419ffca",
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.max_workers = max_workers
        self.delay = delay

        self.session = requests.Session()

        retry_strategy = Retry(
            total=5,
            backoff_factor=2,
            status_forcelist=[
                429,
                500,
                502,
                503,
                504,
            ],
            allowed_methods=["GET"],
        )

        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=20,
            pool_maxsize=20,
        )

        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

        self.headers = {
            "User-Agent": "Android-Vulnerability-Intel/1.0"
        }

        if api_key:
            self.headers["apiKey"] = api_key

    def fetch_cve(self, cve_id: str):

        output_file = self.output_dir / f"{cve_id}.json"

        if output_file.exists():
            return f"[SKIP] {cve_id}"

        try:
            response = self.session.get(
                self.BASE_URL,
                params={"cveId": cve_id},
                headers=self.headers,
                timeout=30,
            )

            response.raise_for_status()

            data = response.json()

            with open(
                output_file,
                "w",
                encoding="utf-8"
            ) as f:
                json.dump(
                    data,
                    f,
                    indent=2,
                    ensure_ascii=False
                )

            time.sleep(self.delay)

            return f"[OK] {cve_id}"

        except Exception as e:

            with open(
                "output/nvd_failed.txt",
                "a",
                encoding="utf-8"
            ) as f:
                f.write(f"{cve_id}\n")

            return f"[ERROR] {cve_id}: {e}"

    def run(self, cve_list):

        Path("output").mkdir(
            parents=True,
            exist_ok=True
        )

        with ThreadPoolExecutor(
            max_workers=self.max_workers
        ) as executor:

            futures = [
                executor.submit(
                    self.fetch_cve,
                    cve
                )
                for cve in cve_list
            ]

            for future in tqdm(
                as_completed(futures),
                total=len(futures),
                desc="Fetching NVD CVEs"
            ):
                result = future.result()

                if result.startswith("[ERROR]"):
                    print(result)


def load_cves(path):

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as f:

        data = json.load(f)

    if isinstance(data, dict):
        return data["cves"]

    return data


def main():
    
    api_key="3966ec1d-63f4-40f7-ae23-a6dd3419ffca"

    if not api_key:
        print(
            "[WARNING] NVD_API_KEY not found. "
            "Running without API key."
        )

    cve_list = load_cves(
        "output/asb_master_cve_list.json"
    )

    print(
        f"Loaded {len(cve_list)} CVEs"
    )

    fetcher = NVDFetcher(
        output_dir="storage/raw/nvd",
        max_workers=10,
        delay=0.1,
        api_key=api_key,
    )

    fetcher.run(cve_list)

    print("Done.")


if __name__ == "__main__":
    main()