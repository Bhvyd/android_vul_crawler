from pathlib import Path

from nvd_fetch import NVDFetcher


def load_failed_cves():
    failed_file = Path("output/nvd_failed.txt")

    if not failed_file.exists():
        print("No failed CVEs file found.")
        return []

    with open(failed_file, "r", encoding="utf-8") as f:
        cves = [
            line.strip()
            for line in f
            if line.strip()
        ]

    return sorted(set(cves))


def main():

    failed_cves = load_failed_cves()

    print(
        f"Retrying {len(failed_cves)} failed CVEs"
    )

    fetcher = NVDFetcher(
        output_dir="storage/raw/nvd",
        max_workers=5,
        delay=0.2,
        api_key="abcd"
    )

    fetcher.run(failed_cves)


if __name__ == "__main__":
    main()