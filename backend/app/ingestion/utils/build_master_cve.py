import json
from pathlib import Path

INPUT_FILES = [
    "backend/app/ingestion/asb/asb_master_cve_list.json",
    "backend/app/ingestion/hardware_bulletins/hardware_master_cve.json",
    "backend/app/ingestion/vendors_bulletin/vendors_bulletins_master_cve/vendor_master_cve_list.json",
]

OUTPUT_FILE = Path("output/master_cve_list.json")


def extract_cves(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    cves = set()

    # Case 1: already list of CVE strings
    if isinstance(data, list):
        for item in data:
            if isinstance(item, str):
                cves.add(item.strip())

            elif isinstance(item, dict):
                cve = item.get("cve_id")
                if cve:
                    cves.add(cve.strip())

    # Case 2: dict wrapper format (future-proof)
    elif isinstance(data, dict):
        for item in data.get("cves", []):
            if isinstance(item, str):
                cves.add(item.strip())
            elif isinstance(item, dict):
                cve = item.get("cve_id")
                if cve:
                    cves.add(cve.strip())

    return cves


def main():
    all_cves = set()

    for file in INPUT_FILES:
        path = Path(file)
        if path.exists():
            all_cves.update(extract_cves(path))

    unique = sorted(all_cves)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(unique, f, indent=2)

    print(f"Total unique CVEs: {len(unique)}")
    print(f"Saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()