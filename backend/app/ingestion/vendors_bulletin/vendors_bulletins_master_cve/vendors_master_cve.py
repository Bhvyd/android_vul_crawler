import json
from pathlib import Path

# Folder containing all vendor JSON files
INPUT_DIR = Path("backend/app/ingestion/vendors_bulletin/vendor_bulletins_output")

# Output file
OUTPUT_FILE = Path("backend/app/ingestion/vendors_bulletin/vendors_bulletins_master_cve/vendor_master_cve_list.json")


def collect_unique_cves(input_dir: Path):
    unique_cves = set()

    for json_file in input_dir.glob("*.json"):
        print(f"Processing {json_file.name}")

        try:
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            if not isinstance(data, list):
                print(f"  Skipping {json_file.name}: expected a list of records.")
                continue

            for record in data:
                cve = record.get("cve_id")
                if cve:
                    unique_cves.add(cve.strip())

        except Exception as e:
            print(f"  Error reading {json_file.name}: {e}")

    return sorted(unique_cves)


def main():
    unique_cves = collect_unique_cves(INPUT_DIR)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(unique_cves, f, indent=4)

    print(f"\nFound {len(unique_cves)} unique CVEs.")
    print(f"Saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()