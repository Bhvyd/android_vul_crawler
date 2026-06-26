import json
from pathlib import Path

INPUT_FILE = Path("backend/output/asb_cves_raw.json")
OUTPUT_FILE = Path("backend/app/ingestion/asb/asb_master_cve_list.json")


def build_master_cve_list():
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        records = json.load(f)

    unique_cves = sorted({
        record["cve_id"].strip()
        for record in records
        if record.get("cve_id")
    })

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(unique_cves, f, indent=2)

    print(f"Found {len(unique_cves)} unique CVEs")
    print(f"Saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    build_master_cve_list()