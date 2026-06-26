import json
from pathlib import Path

INPUT_DIR = Path("backend/app/ingestion/hardware_bulletins/hardware_output")
OUTPUT_FILE = Path("backend/app/ingestion/hardware_bulletins/hardware_master_cve.json")


def extract_cve(record):
    """Handles both dict and string formats"""
    if isinstance(record, dict):
        return record.get("cve_id")

    if isinstance(record, str):
        return record

    return None


def build_master_cve_list():
    unique_cves = set()

    for file in INPUT_DIR.glob("*.json"):
        with open(file, "r", encoding="utf-8") as f:
            records = json.load(f)

        # ensure iterable safety
        if isinstance(records, dict):
            records = records.get("cves", [])

        for record in records:
            cve = extract_cve(record)
            if cve:
                unique_cves.add(cve.strip())

    unique_cves = sorted(unique_cves)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(unique_cves, f, indent=2)

    print(f"Found {len(unique_cves)} unique CVEs")
    print(f"Saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    build_master_cve_list()