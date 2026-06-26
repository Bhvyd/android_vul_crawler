import json
from pathlib import Path

INPUT_FILE = "backend/app/ingestion/hardware_bulletins/hardware_output/samsung_security_cves.json"


def extract_cve(item):
    """Try to extract CVE from multiple possible structures"""

    if isinstance(item, str):
        return item

    if isinstance(item, dict):
        return (
            item.get("cve")
            or item.get("cve_id")
            or item.get("id")
        )

    return None


def count_unique_cves(file_path):
    path = Path(file_path)

    if not path.exists():
        print(f"[ERROR] File not found: {file_path}")
        return

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    unique_cves = set()
    total = 0

    if isinstance(data, list):
        for item in data:
            total += 1
            cve = extract_cve(item)

            if cve and isinstance(cve, str):
                cve = cve.strip().upper()

                if cve.startswith("CVE-"):
                    unique_cves.add(cve)

    elif isinstance(data, dict) and "cves" in data:
        for item in data["cves"]:
            total += 1
            cve = extract_cve(item)

            if cve and isinstance(cve, str):
                cve = cve.strip().upper()

                if cve.startswith("CVE-"):
                    unique_cves.add(cve)

    else:
        print("[ERROR] Unsupported format")
        return

    print(f"Total items: {total}")
    print(f"Unique CVEs: {len(unique_cves)}")


if __name__ == "__main__":
    count_unique_cves(INPUT_FILE)