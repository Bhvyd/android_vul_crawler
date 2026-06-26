from pathlib import Path
import json

BASE_DIR = Path(__file__).resolve().parents[2]

RAW_DIR = BASE_DIR / "data_vendor" / "raw_vendor"
NORMALIZED_DIR = BASE_DIR / "data_vendor" / "normalized"

latest_run = max(
    [d for d in RAW_DIR.iterdir() if d.is_dir()],
    key=lambda p: p.name
)

RUN_DIR = NORMALIZED_DIR / latest_run.name
bulletin_cves_file = RUN_DIR / "bulletin_cves.json"


def create_master_cve_list(bulletin_cves_file: Path) -> list[str]:
    with open(bulletin_cves_file, "r", encoding="utf-8") as f:
        records = json.load(f)

    unique_cves = {
        record["cve_id"]
        for record in records
        if record.get("cve_id")
    }

    return sorted(unique_cves)


master_cves = create_master_cve_list(bulletin_cves_file)

output_file = RUN_DIR / "master_cve_list.json"

print("RUN_DIR:", RUN_DIR)
print("bulletin_cves_file:", bulletin_cves_file)
print("Exists:", bulletin_cves_file.exists())

with open(output_file, "w", encoding="utf-8") as f:
    json.dump(master_cves, f, indent=2)

print(f"Unique CVEs: {len(master_cves)}")
print(f"Saved: {output_file}")






