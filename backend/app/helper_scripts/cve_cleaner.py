import json
import csv
from pathlib import Path
from datetime import datetime

# ============================================================
# CONFIG
# ============================================================
BASE_DIR = Path(__file__).resolve().parents[2]
INPUT_ROOT = BASE_DIR / "data" / "raw_vendor"
run_dirs = [d for d in INPUT_ROOT.iterdir() if d.is_dir()]

latest_run = max(run_dirs, key=lambda p: p.name)

print(f"Processing: {latest_run}")

INPUT_DIR = latest_run
run_id = latest_run.name

OUTPUT_DIR = Path("data/normalized") / run_id
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)



# ============================================================
# HELPERS
# ============================================================

VALID_VENDORS = {
    "samsung",
    "google",
    "xiaomi",
    "oppo",
    "vivo",
    "motorola",
}


def normalize_vendor(vendor):
    return (vendor or "").strip().lower()


def normalize_cve(cve):
    return (cve or "").strip().upper()


def extract_date_parts(date_str):
    try:
        dt = datetime.strptime(date_str, "%Y-%m-%d")
        return dt.date().isoformat(), dt.year, dt.month
    except Exception:
        return None, None, None


import json
from pathlib import Path

def create_master_cve_list(run_dir: Path)-> list[str]:
    """
    Extract all unique cves from normalized vendors as we'll fetch info from nvd ,kev , epss etc from cve id. 
    so redundant info will be fetched with multiple times.
    
    """

    unique_cves=set()

    for json_file in run_dir.glob("*.json"):
        with open(json_file , 'r', encoding='utf-8') as f:
          data=json.load(f)

        if isinstance(data, dict):
            data=[data]

        for record in data:
            cve_id=record.get("cve_id")

            if cve_id:
                unique_cves.add(cve_id)

    return sorted(unique_cves)


# ============================================================
# STORAGE
# ============================================================

bulletins = []
bulletin_cves = []

seen_bulletins = set()
seen_links = set()

stats = {
    "files_processed": 0,
    "total_bulletins": 0,
    "unique_bulletins": 0,
    "total_cve_links": 0,
    "unique_cve_links": 0,
    "duplicate_bulletins_removed": 0,
    "duplicate_links_removed": 0,
    "vendors": {},
}

# ============================================================
# PROCESS FILES
# ============================================================

for json_file in INPUT_DIR.rglob("*.json"):

    try:
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        stats["files_processed"] += 1

        vendor = normalize_vendor(data.get("vendor"))

        if vendor not in VALID_VENDORS:
            print(f"Skipping invalid vendor: {vendor}")
            continue

        stats["vendors"].setdefault(vendor, 0)

        for bulletin in data.get("bulletins", []):

            stats["total_bulletins"] += 1

            bulletin_id = str(
                bulletin.get("bulletin_id", "")
            ).strip()

            if not bulletin_id:
                continue

            published_date, year, month = extract_date_parts(
                bulletin.get("bulletin_date")
            )

            bulletin_url = bulletin.get("bulletin_url")

            bulletin_key = (
                vendor,
                bulletin_id,
            )

            # ------------------------------------------------
            # BULLETINS
            # ------------------------------------------------

            if bulletin_key not in seen_bulletins:

                bulletins.append(
                    {
                        "vendor": vendor,
                        "bulletin_id": bulletin_id,
                        "published_date": published_date,
                        "year": year,
                        "month": month,
                        "bulletin_url": bulletin_url,
                    }
                )

                seen_bulletins.add(bulletin_key)

                stats["unique_bulletins"] += 1
                stats["vendors"][vendor] += 1

            else:
                stats["duplicate_bulletins_removed"] += 1

            # ------------------------------------------------
            # CVES
            # ------------------------------------------------

            cves = bulletin.get("cve_ids", [])

            # dedupe only INSIDE same bulletin
            cves = sorted(
                set(
                    normalize_cve(cve)
                    for cve in cves
                    if cve
                )
            )

            for cve in cves:

                stats["total_cve_links"] += 1

                link_key = (
                    vendor,
                    bulletin_id,
                    cve,
                )

                # remove only exact duplicate rows
                if link_key in seen_links:
                    stats["duplicate_links_removed"] += 1
                    continue

                bulletin_cves.append(
                    {
                        "vendor": vendor,
                        "bulletin_id": bulletin_id,
                        "published_date": published_date,
                        "year": year,
                        "month": month,
                        "cve_id": cve,
                        
                    }
                )

                seen_links.add(link_key)

                stats["unique_cve_links"] += 1

    except Exception as e:
        print(f"ERROR processing {json_file}: {e}")

# ============================================================
# CSV EXPORT
# ============================================================

with open(
    OUTPUT_DIR / "bulletins.csv",
    "w",
    newline="",
    encoding="utf-8",
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=[
            "vendor",
            "bulletin_id",
            "published_date",
            "year",
            "month",
            "bulletin_url",
        ],
    )

    writer.writeheader()
    writer.writerows(bulletins)

with open(
    OUTPUT_DIR / "bulletin_cves.csv",
    "w",
    newline="",
    encoding="utf-8",
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=[
            "vendor",
            "bulletin_id",
            "published_date",
            "year",
            "month",
            "cve_id",
            
        ],
    )

    writer.writeheader()
    writer.writerows(bulletin_cves)

# ============================================================
# JSON EXPORT
# ============================================================

with open(
    OUTPUT_DIR / "bulletins.json",
    "w",
    encoding="utf-8",
) as f:
    json.dump(
        bulletins,
        f,
        indent=2,
        ensure_ascii=False,
    )

with open(
    OUTPUT_DIR / "bulletin_cves.json",
    "w",
    encoding="utf-8",
) as f:
    json.dump(
        bulletin_cves,
        f,
        indent=2,
        ensure_ascii=False,
    )

# ============================================================
# REPORT
# ============================================================

with open(
    OUTPUT_DIR / "cleaning_report.json",
    "w",
    encoding="utf-8",
) as f:
    json.dump(
        stats,
        f,
        indent=2,
        ensure_ascii=False,
    )

# ============================================================
# SUMMARY
# ============================================================

print("=" * 60)
print("NORMALIZATION COMPLETE")
print("=" * 60)

print(f"Files Processed: {stats['files_processed']}")
print(f"Unique Bulletins: {stats['unique_bulletins']}")
print(f"Unique CVE Links: {stats['unique_cve_links']}")

print("\nOutput Directory:")
print(OUTPUT_DIR.resolve())