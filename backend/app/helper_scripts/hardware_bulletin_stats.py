'''import json
from collections import Counter

INPUT_FILE = "backend/output/qualcomm_cves.json"
OUTPUT_FILE = "qualcomm_statistics.txt"

# -------------------------------------------------------
# Load JSON
# -------------------------------------------------------
with open(INPUT_FILE, "r", encoding="utf-8") as f:
    data = json.load(f)

# -------------------------------------------------------
# Basic Statistics
# -------------------------------------------------------
total_records = len(data)

unique_cves = len({
    d.get("cve_id")
    for d in data
    if d.get("cve_id")
})

unique_bulletins = len({
    d.get("bulletin_id")
    for d in data
    if d.get("bulletin_id")
})

# -------------------------------------------------------
# Counters
# -------------------------------------------------------
vuln_counter = Counter()
chipset_counter = Counter()
year_counter = Counter()
month_counter = Counter()
bulletin_counter = Counter()

# -------------------------------------------------------
# Populate Counters
# -------------------------------------------------------
for d in data:

    # Vulnerability Type
    vt = d.get("vulnerability_type")
    if not vt:
        vt = "Unknown"
    vuln_counter[vt] += 1

    # Bulletin Year
    year = d.get("bulletin_year")
    if not year:
        year = "Unknown"
    year_counter[year] += 1

    # Bulletin Month
    month = d.get("bulletin_month")
    if not month:
        month = "Unknown"
    month_counter[month] += 1

    # Bulletin ID
    bulletin = d.get("bulletin_id")
    if not bulletin:
        bulletin = "Unknown"
    bulletin_counter[bulletin] += 1

    # Chipsets
    chipsets = d.get("affected_chipsets", [])

    if isinstance(chipsets, list):
        for chipset in chipsets:
            chipset = str(chipset).strip()
            if chipset:
                chipset_counter[chipset] += 1

    elif isinstance(chipsets, str):
        for chipset in chipsets.split(","):
            chipset = chipset.strip()
            if chipset:
                chipset_counter[chipset] += 1

# -------------------------------------------------------
# Write Report
# -------------------------------------------------------
with open(OUTPUT_FILE, "w", encoding="utf-8") as out:

    out.write("Qualcomm Security Bulletin Statistics\n")
    out.write("=" * 80 + "\n\n")

    out.write(f"Total Records              : {total_records}\n")
    out.write(f"Unique CVEs                : {unique_cves}\n")
    out.write(f"Unique Bulletins           : {unique_bulletins}\n")
    out.write(f"Unique Vulnerability Types : {len(vuln_counter)}\n")
    out.write(f"Unique Chipsets            : {len(chipset_counter)}\n")
    out.write(f"Years Covered              : {len(year_counter)}\n\n")

    # ---------------------------------------------------
    # Vulnerability Types
    # ---------------------------------------------------
    out.write("=" * 80 + "\n")
    out.write("Vulnerability Type Distribution\n")
    out.write("=" * 80 + "\n")

    for vt, count in vuln_counter.most_common():
        out.write(f"{vt:<45} {count}\n")

    out.write("\n")

    # ---------------------------------------------------
    # Bulletin Years
    # ---------------------------------------------------
    out.write("=" * 80 + "\n")
    out.write("Bulletin Year Distribution\n")
    out.write("=" * 80 + "\n")

    for year, count in sorted(year_counter.items()):
        out.write(f"{year}: {count}\n")

    out.write("\n")

    # ---------------------------------------------------
    # Bulletin Months
    # ---------------------------------------------------
    out.write("=" * 80 + "\n")
    out.write("Bulletin Month Distribution\n")
    out.write("=" * 80 + "\n")

    for month, count in month_counter.items():
        out.write(f"{month:<15} {count}\n")

    out.write("\n")

    # ---------------------------------------------------
    # Bulletin IDs
    # ---------------------------------------------------
    out.write("=" * 80 + "\n")
    out.write("Bulletin IDs\n")
    out.write("=" * 80 + "\n")

    for bulletin, count in bulletin_counter.items():
        out.write(f"{bulletin:<25} {count}\n")

    out.write("\n")

    # ---------------------------------------------------
    # Affected Chipsets
    # ---------------------------------------------------
    out.write("=" * 80 + "\n")
    out.write("Affected Chipsets\n")
    out.write("=" * 80 + "\n")

    for chipset, count in chipset_counter.most_common():
        out.write(f"{count:5d}  {chipset}\n")

print(f"Statistics written to '{OUTPUT_FILE}'")'''


import json
from collections import Counter

INPUT_FILE = "backend/output/mediatek_cves.json"

# Count occurrences of each software version
version_counter = Counter()

with open(INPUT_FILE, "r", encoding="utf-8") as f:
    data = json.load(f)

for cve in data:
    versions = cve.get("affected_software_versions", [])

    for version in versions:
        version = version.strip()
        if version:
            version_counter[version] += 1

print("=" * 50)
print("Affected Software Version Statistics")
print("=" * 50)

for version, count in sorted(version_counter.items()):
    print(f"{version:<15} : {count}")

print("=" * 50)
print(f"Unique Software Versions : {len(version_counter)}")