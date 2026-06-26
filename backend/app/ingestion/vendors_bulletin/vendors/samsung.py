import json
import re
from datetime import date
from pathlib import Path
from playwright.sync_api import sync_playwright

# Import your shared schema
from vendors_bulletin.schema.cve import CVERecord

# ----------------------------------------
# Samsung Configuration
# ----------------------------------------

YEARS = [2022, 2023, 2024, 2025, 2026]

PAGE_URL = "https://security.samsungmobile.com/securityUpdate.smsb"

MONTH_MAP = {
    "JAN": 1, "FEB": 2, "MAR": 3, "APR": 4,
    "MAY": 5, "JUN": 6, "JUL": 7, "AUG": 8,
    "SEP": 9, "OCT": 10, "NOV": 11, "DEC": 12,
}


def bulletin_fields(month_year: str) -> tuple[str, date]:
    """
    Convert 'NOV-2022' → bulletin_id 'samsung-2022-11-01'
                        and bulletin_date date(2022, 11, 1).
    """
    parts = month_year.split("-")          # ['NOV', '2022']
    month_num = MONTH_MAP.get(parts[0], 1)
    year_num  = int(parts[1])
    bdate = date(year_num, month_num, 1)
    bid   = f"samsung-{year_num}-{month_num:02d}-01"
    return bid, bdate


SVE_BLOCK_RE = re.compile(
    r"(SVE-\d{4}-\d{4})\s*\(?(CVE-[\d-]+)\)?",
    re.IGNORECASE,
)

# Older bulletins (2022/2023) concatenate all fields on a single line with no
# newline separators. Every regex below is written to handle both:
#   - newline-separated (2024+): fields end at \n
#   - inline (2022/2023):        fields end at the next keyword
#
# _STOP is a lookahead used by fields whose values are free-form text.
_STOP = (
    r"(?="
    r"Severity\s*:"
    r"|Affected versions\s*:"
    r"|Reported on\s*:"
    r"|Disclosure status\s*:"
    r"|The patch\s"
    r"|SVE-\d{4}"
    r"|\Z"
    r")"
)

SEVERITY_RE = re.compile(r"Severity\s*:\s*(Critical|High|Moderate|Low)", re.IGNORECASE)
AFFECTED_RE = re.compile(r"Affected versions\s*:\s*(.+?)" + _STOP, re.IGNORECASE | re.DOTALL)
PATCH_RE    = re.compile(r"(The patch\s+.+?\.)" + _STOP,   re.IGNORECASE | re.DOTALL)

# Disclosure status has a fixed vocabulary — match only known values so the
# regex never bleeds into the description sentence that immediately follows.
DISCLOSURE_RE = re.compile(
    r"Disclosure status\s*:\s*(Privately disclosed|Publicly disclosed|0-day)",
    re.IGNORECASE,
)


# ----------------------------------------------------
# Parsing helpers
# ----------------------------------------------------

def clean(text: str) -> str:
    """Collapse whitespace / newlines to a single space and strip."""
    return re.sub(r"\s+", " ", text).strip()


def guess_subcomponent(description: str, sve_id: str) -> str:
    """Extract subcomponent from 'in <Subcomponent> prior to SMR ...' pattern."""
    m = re.search(r"\bin\s+(.+?)\s+prior\s+to\b", description, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return sve_id


def extract_description(chunk: str) -> str:
    """
    Pull the vulnerability description — the sentence(s) between
    'Disclosure status: <known value>' and 'The patch ...'.
    Works for both newline-separated and inline formats.
    """
    after = re.split(
        r"Disclosure status\s*:\s*(?:Privately disclosed|Publicly disclosed|0-day)\s*",
        chunk,
        maxsplit=1,
        flags=re.IGNORECASE,
    )
    if len(after) < 2:
        return ""
    before_patch = re.split(r"The patch\s+", after[1], maxsplit=1, flags=re.IGNORECASE)
    desc = clean(before_patch[0])
    return desc if len(desc) > 10 else ""


def parse_html_text(full_text: str, year: int) -> list[CVERecord]:
    """
    Parse full page text into CVERecord objects.
    Splits by SMR-MON-YYYY section headers, then parses each SVE block.
    Only processes sections whose year matches the requested year to avoid
    cross-year duplication (the page returns all years in one response).
    """
    records = []

    sections = re.split(r"(SMR-[A-Z]{3}-\d{4})", full_text)

    current_month_year = None
    for part in sections:
        smr_match = re.match(r"SMR-([A-Z]{3}-\d{4})", part.strip())
        if smr_match:
            current_month_year = smr_match.group(1)  # e.g. "DEC-2025"
            continue

        if not current_month_year or not current_month_year.endswith(str(year)):
            continue

        if "SVE-" not in part:
            continue

        chunks = re.split(r"(?=SVE-\d{4}-\d{4})", part)
        for chunk in chunks:
            chunk = chunk.strip()
            if not chunk.startswith("SVE-"):
                continue

            header_match = SVE_BLOCK_RE.match(chunk)
            if not header_match:
                continue

            sve_id = header_match.group(1).upper()
            cve_id = header_match.group(2).upper()

            # Title: text on the header line after the CVE id
            first_line = chunk.split("\n", 1)[0]
            title_part = clean(first_line[header_match.end():].strip(": "))

            sev_m = SEVERITY_RE.search(chunk)
            severity = sev_m.group(1).capitalize() if sev_m else "Unknown"

            aff_m = AFFECTED_RE.search(chunk)
            affected = clean(aff_m.group(1)) if aff_m else ""

            disc_m = DISCLOSURE_RE.search(chunk)
            disclosure = disc_m.group(1).strip() if disc_m else "Privately disclosed"

            patch_m = PATCH_RE.search(chunk)
            patch_info = clean(patch_m.group(1)) if patch_m else ""

            description = extract_description(chunk)
            if not description:
                description = title_part

            subcomponent = guess_subcomponent(description, sve_id)

            bulletin_id, bulletin_date = bulletin_fields(current_month_year)

            vendor_advisory = "\n".join(filter(None, [
                f"Affected versions: {affected}",
                f"Disclosure status: {disclosure}",
                description,
                patch_info,
            ]))

            record = CVERecord(
                cve_id=cve_id,
                vendor="samsung",
                source_name="samsung_bulletin",
                bulletin_id=bulletin_id,
                bulletin_url=PAGE_URL,
                bulletin_date=bulletin_date,
                reference=PAGE_URL,
                severity=severity,
                vulnerability_type="Samsung Vulnerability and Exposure",
                subcomponent=subcomponent,
                description=description,
                affected_versions=affected,
                vendor_advisory=vendor_advisory,
                metadata={
                    "month_year": current_month_year,
                    "sve_id": sve_id,
                    "patch_information": patch_info,
                    "disclosure_status": disclosure,
                },
            )
            records.append(record)

    return records


# ----------------------------------------------------
# Main Execution Loop
# ----------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "vendor_bulletins_output"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

all_records: list[CVERecord] = []

with sync_playwright() as p:
    browser = p.chromium.launch(headless=False)
    page = browser.new_page()

    print("Opening Samsung Security Bulletin page...")
    page.goto(PAGE_URL)
    page.wait_for_load_state("networkidle")

    for year in YEARS:
        print(f"Processing {year}...")
        try:
            html = page.evaluate(
                """async (year) => {
                    const res = await fetch(window.location.href, {
                        method: "POST",
                        headers: {"Content-Type": "application/x-www-form-urlencoded"},
                        body: "year=" + year,
                        credentials: "include",
                    });
                    return res.text();
                }""",
                year,
            )
        except Exception as e:
            print(f"  Failed to fetch {year}: {e}")
            continue

        text = page.evaluate(
            """(html) => {
                const doc = new DOMParser().parseFromString(html, "text/html");
                return doc.body.innerText;
            }""",
            html,
        )

        records = parse_html_text(text, year)
        print(f"  Found {len(records)} SVE records for {year}.")
        all_records.extend(records)

    browser.close()

# ----------------------------------------
# Deduplicate
# ----------------------------------------
seen = set()
unique_records: list[CVERecord] = []

for record in all_records:
    key = (record.cve_id, record.metadata.get("month_year"), record.severity)
    if key not in seen:
        seen.add(key)
        unique_records.append(record)

json_serializable_output = [rec.model_dump(mode="json") for rec in unique_records]

# ----------------------------------------
# Save Output
# ----------------------------------------
json_output_file = OUTPUT_DIR / "samsung.json"
with open(json_output_file, "w", encoding="utf8") as f:
    json.dump(json_serializable_output, f, indent=4, ensure_ascii=False)

print()
print("Finished processing Samsung Bulletins!")
print(f"Saved {len(unique_records)} unique records to: {json_output_file}")