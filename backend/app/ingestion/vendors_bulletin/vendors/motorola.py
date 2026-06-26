import json
import re
from datetime import date
from pathlib import Path
from urllib.parse import parse_qs
from playwright.sync_api import sync_playwright

# Import your shared schema
from vendors_bulletin.schema.cve import CVERecord

# ----------------------------------------
# Motorola Configuration
# ----------------------------------------

GUIDES = {
    2022: 7053,
    2023: 7979,
    2024: 8094,
    2025: 8155,
    2026: 8201,
}

PAGE_URL = (
    "https://en-in.support.motorola.com/app/software-security-update_link/g_id/6853"
)

API = (
    "https://en-in.support.motorola.com/"
    "ci/ajax/widget/custom/knowledgebase/"
    "GuidedAssistantSecurityLink/getGuideAsArray"
)

MONTHS = {
    "January": "01",
    "February": "02",
    "March": "03",
    "April": "04",
    "May": "05",
    "June": "06",
    "July": "07",
    "August": "08",
    "September": "09",
    "October": "10",
    "November": "11",
    "December": "12",
}

SEVERITIES = {
    "Critical",
    "High",
    "Moderate",
    "Low",
}


# ----------------------------------------------------
# Parse bulletin text into CVERecord objects
# ----------------------------------------------------

def parse_tagless_text(text: str, guide_id: int) -> list[CVERecord]:
    records = []

    m = re.search(
        r"Security patch updates on (\w+)\s+(\d{4})",
        text,
        re.I,
    )

    if not m:
        return records

    month_str = m.group(1).capitalize()
    year_str = m.group(2)

    try:
        month_num = int(MONTHS[month_str])
        bulletin_date_obj = date(int(year_str), month_num, 1)
    except KeyError:
        return records

    bulletin_id_str = f"motorola-{year_str}-{MONTHS[month_str]:02s}"
    severity = "Unknown"

    for line in text.splitlines():
        line = line.strip()

        if not line:
            continue

        if line.capitalize() in SEVERITIES:
            severity = line.capitalize()
            continue

        for cve in re.findall(r"CVE-\d{4}-\d+", line):
            record = CVERecord(
                cve_id=cve,
                vendor="motorola",
                source_name="motorola_bulletin",
                bulletin_id=bulletin_id_str,
                bulletin_url=PAGE_URL,
                bulletin_date=bulletin_date_obj,
                severity=severity,
                metadata={"guide_id": guide_id}
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

    captured_payload = {}

    def capture(request):
        if "getGuideAsArray" in request.url:
            data = request.post_data
            if data:
                captured_payload.update(
                    {
                        k: v[0]
                        for k, v in parse_qs(data).items()
                    }
                )

    page.on("request", capture)
    print("Opening Motorola page...")
    page.goto(PAGE_URL)

    page.wait_for_timeout(5000)

    if not captured_payload:
        browser.close()
        raise RuntimeError("Could not capture AJAX payload.")

    print("Captured payload.")

    context = page.context
    cookies = context.cookies()
    cookie_header = "; ".join(f"{c['name']}={c['value']}" for c in cookies)

    for year, guide in GUIDES.items():
        print(f"Processing {year}...")
        payload = captured_payload.copy()
        payload["guideID"] = str(guide)

        try:
            response = page.request.post(
                API,
                form=payload,
                headers={
                    "Cookie": cookie_header,
                    "X-Requested-With": "xmlhttprequest",
                },
            )
            data = response.json()
        except Exception as e:
            print(f"Failed to fetch data for year {year}: {e}")
            continue

        questions = data.get("questions", [])
        for q in questions:
            text = q.get("taglessText", "")
            all_records.extend(parse_tagless_text(text, guide))

    browser.close()

# ----------------------------------------
# Deduplicate using Schema fields
# ----------------------------------------
seen = set()
unique_records: list[CVERecord] = []

for record in all_records:
    key = (record.cve_id, record.bulletin_id, record.severity)
    if key not in seen:
        seen.add(key)
        unique_records.append(record)

# Convert instances to clean JSON-serializable dictionaries
json_serializable_output = [rec.model_dump(mode="json") for rec in unique_records]

# ----------------------------------------
# Save Unified JSON Output Only
# ----------------------------------------
json_output_file = OUTPUT_DIR / "motorola.json"
with open(json_output_file, "w", encoding="utf8") as f:
    json.dump(json_serializable_output, f, indent=4, ensure_ascii=False)

print()
print("Finished processing Motorola Bulletins!")
print(f"Saved {len(unique_records)} unique records directly to: {json_output_file}")