import json
import csv
import re
from playwright.sync_api import sync_playwright

# ----------------------------------------
# Motorola Guide IDs
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
# Parse bulletin text
# ----------------------------------------------------

def parse_tagless_text(text):

    rows = []

    m = re.search(
        r"Security patch updates on (\w+)\s+(\d{4})",
        text,
        re.I,
    )

    if not m:
        return rows

    month = MONTHS[m.group(1)]
    year = m.group(2)

    month_year = f"{year}-{month}"

    severity = None

    for line in text.splitlines():

        line = line.strip()

        if not line:
            continue

        if line in SEVERITIES:
            severity = line
            continue

        for cve in re.findall(r"CVE-\d{4}-\d+", line):

            rows.append(
                {
                    "cve_id": cve,
                    "month_year": month_year,
                    "severity": severity,
                }
            )

    return rows


# ----------------------------------------------------
# Main
# ----------------------------------------------------

with sync_playwright() as p:

    browser = p.chromium.launch(headless=False)

    page = browser.new_page()

    captured_payload = {}

    # Capture the ORIGINAL AJAX request
    def capture(request):

        if "getGuideAsArray" in request.url:

            data = request.post_data

            if data:

                from urllib.parse import parse_qs

                captured_payload.update(
                    {
                        k: v[0]
                        for k, v in parse_qs(data).items()
                    }
                )

    page.on("request", capture)

    print("Opening Motorola page...")

    page.goto(PAGE_URL)

    # Wait until the page performs the request
    page.wait_for_timeout(5000)

    if not captured_payload:
        raise RuntimeError(
            "Could not capture AJAX payload."
        )

    print("Captured payload.")

    context = page.context

    cookies = context.cookies()

    cookie_header = "; ".join(
        f"{c['name']}={c['value']}"
        for c in cookies
    )

    all_rows = []

    for year, guide in GUIDES.items():

        print(f"Processing {year}")

        payload = captured_payload.copy()

        payload["guideID"] = str(guide)

        response = page.request.post(
            API,
            form=payload,
            headers={
                "Cookie": cookie_header,
                "X-Requested-With": "xmlhttprequest",
            },
        )

        data = response.json()

        with open(
            f"motorola_{year}.json",
            "w",
            encoding="utf8",
        ) as f:
            json.dump(data, f, indent=2)

        questions = data.get("questions", [])

        for q in questions:

            text = q.get("taglessText", "")

            all_rows.extend(parse_tagless_text(text))

    browser.close()

# ----------------------------------------
# Remove duplicates
# ----------------------------------------

seen = set()

unique = []

for row in all_rows:

    key = (
        row["cve_id"],
        row["month_year"],
        row["severity"],
    )

    if key not in seen:

        seen.add(key)

        unique.append(row)

# ----------------------------------------
# Save JSON
# ----------------------------------------

with open(
    "motorola_security_bulletins.json",
    "w",
    encoding="utf8",
) as f:

    json.dump(unique, f, indent=4)

# ----------------------------------------
# Save CSV
# ----------------------------------------

with open(
    "motorola_security_bulletins.csv",
    "w",
    newline="",
    encoding="utf8",
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=[
            "cve_id",
            "month_year",
            "severity",
        ],
    )

    writer.writeheader()

    writer.writerows(unique)

print()
print("Finished")
print("Unique CVEs:", len(unique))