import nvdlib as nvd
import pandas as pd
from datetime import datetime

# Initialize NVD client (add api_key='your_key_here' for higher rate limits)
# nvd = nvdlib.NVDClient()

# Keywords for Android apps/kernels (customize as needed)
keywords = ['android', 'android kernel']  # Or specific: 'android webview'

all_cves = []
for keyword in keywords:
    print(f"Fetching CVEs for '{keyword}'...")
    cves = nvd.searchCVE(
        keywordSearch=keyword,
        # cvssV2Severity='MEDIUM',  # Filter by severity
        # resultsPerPage=2000,
        # pubStartDate='2020-01-01 00:00',  # Filter by publish date
        # pubEndDate=datetime.now().strftime('%Y-%m-%d %H:%M')
    )
    
    for cve in cves:
        # Extract primary CWE category
        cwe_category = ''
        if 'weaknesses' in cve:
            primary_weakness = next((w for w in cve.weaknesses if w.type == 'Primary'), None)
            if primary_weakness and primary_weakness.description:
                cwe_desc = primary_weakness.description[0].value if primary_weakness.description else ''
                cwe_category = f"{cwe_desc}"  # e.g., "CWE-79: Improper Neutralization..."
        # print(cve)
        all_cves.append({
            'cve_id': cve.id,
            'description': cve.descriptions[0].value if cve.descriptions else '',
            'cvss_v3_score': cve.metrics.cvssData3.baseScore if cve.metrics and 'cvssData3' in cve.metrics else None,
            'affected_products': [config.criteria for config in cve.configurations[0].nodes[0].cpeMatch if 'configurations' in cve] if 'configurations' in cve else [],
            'published_date': cve.published,
            'references': [ref.url for ref in cve.references] if cve.references else [],
            'keyword': keyword,
            'cwe_category': int(cwe_category.split("-")[-1]) if cwe_category and cwe_category.startswith("CWE-") else None # New: CWE-based category
        })

# Deduplicate and save to CSV
df = pd.DataFrame(all_cves).drop_duplicates(subset=['cve_id'])
output_file = f"android_cves_with_categories_{datetime.now().strftime('%Y%m%d')}.csv"
df.to_csv(output_file, index=False)
print(f"Saved {len(df)} unique CVEs with categories to {output_file}")
