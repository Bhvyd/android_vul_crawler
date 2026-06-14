import requests
from bs4 import BeautifulSoup
import re
import pandas as pd
from nvdUtil import *

def extract_advisory_links(bulletin_url):
    """
    Web crawler to extract advisory links from an Android Security Bulletin page.

    Args:
    bulletin_url (str): URL of the Android Security Bulletin page (e.g., 'https://source.android.com/docs/security/bulletin/2025-09-01')

    Returns:
    list: List of dictionaries containing advisory links with their text and href.
    """
    # Fetch the page
    response = requests.get(bulletin_url)
    response.raise_for_status()  # Raise an error for bad status codes

    # Parse the HTML
    soup = BeautifulSoup(response.content, 'html.parser')

    # Find all tables (vulnerability tables are in <table> elements)
    bullets = soup.find_all('a', class_='devsite-nav-title gc-analytics-event', href=lambda x: x and '/bulletin/' in x)

    base_url = '/'.join(bulletin_url.split('/')[:3])
    print(base_url)

    links = []

    for bullet in bullets:
        links.append(base_url+bullet['href'])

    print(f"Extracting advisory links from {bulletin_url}")
    return links

def get_cve_list(links):
    result = set()
    print(f"Fetching CVEs for {len(links)} advisory links...")
    for i, link in enumerate(links):
        print(f"Stage {i}/{len(links)}...", end=' ')
        response = requests.get(link)
        response.raise_for_status()  # Raise an error for bad status codes

        # Parse the HTML
        soup = BeautifulSoup(response.content, 'html.parser')

        cve_pattern = r'CVE-\d{4}-\d{1,7}'
        text = soup.get_text(strip=True, separator=" ")

        cves = re.findall(cve_pattern, text)

        # print(f"Fetched {len(cves)} CVEs")
        result.update(cves)
        print("Done")
    print(f"Fetched {len(result)} CVEs")
    return sorted(list(result))


if __name__ == "__main__":
    links = extract_advisory_links('https://source.android.com/docs/security/bulletin/2025-09-01')
    cves = get_cve_list(links)
    all_data = []
    for cve in cves[:5000]:
        print(f"Fetching data for {cve}...")
        vuln_info = search_nvd_enhanced(cve)
        if vuln_info:
            all_data.append(vuln_info)

    if all_data:
        df = pd.DataFrame(all_data)
        # Flatten affected_products (list of JSON strings) if needed, but keep as single column for simplicity
        df.to_csv("cve_data_2.csv", index=False)
        print(f"Saved {len(all_data)} records to cve_data_2.csv")
    else:
        print("No data to save.")


