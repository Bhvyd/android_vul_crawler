import requests
from bs4 import BeautifulSoup
import time
import pandas as pd
import csv
import random  # For random delays

# Updated headers as above
HEADERS = {  # Paste the headers here
    # ...
}


def create_session():
    """Create a session and warm it up by visiting homepage."""
    session = requests.Session()
    session.headers.update(HEADERS)
    # Warm up: Visit homepage to get cookies
    try:
        session.get("https://www.cvedetails.com", timeout=10)
        time.sleep(random.uniform(1, 3))  # Random delay
    except requests.RequestException:
        pass  # Continue if fails
    return session


def fetch_cve_list(session, product_url, max_pages=50):
    """
    Use session for requests to maintain cookies.
    """
    cve_ids = []
    page = 1
    while page <= max_pages:
        list_url = f"{product_url}/{page - 1}/" if page > 1 else product_url
        try:
            response = session.get(list_url, timeout=10)
            if response.status_code == 403:
                print(f"403 on {list_url}; retrying with delay...")
                time.sleep(10)  # Longer delay on error
                continue
            if response.status_code != 200:
                break
            soup = BeautifulSoup(response.content, 'lxml')
            rows = soup.find_all('tr', class_='srrowns')
            if not rows:
                break
            for row in rows:
                cve_link = row.find('a', href=lambda x: x and '/cve/' in x)
                if cve_link:
                    cve_id = cve_link.text.strip()
                    cve_ids.append(cve_id)
            print(f"Fetched page {page}: {len(rows)} CVEs")
        except requests.RequestException as e:
            print(f"Error on {list_url}: {e}")
            break
        page += 1
        time.sleep(random.uniform(3, 5))  # Random delay 3-5s
    return cve_ids[:100]


def fetch_cve_details(session, cve_id):
    """
    Use session for detail pages too.
    """
    detail_url = f"https://www.cvedetails.com/cve/{cve_id}/"
    try:
        response = session.get(detail_url, timeout=10)
        if response.status_code == 403:
            print(f"403 on {detail_url}; skipping.")
            return None
        if response.status_code != 200:
            return None
        soup = BeautifulSoup(response.content, 'lxml')
        # Rest of extraction code unchanged...
        # (Include the details extraction from previous script)
    except requests.RequestException:
        return None
    time.sleep(random.uniform(3, 5))
    return details  # Assuming 'details' from extraction


def main():
    session = create_session()
    # URLs unchanged
    android_url = "https://www.cvedetails.com/vulnerability-list/vendor_id-1224/product_id-19997/google-android.html"
    kernel_url = "https://www.cvedetails.com/vulnerability-list/vendor_id-1224/version_id-1864029/Google-Android-Kernel.html"

    print("Fetching Android OS CVEs...")
    android_ids = fetch_cve_list(session, android_url)
    print("Fetching Android Kernel CVEs...")
    kernel_ids = fetch_cve_list(session, kernel_url)
    all_ids = list(set(android_ids + kernel_ids))

    all_details = []
    for cve_id in all_ids:
        detail = fetch_cve_details(session, cve_id)
        if detail:
            all_details.append(detail)
        print(f"Processed {cve_id}")

    df = pd.DataFrame(all_details)
    df.to_csv('android_cve_details.csv', index=False, quoting=csv.QUOTE_ALL)
    print(f"Saved {len(all_details)} CVE details to android_cve_details.csv")
    session.close()


if __name__ == "__main__":
    main()
