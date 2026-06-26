import requests
import json
from bs4 import BeautifulSoup

def scrape_samsung_api(years=["2022","2023","2024", "2025", "2026"], deep_parse=True):
    base_html_url = "https://semiconductor.samsung.com"
    api_url = "https://search.semiconductor.samsung.com/semi/search/query"
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "Origin": "https://semiconductor.samsung.com",
        "Referer": "https://semiconductor.samsung.com/"
    }
    
    dataset = []
    
    for year in years:
        print(f"\n=== Processing Year: {year} ===")
        
        # Loop through all 12 months for the given year
        for month in range(1, 13):
            month_str = f"{month:02d}"
            filter_code = f"U00004006{year}{month_str}"
            
            start_no = 0
            page_size = 10
            
            while True:
                params = {
                    "q": "",
                    "site": "semi",
                    "startno": str(start_no),
                    "num": str(page_size),
                    "filter": f"(SemiFilCode:{filter_code})",
                    "sort": "Newest",
                    "category": "support",
                    "stage": "live",
                    "subcategory": "product-security",
                    "pagetype": "start"
                }
                
                try:
                    response = requests.get(api_url, params=params, headers=headers, timeout=10)
                    if response.status_code != 200:
                        break
                        
                    data = response.json()
                    result_data = data.get("response", {}).get("resultData", {})
                    if not result_data:
                        break
                        
                    result_list = result_data.get("resultList", [])
                    
                    # Safe validation against null or non-dictionary lists
                    if not result_list or result_list[0] is None or not isinstance(result_list[0], dict):
                        break
                        
                    if "contentList" not in result_list[0]:
                        break
                        
                    content_list = result_list[0]["contentList"]
                    if not content_list or content_list is None:
                        break 
                    
                    print(f"  [Code {filter_code}] Found {len(content_list)} entries at index {start_no}...")
                    
                    for item in content_list:
                        if not item or not isinstance(item, dict):
                            continue
                            
                        relative_url = item.get("linkUrl", "")
                        full_url = f"{base_html_url}{relative_url}" if relative_url.startswith("/") else relative_url
                        
                        # Scaffold information parsing directly out of JSON context stream
                        cve_data = {
                            "url": full_url,
                            "cve_id": item.get("cveId", "N/A"),
                            "description": item.get("contDesc", "N/A"),
                            "affected_product": "N/A",
                            "affected_component": "N/A",
                            "severity": item.get("severity", "N/A"),
                            "reported_date": item.get("publishDt", "N/A"),
                            "acknowledgment": "N/A"
                        }
                        
                        # Layer 2 Execution: Dynamic details payload harvesting via BeautifulSoup
                        if deep_parse and relative_url:
                            try:
                                html_res = requests.get(full_url, headers=headers, timeout=10)
                                if html_res.status_code == 200:
                                    soup = BeautifulSoup(html_res.text, "html.parser")
                                    for row in soup.find_all("tr"):
                                        th = row.find("th") or row.find("td", class_="title")
                                        td = row.find("td")
                                        if th and td:
                                            text_label = th.get_text(strip=True).lower()
                                            if "affected product" in text_label:
                                                cve_data["affected_product"] = td.get_text(strip=True)
                                            elif "affected component" in text_label:
                                                cve_data["affected_component"] = td.get_text(strip=True)
                                            elif "acknowledgment" in text_label:
                                                cve_data["acknowledgment"] = td.get_text(strip=True)
                            except Exception as html_err:
                                print(f"    Warning: Could not deep-parse details for {full_url}: {html_err}")
                        
                        dataset.append(cve_data)
                        
                    # Advance data cursor pagination tracking
                    start_no += page_size
                    
                except Exception as api_err:
                    print(f"  Error querying API for filter code {filter_code}: {api_err}")
                    break
                    
    return dataset

if __name__ == "__main__":
    target_years = ["2022","2023","2024", "2025", "2026"]
    
    # Toggle deep_parse=False if you only need the high-level metadata (super fast)
    extracted_records = scrape_samsung_api(years=target_years, deep_parse=True)
    
    print(f"\nScraping complete. Collected {len(extracted_records)} total vulnerability records.")
    
    output_filename = "backend/app/ingestion/hardware_bulletins/hardware_output/samsung_security_cves.json"
    with open(output_filename, "w", encoding="utf-8") as f:
        json.dump(extracted_records, f, indent=4, ensure_ascii=False)
        
    print(f"Results successfully compiled into '{output_filename}'")