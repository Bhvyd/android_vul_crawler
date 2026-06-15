import os
import os
import json
import logging
import requests

# Configure clean logging output
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

INPUT_FILE = "output/asb_master_cve_list.json"
OUTPUT_FILE = "output/cisa_epss.json"

CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"

def extract_target_cves(file_path):
    """Reads the local ASB JSON file and targets the 'cves' key array."""
    if not os.path.exists(file_path):
        logging.error(f"Input file not found at: {file_path}")
        return []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        logging.error(f"Malformed JSON in input file: {e}")
        return []

    cve_ids = set()
    
    # Target your exact structure: a dictionary containing a "cves" list of strings
    if isinstance(data, dict) and "cves" in data and isinstance(data["cves"], list):
        logging.info(f"Detected primary master list format. Processing 'cves' array...")
        for cve in data["cves"]:
            if isinstance(cve, str):
                cve_ids.add(cve.strip().upper())
    
    # Fallback backup options if the file layout shifts in other subsystems
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and "cve_id" in item:
                cve_ids.add(item["cve_id"].strip().upper())
            elif isinstance(item, str):
                cve_ids.add(item.strip().upper())

    logging.info(f"Successfully extracted {len(cve_ids)} unique CVE targets from {file_path}")
    return list(cve_ids)

def fetch_cisa_lookup():
    """Fetches the complete CISA catalog and indexes it by CVE ID for fast lookups."""
    logging.info("Downloading live CISA KEV catalog...")
    try:
        response = requests.get(CISA_URL, timeout=15)
        response.raise_for_status()
        cisa_data = response.json()
    except Exception as e:
        logging.error(f"Failed to fetch CISA catalog: {e}")
        return {}

    vulnerabilities = cisa_data.get("vulnerabilities", [])
    return {v["cveID"].strip().upper(): v for v in vulnerabilities if "cveID" in v}

def fetch_epss_scores(cve_list, chunk_size=60):
    """Queries the First.org EPSS API in safe, comma-separated batch chunks."""
    logging.info(f"Querying EPSS metrics for {len(cve_list)} CVEs...")
    epss_lookup = {}
    
    for i in range(0, len(cve_list), chunk_size):
        chunk = cve_list[i:i + chunk_size]
        cve_param = ",".join(chunk)
        
        try:
            response = requests.get(EPSS_URL, params={"cve": cve_param}, timeout=10)
            response.raise_for_status()
            data = response.json().get("data", [])
            
            for item in data:
                cve_id = item.get("cve")
                if cve_id:
                    epss_lookup[cve_id.strip().upper()] = {
                        "epss_score": float(item.get("epss", 0.0)),
                        "epss_percentile": float(item.get("percentile", 0.0))
                    }
        except Exception as e:
            logging.error(f"Batch EPSS query failed for chunk index {i}: {e}")
            continue

    return epss_lookup

def main():
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    # 1. Gather local tracking list IDs from your "cves" array key
    target_cves = extract_target_cves(INPUT_FILE)
    if not target_cves:
        logging.warning("Pipeline exited: No target CVE targets resolved.")
        return

    # 2. Fetch external datasets
    cisa_map = fetch_cisa_lookup()
    epss_map = fetch_epss_scores(target_cves)

    # 3. Assemble the unified data profiles
    enriched_profiles = {}
    cisa_match_count = 0

    for cve in target_cves:
        has_cisa = cve in cisa_map
        if has_cisa:
            cisa_match_count += 1

        epss_info = epss_map.get(cve, {"epss_score": None, "epss_percentile": None})

        enriched_profiles[cve] = {
            "cve_id": cve,
            "is_cisa_known_exploited": has_cisa,
            "cisa_details": cisa_map[cve] if has_cisa else None,
            "epss_score": epss_info["epss_score"],
            "epss_percentile": epss_info["epss_percentile"]
        }

    logging.info(f"Compilation summary: Found {cisa_match_count} KEV matches out of {len(target_cves)} targets.")

    # 4. Save structured dashboard payload
    try:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(enriched_profiles, f, indent=2, ensure_ascii=False)
        logging.info(f"Unified intelligence profile dumped to: {OUTPUT_FILE}")
    except Exception as e:
        logging.error(f"Failed to write compiled profile data: {e}")

if __name__ == "__main__":
    main()