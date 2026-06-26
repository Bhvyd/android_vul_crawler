import os
import json
import logging
import time
import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

INPUT_FILE = "output/master_cve_list.json"
OUTPUT_FILE = "output/cisa_epss.json"
FAILED_FILE = "output/cisa_epss_failed.txt"

CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"


# ----------------------------
# Retry helper
# ----------------------------
def request_with_retry(url, params=None, retries=3, timeout=15, backoff=2):
    for attempt in range(1, retries + 1):
        try:
            response = requests.get(url, params=params, timeout=timeout)
            response.raise_for_status()
            return response.json()

        except Exception as e:
            logging.warning(f"[Attempt {attempt}/{retries}] Failed request: {url} | Error: {e}")

            if attempt < retries:
                sleep_time = backoff ** attempt
                time.sleep(sleep_time)

    return None


# ----------------------------
# Load CVEs
# ----------------------------
def extract_target_cves(file_path):
    if not os.path.exists(file_path):
        logging.error(f"Input file not found: {file_path}")
        return []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        logging.error(f"Malformed JSON: {e}")
        return []

    cve_ids = set()

    if isinstance(data, dict) and "cves" in data:
        for cve in data["cves"]:
            if isinstance(cve, str):
                cve_ids.add(cve.strip().upper())

    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and "cve_id" in item:
                cve_ids.add(item["cve_id"].strip().upper())
            elif isinstance(item, str):
                cve_ids.add(item.strip().upper())

    logging.info(f"Extracted {len(cve_ids)} CVEs")
    return list(cve_ids)


# ----------------------------
# Fetch CISA KEV
# ----------------------------
def fetch_cisa_lookup():
    logging.info("Fetching CISA KEV...")

    data = request_with_retry(CISA_URL)
    if not data:
        logging.error("CISA fetch failed after retries")
        return {}

    vulns = data.get("vulnerabilities", [])
    return {
        v["cveID"].strip().upper(): v
        for v in vulns
        if "cveID" in v
    }


# ----------------------------
# EPSS fetch with retry + failure tracking
# ----------------------------
def fetch_epss_scores(cve_list, chunk_size=60):
    logging.info(f"Fetching EPSS for {len(cve_list)} CVEs...")

    epss_lookup = {}
    failed_chunks = []

    for i in range(0, len(cve_list), chunk_size):
        chunk = cve_list[i:i + chunk_size]
        cve_param = ",".join(chunk)

        data = None

        for attempt in range(1, 4):
            try:
                response = requests.get(
                    EPSS_URL,
                    params={"cve": cve_param},
                    timeout=10
                )
                response.raise_for_status()
                data = response.json().get("data", [])
                break

            except Exception as e:
                logging.warning(
                    f"EPSS chunk {i} attempt {attempt}/3 failed: {e}"
                )
                time.sleep(2 ** attempt)

        # If still failed after retries
        if data is None:
            logging.error(f"EPSS chunk FAILED permanently: index {i}")
            failed_chunks.extend(chunk)
            continue

        for item in data:
            cve_id = item.get("cve")
            if cve_id:
                epss_lookup[cve_id.upper()] = {
                    "epss_score": float(item.get("epss", 0.0)),
                    "epss_percentile": float(item.get("percentile", 0.0))
                }

    return epss_lookup, failed_chunks


# ----------------------------
# Save failed list
# ----------------------------
def save_failed(failed_cves):
    if not failed_cves:
        return

    os.makedirs(os.path.dirname(FAILED_FILE), exist_ok=True)

    with open(FAILED_FILE, "w", encoding="utf-8") as f:
        for cve in failed_cves:
            f.write(cve + "\n")

    logging.warning(f"Saved {len(failed_cves)} failed CVEs → {FAILED_FILE}")


# ----------------------------
# Main
# ----------------------------
def main():
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    target_cves = extract_target_cves(INPUT_FILE)
    if not target_cves:
        logging.warning("No CVEs found.")
        return

    cisa_map = fetch_cisa_lookup()
    epss_map, failed_epss = fetch_epss_scores(target_cves)

    enriched = {}
    cisa_hits = 0

    for cve in target_cves:
        if cve in cisa_map:
            cisa_hits += 1

        epss = epss_map.get(cve, {"epss_score": None, "epss_percentile": None})

        enriched[cve] = {
            "cve_id": cve,
            "is_cisa_known_exploited": cve in cisa_map,
            "cisa_details": cisa_map.get(cve),
            "epss_score": epss["epss_score"],
            "epss_percentile": epss["epss_percentile"]
        }

    logging.info(f"CISA matches: {cisa_hits}/{len(target_cves)}")

    # Save output
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(enriched, f, indent=2)

    logging.info(f"Saved output → {OUTPUT_FILE}")

    # Save failed CVEs
    save_failed(failed_epss)


if __name__ == "__main__":
    main()