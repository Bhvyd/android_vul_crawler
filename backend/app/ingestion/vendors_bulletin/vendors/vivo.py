import json
import re
import requests
from datetime import date, datetime, timezone
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from pydantic import Field
from vendors_bulletin.schema.cve import CVERecord


class VivoBulletinCollector:
    SOURCE_NAME = "vivo_bulletin"
    VENDOR = "vivo"

    LIST_URL = "https://www.vivo.com/en/support/security-advisory-list"
    API_URL = "https://www.vivo.com/en/support/safeNoticePage"
    BASE_URL = "https://www.vivo.com"

    PAGE_SIZE = 20
    CVE_REGEX = re.compile(r"CVE-\d{4}-\d+")

    def extract_cves_from_html(self, html: str) -> list[str]:
        soup = BeautifulSoup(html, "lxml")
        text = soup.get_text()
        return sorted(set(self.CVE_REGEX.findall(text)))

    def _fetch_all_advisory_ids(
        self,
        headers: dict,
        max_advisories: int | None = None,
    ) -> list[str]:
        """Fetch all advisory IDs from Vivo's paginated API."""
        all_ids: list[str] = []
        page = 1

        while True:
            response = requests.get(
                self.API_URL,
                params={"pageNum": page, "pageSize": self.PAGE_SIZE},
                headers=headers,
                timeout=30,
            )
            response.raise_for_status()

            try:
                data = response.json()
            except Exception:
                break

            payload = data.get("data", {})
            items = payload.get("commSafeNotices", [])
            total = payload.get("total", 0)

            if not items:
                break

            for item in items:
                advisory_id = str(item.get("id", "")).strip()
                if advisory_id and advisory_id not in all_ids:
                    all_ids.append(advisory_id)

            if max_advisories is not None and len(all_ids) >= max_advisories:
                return all_ids[:max_advisories]

            if total and len(all_ids) >= total:
                break

            if len(items) < self.PAGE_SIZE:
                break

            page += 1

        return all_ids

    def _parse_vivo_html(self, html_content: str) -> dict:
        """
        Parses detailed fields from Vivo's Security Advisory HTML.
        Returns a dictionary with parsed fields.
        """
        soup = BeautifulSoup(html_content, "html.parser")
        parsed_data = {}

        page_text = soup.get_text(separator=" \n ")

        # 1. Vulnerability Type / Title
        title_node = soup.find(["h1", "h2"], text=re.compile(r"vulnerability", re.IGNORECASE)) or soup.find(class_="title")
        parsed_data["vulnerability_type"] = title_node.get_text(strip=True) if title_node else None

        # 2. Extract Timeline Dates
        orig_match = re.search(r"Original release date:\s*([\d-]+)", page_text, re.IGNORECASE)
        last_match = re.search(r"Last release date:\s*([\d-]+)", page_text, re.IGNORECASE)
        
        try:
            parsed_data["bulletin_date"] = datetime.strptime(orig_match.group(1), "%Y-%m-%d").date() if orig_match else date.today()
        except ValueError:
            parsed_data["bulletin_date"] = date.today()

        try:
            parsed_data["last_updated_date"] = datetime.strptime(last_match.group(1), "%Y-%m-%d").date() if last_match else None
        except ValueError:
            parsed_data["last_updated_date"] = None

        # 3. CVSS Elements & Severity
        cvss_match = re.search(r"CVSS\s*([\d\.]+).*?Score.*?([\d\.]+).*?[\(（]([^）\)]+)[\)）]", page_text, re.DOTALL | re.IGNORECASE)
        severity_match = re.search(r"Score.*?[\d\.]+\s*([a-zA-Z]+)", page_text, re.DOTALL | re.IGNORECASE) or re.search(r"Severity:\s*([a-zA-Z]+)", page_text, re.IGNORECASE)
        
        parsed_data["severity"] = severity_match.group(1).strip() if severity_match else None
        if cvss_match:
            parsed_data["cvss_score"] = float(cvss_match.group(2))
            parsed_data["cvss_vector"] = cvss_match.group(3).strip()
        else:
            score_fallback = re.search(r"Score\s*([\d\.]+)", page_text, re.IGNORECASE)
            parsed_data["cvss_score"] = float(score_fallback.group(1)) if score_fallback else None
            vector_fallback = re.search(r"([A-Z]+:[A-Z\/:\d\.]+)", page_text)
            parsed_data["cvss_vector"] = vector_fallback.group(1) if vector_fallback else None

        # 4. Description
        desc_match = re.search(r"Description\s*\n+(.*?)(?=\n+\s*(Software Versions|Affected|Source|FAQ|$))", page_text, re.DOTALL | re.IGNORECASE)
        parsed_data["description"] = desc_match.group(1).strip() if desc_match else None

        # 5. Affected Component and Scope (Upgraded Table Parsing Layer)
        parsed_data["subcomponent"] = None
        parsed_data["affected_versions"] = None
        parsed_data["fixed_versions"] = None

        table = soup.find("table")
        if table:
            rows = table.find_all("tr")
            for row in rows:
                cols = [ele.get_text(strip=True) for ele in row.find_all(["td", "th"])]
                
                # Avoid capturing the table headers like "Software", "Affected Version", etc.
                if cols and "software" in cols[0].lower():
                    continue
                
                # Check for standard 3-column rows
                if len(cols) >= 3:
                    parsed_data["subcomponent"] = cols[0]
                    parsed_data["affected_versions"] = cols[1]
                    parsed_data["fixed_versions"] = cols[2]
                    break  # Found the data row, we can stop
                
                # Edge case: If row text collapsed to 1-2 items due to missing td cells but contains data
                elif len(cols) == 1 and ("versions below" in cols[0].lower() or "earlier than" in cols[0].lower()):
                    # Try fallback regex tracking directly inside the cell block
                    text_block = cols[0]
                    parsed_data["subcomponent"] = text_block.split("Versions")[0].strip() if "Versions" in text_block else None
                    
        # Robust Fallback: If table logic extraction fails entirely, parse using regex match lines from page text
        if not parsed_data["affected_versions"]:
            # Capture lines contextually under 'Software Versions and Fixes' block
            version_match = re.search(r"(?:Versions below|earlier than)\s*([\d\.]+)", page_text, re.IGNORECASE)
            fixed_match = re.search(r"(?:Fixed Version|Fixed Versions):\s*(.*?)\n", page_text, re.IGNORECASE)
            
            # Smart String slicing based on your target text example
            if "PcSuite" in page_text:
                parsed_data["subcomponent"] = "PcSuite"
                pc_suite_match = re.search(r"PcSuite\s*Versions\s*below\s*([\d\.]+)\s*([\d\.]+)", page_text, re.IGNORECASE)
                if pc_suite_match:
                    parsed_data["affected_versions"] = f"Versions below {pc_suite_match.group(1)}"
                    parsed_data["fixed_versions"] = pc_suite_match.group(2)
                elif version_match:
                    parsed_data["affected_versions"] = f"Versions below {version_match.group(1)}"

        # 6. Source Credit
        source_match = re.search(r"Source\s*\n+(.*?)(?=\n+\s*(Update Records|FAQ|$))", page_text, re.DOTALL | re.IGNORECASE)
        parsed_data["source_credit"] = source_match.group(1).strip() if source_match else None

        return parsed_data

    def fetch_bulletins(
        self,
        max_advisories: int | None = None,
    ) -> list[CVERecord]:

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0 Safari/537.36"
            )
        }

        fetched_at = datetime.now(timezone.utc).isoformat()
        records: list[CVERecord] = []

        advisory_ids = self._fetch_all_advisory_ids(
            headers=headers,
            max_advisories=max_advisories,
        )

        for advisory_id in advisory_ids:
            advisory_url = urljoin(
                self.BASE_URL,
                f"/en/support/security-advisory-detail?id={advisory_id}",
            )

            try:
                response = requests.get(
                    advisory_url,
                    headers=headers,
                    timeout=30,
                )
                response.raise_for_status()
            except Exception:
                continue

            html = response.text
            cve_ids = self.extract_cves_from_html(html)
            if not cve_ids:
                cve_ids = sorted(set(self.CVE_REGEX.findall(html)))

            try:
                details = self._parse_vivo_html(html)
            except Exception:
                details = {}

            for cve in cve_ids:
                            records.append(
                                CVERecord(
                                    cve_id=cve,
                                    vendor=self.VENDOR,
                                    source_name=self.SOURCE_NAME,
                                    bulletin_id=f"vivo-advisory-{advisory_id}",
                                    bulletin_url=advisory_url,
                                    bulletin_date=details.get("bulletin_date"),
                                    severity=details.get("severity") or "High",
                                    vulnerability_type=details.get("vulnerability_type"),
                                    subcomponent=details.get("subcomponent"),
                                    reference=advisory_url,
                                    
                                    # Set custom fields as first-class metrics if schema allows them, 
                                    # and keep them up-to-date inside the metadata dict.
                                    cvss_score=details.get("cvss_score"),
                                    cvss_vector=details.get("cvss_vector"),
                                    description=details.get("description"),
                                    affected_versions=details.get("affected_versions"),
                                    fixed_versions=details.get("fixed_versions"),
                                    
                                    metadata={
                                        "fetched_at": fetched_at,
                                        "cvss_score": details.get("cvss_score"),
                                        "cvss_vector": details.get("cvss_vector"),
                                        "description": details.get("description"),
                                        "affected_versions": details.get("affected_versions"),
                                        "fixed_versions": details.get("fixed_versions"),
                                        "source_credit": details.get("source_credit"),
                                        "last_updated_date": str(details.get("last_updated_date")) if details.get("last_updated_date") else None
                                    }
                                )
                            )

        if not records:
            try:
                response = requests.get(self.LIST_URL, headers=headers, timeout=30)
                response.raise_for_status()
                list_cves = sorted(set(self.CVE_REGEX.findall(response.text)))

                for cve in list_cves:
                    records.append(
                        CVERecord(
                            cve_id=cve,
                            vendor=self.VENDOR,
                            source_name=self.SOURCE_NAME,
                            bulletin_id="vivo-advisory-list",
                            bulletin_url=self.LIST_URL,
                            bulletin_date=date.today(),
                            metadata={"fallback": "list_page_only", "fetched_at": fetched_at}
                        )
                    )
            except Exception:
                pass

        return records


if __name__ == "__main__":
    collector = VivoBulletinCollector()
    cve_records = collector.fetch_bulletins(max_advisories=None)

    output_data = [record.model_dump(mode="json") for record in cve_records]

    with open("vendors_bulletin/vendor_bulletins_output/vivo.json", "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=4, ensure_ascii=False)