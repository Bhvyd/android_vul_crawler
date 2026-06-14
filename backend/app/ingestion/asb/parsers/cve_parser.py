import os
import re
from pathlib import Path
import json
from bs4 import BeautifulSoup
from typing import List, Dict


class CVEParser:

    def _extract_bulletin_metadata(self, file_path: str):
        filename = os.path.basename(file_path)
        bulletin_id = os.path.splitext(filename)[0]

        match = re.search(r"(\d{4}-\d{2})", bulletin_id)
        bulletin_month = match.group(1) if match else "2025-01"

        return bulletin_id, bulletin_month

    def _determine_patch_level(
        self,
        component_group: str,
        bulletin_month: str
    ) -> str:
        group_lower = component_group.lower()

        if any(
            x in group_lower
            for x in [
                "framework",
                "system",
                "google play",
                "mainline",
                "modules"
            ]
        ):
            return f"{bulletin_month}-01"

        return f"{bulletin_month}-05"

    def _parse_versions(self, version_string: str) -> List[str]:
        if not version_string:
            return []

        version_string = version_string.strip()

        if version_string in ["—", "-", "N/A"]:
            return []

        versions = []
        for part in version_string.split(","):
            part = part.strip()
            if not part:
                continue

            part = re.sub(
                r"^android\s+",
                "",
                part,
                flags=re.I
            )
            versions.append(part)

        return versions


    def parse_file(self, file_path: str) -> List[Dict]:
        bulletin_id, bulletin_month = (
            self._extract_bulletin_metadata(file_path)
        )

        results = []

        if not os.path.exists(file_path):
            print(f"File not found: {file_path}")
            return results

        with open(file_path, "r", encoding="utf-8") as f:
            soup = BeautifulSoup(f.read(), "html.parser")


        headings = soup.find_all(["h3", "h4"])

        for heading in headings:
            component_group = heading.get_text(" ", strip=True)

            table = None
            node = heading.next_sibling
            while node:
                if getattr(node, "name", None) in ["h3", "h4"]:
                    break
                if getattr(node, "name", None) == "table":
                    table = node
                    break
                if getattr(node, "name", None) == "div":
                    nested_table = node.find("table")
                    if nested_table:
                        table = nested_table
                        break
                node = node.next_sibling

            if not table:
                continue

            header_row = table.find("tr")
            if not header_row:
                continue

            headers = [
                cell.get_text(" ", strip=True).lower()
                for cell in header_row.find_all(["th", "td"])
            ]

            if not headers:
                continue

            cve_idx = None
            references_idx = None
            component_idx = None
            subcomponent_idx = None
            type_idx = None
            severity_idx = None
            versions_idx = None

            for idx, header in enumerate(headers):
                if "cve" in header:
                    cve_idx = idx
                elif "reference" in header:
                    references_idx = idx
                elif "subcomponent" in header:
                    subcomponent_idx = idx
                elif header == "component":
                    component_idx = idx
                elif "type" in header:
                    type_idx = idx
                elif "severity" in header:
                    severity_idx = idx
                elif any(
                    x in header
                    for x in [
                        "updated aosp versions",
                        "aosp versions",
                        "android versions",
                        "affected versions",
                        "versions",
                        "version"
                    ]
                ):
                    versions_idx = idx

            if cve_idx is None:
                continue

            rows = table.find_all("tr")[1:]

            is_mainline = any(
                x in component_group.lower()
                for x in [
                    "google play",
                    "mainline",
                    "project mainline",
                    "modules"
                ]
            )

            patch_level = self._determine_patch_level(
                component_group,
                bulletin_month
            )

            for row in rows:
                cols = row.find_all(["td", "th"])

                if len(cols) <= cve_idx:
                    continue

                cve_text = cols[cve_idx].get_text(" ", strip=True)
                cve_ids = re.findall(r"CVE-\d{4}-\d+", cve_text, flags=re.I)

                if not cve_ids:
                    continue

                references = []
                if references_idx is not None and references_idx < len(cols):
                    ref_cell = cols[references_idx]

                    valid_links = [
                      link for link in ref_cell.find_all("a") 
                      if link.get("href") and not link.get("href").startswith("#")
                    ]
  
                    if valid_links:
                        for link in valid_links:
                            ref_id = link.get_text(strip=True)
                            ref_url = link.get("href")
                            if ref_id and ref_id not in ["-", "—", "N/A"]:
                                references.append({
                                    "id": ref_id,
                                    "url": ref_url
                                })
                    else:
                        fallback_text = ref_cell.get_text(" ", strip=True).replace("*", "").strip()
                        if fallback_text not in ["-", "—", "N/A", ""]:
                            for part in fallback_text.split():
                                references.append({
                                    "id": part,
                                    "url": None
                                })

                component_val = None
                if component_idx is not None and component_idx < len(cols):
                    component_val = cols[component_idx].get_text(" ", strip=True)
                    if component_val in ["-", "—", "N/A"]:
                        component_val = None

                subcomponent_val = None
                if subcomponent_idx is not None and subcomponent_idx < len(cols):
                    subcomponent_val = cols[subcomponent_idx].get_text(" ", strip=True)
                    if subcomponent_val in ["-", "—", "N/A"]:
                        subcomponent_val = None

                vulnerability_type = None
                if type_idx is not None and type_idx < len(cols):
                    vulnerability_type = cols[type_idx].get_text(" ", strip=True)

                severity = None
                if severity_idx is not None and severity_idx < len(cols):
                    severity = cols[severity_idx].get_text(" ", strip=True)

                versions = []
                if versions_idx is not None and versions_idx < len(cols):
                    version_text = cols[versions_idx].get_text(
                        separator=",",
                        strip=True
                    )
                    versions = self._parse_versions(version_text)

                for cve_id in cve_ids:
    
                    


                    results.append({
                        "cve_id": cve_id,
                        "bulletin_id": bulletin_id,
                        "patch_level": patch_level,
                        "severity": severity,
                        "vulnerability_type": vulnerability_type,
                        "component_group": component_group,
                        "component": component_val if component_val else (
                            "Google Play system updates" if is_mainline else component_group
                        ),
                        "subcomponent": subcomponent_val,
                        "affected_android_versions": versions,
                        "is_mainline": is_mainline,
                        "mainline_module": (
                            subcomponent_val if is_mainline else None
                        ),
                        "references": references
                    })

        return results


if __name__ == "__main__":
    parser = CVEParser()
    
    all_cves = []
    all_references = []
    
    html_dir = Path("backend/storage/raw/html")

    # 1. Parse unified records from the raw HTML targets
    for html_file in sorted(html_dir.glob("android-*.html")):
        print(f"Processing {html_file.name}...")
        try:
            raw_entries = parser.parse_file(str(html_file))
            print(f"  Found {len(raw_entries)} CVE records")
            
            # 2. Split the unified dictionary entry into two relational lists
            for entry in raw_entries:
                cve_id = entry["cve_id"]
                
                # Extract references array and build the standalone reference table objects
                for ref in entry.get("references", []):
                    ref_url = ref.get("url") or ""
                    
                    ref_type = "upstream_advisory"
                    if "googlesource.com" in ref_url:
                        ref_type = "aosp_patch"
                    elif "cisa.gov" in ref_url:
                        ref_type = "threat_intel"

                    all_references.append({
                        "cve_id": cve_id,
                        "reference_id": ref.get("id"),
                        "url": ref.get("url"),
                        "type": ref_type
                    })
                
                # Strip out the deep nested reference objects to form clean cve metadata
                cve_metadata = entry.copy()
                cve_metadata["reference_ids"] = [r.get("id") for r in entry.get("references", [])]
                del cve_metadata["references"]  # Drop the nested version
                
                all_cves.append(cve_metadata)

        except Exception as e:
            print(f"  Error processing {html_file.name}: {e}")

  
    # 3. Write data to separate structured storage targets
    output_dir = Path("backend/output")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    cve_file = output_dir / "asb_cves_raw.json"
    reference_file = output_dir / "asb_references_raw.json"

    with open(cve_file, "w", encoding="utf-8") as f:
        json.dump(all_cves, f, indent=2, ensure_ascii=False)
        
    with open(reference_file, "w", encoding="utf-8") as f:
        json.dump(all_references, f, indent=2, ensure_ascii=False)



    print(f"\nExport Complete!")
    print(f"  -> Saved {len(all_cves)} base metrics to {cve_file}")
    print(f"  -> Saved {len(all_references)} mapped links to {reference_file}")



