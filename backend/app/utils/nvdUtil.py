import nvdlib
from datetime import datetime
import json


def parse_cpe_product_version(cpe_str):
    """
    Parses a CPE string to extract product and version info.
    CPE format: cpe:2.3:[part]:[vendor]:[product]:[version]:[update]:[edition]:[language]:[sw_edition]:[target_sw]:[target_hw]:[other]
    """
    if not cpe_str:
        return None
    parts = cpe_str.split(':')
    if len(parts) < 5:
        return None
    vendor = parts[3] if parts[3] != '*' else 'unknown'
    product = parts[4] if parts[4] != '*' else 'unknown'
    version = parts[5] if parts[5] != '*' else 'any'
    return {
        'vendor': vendor,
        'product': product,
        'version': version
    }


def extract_patch_date_from_references(references):
    """
    Attempts to extract a patch/release date from references.
    Looks for dates in titles or URLs (heuristic: YYYY-MM-DD or similar).
    Returns the earliest plausible patch date or None.
    """
    import re
    date_pattern = r'\d{4}-\d{2}-\d{2}'  # YYYY-MM-DD
    patch_dates = []

    for ref in references:
        # print(ref)
        text = f"{ref.source} {ref.url}".lower()
        # Keywords indicating patch/advisory
        if any(keyword in text for keyword in ['patch', 'advisory', 'fixed', 'update', 'release']):
            matches = re.findall(date_pattern, text)
            for match in matches:
                try:
                    patch_date = datetime.strptime(match, '%Y-%m-%d')
                    patch_dates.append(patch_date)
                except ValueError:
                    pass

    if patch_dates:
        return min(patch_dates)  # Earliest patch date
    return None


def search_nvd_enhanced(cve_id):
    """
    Enhanced NVD query: Fetches CVE details including affected products/versions,
    approximates discovery date (published), and extracts patch date from references.

    Args:
        cve_id (str): The CVE ID (e.g., 'CVE-2021-44228').

    Returns:
        dict: Enhanced CVE info, or None if not found/error.
    """
    try:
        results = nvdlib.searchCVE(cveId=cve_id)
        print(results)
        if not results:
            print(f"No results found for {cve_id}")
            return None

        vuln = results[0]

        cwe_category = ''
        if 'weaknesses' in vuln:
            primary_weakness = next((w for w in vuln.weaknesses if w.type == 'Primary'), None)
            if primary_weakness and primary_weakness.description:
                cwe_desc = primary_weakness.description[0].value if primary_weakness.description else ''
                cwe_category = f"{cwe_desc}"

        # Basic info
        vuln_info = {
            'id': vuln.id,
            'description': vuln.descriptions[0].value if vuln.descriptions else 'N/A',
            'published': getattr(vuln, 'published', 'N/A'),  # Proxy for discovery date
            'last_modified': getattr(vuln, 'lastModified', 'N/A'),
            'severity': getattr(vuln, 'v31severity', 'N/A'),
            'score': getattr(vuln, 'v31score', 'N/A'),
            'affected_products': [],
            'patch_date': None,
            'discovery_vs_patch_days': None,  # Days between discovery and patch
            'cwe_category': cwe_category
        }

        # Affected products from configurations (CPEs)
        if hasattr(vuln, 'configurations') and vuln.configurations:
            for config in vuln.configurations:
                if hasattr(config, 'nodes') and config.nodes:
                    for node in config.nodes:
                        if hasattr(node, 'cpeMatch') and node.cpeMatch:
                            for cpe_match in node.cpeMatch:
                                cpe_info = parse_cpe_product_version(cpe_match.criteria)
                                if cpe_info:
                                    vuln_info['affected_products'].append(cpe_info)

        # Deduplicate products
        unique_products = {json.dumps(p, sort_keys=True): p for p in vuln_info['affected_products']}
        vuln_info['affected_products'] = list(unique_products.values())

        # Patch date from references
        if hasattr(vuln, 'references') and vuln.references:
            vuln_info['patch_date'] = extract_patch_date_from_references(vuln.references)

        # Calculate days diff (if patch date found)
        if vuln_info['published'] != 'N/A' and vuln_info['patch_date']:
            try:
                disc_date = datetime.fromisoformat(vuln_info['published'].replace('Z', '+00:00'))
                patch_dt = vuln_info['patch_date']
                vuln_info['discovery_vs_patch_days'] = (patch_dt - disc_date).days
            except ValueError:
                pass

        return vuln_info

    except Exception as e:
        print(f"Error querying NVD: {e}")
        return None