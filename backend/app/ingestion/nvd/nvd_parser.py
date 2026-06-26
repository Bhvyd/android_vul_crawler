import json
import re
from pathlib import Path


class NVDParser:

    def extract_description(self, cve):

        for d in cve.get("descriptions", []):

            if d.get("lang") == "en":
                return d.get("value", "")

        return ""

    def extract_cwe(self, cve):

        results = []

        for weakness in cve.get("weaknesses", []):

            source = weakness.get("source")

            for desc in weakness.get(
                "description",
                []
            ):

                value = desc.get("value", "")

                if value.startswith("CWE-"):

                    results.append({
                        "id": value,
                        "source": source
                    })

        return results

    def extract_references(self, cve):

        refs = []

        for ref in cve.get("references", []):

            refs.append({
                "url": ref.get("url"),
                "source": ref.get("source"),
                "tags": ref.get("tags", [])
            })

        return refs



    def extract_commits(self, cve):

        commits = []

        commit_regexes = [
            r"github\.com/.+/commit/[a-f0-9]+",
            r"gitlab\.com/.+/-/commit/[a-f0-9]+",
            r"git\.kernel\.org/.+/commit/\?id=[a-f0-9]+",
            r"android\.googlesource\.com/.+/\+/[a-f0-9]+",
            r"/commit/[a-f0-9]+",
        ]

        for ref in cve.get("references", []):

            url = str(
                ref.get("url", "")
            )

            if any(
                re.search(
                    pattern,
                    url,
                    re.IGNORECASE
                )
                for pattern in commit_regexes
            ):

                commits.append({
                    "url": url,
                    "source": ref.get("source")
                })

        return commits

    def extract_cvss(self, metrics):

        results = {}

        mapping = {
            "cvssMetricV2": "v2",
            "cvssMetricV30": "v3_0",
            "cvssMetricV31": "v3_1",
            "cvssMetricV40": "v4_0"
        }

        for key, label in mapping.items():

            if key not in metrics:
                continue

            if not metrics[key]:
                continue

            metric = metrics[key][0]

            cvss = metric.get(
                "cvssData",
                {}
            )

            results[label] = {

                "source": metric.get(
                    "source"
                ),

                "type": metric.get(
                    "type"
                ),

                "version": cvss.get(
                    "version"
                ),

                "base_score": cvss.get(
                    "baseScore"
                ),

                "severity": (
                    cvss.get("baseSeverity")
                    or metric.get(
                        "baseSeverity"
                    )
                ),

                "vector": cvss.get(
                    "vectorString"
                ),

                "attack_vector": cvss.get(
                    "attackVector"
                ),

                "attack_complexity": cvss.get(
                    "attackComplexity"
                ),

                "privileges_required": cvss.get(
                    "privilegesRequired"
                ),

                "user_interaction": cvss.get(
                    "userInteraction"
                ),

                "scope": cvss.get(
                    "scope"
                ),

                "confidentiality_impact": cvss.get(
                    "confidentialityImpact"
                ),

                "integrity_impact": cvss.get(
                    "integrityImpact"
                ),

                "availability_impact": cvss.get(
                    "availabilityImpact"
                ),

                "exploitability_score": metric.get(
                    "exploitabilityScore"
                ),

                "impact_score": metric.get(
                    "impactScore"
                )
            }

        return results

    def extract_cpes(self, configurations):

        cpes = []

        def walk(nodes):

            for node in nodes:

                for match in node.get(
                    "cpeMatch",
                    []
                ):

                    cpes.append({

                        "criteria": match.get(
                            "criteria"
                        ),

                        "vulnerable":
                            match.get(
                                "vulnerable",
                                True
                            ),

                        "version_start_including":
                            match.get(
                                "versionStartIncluding"
                            ),

                        "version_start_excluding":
                            match.get(
                                "versionStartExcluding"
                            ),

                        "version_end_including":
                            match.get(
                                "versionEndIncluding"
                            ),

                        "version_end_excluding":
                            match.get(
                                "versionEndExcluding"
                            )
                    })

                walk(
                    node.get(
                        "nodes",
                        []
                    )
                )

        walk(configurations)

        return cpes

    def extract_fixed_versions(
        self,
        configurations
    ):
        """
        Infer fixed versions from version ranges.

        Example:
        vulnerable <= 2.5.0
        fixed_after = 2.5.0
        """

        fixed_versions = []

        def walk(nodes):

            for node in nodes:

                for match in node.get(
                    "cpeMatch",
                    []
                ):

                    criteria = match.get(
                        "criteria"
                    )

                    if match.get(
                        "versionEndExcluding"
                    ):

                        fixed_versions.append({
                            "product": criteria,
                            "fixed_after":
                                match.get(
                                    "versionEndExcluding"
                                ),
                            "boundary_type":
                                "exclusive"
                        })

                    if match.get(
                        "versionEndIncluding"
                    ):

                        fixed_versions.append({
                            "product": criteria,
                            "fixed_after":
                                match.get(
                                    "versionEndIncluding"
                                ),
                            "boundary_type":
                                "inclusive"
                        })

                walk(
                    node.get(
                        "nodes",
                        []
                    )
                )

        walk(configurations)

        return fixed_versions

    def parse_file(self, path):

        with open(
            path,
            "r",
            encoding="utf-8"
        ) as f:

            raw = json.load(f)

        vulnerabilities = raw.get(
            "vulnerabilities",
            []
        )

        if not vulnerabilities:
            return None

        cve = vulnerabilities[0]["cve"]

        configurations = cve.get(
            "configurations",
            []
        )

        return {

            "cve_id":
                cve.get("id"),

            "source_identifier":
                cve.get(
                    "sourceIdentifier"
                ),

            "published":
                cve.get(
                    "published"
                ),

            "last_modified":
                cve.get(
                    "lastModified"
                ),

            "vuln_status":
                cve.get(
                    "vulnStatus"
                ),

            "description":
                self.extract_description(
                    cve
                ),

            "cvss":
                self.extract_cvss(
                    cve.get(
                        "metrics",
                        {}
                    )
                ),

            "cwe":
                self.extract_cwe(
                    cve
                ),

            "references":
                self.extract_references(
                    cve
                ),

            "commits":
                self.extract_commits(
                    cve
                ),

            "cpe_configurations":
                self.extract_cpes(
                    configurations
                ),

            "fixed_versions":
                self.extract_fixed_versions(
                    configurations
                ),

            "vendor_comments":
                cve.get(
                    "vendorComments",
                    []
                )
        }


def main():

    raw_dir = Path(
        "storage/raw/nvd"
    )

    output = []

    parser = NVDParser()

    for file in sorted(
        raw_dir.glob("*.json")
    ):

        try:

            parsed = parser.parse_file(
                file
            )

            if parsed:
                output.append(
                    parsed
                )

        except Exception as e:

            print(
                f"[ERROR] {file.name}: {e}"
            )

    Path("backend/output").mkdir(
        exist_ok=True
    )

    output_file = (
        Path("backend/output")
        / "nvd_parser.json"
    )

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            output,
            f,
            indent=2,
            ensure_ascii=False
        )

    print(
        f"Parsed {len(output)} CVEs"
    )

    print(
        f"Saved to {output_file}"
    )


if __name__ == "__main__":
    main()