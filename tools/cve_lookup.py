import requests


class CVELookup:
    """
    Lookup CVE depuis NVD API v2.
    Gratuit, pas de clé requise pour usage basique.
    """

    NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def search_by_keyword(self, keyword: str, max_results: int = 5) -> list:
        """Recherche CVE par mot-clé (ex: 'apache 2.4.49')"""
        try:
            resp = requests.get(
                self.NVD_URL,
                params={"keywordSearch": keyword, "resultsPerPage": max_results},
                timeout=10
            )
            if resp.status_code != 200:
                return []
            data = resp.json()
            return self._parse_results(data)
        except Exception:
            return []

    def get_cve(self, cve_id: str) -> dict:
        """Récupère un CVE précis par ID (ex: 'CVE-2021-44228')"""
        try:
            resp = requests.get(
                self.NVD_URL,
                params={"cveId": cve_id},
                timeout=10
            )
            if resp.status_code != 200:
                return {}
            data = resp.json()
            results = self._parse_results(data)
            return results[0] if results else {}
        except Exception:
            return {}

    def _parse_results(self, data: dict) -> list:
        results = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            desc = next(
                (d["value"] for d in descriptions if d["lang"] == "en"),
                "No description"
            )
            metrics = cve.get("metrics", {})
            score = None
            severity = None

            # CVSS v3 prioritaire
            cvss3 = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
            if cvss3:
                cvss_data = cvss3[0].get("cvssData", {})
                score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity")

            results.append({
                "id": cve_id,
                "description": desc[:300],
                "score": score,
                "severity": severity,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            })
        return results