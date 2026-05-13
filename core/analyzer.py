import re
from pathlib import Path


class Analyzer:
    """
    Détecte le type d'output et extrait les informations clés
    avant envoi au LLM.
    """

    TOOL_SIGNATURES = {
        "nmap": [
            r"Nmap scan report",
            r"PORT\s+STATE\s+SERVICE",
            r"Starting Nmap"
        ],
        "gobuster": [
            r"Gobuster",
            r"/{1,}.*\(Status:",
            r"Progress:"
        ],
        "ffuf": [
            r"FUZZ",
            r"\[Status:",
            r":: Progress ::"
        ],
        "nikto": [
            r"Nikto",
            r"\+ Target IP:",
            r"\+ OSVDB"
        ],
        "sqlmap": [
            r"sqlmap",
            r"\[\*\] starting",
            r"injectable"
        ],
        "nuclei": [
            r"\[nuclei\]",
            r"\[CVE-",
            r"\[critical\]|\[high\]|\[medium\]"
        ],
        "hydra": [
            r"Hydra",
            r"\[DATA\]",
            r"login:"
        ],
        "whatweb": [
            r"WhatWeb",
            r"http.*\[",
        ],
        "dirb": [
            r"DIRB",
            r"GENERATED WORDS:",
            r"==> DIRECTORY:"
        ]
    }

    def detect_tool(self, raw_output: str) -> str:
        """Identifie quel outil a produit cet output."""
        for tool, patterns in self.TOOL_SIGNATURES.items():
            matches = sum(
                1 for p in patterns
                if re.search(p, raw_output, re.IGNORECASE)
            )
            if matches >= 1:
                return tool
        return "unknown"

    def extract_key_info(self, raw_output: str, tool: str) -> dict:
        """
        Extrait les informations structurées selon l'outil détecté.
        """
        if tool == "nmap":
            return self._extract_nmap(raw_output)
        elif tool == "gobuster":
            return self._extract_gobuster(raw_output)
        elif tool == "ffuf":
            return self._extract_ffuf(raw_output)
        elif tool == "nikto":
            return self._extract_nikto(raw_output)
        elif tool == "sqlmap":
            return self._extract_sqlmap(raw_output)
        elif tool == "nuclei":
            return self._extract_nuclei(raw_output)
        else:
            return {"raw": raw_output[:3000], "tool": tool}

    def _extract_nmap(self, output: str) -> dict:
        ports = []
        port_pattern = re.compile(
            r"(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)?\s*(.*)"
        )
        for match in port_pattern.finditer(output):
            ports.append({
                "port": match.group(1),
                "protocol": match.group(2),
                "state": match.group(3),
                "service": match.group(4) or "",
                "version": match.group(5).strip() or ""
            })

        os_match = re.search(r"OS details: (.+)", output)
        host_match = re.search(r"Nmap scan report for (.+)", output)

        return {
            "tool": "nmap",
            "host": host_match.group(1) if host_match else "",
            "os": os_match.group(1) if os_match else "unknown",
            "open_ports": [p for p in ports if p["state"] == "open"],
            "open_count": sum(1 for p in ports if p["state"] == "open"),
            "filtered_count": sum(1 for p in ports if p["state"] == "filtered"),
            "closed_count": sum(1 for p in ports if p["state"] == "closed")
        }

    def _extract_gobuster(self, output: str) -> dict:
        paths = []
        pattern = re.compile(r"(/{1,}\S+)\s+\(Status:\s*(\d+)\)")
        for match in pattern.finditer(output):
            paths.append({
                "path": match.group(1),
                "status": int(match.group(2))
            })
        interesting = [p for p in paths if p["status"] in [200, 301, 302, 403, 401]]
        return {
            "tool": "gobuster",
            "interesting_paths": interesting[:30],  # Limite à 30 pour économiser les tokens
            "total_found": len(paths)
        }

    def _extract_ffuf(self, output: str) -> dict:
        results = []
        pattern = re.compile(r"(\S+)\s+\[Status: (\d+),")
        for match in pattern.finditer(output):
            results.append({
                "word": match.group(1),
                "status": int(match.group(2))
            })
        return {"tool": "ffuf", "results": results}

    def _extract_nikto(self, output: str) -> dict:
        findings = []
        for line in output.splitlines():
            if line.startswith("+ ") and "OSVDB" not in line:
                findings.append(line[2:].strip())
        return {"tool": "nikto", "findings": findings}

    def _extract_sqlmap(self, output: str) -> dict:
        injectable = "injectable" in output.lower()
        params = re.findall(r"Parameter: (\S+)", output)
        dbms = re.search(r"back-end DBMS: (.+)", output)
        return {
            "tool": "sqlmap",
            "injectable": injectable,
            "vulnerable_params": params,
            "dbms": dbms.group(1) if dbms else "unknown"
        }

    def _extract_nuclei(self, output: str) -> dict:
        findings = []
        pattern = re.compile(
            r"\[(critical|high|medium|low|info)\]\s+\[(.+?)\]\s+(.+)"
        )
        for match in pattern.finditer(output):
            findings.append({
                "severity": match.group(1),
                "template": match.group(2),
                "target": match.group(3)
            })
        return {
            "tool": "nuclei",
            "findings": findings,
            "critical": [f for f in findings if f["severity"] == "critical"],
            "high": [f for f in findings if f["severity"] == "high"]
        }

    def prepare_for_llm(self, raw_output: str, tool_hint: str = "") -> dict:
        """
        Point d'entrée principal.
        Détecte, extrait, retourne tout prêt pour le LLM.
        """
        tool = tool_hint if tool_hint else self.detect_tool(raw_output)
        extracted = self.extract_key_info(raw_output, tool)
        
        # Si on a extrait des infos structurées, on réduit drastiquement le raw
        # pour éviter la redondance dans le prompt LLM
        clean_raw = raw_output[:1000] if not extracted else "Infos extraites incluses dans le JSON."
        
        return {
            "tool": tool,
            "extracted": extracted,
            "raw_summary": clean_raw
        }