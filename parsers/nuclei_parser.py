import re


class NucleiParser:

    def parse(self, raw: str) -> dict:
        findings = []
        pattern = re.compile(
            r"\[(critical|high|medium|low|info)\]\s+\[(.+?)\]\s+\[(.+?)\]\s+(.+)"
        )

        for match in pattern.finditer(raw):
            findings.append({
                "severity": match.group(1).lower(),
                "template": match.group(2),
                "type": match.group(3),
                "target": match.group(4).strip()
            })

        severity_order = ["critical", "high", "medium", "low", "info"]

        return {
            "tool": "nuclei",
            "findings": findings,
            "total": len(findings),
            "by_severity": {
                sev: [f for f in findings if f["severity"] == sev]
                for sev in severity_order
            }
        }