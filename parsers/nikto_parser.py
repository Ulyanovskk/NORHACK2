import re


class NiktoParser:

    def parse(self, raw: str) -> dict:
        findings = []
        target = ""
        ip = ""

        for line in raw.splitlines():
            line = line.strip()

            if line.startswith("+ Target IP:"):
                ip = line.replace("+ Target IP:", "").strip()
            elif line.startswith("+ Target Hostname:"):
                target = line.replace("+ Target Hostname:", "").strip()
            elif line.startswith("+ ") and not line.startswith("+ Target") \
                    and not line.startswith("+ Start Time") \
                    and not line.startswith("+ End Time") \
                    and not line.startswith("+ 0 host"):
                findings.append(line[2:].strip())

        return {
            "tool": "nikto",
            "target": target,
            "ip": ip,
            "findings": findings,
            "total": len(findings)
        }