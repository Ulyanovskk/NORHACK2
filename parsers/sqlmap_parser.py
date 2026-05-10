import re


class SqlmapParser:

    def parse(self, raw: str) -> dict:
        injectable = "injectable" in raw.lower()
        not_injectable = "not injectable" in raw.lower()

        params = re.findall(r"Parameter: '?(\S+?)'? \(", raw)
        dbms_match = re.search(r"back-end DBMS: (.+)", raw)
        db_match = re.findall(r"available databases \[\d+\]:\n((?:\[\*\] .+\n?)+)", raw)
        tables_match = re.findall(r"\[\*\] (.+)", raw)

        techniques = []
        tech_pattern = re.compile(r"Type: (.+)")
        for match in tech_pattern.finditer(raw):
            techniques.append(match.group(1).strip())

        return {
            "tool": "sqlmap",
            "injectable": injectable and not not_injectable,
            "vulnerable_params": list(set(params)),
            "dbms": dbms_match.group(1).strip() if dbms_match else "unknown",
            "techniques": list(set(techniques)),
            "databases": tables_match if db_match else []
        }