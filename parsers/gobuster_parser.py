import re


class GobusterParser:

    def parse(self, raw: str) -> dict:
        paths = []
        pattern = re.compile(r"(/{1,}\S*)\s+\(Status:\s*(\d+)\)(?:.*Size:\s*(\d+))?")

        for match in pattern.finditer(raw):
            paths.append({
                "path": match.group(1),
                "status": int(match.group(2)),
                "size": int(match.group(3)) if match.group(3) else None
            })

        interesting = [
            p for p in paths
            if p["status"] in [200, 201, 301, 302, 401, 403, 500]
        ]

        return {
            "tool": "gobuster",
            "total_found": len(paths),
            "paths": paths,
            "interesting": interesting,
            "auth_required": [p for p in paths if p["status"] == 401],
            "forbidden": [p for p in paths if p["status"] == 403],
            "redirects": [p for p in paths if p["status"] in [301, 302]]
        }