import re
import json


class FfufParser:

    def parse(self, raw: str) -> dict:
        # Essai parsing JSON (ffuf -o output.json)
        try:
            data = json.loads(raw)
            return self._parse_json(data)
        except (json.JSONDecodeError, ValueError):
            return self._parse_text(raw)

    def _parse_json(self, data: dict) -> dict:
        results = []
        for r in data.get("results", []):
            results.append({
                "input": r.get("input", {}),
                "status": r.get("status", 0),
                "length": r.get("length", 0),
                "words": r.get("words", 0),
                "url": r.get("url", "")
            })
        return {
            "tool": "ffuf",
            "results": results,
            "interesting": [r for r in results if r["status"] in [200, 301, 302, 401, 403]]
        }

    def _parse_text(self, raw: str) -> dict:
        results = []
        pattern = re.compile(r"(\S+)\s+\[Status: (\d+), Size: (\d+), Words: (\d+)")
        for match in pattern.finditer(raw):
            results.append({
                "input": match.group(1),
                "status": int(match.group(2)),
                "length": int(match.group(3)),
                "words": int(match.group(4)),
                "url": ""
            })
        return {
            "tool": "ffuf",
            "results": results,
            "interesting": [r for r in results if r["status"] in [200, 301, 302, 401, 403]]
        }