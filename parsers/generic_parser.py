class GenericParser:
    """
    Fallback pour tout outil non reconnu.
    Extrait le maximum d'informations sans parsing spécialisé.
    """

    def parse(self, raw: str, tool: str = "unknown") -> dict:
        lines = raw.splitlines()
        non_empty = [l.strip() for l in lines if l.strip()]

        return {
            "tool": tool,
            "raw": raw[:3000],
            "line_count": len(non_empty),
            "preview": non_empty[:20]
        }