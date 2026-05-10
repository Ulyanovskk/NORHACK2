import json
from pathlib import Path


class Router:
    """
    Décide quel LLM utiliser selon le type de tâche.
    Claude Haiku → analyse, stratégie, recon
    DeepSeek V3  → payloads, exploits, bypass
    """

    def __init__(self, config_path: str = "config/settings.json"):
        with open(config_path, "r") as f:
            config = json.load(f)
        self.claude_tasks = config["routing"]["claude_tasks"]
        self.deepseek_tasks = config["routing"]["deepseek_tasks"]

    def route(self, task_type: str) -> str:
        """
        Retourne 'claude' ou 'deepseek' selon le type de tâche.
        """
        if task_type in self.deepseek_tasks:
            return "deepseek"
        return "claude"  # défaut

    def detect_task_type(self, raw_output: str, tool_name: str) -> str:
        """
        Détecte automatiquement le type de tâche selon l'outil
        et le contenu de l'output.
        """
        tool_name = tool_name.lower()

        # Outils de recon/analyse → Claude
        if tool_name in ["nmap", "nikto", "whatweb", "wafw00f", "nuclei"]:
            return "analyze"

        # Outils d'énumération web → Claude
        if tool_name in ["gobuster", "ffuf", "dirb", "dirsearch", "feroxbuster"]:
            return "analyze"

        # Outils d'exploitation → DeepSeek
        if tool_name in ["sqlmap", "hydra", "medusa", "metasploit", "msfconsole"]:
            return "exploit"

        # Détection par mots-clés dans l'output
        output_lower = raw_output.lower()

        deepseek_keywords = [
            "payload", "exploit", "shell", "bypass",
            "injection", "overflow", "reverse", "bind"
        ]
        for kw in deepseek_keywords:
            if kw in output_lower:
                return "payload"

        # Défaut : analyse Claude
        return "analyze"

    def route_auto(self, raw_output: str, tool_name: str) -> str:
        """
        Routing automatique complet : détecte + route.
        Retourne 'claude' ou 'deepseek'.
        """
        task_type = self.detect_task_type(raw_output, tool_name)
        return self.route(task_type)