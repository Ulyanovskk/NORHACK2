import re
import json
import os
from pathlib import Path

class Correlator:
    """
    Moteur de corrélation hybride (Signatures + LLM).
    """
    def __init__(self, rules_path: str = "config/rules.json"):
        self.rules_path = rules_path
        self.rules = self._load_rules()
        self.reported_ids = set()

    def _load_rules(self) -> list:
        """Charge les règles depuis le fichier JSON."""
        if os.path.exists(self.rules_path):
            with open(self.rules_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return []

    def analyze_session(self, session_data: dict) -> list:
        """
        Analyse la session en croisant les signatures statiques 
        et la logique dynamique.
        """
        alerts = []
        ports = session_data.get("ports", {})
        findings = session_data.get("findings", [])
        
        # 1. Extraction des chemins et contenus bruts
        all_paths = set()
        full_text = ""
        for f in findings:
            raw = f.get("raw", "")
            full_text += raw + "\n"
            found = re.findall(r'(/[a-zA-Z0-9\._\-/]+)', raw)
            all_paths.update(found)
        
        # 2. Corrélation par Signatures (Générique)
        for rule in self.rules:
            if rule["id"] in self.reported_ids:
                continue

            match = True
            cond = rule["conditions"]
            
            if "service" in cond:
                service_found = any(cond["service"] in p.get("service", "").lower() for p in ports.values())
                if not service_found: match = False
            
            if match and "version" in cond:
                version_found = any(cond["version"] in p.get("version", "") for p in ports.values())
                if not version_found: match = False
            
            if match and "path" in cond:
                path_found = any(cond["path"] in p for p in all_paths)
                if not path_found: match = False

            if match and "raw_match" in cond:
                if cond["raw_match"] not in full_text.lower():
                    match = False
                
            if match:
                self.reported_ids.add(rule["id"])
                alerts.append({
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "reason": f"Signature détectée : {rule.get('description', rule['name'])}"
                })
        
        # 3. Note : La corrélation complexe (LLM) est gérée par le Planner 
        # dans hack.py via session.get_context_summary().
        
        return alerts
