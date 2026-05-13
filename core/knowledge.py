import json
import os
from datetime import datetime

class KnowledgeBase:
    """
    Gère la mémoire à long terme de NORHACK.
    Stocke les services identifiés et les exploits qui ont fonctionné.
    """
    def __init__(self, storage_path: str = "knowledge/exploits.json"):
        self.storage_path = storage_path
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
        self.data = self._load()

    def _load(self) -> dict:
        if os.path.exists(self.storage_path):
            with open(self.storage_path, "r") as f:
                return json.load(f)
        return {"known_exploits": [], "service_history": {}}

    def save(self):
        with open(self.storage_path, "w") as f:
            json.dump(self.data, f, indent=2)

    def record_success(self, service: str, version: str, exploit_name: str, target: str):
        """Enregistre un exploit réussi pour un service/version donné."""
        entry = {
            "service": service,
            "version": version,
            "exploit": exploit_name,
            "target": target,
            "date": datetime.now().isoformat()
        }
        self.data["known_exploits"].append(entry)
        
        # Indexation par service pour recherche rapide
        key = f"{service.lower()}|{version.lower()}"
        if key not in self.data["service_history"]:
            self.data["service_history"][key] = []
        self.data["service_history"][key].append(exploit_name)
        
        self.save()

    def find_matches(self, service: str, version: str) -> list:
        """Cherche si on a déjà exploité ce service/version par le passé."""
        key = f"{service.lower()}|{version.lower()}"
        return self.data["service_history"].get(key, [])

    def get_global_context(self) -> str:
        """Génère un petit texte de contexte basé sur l'expérience passée."""
        if not self.data["known_exploits"]:
            return ""
        
        summary = "\n=== EXPÉRIENCE PASSÉE (KNOWLEDGE BASE) ===\n"
        # On prend les 5 derniers exploits réussis
        recent = self.data["known_exploits"][-5:]
        for r in recent:
            summary += f"- {r['service']} {r['version']} a été compromis via {r['exploit']} sur {r['target']}\n"
        return summary
