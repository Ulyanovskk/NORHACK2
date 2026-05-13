import json
import os
import threading
from datetime import datetime
from pathlib import Path


class Session:
    """
    Mémoire contextuelle de la cible en cours.
    Stocke tout ce que l'assistant sait sur la cible
    pour enrichir chaque appel LLM avec le contexte complet.
    """
    _lock = threading.Lock()

    def __init__(self, target: str, storage_dir: str = "sessions/"):
        self.target = target
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(exist_ok=True)
        self.session_file = self.storage_dir / f"{self._sanitize(target)}.json"
        self.data = self._load()

    def _sanitize(self, name: str) -> str:
        return name.replace(".", "_").replace("/", "_").replace(":", "_")

    def _load(self) -> dict:
        if self.session_file.exists():
            with open(self.session_file, "r") as f:
                data = json.load(f)
            # Migration des données si nécessaire
            if "notifications" not in data:
                data["notifications"] = []
            return data
        return {
            "target": self.target,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "ports": {},
            "services": {},
            "vulnerabilities": [],
            "findings": [],
            "notifications": [],
            "tested_vectors": [],
            "notes": [],
            "history": [],
            "attack_plan": {}  # Géré par core/planner.py
        }

    def save(self):
        with self._lock:
            self.data["updated_at"] = datetime.now().isoformat()
            with open(self.session_file, "w") as f:
                json.dump(self.data, f, indent=2)

    def add_port(self, port: int, protocol: str, state: str, service: str = "", version: str = ""):
        self.data["ports"][str(port)] = {
            "protocol": protocol,
            "state": state,
            "service": service,
            "version": version
        }
        self.save()

    def add_service(self, name: str, details: dict):
        self.data["services"][name] = details
        self.save()

    def add_vulnerability(self, vuln: dict):
        """
        vuln = {
            "type": "SQLi" | "XSS" | "RCE" | ...,
            "location": "/login",
            "severity": "critical" | "high" | "medium" | "low",
            "details": "...",
            "cve": "CVE-XXXX-XXXX"  # optionnel
        }
        """
        self.data["vulnerabilities"].append({
            **vuln,
            "found_at": datetime.now().isoformat()
        })
        self.save()

    def add_finding(self, tool: str, summary: str, raw: str = ""):
        self.data["findings"].append({
            "tool": tool,
            "summary": summary,
            "raw": raw[:2000],  # limite taille
            "at": datetime.now().isoformat()
        })
        self.save()

    def add_to_history(self, role: str, content: str):
        self.data["history"].append({
            "role": role,
            "content": content,
            "at": datetime.now().isoformat()
        })
        # Garde les 20 derniers échanges
        if len(self.data["history"]) > 20:
            self.data["history"] = self.data["history"][-20:]
        self.save()

    def mark_vector_tested(self, vector: str):
        if vector not in self.data["tested_vectors"]:
            self.data["tested_vectors"].append(vector)
        self.save()

    def get_context_summary(self) -> str:
        """
        Retourne un résumé compact du contexte pour injection dans les prompts LLM.
        """
        ports = self.data.get("ports", {})
        vulns = self.data.get("vulnerabilities", [])
        tested = self.data.get("tested_vectors", [])
        findings = self.data.get("findings", [])
        notifs = self.data.get("notifications", [])
        unread = len([n for n in notifs if not n.get("read", False)])

        open_ports = [
            f"{p}/{v.get('protocol', 'tcp')} {v.get('service', 'unknown')} {v.get('version', '')}"
            for p, v in ports.items()
            if v.get("state") == "open"
        ]

        summary = f"""=== SESSION CONTEXT : {self.target} ===
Démarré : {self.data['created_at']}
Notifications non lues : {unread}

PORTS OUVERTS ({len(open_ports)}) :
{chr(10).join([f"  - {p}" for p in open_ports]) if open_ports else '  Aucun encore'}

VULNÉRABILITÉS TROUVÉES ({len(vulns)}) :
{chr(10).join([f"  [{v['severity'].upper()}] {v['type']} @ {v['location']}" for v in vulns]) if vulns else '  Aucune encore'}

VECTEURS DÉJÀ TESTÉS :
{chr(10).join([f"  - {t}" for t in tested]) if tested else '  Aucun encore'}

HISTORIQUE DES ACTIONS (10 dernières) :
{chr(10).join([f"  - [{f['at']}] {f['tool']}: {f['summary']}" for f in findings[-10:]]) if findings else '  Aucune action encore'}
"""
        return summary

    def get_llm_history(self) -> list:
        """Retourne l'historique formaté pour les appels LLM."""
        return [
            {"role": h["role"], "content": h["content"]}
            for h in self.data["history"]
        ]

    def get_plan_status_summary(self) -> str:
        """
        Retourne un résumé du plan d'attaque actif pour injection dans le contexte LLM.
        Utilisé pour que le LLM sache toujours où on en est dans le plan.
        """
        plan = self.data.get("attack_plan", {})
        if not plan or not plan.get("options"):
            return ""

        lines = [f"\n=== PLAN D'ATTAQUE ACTIF (v{plan.get('version', 1)}) ==="]
        for opt in plan["options"]:
            status = opt.get("status", "pending")
            icon = {"pending": "○", "active": "▶", "success": "✓", "failed": "✗"}.get(status, "?")
            result = opt.get("result_summary", "")
            lines.append(f"  [{icon}] Option {opt['id']} — {opt['label']} [{status}]")
            if result:
                lines.append(f"       Résultat : {result}")
        lines.append("")
        return "\n".join(lines)

    def add_notification(self, message: str):
        """Ajoute une notification au système de fond."""
        self.data["notifications"].append({
            "msg": message,
            "at": datetime.now().isoformat(),
            "read": False
        })
        self.save()

    @classmethod
    def list_sessions(cls, storage_dir: str = "sessions/") -> list:
        path = Path(storage_dir)
        if not path.exists():
            return []
        return [f.stem for f in path.glob("*.json")]