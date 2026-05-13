class TriggerEngine:
    """
    Déclenche des actions automatiques basées sur les découvertes.
    Ex: Port 80 trouvé -> Lancer whatweb.
    """
    def __init__(self, session):
        self.session = session
        if "triggered_tasks" not in self.session.data:
            self.session.data["triggered_tasks"] = []

    def check_and_trigger(self, session_data: dict) -> list:
        """
        Vérifie les ports et services pour déclencher des commandes.
        Retourne une liste de commandes à lancer en arrière-plan.
        """
        new_commands = []
        target = session_data.get("target")
        ports = session_data.get("ports", {})

        for port_id, info in ports.items():
            port_num = int(info.get("port", 0))
            service  = info.get("service", "").lower()
            version  = info.get("version", "")
            
            # ── TRIGGER : Web (80, 443, 8080...) ──
            if port_num in [80, 443, 8080, 8443] or "http" in service:
                task_id = f"whatweb_{target}_{port_num}"
                if task_id not in self.session.data["triggered_tasks"]:
                    proto = "https" if "https" in service or port_num in [443, 8443] else "http"
                    url = f"{proto}://{target}:{port_num}"
                    new_commands.append({
                        "cmd": f"whatweb {url}",
                        "desc": f"Auto-recon Web sur {port_num}"
                    })
                    self.session.data["triggered_tasks"].append(task_id)
                    self.session.save()

            # ── TRIGGER : Vuln Search (SearchSploit) ──
            if service and version:
                task_id = f"searchsploit_{service}_{version}"
                if task_id not in self.session.data["triggered_tasks"]:
                    # On nettoie un peu la version pour searchsploit
                    clean_v = version.split()[0]
                    new_commands.append({
                        "cmd": f"searchsploit {service} {clean_v}",
                        "desc": f"Recherche auto d'exploits pour {service} {version}"
                    })
                    self.session.data["triggered_tasks"].append(task_id)
                    self.session.save()

        return new_commands
