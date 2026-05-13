class Correlator:
    """
    Moteur de corrélation multi-sources.
    Croise les données de différents outils pour identifier des vulnérabilités complexes.
    """
    def __init__(self):
        self.rules = [
            {
                "id": "apache_rce_cgi",
                "name": "Apache 2.4.49/50 RCE (Path Traversal)",
                "conditions": {
                    "service": "apache",
                    "version": "2.4.49",
                    "path": "/cgi-bin/"
                },
                "severity": "CRITICAL"
            },
            {
                "id": "tomcat_manager_default",
                "name": "Tomcat Manager Default Credentials",
                "conditions": {
                    "service": "tomcat",
                    "path": "/manager/html"
                },
                "severity": "HIGH"
            },
            {
                "id": "wp_xmlrpc_brute",
                "name": "WordPress XML-RPC Brute Force",
                "conditions": {
                    "path": "/xmlrpc.php"
                },
                "severity": "MEDIUM"
            }
        ]

    def analyze_session(self, session_data: dict) -> list:
        """Parcourt les données de session pour trouver des corrélations."""
        alerts = []
        ports = session_data.get("ports", {})
        findings = session_data.get("findings", [])
        
        # Extraction simplifiée des chemins intéressants (Gobuster)
        all_paths = []
        for f in findings:
            if f.get("tool") == "gobuster" and "interesting_paths" in f.get("raw", ""):
                 # Extraction basique pour l'exemple
                 pass
        
        # Pour cet exemple, on simule une vérification de règles
        for rule in self.rules:
            match = True
            cond = rule["conditions"]
            
            # Vérif Service/Version (Nmap)
            if "service" in cond:
                service_found = any(p.get("service", "").lower() == cond["service"] for p in ports.values())
                if not service_found: match = False
            
            if match and "version" in cond:
                version_found = any(cond["version"] in p.get("version", "") for p in ports.values())
                if not version_found: match = False
                
            if match:
                alerts.append({
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "reason": f"Corrélation détectée basée sur {cond}"
                })
                
        return alerts
