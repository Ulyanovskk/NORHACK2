import re
import xml.etree.ElementTree as ET


class NmapParser:
    """
    Parse les outputs nmap — texte brut et XML.
    XML prioritaire car plus riche.
    """

    def parse(self, raw: str) -> dict:
        if raw.strip().startswith("<?xml"):
            return self.parse_xml(raw)
        return self.parse_text(raw)

    def parse_xml(self, xml_str: str) -> dict:
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError:
            return self.parse_text(xml_str)

        result = {
            "tool": "nmap",
            "hosts": []
        }

        for host in root.findall("host"):
            addr = host.find("address")
            ip = addr.get("addr", "") if addr is not None else ""

            os_matches = []
            os_el = host.find("os")
            if os_el is not None:
                for osmatch in os_el.findall("osmatch"):
                    os_matches.append({
                        "name": osmatch.get("name", ""),
                        "accuracy": osmatch.get("accuracy", "")
                    })

            for port in host.findall(".//port"):
                ports.append({
                    "port": port.get("portid"),
                    "protocol": port.get("protocol"),
                    "state": port.find("state").get("state"),
                    "service": port.find("service").get("name") if port.find("service") is not None else "",
                    "version": port.find("service").get("product", "") if port.find("service") is not None else ""
                })

            result["hosts"].append({
                "ip": ip,
                "os": os_matches[0]["name"] if os_matches else "unknown",
                "open_ports": [p for p in ports if p["state"] == "open"]
            })

        return result

    def parse_text(self, text: str) -> dict:
        ports = []
        port_pattern = re.compile(r"(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)?\s*(.*)")
        for match in port_pattern.finditer(text):
            ports.append({
                "port": match.group(1),
                "protocol": match.group(2),
                "state": match.group(3),
                "service": match.group(4) or "",
                "version": match.group(5).strip() or ""
            })

        host_match = re.search(r"Nmap scan report for (\S+)", text)
        return {
            "tool": "nmap",
            "hosts": [{
                "ip": host_match.group(1) if host_match else "unknown",
                "open_ports": [p for p in ports if p["state"] == "open"]
            }]
        }