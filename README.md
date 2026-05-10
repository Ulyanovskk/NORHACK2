# NORHACKV - Pentesting Assistant

NORHACK est un framework de cybersécurité modulaire conçu pour assister les phases de reconnaissance et d'exploitation automatisée (Pentest & Bug Bounty).

## 🚀 Architecture

- **Multi-LLM Strategy** :
  - **Claude 3.5 Haiku** : Analyse stratégique, parsing de recon, planification.
  - **DeepSeek V3** : Génération de payloads complexes, contournement de WAF, exploitation.
- **Session Persistence** : Suivi en temps réel de la surface d'attaque et des vulnérabilités.
- **Modular Parsers** : Extraction automatique des données (Nmap, Gobuster, Nuclei, etc.).

## 📁 Structure du projet

```text
NORHACKV/
├── config/           # Paramètres globaux
├── core/             # Logique centrale (session, router, display)
├── llm/              # Clients LLM et Prompts spécialisés
├── parsers/          # Parsers d'outils de sécurité
├── tools/            # Outils auxiliaires (CVE lookup)
└── hack.py           # Point d'entrée principal
```

## 🛠 Installation

```bash
chmod +x install.sh
./install.sh
```

## 📖 Utilisation

**Mode Wrapper :**
```bash
hack nmap -sV -A <target>
```

**Mode Pipe :**
```bash
gobuster dir -u <url> -w <wordlist> | hack
```

**Mode Interactif :**
```bash
hack shell
```
