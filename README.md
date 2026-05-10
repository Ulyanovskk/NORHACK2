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

## 📖 Modes d'Utilisation

NORHACK propose trois modes principaux pour s'adapter à votre workflow de pentest :

### 1. Mode Wrapper (L'enveloppe)
L'assistant lance la commande réelle pour vous et intercepte le résultat.
- **Usage** : `hack <outil> [arguments]`
- **Exemple** : `hack nmap -sV -p- 10.10.10.123`
- **Avantage** : Vous voyez l'output en direct, et l'IA analyse tout automatiquement à la fin (ports, versions, vulnérabilités).

### 2. Mode Pipe (Le tuyau)
Idéal pour analyser l'output d'une commande que vous avez déjà personnalisée ou lancée.
- **Usage** : `commande | hack`
- **Exemple** : `gobuster dir -u http://target.com -w common.txt | hack`
- **Avantage** : Permet d'intégrer NORHACK dans n'importe quel script ou chaine de commandes.

### 3. Mode Interactif (Le Shell)
Discutez directement avec votre assistant IA en utilisant tout le contexte accumulé.
- **Usage** : `hack shell`
- **Avantage** : L'IA connaît déjà tous les ports ouverts, les services et les vulnérabilités trouvés précédemment. Vous pouvez lui demander des payloads spécifiques ou des conseils stratégiques basés sur la surface d'attaque actuelle.

---

## 📂 Gestion des Sessions
NORHACK garde une trace de chaque cible pour enrichir le contexte des LLM.
- `hack target <IP>` : Définit la cible actuelle.
- `hack session` : Affiche le résumé de la surface d'attaque trouvée (ports, vulns).
- `hack sessions` : Liste l'historique de toutes vos cibles scannées.

