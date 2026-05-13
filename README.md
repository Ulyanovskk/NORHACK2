# 🛡️ NORHACK — RedTeam Intelligence Framework

NORHACK est un assistant de pentest de nouvelle génération qui transforme vos outils de sécurité classiques en une plateforme d'attaque orchestrée par IA. Il combine la puissance stratégique de **Claude 3.5 Haiku** et l'agressivité technique de **DeepSeek V3**.

---

## 🌟 Fonctionnalités Clés

- **🧠 Dual-LLM Orchestration** : Claude gère la stratégie et le planning, DeepSeek génère les payloads et condense les logs massifs.
- **🗺️ Autonomous Attack Planner** : Génère automatiquement des plans d'attaque prioritaires (Options A, B, C) après chaque scan de reconnaissance.
- **⚡ Real-time Streaming & Background Jobs** : Lancez des scans longs (Nmap -p-) en arrière-plan avec `&` et continuez à travailler pendant que les résultats s'affichent en direct.
- **📉 Cost Optimizer** : Chaînage intelligent DeepSeek -> Claude pour réduire la consommation de tokens jusqu'à 80% sur les gros volumes de données.
- **💾 Persistent Context** : Mémoire complète de la cible (ports, services, vulnérabilités, historique des commandes).

---

## 🛠️ Installation (WSL2 / Linux)

1. **Cloner le repo** :
   ```bash
   git clone https://github.com/Ulyanovskk/NORHACK2.git
   cd NORHACK2
   ```

2. **Configuration** :
   Créez un fichier `.env` à la racine :
   ```env
   ANTHROPIC_API_KEY=votre_cle_claude
   DEEPSEEK_API_KEY=votre_cle_deepseek
   HACK_TARGET=127.0.0.1
   ```

3. **Installer les dépendances** :
   ```bash
   pip install -r requirements.txt
   ```

---

## 📖 Guide d'Utilisation

### 1. Démarrer une Session
Définissez votre cible pour que NORHACK puisse isoler son contexte :
```bash
python3 hack.py target 165.210.33.18
```

### 2. Le Shell Interactif (Recommandé)
Le cœur de l'outil. Lancez-le pour entrer dans le mode RedTeam :
```bash
python3 hack.py shell
```

### 3. Workflow de Combat
Dans le shell NORHACK, utilisez le préfixe `!` pour lancer vos outils habituels.

#### Étape A : Reconnaissance & Planification
Lancez un scan Nmap. NORHACK va détecter l'outil, parser les ports et **générer automatiquement un plan d'attaque**.
```bash
[norhack]> !nmap -sV -T4 165.210.33.18
```

#### Étape B : Exécution du Plan
Affichez le plan avec `plan`. Activez une option avec `option <ID>`.
```bash
[norhack]> plan
[norhack]> option A
```

#### Étape C : Tâches de fond (Backgrounding)
Besoin de scanner tous les ports sans bloquer votre terminal ?
```bash
[norhack]> !nmap -p- 165.210.33.18 &
```
*Le scan tourne en tâche de fond, vous pouvez continuer à travailler pendant que les résultats s'affichent.*

---

## ⌨️ Commandes du Shell

| Commande | Action |
| :--- | :--- |
| `!commande` | Exécute une commande système (Nmap, Gobuster, etc.) |
| `!cmd &` | Exécute en arrière-plan (non-bloquant) |
| `plan` | Affiche l'état actuel du plan d'attaque A/B/C |
| `option <A\|B\|C>` | Démarre manuellement une option du plan |
| `done <A\|B\|C>` | Marque une option comme réussie |
| `fail <A\|B\|C>` | Marque une option comme échouée et passe à la suite |
| `replan` | Force l'IA à générer un nouveau plan basé sur les échecs passés |
| `session` | Affiche le résumé technique de la cible |
| `help` | Affiche l'aide complète |

---

## 💰 Optimisation des Coûts (Token Management)

NORHACK est conçu pour être économique :
- **Pre-digest** : Les logs de plus de 200 caractères sont d'abord filtrés par DeepSeek (très peu cher) avant d'être envoyés à Claude pour analyse.
- **Output Concision** : L'IA utilise un style ultra-concis et technique pour réduire les tokens de sortie.
- **Context Truncation** : Seuls les 20 derniers échanges et les 10 dernières actions sont conservés dans le prompt actif.

---

## ⚖️ Avertissement Légal
NORHACK est un outil destiné uniquement à un usage légal dans le cadre de tests d'intrusion autorisés ou de programmes de Bug Bounty. L'utilisateur est seul responsable de ses actions.
