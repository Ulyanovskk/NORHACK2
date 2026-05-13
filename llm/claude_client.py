import os
import json
from anthropic import Anthropic
from dotenv import load_dotenv

load_dotenv()

PLANNER_PROMPT_PATH = "llm/prompts/attack_planner.txt"


class ClaudeClient:
    """
    Wrapper Claude Haiku — analyse, stratégie, recon.
    """

    def __init__(self, config_path: str = "config/settings.json"):
        with open(config_path, "r") as f:
            config = json.load(f)
        self.client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        self.model = config["models"]["claude"]
        self.max_tokens = config["limits"]["max_tokens_claude"]
        self.system_prompt = self._load_system_prompt()

    def _load_system_prompt(self) -> str:
        path = "llm/prompts/system_pentest.txt"
        if os.path.exists(path):
            with open(path, "r") as f:
                return f.read()
        return "Tu es un expert en cybersécurité offensive."

    def analyze(self, context: str, extracted: dict, history: list = []) -> str:
        """
        Analyse un output d'outil pentest et retourne
        une analyse stratégique + next steps.
        """
        user_message = f"""
{context}

=== OUTPUT ANALYSÉ ===
Outil : {extracted.get('tool', 'inconnu')}
Données extraites :
{json.dumps(extracted, indent=2, ensure_ascii=False)}

Analyse ce résultat. Donne :
1. Ce que tu vois (services, versions, surface d'attaque)
2. Les vecteurs prioritaires à exploiter
3. Les commandes exactes à lancer maintenant
4. Les CVE pertinents si applicable
"""
        messages = history + [{"role": "user", "content": user_message}]

        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=self.system_prompt,
            messages=messages
        )
        return response.content[0].text

    def build_attack_plan(self, context: str, extracted: dict) -> dict:
        """
        Génère le plan d'attaque A/B/C initial après un scan de recon.
        Retourne un dict parsé depuis le JSON du LLM.
        Lève une ValueError si le JSON est invalide.
        """
        planner_system = self._load_prompt(PLANNER_PROMPT_PATH)

        user_message = f"""
{context}

=== RÉSULTATS DU SCAN DE RECON ===
{json.dumps(extracted, indent=2, ensure_ascii=False)}

Génère le plan d'attaque JSON maintenant. Objectif : accès initial puis escalade.
La cible est : {extracted.get('host', 'inconnue')}
JSON uniquement, aucun texte autour.
"""
        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=planner_system,
            messages=[{"role": "user", "content": user_message}]
        )
        raw = response.content[0].text.strip()
        return self._extract_json(raw)

    def replan(self, context: str, failure_context: str) -> dict:
        """
        Génère un nouveau plan d'attaque après épuisement de toutes les options.
        Utilise le contexte d'échec pour orienter vers de nouveaux vecteurs.
        """
        planner_system = self._load_prompt(PLANNER_PROMPT_PATH)

        user_message = f"""
{context}

{failure_context}

Toutes les options précédentes ont été épuisées. 
Génère un NOUVEAU plan d'attaque avec des vecteurs différents.
Pense latéralement : pivots, vecteurs indirects, chained exploits, social engineering technique.
JSON uniquement.
"""
        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=planner_system,
            messages=[{"role": "user", "content": user_message}]
        )
        raw = response.content[0].text.strip()
        return self._extract_json(raw)

    def analyze_step_result(self, context: str, option: dict, step_output: str, history: list = []) -> str:
        """
        Analyse le résultat d'une étape dans le plan d'attaque.
        Retourne une évaluation : succès / échec + next micro-steps.
        """
        user_message = f"""
{context}

=== OPTION EN COURS : {option['id']} — {option['label']} ===
Objectif : {option['objective']}
Résultat attendu : {option['expected_result']}

=== OUTPUT OBTENU ===
{step_output[:3000]}

Analyse ce résultat :
1. Est-ce concluant ? (OUI/NON + pourquoi)
2. Ce qu'on a appris
3. Prochaines micro-actions si succès, ou verdict d'échec si rien
Sois direct et technique.
"""
        messages = history + [{"role": "user", "content": user_message}]
        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=self.system_prompt,
            messages=messages
        )
        return response.content[0].text

    def _extract_json(self, raw: str) -> dict:
        """
        Extraction robuste du JSON depuis une réponse LLM.
        Stratégie par ordre de robustesse :
          1. Parse direct si déjà du JSON propre
          2. Extrait le bloc ```json ... ``` ou ``` ... ```
          3. Cherche le premier '{' jusqu'au dernier '}' par comptage de niveau
          4. Lève JSONDecodeError si tout échoue
        """
        import re

        # 1. Essai direct
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass

        # 2. Extrait depuis un bloc ```[json] ... ```
        fence_match = re.search(r'```(?:json)?\s*([\s\S]*?)```', raw)
        if fence_match:
            try:
                return json.loads(fence_match.group(1).strip())
            except json.JSONDecodeError:
                pass

        # 3. Trouve le JSON par comptage de niveau (méthode la plus fiable)
        start = raw.find('{')
        if start == -1:
            raise json.JSONDecodeError("Aucun objet JSON trouvé", raw, 0)

        depth   = 0
        in_str  = False
        escape  = False
        end     = start

        for i, ch in enumerate(raw[start:], start):
            if escape:
                escape = False
                continue
            if ch == '\\' and in_str:
                escape = True
                continue
            if ch == '"':
                in_str = not in_str
                continue
            if in_str:
                continue
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    end = i
                    break

        candidate = raw[start:end + 1]

        # 4. Essai direct sur le candidat extrait
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass

        # 5. ast.literal_eval — gère les dicts Python style {'key': 'val'}
        import ast
        try:
            result = ast.literal_eval(candidate)
            if isinstance(result, dict):
                return json.loads(json.dumps(result, ensure_ascii=False))
        except (ValueError, SyntaxError):
            pass

        # 6. Remplacement single quotes → double quotes (heuristique de dernier recours)
        import re as _re
        try:
            normalized = _re.sub(r"(?<![\\])'", '"', candidate)
            return json.loads(normalized)
        except json.JSONDecodeError as e:
            raise json.JSONDecodeError(
                f"JSON introuvable après tous les essais ({e.msg})",
                candidate, e.pos
            )

    def _load_prompt(self, path: str) -> str:
        """Charge un fichier prompt, retourne une string vide si introuvable."""
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return f.read()
        return ""

    def ask(self, question: str, context: str = "", history: list = []) -> str:
        """Question libre avec contexte de session."""
        user_message = f"{context}\n\n{question}" if context else question
        messages = history + [{"role": "user", "content": user_message}]

        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=self.system_prompt,
            messages=messages
        )
        return response.content[0].text