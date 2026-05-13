import os
import json
import re
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()


class DeepSeekClient:
    """
    Wrapper DeepSeek V3 — payloads, exploits, bypass.
    Utilise l'API compatible OpenAI.
    """

    def __init__(self, config_path: str = "config/settings.json"):
        with open(config_path, "r") as f:
            config = json.load(f)
        self.client = OpenAI(
            api_key=os.getenv("DEEPSEEK_API_KEY"),
            base_url="https://api.deepseek.com"
        )
        self.model = config["models"]["deepseek"]
        self.max_tokens = config["limits"]["max_tokens_deepseek"]
        self.system_prompt = self._load_system_prompt()

    def _load_system_prompt(self) -> str:
        path = "llm/prompts/system_pentest.txt"
        if os.path.exists(path):
            with open(path, "r") as f:
                return f.read()
        return "Tu es un expert en cybersécurité offensive."

    def generate_payloads(self, context: str, extracted: dict, history: list = []) -> str:
        """
        Génère des payloads et commandes d'exploitation
        basés sur le contexte de la session.
        """
        user_message = f"""
{context}

=== CIBLE IDENTIFIÉE ===
{json.dumps(extracted, indent=2, ensure_ascii=False)}

Génère :
1. Les payloads adaptés à cette cible
2. Les commandes d'exploitation exactes
3. Les techniques de bypass si nécessaire
4. Les étapes de post-exploitation si accès obtenu
"""
        messages = history + [{"role": "user", "content": user_message}]

        response = self.client.chat.completions.create(
            model=self.model,
            max_tokens=self.max_tokens,
            messages=[
                {"role": "system", "content": self.system_prompt},
                *messages
            ]
        )
        return response.choices[0].message.content

    def ask(self, question: str, context: str = "", history: list = []) -> str:
        """Question libre orientée exploitation."""
        user_message = f"{context}\n\n{question}" if context else question
        messages = history + [{"role": "user", "content": user_message}]

        response = self.client.chat.completions.create(
            model=self.model,
            max_tokens=self.max_tokens,
            messages=[
                {"role": "system", "content": self.system_prompt},
                *messages
            ]
        )
        return response.choices[0].message.content

    def pre_digest(self, raw_output: str) -> str:
        """
        Utilise DeepSeek pour 'nettoyer' et résumer un log massif.
        """
        if len(raw_output) > 8000:
            content = f"[DÉBUT DU LOG]\n{raw_output[:4000]}\n\n[... TRONQUÉ ...]\n\n[FIN DU LOG]\n{raw_output[-4000:]}"
        else:
            content = raw_output

        prompt = """Tu es un pré-processeur de logs pentest.
TON RÔLE : Extraire UNIQUEMENT les faits techniques utiles (versions, erreurs, ports, chemins) d'un log brut.
CONTRAINTES : Mots-clés uniquement, suppression des bannières.
"""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                max_tokens=500,
                messages=[
                    {"role": "system", "content": prompt},
                    {"role": "user", "content": f"LOG À CONDENSER :\n{content}"}
                ]
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"[Erreur filtrage : {e}]"

    def analyze_verdict(self, output: str, objective: str) -> dict:
        """
        Détermine si l'outil a réussi son objectif (verdict JSON).
        """
        prompt = f"""Analyse ce résultat d'outil et détermine si l'objectif a été atteint.
OBJECTIF : {objective}
RÉSULTAT : {output[:2000]}

Réponds UNIQUEMENT au format JSON :
{{
  "status": "success" | "failed",
  "confidence": 0.0-1.0,
  "reason": "Explication courte",
  "findings": ["points", "clés"]
}}
"""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                max_tokens=300,
                messages=[{"role": "user", "content": prompt}]
            )
            return self._extract_json(response.choices[0].message.content)
        except:
            return {"status": "failed", "confidence": 0, "reason": "Erreur verdict"}

    def suggest_fix(self, failed_cmd: str, output: str) -> dict:
        """
        Propose une correction de commande en cas d'échec.
        """
        prompt = f"""La commande suivante a échoué :
CMD : {failed_cmd}
ERREUR : {output[:2000]}

Analyse l'erreur et propose une commande corrigée.
Réponds UNIQUEMENT au format JSON :
{{
  "error_analysis": "Pourquoi ça a échoué",
  "fixed_command": "Nouvelle commande à tester",
  "explanation": "Ce qui a été changé"
}}
"""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                max_tokens=500,
                messages=[{"role": "user", "content": prompt}]
            )
            return self._extract_json(response.choices[0].message.content)
        except:
            return None

    def _extract_json(self, text: str) -> dict:
        """Extrait le JSON d'une réponse textuelle."""
        try:
            # Cherche le premier { et le dernier }
            match = re.search(r'(\{.*\})', text, re.DOTALL)
            if match:
                return json.loads(match.group(1))
            return json.loads(text)
        except:
            return {}