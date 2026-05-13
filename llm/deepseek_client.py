import os
import json
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
        Objectif : Réduire les tokens d'entrée pour Claude Haiku.
        """
        prompt = """Tu es un pré-processeur de logs pentest.
TON RÔLE : Extraire UNIQUEMENT les faits techniques utiles (versions, erreurs, ports, chemins) d'un log brut.
CONTRAINTES :
- Style télégraphique (mots-clés uniquement)
- Supprime les bannières, le texte de progression, les répétitions
- Ne fais AUCUNE analyse, juste une extraction brute condensée
- Si le log est vide ou inutile, réponds 'RIEN'
"""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                max_tokens=500,
                messages=[
                    {"role": "system", "content": prompt},
                    {"role": "user", "content": f"LOG À CONDENSER :\n{raw_output[:8000]}"}
                ]
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"[Erreur filtrage : {e}]"