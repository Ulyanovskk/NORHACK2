import os
import json
from anthropic import Anthropic
from dotenv import load_dotenv

load_dotenv()


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