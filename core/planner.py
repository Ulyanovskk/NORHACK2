"""
core/planner.py
Gestionnaire du plan d'attaque RedTeam.

Logique :
  1. Après le premier scan recon → génère un plan A/B/C via LLM
  2. Suit l'état de chaque option (pending / active / success / failed)
  3. Si toutes les options échouent → déclenche un re-plan
  4. Garde l'historique des tentatives pour enrichir les re-plans
"""

from datetime import datetime
from enum import Enum


class OptionStatus(str, Enum):
    PENDING  = "pending"   # Pas encore tentée
    ACTIVE   = "active"    # En cours d'exécution
    SUCCESS  = "success"   # A donné un résultat intéressant
    FAILED   = "failed"    # N'a rien donné


class Planner:
    """
    Orchestre le plan d'attaque RedTeam.
    Toutes les données sont stockées dans session.data["attack_plan"].
    """

    def __init__(self, session):
        self.session = session
        # Initialise ou complète la structure dans la session
        default_plan = {
            "version": 0,          # Incrément à chaque re-plan
            "options": [],          # Liste des options A, B, C
            "active_option": None,  # ID de l'option en cours ("A", "B", "C")
            "history": [],          # Historique de toutes les tentatives
            "recon_summary": "",
            "threat_level": "unknown",
            "pivot_trigger": "",
            "created_at": datetime.now().isoformat()
        }

        if "attack_plan" not in self.session.data:
            self.session.data["attack_plan"] = default_plan
        else:
            # S'assure que toutes les clés nécessaires sont présentes (migration)
            for key, val in default_plan.items():
                if key not in self.session.data["attack_plan"]:
                    self.session.data["attack_plan"][key] = val

    # ─────────────────────────────────────────────
    # ÉTAT DU PLAN
    # ─────────────────────────────────────────────

    @property
    def plan(self) -> dict:
        return self.session.data["attack_plan"]

    def has_plan(self) -> bool:
        """Retourne True si un plan existe et a au moins une option."""
        return bool(self.plan.get("options"))

    def get_active_option(self) -> dict | None:
        """Retourne l'option actuellement active, ou None."""
        active_id = self.plan.get("active_option")
        if not active_id:
            return None
        return self._get_option(active_id)

    def get_next_pending(self) -> dict | None:
        """Retourne la prochaine option en attente, ou None si toutes traitées."""
        for opt in self.plan["options"]:
            if opt["status"] == OptionStatus.PENDING:
                return opt
        return None

    def all_options_exhausted(self) -> bool:
        """True si toutes les options sont FAILED ou SUCCESS."""
        if not self.plan["options"]:
            return False
        return all(
            opt["status"] in [OptionStatus.FAILED, OptionStatus.SUCCESS]
            for opt in self.plan["options"]
        )

    def any_success(self) -> bool:
        """True si au moins une option a réussi."""
        return any(
            opt["status"] == OptionStatus.SUCCESS
            for opt in self.plan["options"]
        )

    # ─────────────────────────────────────────────
    # CHARGEMENT DU PLAN DEPUIS LLM
    # ─────────────────────────────────────────────

    def load_from_llm(self, llm_json: dict):
        """
        Charge un plan généré par le LLM (format JSON défini dans attack_planner.txt).
        Incrémente la version (re-plan).
        """
        # Incrémente la version (sécurisé)
        if "version" not in self.plan:
            self.plan["version"] = 1
        else:
            self.plan["version"] += 1
        self.plan["recon_summary"] = llm_json.get("recon_summary", "")
        self.plan["threat_level"] = llm_json.get("threat_level", "unknown")
        self.plan["pivot_trigger"] = llm_json.get("pivot_trigger", "")
        self.plan["active_option"] = None

        # Construit les options enrichies avec statut
        self.plan["options"] = []
        for opt in llm_json.get("options", []):
            self.plan["options"].append({
                "id":              opt.get("id", "?"),
                "label":           opt.get("label", ""),
                "objective":       opt.get("objective", ""),
                "rationale":       opt.get("rationale", ""),
                "commands":        opt.get("commands", []),
                "expected_result": opt.get("expected_result", ""),
                "fallback_if_fail":opt.get("fallback_if_fail", ""),
                "status":          OptionStatus.PENDING,
                "result_summary":  None,
                "started_at":      None,
                "ended_at":        None,
            })

        self.session.save()

    # ─────────────────────────────────────────────
    # TRANSITIONS D'ÉTAT
    # ─────────────────────────────────────────────

    def start_option(self, option_id: str):
        """Marque une option comme ACTIVE."""
        opt = self._get_option(option_id)
        if opt:
            opt["status"] = OptionStatus.ACTIVE
            opt["started_at"] = datetime.now().isoformat()
            self.plan["active_option"] = option_id
            self.session.save()

    def mark_success(self, option_id: str, result_summary: str = ""):
        """Marque une option comme réussie."""
        opt = self._get_option(option_id)
        if opt:
            opt["status"] = OptionStatus.SUCCESS
            opt["result_summary"] = result_summary
            opt["ended_at"] = datetime.now().isoformat()
            self.plan["active_option"] = None
            self._record_history(option_id, "success", result_summary)
            self.session.save()

    def mark_failed(self, option_id: str, reason: str = ""):
        """Marque une option comme échouée."""
        opt = self._get_option(option_id)
        if opt:
            opt["status"] = OptionStatus.FAILED
            opt["result_summary"] = reason or "Rien de concluant"
            opt["ended_at"] = datetime.now().isoformat()
            self.plan["active_option"] = None
            self._record_history(option_id, "failed", reason)
            self.session.save()

    def auto_advance(self) -> dict | None:
        """
        Avance automatiquement à la prochaine option PENDING.
        Retourne l'option démarrée, ou None si toutes épuisées.
        """
        next_opt = self.get_next_pending()
        if next_opt:
            self.start_option(next_opt["id"])
            return next_opt
        return None

    # ─────────────────────────────────────────────
    # CONTEXTE POUR LE RE-PLAN
    # ─────────────────────────────────────────────

    def get_failure_context(self) -> str:
        """
        Génère un résumé des échecs pour alimenter le re-plan LLM.
        """
        lines = [
            f"=== PLAN v{self.plan['version']} — TOUTES OPTIONS ÉPUISÉES ===",
            f"Résumé recon initial : {self.plan['recon_summary']}",
            "",
            "OPTIONS TENTÉES :"
        ]
        for opt in self.plan["options"]:
            status_icon = "✓" if opt["status"] == OptionStatus.SUCCESS else "✗"
            lines.append(
                f"  [{status_icon}] Option {opt['id']} — {opt['label']} : "
                f"{opt.get('result_summary', 'aucun résultat')}"
            )
            if opt.get("fallback_if_fail") and opt["status"] == OptionStatus.FAILED:
                lines.append(f"       → Indice : {opt['fallback_if_fail']}")

        lines.append("")
        lines.append("HISTORIQUE DES TENTATIVES :")
        for h in self.plan["history"][-6:]:
            lines.append(f"  [{h['outcome'].upper()}] {h['option_id']} @ {h['at']}: {h['summary']}")

        return "\n".join(lines)

    # ─────────────────────────────────────────────
    # RÉSUMÉ AFFICHABLE
    # ─────────────────────────────────────────────

    def get_plan_summary(self) -> dict:
        """Retourne les données du plan pour affichage via Display."""
        return {
            "version":      self.plan["version"],
            "threat_level": self.plan["threat_level"],
            "recon_summary":self.plan["recon_summary"],
            "options":      self.plan["options"],
            "active":       self.plan["active_option"],
            "exhausted":    self.all_options_exhausted(),
        }

    # ─────────────────────────────────────────────
    # UTILITAIRES PRIVÉS
    # ─────────────────────────────────────────────

    def _get_option(self, option_id: str) -> dict | None:
        for opt in self.plan["options"]:
            if opt["id"] == option_id:
                return opt
        return None

    def _record_history(self, option_id: str, outcome: str, summary: str):
        self.plan["history"].append({
            "option_id": option_id,
            "outcome":   outcome,
            "summary":   summary,
            "at":        datetime.now().isoformat()
        })
