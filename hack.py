#!/usr/bin/env python3
"""
NORHACK — REDTEAM ASSISTANT
Usage:
  hack <tool> [args...]         — wrapper de commande + analyse IA
  <tool> [args] | hack          — mode pipe
  hack shell [target]           — mode shell interactif
  hack target <ip>              — définit la cible active
  hack plan                     — affiche le plan d'attaque en cours
  hack option <A|B|C>           — démarre une option du plan
  hack done [A|B|C] ["résumé"] — marque l'option active comme réussie
  hack fail [A|B|C] ["raison"] — marque l'option active comme échouée
  hack replan                   — force un nouveau plan d'attaque
  hack session [target]         — affiche la session en cours
  hack sessions                 — liste toutes les sessions
"""

import sys
import os
import subprocess
import json
import argparse
import threading
import time
from dotenv import load_dotenv

try:
    import readline
except ImportError:
    pass

load_dotenv()

from core.session import Session
from core.router import Router
from core.analyzer import Analyzer
from core.display import Display
from core.planner import Planner, OptionStatus
from llm.claude_client import ClaudeClient
from llm.deepseek_client import DeepSeekClient

display  = Display()
analyzer = Analyzer()
router   = Router()
claude   = ClaudeClient()
deepseek = DeepSeekClient()


# ─────────────────────────────────────────────
# SESSION
# ─────────────────────────────────────────────

def get_or_create_session(target: str) -> Session:
    return Session(target=target)


# ─────────────────────────────────────────────
# LOGIQUE DU PLAN D'ATTAQUE
# ─────────────────────────────────────────────

def _is_recon_tool(tool: str) -> bool:
    """True si l'outil est un scan de reconnaissance initial."""
    return tool.lower() in ["nmap", "masscan", "rustscan", "arp-scan"]


def _trigger_plan_generation(session: Session, planner: Planner, extracted: dict):
    """
    Génère le plan d'attaque initial après un scan recon.
    Affiche le plan et démarre automatiquement l'option A.
    """
    display.info("Génération du plan d'attaque RedTeam...")
    context = session.get_context_summary()

    try:
        plan_json = claude.build_attack_plan(context, extracted)
        planner.load_from_llm(plan_json)
        summary = planner.get_plan_summary()

        display.plan_generated(
            version=summary["version"],
            threat_level=summary["threat_level"],
            recon_summary=summary["recon_summary"]
        )
        display.plan_table(summary["options"])

        # Démarre automatiquement l'option A
        first_opt = planner.auto_advance()
        if first_opt:
            display.option_start(first_opt)

    except (json.JSONDecodeError, ValueError) as e:
        display.error(f"Erreur parsing plan LLM : {e}")
    except Exception as e:
        display.error(f"Erreur génération plan : {e}")


def _trigger_replan(session: Session, planner: Planner):
    """
    Déclenche un re-plan complet quand toutes les options sont épuisées.
    """
    display.replan_alert()
    context = session.get_context_summary()
    failure_ctx = planner.get_failure_context()

    try:
        plan_json = claude.replan(context, failure_ctx)
        planner.load_from_llm(plan_json)
        summary = planner.get_plan_summary()

        display.plan_generated(
            version=summary["version"],
            threat_level=summary["threat_level"],
            recon_summary=summary["recon_summary"]
        )
        display.plan_table(summary["options"])

        first_opt = planner.auto_advance()
        if first_opt:
            display.option_start(first_opt)

    except (json.JSONDecodeError, ValueError) as e:
        display.error(f"Erreur parsing re-plan LLM : {e}")
    except Exception as e:
        display.error(f"Erreur re-plan : {e}")


# ─────────────────────────────────────────────
# ANALYSE D'UN OUTPUT D'OUTIL
# ─────────────────────────────────────────────

def process_output(raw_output: str, command_line: str, session: Session, planner: Planner):
    """
    Cœur du système :
    1. Détecte l'outil et parse l'output
    2. Met à jour la session (ports, vulns, findings)
    3. Si scan recon initial → génère le plan A/B/C
    4. Sinon → analyse le résultat dans le contexte du plan actif
    5. Si toutes les options épuisées → re-plan
    """
    tool_hint = command_line.split()[0] if command_line else ""
    prepared  = analyzer.prepare_for_llm(raw_output, tool_hint)
    tool      = prepared["tool"]
    extracted = prepared["extracted"]

    display.tool_detected(tool, session.target)

    # ── Affichage structuré + mise à jour session ──
    if tool == "nmap":
        hosts = extracted.get("hosts", [extracted])  # compat avec les deux formats
        for host in hosts if isinstance(hosts, list) else [hosts]:
            ports = host.get("open_ports", extracted.get("ports", []))
            display.ports_table(ports)
            for p in ports:
                if p.get("state") == "open":
                    session.add_port(
                        port=int(p["port"]),
                        protocol=p.get("protocol", "tcp"),
                        state=p["state"],
                        service=p.get("service", ""),
                        version=p.get("version", "")
                    )

    elif tool == "gobuster":
        display.paths_table(extracted.get("interesting_paths", []))

    elif tool == "nuclei":
        display.vulnerabilities_table(extracted.get("findings", []))
        for f in extracted.get("findings", []):
            if f.get("severity") in ["critical", "high"]:
                session.add_vulnerability({
                    "type":     f.get("template", ""),
                    "location": f.get("target", ""),
                    "severity": f.get("severity", ""),
                    "details":  f.get("type", "")
                })

    # Enregistre le finding
    items = extracted.get("open_ports",
            extracted.get("paths",
            extracted.get("findings", [])))
    # Enregistre le finding avec la commande réelle
    session.add_finding(
        tool=tool,
        summary=f"Cmd: {command_line or tool}",
        raw=raw_output
    )

    display.separator()

    # ── Logique Plan ──
    active_option = planner.get_active_option()
    is_recon      = _is_recon_tool(tool)

    # CAS 1 : Scan recon initial et pas encore de plan → génère le plan
    if is_recon and not planner.has_plan():
        # Analyse standard d'abord
        _run_standard_analysis(raw_output, tool, session, extracted)
        display.separator()
        _trigger_plan_generation(session, planner, extracted)
        return

    # CAS 2 : Une option est active → analyse le résultat dans ce contexte
    if active_option:
        context  = session.get_context_summary() + session.get_plan_status_summary()
        history  = session.get_llm_history()
        
        # Optimisation Coût : DeepSeek résume le log brut pour Claude
        if len(raw_output) > 200:
            display.filtering()
            digest = deepseek.pre_digest(raw_output)
        else:
            digest = raw_output
            
        display.analyzing("claude")
        analysis = claude.analyze_step_result(context, active_option, digest, history)

        # Détermine si c'est un succès ou un échec (heuristique simple)
        success_keywords = ["succès", "trouvé", "access", "shell", "credential",
                            "injectable", "vulnerable", "valid", "login:", "password:"]
        fail_keywords    = ["aucun", "nothing", "no result", "failed", "timeout",
                            "error", "filtered", "closed", "not found"]

        analysis_lower = analysis.lower()
        is_success = any(k in analysis_lower for k in success_keywords)
        is_fail    = any(k in analysis_lower for k in fail_keywords)

        if is_success and not is_fail:
            active_option["status"] = OptionStatus.SUCCESS
        elif is_fail:
            active_option["status"] = OptionStatus.FAILED

        display.option_result(active_option, "", analysis)
        session.add_to_history("assistant", analysis)
        session.save()

        # Affiche le tableau mis à jour
        summary = planner.get_plan_summary()
        display.plan_table(summary["options"], summary["active"])

        # CAS 3 : Toutes les options épuisées → re-plan
        if planner.all_options_exhausted():
            _trigger_replan(session, planner)
        return

    # CAS 4 : Pas de plan actif → analyse standard + routing LLM classique
    _run_standard_analysis(raw_output, tool, session, extracted)


def _run_standard_analysis(raw_output: str, tool: str, session: Session, extracted: dict):
    """Analyse LLM standard (routing Claude/DeepSeek)."""
    llm_choice = router.route_auto(raw_output, tool)
    context    = session.get_context_summary() + session.get_plan_status_summary()
    history    = session.get_llm_history()

    if llm_choice == "claude":
        # Optimisation Coût : DeepSeek pré-digère l'output pour Claude
        if len(raw_output) > 200:
            display.filtering()
            digest = deepseek.pre_digest(raw_output)
        else:
            digest = raw_output
            
        display.analyzing("claude")
        response = claude.analyze(context, {"digest": digest, "metadata": extracted}, history)
    else:
        display.analyzing("deepseek")
        response = deepseek.generate_payloads(context, extracted, history)

    display.analysis_result(response, llm_choice)
    session.add_to_history("assistant", response)


# ─────────────────────────────────────────────
# GESTION DES JOBS (ARRIÈRE-PLAN)
# ─────────────────────────────────────────────

background_jobs = []

def wrapper_mode(tool: str, args: list, session: Session, planner: Planner, background: bool = False):
    """Lance la commande réelle et intercepte l'output."""
    if background:
        # Lance dans un thread séparé
        t = threading.Thread(
            target=_run_command_thread, 
            args=(tool, args, session, planner),
            daemon=True
        )
        t.start()
        display.success(f"Commande lancée en arrière-plan (Job {len(background_jobs) + 1})")
        background_jobs.append({"tool": tool, "thread": t, "start": time.time()})
        return

    _run_command_thread(tool, args, session, planner)


def _run_command_thread(tool: str, args: list, session: Session, planner: Planner):
    """Logique d'exécution réelle (synchrone)."""
    cmd_str = " ".join([tool] + args)
    display.info(f"Lancement : {cmd_str}")

    try:
        process = subprocess.Popen(
            cmd_str,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            shell=True,
            bufsize=1,
            universal_newlines=True
        )
        
        raw_output = ""
        for line in process.stdout:
            print(line, end="", flush=True)
            raw_output += line
            
        process.wait(timeout=1800)
        
        if not raw_output.strip():
            display.error("Aucun output reçu.")
            return

        display.separator()
        process_output(raw_output, cmd_str, session, planner)
        
        # Si c'était en arrière-plan, on notifie à la fin
        # (On pourrait ajouter un flag, mais l'affichage suffit)

    except FileNotFoundError:
        display.error(f"Outil '{tool}' introuvable. Vérifie ton PATH.")
    except subprocess.TimeoutExpired:
        display.error("Timeout — commande trop longue.")
    except Exception as e:
        display.error(f"Erreur d'exécution : {e}")


def pipe_mode(session: Session, planner: Planner):
    """Lit depuis stdin (mode pipe)."""
    if sys.stdin.isatty():
        return False

    raw_output = sys.stdin.read()
    if not raw_output.strip():
        return False

    process_output(raw_output, "", session, planner)
    return True


def interactive_shell(session: Session, planner: Planner):
    """Mode shell interactif."""
    display.banner()
    display.session_summary(session.data)

    # Affiche le plan si déjà existant
    if planner.has_plan():
        summary = planner.get_plan_summary()
        display.plan_table(summary["options"], summary["active"])

    display.info("Mode shell interactif. '!' pour lancer une commande, 'help' pour l'aide.")

    while True:
        try:
            target_label = session.target if session.target != "unknown" else "no-target"
            active_opt   = planner.get_active_option()
            opt_label    = f"|opt:{active_opt['id']}" if active_opt else ""
            question     = input(f"\n[norhack][{target_label}{opt_label}]> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if question.lower() in ["exit", "quit", "q"]:
            break

        if not question:
            continue

        # ── Commandes internes du shell ──
        if question == "help":
            print(__doc__)
            continue

        if question == "plan":
            _cmd_plan(planner)
            continue

        if question.startswith("option "):
            opt_id = question.split()[1].upper()
            _cmd_option(opt_id, planner)
            continue

        if question.startswith("done"):
            parts   = question.split(maxsplit=2)
            opt_id  = parts[1].upper() if len(parts) > 1 and len(parts[1]) == 1 else None
            summary = parts[2] if len(parts) > 2 else ""
            _cmd_done(opt_id, summary, session, planner)
            continue

        if question.startswith("fail"):
            parts  = question.split(maxsplit=2)
            opt_id = parts[1].upper() if len(parts) > 1 and len(parts[1]) == 1 else None
            reason = parts[2] if len(parts) > 2 else ""
            _cmd_fail(opt_id, reason, session, planner)
            continue

        # ── Lancement d'une commande outil ──
        if question.startswith("!"):
            cmd_line = question[1:].strip()
            is_bg    = cmd_line.endswith("&")
            if is_bg:
                cmd_line = cmd_line[:-1].strip()
            
            cmd_parts = cmd_line.split()
            if cmd_parts:
                wrapper_mode(cmd_parts[0], cmd_parts[1:], session, planner, background=is_bg)
            continue

        # ── Question libre → LLM ──
        context  = session.get_context_summary() + session.get_plan_status_summary()
        history  = session.get_llm_history()

        keywords_deepseek = ["payload", "exploit", "bypass", "shell", "inject"]
        llm_choice        = "deepseek" if any(k in question.lower() for k in keywords_deepseek) else "claude"

        display.analyzing(llm_choice)

        if llm_choice == "claude":
            response = claude.ask(question, context, history)
        else:
            response = deepseek.ask(question, context, history)

        display.analysis_result(response, llm_choice)
        session.add_to_history("user", question)
        session.add_to_history("assistant", response)


# ─────────────────────────────────────────────
# COMMANDES INTERNES
# ─────────────────────────────────────────────

def _cmd_plan(planner: Planner):
    """Affiche le plan d'attaque actif."""
    if not planner.has_plan():
        display.info("Aucun plan d'attaque actif. Lance un scan nmap d'abord.")
        return
    summary = planner.get_plan_summary()
    display.plan_generated(
        version=summary["version"],
        threat_level=summary["threat_level"],
        recon_summary=summary["recon_summary"]
    )
    display.plan_table(summary["options"], summary["active"])


def _cmd_option(option_id: str, planner: Planner):
    """Démarre manuellement une option du plan."""
    if not planner.has_plan():
        display.error("Aucun plan actif.")
        return
    planner.start_option(option_id)
    opt = planner.get_active_option()
    if opt:
        display.option_start(opt)
    else:
        display.error(f"Option '{option_id}' introuvable.")


def _cmd_done(option_id: str | None, result_summary: str, session: Session, planner: Planner):
    """Marque une option comme réussie."""
    opt = planner.get_active_option() if not option_id else None
    if option_id:
        planner.start_option(option_id)  # s'assure qu'elle est active
        opt = planner.get_active_option()

    if not opt:
        display.error("Aucune option active à marquer.")
        return

    planner.mark_success(opt["id"], result_summary or "Résultat concluant.")
    display.success(f"Option {opt['id']} marquée SUCCÈS : {result_summary}")
    summary = planner.get_plan_summary()
    display.plan_table(summary["options"], summary["active"])


def _cmd_fail(option_id: str | None, reason: str, session: Session, planner: Planner):
    """Marque une option comme échouée et passe à la suivante."""
    opt = planner.get_active_option() if not option_id else None
    if option_id:
        planner.start_option(option_id)
        opt = planner.get_active_option()

    if not opt:
        display.error("Aucune option active à marquer.")
        return

    planner.mark_failed(opt["id"], reason or "Rien de concluant.")
    display.error(f"Option {opt['id']} marquée ÉCHEC : {reason}")

    # Avance automatiquement à la suivante
    next_opt = planner.auto_advance()
    if next_opt:
        display.option_start(next_opt)
    elif planner.all_options_exhausted():
        _trigger_replan(session, planner)


# ─────────────────────────────────────────────
# POINT D'ENTRÉE PRINCIPAL
# ─────────────────────────────────────────────

def main():
    target  = os.getenv("HACK_TARGET", "unknown")
    session = get_or_create_session(target)
    planner = Planner(session)

    # Mode pipe
    if not sys.stdin.isatty():
        pipe_mode(session, planner)
        return

    if len(sys.argv) < 2:
        display.banner()
        print(__doc__)
        return

    cmd = sys.argv[1].lower()

    # ── Commandes internes ──

    if cmd == "shell":
        if len(sys.argv) >= 3:
            target  = sys.argv[2]
            session = get_or_create_session(target)
            planner = Planner(session)
        interactive_shell(session, planner)

    elif cmd == "target":
        if len(sys.argv) >= 3:
            target = sys.argv[2]
            os.environ["HACK_TARGET"] = target
            session = get_or_create_session(target)
            planner = Planner(session)
            display.success(f"Cible définie : {target}")
        else:
            display.error("Usage: hack target <ip_ou_domaine>")

    elif cmd == "plan":
        if len(sys.argv) >= 3:
            target  = sys.argv[2]
            session = get_or_create_session(target)
            planner = Planner(session)
        _cmd_plan(planner)

    elif cmd == "option":
        if len(sys.argv) >= 3:
            _cmd_option(sys.argv[2].upper(), planner)
        else:
            display.error("Usage: hack option <A|B|C>")

    elif cmd == "done":
        opt_id  = sys.argv[2].upper() if len(sys.argv) >= 3 and len(sys.argv[2]) == 1 else None
        summary = " ".join(sys.argv[3:]) if len(sys.argv) >= 4 else (sys.argv[2] if len(sys.argv) >= 3 and len(sys.argv[2]) > 1 else "")
        _cmd_done(opt_id, summary, session, planner)

    elif cmd == "fail":
        opt_id = sys.argv[2].upper() if len(sys.argv) >= 3 and len(sys.argv[2]) == 1 else None
        reason = " ".join(sys.argv[3:]) if len(sys.argv) >= 4 else (sys.argv[2] if len(sys.argv) >= 3 and len(sys.argv[2]) > 1 else "")
        _cmd_fail(opt_id, reason, session, planner)

    elif cmd == "replan":
        if len(sys.argv) >= 3:
            target  = sys.argv[2]
            session = get_or_create_session(target)
            planner = Planner(session)
        if planner.has_plan():
            _trigger_replan(session, planner)
        else:
            display.error("Aucun plan existant. Lance un scan nmap d'abord.")

    elif cmd == "session":
        if len(sys.argv) >= 3:
            session = get_or_create_session(sys.argv[2])
        display.session_summary(session.data)

    elif cmd == "sessions":
        sessions = Session.list_sessions()
        if sessions:
            display.info(f"{len(sessions)} session(s) trouvée(s) :")
            for s in sessions:
                print(f"  • {s}")
        else:
            display.info("Aucune session sauvegardée.")

    else:
        # Mode wrapper — premier arg = outil pentest
        tool = sys.argv[1]
        args = sys.argv[2:]
        wrapper_mode(tool, args, session, planner)


if __name__ == "__main__":
    main()