#!/usr/bin/env python3
"""
REDTEAM ASSISTANT
Usage:
  hack <tool> [args...]     — wrapper de commande
  <tool> [args] | hack      — mode pipe
  hack shell                — mode interactif
  hack session <target>     — affiche la session en cours
  hack sessions             — liste toutes les sessions
"""

import sys
import os
import subprocess
import argparse
from dotenv import load_dotenv

load_dotenv()

from core.session import Session
from core.router import Router
from core.analyzer import Analyzer
from core.display import Display
from llm.claude_client import ClaudeClient
from llm.deepseek_client import DeepSeekClient

display = Display()
analyzer = Analyzer()
router = Router()
claude = ClaudeClient()
deepseek = DeepSeekClient()


def get_or_create_session(target: str) -> Session:
    return Session(target=target)


def process_output(raw_output: str, tool_hint: str, session: Session):
    """
    Cœur du système :
    1. Détecte l'outil
    2. Parse l'output
    3. Route vers le bon LLM
    4. Affiche l'analyse
    """
    prepared = analyzer.prepare_for_llm(raw_output, tool_hint)
    tool = prepared["tool"]
    extracted = prepared["extracted"]

    display.tool_detected(tool, session.target)

    # Affichage structuré selon l'outil
    if tool == "nmap":
        hosts = extracted.get("hosts", [])
        for host in hosts:
            display.ports_table(host.get("open_ports", []))
            # Mise à jour session
            for p in host.get("open_ports", []):
                session.add_port(
                    port=int(p["port"]),
                    protocol=p["protocol"],
                    state=p["state"],
                    service=p["service"],
                    version=p["version"]
                )

    elif tool == "gobuster":
        display.paths_table(extracted.get("interesting", []))

    elif tool == "nuclei":
        display.vulnerabilities_table(extracted.get("findings", []))
        for f in extracted.get("findings", []):
            if f["severity"] in ["critical", "high"]:
                session.add_vulnerability({
                    "type": f["template"],
                    "location": f["target"],
                    "severity": f["severity"],
                    "details": f["type"]
                })

    # Ajout au finding log de session
    session.add_finding(
        tool=tool,
        summary=f"{len(extracted.get('open_ports', extracted.get('paths', extracted.get('findings', []))))} éléments trouvés",
        raw=raw_output
    )

    # Routing LLM
    llm_choice = router.route_auto(raw_output, tool)
    context = session.get_context_summary()
    history = session.get_llm_history()

    display.analyzing(llm_choice)
    display.separator()

    if llm_choice == "claude":
        response = claude.analyze(context, extracted, history)
    else:
        response = deepseek.generate_payloads(context, extracted, history)

    display.analysis_result(response, llm_choice)

    # Sauvegarde dans l'historique
    session.add_to_history("assistant", response)


def wrapper_mode(tool: str, args: list, session: Session):
    """Lance la commande réelle et intercepte l'output."""
    cmd = [tool] + args
    display.info(f"Lancement : {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        raw_output = result.stdout + result.stderr

        if not raw_output.strip():
            display.error("Aucun output reçu.")
            return

        # Affiche l'output brut
        print(raw_output)
        display.separator()

        process_output(raw_output, tool, session)

    except FileNotFoundError:
        display.error(f"Outil '{tool}' introuvable. Vérifie ton PATH.")
    except subprocess.TimeoutExpired:
        display.error("Timeout — commande trop longue.")


def pipe_mode(session: Session):
    """Lit depuis stdin (mode pipe)."""
    if sys.stdin.isatty():
        return False

    raw_output = sys.stdin.read()
    if not raw_output.strip():
        return False

    process_output(raw_output, "", session)
    return True


def interactive_shell(session: Session):
    """Mode shell interactif — pose des questions libres ou exécute des outils."""
    display.banner()
    display.session_summary(session.data)
    display.info("Mode shell interactif. Tape 'exit' pour quitter ou '!' pour lancer une commande.")
    display.info("Exemple : !nmap -sV 10.10.10.123")

    while True:
        try:
            prompt_target = session.target if session.target != "unknown" else "no-target"
            question = input(f"\n[hack][{prompt_target}]> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if question.lower() in ["exit", "quit", "q"]:
            break

        if not question:
            continue

        # MODE COMMANDE DIRECTE (commence par !)
        if question.startswith("!"):
            cmd_parts = question[1:].split()
            if cmd_parts:
                tool = cmd_parts[0]
                args = cmd_parts[1:]
                wrapper_mode(tool, args, session)
            continue

        context = session.get_context_summary()
        history = session.get_llm_history()

        # Questions d'exploitation → DeepSeek, reste → Claude
        keywords_deepseek = ["payload", "exploit", "bypass", "shell", "inject"]
        llm_choice = "deepseek" if any(k in question.lower() for k in keywords_deepseek) else "claude"

        display.analyzing(llm_choice)

        if llm_choice == "claude":
            response = claude.ask(question, context, history)
        else:
            response = deepseek.ask(question, context, history)

        display.analysis_result(response, llm_choice)
        session.add_to_history("user", question)
        session.add_to_history("assistant", response)


def main():
    # Charge ou crée une session
    # La cible peut être passée via env var pour le pipe mode
    target = os.getenv("HACK_TARGET", "unknown")
    session = get_or_create_session(target)

    # Mode pipe
    if not sys.stdin.isatty():
        pipe_mode(session)
        return

    if len(sys.argv) < 2:
        display.banner()
        print(__doc__)
        return

    cmd = sys.argv[1].lower()

    # Commandes internes
    if cmd == "shell":
        if len(sys.argv) >= 3:
            target = sys.argv[2]
            session = get_or_create_session(target)
        interactive_shell(session)

    elif cmd == "session":
        if len(sys.argv) >= 3:
            target = sys.argv[2]
            session = get_or_create_session(target)
        display.session_summary(session.data)

    elif cmd == "sessions":
        sessions = Session.list_sessions()
        if sessions:
            display.info(f"{len(sessions)} session(s) trouvée(s) :")
            for s in sessions:
                print(f"  • {s}")
        else:
            display.info("Aucune session sauvegardée.")

    elif cmd == "target":
        if len(sys.argv) >= 3:
            target = sys.argv[2]
            os.environ["HACK_TARGET"] = target
            session = get_or_create_session(target)
            display.success(f"Cible définie : {target}")
        else:
            display.error("Usage: hack target <ip_ou_domaine>")

    else:
        # Mode wrapper — premier arg = outil pentest
        tool = sys.argv[1]
        args = sys.argv[2:]
        wrapper_mode(tool, args, session)


if __name__ == "__main__":
    main()