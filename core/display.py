from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.rule import Rule
from rich.syntax import Syntax
from rich import box
from rich.columns import Columns
import json

console = Console()


class Display:
    """
    Rendu terminal Rich — coloré, structuré, lisible.
    """

    def banner(self):
        console.print(Panel.fit(
            "[bold red]REDTEAM ASSISTANT[/bold red]\n"
            "[dim]Claude Haiku + DeepSeek V3 | Pentest AI Mentor[/dim]",
            border_style="red"
        ))

    def tool_detected(self, tool: str, target: str = ""):
        console.print(
            f"\n[bold yellow]⚡ Tool détecté :[/bold yellow] [cyan]{tool}[/cyan]"
            + (f" [dim]→ {target}[/dim]" if target else "")
        )

    def analyzing(self, llm: str):
        label = (
            "[bold blue]Claude Haiku[/bold blue]"
            if llm == "claude"
            else "[bold magenta]DeepSeek V3[/bold magenta]"
        )
        console.print(f"[dim]Analyse en cours → {label}...[/dim]")

    def filtering(self):
        console.print("[dim]⚡ Filtrage intelligent (DeepSeek V3)...[/dim]")

    def analysis_result(self, content: str, llm: str):
        color = "blue" if llm == "claude" else "magenta"
        label = "CLAUDE HAIKU — ANALYSE" if llm == "claude" else "DEEPSEEK V3 — EXPLOIT"
        console.print(Panel(
            content,
            title=f"[bold {color}]{label}[/bold {color}]",
            border_style=color,
            padding=(1, 2)
        ))

    def ports_table(self, ports: list):
        if not ports:
            return
        table = Table(
            title="Ports découverts",
            box=box.ROUNDED,
            border_style="cyan"
        )
        table.add_column("Port", style="cyan", justify="right")
        table.add_column("Proto", style="dim")
        table.add_column("État", style="bold")
        table.add_column("Service", style="green")
        table.add_column("Version", style="yellow")

        for p in ports:
            state_color = "green" if p["state"] == "open" else "red"
            table.add_row(
                p["port"],
                p["protocol"],
                f"[{state_color}]{p['state']}[/{state_color}]",
                p["service"],
                p["version"]
            )
        console.print(table)

    def paths_table(self, paths: list):
        if not paths:
            return
        table = Table(
            title="Chemins trouvés",
            box=box.ROUNDED,
            border_style="green"
        )
        table.add_column("Path", style="green")
        table.add_column("Status", justify="center")

        status_colors = {
            200: "green", 301: "yellow", 302: "yellow",
            401: "red", 403: "red", 500: "bold red"
        }
        for p in paths:
            color = status_colors.get(p["status"], "white")
            table.add_row(
                p["path"],
                f"[{color}]{p['status']}[/{color}]"
            )
        console.print(table)

    def vulnerabilities_table(self, findings: list):
        if not findings:
            return
        table = Table(
            title="Vulnérabilités détectées",
            box=box.ROUNDED,
            border_style="red"
        )
        table.add_column("Sévérité", justify="center")
        table.add_column("Type")
        table.add_column("Localisation")
        table.add_column("CVE", style="dim")

        severity_colors = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "green",
            "info": "dim"
        }
        for v in findings:
            sev = v.get("severity", "info").lower()
            color = severity_colors.get(sev, "white")
            table.add_row(
                f"[{color}]{sev.upper()}[/{color}]",
                v.get("type", v.get("template", "")),
                v.get("location", v.get("target", "")),
                v.get("cve", "—")
            )
        console.print(table)

    def command_suggestion(self, cmd: str, description: str = ""):
        console.print(f"\n[bold green]→ Commande suggérée :[/bold green]")
        console.print(Syntax(cmd, "bash", theme="monokai", line_numbers=False))
        if description:
            console.print(f"[dim]{description}[/dim]")

    def session_summary(self, session_data: dict):
        ports = session_data.get("ports", {})
        vulns = session_data.get("vulnerabilities", [])
        console.print(Panel(
            f"[bold]Cible :[/bold] {session_data['target']}\n"
            f"[bold]Ports ouverts :[/bold] {len([p for p in ports.values() if p.get('state') == 'open'])}\n"
            f"[bold]Vulnérabilités :[/bold] {len(vulns)}\n"
            f"[bold]Mis à jour :[/bold] {session_data.get('updated_at', '—')}",
            title="[bold cyan]SESSION[/bold cyan]",
            border_style="cyan"
        ))

    def error(self, msg: str):
        console.print(f"[bold red]✗ Erreur :[/bold red] {msg}")

    def info(self, msg: str):
        console.print(f"[bold blue]ℹ[/bold blue] {msg}")

    def success(self, msg: str):
        console.print(f"[bold green]✓[/bold green] {msg}")

    def separator(self):
        console.print(Rule(style="dim"))

    # ─────────────────────────────────────────────
    # ATTACK PLAN DISPLAY
    # ─────────────────────────────────────────────

    def plan_generated(self, version: int, threat_level: str, recon_summary: str):
        """Annonce la génération d'un nouveau plan d'attaque."""
        threat_colors = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "green",
            "unknown": "dim"
        }
        color = threat_colors.get(threat_level.lower(), "white")
        title = f"[bold red]PLAN D'ATTAQUE v{version}[/bold red]  [{color}]MENACE : {threat_level.upper()}[/{color}]"
        console.print(Panel(
            f"[italic]{recon_summary}[/italic]",
            title=title,
            border_style="red",
            padding=(1, 2)
        ))

    def plan_table(self, options: list, active_id: str = None):
        """Affiche le tableau des options A/B/C avec leur statut."""
        status_styles = {
            "pending":  ("[dim]○[/dim]",  "dim"),
            "active":   ("[bold yellow]▶[/bold yellow]", "yellow"),
            "success":  ("[bold green]✓[/bold green]",  "green"),
            "failed":   ("[bold red]✗[/bold red]",    "red"),
        }

        table = Table(
            title="Options d'attaque",
            box=box.ROUNDED,
            border_style="red",
            show_lines=True
        )
        table.add_column("ID",  style="bold",    width=4,  justify="center")
        table.add_column("",                     width=3,  justify="center")  # icone statut
        table.add_column("Option",               min_width=18)
        table.add_column("Objectif",             min_width=25)
        table.add_column("Statut",               width=10, justify="center")
        table.add_column("Résultat",            min_width=20, style="dim")

        for opt in options:
            status = opt.get("status", "pending")
            icon, row_style = status_styles.get(status, ("○", "dim"))
            is_active = opt["id"] == active_id

            label = f"[bold yellow]{opt['label']}[/bold yellow]" if is_active else opt["label"]
            result = opt.get("result_summary") or "—"

            table.add_row(
                f"[bold]{opt['id']}[/bold]",
                icon,
                label,
                opt.get("objective", ""),
                f"[{row_style}]{status}[/{row_style}]",
                result
            )
        console.print(table)

    def option_start(self, option: dict):
        """Annonce le démarrage d'une option."""
        commands = option.get("commands", [])
        cmd_lines = "\n".join(
            f"  [cyan]→[/cyan] {c['cmd']}  [dim]# {c.get('desc', '')}[/dim]"
            for c in commands
        )
        console.print(Panel(
            f"[bold]Objectif :[/bold] {option['objective']}\n"
            f"[bold]Pourquoi :[/bold] {option['rationale']}\n\n"
            f"[bold]Commandes :[/bold]\n{cmd_lines}",
            title=f"[bold yellow]▶ OPTION {option['id']} — {option['label']}[/bold yellow]",
            border_style="yellow",
            padding=(1, 2)
        ))

    def option_result(self, option: dict, verdict: str, analysis: str):
        """Affiche le verdict d'analyse après exécution d'une option."""
        is_success = option.get("status") == "success"
        color = "green" if is_success else "red"
        icon  = "✓ SUCCÈS" if is_success else "✗ ÉCHEC"
        console.print(Panel(
            analysis,
            title=f"[bold {color}]{icon} — Option {option['id']} : {option['label']}[/bold {color}]",
            border_style=color,
            padding=(1, 2)
        ))

    def replan_alert(self):
        """Alerte visuelle quand toutes les options sont épuisées."""
        console.print(Rule(style="red"))
        console.print(
            Panel(
                "[bold red]Toutes les options ont été épuisées.[/bold red]\n"
                "[yellow]Analyse globale en cours — génération d'un nouveau plan...[/yellow]",
                border_style="red",
                padding=(0, 2)
            )
        )
        console.print(Rule(style="red"))