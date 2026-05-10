from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.rule import Rule
from rich.syntax import Syntax
from rich import box
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