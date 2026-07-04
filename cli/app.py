import typer
from rich.console import Console
from rich.table import Table

from cli.banner import show_banner
from core.analyzer import analyze_password

app = typer.Typer(help="Password Intelligence Toolkit CLI")
console = Console()


@app.command()
def start():
    """Start PIT CLI"""
    show_banner()
    print("\n[+] Welcome to Password Intelligence Toolkit\n")

@app.command()
def analyze(password: str):
    """Analyze password strength"""

    show_banner()

    result = analyze_password(password)

    table = Table(title="Password Analysis Report", style="cyan")

    table.add_column("Field", style="bold")
    table.add_column("Value", style="green")

    table.add_row("Password", result["password"])
    table.add_row("Entropy", str(result["entropy"]))
    table.add_row("Score", f"{result['score']} / 100")
    table.add_row("Strength Level", result["level"])
    table.add_row("Weak Patterns", ", ".join(result["weak_patterns"]) or "None")

    console.print(table)