import typer
from rich.console import Console
from rich.table import Table

from cli.banner import show_banner
from core.analyzer import analyze_password
from core.wordlist import generate_wordlist
from core.hashes import generate_hash, verify_hash

app = typer.Typer(help="Password Intelligence Toolkit CLI")
console = Console()


@app.command()
def start():
    """Start PIT CLI"""
    show_banner()
    print("\n[+] Welcome to Password Intelligence Toolkit\n")

@app.command()
@app.command()
def analyze(password: str):
    """Analyze password strength"""

    show_banner()

    result = analyze_password(password)
    attack = result.get("attack", {})

    table = Table(title="Password Analysis Report", style="cyan")

    table.add_column("Field", style="bold")
    table.add_column("Value", style="green")

    table.add_row("Password", result["password"])
    table.add_row("Entropy", str(result["entropy"]))
    table.add_row("Score", f"{result['score']} / 100")
    table.add_row("Strength Level", result["level"])
    table.add_row("Weak Patterns", ", ".join(result["weak_patterns"]) or "None")
    
    table.add_row("Offline Mid GPU", str(attack.get("offline_mid_gpu", "N/A")))
    table.add_row("Offline Fast GPU", str(attack.get("offline_fast_gpu", "N/A")))
    table.add_row("Online Attack", str(attack.get("online_attack", "N/A")))
    table.add_row("Strength Rating", str(attack.get("strength_rating", "N/A")))
    
    if attack.get("recommendations"):
        recs = " | ".join(attack["recommendations"][:2])  
        table.add_row("Recommendations", recs)

    console.print(table)


@app.command()
def wordlist(seed: str):
    """Generate wordlist from seed"""

    show_banner()

    seeds = seed.split(",")
    results = generate_wordlist(seeds)

    console.print(f"\n[bold green]Generated {len(results)} passwords[/bold green]\n")

    for i, word in enumerate(results[:50]):  
        console.print(f"[{i}] {word}")


@app.command()
def hash(text: str, algorithm: str = "sha256"):
    """Generate hash from text"""

    show_banner()

    result = generate_hash(text, algorithm)

    console.print("\n[bold cyan]Hash Result[/bold cyan]\n")
    console.print(f"[green]{algorithm}[/green]: {result}")

@app.command()
def verify(text: str, hash_value: str, algorithm: str = "sha256"):
    """Verify hash"""

    show_banner()

    result = verify_hash(text, hash_value, algorithm)

    if result:
        console.print("[bold green]✔ Hash MATCHED[/bold green]")
    else:
        console.print("[bold red]✖ Hash NOT matched[/bold red]")