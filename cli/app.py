import typer
from rich.console import Console
from rich.table import Table

from cli.banner import show_banner
from core.analyzer import analyze_password

app = typer.Typer(help="Password Intelligence Toolkit CLI")
console = Console()

@app.command()
def start():
    show_banner()
    print("\n[+] Welcome to Password Intelligence Toolkit\n")

@app.command()
def analyze(
    password: str,
    check_breach: bool = typer.Option(
        False, "--check-breach", "-b", help="Also check this password against HaveIBeenPwned (requires internet)."
    ),
):
    """Analyze password strength"""
    show_banner()
    result = analyze_password(password)
    attack = result.get("attack", {})
    zx = result.get("zxcvbn", {})

    table = Table(title="Password Analysis Report", style="cyan")
    table.add_column("Field", style="bold")
    table.add_column("Value", style="green")

    table.add_row("Password", result["password"])
    table.add_row("Entropy", str(result["entropy"]))
    table.add_row("Local Score", f"{result['score']} / 100 ({result['level']})")
    table.add_row("Weak Patterns", ", ".join(result["weak_patterns"]) or "None")

    table.add_row("", "")
    table.add_row("[bold]zxcvbn Score[/bold]", f"{zx.get('score', 'N/A')} / 4 ({zx.get('level', 'N/A')})")
    if zx.get("matched_patterns"):
        table.add_row("Matched Patterns", ", ".join(zx["matched_patterns"]))
    if zx.get("warning"):
        table.add_row("[bold yellow]Warning[/bold yellow]", zx["warning"])
    ct = zx.get("crack_times", {})
    table.add_row("Crack: Online (throttled)", ct.get("online_throttled", "N/A"))
    table.add_row("Crack: Online (no limit)", ct.get("online_unthrottled", "N/A"))
    table.add_row("Crack: Offline (slow hash)", ct.get("offline_slow_hash", "N/A"))
    table.add_row("Crack: Offline (fast hash/GPU)", ct.get("offline_fast_hash", "N/A"))

    table.add_row("", "")
    verdict_style = "bold green" if result["final_level"] in ("STRONG", "VERY STRONG") else "bold red"
    table.add_row(
        f"[{verdict_style}]FINAL VERDICT[/{verdict_style}]",
        f"[{verdict_style}]{result['final_score']} / 100 -- {result['final_level']}[/{verdict_style}]",
    )
    if not result["engines_agree"]:
        table.add_row(
            "Note",
            "Local score and zxcvbn disagree -- the weaker (more conservative) verdict was used.",
        )

    if check_breach:
        from core.breach_check import check_password_breach, format_breach_result, BreachCheckError

        try:
            breach_result = check_password_breach(password)
            table.add_row("", "")
            style = "bold red" if breach_result["breached"] else "bold green"
            table.add_row(
                f"[{style}]HIBP Breach Check[/{style}]",
                f"[{style}]{format_breach_result(breach_result)}[/{style}]",
            )
        except BreachCheckError as exc:
            table.add_row("HIBP Breach Check", f"[yellow]{exc}[/yellow]")

    if zx.get("suggestions"):
        table.add_row("Suggestions", "\n".join(zx["suggestions"][:3]))
    elif attack.get("recommendations"):
        recs = "\n".join(attack["recommendations"][:3])
        table.add_row("Recommendations", recs)

    console.print(table)


@app.command(name="check-breach")
def check_breach_command(password: str):
    """Check a password against HaveIBeenPwned (k-anonymity, password never leaves your machine in full)."""
    from core.breach_check import check_password_breach, format_breach_result, BreachCheckError

    show_banner()
    console.print(
        "[dim]Sending only the first 5 chars of the SHA-1 hash (k-anonymity) -- "
        "your password is never transmitted.[/dim]\n"
    )
    try:
        result = check_password_breach(password)
    except BreachCheckError as exc:
        console.print(f"[bold yellow][!] {exc}[/bold yellow]")
        raise typer.Exit(code=1)

    style = "bold red" if result["breached"] else "bold green"
    console.print(f"[{style}]{format_breach_result(result)}[/{style}]")
    console.print(f"[dim]Prefix sent to API: {result['prefix_sent']}[/dim]")

@app.command()
def wordlist(seed: str):
    from core.wordlist import generate_wordlist
    show_banner()
    seeds = seed.split(",")
    results = generate_wordlist(seeds)
    console.print(f"\n[bold green]Generated {len(results)} passwords[/bold green]\n")
    for i, word in enumerate(results[:30]):
        console.print(f"[{i}] {word}")

if __name__ == "__main__":
    app()