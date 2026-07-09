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
def wordlist(
    seed: str,
    output: str = typer.Option(None, "--output", "-o", help="Save the full wordlist to a file (hashcat/John compatible)."),
    min_length: int = typer.Option(None, "--min-length", help="Discard candidates shorter than this."),
    max_length: int = typer.Option(None, "--max-length", help="Discard candidates longer than this."),
    no_combine: bool = typer.Option(False, "--no-combine", help="Don't combine multiple seeds pairwise (e.g. firstname+lastname)."),
):
    """Generate a mutated wordlist from seed word(s).

    Pass multiple comma-separated seeds (e.g. a first name, last name, pet
    name, birth year) to also get OSINT-style combinations like
    "johndoe", "john.doe", "jdoe".
    """
    from core.wordlist import generate_wordlist, save_wordlist

    show_banner()
    seeds = seed.split(",")
    results = generate_wordlist(
        seeds,
        combine=not no_combine,
        min_length=min_length,
        max_length=max_length,
    )

    console.print(f"\n[bold green]Generated {len(results)} passwords[/bold green]\n")

    if output:
        count = save_wordlist(results, output)
        console.print(f"[bold cyan]Saved {count} candidates to {output}[/bold cyan]")
        console.print(f"[dim]hashcat: hashcat -a 0 -m <mode> <hash_file> {output}[/dim]")
        console.print(f"[dim]John:    john --wordlist={output} <hash_file>[/dim]")
    else:
        for i, word in enumerate(results[:30]):
            console.print(f"[{i}] {word}")
        if len(results) > 30:
            console.print(f"[dim]...and {len(results) - 30} more. Use --output to save the full list.[/dim]")


@app.command()
def hash(
    text: str,
    algo: str = typer.Option("sha256", "--algo", "-a", help="md5, sha1, sha224, sha256, sha384, sha512"),
    all: bool = typer.Option(False, "--all", help="Show the hash under every supported algorithm."),
):
    """Generate the hash of a piece of text."""
    from core.hashes import generate_hash, SUPPORTED_ALGORITHMS

    show_banner()
    table = Table(title="Hash Output", style="cyan")
    table.add_column("Algorithm", style="bold")
    table.add_column("Digest", style="green")

    algos = SUPPORTED_ALGORITHMS if all else [algo]
    for a in algos:
        try:
            table.add_row(a, generate_hash(text, a))
        except ValueError:
            table.add_row(a, "[red]unsupported[/red]")

    console.print(table)


@app.command()
def crack(
    hash_value: str,
    wordlist_file: str = typer.Option(
        None, "--wordlist", "-w", help="Path to a plaintext wordlist file (one candidate per line)."
    ),
    seed: str = typer.Option(
        None, "--seed", "-s", help="Comma-separated seed word(s) to mutate on the fly via the wordlist generator, instead of a file."
    ),
    algo: str = typer.Option(
        None, "--algo", "-a", help="Force a specific algorithm instead of auto-detecting from hash length."
    ),
):
    """Dictionary attack against a hash you're authorized to audit.

    Provide either --wordlist (a file) or --seed (mutated on the fly).
    Use this to check whether a password you control would survive a
    basic wordlist attack -- not against systems you don't own.
    """
    from core.hashes import crack_hash, identify_hash_algorithm
    from core.wordlist import generate_wordlist

    show_banner()

    if not wordlist_file and not seed:
        console.print("[bold red][!] Provide either --wordlist <file> or --seed <word(s)>.[/bold red]")
        raise typer.Exit(code=1)

    guessed = identify_hash_algorithm(hash_value)
    if algo:
        console.print(f"[dim]Forcing algorithm: {algo}[/dim]")
    elif guessed:
        console.print(f"[dim]Auto-detected possible algorithm(s) from hash length: {', '.join(guessed)}[/dim]")
    else:
        console.print("[dim]Could not detect algorithm from hash format -- trying all supported algorithms.[/dim]")

    if wordlist_file:
        try:
            with open(wordlist_file, "r", encoding="utf-8", errors="ignore") as f:
                candidates = [line.strip() for line in f if line.strip()]
        except OSError as exc:
            console.print(f"[bold red][!] Could not read wordlist file: {exc}[/bold red]")
            raise typer.Exit(code=1)
        console.print(f"[dim]Loaded {len(candidates)} candidates from {wordlist_file}[/dim]\n")
    else:
        seeds = seed.split(",")
        candidates = generate_wordlist(seeds)
        console.print(f"[dim]Generated {len(candidates)} candidates from seed(s): {seed}[/dim]\n")

    result = crack_hash(hash_value, candidates, algorithm=algo)

    if result["cracked"]:
        console.print(
            f"[bold green][+] CRACKED after {result['attempts']} attempts![/bold green]\n"
            f"    Plaintext : [bold]{result['plaintext']}[/bold]\n"
            f"    Algorithm : {result['algorithm']}"
        )
    else:
        console.print(
            f"[bold yellow][-] Not found in {result['attempts']} attempts. "
            "Try a bigger wordlist or different seeds.[/bold yellow]"
        )

if __name__ == "__main__":
    app()