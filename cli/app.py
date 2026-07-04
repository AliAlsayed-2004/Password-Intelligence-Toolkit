import typer
from cli.banner import show_banner

app = typer.Typer(help="Password Intelligence Toolkit CLI")

@app.command()
def start():
    """Start PIT CLI"""
    show_banner()
    print("\n[+] Welcome to Password Intelligence Toolkit\n")

@app.command()
def analyze(password: str):
    """Dummy analyzer (we will improve later)"""
    show_banner()
    print(f"\n[*] Analyzing password: {password}\n")