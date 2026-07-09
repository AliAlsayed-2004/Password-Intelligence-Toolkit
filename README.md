# CERBERUS -- Password Intelligence Toolkit (PIT)

A red-team CLI toolkit for password auditing, breach checking, hash cracking, and
wordlist generation — built to help security professionals evaluate real-world
password strength, not just theoretical entropy.

> ⚠️ **Authorized use only.** PIT is meant for auditing passwords/hashes you own or
> have explicit written authorization to test (your own accounts, your
> organization's password policy, an engagement you're contracted for). Do not use
> it against systems or accounts you don't have permission to test.

---

## Why PIT?

Most simple password checkers score strength using raw entropy (length ×
character-set size). That's misleading: a password like `P@ssw0rd123` looks
strong by that math but is one of the most commonly cracked passwords in the
world once you account for dictionary words and leetspeak substitutions.

PIT runs **two engines side by side** — a fast local heuristic engine and
[`zxcvbn`](https://github.com/dwolfhub/zxcvbn) (the realistic, dictionary-aware
estimator originally built at Dropbox) — and always reports the more
conservative verdict, so you don't get a false sense of security.

## Features

| Command | What it does |
|---|---|
| `analyze` | Full strength report: entropy, dual-engine score, real-world crack-time estimates, weak-pattern detection, optional breach check |
| `check-breach` | Check a password against HaveIBeenPwned's Pwned Passwords database, safely (k-anonymity — your password never leaves your machine) |
| `hash` | Generate a hash of any text (md5, sha1, sha224, sha256, sha384, sha512) |
| `crack` | Dictionary attack against a hash you're authorized to audit, from a wordlist file or generated mutations |
| `wordlist` | Generate a mutated wordlist from seed words (names, dates, pet names) with leetspeak, case variants, numeric suffixes, and OSINT-style combinations |

---

## Installation

Requires Python 3.10+.

```bash
git clone <this-repo-url>
cd "Password Intelligence Toolkit"
pip install -r requirements.txt
```

All commands below are run as:

```bash
python main.py <command> [options]
```

---

## Usage

### `analyze` — full password strength report

```bash
python main.py analyze "P@ssw0rd123"
```

Reports, side by side:
- **Local Score** — fast heuristic score (0-100) based on entropy and pattern detection
- **zxcvbn Score** — realistic score (0-4) based on actual dictionary/pattern matching
- **Matched Patterns** — exactly what zxcvbn recognized (e.g. `dictionary:password (l33t)`)
- **Crack times** — four real-world scenarios: online throttled, online unthrottled, offline slow hash (bcrypt-style), offline fast hash (GPU)
- **FINAL VERDICT** — the weaker (more conservative) of the two engines' verdicts

Add a live breach check (requires internet):

```bash
python main.py analyze "P@ssw0rd123" --check-breach
# or the short flag:
python main.py analyze "P@ssw0rd123" -b
```

---

### `check-breach` — standalone HaveIBeenPwned check

```bash
python main.py check-breach "mypassword123"
```

Uses the Pwned Passwords k-anonymity API: your password is hashed locally
(SHA-1), and only the **first 5 characters** of the hash are sent to the API.
The full comparison happens on your machine — the actual password or full
hash is never transmitted. See: https://haveibeenpwned.com/API/v3#PwnedPasswords

---

### `hash` — generate a hash

```bash
python main.py hash "mypassword"                 # sha256 by default
python main.py hash "mypassword" --algo md5       # specific algorithm
python main.py hash "mypassword" --all            # every supported algorithm
```

Supported algorithms: `md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`.

---

### `crack` — dictionary attack against a hash

```bash
# From a wordlist file you already have
python main.py crack "<hash>" --wordlist rockyou.txt

# From mutated seed words, generated on the fly
python main.py crack "<hash>" --seed "letmein"

# Force a specific algorithm instead of auto-detecting from hash length
python main.py crack "<hash>" --seed "admin" --algo sha1
```

The algorithm is auto-detected from the hash's length when possible (e.g. a
32-character hex string is assumed to be MD5). Use this to check whether a
password you control would survive a basic dictionary attack.

---

### `wordlist` — generate a mutated wordlist

```bash
# Single seed
python main.py wordlist "ali"

# Multiple seeds -> also generates OSINT-style combinations
# (johndoe, doejohn, john.doe, john_doe, jdoe, johnd, ...)
python main.py wordlist "john,doe,1990"

# Filter by length (useful when you know the target's password policy)
python main.py wordlist "ali" --min-length 8 --max-length 12

# Skip pairwise seed combinations
python main.py wordlist "john,doe" --no-combine

# Save directly to a file, ready for hashcat / John the Ripper
python main.py wordlist "john,doe,1990" --output wordlist.txt
```

Each seed is expanded with: leetspeak substitutions, case variants
(`test`/`TEST`/`Test`), year suffixes (2024-2026), common numeric suffixes
(`123`, `007`, `69`, ...), and symbol prefixes/suffixes (`!`, `@`, `#`, `$`,
`*`). When 2+ seeds are given, pairwise OSINT-style combinations are added
too.

Once saved, feed the file straight into your cracking tool of choice:

```bash
hashcat -a 0 -m <mode> <hash_file> wordlist.txt
john --wordlist=wordlist.txt <hash_file>
```

---

## Project structure

```
main.py                    entry point
cli/app.py                 CLI commands (analyze, check-breach, hash, crack, wordlist)
core/analyzer.py           combines all engines into one report
core/entropy.py            charset/length-based entropy calculation
core/patterns.py           weak-pattern detection (sequences, keyboard walks, common passwords)
core/scoring.py             local scoring + score reconciliation between engines
core/zx_engine.py          zxcvbn wrapper (realistic, dictionary-aware analysis)
core/attack_simulation.py  crack-time estimation
core/breach_check.py       HaveIBeenPwned k-anonymity breach check
core/hashes.py             hash generation, algorithm detection, dictionary cracking
core/wordlist.py           mutated wordlist generation
tests/                     unit tests for every module
```

## Running tests

```bash
pip install pytest
pytest tests/ -v
```

## Roadmap

- Bulk/audit mode for scanning a file of passwords and producing a statistics report
- JSON/CSV export for `analyze` results
- Salted-hash support in `crack`
- hashcat `.rule` file support in `wordlist`

## Disclaimer

This tool is provided for educational purposes and authorized security testing
only. The authors are not responsible for misuse. Always obtain proper
authorization before testing systems or accounts you do not own.
