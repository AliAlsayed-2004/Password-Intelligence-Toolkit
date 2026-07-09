"""
breach_check.py
----------------
Checks a password against the HaveIBeenPwned "Pwned Passwords" database
using the k-anonymity range API. The full password (and even its full
hash) NEVER leaves the machine:

  1. The password is hashed locally with SHA-1.
  2. Only the first 5 hex characters of the hash (the "prefix") are sent
     to the API.
  3. HIBP returns every known breached-hash suffix that starts with that
     prefix (typically several hundred), along with how many times each
     one has been seen.
  4. The comparison against the *full* hash happens locally.

This means the API operator can never learn which password was checked --
it only ever sees a 5-character prefix shared by hundreds of other
passwords. See: https://haveibeenpwned.com/API/v3#PwnedPasswords
"""
import hashlib
from typing import Optional

import requests

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
USER_AGENT = "Password-Intelligence-Toolkit"
REQUEST_TIMEOUT = 6  # seconds


class BreachCheckError(Exception):
    """Raised when the HIBP API can't be reached or returns an error."""


def _sha1_prefix_suffix(password: str) -> tuple[str, str]:
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return sha1[:5], sha1[5:]


def check_password_breach(password: str) -> dict:
    """Check whether a password appears in the HIBP Pwned Passwords set.

    Returns:
        {
            "breached": bool,
            "times_seen": int,       # 0 if not found
            "prefix_sent": str,      # the 5-char prefix actually transmitted
        }

    Raises:
        BreachCheckError if the request fails (network issue, non-200, etc).
    """
    if not password:
        return {"breached": False, "times_seen": 0, "prefix_sent": ""}

    prefix, suffix = _sha1_prefix_suffix(password)

    try:
        response = requests.get(
            HIBP_RANGE_URL.format(prefix=prefix),
            headers={"User-Agent": USER_AGENT},
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise BreachCheckError(f"Could not reach HaveIBeenPwned API: {exc}") from exc

    if response.status_code != 200:
        raise BreachCheckError(f"HIBP API returned unexpected status {response.status_code}")

    times_seen = 0
    for line in response.text.splitlines():
        if ":" not in line:
            continue
        hash_suffix, count = line.split(":", 1)
        if hash_suffix.strip() == suffix:
            times_seen = int(count.strip())
            break

    return {
        "breached": times_seen > 0,
        "times_seen": times_seen,
        "prefix_sent": prefix,
    }


def format_breach_result(result: dict, error: Optional[str] = None) -> str:
    """Human-readable one-liner for CLI output."""
    if error:
        return f"[!] Breach check failed: {error}"
    if result["breached"]:
        return (
            f"[!] FOUND in {result['times_seen']:,} known breaches. "
            "Never use this password anywhere."
        )
    return "[OK] Not found in the HIBP breach database (but that alone doesn't make it a good password)."
