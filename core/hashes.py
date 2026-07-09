import hashlib
import re
from typing import Iterable, Optional


SUPPORTED_ALGORITHMS = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"]

# Hex digest length -> candidate algorithm(s). Some lengths are ambiguous
# (sha3 variants share lengths with the classic family in other libs), but
# within SUPPORTED_ALGORITHMS each length maps to exactly one algorithm.
HASH_LENGTH_MAP = {
    32: ["md5"],
    40: ["sha1"],
    56: ["sha224"],
    64: ["sha256"],
    96: ["sha384"],
    128: ["sha512"],
}


def generate_hash(text: str, algorithm: str = "sha256"):

    text = text.encode()

    if algorithm == "md5":
        return hashlib.md5(text).hexdigest()

    elif algorithm == "sha1":
        return hashlib.sha1(text).hexdigest()

    elif algorithm == "sha224":
        return hashlib.sha224(text).hexdigest()

    elif algorithm == "sha256":
        return hashlib.sha256(text).hexdigest()

    elif algorithm == "sha384":
        return hashlib.sha384(text).hexdigest()

    elif algorithm == "sha512":
        return hashlib.sha512(text).hexdigest()

    else:
        raise ValueError("Unsupported algorithm")


def verify_hash(text: str, hash_value: str, algorithm: str = "sha256"):
    return generate_hash(text, algorithm) == hash_value


def identify_hash_algorithm(hash_value: str) -> list[str]:
    """Guess which algorithm(s) could have produced this hash, purely from
    its format (hex length). Ambiguous by nature -- a 64-char hex string
    could be sha256 or several other algorithms outside this toolkit's
    scope -- so this returns every plausible candidate, not a single answer.
    """
    hash_value = hash_value.strip()
    if not re.fullmatch(r"[0-9a-fA-F]+", hash_value):
        return []
    return HASH_LENGTH_MAP.get(len(hash_value), [])


def crack_hash(
    hash_value: str,
    candidates: Iterable[str],
    algorithm: Optional[str] = None,
) -> dict:
    """Dictionary attack: try each candidate word against a target hash.

    Intended for auditing your own hashes (e.g. "would this password have
    survived a wordlist attack?") -- not for attacking systems you don't
    own or have authorization to test.

    Args:
        hash_value: the target hex digest.
        candidates: an iterable of plaintext candidate strings.
        algorithm: force a specific algorithm; if None, auto-detected from
            the hash's length (and if ambiguous, every candidate algorithm
            is tried).

    Returns:
        {
            "cracked": bool,
            "plaintext": str | None,
            "algorithm": str | None,   # the algorithm that produced the match
            "attempts": int,           # how many candidates were tried
        }
    """
    hash_value = hash_value.strip().lower()
    algorithms = [algorithm] if algorithm else (identify_hash_algorithm(hash_value) or SUPPORTED_ALGORITHMS)

    attempts = 0
    for candidate in candidates:
        for algo in algorithms:
            attempts += 1
            if generate_hash(candidate, algo) == hash_value:
                return {
                    "cracked": True,
                    "plaintext": candidate,
                    "algorithm": algo,
                    "attempts": attempts,
                }

    return {"cracked": False, "plaintext": None, "algorithm": None, "attempts": attempts}