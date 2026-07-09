"""
zx_engine.py
------------
Wrapper around the `zxcvbn` library (Dropbox's realistic password-strength
estimator). Unlike a naive entropy calculation (length x log2(charset)),
zxcvbn actually pattern-matches against dictionaries (common passwords,
English words, names, wikipedia titles), keyboard walks, l33t substitutions,
dates and repeats -- so it correctly flags things like "P@ssw0rd123" as
weak even though its raw character-set entropy looks high.

This module normalizes zxcvbn's output into the shapes the rest of the
toolkit (analyzer.py, scoring.py, cli/app.py) already expects, so it can be
merged with the existing entropy/pattern engine instead of replacing it.
"""
from typing import Dict, List

from zxcvbn import zxcvbn

# zxcvbn score: 0 = too guessable ... 4 = very unguessable
SCORE_LABELS = {
    0: "VERY WEAK",
    1: "WEAK",
    2: "MEDIUM",
    3: "STRONG",
    4: "VERY STRONG",
}


def _summarize_sequence(sequence: List[dict]) -> List[str]:
    """Turn zxcvbn's raw match sequence into short human-readable tags,
    e.g. ['dictionary:password (l33t)', 'sequence:digits']."""
    summary = []
    for match in sequence:
        pattern = match.get("pattern", "unknown")
        if pattern == "dictionary":
            word = match.get("matched_word", match.get("token", ""))
            tag = f"dictionary:{word}"
            if match.get("l33t"):
                tag += " (l33t)"
            if match.get("reversed"):
                tag += " (reversed)"
            summary.append(tag)
        elif pattern == "sequence":
            summary.append(f"sequence:{match.get('sequence_name', 'unknown')}")
        elif pattern == "repeat":
            summary.append(f"repeat:{match.get('base_token', match.get('token', ''))}")
        elif pattern == "date":
            summary.append("date")
        elif pattern == "spatial":
            summary.append(f"keyboard_walk:{match.get('graph', 'unknown')}")
        else:
            summary.append(pattern)
    return summary


def analyze_zxcvbn(password: str) -> Dict:
    """Run zxcvbn against a password and return a normalized result dict.

    Returns:
        {
            "score": int (0-4),
            "level": str,
            "guesses": float,             # estimated total guesses needed
            "guesses_log10": float,
            "crack_times": {              # human readable, real-world scenarios
                "online_throttled": str,   # e.g. rate-limited login form
                "online_unthrottled": str, # no rate limiting
                "offline_slow_hash": str,  # bcrypt/scrypt/argon2 style
                "offline_fast_hash": str,  # unsalted md5/sha1 + GPU
            },
            "warning": str,               # empty string if none
            "suggestions": List[str],
            "matched_patterns": List[str],# human readable pattern tags
        }
    """
    if not password:
        return {
            "score": 0,
            "level": "VERY WEAK",
            "guesses": 0,
            "guesses_log10": 0.0,
            "crack_times": {
                "online_throttled": "instantly",
                "online_unthrottled": "instantly",
                "offline_slow_hash": "instantly",
                "offline_fast_hash": "instantly",
            },
            "warning": "Empty password",
            "suggestions": ["Enter a password"],
            "matched_patterns": [],
        }

    result = zxcvbn(password)
    score = result["score"]
    feedback = result.get("feedback", {}) or {}
    crack_display = result.get("crack_times_display", {})

    return {
        "score": score,
        "level": SCORE_LABELS.get(score, "UNKNOWN"),
        "guesses": float(result.get("guesses", 0)),
        "guesses_log10": float(result.get("guesses_log10", 0.0)),
        "crack_times": {
            "online_throttled": crack_display.get("online_throttling_100_per_hour", "N/A"),
            "online_unthrottled": crack_display.get("online_no_throttling_10_per_second", "N/A"),
            "offline_slow_hash": crack_display.get("offline_slow_hashing_1e4_per_second", "N/A"),
            "offline_fast_hash": crack_display.get("offline_fast_hashing_1e10_per_second", "N/A"),
        },
        "warning": feedback.get("warning") or "",
        "suggestions": list(feedback.get("suggestions") or []),
        "matched_patterns": _summarize_sequence(result.get("sequence", [])),
    }
