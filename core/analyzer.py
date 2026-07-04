import string
from core.entropy import calculate_entropy


COMMON_PATTERNS = [
    "1234", "123456", "password", "admin",
    "qwerty", "abc123", "1111", "0000"
]


def detect_weak_patterns(password: str):
    found = []

    lower = password.lower()

    for pattern in COMMON_PATTERNS:
        if pattern in lower:
            found.append(pattern)

    return found


def calculate_score(password: str, entropy: float, weak_patterns: list):
    score = 0

    # base from entropy
    score += min(entropy, 60)

    # length bonus
    score += min(len(password) * 2, 20)

    # complexity bonus
    if any(c.isupper() for c in password):
        score += 5
    if any(c.isdigit() for c in password):
        score += 5
    if any(c in string.punctuation for c in password):
        score += 10

    # penalty for weak patterns
    score -= len(weak_patterns) * 15

    return max(0, min(100, round(score)))


def classify_score(score: int):
    if score < 30:
        return "VERY WEAK"
    elif score < 50:
        return "WEAK"
    elif score < 70:
        return "MEDIUM"
    elif score < 85:
        return "STRONG"
    else:
        return "VERY STRONG"


def analyze_password(password: str):
    entropy = calculate_entropy(password)
    weak_patterns = detect_weak_patterns(password)
    score = calculate_score(password, entropy, weak_patterns)
    level = classify_score(score)

    return {
        "password": password,
        "entropy": entropy,
        "score": score,
        "level": level,
        "weak_patterns": weak_patterns
    }