from core.patterns import has_repetition, has_sequence, keyboard_weak


def advanced_score(password: str, entropy: float) -> int:
    score = 100

    if len(password) < 8:
        score -= 25

    if "password" in password.lower():
        score -= 40

    if "123" in password:
        score -= 25

    # entropy (small influence only)
    if entropy < 20:
        score -= 30
    elif entropy < 40:
        score -= 15
    elif entropy < 60:
        score -= 5

    # patterns
    if has_sequence(password):
        score -= 20

    if has_repetition(password):
        score -= 15

    if keyboard_weak(password):
        score -= 20

    return max(0, min(100, round(score)))

def classify(score: int) -> str:
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