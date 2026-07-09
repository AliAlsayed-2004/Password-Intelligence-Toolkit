from core.patterns import has_repetition, has_sequence, keyboard_weak


def advanced_score(password: str, entropy: float) -> int:
    score = 100

    if len(password) < 8:
        score -= 25

    if "password" in password.lower():
        score -= 40

    if "123" in password:
        score -= 25

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


# zxcvbn's 0-4 score mapped onto the same 0-100 scale used by advanced_score,
# so the two engines can be compared/combined on equal footing.
ZXCVBN_SCORE_TO_100 = {0: 5, 1: 25, 2: 50, 3: 75, 4: 95}
ZXCVBN_SCORE_TO_LEVEL = {0: "VERY WEAK", 1: "WEAK", 2: "MEDIUM", 3: "STRONG", 4: "VERY STRONG"}
LEVEL_RANK = {"VERY WEAK": 0, "WEAK": 1, "MEDIUM": 2, "STRONG": 3, "VERY STRONG": 4}


def reconcile_score(custom_score: int, zxcvbn_score: int) -> dict:
    """Combine the naive charset/pattern score with zxcvbn's real-world
    dictionary-aware score.

    zxcvbn is far better at catching disguised weak passwords (e.g.
    "P@ssw0rd123" scores high on raw entropy but is a well-known password
    with leet substitutions). Rather than pick one engine, we take the more
    conservative (weaker) verdict of the two -- a password is only as
    strong as its weakest assessment.
    """
    zxcvbn_as_100 = ZXCVBN_SCORE_TO_100.get(zxcvbn_score, 50)
    custom_level = classify(custom_score)
    zxcvbn_level = ZXCVBN_SCORE_TO_LEVEL.get(zxcvbn_score, "MEDIUM")

    final_score = min(custom_score, zxcvbn_as_100)
    final_level = custom_level if LEVEL_RANK[custom_level] <= LEVEL_RANK[zxcvbn_level] else zxcvbn_level

    return {
        "final_score": final_score,
        "final_level": final_level,
        "custom_score": custom_score,
        "custom_level": custom_level,
        "zxcvbn_score": zxcvbn_score,
        "zxcvbn_level": zxcvbn_level,
        "engines_agree": custom_level == zxcvbn_level,
    }