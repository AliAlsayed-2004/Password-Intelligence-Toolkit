from core.zx_engine import analyze_zxcvbn
from core.scoring import reconcile_score


def test_empty_password():
    result = analyze_zxcvbn("")
    assert result["score"] == 0
    assert result["level"] == "VERY WEAK"


def test_common_password_flagged_weak():
    result = analyze_zxcvbn("password123")
    assert result["score"] <= 1
    assert result["level"] in ("VERY WEAK", "WEAK")
    assert any("dictionary" in p for p in result["matched_patterns"])


def test_disguised_weak_password_still_flagged():
    # Looks strong by charset/length alone, but is a well-known password
    # with leetspeak substitutions -- zxcvbn should still catch it.
    result = analyze_zxcvbn("P@ssw0rd123")
    assert result["score"] <= 1
    assert any("dictionary" in p for p in result["matched_patterns"])


def test_long_random_password_scores_high():
    result = analyze_zxcvbn("Tr4ck!ng-Nebula-Ferret-92xQ")
    assert result["score"] >= 3


def test_reconcile_takes_weaker_verdict():
    # local engine over-scores this password (high entropy), zxcvbn should
    # pull the final verdict down
    reconciled = reconcile_score(custom_score=75, zxcvbn_score=1)
    assert reconciled["final_level"] == "WEAK"
    assert reconciled["final_score"] <= 25
    assert reconciled["engines_agree"] is False


def test_reconcile_when_engines_agree():
    reconciled = reconcile_score(custom_score=90, zxcvbn_score=4)
    assert reconciled["final_level"] == "VERY STRONG"
    assert reconciled["engines_agree"] is True
