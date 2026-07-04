from core.analyzer import analyze_password


def test_basic_analysis():
    result = analyze_password("Ali123")

    assert "entropy" in result
    assert "score" in result
    assert "level" in result


def test_weak_password():
    result = analyze_password("password123")

    assert result["weak_patterns"]  


def test_strong_password():
    result = analyze_password("A!iX92$kLm#9")

    assert result["score"] > 50