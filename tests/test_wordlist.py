from core.wordlist import generate_wordlist


def test_wordlist_generation():
    result = generate_wordlist(["ali"])

    assert isinstance(result, list)
    assert len(result) > 1


def test_wordlist_contains_seed():
    result = generate_wordlist(["test"])

    assert "test" in result