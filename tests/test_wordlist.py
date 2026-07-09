from core.wordlist import generate_wordlist, combine_seeds, case_variations, save_wordlist


def test_wordlist_generation():
    result = generate_wordlist(["ali"])

    assert isinstance(result, list)
    assert len(result) > 1


def test_wordlist_contains_seed():
    result = generate_wordlist(["test"])

    assert "test" in result


def test_combine_seeds_produces_osint_style_combos():
    combos = combine_seeds(["john", "doe"])
    assert "johndoe" in combos
    assert "doejohn" in combos
    assert "john.doe" in combos
    assert "jdoe" in combos


def test_combine_seeds_needs_two_or_more():
    assert combine_seeds(["onlyone"]) == []


def test_generate_wordlist_combines_multiple_seeds():
    result = generate_wordlist(["john", "doe"])
    assert "johndoe" in result


def test_generate_wordlist_no_combine_flag():
    result = generate_wordlist(["john", "doe"], combine=False)
    assert "johndoe" not in result
    assert "john" in result
    assert "doe" in result


def test_case_variations():
    variants = case_variations("test")
    assert "test" in variants
    assert "TEST" in variants
    assert "Test" in variants


def test_length_filters():
    result = generate_wordlist(["ali"], min_length=6, max_length=10)
    assert all(6 <= len(w) <= 10 for w in result)


def test_numeric_suffixes_present():
    result = generate_wordlist(["ali"])
    assert "ali123" in result
    assert "ali007" in result


def test_save_wordlist(tmp_path):
    words = ["alpha", "beta", "gamma"]
    out_file = tmp_path / "out.txt"
    count = save_wordlist(words, str(out_file))

    assert count == 3
    content = out_file.read_text(encoding="utf-8").splitlines()
    assert content == words