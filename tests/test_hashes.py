from core.hashes import generate_hash, verify_hash, identify_hash_algorithm, crack_hash


def test_sha256_hash():
    result = generate_hash("hello", "sha256")
    assert isinstance(result, str)
    assert len(result) == 64


def test_md5_hash():
    result = generate_hash("hello", "md5")
    assert len(result) == 32


def test_verify_hash_true():
    h = generate_hash("test", "sha256")
    assert verify_hash("test", h, "sha256") is True


def test_verify_hash_false():
    h = generate_hash("test", "sha256")
    assert verify_hash("wrong", h, "sha256") is False


def test_identify_hash_algorithm_md5():
    h = generate_hash("hello", "md5")
    assert identify_hash_algorithm(h) == ["md5"]


def test_identify_hash_algorithm_sha256():
    h = generate_hash("hello", "sha256")
    assert identify_hash_algorithm(h) == ["sha256"]


def test_identify_hash_algorithm_invalid_hex():
    assert identify_hash_algorithm("not-a-hex-hash!!") == []


def test_identify_hash_algorithm_unknown_length():
    assert identify_hash_algorithm("abcd") == []


def test_crack_hash_success():
    target = generate_hash("letmein", "sha256")
    candidates = ["admin", "password", "letmein", "qwerty"]
    result = crack_hash(target, candidates, algorithm="sha256")
    assert result["cracked"] is True
    assert result["plaintext"] == "letmein"
    assert result["algorithm"] == "sha256"


def test_crack_hash_failure():
    target = generate_hash("a-very-unique-string-92xQ", "sha256")
    candidates = ["admin", "password", "letmein", "qwerty"]
    result = crack_hash(target, candidates, algorithm="sha256")
    assert result["cracked"] is False
    assert result["plaintext"] is None
    assert result["attempts"] == len(candidates)


def test_crack_hash_auto_detects_algorithm():
    # md5 hash, no algorithm specified -- should auto-detect from length
    target = generate_hash("secret", "md5")
    candidates = ["wrong1", "wrong2", "secret"]
    result = crack_hash(target, candidates)
    assert result["cracked"] is True
    assert result["algorithm"] == "md5"