from core.hashes import generate_hash, verify_hash


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