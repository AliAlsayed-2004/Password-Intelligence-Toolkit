from core.entropy import calculate_entropy


def test_entropy_basic():
    result = calculate_entropy("abc")
    assert result > 0


def test_entropy_empty():
    result = calculate_entropy("")
    assert result == 0


def test_entropy_numbers():
    result = calculate_entropy("123456")
    assert result > 0


def test_entropy_complex():
    result = calculate_entropy("Aa1!")
    assert result > 10