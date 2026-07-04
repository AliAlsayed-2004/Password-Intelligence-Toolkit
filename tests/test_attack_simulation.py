from core.attack_simulation import simulate_attack


def test_attack_simulation():
    result = simulate_attack("password123")

    assert "offline_gpu" in result
    assert "fast_gpu" in result
    assert "online_attack" in result