from core.attack_simulation import simulate_attack


def test_attack_simulation():
    result = simulate_attack("password123")

    assert "search_space_bits" in result
    assert "strength_rating" in result
    assert "offline_mid_gpu" in result
    assert "offline_fast_gpu" in result
    assert "online_attack" in result
    assert "recommendations" in result