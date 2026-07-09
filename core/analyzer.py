from core.entropy import calculate_entropy
from core.patterns import detect_all_patterns, get_weak_patterns_list
from core.scoring import advanced_score, classify
from core.attack_simulation import simulate_attack

def analyze_password(password: str) -> dict:
    """تحليل كلمة المرور الشامل"""
    if not password:
        return {"error": "Empty password"}

    entropy = calculate_entropy(password)
    patterns = detect_all_patterns(password)
    weak_patterns = get_weak_patterns_list(password)
    
    score = advanced_score(password, entropy)
    level = classify(score)
    attack = simulate_attack(password)

    return {
        "password": password,
        "entropy": entropy,
        "score": score,
        "level": level,
        "weak_patterns": weak_patterns,
        "attack": attack,
        "patterns": patterns
    }