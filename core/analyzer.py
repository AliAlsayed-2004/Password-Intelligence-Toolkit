from core.entropy import calculate_entropy
from core.patterns import detect_all_patterns
from core.scoring import advanced_score, classify
from core.attack_simulation import simulate_attack

def analyze_password(password: str) -> dict:
    entropy = calculate_entropy(password)

    patterns = detect_all_patterns(password)

    score = advanced_score(password, entropy)

    level = classify(score)
    
    attack = simulate_attack(password)

    weak_patterns = [
        k for k, v in patterns.items() if v
    ]

    return {
        "password": password,
        "entropy": entropy,
        "score": score,
        "level": level,
        "weak_patterns": weak_patterns,
        "attack": attack
        
    }