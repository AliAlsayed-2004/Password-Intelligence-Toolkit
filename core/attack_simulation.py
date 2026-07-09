import math
from core.entropy import detect_charset
from core.patterns import has_sequence, has_repetition, keyboard_weak, is_known_weak

GUESSES_PER_SECOND = {
    "offline_fast_gpu": 1e10,   # 10 مليار
    "offline_mid_gpu": 1e8,     # 100 مليون
    "online_attack": 5          # أقل واقعية (غالباً أقل من 10)
}

def estimate_base_entropy(password: str) -> float:
    if not password:
        return 0.0
    charset = detect_charset(password)
    if charset == 0:
        return 0.0
    
    base = len(password) * math.log2(charset)
    length = len(password)
    if length < 8:
        base *= 0.65
    elif length >= 14:
        base *= 1.25
    return base

def calculate_pattern_penalty(password: str) -> float:
    penalty = 1.0
    
    if is_known_weak(password):
        penalty *= 0.05          # جداً ضعيف
    elif has_sequence(password):
        penalty *= 0.15
    elif has_repetition(password):
        penalty *= 0.4
    elif keyboard_weak(password):
        penalty *= 0.25
    
    # مكافأة الطول
    if len(password) >= 16:
        penalty *= 2.0
    elif len(password) >= 12:
        penalty *= 1.5
    
    return max(0.01, min(penalty, 1.0))

def estimate_strength(password: str) -> float:
    base = estimate_base_entropy(password)
    penalty = calculate_pattern_penalty(password)
    return max(0.0, base * penalty)

def crack_time(strength_bits: float, speed: float) -> float:
    if strength_bits <= 0 or speed <= 0:
        return float("inf")
    return (2 ** strength_bits) / speed

def format_time(seconds: float) -> str:
    if seconds < 1:
        return "instantly"
    elif seconds < 60:
        return f"{round(seconds, 1)} seconds"
    elif seconds < 3600:
        return f"{round(seconds/60, 1)} minutes"
    elif seconds < 86400:
        return f"{round(seconds/3600, 1)} hours"
    elif seconds < 31536000:
        return f"{round(seconds/86400, 1)} days"
    else:
        years = seconds / 31536000
        return f"{round(years, 1)} years" if years < 500 else "centuries+"

def simulate_attack(password: str) -> dict:
    strength_bits = estimate_strength(password)
    
    return {
        "strength_bits": round(strength_bits, 2),
        "strength_rating": "Very Strong" if strength_bits > 80 else 
                          "Strong" if strength_bits > 65 else 
                          "Medium" if strength_bits > 50 else "Weak",
        "offline_mid_gpu": format_time(crack_time(strength_bits, GUESSES_PER_SECOND["offline_mid_gpu"])),
        "offline_fast_gpu": format_time(crack_time(strength_bits, GUESSES_PER_SECOND["offline_fast_gpu"])),
        "online_attack": format_time(crack_time(strength_bits, GUESSES_PER_SECOND["online_attack"])),
        "recommendations": ["Use at least 14+ characters with symbols" if strength_bits < 60 else "Good password!"]
    }