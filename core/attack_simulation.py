import math
from core.entropy import detect_charset
from core.patterns import has_sequence, has_repetition, keyboard_weak, is_known_weak

# سرعات الهجوم التقريبية
GUESSES_PER_SECOND = {
    "offline_fast_gpu": 1e10,   # أقوى جهاز
    "offline_mid_gpu": 1e8,     # جهاز متوسط
    "online_attack": 10         # هجوم أونلاين
}


def estimate_base_entropy(password: str) -> float:
    """حساب الإنتروبي الأساسي المحسن"""
    if not password:
        return 0.0
    
    charset = detect_charset(password)
    if charset == 0:
        return 0.0
    
    base = len(password) * math.log2(charset)
    
    # تعديلات حسب الطول
    length = len(password)
    if length < 6:
        base *= 0.6
    elif length < 8:
        base *= 0.85
    elif length >= 16:
        base *= 1.25  # مكافأة طول قوي
    
    return base


def calculate_pattern_penalty(password: str) -> float:
    """عقوبات تضاعفية (أكثر واقعية)"""
    penalty = 1.0
    
    if has_sequence(password):
        penalty *= 0.18      # تسلسلات خطيرة
    
    if has_repetition(password):
        penalty *= 0.45
    
    if keyboard_weak(password):
        penalty *= 0.28
    
    if is_known_weak(password):
        penalty *= 0.08      # كلمات معروفة ضعيفة جداً
    
    # مكافآت طول
    length = len(password)
    if length >= 16:
        penalty *= 1.9
    elif length >= 12:
        penalty *= 1.45
    elif length >= 8:
        penalty *= 1.1
    
    return max(0.01, min(penalty, 1.0))


def estimate_strength(password: str) -> float:
    """القوة النهائية بالـ bits"""
    base = estimate_base_entropy(password)
    penalty = calculate_pattern_penalty(password)
    return max(0.0, base * penalty)


def crack_time(strength_bits: float, speed: float) -> float:
    """حساب الزمن بالثواني"""
    if strength_bits <= 0 or speed <= 0:
        return float("inf")
    return (2 ** strength_bits) / speed


def format_time(seconds: float) -> str:
    """تنسيق زمن بشري محسن"""
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
        return f"{round(years, 1)} years" if years < 100 else "centuries+"


def get_strength_rating(strength_bits: float) -> str:
    if strength_bits < 25:
        return "Very Weak"
    elif strength_bits < 45:
        return "Weak"
    elif strength_bits < 65:
        return "Medium"
    elif strength_bits < 85:
        return "Strong"
    else:
        return "Very Strong"


def generate_recommendations(password: str, strength_bits: float) -> list:
    recs = []
    if len(password) < 12:
        recs.append("Increase length to 12+ characters")
    if has_sequence(password) or has_repetition(password):
        recs.append("Avoid sequences and repetitions")
    if keyboard_weak(password):
        recs.append("Avoid keyboard patterns")
    if strength_bits < 60:
        recs.append("Use a strong passphrase or password manager")
    return recs or ["Excellent password!"]


def simulate_attack(password: str) -> dict:
    """الدالة الرئيسية - تحليل هجوم"""
    if not password:
        return {"error": "Empty password"}
    
    strength_bits = estimate_strength(password)
    rating = get_strength_rating(strength_bits)
    
    return {
        "search_space_bits": round(strength_bits, 2),
        "strength_rating": rating,
        "offline_mid_gpu": format_time(
            crack_time(strength_bits, GUESSES_PER_SECOND["offline_mid_gpu"])
        ),
        "offline_fast_gpu": format_time(
            crack_time(strength_bits, GUESSES_PER_SECOND["offline_fast_gpu"])
        ),
        "online_attack": format_time(
            crack_time(strength_bits, GUESSES_PER_SECOND["online_attack"])
        ),
        "recommendations": generate_recommendations(password, strength_bits)
    }