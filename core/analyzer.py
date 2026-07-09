from core.entropy import calculate_entropy
from core.patterns import detect_all_patterns, get_weak_patterns_list
from core.scoring import advanced_score, classify, reconcile_score
from core.attack_simulation import simulate_attack
from core.zx_engine import analyze_zxcvbn

def analyze_password(password: str) -> dict:
    """تحليل كلمة المرور الشامل

    يدمج بين محركين:
    - المحرك المحلي (entropy/patterns/scoring): سريع وبسيط، بيعتمد على
      طول الباسورد وتنوع الأحرف.
    - zxcvbn: محرك واقعي بيعتمد على قواميس فعلية (كلمات شائعة، أسماء،
      leetspeak، أنماط لوحة مفاتيح) وبيمسك باسوردات زي "P@ssw0rd123"
      يلي بتبدو قوية نظرياً بس هي ضعيفة عملياً.

    النتيجة النهائية (final_score/final_level) بتاخد الحكم الأضعف بين
    المحركين، لأنه الباسورد قوته الحقيقية هي بقوة أضعف تقييم إلها.
    """
    if not password:
        return {"error": "Empty password"}

    entropy = calculate_entropy(password)
    patterns = detect_all_patterns(password)
    weak_patterns = get_weak_patterns_list(password)

    score = advanced_score(password, entropy)
    level = classify(score)
    attack = simulate_attack(password)

    zx = analyze_zxcvbn(password)
    reconciled = reconcile_score(score, zx["score"])

    return {
        "password": password,
        "entropy": entropy,
        "score": score,
        "level": level,
        "weak_patterns": weak_patterns,
        "attack": attack,
        "patterns": patterns,
        "zxcvbn": zx,
        "final_score": reconciled["final_score"],
        "final_level": reconciled["final_level"],
        "engines_agree": reconciled["engines_agree"],
    }