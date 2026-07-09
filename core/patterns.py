import re
from typing import Dict, List

KEYBOARD_PATTERNS = ["qwerty", "asdf", "zxcv", "1234567890", "poiu", "lkjh", "mnbv"]
SEQUENCES = ["1234","2345","3456","4567","5678","6789","abcd","bcde","cdef","qwert"]

COMMON_PASSWORDS = {
    "password","123456","123456789","qwerty","abc123","letmein","welcome","admin",
    "monkey","football","superman","iloveyou","12345678","111111","123123","admin123",
    "password123","qwerty123","1234567","letmein123"
}

def has_repetition(password: str) -> bool:
    return bool(re.search(r'(.)\1{2,}', password))

def has_sequence(password: str) -> bool:
    p = password.lower()
    return any(seq in p for seq in SEQUENCES)

def keyboard_weak(password: str) -> bool:
    p = password.lower()
    return any(kb in p for kb in KEYBOARD_PATTERNS)

def is_known_weak(password: str) -> bool:
    lower = password.lower()
    return any(cp in lower for cp in COMMON_PASSWORDS)

def contains_dictionary_word(password: str) -> bool:
    return is_known_weak(password)

def has_common_pattern(password: str) -> bool:
    patterns = [r'(\d{4})', r'(.)\1{3,}', r'(123|234|345|456)']
    return any(re.search(p, password.lower()) for p in patterns)

def is_leet_speak(password: str) -> bool:
    if len(password) < 4:
        return False
    trans = password.lower().translate(str.maketrans("4310@$5!2", "aeioassiz"))
    return any(word in trans for word in COMMON_PASSWORDS)

def get_weak_patterns_list(password: str) -> List[str]:
    patterns = []
    if has_repetition(password): patterns.append("repetition")
    if has_sequence(password): patterns.append("sequence")
    if keyboard_weak(password): patterns.append("keyboard")
    if is_known_weak(password): patterns.append("known_weak")
    if has_common_pattern(password): patterns.append("common_pattern")
    if is_leet_speak(password): patterns.append("leet_speak")
    return patterns

def detect_all_patterns(password: str) -> Dict[str, bool]:
    return {
        "repetition": has_repetition(password),
        "sequence": has_sequence(password),
        "keyboard": keyboard_weak(password),
        "known_weak": is_known_weak(password),
        "dictionary": contains_dictionary_word(password),
        "common_pattern": has_common_pattern(password),
        "leet_speak": is_leet_speak(password)
    }