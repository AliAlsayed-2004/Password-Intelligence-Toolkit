KEYBOARD_PATTERNS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "qwerty",
]

SEQUENCES = [
    "1234", "2345", "3456", "abcd", "qwerty"
]

KNOWN_WEAK_PASSWORDS = [
    "password", "123456", "qwerty", "abc123", "letmein"
]


def has_repetition(password: str) -> bool:
    for i in range(len(password) - 2):
        if password[i] == password[i+1] == password[i+2]:
            return True
    return False


def has_sequence(password: str) -> bool:
    p = password.lower()
    return any(seq in p for seq in SEQUENCES)


def keyboard_weak(password: str) -> bool:
    p = password.lower()
    return any(pattern in p for pattern in KEYBOARD_PATTERNS)

def is_known_weak(password: str) -> bool:
    for weak in KNOWN_WEAK_PASSWORDS:
        if weak in password.lower():
            return True

def detect_all_patterns(password: str) -> dict:
    return {
        "repetition": has_repetition(password),
        "sequence": has_sequence(password),
        "keyboard": keyboard_weak(password),
        "known_weak": is_known_weak(password)
    }