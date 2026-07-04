import math


def detect_charset(password: str) -> int:
    charset = 0

    if any(c.islower() for c in password):
        charset += 26
    if any(c.isupper() for c in password):
        charset += 26
    if any(c.isdigit() for c in password):
        charset += 10
    if any(c in "!@#$%^&*()-_=+[]{};:,.<>?/\\|" for c in password):
        charset += 32
    if any(ord(c) > 127 for c in password):
        charset += 100

    return charset


def calculate_entropy(password: str) -> float:
    charset = detect_charset(password)

    if charset == 0 or len(password) == 0:
        return 0

    entropy = len(password) * math.log2(charset)
    return round(entropy, 2)