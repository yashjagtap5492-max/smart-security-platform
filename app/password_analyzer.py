import math
import re
import string
from collections import Counter


COMMON_PASSWORDS = {
    "password",
    "password123",
    "123456",
    "12345678",
    "123456789",
    "qwerty",
    "qwerty123",
    "admin",
    "admin123",
    "welcome",
    "welcome123",
    "letmein",
    "iloveyou",
    "passw0rd",
    "changeme",
    "secret",
    "user",
    "root"
}

COMMON_PATTERNS = [
    r"123456",
    r"12345",
    r"abcdef",
    r"qwerty",
    r"asdfgh",
    r"password",
    r"admin",
    r"welcome",
    r"letmein",
    r"iloveyou"
]

SEQUENTIAL_PATTERNS = [
    "0123456789",
    "9876543210",
    "abcdefghijklmnopqrstuvwxyz",
    "zyxwvutsrqponmlkjihgfedcba"
]


def calculate_character_space(password):
    charset = 0

    if re.search(r"[a-z]", password):
        charset += 26

    if re.search(r"[A-Z]", password):
        charset += 26

    if re.search(r"[0-9]", password):
        charset += 10

    if re.search(r"[^A-Za-z0-9]", password):
        charset += len(string.punctuation)

    return charset


def calculate_entropy(password):
    if not password:
        return 0.0

    charset = calculate_character_space(password)

    if charset == 0:
        return 0.0

    return round(
        len(password) * math.log2(charset),
        2
    )


def calculate_unique_ratio(password):
    if not password:
        return 0.0

    return round(
        len(set(password)) / len(password),
        2
    )


def detect_repeated_characters(password):
    return bool(
        re.search(r"(.)\1{2,}", password)
    )


def detect_sequential_characters(password):
    password_lower = password.lower()

    for sequence in SEQUENTIAL_PATTERNS:
        for size in range(3, min(6, len(sequence) + 1)):
            for index in range(
                len(sequence) - size + 1
            ):
                pattern = sequence[index:index + size]

                if pattern in password_lower:
                    return True

    return False


def detect_keyboard_pattern(password):
    patterns = [
        "qwerty",
        "asdf",
        "zxcv",
        "qaz",
        "wsx",
        "edc"
    ]

    password_lower = password.lower()

    return any(
        pattern in password_lower
        for pattern in patterns
    )


def detect_common_password(password):
    return password.lower() in COMMON_PASSWORDS


def detect_common_pattern(password):
    password_lower = password.lower()

    return any(
        re.search(pattern, password_lower)
        for pattern in COMMON_PATTERNS
    )


def calculate_dictionary_risk(password):
    if detect_common_password(password):
        return 100

    if detect_common_pattern(password):
        return 80

    return 0


def calculate_pattern_penalty(password):
    penalty = 0

    if detect_repeated_characters(password):
        penalty += 10

    if detect_sequential_characters(password):
        penalty += 15

    if detect_keyboard_pattern(password):
        penalty += 15

    if detect_common_pattern(password):
        penalty += 25

    return penalty


def calculate_strength_score(password):
    if not password:
        return 0

    score = 0
    length = len(password)

    if length >= 8:
        score += 15

    if length >= 10:
        score += 10

    if length >= 12:
        score += 15

    if length >= 16:
        score += 10

    if re.search(r"[a-z]", password):
        score += 10

    if re.search(r"[A-Z]", password):
        score += 10

    if re.search(r"[0-9]", password):
        score += 10

    if re.search(r"[^A-Za-z0-9]", password):
        score += 15

    unique_ratio = calculate_unique_ratio(password)

    if unique_ratio >= 0.70:
        score += 5

    if unique_ratio >= 0.85:
        score += 5

    score -= calculate_pattern_penalty(password)

    dictionary_risk = calculate_dictionary_risk(password)

    if dictionary_risk >= 80:
        score -= 30

    return max(
        0,
        min(score, 100)
    )


def get_risk_level(score):
    if score >= 85:
        return "LOW"

    if score >= 65:
        return "MEDIUM"

    if score >= 40:
        return "HIGH"

    return "CRITICAL"


def get_strength_label(score):
    if score >= 85:
        return "VERY_STRONG"

    if score >= 70:
        return "STRONG"

    if score >= 50:
        return "MODERATE"

    if score >= 30:
        return "WEAK"

    return "VERY_WEAK"


def generate_warnings(password, checks, entropy):
    warnings = []

    if len(password) < 8:
        warnings.append(
            "Password is shorter than the recommended minimum length"
        )

    if len(password) < 12:
        warnings.append(
            "Use at least 12 characters for stronger protection"
        )

    if not checks["lowercase"]:
        warnings.append(
            "Missing lowercase characters"
        )

    if not checks["uppercase"]:
        warnings.append(
            "Missing uppercase characters"
        )

    if not checks["numbers"]:
        warnings.append(
            "Missing numeric characters"
        )

    if not checks["special"]:
        warnings.append(
            "Missing special characters"
        )

    if checks["repeated"]:
        warnings.append(
            "Repeated character pattern detected"
        )

    if checks["sequential"]:
        warnings.append(
            "Sequential character pattern detected"
        )

    if checks["keyboard"]:
        warnings.append(
            "Keyboard pattern detected"
        )

    if checks["common"]:
        warnings.append(
            "Password matches a commonly used password"
        )

    if entropy < 40:
        warnings.append(
            "Low estimated password entropy"
        )

    return list(dict.fromkeys(warnings))


def analyze_password(password):
    if password is None:
        password = ""

    password = str(password)

    if not password:
        return {
            "score": 0,
            "risk_level": "CRITICAL",
            "strength": "VERY_WEAK",
            "entropy": 0.0,
            "length": 0,
            "character_space": 0,
            "unique_ratio": 0.0,
            "dictionary_risk": 100,
            "checks": {},
            "warnings": [
                "Password cannot be empty"
            ]
        }

    checks = {
        "minimum_length": len(password) >= 8,
        "strong_length": len(password) >= 12,
        "lowercase": bool(
            re.search(r"[a-z]", password)
        ),
        "uppercase": bool(
            re.search(r"[A-Z]", password)
        ),
        "numbers": bool(
            re.search(r"[0-9]", password)
        ),
        "special": bool(
            re.search(r"[^A-Za-z0-9]", password)
        ),
        "repeated": detect_repeated_characters(
            password
        ),
        "sequential": detect_sequential_characters(
            password
        ),
        "keyboard": detect_keyboard_pattern(
            password
        ),
        "common": detect_common_password(
            password
        ),
        "common_pattern": detect_common_pattern(
            password
        )
    }

    entropy = calculate_entropy(password)

    score = calculate_strength_score(
        password
    )

    risk_level = get_risk_level(score)

    strength = get_strength_label(score)

    warnings = generate_warnings(
        password,
        checks,
        entropy
    )

    return {
        "score": score,
        "risk_level": risk_level,
        "strength": strength,
        "entropy": entropy,
        "length": len(password),
        "character_space": calculate_character_space(
            password
        ),
        "unique_ratio": calculate_unique_ratio(
            password
        ),
        "dictionary_risk": calculate_dictionary_risk(
            password
        ),
        "checks": checks,
        "warnings": warnings
    }