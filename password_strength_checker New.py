"""
Password Strength Checker
-------------------------
DecodeLabs Industrial Training Kit - Project 1
Track: Defensive Logic / Junior Analyst

Goal:
    Rate a password as Weak, Medium or Strong using its length,
    character variety, estimated entropy and a few common-attack checks
    (leaked passwords, keyboard/alphabet patterns, repeated characters).

Author: Arsalan (Ahmad Nawaz)
"""

import getpass
import math
import re
import string


# ---------------------------------------------------------------------------
# 1. Reference data
# ---------------------------------------------------------------------------

# Small sample of the most commonly leaked passwords. A real system would
# check a breach database instead (e.g. the Have I Been Pwned range API).
COMMON_LEAKED_PASSWORDS = {
    "123456", "123456789", "qwerty", "password", "111111",
    "12345678", "abc123", "1234567", "password1", "12345",
    "iloveyou", "admin", "welcome", "monkey", "login",
    "letmein", "dragon", "football", "starwars", "qwertyuiop",
}

# Runs of 4+ characters from these (forwards or backwards) count as a pattern.
PATTERN_SOURCES = (
    "0123456789",
    "abcdefghijklmnopqrstuvwxyz",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
)

MAX_SCORE = 9


# ---------------------------------------------------------------------------
# 2. Checks
# ---------------------------------------------------------------------------

def check_character_classes(password: str) -> dict:
    return {
        "has_lower": any(c.islower() for c in password),
        "has_upper": any(c.isupper() for c in password),
        "has_digit": any(c.isdigit() for c in password),
        "has_symbol": any(c in string.punctuation for c in password),
        "has_space": any(c.isspace() for c in password),
    }


def calculate_entropy(password: str) -> float:
    """
    Rough entropy estimate in bits: length * log2(pool size).
    The pool grows with each character class found in the password.
    This is only an estimate - it assumes every character is random.
    """
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if any(c in string.punctuation for c in password):
        pool += len(string.punctuation)
    if " " in password:
        pool += 1

    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)


def is_leaked_password(password: str) -> bool:
    return password.lower() in COMMON_LEAKED_PASSWORDS


def contains_common_password(password: str) -> bool:
    """True if a known leaked password is hidden inside, e.g. 'Password123!'."""
    lowered = password.lower()
    return any(len(bad) >= 5 and bad in lowered for bad in COMMON_LEAKED_PASSWORDS)


def has_sequential_or_repeated_chars(password: str) -> bool:
    """Catches 'aaa', '1111', '1234', 'abcd', 'dcba', 'qwer' and similar."""
    lowered = password.lower()
    if re.search(r"(.)\1{2,}", lowered):
        return True
    for source in PATTERN_SOURCES:
        for seq in (source, source[::-1]):
            for i in range(len(seq) - 3):
                if seq[i:i + 4] in lowered:
                    return True
    return False


# ---------------------------------------------------------------------------
# 3. Scoring
# ---------------------------------------------------------------------------

def score_password(password: str) -> dict:
    length = len(password)
    classes = check_character_classes(password)
    entropy = calculate_entropy(password)
    leaked = is_leaked_password(password)
    common_inside = contains_common_password(password)
    weak_pattern = has_sequential_or_repeated_chars(password)

    score = 0
    tips = []

    # length (0-3)
    if length < 8:
        tips.append("Too short - use at least 8 characters.")
    elif length < 12:
        score += 1
        tips.append("Length is acceptable, but 12 or more is better.")
    elif length < 16:
        score += 2
    else:
        score += 3

    # character variety (0-4)
    variety = sum([classes["has_lower"], classes["has_upper"],
                   classes["has_digit"], classes["has_symbol"]])
    score += variety

    # a long passphrase is fine without every character class
    if length < 16:
        if not classes["has_lower"]:
            tips.append("Add a lowercase letter (a-z).")
        if not classes["has_upper"]:
            tips.append("Add an uppercase letter (A-Z).")
        if not classes["has_digit"]:
            tips.append("Add a number (0-9).")
        if not classes["has_symbol"]:
            tips.append("Add a symbol (e.g. ! @ # $ %).")

    # entropy bonus (0-2)
    if entropy >= 60:
        score += 2
    elif entropy >= 40:
        score += 1

    # penalties
    if weak_pattern:
        score -= 4
        tips.append("Avoid repeated or predictable patterns (aaaa, 1234, qwer).")
    if common_inside:
        score = min(score, 2)
        tips.append("Built on a very common password - adding digits or symbols does not fix that.")
    if leaked:
        score = 0
        tips.append("This password appears in known data breaches. Do not use it.")

    score = max(0, score)

    if length < 8 or leaked or score <= 2:
        strength = "Weak"
    elif score <= 5:
        strength = "Medium"
    else:
        strength = "Strong"

    return {
        "password_length": length,
        "entropy_bits": round(entropy, 2),
        "character_classes": classes,
        "is_leaked": leaked,
        "has_weak_pattern": weak_pattern,
        "score": score,
        "strength": strength,
        "recommendations": tips,
    }


# ---------------------------------------------------------------------------
# 4. Output
# ---------------------------------------------------------------------------

def print_report(password: str) -> None:
    r = score_password(password)
    c = r["character_classes"]
    yes_no = lambda value: "Yes" if value else "No"

    print("\n" + "=" * 50)
    print(" PASSWORD STRENGTH REPORT - DecodeLabs Project 1")
    print("=" * 50)
    print(f" Length            : {r['password_length']} characters")
    print(f" Estimated entropy : {r['entropy_bits']} bits")
    print(f" Lowercase         : {yes_no(c['has_lower'])}")
    print(f" Uppercase         : {yes_no(c['has_upper'])}")
    print(f" Digit             : {yes_no(c['has_digit'])}")
    print(f" Symbol            : {yes_no(c['has_symbol'])}")
    print(f" Found in leaks    : {yes_no(r['is_leaked'])}")
    print(f" Weak pattern      : {yes_no(r['has_weak_pattern'])}")
    print("-" * 50)
    print(f" VERDICT: {r['strength'].upper()}   (score: {r['score']}/{MAX_SCORE})")
    if r["recommendations"]:
        print(" Suggestions:")
        for tip in r["recommendations"]:
            print(f"   - {tip}")
    print("=" * 50 + "\n")


def main():
    print("DecodeLabs Password Strength Checker")
    print("(your typing is hidden and the password is never stored)\n")
    try:
        password = getpass.getpass("Enter a password to evaluate: ")
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        return
    print_report(password)


if __name__ == "__main__":
    main()
