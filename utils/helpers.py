import math
import re
import string

def entropy(text):
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0
    entropy = 0
    for x in range(256):
        p_x = text.count(chr(x)) / len(text)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy

def contains_flag(text, flag_format):
    """Check if text contains the flag format (supports literal or regex)."""
    if not flag_format:
        # Auto-detect common patterns like CTF{...}
        return bool(re.search(r'[A-Za-z0-9_-]+\{[^}]+\}', text))
    
    try:
        if re.search(flag_format, text):
            return True
    except re.error:
        if flag_format in text:
            return True
    return False

def score_output(text, original_entropy=None):
    """
    Score how likely the text is to be plaintext.
    Returns (score, reasons)
    """
    score = 0
    reasons = []
    
    if not text:
        return 0, ["Empty input"]

    # 1. Fully printable ASCII (+3)
    printable_ratio = sum(1 for c in text if c in string.printable) / len(text)
    if printable_ratio == 1.0:
        score += 3
        reasons.append("Fully printable ASCII")
    elif printable_ratio > 0.9:
        score += 1
        reasons.append("Mostly printable ASCII")

    # 2. Common words (+2)
    common_words = ["the", "and", "flag", "this", "that", "with", "from", "have", "you", "for"]
    found_words = [w for w in common_words if w in text.lower()]
    if found_words:
        score += 2
        reasons.append(f"Contains common words: {', '.join(found_words[:3])}")

    # 3. Entropy drop (+2)
    current_entropy = entropy(text)
    if original_entropy is not None and current_entropy < original_entropy * 0.8:
        score += 2
        reasons.append(f"Entropy dropped (original: {original_entropy:.2f}, current: {current_entropy:.2f})")
    elif current_entropy < 4.5:
        score += 1
        reasons.append(f"Low entropy ({current_entropy:.2f})")

    # 4. Flag-like pattern detected (+5)
    if re.search(r'[A-Za-z0-9_-]+\{[^}]+\}', text):
        score += 5
        reasons.append("Flag-like pattern detected")

    # 5. Still looks encoded (-1 to -3)
    # High frequency of non-alphanumeric chars
    special_ratio = sum(1 for c in text if not c.isalnum() and not c.isspace()) / len(text)
    if special_ratio > 0.3:
        score -= 2
        reasons.append("High special character ratio")

    return score, reasons
