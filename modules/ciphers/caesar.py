def decrypt(text, shift):
    """Decrypt Caesar cipher with given shift."""
    result = []
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base - shift) % 26 + base))
        else:
            result.append(c)
    return "".join(result)


def brute_force(text):
    """Return all 25 Caesar shifts as list of (shift, decrypted)."""
    results = []
    for shift in range(1, 26):
        results.append((shift, decrypt(text, shift)))
    return results


def crack(text, flag_format=None, scorer=None):
    """
    Crack Caesar — returns best result.
    If flag_format given, match against it.
    Otherwise use scorer to pick best.
    """
    candidates = brute_force(text)

    if flag_format:
        for shift, decoded in candidates:
            if flag_format.lower() in decoded.lower():
                return decoded, f"Caesar (shift {shift})"

    if scorer:
        best = max(candidates, key=lambda x: scorer(x[1])[0])
        shift, decoded = best
        score, _ = scorer(decoded)
        if score >= 3:
            return decoded, f"Caesar (shift {shift})"

    return None, None
