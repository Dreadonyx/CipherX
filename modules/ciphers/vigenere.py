import os

WORDLIST_PATH = os.path.join(os.path.dirname(__file__), "../../wordlists/vigenere_keys.txt")


def decrypt(text, key):
    """Decrypt Vigenere cipher with given key."""
    key = key.lower()
    result = []
    key_idx = 0
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            shift = ord(key[key_idx % len(key)]) - ord('a')
            result.append(chr((ord(c) - base - shift) % 26 + base))
            key_idx += 1
        else:
            result.append(c)
    return "".join(result)


def crack(text, flag_format=None, scorer=None):
    """
    Try all keys from wordlist.
    Returns (decrypted, method) or (None, None)
    """
    try:
        with open(WORDLIST_PATH, "r", errors="ignore") as f:
            keys = [line.strip() for line in f if line.strip().isalpha()]
    except FileNotFoundError:
        keys = ["key", "flag", "secret", "ctf", "password", "crypto", "cipher"]

    best_score = -99
    best_result = None
    best_key = None

    for key in keys:
        decoded = decrypt(text, key)

        if flag_format and flag_format.lower() in decoded.lower():
            return decoded, f"Vigenere (key={key})"

        if scorer:
            score, _ = scorer(decoded)
            if score > best_score:
                best_score = score
                best_result = decoded
                best_key = key

    if best_result and best_score >= 4:
        return best_result, f"Vigenere (key={best_key})"

    return None, None
