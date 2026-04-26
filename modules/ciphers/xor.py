import itertools


def decrypt_single(data, key):
    """XOR each byte with single byte key."""
    if isinstance(data, str):
        data = data.encode("latin-1")
    return bytes(b ^ key for b in data)


def decrypt_multibyte(data, key):
    """XOR with multi-byte key."""
    if isinstance(data, str):
        data = data.encode("latin-1")
    key_bytes = key if isinstance(key, bytes) else key.encode()
    return bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))


def crack_single(text, flag_format=None, scorer=None):
    """
    Brute force single-byte XOR (0x00 - 0xFF).
    Returns (decrypted, method) or (None, None)
    """
    if isinstance(text, str):
        # Try to interpret as hex first
        try:
            data = bytes.fromhex(text.strip().replace(" ", ""))
        except ValueError:
            data = text.encode("latin-1")
    else:
        data = text

    best_score = -99
    best_result = None
    best_key = None

    for key in range(256):
        decoded_bytes = decrypt_single(data, key)
        try:
            decoded = decoded_bytes.decode("utf-8", errors="ignore")
        except Exception:
            continue

        if flag_format and flag_format.lower() in decoded.lower():
            return decoded, f"XOR (key=0x{key:02x})"

        if scorer:
            score, _ = scorer(decoded)
            if score > best_score:
                best_score = score
                best_result = decoded
                best_key = key

    if best_result and best_score >= 3:
        return best_result, f"XOR (key=0x{best_key:02x})"

    return None, None


def crack_multibyte(text, key_str, flag_format=None):
    """Decrypt with a known/guessed multi-byte key string."""
    if isinstance(text, str):
        try:
            data = bytes.fromhex(text.strip().replace(" ", ""))
        except ValueError:
            data = text.encode("latin-1")
    else:
        data = text

    decoded_bytes = decrypt_multibyte(data, key_str)
    try:
        decoded = decoded_bytes.decode("utf-8", errors="ignore")
        if flag_format and flag_format.lower() in decoded.lower():
            return decoded, f"XOR (key={key_str})"
        return decoded, f"XOR (key={key_str})"
    except Exception:
        return None, None
