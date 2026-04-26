import re
import string
import base64
import binascii


def detect(text):
    """
    Detect likely encoding/cipher type of input.
    Returns ordered list of (method_name, confidence) tuples.
    """
    text = text.strip()
    candidates = []

    # --- Binary ---
    if re.match(r'^[01\s]+$', text):
        clean = text.replace(" ", "")
        if len(clean) % 8 == 0 and len(clean) >= 8:
            candidates.append(("Binary", 90))

    # --- Morse ---
    if re.match(r'^[.\-/ ]+$', text):
        candidates.append(("Morse Code", 85))

    # --- Hex ---
    clean_hex = text.replace(" ", "").replace("0x", "").replace("\\x", "")
    if re.match(r'^[0-9a-fA-F]+$', clean_hex) and len(clean_hex) % 2 == 0 and len(clean_hex) >= 6:
        candidates.append(("Hex", 80))

    # --- Base64 ---
    b64_clean = text.replace("\n", "").replace(" ", "")
    if re.match(r'^[A-Za-z0-9+/]+=*$', b64_clean) and len(b64_clean) % 4 == 0:
        candidates.append(("Base64", 75))

    # --- Base64 URL-safe ---
    if re.match(r'^[A-Za-z0-9\-_]+=*$', b64_clean):
        candidates.append(("Base64 URL-safe", 70))

    # --- Base32 ---
    if re.match(r'^[A-Z2-7]+=*$', text.replace(" ", "")) and len(text.replace(" ", "")) % 8 == 0:
        candidates.append(("Base32", 75))

    # --- Base58 ---
    BASE58_ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    if all(c in BASE58_ALPHA for c in text) and len(text) > 6:
        candidates.append(("Base58", 65))

    # --- URL Encoding ---
    if "%" in text and re.search(r'%[0-9a-fA-F]{2}', text):
        candidates.append(("URL Encoding", 90))

    # --- HTML Entities ---
    if "&" in text and ";" in text and re.search(r'&[a-zA-Z]+;|&#\d+;|&#x[0-9a-fA-F]+;', text):
        candidates.append(("HTML Entities", 85))

    # --- Decimal ASCII ---
    parts = text.split()
    if all(p.isdigit() and 0 <= int(p) <= 127 for p in parts) and len(parts) > 2:
        candidates.append(("Decimal ASCII", 75))

    # --- Octal ---
    if all(re.match(r'^[0-7]+$', p) for p in text.split()) and len(text.split()) > 2:
        candidates.append(("Octal", 65))

    # --- ROT13 ---
    if re.match(r'^[A-Za-z\s\.,!?\'\-]+$', text) and len(text) > 5:
        candidates.append(("ROT13", 40))
        candidates.append(("ROT47", 35))

    # --- Caesar ---
    if re.match(r'^[A-Za-z\s]+$', text) and len(text) > 4:
        candidates.append(("Caesar", 45))

    # --- Vigenere (similar to Caesar but mixed case) ---
    if re.match(r'^[A-Za-z\s]+$', text) and len(text) > 8:
        candidates.append(("Vigenere", 40))

    # --- Hash detection ---
    if re.match(r'^[a-fA-F0-9]{32}$', text):
        candidates.append(("MD5 Hash", 95))
    if re.match(r'^[a-fA-F0-9]{40}$', text):
        candidates.append(("SHA1 Hash", 95))
    if re.match(r'^[a-fA-F0-9]{64}$', text):
        candidates.append(("SHA256 Hash", 95))
    if re.match(r'^[a-fA-F0-9]{128}$', text):
        candidates.append(("SHA512 Hash", 95))
    if re.match(r'^\$2[ayb]\$.{56}$', text):
        candidates.append(("bcrypt Hash", 99))

    # XOR hex
    if re.match(r'^[0-9a-fA-F\s]+$', text) and len(clean_hex) % 2 == 0:
        candidates.append(("XOR (hex)", 30))

    # Sort by confidence descending
    candidates.sort(key=lambda x: x[1], reverse=True)
    return candidates


def detect_with_flag_hint(text, flag_format=None):
    """
    Enhanced detect that adds cipher candidates when flag_format is given
    but current text has flag-like structure (braces present).
    """
    candidates = detect(text)
    names = [c[0] for c in candidates]

    # If text has {}, it might be a cipher-encoded flag — boost cipher candidates
    if "{" in text or "}" in text:
        if "ROT13" not in names:
            candidates.append(("ROT13", 60))
        if "ROT47" not in names:
            candidates.append(("ROT47", 55))
        if "Caesar" not in names:
            candidates.append(("Caesar", 50))

    # If mostly alpha + punctuation, try ciphers
    alpha_ratio = sum(1 for c in text if c.isalpha()) / max(len(text), 1)
    if alpha_ratio > 0.6:
        if "ROT13" not in names:
            candidates.append(("ROT13", 55))
        if "Atbash" not in names:
            candidates.append(("Atbash", 40))

    candidates.sort(key=lambda x: x[1], reverse=True)
    return candidates
