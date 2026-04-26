import base64
import binascii


def decode_base64(text):
    """Decode Base64, handles standard and URL-safe variants."""
    try:
        # Fix padding
        padded = text.strip() + "=" * (4 - len(text.strip()) % 4)
        result = base64.b64decode(padded)
        return result.decode("utf-8", errors="ignore")
    except Exception:
        return None


def decode_base64_urlsafe(text):
    """Decode URL-safe Base64."""
    try:
        padded = text.strip() + "=" * (4 - len(text.strip()) % 4)
        result = base64.urlsafe_b64decode(padded)
        return result.decode("utf-8", errors="ignore")
    except Exception:
        return None


def decode_base32(text):
    """Decode Base32."""
    try:
        padded = text.strip().upper() + "=" * (8 - len(text.strip()) % 8)
        result = base64.b32decode(padded)
        return result.decode("utf-8", errors="ignore")
    except Exception:
        return None


def decode_base58(text):
    """Decode Base58 (Bitcoin alphabet)."""
    ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    try:
        num = 0
        for char in text.strip():
            if char not in ALPHABET:
                return None
            num = num * 58 + ALPHABET.index(char)
        result = []
        while num > 0:
            result.append(num % 256)
            num //= 256
        for char in text.strip():
            if char == ALPHABET[0]:
                result.append(0)
            else:
                break
        return bytes(reversed(result)).decode("utf-8", errors="ignore")
    except Exception:
        return None


def decode_base85(text):
    """Decode Base85."""
    try:
        result = base64.b85decode(text.strip())
        return result.decode("utf-8", errors="ignore")
    except Exception:
        return None


def decode_base16(text):
    """Decode Base16 (hex via base64 module)."""
    try:
        result = base64.b16decode(text.strip().upper())
        return result.decode("utf-8", errors="ignore")
    except Exception:
        return None


# Encoder registry for auto-detection
ENCODERS = {
    "Base64": decode_base64,
    "Base64 URL-safe": decode_base64_urlsafe,
    "Base32": decode_base32,
    "Base58": decode_base58,
    "Base85": decode_base85,
    "Base16": decode_base16,
}
