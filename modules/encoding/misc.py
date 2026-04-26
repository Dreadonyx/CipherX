import codecs
import re


def decode_rot13(text):
    """Decode ROT13."""
    try:
        return codecs.decode(text.strip(), "rot_13")
    except Exception:
        return None


def decode_rot47(text):
    """Decode ROT47 — rotates ASCII 33-126."""
    try:
        result = []
        for c in text:
            code = ord(c)
            if 33 <= code <= 126:
                result.append(chr(33 + (code - 33 + 47) % 94))
            else:
                result.append(c)
        return "".join(result)
    except Exception:
        return None


def decode_binary(text):
    """Decode binary string (space or 8-char grouped)."""
    try:
        clean = text.strip().replace(" ", "")
        if not all(c in "01" for c in clean):
            return None
        if len(clean) % 8 != 0:
            return None
        chars = [chr(int(clean[i:i+8], 2)) for i in range(0, len(clean), 8)]
        return "".join(chars)
    except Exception:
        return None


def decode_octal(text):
    """Decode space-separated octal values."""
    try:
        nums = text.strip().split()
        return "".join(chr(int(n, 8)) for n in nums)
    except Exception:
        return None


def decode_morse(text):
    """Decode Morse code."""
    MORSE = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
        '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
        '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
        '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
        '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
        '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
        '...--': '3', '....-': '4', '.....': '5', '-....': '6',
        '--...': '7', '---..': '8', '----.': '9', '/': ' ',
    }
    try:
        words = text.strip().split("   ")
        decoded = []
        for word in words:
            letters = word.strip().split(" ")
            decoded.append("".join(MORSE.get(l, "?") for l in letters if l))
        return " ".join(decoded)
    except Exception:
        return None


def decode_atbash(text):
    """Decode Atbash cipher (A↔Z, B↔Y...)."""
    try:
        result = []
        for c in text:
            if c.isalpha():
                if c.isupper():
                    result.append(chr(ord('Z') - (ord(c) - ord('A'))))
                else:
                    result.append(chr(ord('z') - (ord(c) - ord('a'))))
            else:
                result.append(c)
        return "".join(result)
    except Exception:
        return None


def decode_reversed(text):
    """Reverse the string."""
    try:
        return text.strip()[::-1]
    except Exception:
        return None


ENCODERS = {
    "ROT13": decode_rot13,
    "ROT47": decode_rot47,
    "Binary": decode_binary,
    "Octal": decode_octal,
    "Morse Code": decode_morse,
    "Atbash": decode_atbash,
    "Reversed": decode_reversed,
}
