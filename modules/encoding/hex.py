import binascii
from urllib.parse import unquote, unquote_plus
import html


def decode_hex(text):
    """Decode hex string."""
    try:
        clean = text.strip().replace(" ", "").replace("0x", "").replace("\\x", "")
        result = binascii.unhexlify(clean)
        return result.decode("utf-8", errors="ignore")
    except Exception:
        return None


def decode_hex_spaced(text):
    """Decode space-separated hex bytes like 'DE AD BE EF'."""
    try:
        clean = "".join(text.strip().split())
        result = binascii.unhexlify(clean)
        return result.decode("utf-8", errors="ignore")
    except Exception:
        return None


def decode_url(text):
    """Decode URL encoding (%xx)."""
    try:
        return unquote(text.strip())
    except Exception:
        return None


def decode_url_plus(text):
    """Decode URL encoding with + as space."""
    try:
        return unquote_plus(text.strip())
    except Exception:
        return None


def decode_html_entities(text):
    """Decode HTML entities like &amp; &#x41; etc."""
    try:
        return html.unescape(text.strip())
    except Exception:
        return None


def decode_decimal(text):
    """Decode space-separated decimal ASCII values."""
    try:
        nums = text.strip().split()
        return "".join(chr(int(n)) for n in nums)
    except Exception:
        return None


ENCODERS = {
    "Hex": decode_hex,
    "Hex (spaced)": decode_hex_spaced,
    "URL Encoding": decode_url,
    "URL Encoding (plus)": decode_url_plus,
    "HTML Entities": decode_html_entities,
    "Decimal ASCII": decode_decimal,
}
