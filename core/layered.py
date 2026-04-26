from core.detector import detect, detect_with_flag_hint
from utils.helpers import score_output, contains_flag, entropy

from modules.encoding.base import ENCODERS as BASE_ENCODERS
from modules.encoding.hex import ENCODERS as HEX_ENCODERS
from modules.encoding.misc import ENCODERS as MISC_ENCODERS
from modules.ciphers import caesar, vigenere, xor
from modules.hashing.identifier import identify as identify_hash
from modules.hashing.cracker import crack as crack_hash


# Master decoder map: name → decode function
DECODER_MAP = {}
DECODER_MAP.update(BASE_ENCODERS)
DECODER_MAP.update(HEX_ENCODERS)
DECODER_MAP.update(MISC_ENCODERS)


def _try_decode(method_name, text, flag_format, scorer):
    """Try a single decoding method. Returns (decoded, method) or (None, None)."""

    # Standard encoders
    if method_name in DECODER_MAP:
        result = DECODER_MAP[method_name](text)
        if result and result != text:
            return result, method_name

    # Caesar brute force
    if method_name == "Caesar":
        decoded, method = caesar.crack(text, flag_format=flag_format, scorer=scorer)
        if decoded:
            return decoded, method

    # Vigenere wordlist
    if method_name == "Vigenere":
        decoded, method = vigenere.crack(text, flag_format=flag_format, scorer=scorer)
        if decoded:
            return decoded, method

    # ROT13
    if method_name == "ROT13":
        result = DECODER_MAP.get("ROT13", lambda x: None)(text)
        if result and result != text:
            return result, "ROT13"

    # ROT47
    if method_name == "ROT47":
        result = DECODER_MAP.get("ROT47", lambda x: None)(text)
        if result and result != text:
            return result, "ROT47"

    # XOR single byte
    if method_name == "XOR (hex)":
        decoded, method = xor.crack_single(text, flag_format=flag_format, scorer=scorer)
        if decoded:
            return decoded, method

    # Hash identification (not cracking, just flagging)
    if "Hash" in method_name:
        return None, None

    return None, None


def crack_layers(text, flag_format=None, max_layers=5, verbose=True, logger=None):
    """
    Recursively decode input up to max_layers deep.
    Returns (final_text, chain_list, found_flag)
    """
    current = text.strip()
    chain = []
    found_flag = False

    def scorer(t):
        return score_output(t, entropy(text))

    for layer_num in range(1, max_layers + 1):
        # Check if already a flag
        if flag_format and contains_flag(current, flag_format):
            if logger:
                logger.flag(current)
            found_flag = True
            break

        # Score current text
        # Only stop on high score if: no flag_format given, OR flag_format given but already found
        score, reasons = score_output(current)
        if layer_num > 1 and score >= 6:
            if flag_format and not contains_flag(current, flag_format):
                pass  # flag format set but not matched yet — keep going
            else:
                if logger:
                    logger.success(f"Looks like plaintext (score={score}): {', '.join(reasons)}")
                break

        # Detect likely encodings
        candidates = detect_with_flag_hint(current, flag_format)

        if not candidates:
            if logger:
                logger.warning("Could not detect encoding — stopping")
            break

        decoded_this_layer = False

        for method_name, confidence in candidates:
            decoded, method = _try_decode(method_name, current, flag_format, scorer)

            if decoded and decoded != current:
                if logger:
                    logger.layer(layer_num, method, decoded)
                chain.append(method)
                current = decoded
                decoded_this_layer = True

                # Check flag immediately after decode
                if flag_format and contains_flag(current, flag_format):
                    if logger:
                        logger.flag(current)
                    found_flag = True
                break

        if not decoded_this_layer:
            if logger:
                logger.warning(f"Layer {layer_num}: no successful decode found")
            break

        if found_flag:
            break

    return current, chain, found_flag
