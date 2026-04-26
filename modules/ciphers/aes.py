try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    AES_AVAILABLE = True
except ImportError:
    AES_AVAILABLE = False

import base64


def decrypt(ciphertext, key, iv=None, mode="CBC"):
    """
    Decrypt AES with given key and optional IV.
    ciphertext: hex string or base64 string or bytes
    key: string or bytes (must be 16/24/32 bytes)
    iv: string or bytes (16 bytes for CBC), None for ECB
    """
    if not AES_AVAILABLE:
        return None, "pycryptodome not installed — pip install pycryptodome"

    # Decode ciphertext
    if isinstance(ciphertext, str):
        try:
            ct_bytes = bytes.fromhex(ciphertext.replace(" ", ""))
        except ValueError:
            try:
                ct_bytes = base64.b64decode(ciphertext + "==")
            except Exception:
                ct_bytes = ciphertext.encode("latin-1")
    else:
        ct_bytes = ciphertext

    # Prepare key
    if isinstance(key, str):
        key_bytes = key.encode("utf-8")
    else:
        key_bytes = key

    if len(key_bytes) not in (16, 24, 32):
        return None, f"Invalid key length: {len(key_bytes)} (must be 16, 24, or 32)"

    try:
        if mode.upper() == "ECB":
            cipher = AES.new(key_bytes, AES.MODE_ECB)
            decrypted = unpad(cipher.decrypt(ct_bytes), AES.block_size)
        else:
            if iv is None:
                iv_bytes = b'\x00' * 16
            elif isinstance(iv, str):
                try:
                    iv_bytes = bytes.fromhex(iv)
                except ValueError:
                    iv_bytes = iv.encode("utf-8")[:16].ljust(16, b'\x00')
            else:
                iv_bytes = iv

            cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
            decrypted = unpad(cipher.decrypt(ct_bytes), AES.block_size)

        return decrypted.decode("utf-8", errors="ignore"), None

    except Exception as e:
        return None, str(e)


def is_available():
    return AES_AVAILABLE
