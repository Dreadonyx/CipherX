import re

HASH_PATTERNS = [
    {"name": "MD5",         "regex": r"^[a-fA-F0-9]{32}$"},
    {"name": "SHA1",        "regex": r"^[a-fA-F0-9]{40}$"},
    {"name": "SHA224",      "regex": r"^[a-fA-F0-9]{56}$"},
    {"name": "SHA256",      "regex": r"^[a-fA-F0-9]{64}$"},
    {"name": "SHA384",      "regex": r"^[a-fA-F0-9]{96}$"},
    {"name": "SHA512",      "regex": r"^[a-fA-F0-9]{128}$"},
    {"name": "NTLM",        "regex": r"^[a-fA-F0-9]{32}$"},
    {"name": "bcrypt",      "regex": r"^\$2[ayb]\$.{56}$"},
    {"name": "MD5 (Unix)",  "regex": r"^\$1\$.{8}\$.{22}$"},
    {"name": "SHA512crypt", "regex": r"^\$6\$.{8}\$.+$"},
    {"name": "CRC32",       "regex": r"^[a-fA-F0-9]{8}$"},
    {"name": "MySQL323",    "regex": r"^[a-fA-F0-9]{16}$"},
    {"name": "RIPEMD160",   "regex": r"^[a-fA-F0-9]{40}$"},
]


def identify(hash_str):
    """Return list of possible hash types for a given string."""
    hash_str = hash_str.strip()
    matches = []
    for pattern in HASH_PATTERNS:
        if re.match(pattern["regex"], hash_str):
            matches.append(pattern["name"])
    return matches
