import hashlib
import os
import gzip
import requests as req

WORDLIST_PATH = os.path.join(os.path.dirname(__file__), "../../wordlists/rockyou_mini.txt.gz")


def _hash_word(word, algo):
    """Hash a word with given algorithm."""
    try:
        h = hashlib.new(algo)
        h.update(word.encode("utf-8", errors="ignore"))
        return h.hexdigest()
    except Exception:
        return None


def crack_with_wordlist(hash_str, algos=None):
    """
    Try to crack hash using wordlist.
    algos: list of hashlib algo names to try e.g. ['md5', 'sha1']
    """
    if algos is None:
        algos = ["md5", "sha1", "sha256", "sha224", "sha384", "sha512"]

    hash_str = hash_str.strip().lower()

    try:
        # Open gzip file in text mode
        with gzip.open(WORDLIST_PATH, "rt", encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.strip()
                for algo in algos:
                    if _hash_word(word, algo) == hash_str:
                        return word, algo
    except FileNotFoundError:
        return None, None

    return None, None


def crack_online(hash_str):
    """
    Try online hash lookup via md5decrypt.net (free, no key needed).
    Falls back gracefully if offline.
    """
    hash_str = hash_str.strip()
    try:
        url = f"https://md5decrypt.net/Api/api.php?hash={hash_str}&hash_type=md5&email=test@test.com&code=code1"
        response = req.get(url, timeout=5)
        result = response.text.strip()
        if result and result != "NOTFOUND" and result != "ERROR":
            return result
    except Exception:
        pass
    return None


def crack(hash_str, algos=None, try_online=False):
    """Main crack function — wordlist first, then online."""
    word, algo = crack_with_wordlist(hash_str, algos)
    if word:
        return word, algo, "wordlist"

    if try_online:
        result = crack_online(hash_str)
        if result:
            return result, "unknown", "online lookup"

    return None, None, None
