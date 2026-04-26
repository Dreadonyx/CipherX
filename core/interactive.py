from core.layered import crack_layers
from core.detector import detect
from core.reporter import Reporter
from modules.encoding.base import ENCODERS as BASE_ENCODERS
from modules.encoding.hex import ENCODERS as HEX_ENCODERS
from modules.encoding.misc import ENCODERS as MISC_ENCODERS
from modules.hashing.identifier import identify as identify_hash
from modules.hashing.cracker import crack as crack_hash
from modules.ciphers import caesar, vigenere, xor
from modules.ciphers.aes import decrypt as aes_decrypt, is_available as aes_available
from modules.steg.lsb import extract_lsb, is_available as pil_available
from modules.steg.strings import extract_from_file


ALL_ENCODERS = {}
ALL_ENCODERS.update(BASE_ENCODERS)
ALL_ENCODERS.update(HEX_ENCODERS)
ALL_ENCODERS.update(MISC_ENCODERS)

MENU = """
╔══════════════════════════════════════════╗
║           CipherX — Interactive          ║
╠══════════════════════════════════════════╣
║  [1]  Auto Crack (multi-layer)           ║
║  [2]  Encoding  (Base64/32/58/Hex etc)   ║
║  [3]  Ciphers   (Caesar/Vigenere/XOR)    ║
║  [4]  AES Decrypt                        ║
║  [5]  Hash Identify + Crack              ║
║  [6]  Steg — LSB Extract (image)         ║
║  [7]  Steg — Strings Extract (file)      ║
║  [8]  Detect Encoding Type               ║
║  [0]  Exit                               ║
╚══════════════════════════════════════════╝
"""

ENCODING_MENU = """
  Encoding options:
  [1]  Base64       [2]  Base32
  [3]  Base58       [4]  Base85
  [5]  Base16       [6]  Hex
  [7]  URL Decode   [8]  HTML Entities
  [9]  ROT13        [10] ROT47
  [11] Binary       [12] Octal
  [13] Morse        [14] Decimal ASCII
  [15] Atbash       [16] Reversed
  [0]  Back
"""

ENCODING_MAP = {
    "1": "Base64", "2": "Base32", "3": "Base58", "4": "Base85",
    "5": "Base16", "6": "Hex", "7": "URL Encoding", "8": "HTML Entities",
    "9": "ROT13", "10": "ROT47", "11": "Binary", "12": "Octal",
    "13": "Morse Code", "14": "Decimal ASCII", "15": "Atbash", "16": "Reversed"
}


def get_input(prompt):
    return input(f"\n  {prompt}: ").strip()


def run(logger):
    print(MENU)

    while True:
        choice = get_input("Select option")

        if choice == "0":
            print("\n  Bye! 👋")
            break

        elif choice == "1":
            text = get_input("Enter ciphertext (or 'file:<path>' to load)")
            if text.startswith("file:"):
                try:
                    text = open(text[5:]).read().strip()
                except Exception as e:
                    logger.error(f"Could not read file: {e}")
                    continue

            flag_fmt = get_input("Flag format (e.g. HTB{ or leave blank for auto)")
            layers = get_input("Max layers (default 3)")
            layers = int(layers) if layers.isdigit() else 3

            result, chain, found = crack_layers(
                text, flag_format=flag_fmt or None,
                max_layers=layers, logger=logger
            )

            logger.chain(chain if chain else ["No layers decoded"])
            reporter = Reporter(text, result, chain, found, flag_fmt or None)
            reporter.print_summary()

            save = get_input("Save report? (json/html/both/no)")
            if save in ("json", "both"):
                reporter.to_json()
            if save in ("html", "both"):
                reporter.to_html()

        elif choice == "2":
            print(ENCODING_MENU)
            enc_choice = get_input("Select encoding")
            method = ENCODING_MAP.get(enc_choice)
            if not method:
                logger.error("Invalid option")
                continue
            text = get_input("Enter encoded text")
            decoder = ALL_ENCODERS.get(method)
            if decoder:
                result = decoder(text)
                if result:
                    logger.success(f"{method} → {result}")
                else:
                    logger.error(f"Failed to decode as {method}")

        elif choice == "3":
            print("\n  Cipher options:")
            print("  [1] Caesar (brute force all shifts)")
            print("  [2] Vigenere (wordlist attack)")
            print("  [3] XOR single-byte brute force")
            print("  [4] XOR with known key")
            sub = get_input("Select")
            text = get_input("Enter ciphertext")
            flag_fmt = get_input("Flag format (or blank)")

            if sub == "1":
                results = caesar.brute_force(text)
                logger.section("Caesar — All 25 shifts")
                for shift, decoded in results:
                    print(f"  Shift {shift:2d}: {decoded}")
                best, method = caesar.crack(text, flag_format=flag_fmt or None)
                if best:
                    logger.success(f"Best guess: {method} → {best}")

            elif sub == "2":
                result, method = vigenere.crack(text, flag_format=flag_fmt or None)
                if result:
                    logger.success(f"{method} → {result}")
                else:
                    logger.warning("Could not crack Vigenere with wordlist")

            elif sub == "3":
                result, method = xor.crack_single(text, flag_format=flag_fmt or None)
                if result:
                    logger.success(f"{method} → {result}")
                else:
                    logger.warning("XOR brute force: no confident result")

            elif sub == "4":
                key = get_input("Enter XOR key (string)")
                result, method = xor.crack_multibyte(text, key, flag_format=flag_fmt or None)
                if result:
                    logger.success(f"{method} → {result}")

        elif choice == "4":
            if not aes_available():
                logger.error("pycryptodome not installed — run: pip install pycryptodome")
                continue
            ct = get_input("Ciphertext (hex or base64)")
            key = get_input("Key (string or hex)")
            iv = get_input("IV (hex, or blank for null IV / ECB)")
            mode = get_input("Mode (CBC/ECB, default CBC)")
            mode = mode.upper() if mode else "CBC"
            result, err = aes_decrypt(ct, key, iv or None, mode)
            if result:
                logger.success(f"AES {mode} → {result}")
            else:
                logger.error(f"AES failed: {err}")

        elif choice == "5":
            hash_str = get_input("Enter hash")
            types = identify_hash(hash_str)
            if types:
                logger.info(f"Possible hash types: {', '.join(types)}")
            else:
                logger.warning("Unknown hash type")

            crack_it = get_input("Try to crack? (y/n)")
            if crack_it.lower() == "y":
                online = get_input("Try online lookup too? (y/n)")
                word, algo, source = crack_hash(hash_str, try_online=online.lower() == "y")
                if word:
                    logger.success(f"Cracked! [{source}] {algo} → {word}")
                else:
                    logger.warning("Hash not cracked with current wordlist")

        elif choice == "6":
            if not pil_available():
                logger.error("Pillow not installed — run: pip install Pillow")
                continue
            path = get_input("Image file path")
            result, err = extract_lsb(path)
            if result:
                logger.success(f"LSB extracted: {result}")
            else:
                logger.error(f"LSB failed: {err}")

        elif choice == "7":
            path = get_input("File path")
            flag_fmt = get_input("Flag format (or blank)")
            strings, flags, err = extract_from_file(path, flag_format=flag_fmt or None)
            if err:
                logger.error(f"Error: {err}")
                continue
            logger.info(f"Extracted {len(strings)} strings")
            if flags:
                logger.section("Potential Flags Found")
                for f in flags:
                    logger.flag(f)
            else:
                show = get_input(f"Show all {len(strings)} strings? (y/n)")
                if show.lower() == "y":
                    for s in strings:
                        print(f"  {s}")

        elif choice == "8":
            text = get_input("Enter text to detect")
            candidates = detect(text)
            if candidates:
                logger.section("Detection Results")
                for method, confidence in candidates:
                    bar = "█" * (confidence // 10)
                    print(f"  {method:<25} {bar} {confidence}%")
            else:
                logger.warning("No encoding detected")

        else:
            logger.error("Invalid option")

        print(MENU)
