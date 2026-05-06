#  CipherX

A multi-layer CTF cipher/encoding auto-cracker for your terminal. Give it a ciphertext — it figures out the encoding stack and peels it layer by layer until it finds your flag.

```
Input: 565564506533706f6557643258336c7562484a6c583264795a6d6439
  Layer 1: Hex     → VUdPe3poeWd2X3lubHJlX2dyZmd9
  Layer 2: Base64  → UGO{zhygv_ynlre_grfg}
  Layer 3: ROT13   → HTB{multi_layer_test}

FLAG FOUND: HTB{multi_layer_test}
[Chain] Hex → Base64 → ROT13
```

---

##  Installation

```bash
git clone https://github.com/Dreadonyx/CipherX.git
cd CipherX
pip install -r requirements.txt
```

---

##  Usage

### Auto-crack mode
```bash
# Auto-detect and crack up to 3 layers
python main.py -a "SGVsbG8gV29ybGQ="

# With flag format (stops as soon as flag is found)
python main.py -a "565564506533..." --flag-format "HTB{" --layers 5

# From a file
python main.py -f cipher.txt --flag-format "CTF{"

# Save report
python main.py -a "..." --flag-format "HTB{" --report html
```

### Interactive menu
```bash
python main.py -i
```

### Just detect encoding type
```bash
python main.py -d "SGVsbG8="
```

---

##  Supported Techniques

### Encodings (auto-detected + manual)
| Encoding | Notes |
|----------|-------|
| Base64 / Base64 URL-safe | With auto padding fix |
| Base32 / Base58 / Base85 / Base16 | All variants |
| Hex | With/without spaces, 0x prefix |
| URL Encoding | %xx and + variants |
| HTML Entities | `&amp;` `&#x41;` etc |
| Binary | Space or 8-char grouped |
| Octal | Space-separated |
| Decimal ASCII | Space-separated decimal values |
| ROT13 / ROT47 | Classic rotations |
| Atbash | A↔Z mirror cipher |
| Morse Code | Dot-dash with spaces |
| Reversed | String reversal |

### Ciphers
| Cipher | Method |
|--------|--------|
| Caesar | Brute forces all 25 shifts |
| Vigenere | Wordlist-based key attack |
| XOR (single-byte) | Brute forces 0x00–0xFF |
| XOR (multi-byte) | Known key decryption |
| AES CBC/ECB | Known key + IV decryption |

### Hashing
| Feature | Detail |
|---------|--------|
| Hash identification | MD5, SHA1, SHA256, SHA512, bcrypt, NTLM... |
| Wordlist crack | Against included wordlist |
| Online lookup | md5decrypt.net (optional) |

### Steganography
| Feature | Detail |
|---------|--------|
| LSB extraction | From PNG/JPG images |
| Strings extraction | Like `strings` binary — extracts printable content + flags |

---

##  How Auto-Detection Works

CipherX uses two layers to decide when it's done:

**1. Flag Format Match** — if you provide `--flag-format "HTB{"`, it stops the moment the decoded output contains it.

**2. Entropy + Printability Scoring** — when no flag format is given, each decoded layer is scored:
- Fully printable ASCII → +3
- Contains common words → +2
- Entropy dropped significantly → +2
- Flag-like pattern `XX{...}` detected → +5
- Still looks encoded → -1 to -3

Score ≥ 6 = plaintext found. Score < threshold = keep decoding.

---

##  Project Structure

```
CipherX/
├── main.py                    # Entry point
├── core/
│   ├── detector.py            # Auto-detect encoding type
│   ├── layered.py             # Multi-layer recursive cracker
│   ├── interactive.py         # Interactive menu
│   └── reporter.py            # JSON + HTML reports
├── modules/
│   ├── encoding/
│   │   ├── base.py            # Base64/32/58/85/16
│   │   ├── hex.py             # Hex, URL, HTML, Decimal
│   │   └── misc.py            # ROT13/47, Binary, Morse, Octal
│   ├── hashing/
│   │   ├── identifier.py      # Hash type detection
│   │   └── cracker.py         # Wordlist + online crack
│   ├── ciphers/
│   │   ├── caesar.py          # Brute force all shifts
│   │   ├── vigenere.py        # Wordlist key attack
│   │   ├── xor.py             # Single + multi-byte XOR
│   │   └── aes.py             # AES CBC/ECB decrypt
│   └── steg/
│       ├── lsb.py             # LSB image extraction
│       └── strings.py         # Strings + flag finder
├── wordlists/
│   ├── rockyou_mini.txt       # Common passwords for hash cracking
│   └── vigenere_keys.txt      # Vigenere key wordlist
├── utils/
│   ├── logger.py              # Colored terminal output
│   └── helpers.py             # Entropy, scoring, flag detection
└── reports/                   # Generated scan reports
```

---

##  Test It

```bash
# Single layer Base64
python main.py -a "SGVsbG8gV29ybGQ=" --flag-format "Hello"

# 3-layer: Hex → Base64 → ROT13
python main.py -a "565564506533706f6557643258336c7562484a6c583264795a6d6439" --flag-format "HTB{" --layers 5

# Hash crack
# interactive: option 5 → 5f4dcc3b5aa765d61d8327deb882cf99 → "password"
```

---

##  Dependencies

```
requests        — online hash lookup
colorama        — colored terminal output
pycryptodome    — AES decryption
Pillow          — LSB steganography
```

---

##  Author

**Dreadonyx** — [github.com/Dreadonyx](https://github.com/Dreadonyx)

>  For CTF and educational use only.
