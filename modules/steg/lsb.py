try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


def extract_lsb(image_path, channels="RGB"):
    """
    Extract LSB steganography from image.
    Reads least significant bit of each channel byte.
    Returns extracted string or None.
    """
    if not PIL_AVAILABLE:
        return None, "Pillow not installed — pip install Pillow"

    try:
        img = Image.open(image_path)
        img = img.convert("RGB")
        pixels = list(img.getdata())

        bits = []
        for pixel in pixels:
            for i, channel in enumerate(["R", "G", "B"]):
                if channel in channels.upper():
                    bits.append(pixel[i] & 1)

        # Convert bits to bytes
        chars = []
        for i in range(0, len(bits) - 7, 8):
            byte = bits[i:i+8]
            char = chr(int("".join(str(b) for b in byte), 2))
            if char == '\x00':
                break
            chars.append(char)

        result = "".join(chars)
        if result and all(32 <= ord(c) <= 126 for c in result[:20]):
            return result, None
        return None, "No readable LSB data found"

    except Exception as e:
        return None, str(e)


def is_available():
    return PIL_AVAILABLE
