import re
import os


def extract_strings(file_path, min_length=4):
    """Extract printable strings from any binary file (like Linux strings command)."""
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        pattern = rb'[ -~]{' + str(min_length).encode() + rb',}'
        matches = re.findall(pattern, data)
        return [m.decode("ascii", errors="ignore") for m in matches], None
    except Exception as e:
        return [], str(e)


def find_flags(strings_list, flag_format=None):
    """Filter strings that look like flags."""
    flag_patterns = [
        r'[A-Z]{2,8}\{[^\}]+\}',   # Generic CTF flag
        r'flag\{[^\}]+\}',
        r'HTB\{[^\}]+\}',
        r'THM\{[^\}]+\}',
        r'CTF\{[^\}]+\}',
    ]

    if flag_format:
        flag_patterns.append(re.escape(flag_format) + r'[^\}]*\}')

    results = []
    for s in strings_list:
        for pattern in flag_patterns:
            if re.search(pattern, s, re.IGNORECASE):
                results.append(s)
                break

    return results


def extract_from_file(file_path, flag_format=None, min_length=4):
    """Full pipeline: extract strings + find flags."""
    strings, err = extract_strings(file_path, min_length)
    if err:
        return [], [], err

    flags = find_flags(strings, flag_format)
    return strings, flags, None
