# Ghidra Python Script: XOR String Deobfuscation & Annotator
# @category MalwareAnalysis.Deobfuscation
# @author Malware Analyst
#
# Features:
#  - XOR decryption (single-byte or multi-byte key)
#  - single-byte key brute-force auto-detection, if unknown
#  - ASCII or UTF-16LE decoding
#  - Plate/EOL comments, a label, and a bookmark on the found string
#  - doesn't crash on a bad address - skips it and moves on

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.mem import MemoryAccessException

# ==============================================================================
# SETTINGS
# ==============================================================================
# XOR key: single-byte [0x5A] or multi-byte [0xDE, 0xAD, 0xBE, 0xEF].
# Ignored if AUTO_DETECT_KEY = True.
XOR_KEY = [0x5A]

# Brute-force a single-byte key (256 options) instead of taking it from XOR_KEY.
# Only works for single-byte keys - multi-byte keys need a different approach.
AUTO_DETECT_KEY = False

# Encoding of the decrypted data: "ascii" or "utf16le"
ENCODING = "ascii"

# Create a Bookmark on the found string (visible in the Bookmarks window for quick navigation)
ADD_BOOKMARKS = True

# Set addresses manually if you're NOT using mouse selection in the UI.
# Format: (0xADDRESS, LENGTH_IN_BYTES)
TARGET_ADDRESSES = [
    # (0x00401050, 32),
    # (0x00401090, 16),
]
# ==============================================================================


def xor_decrypt(data, key):
    """Decrypts bytes using a cyclic XOR key."""
    decrypted = bytearray()
    for i, b in enumerate(data):
        k = key[i % len(key)]
        decrypted.append((b & 0xFF) ^ k)
    return decrypted


def decode_string(data, encoding):
    """Decodes a buffer up to the first null byte/char. ascii or utf16le."""
    chars = []
    if encoding == "utf16le":
        i = 0
        while i + 1 < len(data):
            code = data[i] | (data[i + 1] << 8)
            if code == 0:
                break
            chars.append(chr(code) if 32 <= code <= 126 else '.')
            i += 2
    else:
        for b in data:
            if b == 0:
                break
            chars.append(chr(b) if 32 <= b <= 126 else '.')
    return "".join(chars)


def score_printable(data):
    """Fraction of printable ASCII bytes (0.0-1.0) - used for key guessing."""
    if not data:
        return 0.0
    printable = sum(1 for b in data if 32 <= b <= 126)
    return float(printable) / len(data)


def guess_single_byte_key(data):
    """
    Brute-forces all 256 single-byte keys, picks the one with the highest printable-char ratio.
    Heuristic: can be wrong on short buffers (< ~8 bytes) - worth double-checking manually.
    """
    best_key, best_score = 0, -1.0
    for k in range(256):
        score = score_printable(xor_decrypt(data, [k]))
        if score > best_score:
            best_key, best_score = k, score
    return best_key, best_score


def safe_read_bytes(start_addr, length):
    """Reads bytes from memory, raising a clear error instead of silently corrupting data."""
    buf = bytearray(length)
    try:
        read_count = getBytes(start_addr, buf)
    except MemoryAccessException as e:
        raise MemoryAccessException("failed to read {} bytes: {}".format(length, str(e)))
    if isinstance(read_count, int) and read_count < length:
        print("[!] {}: requested {} bytes, actually read {} (region boundary?)".format(
            start_addr, length, read_count))
    return buf


def make_unique_label(text, addr):
    """Label name includes the address to avoid conflicts with other addresses."""
    clean = "".join(c for c in text[:16] if c.isalnum() or c == '_')
    if not clean:
        return None
    return "dec_{}_{}".format(clean, addr.toString().replace(":", "_"))


def process_memory_range(start_addr, length):
    """Reads, decrypts, and annotates a memory range. Never raises exceptions outward."""
    try:
        buf = safe_read_bytes(start_addr, length)
    except MemoryAccessException as e:
        print("[-] Skipping {}: {}".format(start_addr, str(e)))
        return

    if AUTO_DETECT_KEY:
        guessed, score = guess_single_byte_key(buf)
        key = [guessed]
        print("[?] {}: guessed key 0x{:02X} (score={:.2f})".format(start_addr, guessed, score))
    else:
        key = XOR_KEY

    decrypted = xor_decrypt(buf, key)
    text = decode_string(decrypted, ENCODING)
    hex_str = " ".join("{:02X}".format(b) for b in decrypted)
    key_hex = ", ".join(hex(k) for k in key)

    plate_msg = (
        "----------------------------------------\n"
        "[+] DEOBFUSCATED STRING\n"
        "Key:      {}\n"
        "Encoding: {}\n"
        "Hex:      {}\n"
        "Text:     {}\n"
        "----------------------------------------"
    ).format(key_hex, ENCODING, hex_str, text)
    setPlateComment(start_addr, plate_msg)
    setEOLComment(start_addr, 'Decrypted: "{}"'.format(text))

    label_name = make_unique_label(text, start_addr)
    if label_name:
        try:
            createLabel(start_addr, label_name, True, SourceType.USER_DEFINED)
        except Exception as e:
            print("[!] Label '{}' not created: {}".format(label_name, str(e)))

    if ADD_BOOKMARKS:
        try:
            createBookmark(start_addr, "XOR Deobfuscation", text[:80])
        except Exception as e:
            print("[!] Bookmark not created at address {}: {}".format(start_addr, str(e)))

    print("[+] [{}] -> {}".format(start_addr, text))


def get_key_interactively():
    """Asks the user for the XOR key if it isn't set and auto-detection is off."""
    key_str = askString("XOR Key", "Enter key bytes separated by spaces (example: 5A or DE AD BE EF):")
    try:
        return [int(part, 16) for part in key_str.replace(",", " ").split()]
    except ValueError:
        print("[-] Could not parse '{}'. Using 0x00.".format(key_str))
        return [0x00]


def main():
    global XOR_KEY
    if not AUTO_DETECT_KEY and not XOR_KEY:
        XOR_KEY = get_key_interactively()

    # Mode 1: selection in the Listing window
    if currentSelection is not None and not currentSelection.isEmpty():
        for address_range in currentSelection:
            process_memory_range(address_range.getMinAddress(), address_range.getLength())
        return

    # Mode 2: TARGET_ADDRESSES list
    if TARGET_ADDRESSES:
        for addr_hex, length in TARGET_ADDRESSES:
            process_memory_range(toAddr(addr_hex), length)
        return

    # Mode 3: interactive address prompt if nothing else is set
    addr_str = askString("Address", "Selection is empty, TARGET_ADDRESSES is not filled.\nEnter address in hex:")
    if not addr_str.strip():
        print("[-] Cancelled by user.")
        return
    length = askInt("Length", "How many bytes to read at address {}?".format(addr_str))
    process_memory_range(toAddr(addr_str), length)


main()
