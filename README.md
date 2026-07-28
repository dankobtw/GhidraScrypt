# GhidraScrypt

*[Читать на русском](README.ru.md)*

A Ghidra Python (Jython) script that automates decrypting XOR-obfuscated strings while reverse-engineering malware: it finds a string, decrypts it, decodes it, and annotates it in place (comments, label, bookmark) - no need to copy bytes out into a separate script.

## Features

- XOR decryption with a single-byte (`[0x5A]`) or multi-byte (`[0xDE, 0xAD, 0xBE, 0xEF]`) key
- Single-byte key brute-force auto-detection (all 256 candidates, scored by the fraction of printable ASCII bytes in the result)
- Decodes the result as ASCII or UTF-16LE
- Annotates directly in the Listing: a Plate comment with details (key, encoding, hex, text), an EOL comment with the decrypted string, a unique label at the address, and a bookmark for quick navigation
- Safe memory reads - a bad address is skipped with a warning instead of crashing the script

## Installation

1. Copy `xor_deobfuscator.py` into your Ghidra scripts folder (`Window → Script Manager → Script Directories`, or the default `~/ghidra_scripts`).
2. Refresh the script list in the Script Manager (refresh icon) - the script shows up under the `MalwareAnalysis.Deobfuscation` category.

## Usage

There are three modes - the script picks whichever applies, in this order:

1. **Selection in the Listing.** Select one or more byte ranges in the Listing window and run the script - each selection gets processed.
2. **`TARGET_ADDRESSES` in the code.** If nothing is selected, the script uses the address list from the settings at the top of the file:
   ```python
   TARGET_ADDRESSES = [
       (0x00401050, 32),
       (0x00401090, 16),
   ]
   ```
3. **Interactive prompt.** If both the selection and `TARGET_ADDRESSES` are empty, the script asks for an address and length via a dialog.

### Settings (top of the file)

| Setting | Description |
|---|---|
| `XOR_KEY` | XOR key as a list of bytes, e.g. `[0x5A]` or `[0xDE, 0xAD, 0xBE, 0xEF]`. Ignored if `AUTO_DETECT_KEY` is enabled. If left empty (`[]`) with auto-detect off, the script will prompt for a key. |
| `AUTO_DETECT_KEY` | `True`/`False`. Brute-forces all 256 single-byte keys and picks the one with the highest printable-character ratio. Only works for single-byte keys. |
| `ENCODING` | `"ascii"` or `"utf16le"` - how to decode the decrypted bytes. |
| `ADD_BOOKMARKS` | Whether to create a bookmark on the found string (visible in the Bookmarks window). |
| `TARGET_ADDRESSES` | List of `(address, length_in_bytes)` for batch processing without manual selection. |

## Example output

```
[+] [0x00401050] -> https://example.com/gate.php
```

At that address in the Listing you'll see a Plate comment with the key, hex dump, and decrypted text, plus a bookmark and a `dec_https___...` label.

## Limitations

- Key auto-detection is a heuristic based on printable ASCII ratio - it can be wrong on short buffers (under ~8 bytes), so double-check the result manually.
- Auto-detection is only implemented for single-byte keys.
