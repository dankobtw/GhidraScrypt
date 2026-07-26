# Ghidra Python Script: XOR String Deobfuscation & Annotator
# @category MalwareAnalysis.Deobfuscation
# @author Malware Analyst
#
# Что умеет:
#  - расшифровка XOR (однобайтовый или многобайтовый ключ)
#  - автоподбор однобайтового ключа перебором, если он неизвестен
#  - декодирование ASCII или UTF-16LE
#  - Plate/EOL комментарии, метка и bookmark на найденной строке
#  - не падает на плохом адресе - пропускает и идёт дальше

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.mem import MemoryAccessException

# ==============================================================================
# НАСТРОЙКИ
# ==============================================================================
# Ключ XOR: однобайтовый [0x5A] или многобайтовый [0xDE, 0xAD, 0xBE, 0xEF].
# Игнорируется, если AUTO_DETECT_KEY = True.
XOR_KEY = [0x5A]

# Подбирать однобайтовый ключ перебором (256 вариантов), а не брать его из XOR_KEY.
# Работает только для однобайтовых ключей - для многобайтовых нужен другой подход.
AUTO_DETECT_KEY = False

# Кодировка расшифрованных данных: "ascii" или "utf16le"
ENCODING = "ascii"

# Создавать Bookmark на найденной строке (видно в окне Bookmarks для быстрой навигации)
ADD_BOOKMARKS = True

# Задайте адреса вручную, если НЕ используете выделение мышкой в UI.
# Формат: (0xАДРЕС, ДЛИНА_В_БАЙТАХ)
TARGET_ADDRESSES = [
    # (0x00401050, 32),
    # (0x00401090, 16),
]
# ==============================================================================


def xor_decrypt(data, key):
    """Дешифровка байт с использованием циклического XOR-ключа."""
    decrypted = bytearray()
    for i, b in enumerate(data):
        k = key[i % len(key)]
        decrypted.append((b & 0xFF) ^ k)
    return decrypted


def decode_string(data, encoding):
    """Декодирует буфер до первого null-байта/null-символа. ascii или utf16le."""
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
    """Доля печатных ASCII-байт (0.0-1.0) - используется для подбора ключа."""
    if not data:
        return 0.0
    printable = sum(1 for b in data if 32 <= b <= 126)
    return float(printable) / len(data)


def guess_single_byte_key(data):
    """
    Перебор всех 256 однобайтовых ключей, выбор по максимальной доле печатных символов.
    Эвристика: на коротких буферах (< ~8 байт) может ошибиться - стоит перепроверить глазами.
    """
    best_key, best_score = 0, -1.0
    for k in range(256):
        score = score_printable(xor_decrypt(data, [k]))
        if score > best_score:
            best_key, best_score = k, score
    return best_key, best_score


def safe_read_bytes(start_addr, length):
    """Читает байты из памяти, бросая понятную ошибку вместо тихой порчи данных."""
    buf = bytearray(length)
    try:
        read_count = getBytes(start_addr, buf)
    except MemoryAccessException as e:
        raise MemoryAccessException("не удалось прочитать {} байт: {}".format(length, str(e)))
    if isinstance(read_count, int) and read_count < length:
        print("[!] {}: запрошено {} байт, реально прочитано {} (граница региона?)".format(
            start_addr, length, read_count))
    return buf


def make_unique_label(text, addr):
    """Имя метки включает адрес, чтобы не конфликтовать с другими адресами."""
    clean = "".join(c for c in text[:16] if c.isalnum() or c == '_')
    if not clean:
        return None
    return "dec_{}_{}".format(clean, addr.toString().replace(":", "_"))


def process_memory_range(start_addr, length):
    """Чтение, расшифровка и аннотирование участка памяти. Не бросает исключений наружу."""
    try:
        buf = safe_read_bytes(start_addr, length)
    except MemoryAccessException as e:
        print("[-] Пропуск {}: {}".format(start_addr, str(e)))
        return

    if AUTO_DETECT_KEY:
        guessed, score = guess_single_byte_key(buf)
        key = [guessed]
        print("[?] {}: подобран ключ 0x{:02X} (score={:.2f})".format(start_addr, guessed, score))
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
            print("[!] Метка '{}' не создана: {}".format(label_name, str(e)))

    if ADD_BOOKMARKS:
        try:
            createBookmark(start_addr, "XOR Deobfuscation", text[:80])
        except Exception as e:
            print("[!] Bookmark не создан по адресу {}: {}".format(start_addr, str(e)))

    print("[+] [{}] -> {}".format(start_addr, text))


def get_key_interactively():
    """Запрашивает XOR-ключ у пользователя, если он не задан и автоподбор выключен."""
    key_str = askString("XOR Key", "Введите байты ключа через пробел (пример: 5A или DE AD BE EF):")
    try:
        return [int(part, 16) for part in key_str.replace(",", " ").split()]
    except ValueError:
        print("[-] Не удалось разобрать '{}'. Использую 0x00.".format(key_str))
        return [0x00]


def main():
    global XOR_KEY
    if not AUTO_DETECT_KEY and not XOR_KEY:
        XOR_KEY = get_key_interactively()

    # Режим 1: выделение в окне Listing
    if currentSelection is not None and not currentSelection.isEmpty():
        for address_range in currentSelection:
            process_memory_range(address_range.getMinAddress(), address_range.getLength())
        return

    # Режим 2: список TARGET_ADDRESSES
    if TARGET_ADDRESSES:
        for addr_hex, length in TARGET_ADDRESSES:
            process_memory_range(toAddr(addr_hex), length)
        return

    # Режим 3: интерактивный запрос адреса, если ничего не задано
    addr_str = askString("Адрес", "Выделение пустое, TARGET_ADDRESSES не заполнен.\nВведите адрес в hex:")
    if not addr_str.strip():
        print("[-] Отменено пользователем.")
        return
    length = askInt("Длина", "Сколько байт прочитать по адресу {}?".format(addr_str))
    process_memory_range(toAddr(addr_str), length)


main()
