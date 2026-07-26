# Ghidra Python Script: XOR String Deobfuscation & Annotator
# @category MalwareAnalysis.Deobfuscation
# @author Malware Analyst
#
# Изменения по сравнению с исходной версией:
#  - обработка исключений при чтении памяти (не падает на первом же плохом адресе)
#  - поддержка ASCII и UTF-16LE строк
#  - извлечение всех null-terminated строк из буфера, а не только первой
#  - уникальные имена меток (не конфликтуют между разными адресами)
#  - интерактивный запрос ключа/адреса, если ничего не задано в настройках
#  - createLabel обёрнут в try/except (дубликат имени больше не роняет скрипт)

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.mem import MemoryAccessException

# ==============================================================================
# НАСТРОЙКИ
# ==============================================================================
# Ключ XOR: однобайтовый [0x5A] или многобайтовый [0xDE, 0xAD, 0xBE, 0xEF].
# Если оставить пустым списком [], скрипт спросит ключ интерактивно.
XOR_KEY = [0x5A]

# Кодировка расшифрованных данных: "ascii" или "utf16le"
ENCODING = "ascii"

# Извлекать все null-terminated строки из буфера, а не только первую
EXTRACT_ALL_STRINGS = True

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


def extract_ascii_strings(data):
    """Извлечение всех null-terminated ASCII-строк из буфера."""
    strings = []
    current = []
    for b in data:
        if b == 0:
            if current:
                strings.append("".join(current))
                current = []
            continue
        current.append(chr(b) if 32 <= b <= 126 else '.')
    if current:
        strings.append("".join(current))
    return strings if strings else [""]


def extract_utf16le_strings(data):
    """Извлечение всех null-terminated UTF-16LE строк из буфера."""
    strings = []
    current = []
    i = 0
    n = len(data)
    while i + 1 < n:
        lo = data[i]
        hi = data[i + 1]
        code = lo | (hi << 8)
        if code == 0:
            if current:
                strings.append("".join(current))
                current = []
        elif 32 <= code <= 126:
            current.append(chr(code))
        else:
            current.append('.')
        i += 2
    if current:
        strings.append("".join(current))
    return strings if strings else [""]


def to_strings(data, encoding):
    """Диспетчер извлечения строк по выбранной кодировке."""
    if encoding == "utf16le":
        return extract_utf16le_strings(data)
    return extract_ascii_strings(data)


def safe_read_bytes(start_addr, length):
    """
    Безопасное чтение байт из памяти.
    Бросает MemoryAccessException с понятным сообщением, если чтение не удалось,
    и предупреждает (но не молчит), если реально прочитано байт меньше запрошенного.
    """
    buf = bytearray(length)
    try:
        read_count = getBytes(start_addr, buf)
    except MemoryAccessException as e:
        raise MemoryAccessException(
            "Не удалось прочитать {} байт по адресу {}: {}".format(length, start_addr, str(e))
        )
    if isinstance(read_count, int) and read_count < length:
        print("[!] ВНИМАНИЕ: по адресу {} запрошено {} байт, реально прочитано {}. "
              "Регион памяти может быть короче или лежать на границе сегмента.".format(
                  start_addr, length, read_count))
    return buf


def make_unique_label(base_name, addr):
    """Строит уникальное имя метки, включая адрес, чтобы избежать коллизий имён."""
    return "dec_{}_{}".format(base_name, addr.toString().replace(":", "_"))


def process_memory_range(start_addr, length):
    """Чтение, расшифровка и аннотирование участка памяти. Не бросает исключений наружу."""
    try:
        buf = safe_read_bytes(start_addr, length)
    except MemoryAccessException as e:
        print("[-] Пропуск {}: {}".format(start_addr, str(e)))
        return

    decrypted = xor_decrypt(buf, XOR_KEY)
    strings_found = to_strings(decrypted, ENCODING)

    if not EXTRACT_ALL_STRINGS:
        strings_found = strings_found[:1]

    text_result = strings_found[0] if strings_found else ""
    hex_str = " ".join("{:02X}".format(b) for b in decrypted)

    # Если строк несколько - показываем все в комментарии, а не только первую
    if len(strings_found) > 1:
        strings_block = "\n".join("  [{}] {}".format(i, s) for i, s in enumerate(strings_found))
    else:
        strings_block = text_result

    # 1. Plate Comment (крупный блок над адресом)
    plate_msg = (
        "----------------------------------------\n"
        "[+] DEOBFUSCATED STRING(S)\n"
        "Key:      {}\n"
        "Encoding: {}\n"
        "Hex:      {}\n"
        "Text:\n{}\n"
        "----------------------------------------"
    ).format(
        [hex(k) for k in XOR_KEY],
        ENCODING,
        hex_str,
        strings_block,
    )
    setPlateComment(start_addr, plate_msg)

    # 2. EOL Comment (комментарий в той же строке)
    setEOLComment(start_addr, 'Decrypted: "{}"'.format(text_result))

    # 3. Метка (Label), если строка читаема. Имя включает адрес,
    #    чтобы не конфликтовать с другими адресами, дающими тот же текст
    #    (например, повторяющиеся "http" в разных строках).
    clean_label = "".join(c for c in text_result[:16] if c.isalnum() or c == '_')
    if clean_label:
        label_name = make_unique_label(clean_label, start_addr)
        try:
            createLabel(start_addr, label_name, True, SourceType.USER_DEFINED)
        except Exception as e:
            print("[!] Не удалось создать метку '{}' по адресу {}: {}".format(
                label_name, start_addr, str(e)))

    print("[+] [{}] -> {}".format(start_addr, text_result))


def get_key_interactively():
    """Запрашивает XOR-ключ у пользователя, если он не задан в настройках."""
    key_str = askString(
        "XOR Key",
        "Ключ не задан в XOR_KEY. Введите байты через пробел (пример: 5A или DE AD BE EF):"
    )
    try:
        return [int(part, 16) for part in key_str.replace(",", " ").split()]
    except ValueError:
        print("[-] Не удалось разобрать ключ '{}'. Использую 0x00 (без изменений).".format(key_str))
        return [0x00]


def main():
    global XOR_KEY

    if not XOR_KEY:
        XOR_KEY = get_key_interactively()

    # Режим 1: Работа по выделенной области в окне Listing
    if currentSelection is not None and not currentSelection.isEmpty():
        for address_range in currentSelection:
            process_memory_range(address_range.getMinAddress(), address_range.getLength())
        return

    # Режим 2: Работа по списку TARGET_ADDRESSES
    if TARGET_ADDRESSES:
        for addr_hex, length in TARGET_ADDRESSES:
            addr = toAddr(addr_hex)
            process_memory_range(addr, length)
        return

    # Режим 3: интерактивный запрос адреса и длины, если ничего не задано
    addr_str = askString(
        "Адрес",
        "Выделение пустое и TARGET_ADDRESSES не заполнен.\n"
        "Введите адрес в hex (пример: 00401050) или оставьте пустым для отмены:"
    )
    if not addr_str.strip():
        print("[-] Отменено пользователем.")
        return

    length = askInt("Длина", "Сколько байт прочитать по адресу {}?".format(addr_str))
    addr = toAddr(addr_str)
    process_memory_range(addr, length)


main()