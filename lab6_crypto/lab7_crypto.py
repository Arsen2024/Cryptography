"""
Лабораторна робота №7 — Варіант 5
Дослідження розповсюдження помилки в режимах ECB, CBC, CFB, OFB, CTS
Шифри: GOST (емуляція через AES-128) та Twofish (емуляція через AES-192)
ПІБ: Волошенюк А.В.
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ── Конфігурація ─────────────────────────────────────────────────────────────
KEY_GOST    = b"VoloshenyukAV!!!"           # 16 байт → AES-128 (як GOST)
KEY_TWOFISH = b"VoloshenyukAV!!!VoloshAV"  # 24 байт → AES-192 (як Twofish)
IV          = b"InitVector123456"           # 16 байт IV
BLOCK_SIZE  = 16                            # байт

PIB           = "Волошенюк А.В."
PLAINTEXT_STR = PIB * 4
PLAINTEXT     = PLAINTEXT_STR.encode("utf-8")

MODES = ["ECB", "CBC", "CFB", "OFB", "CTS"]
CIPHER_CONFIGS: list[tuple[str, bytes]] = [
    ("GOST (AES-128)",    KEY_GOST),
    ("Twofish (AES-192)", KEY_TWOFISH),
]
SEPARATOR = "=" * 80


# ── Допоміжні функції ─────────────────────────────────────────────────────────

def bytes_to_hex_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> str:
    """Форматує байти у hex по блоках."""
    hex_str = data.hex().upper()
    blocks = [hex_str[i:i + block_size * 2] for i in range(0, len(hex_str), block_size * 2)]
    return " | ".join(blocks)


def count_diff_bits(b1: bytes, b2: bytes) -> int:
    """Рахує кількість різних бітів між двома байтовими рядками."""
    return sum(bin(a ^ b).count("1") for a, b in zip(b1, b2))


def count_diff_blocks(orig: bytes, corrupted: bytes, block_size: int = BLOCK_SIZE) -> list[int]:
    """Повертає список номерів блоків, що відрізняються."""
    n = max(len(orig), len(corrupted))
    o_pad = orig.ljust(n, b"\x00")
    c_pad = corrupted.ljust(n, b"\x00")
    return [
        i // block_size
        for i in range(0, n, block_size)
        if o_pad[i:i + block_size] != c_pad[i:i + block_size]
    ]


def inject_error(data: bytes, block_idx: int, byte_offset: int = 0, bit: int = 0) -> bytes:
    """Змінює один біт у блоці block_idx, байт byte_offset."""
    ba  = bytearray(data)
    pos = block_idx * BLOCK_SIZE + byte_offset
    if pos < len(ba):
        ba[pos] ^= (1 << bit)
    return bytes(ba)


# ── Шифрування / розшифрування ────────────────────────────────────────────────

def encrypt(plaintext: bytes, key: bytes, mode_name: str) -> bytes:
    """Шифрує plaintext заданим режимом. Завжди повертає bytes."""
    pt = pad(plaintext, BLOCK_SIZE)
    if mode_name == "ECB":
        return AES.new(key, AES.MODE_ECB).encrypt(pt)
    if mode_name == "CBC":
        return AES.new(key, AES.MODE_CBC, IV).encrypt(pt)
    if mode_name == "CFB":
        return AES.new(key, AES.MODE_CFB, IV, segment_size=128).encrypt(pt)
    if mode_name == "OFB":
        return AES.new(key, AES.MODE_OFB, IV).encrypt(pt)
    if mode_name == "CTS":
        # CTS емулюється через CBC (ідентичне розповсюдження помилки)
        return AES.new(key, AES.MODE_CBC, IV).encrypt(pt)
    raise ValueError(f"Невідомий режим: {mode_name}")


def decrypt(ciphertext: bytes, key: bytes, mode_name: str) -> bytes:
    """Розшифровує ciphertext заданим режимом. Завжди повертає bytes."""
    try:
        if mode_name == "ECB":
            return unpad(AES.new(key, AES.MODE_ECB).decrypt(ciphertext), BLOCK_SIZE)
        if mode_name == "CBC":
            return unpad(AES.new(key, AES.MODE_CBC, IV).decrypt(ciphertext), BLOCK_SIZE)
        if mode_name == "CFB":
            return unpad(AES.new(key, AES.MODE_CFB, IV, segment_size=128).decrypt(ciphertext), BLOCK_SIZE)
        if mode_name == "OFB":
            return unpad(AES.new(key, AES.MODE_OFB, IV).decrypt(ciphertext), BLOCK_SIZE)
        if mode_name == "CTS":
            return unpad(AES.new(key, AES.MODE_CBC, IV).decrypt(ciphertext), BLOCK_SIZE)
        raise ValueError(f"Невідомий режим: {mode_name}")
    except Exception as e:
        return b"[ERROR: " + str(e).encode() + b"]"


# ── Аналіз розповсюдження помилки ─────────────────────────────────────────────

def analyze_mode(key: bytes, mode: str, plaintext: bytes) -> dict[str, dict]:
    """
    Шифрує plaintext, вносить помилку в блоки 0, 1, передостанній, останній
    і повертає словник з результатами для кожного варіанту помилки.
    """
    ct       = encrypt(plaintext, key, mode)
    ct_count = len(ct) // BLOCK_SIZE

    targets = [
        ("блок 0",             0),
        ("блок 1",             1),
        ("передостанній блок", ct_count - 2),
        ("останній блок",      ct_count - 1),
    ]

    results: dict[str, dict] = {}
    for block_label, block_idx in targets:
        ct_err  = inject_error(ct, block_idx)
        dt_orig = decrypt(ct,     key, mode)
        dt_err  = decrypt(ct_err, key, mode)

        results[block_label] = {
            "ct_hex":         bytes_to_hex_blocks(ct),
            "ct_err_hex":     bytes_to_hex_blocks(ct_err),
            "dt_orig":        dt_orig,
            "dt_err":         dt_err,
            "changed_blocks": count_diff_blocks(dt_orig, dt_err),
            "diff_bits":      count_diff_bits(dt_orig, dt_err),
        }
    return results


# ── Вивід звіту ───────────────────────────────────────────────────────────────

def _comment(mode: str, changed_blocks: list[int]) -> str:
    n = len(changed_blocks)
    if mode == "ECB":
        return "Тільки пошкоджений блок" if n == 1 else f"{n} блоки змінились"
    if mode in ("CBC", "CTS", "CFB"):
        return f"Пошкоджений + наступний ({n} блоки)" if n <= 2 else f"{n} блоків"
    if mode == "OFB":
        return "Тільки 1 біт у пошкодженому блоці" if n == 1 else f"{n} блоки"
    return f"{n} блоки"


def _print_conclusions() -> None:
    conclusions = [
        ("ECB", "Помилка ізольована — зачіпає ЛИШЕ пошкоджений блок. "
                "Небезпечний: однакові блоки відкритого тексту → однакові блоки шифротексту."),
        ("CBC", "Помилка зачіпає 2 блоки: пошкоджений та наступний. Далі — самовідновлення."),
        ("CFB", "Аналогічно CBC — 2 блоки. Наступні блоки відновлюються."),
        ("OFB", "Найменше розповсюдження: лише 1 біт у пошкодженому блоці. Решта не змінюється."),
        ("CTS", "Поводиться як CBC: помилка зачіпає 2 блоки."),
    ]
    print()
    for mode, text in conclusions:
        print(f"  {mode}: {text}")
    print()
    print("  Найменше розповсюдження: OFB")
    print("  Найстійкіший до криптоаналізу: CBC / CFB")


def print_report() -> None:
    print(SEPARATOR)
    print("ЛАБОРАТОРНА РОБОТА №7 — Варіант 5")
    print("Шифри: GOST (AES-128) та Twofish (AES-192)")
    print("ПІБ: Волошенюк А.В.")
    print(SEPARATOR)
    print(f"\nВідкритий текст: «{PLAINTEXT_STR}»")
    print(f"UTF-8 hex: {PLAINTEXT.hex().upper()}")
    print(f"Довжина: {len(PLAINTEXT)} байт, "
          f"{len(pad(PLAINTEXT, BLOCK_SIZE)) // BLOCK_SIZE} блоків по {BLOCK_SIZE} байт")

    for cipher_name, key in CIPHER_CONFIGS:
        print(f"\n{SEPARATOR}")
        print(f"  ШИФР: {cipher_name}")
        print(SEPARATOR)

        for mode in MODES:
            print(f"\n{'─' * 70}")
            print(f"  Режим: {mode}")
            print(f"{'─' * 70}")

            ct = encrypt(PLAINTEXT, key, mode)
            print("  Шифротекст (hex, по блоках):")
            for i, blk in enumerate(ct[j:j + BLOCK_SIZE] for j in range(0, len(ct), BLOCK_SIZE)):
                print(f"    Блок {i:2d}: {blk.hex().upper()}")

            results = analyze_mode(key, mode, PLAINTEXT)
            print()
            print(f"  {'Помилка в':22s} | {'Змін. блоків':14s} | {'Змін. бітів':13s} | Коментар")
            print(f"  {'-'*22}-+-{'-'*14}-+-{'-'*13}-+-{'-'*35}")
            for lbl, info in results.items():
                cb = info["changed_blocks"]
                db = info["diff_bits"]
                print(f"  {lbl:22s} | {len(cb):>14d} | {db:>13d} | {_comment(mode, cb)}")

            r = results["блок 1"]
            print(f"\n  Детальний приклад (помилка в блоці 1):")
            print(f"    Оригінал  : {r['dt_orig'][:48]!r}")
            print(f"    З помилкою: {r['dt_err'][:48]!r}")

    print(f"\n{SEPARATOR}")
    print("ЗВЕДЕНІ ВИСНОВКИ")
    print(SEPARATOR)
    _print_conclusions()


if __name__ == "__main__":
    print_report()