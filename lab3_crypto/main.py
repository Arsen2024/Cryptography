# Лабораторна робота №3
# Цифровий підпис на основі RSA

# Українська абетка: 33 літери + пробіл = 34 символи
# Потрібні нові ключі RSA, щоб n > 33 (розмір алфавіту)
# Беремо p=3, q=13 → n=39, що покриває всі 34 символи (0..33)
# (p-1)(q-1) = 2*12 = 24
# E=5: gcd(5,24)=1 ✓
# D: 5*D ≡ 1 mod 24 → D=5 (5*5=25≡1 mod 24) ✓
p = 3
q = 13
n = p * q   # n = 39
E = 5       # відкритий ключ
D = 5       # секретний ключ (5*5=25 ≡ 1 mod 24)

# Українська абетка (33 літери) + пробіл = 34 символи, індекси 0..33
# А=00, Б=01, В=02, ..., Я=32, пробіл=33
ALPHABET = "АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ "
# Індекси: А=0, Б=1, ..., Я=32, пробіл=33

def char_to_num(c):
    """Перетворює символ у число за таблицею."""
    c = c.upper()
    if c in ALPHABET:
        return ALPHABET.index(c)
    return None

def num_to_char(num):
    """Перетворює число у символ за таблицею."""
    if 0 <= num < len(ALPHABET):
        return ALPHABET[num]
    return '?'

def rsa_encrypt(x, key, mod):
    """Шифрування: C = X^key mod n"""
    return pow(x, key, mod)

def rsa_decrypt(c, key, mod):
    """Дешифрування: X = C^key mod n"""
    return pow(c, key, mod)

def hash_function(numbers):
    """Хеш-функція: H(M) = сума всіх mi mod n (mod 39)"""
    return sum(numbers) % n

# ============================================================
# ЧАСТИНА 1: Відправник — шифрування і цифровий підпис
# ============================================================

def sign_message(message: str, input_file: str = "message.txt", output_file: str = "signed_message.txt"):
    """
    Читає повідомлення, шифрує його, обчислює хеш і цифровий підпис,
    записує результат у файл.
    """
    # Записати відкрите повідомлення у файл
    with open(input_file, "w", encoding="utf-8") as f:
        f.write(message)
    print(f"[1] Відкрите повідомлення записано у '{input_file}'")

    # Читаємо повідомлення з файлу
    with open(input_file, "r", encoding="utf-8") as f:
        text = f.read().strip().upper()
    print(f"[2] Прочитано повідомлення: {text}")

    # Перетворюємо символи у числа
    numbers = []
    for char in text:
        num = char_to_num(char)
        if num is not None:
            numbers.append(num)
        else:
            print(f"    [!] Символ '{char}' пропущено (не знайдено в таблиці)")

    print(f"[3] Числові коди: {numbers}")

    # Шифруємо кожен символ: Ci = Xi^E mod n
    encrypted = [rsa_encrypt(x, E, n) for x in numbers]
    print(f"[4] Зашифроване повідомлення: {encrypted}")

    # Обчислюємо хеш відкритого повідомлення
    h = hash_function(numbers)
    print(f"[5] Хеш-функція H(M) = {h}")

    # Обчислюємо цифровий підпис: P = H^E mod n
    signature = rsa_encrypt(h, E, n)
    print(f"[6] Цифровий підпис P = {signature}")

    # Записуємо зашифроване повідомлення і підпис у файл
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("ЗАШИФРОВАНЕ ПОВІДОМЛЕННЯ:\n")
        f.write(" ".join(map(str, encrypted)) + "\n")
        f.write("ЦИФРОВИЙ ПІДПИС:\n")
        f.write(str(signature) + "\n")

    print(f"[7] Результат записано у '{output_file}'\n")
    return encrypted, signature

# ============================================================
# ЧАСТИНА 2: Отримувач — перевірка підпису
# ============================================================

def verify_message(signed_file: str = "signed_message.txt"):
    """
    Читає зашифроване повідомлення і підпис, розшифровує,
    перевіряє автентичність.
    """
    print("=" * 50)
    print("ПЕРЕВІРКА ЦИФРОВОГО ПІДПИСУ")
    print("=" * 50)

    # Читаємо файл
    with open(signed_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    encrypted = list(map(int, lines[1].strip().split()))
    signature = int(lines[3].strip())

    print(f"[1] Зашифроване повідомлення: {encrypted}")
    print(f"[2] Цифровий підпис: {signature}")

    # Розшифровуємо повідомлення: Xi = Ci^D mod n
    decrypted_numbers = [rsa_decrypt(c, D, n) for c in encrypted]
    print(f"[3] Розшифровані коди: {decrypted_numbers}")

    # Відновлюємо текст
    decrypted_text = "".join(num_to_char(x) for x in decrypted_numbers)
    print(f"[4] Розшифроване повідомлення: {decrypted_text}")

    # Обчислюємо хеш розшифрованого повідомлення
    h_computed = hash_function(decrypted_numbers)
    print(f"[5] Обчислений хеш H(M) = {h_computed}")

    # Розшифровуємо підпис: H' = P^D mod n
    h_from_signature = rsa_decrypt(signature, D, n)
    print(f"[6] Хеш з підпису = {h_from_signature}")

    # Порівнюємо
    print("\n--- РЕЗУЛЬТАТ ПЕРЕВІРКИ ---")
    if h_computed == h_from_signature:
        print("✅ Підпис ДІЙСНИЙ. Повідомлення автентичне!")
    else:
        print("❌ Підпис НЕДІЙСНИЙ! Повідомлення було змінено або підроблено!")
    print()

# ============================================================
# ДЕМОНСТРАЦІЯ РОБОТИ
# ============================================================

if __name__ == "__main__":
    print("=" * 50)
    print("ЛАБОРАТОРНА РОБОТА №3 — RSA ЦИФРОВИЙ ПІДПИС")
    print(f"Ключі: p={p}, q={q}, n={n}, E={E}, D={D}")
    print("=" * 50 + "\n")

    # --- Крок 1: Підписуємо повідомлення ---
    message = "ПРИВІТ УКРАЇНО"
    print(f"Повідомлення для підпису: '{message}'\n")
    sign_message(message)

    # --- Крок 2: Перевіряємо справжній підпис ---
    verify_message()

    # --- Крок 3: Підробляємо підпис і перевіряємо ---
    print("=" * 50)
    print("ТЕСТ: Замінюємо підпис на підроблений (число 15)")
    print("=" * 50)

    with open("signed_message.txt", "r", encoding="utf-8") as f:
        lines = f.readlines()

    # Підробляємо підпис
    lines[3] = "15\n"

    with open("signed_message.txt", "w", encoding="utf-8") as f:
        f.writelines(lines)

    verify_message()