from unittest import result
import time

P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
P8 = [6, 3, 7, 4, 8, 5, 10, 9]

IP = [2, 6, 3, 1, 4, 8, 5, 7]
IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]

EP = [4, 1, 2, 3, 2, 3, 4, 1]
P4 = [2, 4, 3, 1]

S0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 1]
]

S1 = [
    [1, 1, 2, 3],
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3]
]

def permute(bits, table):
    return ''.join(bits[i-1] for i in table)

def left_shift(bits, shifts):
    return bits[shifts:] + bits[:shifts]

def xor(bits1, bits2):
    return ''.join('0' if b1 == b2 else '1' for b1, b2 in zip(bits1, bits2))

def generate_keys(key):
    key = permute(key, P10)

    left = key[:5]
    right = key[5:]

    left = left_shift(left, 1)
    right = left_shift(right, 1)

    K1 = permute(left + right, P8)

    left = left_shift(left, 2)
    right = left_shift(right, 2)

    K2 = permute(left + right, P8)

    return K1, K2

def sbox_lookup(bits, sbox):
    row = int(bits[0] + bits[3], 2)
    col = int(bits[1] + bits[2], 2)
    value = sbox[row][col]
    return format(value, '02b') #2 біти

def fk(bits, key):
    left = bits[:4]
    right = bits[4:]

    expanded = permute(right, EP)

    temp = xor(expanded, key)

    left_part = temp[:4]
    right_part = temp[4:]

    s0_output = sbox_lookup(left_part, S0)
    s1_output = sbox_lookup(right_part, S1)

    combined = s0_output + s1_output

    p4_result = permute(combined, P4)

    result_left = xor(left, p4_result)

    return result_left + right

def switch(bits):
    return bits[4:] + bits[:4]

def encrypt_block(plaintext, K1, K2):
    bits = permute(plaintext, IP)
    bits = fk(bits, K1)
    bits = switch(bits)
    bits = fk(bits, K2)
    ciphertext = permute(bits, IP_INV)
    return ciphertext

def decrypt_block(ciphertext, K1, K2):
    bits = permute(ciphertext, IP)
    bits = fk(bits, K2)
    bits = switch(bits)
    bits = fk(bits, K1)
    plaintext = permute(bits, IP_INV)
    return plaintext

def text_to_bits(text):
    return[format(ord(c), '08b') for c in text]

def bits_to_text(bits_list):
    return ''.join(chr(int(b, 2)) for b in bits_list)

def encrypt_text(text, key):
    K1, K2 = generate_keys(key)
    bits_list = text_to_bits(text)
    encrypted_bits = [encrypt_block(b, K1, K2) for b in bits_list]
    return encrypted_bits

def decrypt_text(encrypted_bits, key):
    K1, K2 = generate_keys(key)
    decrypted_bits = [decrypt_block(b, K1, K2) for b in encrypted_bits]
    return bits_to_text(decrypted_bits)

def brute_force(plaintext, ciphertext):
    start = time.time()
    for i in range(1024):
        key = format(i, '010b')
        K1, K2 = generate_keys(key)
        test = encrypt_block(plaintext, K1, K2)
        if test == ciphertext:
            end = time.time()
            print("Можливий ключ:", key)
            print("Час:", end-start)
            return


def brute_force_text(cipher_bits, expected_text):
    start = time.time()
    for i in range(1024):
        key = format(i, '010b')
        decrypted = decrypt_text(cipher_bits, key)
        if decrypted == expected_text:
            end = time.time()
            print("Ключ знайдено:", key)
            print("Розшифрований текст:", decrypted)
            print("Перебрано ключів:", i+1)
            print("Час:", end - start)
            return

    print("Ключ не знайдено")

if __name__ == '__main__':
    key = "1010000010"
    plaintext = "11010111"
    text = "hello"

    K1, K2 = generate_keys(key)

    encrypted = encrypt_block(plaintext, K1, K2)
    decrypted = decrypt_block(encrypted, K1, K2)

    encrypted_text = encrypt_text(text, key)
    decrypted_text = decrypt_text(encrypted_text, key)

    print("Plaintext:", plaintext)
    print("Encrypted:", encrypted)
    print("Decrypted:", decrypted)

    print("\nТест 1")
    print("Ключ:", key)
    print("Відкритий текст:", text)
    print("Зашифрований (біти):", encrypted_text)
    print("Розшифрований текст:", decrypted_text)

    # Другий текст і ключ
    text2 = "simple"
    key2 = "1110001110"

    K1, K2 = generate_keys(key2)
    encrypted2 = encrypt_text(text2, key2)
    decrypted2 = decrypt_text(encrypted2, key2)

    print("\nТест 2")
    print("Ключ:", key2)
    print("Відкритий текст:", text2)
    print("Зашифрований (біти):", ' '.join(encrypted2))
    print("Розшифрований текст:", decrypted2)

    # Третій текст і ключ
    text3 = "hard"
    key3 = "0010010111"

    K1, K2 = generate_keys(key3)
    encrypted3 = encrypt_text(text3, key3)
    decrypted3 = decrypt_text(encrypted3, key3)

    print("\nТест 3")
    print("Ключ:", key3)
    print("Відкритий текст:", text3)
    print("Зашифрований (біти):", ' '.join(encrypted3))
    print("Розшифрований текст:", decrypted3)

    print("\nBrute Force атака")
    key4 = "0010100111"
    plaintext2 = "10000111"

    K1, K2 = generate_keys(key4)
    cipher = encrypt_block(plaintext2, K1, K2)

    brute_force(plaintext2, cipher)

    print("\nBrute Force атака (для тексту)")

    text_attack = "hard"
    key_attack = "0010010111"

    encrypted_attack = encrypt_text(text_attack, key_attack)
    print("Зашифрований текст (біти):", ' '.join(encrypted_attack))
    brute_force_text(encrypted_attack, text_attack)
