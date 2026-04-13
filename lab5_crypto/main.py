import random

# BBS генератор
def bbs_generator(p, q, seed, length):

    n = p * q

    x = seed % n

    bits = []

    for _ in range(length):
        x = (x * x) % n
        bits.append(x % 2)

    return bits

# XOR
def xor_bit(a, b):
    return str(int(a) ^ int(b))

def text_to_bits(text):
    return ''.join(format(ord(c), '08b') for c in text)

def bits_to_text(bits):
    chars = []
    for i in range(0, len(bits), 8):
        chars.append(chr(int(bits[i:i+8], 2)))
    return ''.join(chars)


def encrypt(text, keystream):

    text_bits = text_to_bits(text)

    cipher_bits = ''

    for t, k in zip(text_bits, keystream):
        cipher_bits += xor_bit(t, k)

    return cipher_bits

def decrypt(cipher_bits, keystream):

    plain_bits = ''

    for c, k in zip(cipher_bits, keystream):
        plain_bits += xor_bit(c, k)

    return bits_to_text(plain_bits)

if __name__ == "__main__":
    p = 383
    q = 503

    n = p * q

    seed = 123

    text = "HELLO"

    bits_len = len(text) * 8

    keystream = bbs_generator(p, q, seed, bits_len)

    print("Keystream:", keystream)

    cipher = encrypt(text, keystream)

    print("\nCipher bits:", cipher)

    decrypted = decrypt(cipher, keystream)

    print("\nDecrypted:", decrypted)