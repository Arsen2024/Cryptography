"""
Мережний чат з блочним симетричним шифруванням (AES-CBC)
==========================================================
КЛІЄНТ
"""

import socket
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import os

# ── Спільний ключ (однаковий на сервері та клієнті) ──────────────────────────
SHARED_SECRET = b"my_secret_key_12"
KEY = hashlib.sha256(SHARED_SECRET).digest()[:16]

HOST = "127.0.0.1"
PORT = 9999

def encrypt(plaintext: str) -> bytes:
    """Шифрування AES-CBC. Повертає IV (16 байт) + зашифровані дані."""
    iv = os.urandom(16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
    return iv + ct

def decrypt(data: bytes) -> str:
    """Розшифрування AES-CBC. Очікує IV (16 байт) + зашифровані дані."""
    iv = data[:16]
    ct = data[16:]
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode("utf-8")

def recv_exact(sock, length):
    """Зчитує рівно length байт із сокета."""
    buf = b""
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            raise ConnectionError("З'єднання закрито")
        buf += chunk
    return buf


def send_message(sock, text):
    """Шифрує та відправляє повідомлення: [4 байти довжини][дані]."""
    encrypted = encrypt(text)
    length = len(encrypted).to_bytes(4, "big")
    sock.sendall(length + encrypted)


def receive_message(sock):
    """Отримує та розшифровує повідомлення."""
    raw_len = recv_exact(sock, 4)
    length = int.from_bytes(raw_len, "big")
    data = recv_exact(sock, length)
    return decrypt(data)


def main():
    print("=" * 50)
    print("  ЗАШИФРОВАНИЙ ЧАТ — КЛІЄНТ (AES-128-CBC)")
    print("=" * 50)

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))
    print(f"[+] Підключено до сервера {HOST}:{PORT}")
    print(f"[*] Алгоритм шифрування: AES-128-CBC")
    print(f"[*] Ключ (hex): {KEY.hex()}")
    print("[*] Введіть 'вихід' для завершення\n")
    print("-" * 50)

    def receiver():
        try:
            while True:
                msg = receive_message(client)
                print(f"\n[Сервер → зашифровано → розшифровано]: {msg}")
                print("Ваше повідомлення: ", end="", flush=True)
        except Exception:
            print("\n[!] Сервер відключився.")

    t = threading.Thread(target=receiver, daemon=True)
    t.start()

    try:
        while True:
            text = input("Ваше повідомлення: ")
            if text.lower() == "вихід":
                break
            send_message(client, text)
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        client.close()
        print("[*] З'єднання закрито.")

if __name__ == "__main__":
    main()