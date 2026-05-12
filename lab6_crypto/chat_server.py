"""
Мережний чат з блочним симетричним шифруванням (AES-CBC)
==========================================================
СЕРВЕР
"""

import socket
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import os

# ── Спільний ключ (у реальній системі передається через DH або RSA) ──────────
SHARED_SECRET = b"my_secret_key_12"  # 16 байт → AES-128
KEY = hashlib.sha256(SHARED_SECRET).digest()[:16]  # 128-бітний ключ AES

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

def handle_client(conn, addr):
    print(f"[+] Клієнт підключився: {addr}")
    print(f"[*] Алгоритм шифрування: AES-128-CBC")
    print(f"[*] Ключ (hex): {KEY.hex()}")
    print("-" * 50)

    def receiver():
        try:
            while True:
                msg = receive_message(conn)
                print(f"\n[Клієнт → зашифровано → розшифровано]: {msg}")
                print("Ваше повідомлення: ", end="", flush=True)
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            print("\n[!] Клієнт відключився.")
        except Exception as e:
            print(f"\n[!] Помилка: {e}")

    t = threading.Thread(target=receiver, daemon=True)
    t.start()

    try:
        while True:
            text = input("Ваше повідомлення: ")
            if text.lower() == "вихід":
                break
            send_message(conn, text)
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        conn.close()
        print("[*] З'єднання закрито.")


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)
    print("=" * 50)
    print("  ЗАШИФРОВАНИЙ ЧАТ — СЕРВЕР (AES-128-CBC)")
    print("=" * 50)
    print(f"[*] Слухаю на {HOST}:{PORT} ...")
    print("[*] Введіть 'вихід' для завершення\n")

    conn, addr = server.accept()
    handle_client(conn, addr)
    server.close()

if __name__ == "__main__":
    main()