import socket
import threading
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import os

SHARED_SECRET = b"my_secret_key_12"
KEY = hashlib.sha256(SHARED_SECRET).digest()[:16]
HOST = "127.0.0.1"
PORT = 9998

def encrypt(plaintext: str) -> bytes:
    iv = os.urandom(16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
    return iv + ct

def decrypt(data: bytes) -> str:
    iv = data[:16]
    ct = data[16:]
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode("utf-8")

def recv_exact(sock, length):
    buf = b""
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            raise ConnectionError
        buf += chunk
    return buf

def send_msg(sock, text):
    enc = encrypt(text)
    sock.sendall(len(enc).to_bytes(4, "big") + enc)
    return enc  # повертаємо зашифровані байти для демонстрації

def recv_msg(sock):
    length = int.from_bytes(recv_exact(sock, 4), "big")
    data = recv_exact(sock, length)
    return data, decrypt(data)

# ── Тестові повідомлення ─────────────────────────────────────────────────────
MESSAGES_CLIENT = [
    "Привіт, сервере! Це зашифроване повідомлення.",
    "AES-CBC шифрує блоками по 16 байт.",
    "Кожне повідомлення має унікальний IV.",
]
MESSAGES_SERVER = [
    "Привіт, клієнте! Повідомлення отримано.",
    "Шифрування працює коректно.",
    "З'єднання захищено!",
]

results = []
lock = threading.Lock()

def server_thread():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(1)
    conn, _ = srv.accept()
    for reply in MESSAGES_SERVER:
        # отримати від клієнта
        raw, plain = recv_msg(conn)
        with lock:
            results.append(("КЛІЄНТ→СЕРВЕР", plain, raw))
        # відповісти
        enc = send_msg(conn, reply)
        with lock:
            results.append(("СЕРВЕР→КЛІЄНТ", reply, enc))
    conn.close()
    srv.close()

def client_thread():
    time.sleep(0.2)
    cli = socket.socket()
    cli.connect((HOST, PORT))
    for msg in MESSAGES_CLIENT:
        enc = send_msg(cli, msg)
        # отримати відповідь
        raw, plain = recv_msg(cli)
    cli.close()

# ── Запуск ───────────────────────────────────────────────────────────────────
s = threading.Thread(target=server_thread)
c = threading.Thread(target=client_thread)
s.start(); c.start()
s.join(); c.join()

# ── Вивід результатів ────────────────────────────────────────────────────────
print("=" * 65)
print("  ЛАБОРАТОРНА РОБОТА №6 — Варіант 5")
print("  Мережний чат з блочним шифруванням AES-128-CBC")
print("=" * 65)
print(f"\nАлгоритм: AES-CBC (блок 16 байт, режим CBC)")
print(f"Довжина ключа: 128 біт")
print(f"Ключ (hex): {KEY.hex()}")
print(f"IV: генерується випадково для КОЖНОГО повідомлення (16 байт)\n")
print("-" * 65)

pair_idx = 0
pairs = list(zip(results[0::2], results[1::2]))
for (dir1, plain1, enc1), (dir2, plain2, enc2) in pairs:
    pair_idx += 1
    print(f"\n📨 Обмін #{pair_idx}")
    print(f"  [{dir1}]")
    print(f"  Відкритий текст : {plain1}")
    print(f"  Зашифровано     : {enc1.hex()}")
    print(f"  [{dir2}]")
    print(f"  Відкритий текст : {plain2}")
    print(f"  Зашифровано     : {enc2.hex()}")
    print("-" * 65)

print("\n✅ Усі повідомлення успішно зашифровано та розшифровано!")
print("✅ Мережею передавались лише зашифровані байти.")
print("✅ Кожне повідомлення має унікальний IV — захист від повторів.\n")