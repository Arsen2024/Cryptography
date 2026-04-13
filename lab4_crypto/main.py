import random

# Перевірка простого числа
def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

# Обираємо p і a
p = 104729
a = 2

print("p is prime:", is_prime(p))

# Сторона A
x = random.randint(2, p-2)   # секрет A
X = pow(a, x, p)

# Сторона B
y = random.randint(2, p-2)   # секрет B
Y = pow(a, y, p)

# Обмін і обчислення ключа
k_A = pow(Y, x, p)
k_B = pow(X, y, p)

# Результати
print("\n--- Діффі-Хеллман ---")
print("p =", p)
print("a =", a)

print("\nA secret x =", x)
print("B secret y =", y)

print("\nX =", X)
print("Y =", Y)

print("\nKey A =", k_A)
print("Key B =", k_B)

print("\nKeys equal:", k_A == k_B)