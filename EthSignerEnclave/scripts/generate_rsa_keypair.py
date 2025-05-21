from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64

# 1. Генерация RSA-3072
key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=3072
)

# 2. Извлекаем n и e
pub = key.public_key().public_numbers()
n = pub.n
e = pub.e

modulus_bytes = n.to_bytes(384, 'big')
exponent_bytes = e.to_bytes(4, 'big')

modulus_hex = modulus_bytes.hex()
exponent_hex = exponent_bytes.hex()

# 3. Печатаем как строку CLI (для App)
print(f"{modulus_hex} {exponent_hex}")

# 4. (опционально) сохраняем приватный ключ
with open("rsa_private_key.pem", "wb") as f:
    f.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

# 5. (опционально) сохраняем публичный ключ
with open("rsa_public_key.pem", "wb") as f:
    f.write(key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

print("Keys saved: rsa_private_key.pem, rsa_public_key.pem")
