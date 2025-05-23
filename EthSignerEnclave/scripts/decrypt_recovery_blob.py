from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from eth_keys import keys
import sys
import os

# 📥 Аргументы
if len(sys.argv) != 3:
    print("Usage: python3 decrypt_recovery_blob.py <ethereum_address> <rsa_private_key.pem>")
    sys.exit(1)

address = sys.argv[1].lower()
if not address.startswith("0x") or len(address) != 42:
    print("Invalid Ethereum address format.")
    sys.exit(1)

# 📁 Пути
recovery_path = os.path.join("accounts", f"{address}.account.recovery")
privkey_path = sys.argv[2]

# 🔐 Загрузка приватного ключа RSA
with open(privkey_path, "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# 📦 Загрузка зашифрованного recovery blob
with open(recovery_path, "rb") as f:
    encrypted_blob = f.read()

# Проверяем размер
key_size = private_key.key_size // 8
modulus_size = len(encrypted_blob)  # BearSSL использует фактический размер модуля
print(f"RSA key size: {key_size} bytes")
print(f"Modulus size: {modulus_size} bytes")
print(f"Encrypted blob size: {len(encrypted_blob)} bytes")

# Проверяем, что размер зашифрованных данных не превышает размер ключа
if len(encrypted_blob) > key_size:
    print("Error: Ciphertext length exceeds key size.")
    sys.exit(1)

# 🔓 Расшифровка с OAEP (совместимо с BearSSL)
try:
    # Используем точный размер модуля без дополнения
    decrypted = private_key.decrypt(
        encrypted_blob,  # Используем данные как есть, без дополнения
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Используем SHA-256 как в BearSSL
            algorithm=hashes.SHA256(),  # Используем SHA-256 как в BearSSL
            label=None  # BearSSL использует пустую метку
        )
    )
    print(f"Decrypted data size: {len(decrypted)} bytes")
    print(f"Decrypted data (hex): {decrypted.hex()}")
except Exception as e:
    print(f"Decryption failed: {str(e)}")
    sys.exit(1)

# 📤 Разбор ключей
if len(decrypted) < 97:
    print(f"Error: Decrypted data too short ({len(decrypted)} bytes)")
    sys.exit(1)

private_key_bytes = decrypted[:32]
public_key_bytes = decrypted[32:97]

eth_priv = keys.PrivateKey(private_key_bytes)
eth_address = eth_priv.public_key.to_checksum_address()

print("\nRecovery successful")
print("Private key:  ", private_key_bytes.hex())
print("Public key:   ", public_key_bytes.hex())
print("Ethereum addr:", eth_address)

if eth_address.lower() != address:
    print("Warning: recovered address does NOT match input!")
else:
    print("Address matches")
