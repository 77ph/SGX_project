from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from eth_keys import keys
from eth_utils import to_checksum_address
import sys
import os

# 📥 Аргументы
if len(sys.argv) != 2:
    print("Usage: python3 decrypt_recovery_blob.py <ethereum_address>")
    sys.exit(1)

address = sys.argv[1].lower()
if not address.startswith("0x") or len(address) != 42:
    print("Invalid Ethereum address format.")
    sys.exit(1)

# 📁 Пути
recovery_path = os.path.join("accounts", f"{address}.account.recovery")
privkey_path = "rsa_private_key.pem"

# 🔐 Загрузка приватного ключа RSA
with open(privkey_path, "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# 📦 Загрузка зашифрованного recovery blob
with open(recovery_path, "rb") as f:
    encrypted_blob = f.read()

# Получаем размер ключа
key_size = private_key.key_size // 8
print(f"RSA key size: {key_size} bytes")
print(f"Encrypted blob size: {len(encrypted_blob)} bytes")

# Проверяем, что зашифрованные данные не превышают размер ключа
if len(encrypted_blob) > key_size:
    print(f"Error: Encrypted data size ({len(encrypted_blob)}) exceeds key size ({key_size})")
    sys.exit(1)

# 🔓 Расшифровка с PKCS#1 v1.5 padding
try:
    # Используем PKCS#1 v1.5 padding без дополнительных параметров
    decrypted = private_key.decrypt(
        encrypted_blob,
        padding.PKCS1v15()
    )
    print(f"Decrypted data size: {len(decrypted)} bytes")
    print(f"Decrypted data (hex): {decrypted.hex()}")
except Exception as e:
    print(f"Decryption failed: {str(e)}")
    sys.exit(1)

# 📤 Разбор: privkey (32), pubkey (65)
if len(decrypted) < 97:  # 32 + 65
    print(f"Error: Decrypted data too short ({len(decrypted)} bytes)")
    sys.exit(1)

# Берем первые 97 байт (32 + 65)
private_key_bytes = decrypted[:32]
public_key_bytes = decrypted[32:97]

eth_priv = keys.PrivateKey(private_key_bytes)
eth_pub = eth_priv.public_key
eth_address = eth_pub.to_checksum_address()

print("\nRecovery successful")
print("Private key:  ", private_key_bytes.hex())
print("Public key:   ", public_key_bytes.hex())
print("Ethereum addr:", eth_address)

# 🧪 Сравнение с именем файла
if eth_address.lower() != address:
    print("Warning: recovered address does NOT match input!")
else:
    print("Address matches")
