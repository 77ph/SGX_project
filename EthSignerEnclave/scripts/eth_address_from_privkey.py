from eth_keys import keys
from eth_utils import to_checksum_address

# Пример приватного ключа в hex (32 байта / 64 hex-символа)
# Можно заменить на свой
hex_priv_key = "b71c71a69c804f6b50fa52eecb91b84f0cd7fc938d4ee5a7b2fe9b8eb2e5e82e"

# Преобразуем в объект ключа
priv_key = keys.PrivateKey(bytes.fromhex(hex_priv_key))

# Получим публичный ключ
pub_key = priv_key.public_key

# Получим адрес
eth_address = pub_key.to_checksum_address()

print(f"Private key:  {hex_priv_key}")
print(f"Public key:   {pub_key}")
print(f"Ethereum address: {eth_address}")

