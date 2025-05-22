#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "bearssl.h"
#include "bearssl_rsa.h"

// Простой PRNG для тестирования
static void test_prng_generate(const br_prng_class** ctx, void* out, size_t len) {
    (void)ctx;  // unused
    // Для тестирования используем фиксированную последовательность
    static uint8_t counter = 0;
    uint8_t* p = (uint8_t*)out;
    for (size_t i = 0; i < len; i++) {
        p[i] = counter++;
    }
}

static const br_prng_class test_prng_class = {
    .context_size = 0,
    .init = NULL,
    .generate = test_prng_generate
};

// Функция для конвертации hex строки в байты
static size_t hex_to_bytes(const char* hex_str, uint8_t* out_bytes, size_t max_out_len) {
    if (!hex_str || !out_bytes || max_out_len == 0) {
        return 0;
    }

    size_t hex_len = strlen(hex_str);
    if (hex_len < 2) {
        printf("Hex string too short\n");
        return 0;
    }

    // Skip 0x prefix if present
    const char* hex_start = hex_str;
    if (hex_str[0] == '0' && hex_str[1] == 'x') {
        hex_start += 2;
        hex_len -= 2;
    }

    if (hex_len % 2 != 0) {
        printf("Invalid hex string length\n");
        return 0;
    }

    size_t bytes_len = hex_len / 2;
    if (bytes_len > max_out_len) {
        printf("Output buffer too small\n");
        return 0;
    }

    for (size_t i = 0; i < bytes_len; i++) {
        char byte_str[3] = {hex_start[i*2], hex_start[i*2+1], 0};
        char* end;
        out_bytes[i] = (uint8_t)strtol(byte_str, &end, 16);
        if (*end != 0) {
            printf("Invalid hex character at position %zu\n", i*2);
            return 0;
        }
    }

    return bytes_len;
}

// Функция для RSA шифрования
static int rsa_encrypt(const uint8_t* data, size_t data_len,
                      const uint8_t* modulus, size_t modulus_len,
                      const uint8_t* exponent, size_t exponent_len,
                      uint8_t* encrypted_data, size_t* encrypted_data_len) {
    if (!data || !modulus || !exponent || !encrypted_data || !encrypted_data_len) {
        return -1;
    }

    if (modulus_len != 384 || exponent_len == 0) {
        printf("Invalid RSA modulus (%zu) or exponent (%zu)\n", modulus_len, exponent_len);
        return -1;
    }

    // Debug: Print data before encryption
    printf("Debug: Data before encryption:\n");
    printf("Data: ");
    for (size_t i = 0; i < data_len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");

    // Create non-const copy of data
    uint8_t data_copy[318];
    memcpy(data_copy, data, data_len);
    memset(data_copy + data_len, 0, sizeof(data_copy) - data_len);  // Заполняем оставшиеся байты нулями

    // Initialize BearSSL RSA public key
    br_rsa_public_key pk;
    pk.n = (unsigned char*)modulus;
    pk.nlen = (uint32_t)modulus_len;
    pk.e = (unsigned char*)exponent;
    pk.elen = (uint32_t)exponent_len;

    printf("Debug: RSA key lengths - modulus: %zu, exponent: %zu\n", modulus_len, exponent_len);
    printf("Debug: RSA key values:\n");
    printf("Modulus: ");
    for (size_t i = 0; i < modulus_len; i++) {
        printf("%02x", pk.n[i]);
    }
    printf("\nExponent: ");
    for (size_t i = 0; i < exponent_len; i++) {
        printf("%02x", pk.e[i]);
    }
    printf("\n");

    // Encrypt with RSA OAEP
    const br_prng_class* prng = &test_prng_class;
    printf("Debug: Starting RSA OAEP encryption...\n");
    printf("Debug: Data length: %zu\n", data_len);
    printf("Debug: Output buffer size: %zu\n", *encrypted_data_len);
    
    // Проверяем, что модуль начинается с ненулевого байта
    printf("Debug: First byte of modulus: %02x\n", pk.n[0]);
    printf("Debug: Last byte of modulus: %02x\n", pk.n[pk.nlen-1]);
    
    // Проверяем экспоненту
    printf("Debug: First byte of exponent: %02x\n", pk.e[0]);
    printf("Debug: Last byte of exponent: %02x\n", pk.e[pk.elen-1]);
    
    // Проверяем условия OAEP padding
    size_t hlen = br_sha256_SIZE;  // 32 bytes for SHA-256
    printf("Debug: Hash length (hlen): %zu\n", hlen);
    printf("Debug: Minimum modulus length: %zu\n", (hlen << 1) + 2);
    printf("Debug: Maximum source length: %zu\n", pk.nlen - (hlen << 1) - 2);
    
    // Проверяем значения для OAEP padding
    printf("Debug: OAEP padding values:\n");
    printf("k (modulus length): %zu\n", pk.nlen);
    printf("hlen (hash length): %zu\n", hlen);
    printf("src_len (source length): %zu\n", data_len);
    printf("dst_max_len (output buffer size): %zu\n", *encrypted_data_len);
    printf("Minimum k: %zu\n", (hlen << 1) + 2);
    printf("Maximum src_len: %zu\n", pk.nlen - (hlen << 1) - 2);
    
    // Проверяем значения для br_rsa_i31_public
    printf("Debug: RSA public key values:\n");
    printf("Modulus length: %zu\n", pk.nlen);
    printf("Exponent length: %zu\n", pk.elen);
    printf("First byte of modulus: %02x\n", pk.n[0]);
    printf("Last byte of modulus: %02x\n", pk.n[pk.nlen-1]);
    printf("First byte of exponent: %02x\n", pk.e[0]);
    printf("Last byte of exponent: %02x\n", pk.e[pk.elen-1]);
    
    size_t out_len = br_rsa_i31_oaep_encrypt(
        &prng,             // Use our test PRNG class
        &br_sha256_vtable, // Hash function for OAEP
        NULL,              // Label
        0,                 // Label length
        &pk,               // RSA public key
        encrypted_data,    // Output buffer (dst)
        *encrypted_data_len, // Output buffer size (dst_max_len)
        data_copy,         // Data to encrypt (src)
        sizeof(data_copy)  // Data length (src_len)
    );

    if (out_len == 0) {
        printf("Debug: BearSSL RSA encryption failed with error code: %zu\n", out_len);
        return -1;
    }

    // Debug: Print encrypted data
    printf("Debug: Encrypted data:\n");
    for (size_t i = 0; i < out_len; i++) {
        printf("%02x", encrypted_data[i]);
    }
    printf("\n");

    *encrypted_data_len = out_len;
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: %s <modulus_hex> <exponent_hex>\n", argv[0]);
        return 1;
    }

    // Decode hex strings into byte arrays
    uint8_t modulus[384] = {0};
    uint8_t exponent[4] = {0};
    size_t modulus_len = hex_to_bytes(argv[1], modulus, sizeof(modulus));
    size_t exponent_len = hex_to_bytes(argv[2], exponent, sizeof(exponent));
    if (modulus_len == 0 || exponent_len == 0) {
        printf("Failed to parse hex modulus or exponent\n");
        return 1;
    }

    // Убираем ведущие нули из модуля
    while (modulus_len > 1 && modulus[0] == 0x00) {
        memmove(modulus, modulus + 1, --modulus_len);
    }

    // Убираем завершающие нули из модуля
    while (modulus_len > 1 && modulus[modulus_len - 1] == 0x00) {
        --modulus_len;
    }

    // Если модуль короче 384 байт, дополняем нулями справа
    if (modulus_len < 384) {
        memset(modulus + modulus_len, 0, 384 - modulus_len);
        modulus_len = 384;
    }

    // Убираем ведущие нули из экспоненты
    while (exponent_len > 1 && exponent[0] == 0x00) {
        memmove(exponent, exponent + 1, --exponent_len);
    }

    printf("Debug: RSA key prepared:\n");
    printf("Modulus (hex): ");
    for (size_t i = 0; i < modulus_len; i++) {
        printf("%02x", modulus[i]);
    }
    printf("\nExponent (hex): ");
    for (size_t i = 0; i < exponent_len; i++) {
        printf("%02x", exponent[i]);
    }
    printf("\n");

    // Test data (318 bytes: 32 bytes private key + 65 bytes public key + padding)
    uint8_t test_data[318] = {0};
    for (int i = 0; i < 97; i++) {
        test_data[i] = i;
    }
    // Остальные байты заполняем нулями

    // Encrypt with RSA
    uint8_t encrypted[384] = {0};
    size_t encrypted_len = sizeof(encrypted);
    
    int result = rsa_encrypt(
        test_data,
        sizeof(test_data),  // Используем 318 байт вместо 384
        modulus,
        modulus_len,
        exponent,
        exponent_len,
        encrypted,
        &encrypted_len
    );

    if (result != 0) {
        printf("RSA encryption failed\n");
        return 1;
    }

    printf("RSA encryption successful\n");
    return 0;
} 