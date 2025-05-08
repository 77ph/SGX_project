#include "Enclave.h"
#include "Enclave_t.h"  // Автоматически сгенерирован sgx_edger8r
#include <sgx_trts.h>
#include <sgx_tcrypto.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <secp256k1.h>

#define ENCLAVE_BUFSIZ 1024

/* 
 * enclave_printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int enclave_printf(const char* fmt, ...)
{
    char buf[ENCLAVE_BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, ENCLAVE_BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print(buf);
    return 0;
}

#ifdef __cplusplus
extern "C" {
#endif

// Простая функция для проверки работы энклава
int ecall_test_function(void) {
    enclave_printf("Hello from enclave!\n");
    return 42;
}

// Упрощенная версия генерации ключа
int ecall_generate_private_key(uint8_t* private_key, size_t private_key_size) {
    if (private_key == NULL || private_key_size != 32) {
        return -1;
    }

    // Generate random private key
    if (sgx_read_rand(private_key, 32) != SGX_SUCCESS) {
        return -1;
    }

    // Create secp256k1 context
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (ctx == NULL) {
        return -1;
    }

    // Verify the private key
    if (!secp256k1_ec_seckey_verify(ctx, private_key)) {
        secp256k1_context_destroy(ctx);
        return -1;
    }

    secp256k1_context_destroy(ctx);
    return 0;
}

// Упрощенная версия подписи
int ecall_sign_transaction(const uint8_t* tx_hash, size_t tx_hash_size,
                         const uint8_t* private_key, size_t private_key_size,
                         uint8_t* signature, size_t signature_size) {
    if (tx_hash == NULL || tx_hash_size != 32 ||
        private_key == NULL || private_key_size != 32 ||
        signature == NULL || signature_size != 64) {
        enclave_printf("Error: Invalid input parameters\n");
        return -1;
    }

    // Create secp256k1 context
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (ctx == NULL) {
        enclave_printf("Error: Failed to create secp256k1 context\n");
        return -1;
    }

    // Verify the private key
    if (!secp256k1_ec_seckey_verify(ctx, private_key)) {
        enclave_printf("Error: Invalid private key\n");
        secp256k1_context_destroy(ctx);
        return -1;
    }

    // Create signature
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_sign(ctx, &sig, tx_hash, private_key, NULL, NULL)) {
        enclave_printf("Error: Failed to create signature\n");
        secp256k1_context_destroy(ctx);
        return -1;
    }

    // Serialize signature
    if (!secp256k1_ecdsa_signature_serialize_compact(ctx, signature, &sig)) {
        enclave_printf("Error: Failed to serialize signature\n");
        secp256k1_context_destroy(ctx);
        return -1;
    }

    enclave_printf("Transaction signed successfully\n");
    secp256k1_context_destroy(ctx);
    return 0;
}

#ifdef __cplusplus
}
#endif
