#include "Enclave.h"
#include "Enclave_t.h"  // Автоматически сгенерирован sgx_edger8r
#include <sgx_trts.h>
#include <sgx_tcrypto.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define ENCLAVE_BUFSIZ 2048

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
    return (int)strnlen(buf, ENCLAVE_BUFSIZ - 1) + 1;
}

// Простая функция для проверки работы энклава
void ecall_test_function(int* retval) {
    enclave_printf("Test function called\n");
    *retval = 42;
}

// Упрощенная версия генерации ключа
void ecall_generate_private_key(int* retval, uint8_t* private_key, size_t key_size) {
    enclave_printf("Starting key generation...\n");
    
    if (!private_key || key_size != 32) {
        enclave_printf("Invalid parameters: private_key=%p, key_size=%zu\n", (void*)private_key, key_size);
        *retval = -1;
        return;
    }

    // Use a local buffer first
    uint8_t temp_key[32] = {0};
    enclave_printf("Created temporary buffer\n");

    // Generate random data
    sgx_status_t status = sgx_read_rand(temp_key, sizeof(temp_key));
    if (status != SGX_SUCCESS) {
        enclave_printf("Failed to generate random data: %d\n", status);
        *retval = -1;
        return;
    }
    enclave_printf("Generated random data successfully\n");

    // Copy to output buffer
    memcpy(private_key, temp_key, sizeof(temp_key));
    enclave_printf("Copied data to output buffer\n");

    // Verify the copy
    if (memcmp(private_key, temp_key, sizeof(temp_key)) != 0) {
        enclave_printf("Data verification failed\n");
        *retval = -1;
        return;
    }
    enclave_printf("Data verification successful\n");

    enclave_printf("Key generation completed successfully\n");
    *retval = 0;
}

// Упрощенная версия подписи
void ecall_sign_transaction(int* retval, const uint8_t* transaction_hash, size_t hash_size,
                          uint8_t* signature, size_t sig_size) {
    if (!transaction_hash || !signature || hash_size != 32 || sig_size != 64) {
        *retval = -1;
        return;
    }

    // For demonstration, we'll just copy the hash to the signature
    // In a real implementation, this would use proper cryptographic signing
    memcpy(signature, transaction_hash, 32);
    memcpy(signature + 32, transaction_hash, 32);

    *retval = 0;
}
