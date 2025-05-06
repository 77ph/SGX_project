#include "Enclave_t.h"  // Автоматически сгенерирован sgx_edger8r
#include <sgx_trts.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>

static secp256k1_context* ctx = nullptr;

// Определяем функции явно, без использования автоматически сгенерированных
extern "C" {

sgx_status_t ecall_generate_key(uint8_t* private_key, uint8_t* public_key) {
    // Просто заполняем буферы случайными данными для теста
    sgx_read_rand(private_key, 32);
    sgx_read_rand(public_key, 65);
    return SGX_SUCCESS;
}

sgx_status_t ecall_sign_message(const uint8_t* msg_hash, uint8_t* signature) {
    // Просто заполняем подпись случайными данными для теста
    sgx_read_rand(signature, 64);
    return SGX_SUCCESS;
}

} // extern "C"
