#include "Enclave_t.h"  // Автоматически сгенерирован sgx_edger8r
#include <secp256k1.h>
#include <secp256k1_recovery.h>

static secp256k1_context* ctx = nullptr;

extern "C" {

sgx_status_t ecall_generate_key(uint8_t* private_key, uint8_t* public_key) {
    if (!ctx) {
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }

    sgx_read_rand(private_key, 32);

    // Проверка валидности ключа
    if (!secp256k1_ec_seckey_verify(ctx, private_key)) {
        return SGX_ERROR_UNEXPECTED;
    }

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, private_key)) {
        return SGX_ERROR_UNEXPECTED;
    }

    size_t pubkey_len = 65;
    secp256k1_ec_pubkey_serialize(ctx, public_key, &pubkey_len, &pubkey, SECP256K1_EC_UNCOMPRESSED);

    return SGX_SUCCESS;
}

sgx_status_t ecall_sign_message(const uint8_t* msg_hash, uint8_t* signature) {
    if (!ctx) {
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }

    // Здесь нужно либо передать приватный ключ дополнительно, либо хранить его в enclave-памяти
    // Пока подпишем с тестовым ключом для простоты
    uint8_t private_key[32] = { /* !!! сюда нужно будет свой правильный ключ !!! */ };

    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_sign(ctx, &sig, msg_hash, private_key, NULL, NULL)) {
        return SGX_ERROR_UNEXPECTED;
    }

    secp256k1_ecdsa_signature_serialize_compact(ctx, signature, &sig);

    return SGX_SUCCESS;
}

} // extern "C"

