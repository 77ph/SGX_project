#include "Enclave_t.h"  // Автоматически сгенерирован sgx_edger8r
#include <sgx_trts.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <string.h>

static secp256k1_context* ctx = nullptr;
static uint8_t current_private_key[32] = {0};
static bool key_generated = false;

// Инициализация контекста secp256k1
static bool init_secp256k1() {
    if (ctx == nullptr) {
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
        return ctx != nullptr;
    }
    return true;
}

// Генерация приватного ключа с проверкой на валидность
static bool generate_valid_private_key(uint8_t* private_key) {
    bool valid = false;
    while (!valid) {
        // Генерация случайного приватного ключа
        if (sgx_read_rand(private_key, 32) != SGX_SUCCESS) {
            return false;
        }

        // Проверка, что ключ не равен нулю
        bool is_zero = true;
        for (int i = 0; i < 32; i++) {
            if (private_key[i] != 0) {
                is_zero = false;
                break;
            }
        }
        if (is_zero) continue;

        // Проверка, что ключ меньше порядка кривой
        const uint8_t curve_order[] = {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
            0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
            0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
        };

        // Сравнение ключа с порядком кривой
        int cmp = 0;
        for (int i = 0; i < 32; i++) {
            if (private_key[i] < curve_order[i]) {
                cmp = -1;
                break;
            } else if (private_key[i] > curve_order[i]) {
                cmp = 1;
                break;
            }
        }
        if (cmp < 0) {
            valid = true;
        }
    }
    return true;
}

// Определяем функции явно, без использования автоматически сгенерированных
extern "C" {

sgx_status_t ecall_generate_private_key() {
    if (!init_secp256k1()) {
        return SGX_ERROR_UNEXPECTED;
    }

    // Генерация валидного приватного ключа
    if (!generate_valid_private_key(current_private_key)) {
        return SGX_ERROR_UNEXPECTED;
    }

    key_generated = true;
    return SGX_SUCCESS;
}

sgx_status_t ecall_sign_transaction(uint64_t nonce,
                                  uint64_t gas_price,
                                  uint64_t gas_limit,
                                  uint8_t* to,
                                  uint64_t value,
                                  uint8_t* data,
                                  size_t data_len,
                                  uint8_t* signature) {
    if (!init_secp256k1() || !key_generated) {
        return SGX_ERROR_UNEXPECTED;
    }

    // Создание хеша транзакции (здесь нужно реализовать RLP кодирование и Keccak-256)
    // TODO: Реализовать RLP кодирование и хеширование
    uint8_t tx_hash[32] = {0};  // Временный заглушка

    // Создание подписи
    secp256k1_ecdsa_recoverable_signature sig;
    if (!secp256k1_ecdsa_sign_recoverable(ctx, &sig, tx_hash, current_private_key, NULL, NULL)) {
        return SGX_ERROR_UNEXPECTED;
    }

    // Сериализация подписи
    int recid;
    if (!secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, signature, &recid, &sig)) {
        return SGX_ERROR_UNEXPECTED;
    }

    return SGX_SUCCESS;
}

} // extern "C"
