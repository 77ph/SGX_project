#include <iostream>
#include <iomanip>
#include <cstring>
#include <sgx_urts.h>
#include "Enclave_u.h"

sgx_enclave_id_t global_eid = 0;

void print_hex(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    std::cout << std::dec << std::endl;
}

int main() {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    sgx_status_t ecall_status = SGX_ERROR_UNEXPECTED;

    // Создание enclave
    ret = sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        std::cerr << "Failed to create enclave: error code " << std::hex << ret << std::endl;
        return 1;
    }

    // Генерация приватного ключа
    ret = ecall_generate_private_key(global_eid, &ecall_status);
    if (ret != SGX_SUCCESS || ecall_status != SGX_SUCCESS) {
        std::cerr << "Failed to generate private key: error code " << std::hex << ret << " enclave status " << ecall_status << std::endl;
        return 1;
    }

    // Подготовка тестовой транзакции
    uint64_t nonce = 1;
    uint64_t gas_price = 20000000000;  // 20 Gwei
    uint64_t gas_limit = 21000;
    uint8_t to[20] = {0};  // Тестовый адрес получателя
    uint64_t value = 1000000000000000000;  // 1 ETH
    uint8_t* data = nullptr;  // Пустые данные
    size_t data_len = 0;
    uint8_t signature[65] = {0};  // Подпись (r, s, v)

    // Подпись транзакции
    ret = ecall_sign_transaction(global_eid, &ecall_status,
                               nonce, gas_price, gas_limit,
                               to, value, data, data_len,
                               signature);
    if (ret != SGX_SUCCESS || ecall_status != SGX_SUCCESS) {
        std::cerr << "Failed to sign transaction: error code " << std::hex << ret << " enclave status " << ecall_status << std::endl;
        return 1;
    }

    std::cout << "Transaction signature:" << std::endl;
    print_hex(signature, 65);

    sgx_destroy_enclave(global_eid);
    return 0;
}
