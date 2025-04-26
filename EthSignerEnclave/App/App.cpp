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
    sgx_status_t ecall_status = SGX_ERROR_UNEXPECTED; // <=== добавляем такую переменную

    // Создание enclave
    ret = sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        std::cerr << "Failed to create enclave: error code " << std::hex << ret << std::endl;
        return 1;
    }

    uint8_t private_key[32] = {0};
    uint8_t public_key[65] = {0};

    // Генерация ключей
    ret = ecall_generate_key(global_eid, &ecall_status, private_key, public_key);  // <=== передаем &ecall_status
    if (ret != SGX_SUCCESS || ecall_status != SGX_SUCCESS) {
        std::cerr << "Failed to generate key: error code " << std::hex << ret << " enclave status " << ecall_status << std::endl;
        return 1;
    }

    std::cout << "Private key:" << std::endl;
    print_hex(private_key, 32);
    std::cout << "Public key:" << std::endl;
    print_hex(public_key, 65);

    // Генерация тестового сообщения для подписи
    uint8_t message_hash[32] = {0};
    for (int i = 0; i < 32; i++) {
        message_hash[i] = i;
    }

    uint8_t signature[64] = {0};

    // Подпись сообщения
    ret = ecall_sign_message(global_eid, &ecall_status, message_hash, signature);  // <=== тоже передаем &ecall_status
    if (ret != SGX_SUCCESS || ecall_status != SGX_SUCCESS) {
        std::cerr << "Failed to sign message: error code " << std::hex << ret << " enclave status " << ecall_status << std::endl;
        return 1;
    }

    std::cout << "Signature:" << std::endl;
    print_hex(signature, 64);

    sgx_destroy_enclave(global_eid);
    return 0;
}

