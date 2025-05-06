#include <iostream>
#include <iomanip>
#include <cstring>
#include <vector>
#include <unistd.h>  // для access() и F_OK
#include <sgx_urts.h>
#include "Enclave_u.h"
#include "sgx_utils/sgx_utils.h"

sgx_enclave_id_t global_eid = 0;

// Функция для вывода данных в hex формате
void print_hex(const uint8_t* data, size_t len, const char* prefix = "") {
    std::cout << prefix;
    for (size_t i = 0; i < len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    std::cout << std::dec << std::endl;
}

// Функция для создания тестового адреса получателя
void create_test_address(uint8_t* to) {
    // Создаем тестовый адрес (20 байт)
    for (int i = 0; i < 20; i++) {
        to[i] = i + 1;  // Простой паттерн для тестирования
    }
}

int main() {
    try {
        std::cout << "Starting Ethereum Transaction Signer Enclave Test" << std::endl;
        std::cout << "=============================================" << std::endl;

        // Проверяем наличие файла энклава
        if (access("enclave.signed.so", F_OK) == -1) {
            std::cerr << "Error: enclave.signed.so not found" << std::endl;
            return 1;
        }

        // Проверяем права доступа к файлу энклава
        if (access("enclave.signed.so", R_OK) == -1) {
            std::cerr << "Error: no read permission for enclave.signed.so" << std::endl;
            return 1;
        }

        sgx_status_t ret = SGX_ERROR_UNEXPECTED;
        sgx_status_t ecall_status = SGX_ERROR_UNEXPECTED;

        // Создание enclave
        std::cout << "\nCreating enclave..." << std::endl;
        
        // Инициализация энклава с использованием утилит
        if (initialize_enclave(&global_eid, "enclave.token", "enclave.signed.so") < 0) {
            std::cerr << "Failed to initialize enclave" << std::endl;
            return 1;
        }

        if (global_eid == 0) {
            std::cerr << "Enclave ID is 0 after initialization" << std::endl;
            return 1;
        }

        std::cout << "Enclave created successfully with ID: " << std::hex << global_eid << std::dec << std::endl;

        // Генерация приватного ключа
        std::cout << "\nGenerating private key..." << std::endl;
        ret = ecall_generate_private_key(global_eid, &ecall_status);
        if (!is_ecall_successful(ret, "Failed to generate private key", ecall_status)) {
            sgx_destroy_enclave(global_eid);
            return 1;
        }
        std::cout << "Private key generated successfully" << std::endl;

        // Подготовка тестовой транзакции
        std::cout << "\nPreparing test transaction..." << std::endl;
        uint64_t nonce = 1;
        uint64_t gas_price = 20000000000;  // 20 Gwei
        uint64_t gas_limit = 21000;
        uint8_t to[20] = {0};
        uint64_t value = 1000000000000000000;  // 1 ETH
        uint8_t* data = nullptr;
        size_t data_len = 0;
        uint8_t signature[65] = {0};

        // Создаем тестовый адрес получателя
        create_test_address(to);
        std::cout << "Transaction parameters:" << std::endl;
        std::cout << "Nonce: " << nonce << std::endl;
        std::cout << "Gas Price: " << gas_price << " wei" << std::endl;
        std::cout << "Gas Limit: " << gas_limit << std::endl;
        std::cout << "Value: " << value << " wei" << std::endl;
        std::cout << "To address: ";
        print_hex(to, 20);

        // Подпись транзакции
        std::cout << "\nSigning transaction..." << std::endl;
        ret = ecall_sign_transaction(global_eid, &ecall_status,
                                   nonce, gas_price, gas_limit,
                                   to, value, data, data_len,
                                   signature);
        if (!is_ecall_successful(ret, "Failed to sign transaction", ecall_status)) {
            sgx_destroy_enclave(global_eid);
            return 1;
        }

        // Вывод подписи
        std::cout << "\nTransaction signed successfully" << std::endl;
        std::cout << "Signature (65 bytes):" << std::endl;
        print_hex(signature, 65, "0x");

        // Разбор подписи на компоненты
        std::cout << "\nSignature components:" << std::endl;
        std::cout << "r: 0x";
        print_hex(signature, 32);
        std::cout << "s: 0x";
        print_hex(signature + 32, 32);
        std::cout << "v: 0x";
        print_hex(signature + 64, 1);

        // Очистка
        std::cout << "\nCleaning up..." << std::endl;
        sgx_destroy_enclave(global_eid);
        std::cout << "Enclave destroyed" << std::endl;

        std::cout << "\nTest completed successfully" << std::endl;
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Exception caught: " << e.what() << std::endl;
        if (global_eid != 0) {
            sgx_destroy_enclave(global_eid);
        }
        return 1;
    } catch (...) {
        std::cerr << "Unknown exception caught" << std::endl;
        if (global_eid != 0) {
            sgx_destroy_enclave(global_eid);
        }
        return 1;
    }
}
