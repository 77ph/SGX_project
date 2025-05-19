#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <stdlib.h>
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <sgx_trts.h>
#include <sgx_tcrypto.h>
#include <sgx_tseal.h>
#include <sgx_tprotected_fs.h>

#if defined(__cplusplus)
extern "C" {
#endif

// Глобальные переменные для SGX
extern void* g_global_data_sim;
extern void* g_global_data;
extern void* g_peak_heap_used;
extern void* g_peak_rsrv_mem_committed;



// Константы
#define MAX_POOL_SIZE 100  // Увеличиваем размер пула до 100 аккаунтов
#define ADDRESS_SIZE 20
#define INDEX_TABLE_CAPACITY 2048

// Структура для хранения данных аккаунта
typedef struct {
    uint8_t private_key[32];
    uint8_t public_key[65];
    uint8_t address[20];
    uint8_t hmac[32];
    uint32_t use_count;    // счетчик использований (подписей)
    bool is_initialized;
} Account;

typedef struct {
    Account account;
    uint8_t file_hmac[32];
} AccountFile;

// Структура для хранения аккаунта в пуле
typedef struct {
    Account account;
} PoolAccount;

// Структура для хранения пула аккаунтов
typedef struct {
    PoolAccount accounts[MAX_POOL_SIZE];
} AccountPool;

typedef struct {
    uint8_t address[ADDRESS_SIZE];  // ключ
    int index;                      // индекс в account_pool
    int is_occupied;                // 0 = пусто, 1 = занято
} AccountIndexEntry;

// Enclave initialization
sgx_status_t sgx_ecall_initialize();

// Функции для работы с аккаунтами
// int ecall_generate_account(void);  // Removed as it's now internal
// int ecall_save_account(const char* account_id);  // Removed as deprecated
// int ecall_load_account(const char* account_id);  // Removed as it's now internal
int ecall_load_account_to_pool(const char* account_id);
int ecall_unload_account_from_pool(const char* account_id);
int ecall_sign_with_pool_account(const char* account_id, const uint8_t* message, size_t message_len, uint8_t* signature, size_t signature_len);

// Структура для статистики байтов
typedef struct {
    uint8_t byte_counts[256];
    uint32_t total_bytes;
} ByteStatistics;

// Key rotation functions
int ecall_rotate_account_key(const char* account_id);
int ecall_check_key_rotation_status(const char* account_id, bool* needs_rotation);
int ecall_get_key_age(const char* account_id, uint64_t* key_age);

// Helper functions
void secure_memzero(void* ptr, size_t len);
double calculate_entropy(const uint8_t* data, size_t size);
bool is_strong_private_key(const uint8_t* private_key, size_t size);
sgx_status_t generate_secure_private_key(uint8_t* private_key, size_t size);
bool add_account_to_pool(const char* account_id, const Account& account);
void keccak_256(const uint8_t* input, size_t input_len, uint8_t* output);

int ecall_test_function(void);
// Removed as unused, functionality covered by ecall_generate_account_to_pool
// int ecall_generate_private_key(uint8_t* private_key, size_t private_key_size);

#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE_H_ */
