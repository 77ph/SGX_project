#include <stdio.h>
#include <string.h>
#include <sgx_tcrypto.h>
#include <sgx_trts.h>
#include <sgx_tseal.h>
#include <sgx_utils.h>
#include "Enclave_t.h"
#include "Enclave.h"
#include "secp256k1.h"
#include "secp256k1_ecdh.h"
#include "secp256k1_recovery.h"
#include <stdarg.h>
#include <time.h>
#include <math.h>  // Добавляем для log2
#include "sha3.h"  // Добавляем для Keccak-256
#include "bearssl.h"
#include "bearssl_rsa.h"

#define ENCLAVE_BUFSIZ 1024
// Logging levels
#define LOG_ERROR 0
#define LOG_WARNING 1
#define LOG_INFO  2
#define LOG_DEBUG 3
// Temporary debug flag
#define SGX_DEBUG 1

#if defined(SGX_DEBUG) && SGX_DEBUG == 1
    #define LOG_DEBUG_MACRO(...) log_message(LOG_DEBUG, __VA_ARGS__)
    #define LOG_INFO_MACRO(...)  log_message(LOG_INFO,  __VA_ARGS__)
    #define LOG_WARN_MACRO(...)  log_message(LOG_WARNING,  __VA_ARGS__)
    #define LOG_ERROR_MACRO(...) log_message(LOG_ERROR, __VA_ARGS__)
#else
    #define LOG_DEBUG_MACRO(...) do {} while(0)
    #define LOG_INFO_MACRO(...)  do {} while(0)
    #define LOG_WARN_MACRO(...)  do {} while(0)
    #define LOG_ERROR_MACRO(...) log_message(LOG_ERROR, __VA_ARGS__)
#endif

// Test result structure
typedef struct {
    const char* test_name;
    int passed;
    const char* error_message;
} test_result_t;

// Test suite structure
typedef struct {
    const char* suite_name;
    test_result_t* results;
    int result_count;
    int passed_count;
} test_suite_t;

// Структура для recovery файла
typedef struct {
    uint8_t version;
    uint8_t private_key[32];  // Зашифровано RSA
    uint8_t public_key[65];   // Зашифровано RSA
    uint8_t hmac[32];         // HMAC для верификации
} recovery_file_t;

#ifdef __cplusplus
extern "C" {
#endif

// Default log level
static int g_log_level = LOG_DEBUG;
// Global pool instance
static AccountPool account_pool = {0};

static AccountIndexEntry account_index_table[INDEX_TABLE_CAPACITY] = {0};

// Простая реализация strcat без использования strlen
static char* my_strcat(char* dest, const char* src) {
    // Find end of dest string manually
    char* ptr = dest;
    while (*ptr != '\0') {
        ptr++;
    }
    
    // Copy src to end of dest, ensuring we don't overflow
    while (*src != '\0' && (ptr - dest) < 4299) { // Leave room for null terminator
        *ptr++ = *src++;
    }
    *ptr = '\0';
    return dest;
}

// Logging function
static void log_message(int level, const char* format, ...) {
    if (level > g_log_level) return;
    
    va_list args;
    va_start(args, format);
    char buf[ENCLAVE_BUFSIZ] = { '\0' };
    vsnprintf(buf, ENCLAVE_BUFSIZ, format, args);
    va_end(args);
    ocall_print(buf);
}

// Initialize account pool
static bool initialize_account_pool() {
    LOG_INFO_MACRO("Initializing account pool...\n");
    
    // Initialize all slots as free
    for (int i = 0; i < MAX_POOL_SIZE; i++) {
        account_pool.accounts[i].account.use_count = 0;
        secure_memzero(&account_pool.accounts[i].account, sizeof(Account));
    }
    
    LOG_DEBUG_MACRO("Account pool initialized with %d slots\n", MAX_POOL_SIZE);
    return true;
}

// Helper function to securely zero memory
void secure_memzero(void* ptr, size_t len) {
    volatile unsigned char* p = (volatile unsigned char*)ptr;
    while (len--) {
        *p++ = 0;
    }
}

static uint32_t address_hash(const uint8_t* address) {
    uint32_t hash = 5381;
    for (int i = 0; i < ADDRESS_SIZE; i++) {
        hash = ((hash << 5) + hash) + address[i];  // hash * 33 + address[i]
    }
    return hash % INDEX_TABLE_CAPACITY;
}

bool account_index_insert(const uint8_t* address, int index) {
    uint32_t hash = address_hash(address);
    
    for (int i = 0; i < INDEX_TABLE_CAPACITY; i++) {
        uint32_t pos = (hash + i) % INDEX_TABLE_CAPACITY;
        
        if (account_index_table[pos].is_occupied == SLOT_EMPTY || 
            account_index_table[pos].is_occupied == SLOT_DELETED) {
            memcpy(account_index_table[pos].address, address, ADDRESS_SIZE);
            account_index_table[pos].index = index;
            account_index_table[pos].is_occupied = SLOT_OCCUPIED;
            return true;
        }
    }
    return false;
}

bool account_index_find(const uint8_t* address, int* out_index) {
    uint32_t hash = address_hash(address);
    
    for (int i = 0; i < INDEX_TABLE_CAPACITY; i++) {
        uint32_t pos = (hash + i) % INDEX_TABLE_CAPACITY;
        if (account_index_table[pos].is_occupied == SLOT_EMPTY) {
            return false;
        }
        if (account_index_table[pos].is_occupied == SLOT_OCCUPIED && 
            memcmp(account_index_table[pos].address, address, ADDRESS_SIZE) == 0) {
            *out_index = account_index_table[pos].index;
            return true;
        }
    }
    return false;
}

bool account_index_remove(const uint8_t* address) {
    uint32_t hash = address_hash(address);
    for (int i = 0; i < INDEX_TABLE_CAPACITY; i++) {
        uint32_t pos = (hash + i) % INDEX_TABLE_CAPACITY;
        if (account_index_table[pos].is_occupied == SLOT_EMPTY) {
            return false;
        }
        if (account_index_table[pos].is_occupied == SLOT_OCCUPIED && 
            memcmp(account_index_table[pos].address, address, ADDRESS_SIZE) == 0) {
            // TODO: Consider implementing rehashing if performance degrades due to too many SLOT_DELETED entries
            // This would involve moving entries to fill gaps and reduce search time
            account_index_table[pos].is_occupied = SLOT_DELETED;
            return true;
        }
    }
    return false;
}

void account_index_clear() {
    for (int i = 0; i < INDEX_TABLE_CAPACITY; i++) {
        account_index_table[i].is_occupied = SLOT_EMPTY;
    }
}

// Helper function to convert hex string to bytes
static size_t hex_to_bytes(const char* hex_str, uint8_t* out_bytes, size_t max_out_len) {
    LOG_INFO_MACRO("[Enclave] hex_to_bytes: Starting conversion\n");
    LOG_INFO_MACRO("[Enclave] hex_to_bytes: Input hex string: %s\n", hex_str);
    LOG_INFO_MACRO("[Enclave] hex_to_bytes: Max output length: %zu\n", max_out_len);
    
    if (!hex_str || !out_bytes || max_out_len == 0) {
        LOG_ERROR_MACRO("[Enclave] hex_to_bytes: Invalid parameters\n");
        return 0;
    }

    size_t hex_len = strlen(hex_str);
    LOG_INFO_MACRO("[Enclave] hex_to_bytes: Input length: %zu\n", hex_len);

    if (hex_len < 2) {
        LOG_ERROR_MACRO("[Enclave] hex_to_bytes: Hex string too short\n");
        return 0;
    }

    // Skip 0x prefix if present
    const char* hex_start = hex_str;
    if (hex_str[0] == '0' && hex_str[1] == 'x') {
        hex_start += 2;
        hex_len -= 2;
        LOG_INFO_MACRO("[Enclave] hex_to_bytes: Skipped 0x prefix, new length: %zu\n", hex_len);
    }

    if (hex_len % 2 != 0) {
        LOG_ERROR_MACRO("[Enclave] hex_to_bytes: Invalid hex string length: %zu\n", hex_len);
        return 0;
    }

    size_t bytes_len = hex_len / 2;
    LOG_INFO_MACRO("[Enclave] hex_to_bytes: Will convert to %zu bytes\n", bytes_len);

    if (bytes_len > max_out_len) {
        LOG_ERROR_MACRO("[Enclave] hex_to_bytes: Output buffer too small: need %zu, have %zu\n", bytes_len, max_out_len);
        return 0;
    }

    // Convert hex to bytes
    for (size_t i = 0; i < bytes_len; i++) {
        char byte_str[3] = {hex_start[i*2], hex_start[i*2+1], 0};
        char* end;
        out_bytes[i] = (uint8_t)strtol(byte_str, &end, 16);
        if (*end != 0) {
            LOG_ERROR_MACRO("[Enclave] hex_to_bytes: Invalid hex character at position %zu: '%s'\n", i*2, byte_str);
            return 0;
        }
    }

    LOG_INFO_MACRO("[Enclave] hex_to_bytes: Successfully converted %zu bytes\n", bytes_len);
    LOG_INFO_MACRO("[Enclave] hex_to_bytes: Output bytes: ");
    for (size_t i = 0; i < bytes_len; i++) {
        LOG_INFO_MACRO("%02x", out_bytes[i]);
    }
    LOG_INFO_MACRO("\n");
    
    return bytes_len;
}

// Helper function to calculate Shannon entropy
double calculate_entropy(const uint8_t* data, size_t size) {
    if (!data || size == 0) return 0.0;
    
    // Count byte frequencies
    uint32_t counts[256] = {0};
    for (size_t i = 0; i < size; i++) {
        counts[data[i]]++;
    }
    
    // Calculate entropy in bits
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            double p = (double)counts[i] / size;
            entropy -= p * log2(p);
        }
    }
    
    LOG_DEBUG_MACRO("Entropy calculation details:\n");
    LOG_DEBUG_MACRO("  Data size: %zu bytes\n", size);
    LOG_DEBUG_MACRO("  Unique bytes: ");
    int unique_bytes = 0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            unique_bytes++;
            LOG_DEBUG_MACRO("%02x ", i);
        }
    }
    LOG_DEBUG_MACRO("\n  Unique bytes count: %d\n", unique_bytes);
    LOG_DEBUG_MACRO("  Raw entropy: %.2f bits\n", entropy);
    
    return entropy;
}

// Helper function to check if a private key is cryptographically strong
bool is_strong_private_key(const uint8_t* private_key, size_t size) {
    if (!private_key || size != 32) {
        return false;
    }
    
    // Create secp256k1 context for verification
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!ctx) {
        return false;
    }
    
    // Verify key using secp256k1
    bool is_valid = secp256k1_ec_seckey_verify(ctx, private_key);
    secp256k1_context_destroy(ctx);
    
    return is_valid;
}

// Enhanced entropy generation
sgx_status_t generate_entropy(uint8_t* entropy, size_t size) {
    if (!entropy || size == 0) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // Generate random data directly from SGX RNG
    sgx_status_t status = sgx_read_rand(entropy, size);
    if (status != SGX_SUCCESS) {
        return status;
    }

    return SGX_SUCCESS;
}

// Enhanced key generation with security checks
sgx_status_t generate_secure_private_key(uint8_t* private_key, size_t size) {
    if (!private_key || size != 32) {
        LOG_ERROR_MACRO("Invalid parameters: private_key=%p, size=%zu\n", private_key, size);
        return SGX_ERROR_INVALID_PARAMETER;
    }
    
    // Step 1: Generate entropy - reduced from 128 to 64 bytes as we only need 32 bytes output
    uint8_t entropy[64];
    sgx_status_t status = generate_entropy(entropy, sizeof(entropy));
    if (status != SGX_SUCCESS) {
        LOG_ERROR_MACRO("Failed to generate entropy: %d\n", status);
        return status;
    }
    
    // Step 2: Extract PRK using SHA-256 (HKDF-Extract)
    sgx_sha256_hash_t prk;
    status = sgx_sha256_msg(entropy, sizeof(entropy), &prk);
    if (status != SGX_SUCCESS) {
        LOG_ERROR_MACRO("Failed to extract PRK: %d\n", status);
        secure_memzero(entropy, sizeof(entropy));  // Clear entropy before returning
        return status;
    }
    
    // Step 3: Expand PRK with info string (HKDF-Expand)
    const char* info = "keygen";
    size_t info_len = strlen(info);
    
    // Prepare expand input: PRK || info || 0x01
    uint8_t expand_input[32 + 32 + 1] = {0};
    memcpy(expand_input, prk, 32);
    memcpy(expand_input + 32, info, info_len);
    expand_input[32 + info_len] = 0x01;
    
    // Generate final key using SHA-256
    sgx_sha256_hash_t final_hash;
    status = sgx_sha256_msg(expand_input, 32 + info_len + 1, &final_hash);
    if (status != SGX_SUCCESS) {
        LOG_ERROR_MACRO("Failed to expand key: %d\n", status);
        secure_memzero(entropy, sizeof(entropy));  // Clear entropy before returning
        return status;
    }
    
    // Copy the final hash to the private key
    memcpy(private_key, final_hash, 32);
    
    // Verify key strength
    if (is_strong_private_key(private_key, size)) {
        secure_memzero(entropy, sizeof(entropy));  // Clear entropy after successful key generation
        return SGX_SUCCESS;
    }
    
    LOG_ERROR_MACRO("Generated key did not meet strength requirements\n");
    secure_memzero(entropy, sizeof(entropy));  // Clear entropy before returning error
    return SGX_ERROR_UNEXPECTED;
}

void keccak_256(const uint8_t* input, size_t input_len, uint8_t* output) {
    sha3_context ctx;
    sha3_Init256(&ctx);
    sha3_SetFlags(&ctx, SHA3_FLAGS_KECCAK); // correct
    sha3_Update(&ctx, input, input_len);
    const uint8_t* hash = (const uint8_t*)sha3_Finalize(&ctx);
    memcpy(output, hash, 32);
}

// Internal function to generate account
static int generate_account(Account* account) {
    if (!account) {
        LOG_ERROR_MACRO("Invalid account parameter\n");
        return -1;
    }

    uint8_t private_key[32] = {0};
    sgx_status_t status = generate_secure_private_key(private_key, sizeof(private_key));
    
    if (status != SGX_SUCCESS) {
        LOG_ERROR_MACRO("Failed to generate private key\n");
        return -1;
    }

    // Generate public key from private key
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!ctx) {
        LOG_ERROR_MACRO("Failed to create secp256k1 context\n");
        secure_memzero(private_key, sizeof(private_key));  // Clear private key before returning
        return -1;
    }
    LOG_DEBUG_MACRO("Secp256k1 context created\n");

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, private_key)) {
        LOG_ERROR_MACRO("Failed to create public key\n");
        secp256k1_context_destroy(ctx);
        secure_memzero(private_key, sizeof(private_key));  // Clear private key before returning
        return -1;
    }

    // Serialize public key
    uint8_t serialized_pubkey[65];
    size_t serialized_pubkey_len = sizeof(serialized_pubkey);
    if (!secp256k1_ec_pubkey_serialize(ctx, serialized_pubkey, &serialized_pubkey_len, &pubkey, SECP256K1_EC_UNCOMPRESSED)) {
        LOG_ERROR_MACRO("Failed to serialize public key\n");
        secp256k1_context_destroy(ctx);
        secure_memzero(private_key, sizeof(private_key));  // Clear private key before returning
        return -1;
    }
    LOG_DEBUG_MACRO("Public key serialized\n");
    
    // Calculate Ethereum address
    uint8_t hash[32];
    keccak_256(serialized_pubkey + 1, 64, hash);
    uint8_t address[20];
    memcpy(address, hash + 12, 20);
    
    // Store the account data
    memcpy(account->private_key, private_key, sizeof(private_key));
    secure_memzero(private_key, sizeof(private_key));  // Clear private key after copying to account
    memcpy(account->public_key, serialized_pubkey, sizeof(serialized_pubkey));
    memcpy(account->address, address, sizeof(address));
    account->use_count = 0;
    account->is_initialized = true;
    LOG_DEBUG_MACRO("Account data stored\n");
    
    // Calculate HMAC
    sgx_status_t hmac_status = sgx_sha256_msg((const uint8_t*)account, sizeof(Account) - 32, (sgx_sha256_hash_t*)account->hmac);
    if (hmac_status != SGX_SUCCESS) {
        LOG_ERROR_MACRO("Failed to calculate HMAC\n");
        secp256k1_context_destroy(ctx);
        return -1;
    }
    LOG_DEBUG_MACRO("HMAC calculated\n");

    secp256k1_context_destroy(ctx);
    return 0;
}

// Internal function to save account to pool
static int save_account_to_pool(const char* account_id, const Account* account) {
    if (!account || !account->is_initialized) {
        LOG_ERROR_MACRO("Account is not initialized\n");
        return -1;
    }

    // Create structure for saving
    AccountFile data;
    memcpy(&data.account, account, sizeof(Account));

    // Calculate HMAC
    uint8_t computed_hash[32];
    sgx_status_t status = sgx_sha256_msg((const uint8_t*)&data, sizeof(AccountFile) - 32, (sgx_sha256_hash_t*)computed_hash);
    if (status != SGX_SUCCESS) {
        LOG_ERROR_MACRO("Failed to calculate HMAC: %d\n", status);
        return -1;
    }
    memcpy(data.file_hmac, computed_hash, 32);
    LOG_DEBUG_MACRO("HMAC calculated and stored\n");

    // Encrypt data
    size_t sealed_size = sgx_calc_sealed_data_size(0, sizeof(AccountFile));
    if (sealed_size == UINT32_MAX) {
        LOG_ERROR_MACRO("Failed to calculate sealed data size\n");
        return -1;
    }

    uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);
    if (!sealed_data) {
        LOG_ERROR_MACRO("Failed to allocate memory for sealed data\n");
        return -1;
    }

    status = sgx_seal_data(0, NULL, sizeof(AccountFile), (uint8_t*)&data, sealed_size, (sgx_sealed_data_t*)sealed_data);
    if (status != SGX_SUCCESS) {
        LOG_ERROR_MACRO("Failed to seal data: %d\n", status);
        free(sealed_data);
        return -1;
    }

    // Save encrypted data using provided account_id as filename
    char filename[256];
    snprintf(filename, sizeof(filename), "%s.account", account_id);
    
    int ret = 0;
    status = ocall_save_to_file(&ret, sealed_data, sealed_size, filename);
    free(sealed_data);
    
    if (status != SGX_SUCCESS || ret != 0) {
        LOG_ERROR_MACRO("Failed to save file: status=%d, ret=%d\n", status, ret);
        return -1;
    }
    
    return 0;
}

// Helper function to load account from file
static int load_account(const char* account_id, Account* account) {
    if (!account_id || !account) {
        LOG_ERROR_MACRO("Invalid parameters: account_id=%p, account=%p\n", account_id, account);
        return -1;
    }

    // Открытие файла
    char filename[256];
    snprintf(filename, sizeof(filename), "%s.account", account_id);
    LOG_DEBUG_MACRO("Opening file: %s\n", filename);
    
    // Получение размера файла через OCALL
    uint8_t* sealed_data = NULL;
    size_t file_size = 0;
    int ret = 0;
    sgx_status_t ocall_status = ocall_read_from_file(&ret, NULL, 0, filename);
    if (ocall_status != SGX_SUCCESS || ret < 0) {
        LOG_ERROR_MACRO("Failed to get file size: status=%d, ret=%d\n", ocall_status, ret);
        return -1;
    }
    file_size = ret;

    // Чтение зашифрованных данных
    sealed_data = (uint8_t*)malloc(file_size);
    if (!sealed_data) {
        LOG_ERROR_MACRO("Failed to allocate memory for sealed data\n");
        return -1;
    }

    ocall_status = ocall_read_from_file(&ret, sealed_data, file_size, filename);
    if (ocall_status != SGX_SUCCESS || ret != file_size) {
        LOG_ERROR_MACRO("Failed to read file: status=%d, ret=%d\n", ocall_status, ret);
        free(sealed_data);
        return -1;
    }

    // Расшифровка данных
    uint32_t decrypted_size = sgx_get_encrypt_txt_len((sgx_sealed_data_t*)sealed_data);
    if (decrypted_size == UINT32_MAX) {
        LOG_ERROR_MACRO("Failed to get decrypted size\n");
        free(sealed_data);
        return -1;
    }
    LOG_DEBUG_MACRO("Decrypted size: %u bytes\n", decrypted_size);

    uint8_t* decrypted_data = (uint8_t*)malloc(decrypted_size);
    if (!decrypted_data) {
        LOG_ERROR_MACRO("Failed to allocate memory for decrypted data\n");
        free(sealed_data);
        return -1;
    }

    sgx_status_t unseal_status = sgx_unseal_data((sgx_sealed_data_t*)sealed_data, NULL, NULL, decrypted_data, &decrypted_size);
    free(sealed_data);

    if (unseal_status != SGX_SUCCESS || decrypted_size != sizeof(AccountFile)) {
        LOG_ERROR_MACRO("Failed to unseal data: status=%d, size=%u\n", unseal_status, decrypted_size);
        free(decrypted_data);
        return -1;
    }
    LOG_DEBUG_MACRO("Data unsealed successfully\n");

    // Проверка HMAC
    AccountFile* data = (AccountFile*)decrypted_data;
    uint8_t computed_hash[32];
    sgx_status_t hmac_status = sgx_sha256_msg((const uint8_t*)data, sizeof(AccountFile) - 32, (sgx_sha256_hash_t*)computed_hash);
    if (hmac_status != SGX_SUCCESS || memcmp(data->file_hmac, computed_hash, 32) != 0) {
        LOG_ERROR_MACRO("HMAC verification failed\n");
        free(decrypted_data);
        return -1;
    }
    LOG_DEBUG_MACRO("HMAC verified successfully\n");

    // Проверка адреса
    char expected_filename[256];
    snprintf(expected_filename, sizeof(expected_filename), "0x");
    for (int i = 0; i < 20; i++) {
        snprintf(expected_filename + 2 + i * 2, 3, "%02x", data->account.address[i]);
    }
    my_strcat(expected_filename, ".account");
    
    if (strcmp(filename, expected_filename) != 0) {
        LOG_ERROR_MACRO("Account address mismatch\n");
        free(decrypted_data);
        return -1;
    }

    // Копирование данных аккаунта
    memcpy(account, &data->account, sizeof(Account));
    account->is_initialized = true;

    free(decrypted_data);
    return 0;
}

// Helper function to find account in pool by address
static int find_account_in_pool(const uint8_t* address, int* out_index) {
    
    // Сначала ищем в хеш-таблице
    int index;
    if (account_index_find(address, &index)) {
        // Проверяем, что аккаунт действительно инициализирован
        if (index >= 0 && index < MAX_POOL_SIZE && account_pool.accounts[index].account.is_initialized) {
            if (out_index) {
                *out_index = index;
            }
            return index;
        }
    }
    return -1;
}

// Helper function to print test result
static void print_test_result(const char* test_name, int passed, const char* error_message) {
    if (passed) {
        LOG_DEBUG_MACRO("✓ %s: PASSED\n", test_name);
    } else {
        LOG_DEBUG_MACRO("✗ %s: FAILED - %s\n", test_name, error_message);
    }
}

// Helper function to print test suite summary
static void print_test_suite_summary(const test_suite_t* suite) {
    LOG_DEBUG_MACRO("\n=== Test Suite: %s ===\n", suite->suite_name);
    LOG_DEBUG_MACRO("Total tests: %d\n", suite->result_count);
    LOG_DEBUG_MACRO("Passed: %d\n", suite->passed_count);
    LOG_DEBUG_MACRO("Failed: %d\n", suite->result_count - suite->passed_count);
    LOG_DEBUG_MACRO("=====================\n\n");
}

// Test function for find_account_in_pool
static int test_find_account_in_pool(test_suite_t* suite) {
    LOG_DEBUG_MACRO("[TEST] Testing account lookup security measures...\n");
    
    // Test 1: Find in empty pool
    // Сначала убедимся, что пул пустой
    for (int i = 0; i < MAX_POOL_SIZE; i++) {
        account_pool.accounts[i].account.is_initialized = false;
    }
    uint8_t address_bytes[20] = {0};  // Просто нулевой адрес
    int result = find_account_in_pool(address_bytes, NULL);
    print_test_result("Empty pool", result == -1, "Expected -1 for empty pool");
    
    // Test 2: Add test account to pool
    LOG_DEBUG_MACRO("[TEST] Setting up test environment...\n");
    Account test_account = {0};
    if (generate_account(&test_account) != 0) {
        print_test_result("Test environment setup", 0, "Failed to set up test environment");
        return -1;
    }
    
    // Add to pool at index 0
    memcpy(&account_pool.accounts[0].account, &test_account, sizeof(Account));
    account_pool.accounts[0].account.use_count = 0;
    account_pool.accounts[0].account.is_initialized = true;  // Явно устанавливаем
    
    // Test 3: Find existing account
    result = find_account_in_pool(test_account.address, NULL);
    print_test_result("Valid account lookup", result == 0, "Security check passed: valid account found");
    
    // Cleanup
    secure_memzero(&account_pool.accounts[0].account, sizeof(Account));
    account_pool.accounts[0].account.use_count = 0;
    account_pool.accounts[0].account.is_initialized = false;
    
    return 0;
}

// Test function for ecall_load_account_to_pool
static int test_load_account_to_pool(test_suite_t* suite) {
    LOG_DEBUG_MACRO("[TEST] Testing account loading security measures...\n");
    
    // Test 1: Load with null account_id
    int result = ecall_load_account_to_pool(NULL);
    print_test_result("Null account ID security", result == -1, "Security check passed: null account ID correctly rejected");
    
    // Test 2: Generate and load test account
    LOG_DEBUG_MACRO("[TEST] Setting up test environment...\n");
    Account test_account = {0};
    if (generate_account(&test_account) != 0) {
        print_test_result("Test environment setup", 0, "Failed to set up test environment");
        return -1;
    }
    
    // Create account_id from address
    char account_id[43] = "0x";
    for (int i = 0; i < 20; i++) {
        snprintf(account_id + 2 + i * 2, 3, "%02x", test_account.address[i]);
    }
    
    // Save account using its address as filename
    if (save_account_to_pool(account_id, &test_account) != 0) {
        print_test_result("Test account preparation", 0, "Failed to prepare test account");
        return -1;
    }
    
    // Load account to pool
    result = ecall_load_account_to_pool(account_id);
    print_test_result("Valid account loading", result >= 0, "Security check passed: valid account loaded successfully");
    if (result < 0) {
        return -1;
    }
    
    // Test 3: Try to load same account again
    result = ecall_load_account_to_pool(account_id);
    print_test_result("Duplicate account security", result == -1, "Security check passed: duplicate account correctly rejected");
    
    // Test 4: Load non-existent account
    result = ecall_load_account_to_pool("0x0000000000000000000000000000000000000000");
    print_test_result("Non-existent account security", result == -1, "Security check passed: non-existent account correctly rejected");
    
    // Cleanup
    secure_memzero(&account_pool.accounts[0].account, sizeof(Account));
    account_pool.accounts[0].account.use_count = 0;
    
    return 0;
}

// Test function for ecall_unload_account_from_pool
static int test_unload_account_from_pool(test_suite_t* suite) {
    LOG_INFO_MACRO("[TEST] Testing ecall_unload_account_from_pool...\n");
    
    // Test 1: Unload with null account_id
    int result = ecall_unload_account_from_pool(NULL);
    print_test_result("Unload with null account_id", result == -1, "Expected -1 for null account_id");
    
    // Test 2: Unload non-existent account
    result = ecall_unload_account_from_pool("0x0000000000000000000000000000000000000000");
    LOG_INFO_MACRO("[TEST] Test 2 (unload non-existent): result = %d (expected -1)\n", result);
    
    // Test 3: Generate, load and unload test account
    LOG_INFO_MACRO("[TEST] Test 3: Generate, load and unload test account...\n");
    Account test_account = {0};
    if (generate_account(&test_account) != 0) {
        LOG_ERROR_MACRO("Failed to generate test account\n");
        return -1;
    }

    // Create account_id from address
    char account_id[43] = "0x";
    for (int i = 0; i < 20; i++) {
        snprintf(account_id + 2 + i * 2, 3, "%02x", test_account.address[i]);
    }
    
    // Save account using its address as filename
    if (save_account_to_pool(account_id, &test_account) != 0) {
        LOG_ERROR_MACRO("Failed to save test account\n");
        return -1;
    }

    // Load account to pool
    if (ecall_load_account_to_pool(account_id) < 0) {
        LOG_ERROR_MACRO("Failed to load account to pool\n");
        return -1;
    }

    // Unload account
    result = ecall_unload_account_from_pool(account_id);
    LOG_INFO_MACRO("Test 3 (unload account): result = %d (expected 0)\n", result);
    if (result != 0) {
        return -1;
    }

    // Verify account was unloaded
    if (find_account_in_pool(test_account.address, NULL) != -1) {
        LOG_ERROR_MACRO("Account still found in pool after unload\n");
        return -1;
    }

    return 0;
}

static int test_generate_account_in_pool(test_suite_t* suite) {
    LOG_INFO_MACRO("[TEST] Testing account generation and pool loading...\n");
    
    // Test 1: Generate account
    Account test_account = {0};
    if (generate_account(&test_account) != 0) {
        print_test_result("Generate account", 0, "Failed to generate account");
        return -1;
    }
    print_test_result("[TEST] Generate account", 1, NULL);

    // Create account_id from address
    char account_id[43] = "0x";
    for (int i = 0; i < 20; i++) {
        snprintf(account_id + 2 + i * 2, 3, "%02x", test_account.address[i]);
    }

    // Save account using its address as filename
    if (save_account_to_pool(account_id, &test_account) != 0) {
        print_test_result("Save account", 0, "Failed to save test account");
        return -1;
    }

    // Test 2: Load account to pool
    int pool_index = ecall_load_account_to_pool(account_id);
    if (pool_index < 0) {
        print_test_result("Load to pool", 0, "Failed to load account to pool");
        return -1;
    }
    print_test_result("[TEST] Load to pool", 1, NULL);

    // Test 3: Verify account was added to pool
    if (!account_pool.accounts[pool_index].account.is_initialized) {
        print_test_result("Verify account", 0, "Account not initialized");
        return -1;
    }
    print_test_result("Verify account", 1, NULL);

    // Test 4: Verify use count
    if (account_pool.accounts[pool_index].account.use_count != 0) {
        print_test_result("Verify use count", 0, "Use count is not 0");
        return -1;
    }
    print_test_result("Verify use count", 1, NULL);

    return 0;
}

static int test_sign_with_pool_account(test_suite_t* suite) {
    LOG_INFO_MACRO("[TEST] Testing sign_with_pool_account...\n");
    
    // Test 1: Sign with null account_id
    uint8_t test_message[32] = {0};
    uint8_t test_signature[65] = {0};
    int result = ecall_sign_with_pool_account(NULL, test_message, sizeof(test_message), test_signature, sizeof(test_signature));
    print_test_result("Sign with null account_id", result == -1, "Expected -1 for null account_id");
    
    // Test 2: Generate, load and sign with test account
    LOG_INFO_MACRO("[TEST] Generating test account...\n");
    Account test_account = {0};
    if (generate_account(&test_account) != 0) {
        print_test_result("Generate test account", 0, "Failed to generate test account");
        return -1;
    }
    
    // Create account_id from address
    char account_id[43] = "0x";
    for (int i = 0; i < 20; i++) {
        snprintf(account_id + 2 + i * 2, 3, "%02x", test_account.address[i]);
    }
    
    // Save account using its address as filename
    if (save_account_to_pool(account_id, &test_account) != 0) {
        print_test_result("Save test account", 0, "Failed to save test account");
        return -1;
    }
    
    // Load account to pool
    int pool_index = ecall_load_account_to_pool(account_id);
    if (pool_index < 0) {
        print_test_result("Load to pool", 0, "Failed to load account to pool");
        return -1;
    }

    // Verify initial use_count
    if (account_pool.accounts[pool_index].account.use_count != 0) {
        print_test_result("Verify initial use_count", 0, "Initial use_count is not 0");
        return -1;
    }
    print_test_result("Verify initial use_count", 1, NULL);
    
    // Create test message
    for (int i = 0; i < sizeof(test_message); i++) {
        test_message[i] = i;
    }
    
    // Sign message
    result = ecall_sign_with_pool_account(account_id, test_message, sizeof(test_message), test_signature, sizeof(test_signature));
    if (result != 0) {
        print_test_result("Sign message", 0, "Failed to sign message");
        return -1;
    }
    print_test_result("Sign message", 1, NULL);

    // Verify use_count was incremented
    if (account_pool.accounts[pool_index].account.use_count != 1) {
        print_test_result("Verify use_count increment", 0, "Use count not incremented");
        return -1;
    }
    print_test_result("Verify use_count increment", 1, NULL);

    // Test 3: Verify signature
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        print_test_result("Create context", 0, "Failed to create secp256k1 context");
        return -1;
    }

    // Parse signature
    secp256k1_ecdsa_recoverable_signature rsig;
    uint8_t v = test_signature[64];  // Get v from signature
    if (v != 27 && v != 28) {
        print_test_result("Verify v value", 0, "Invalid v value in signature");
        secp256k1_context_destroy(ctx);
        return -1;
    }
    int recid = v - 27;  // Convert v back to recid (0 or 1)
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &rsig, test_signature, recid)) {
        print_test_result("Parse signature", 0, "Failed to parse signature");
        secp256k1_context_destroy(ctx);
        return -1;
    }

    // Parse public key
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, test_account.public_key, sizeof(test_account.public_key))) {
        print_test_result("Parse public key", 0, "Failed to parse public key");
        secp256k1_context_destroy(ctx);
        return -1;
    }

    // Convert recoverable signature to normal signature
    secp256k1_ecdsa_signature normal_sig;
    if (!secp256k1_ecdsa_recoverable_signature_convert(ctx, &normal_sig, &rsig)) {
        print_test_result("Convert signature", 0, "Failed to convert signature");
        secp256k1_context_destroy(ctx);
        return -1;
    }

    // Verify signature
    if (!secp256k1_ecdsa_verify(ctx, &normal_sig, test_message, &pubkey)) {
        print_test_result("Verify signature", 0, "Signature verification failed");
        secp256k1_context_destroy(ctx);
        return -1;
    }
    print_test_result("Verify signature", 1, NULL);
    
    secp256k1_context_destroy(ctx);
    
    // Cleanup
    secure_memzero(&account_pool.accounts[pool_index].account, sizeof(Account));
    account_pool.accounts[pool_index].account.use_count = 0;
    account_pool.accounts[pool_index].account.is_initialized = false;
    
    return 0;
}

static int test_get_pool_status(test_suite_t* suite) {
    LOG_INFO_MACRO("[TEST] Testing get_pool_status...\n");
    
    // Clear pool before testing
    for (int i = 0; i < MAX_POOL_SIZE; i++) {
        secure_memzero(&account_pool.accounts[i].account, sizeof(Account));
        account_pool.accounts[i].account.is_initialized = false;
    }
    LOG_INFO_MACRO("[TEST] Pool cleared\n");
    
    // Test 1: Check empty pool
    uint32_t total_accounts = 0;
    uint32_t active_accounts = 0;
    char account_addresses[4300] = {0};
    
    int result = ecall_get_pool_status(&total_accounts, &active_accounts, account_addresses);
    print_test_result("Get status of empty pool", result == 0 && total_accounts == 0 && active_accounts == 0, 
                     "Expected empty pool status");
    
    // Test 2: Add an account to pool
    Account test_account = {0};
    if (generate_account(&test_account) != 0) {
        print_test_result("Generate test account", 0, "Failed to generate test account");
        return -1;
    }
    print_test_result("Generate test account", 1, NULL);

    // Create account_id from address
    char account_id[43] = "0x";
    for (int i = 0; i < 20; i++) {
        snprintf(account_id + 2 + i * 2, 3, "%02x", test_account.address[i]);
    }

    // Save account using its address as filename
    if (save_account_to_pool(account_id, &test_account) != 0) {
        print_test_result("Save test account", 0, "Failed to save test account");
        return -1;
    }

    // Load account to pool
    int pool_index = ecall_load_account_to_pool(account_id);
    if (pool_index < 0) {
        print_test_result("Load to pool", 0, "Failed to load account to pool");
        return -1;
    }
    print_test_result("Load to pool", 1, NULL);

    // Check pool status after loading
    result = ecall_get_pool_status(&total_accounts, &active_accounts, account_addresses);
    print_test_result("Get status after loading", 
                     result == 0 && total_accounts == 1 && active_accounts == 0,
                     "Expected one inactive account");

    // Test 3: Sign a message to make account active
    uint8_t test_message[32] = {0};
    uint8_t test_signature[65] = {0};
    for (int i = 0; i < sizeof(test_message); i++) {
        test_message[i] = i;
    }

    result = ecall_sign_with_pool_account(account_id, test_message, sizeof(test_message), test_signature, sizeof(test_signature));
    if (result != 0) {
        print_test_result("Sign message", 0, "Failed to sign message");
        return -1;
    }
    print_test_result("Sign message", 1, NULL);

    // Check pool status after signing
    result = ecall_get_pool_status(&total_accounts, &active_accounts, account_addresses);
    print_test_result("Get status after signing",
                     result == 0 && total_accounts == 1 && active_accounts == 1,
                     "Expected one active account");

    // Cleanup
    secure_memzero(&account_pool.accounts[pool_index].account, sizeof(Account));
    account_pool.accounts[pool_index].account.use_count = 0;
    account_pool.accounts[pool_index].account.is_initialized = false;
    
    return 0;
}

// Test Keccak-256 address generation
static int test_keccak_address_generation(test_suite_t* suite) {
    const char* test_name = "[TEST] Keccak-256 Address Generation";
    LOG_INFO_MACRO("Running test: %s\n", test_name);
    
    // Predefined private key (32 bytes) - using the same key as in Python test
    const uint8_t test_private_key[32] = {
        0xb7, 0x1c, 0x71, 0xa6, 0x9c, 0x80, 0x4f, 0x6b,
        0x50, 0xfa, 0x52, 0xee, 0xcb, 0x91, 0xb8, 0x4f,
        0x0c, 0xd7, 0xfc, 0x93, 0x8d, 0x4e, 0xe5, 0xa7,
        0xb2, 0xfe, 0x9b, 0x8e, 0xb2, 0xe5, 0xe8, 0x2e
    };
    
    // Expected Ethereum address for this private key
    const char* expected_address = "0x3c91a91e07531821faa19a9213bcce2169892f8a";
    
    // Create secp256k1 context
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!ctx) {
        print_test_result(test_name, 0, "Failed to create secp256k1 context");
        return -1;
    }

    // Create public key
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, test_private_key)) {
        secp256k1_context_destroy(ctx);
        print_test_result(test_name, 0, "Failed to create public key");
        return -1;
    }

    // Serialize public key
    uint8_t serialized_pubkey[65];
    size_t serialized_pubkey_len = sizeof(serialized_pubkey);
    if (!secp256k1_ec_pubkey_serialize(ctx, serialized_pubkey, &serialized_pubkey_len, &pubkey, SECP256K1_EC_UNCOMPRESSED)) {
        secp256k1_context_destroy(ctx);
        print_test_result(test_name, 0, "Failed to serialize public key");
        return -1;
    }

    // Calculate Ethereum address
    uint8_t hash[32];
    keccak_256(serialized_pubkey + 1, 64, hash);
    
    // Convert to Ethereum address format
    char generated_address[43];
    snprintf(generated_address, sizeof(generated_address), "0x");
    for (int i = 12; i < 32; i++) {
        snprintf(generated_address + 2 + (i-12)*2, 3, "%02x", hash[i]);
    }
    
    // Compare addresses
    if (strcmp(generated_address, expected_address) != 0) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), 
                "Address mismatch. Expected: %s, Got: %s", 
                expected_address, generated_address);
        secp256k1_context_destroy(ctx);
        print_test_result(test_name, 0, error_msg);
        return -1;
    }
    
    secp256k1_context_destroy(ctx);
    print_test_result(test_name, 1, NULL);
    return 0;
}

// Test function for testing pool capacity and hash table functionality
static int test_pool_capacity_and_hash_table(test_suite_t* suite) {
    // Set log level to ERROR to reduce output
    int old_log_level = g_log_level;
    g_log_level = LOG_ERROR;
    
    LOG_INFO_MACRO("[TEST] Testing pool capacity and hash table functionality...\n");
    
    // Clear pool and hash table before testing
    for (int i = 0; i < MAX_POOL_SIZE; i++) {
        secure_memzero(&account_pool.accounts[i].account, sizeof(Account));
        account_pool.accounts[i].account.is_initialized = false;
    }
    account_index_clear();
    
    // Array to store generated account addresses
    char account_addresses[MAX_POOL_SIZE][43]; // 0x + 40 hex chars + null terminator
    int generated_count = 0;
    
    // Generate accounts until pool is full
    while (generated_count < MAX_POOL_SIZE) {
        int result = ecall_generate_account_to_pool(account_addresses[generated_count]);
        if (result < 0) {
            LOG_ERROR_MACRO("Failed to generate account %d\n", generated_count);
            g_log_level = old_log_level; // Restore original log level
            return -1;
        }
        generated_count++;
    }
    
    // Try to generate one more account - should fail
    char extra_address[43];
    int result = ecall_generate_account_to_pool(extra_address);
    if (result >= 0) {
        LOG_ERROR_MACRO("Pool should be full but generated extra account\n");
        g_log_level = old_log_level; // Restore original log level
        return -1;
    }

    // Verify all accounts can be found
    for (int i = 0; i < generated_count; i++) {
        uint8_t address_bytes[20];
        for (int j = 0; j < 20; j++) {
            char byte_str[3] = {account_addresses[i][2+j*2], account_addresses[i][2+j*2+1], '\0'};
            address_bytes[j] = (uint8_t)strtol(byte_str, NULL, 16);
        }
        
        int pool_index;
        bool found = find_account_in_pool(address_bytes, &pool_index) >= 0;
        if (!found) {
            LOG_ERROR_MACRO("Failed to find account %s in pool\n", account_addresses[i]);
            g_log_level = old_log_level; // Restore original log level
            return -1;
        }
    }
    
    // Unload all accounts
    for (int i = 0; i < generated_count; i++) {
        result = ecall_unload_account_from_pool(account_addresses[i]);
        if (result != 0) {
            LOG_ERROR_MACRO("Failed to unload account %s\n", account_addresses[i]);
            g_log_level = old_log_level; // Restore original log level
            return -1;
        }
    }
    
    // Verify pool is empty
    uint32_t total_accounts, active_accounts;
    char addresses[1024];
    result = ecall_get_pool_status(&total_accounts, &active_accounts, addresses);
    if (result != 0 || total_accounts != 0 || active_accounts != 0) {
        LOG_ERROR_MACRO("Pool should be empty but contains accounts\n");
        g_log_level = old_log_level; // Restore original log level
        return -1;
    }
    
    // Restore original log level before returning
    g_log_level = old_log_level;
    return 0;
}

// Enclave initialization function
sgx_status_t sgx_ecall_initialize() {
    LOG_INFO_MACRO("Initializing enclave...\n");
    
    // Initialize account pool
    if (!initialize_account_pool()) {
        LOG_ERROR_MACRO("Failed to initialize account pool\n");
        return SGX_ERROR_UNEXPECTED;
    }

    account_index_clear();
    
    LOG_INFO_MACRO("Enclave initialized successfully\n");
    return SGX_SUCCESS;
}

// Function to set log level
int ecall_set_log_level(int level) {
    if (level < LOG_ERROR || level > LOG_DEBUG) {
        return -1;
    }
    g_log_level = level;
    return 0;
}

int ecall_test_function() {
    LOG_INFO_MACRO("=== Test Suite: System Tests ===\n");
    
    test_suite_t suite = {
        .suite_name = "System Tests",
        .results = NULL,
        .result_count = 0,
        .passed_count = 0
    };
    
    // Allocate space for test results
    suite.results = (test_result_t*)malloc(sizeof(test_result_t) * 10);
    if (!suite.results) {
        return -1;
    }
    
    // Run tests
    int test_result = test_find_account_in_pool(&suite);
    suite.results[suite.result_count++] = (test_result_t){
        "Find Account in Pool",
        test_result == 0,
        NULL
    };
    if (test_result == 0) suite.passed_count++;
    
    test_result = test_load_account_to_pool(&suite);
    suite.results[suite.result_count++] = (test_result_t){
        "Load Account to Pool",
        test_result == 0,
        NULL
    };
    if (test_result == 0) suite.passed_count++;
    
    test_result = test_unload_account_from_pool(&suite);
    suite.results[suite.result_count++] = (test_result_t){
        "Unload Account from Pool",
        test_result == 0,
        NULL
    };
    if (test_result == 0) suite.passed_count++;
    
    test_result = test_generate_account_in_pool(&suite);
    suite.results[suite.result_count++] = (test_result_t){
        "Generate Account in Pool",
        test_result == 0,
        NULL
    };
    if (test_result == 0) suite.passed_count++;
    
    test_result = test_sign_with_pool_account(&suite);
    suite.results[suite.result_count++] = (test_result_t){
        "Sign with Pool Account",
        test_result == 0,
        NULL
    };
    if (test_result == 0) suite.passed_count++;
    
    test_result = test_get_pool_status(&suite);
    suite.results[suite.result_count++] = (test_result_t){
        "Get Pool Status",
        test_result == 0,
        NULL
    };
    if (test_result == 0) suite.passed_count++;
    
    // Add Keccak address generation test
    test_result = test_keccak_address_generation(&suite);
    suite.results[suite.result_count++] = (test_result_t){
        "Keccak-256 Address Generation",
        test_result == 0,
        NULL
    };
    if (test_result == 0) suite.passed_count++;
    
    // Add new test
    test_result = test_pool_capacity_and_hash_table(&suite);
    suite.results[suite.result_count++] = (test_result_t){
        "Pool Capacity and Hash Table",
        test_result == 0,
        NULL
    };
    if (test_result == 0) suite.passed_count++;
    
    // Print test suite summary
    print_test_suite_summary(&suite);
    
    // Clean up
    free(suite.results);
    
    return 0;
}

int ecall_load_account_to_pool(const char* account_id) {
    LOG_DEBUG_MACRO("Loading account %s to pool...\n", account_id);
    
    // Validate input parameters
    if (!account_id) {
        LOG_ERROR_MACRO("Invalid account ID: NULL pointer\n");
        return -1;
    }

    // Validate account_id format (should be "0x" followed by 40 hex characters)
    if (strlen(account_id) != 42 || account_id[0] != '0' || account_id[1] != 'x') {
        LOG_ERROR_MACRO("Invalid account ID format: %s (should be 0x followed by 40 hex characters)\n", account_id);
        return -1;
    }

    // Validate hex characters
    for (int i = 2; i < 42; i++) {
        char c = account_id[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            LOG_ERROR_MACRO("Invalid account ID: contains non-hex character '%c' at position %d\n", c, i);
            return -1;
        }
    }

    // Convert hex string to bytes
    uint8_t address[20];
    hex_to_bytes(account_id, address, sizeof(address));
    
    // Check if account is already in pool
    int existing_index = find_account_in_pool(address, NULL);
    if (existing_index != -1) {
        LOG_ERROR_MACRO("Account already in pool at index %d\n", existing_index);
        return -1;
    }

    // Load account into temporary variable
    Account temp_account = {0};
    if (load_account(account_id, &temp_account) != 0) {
        LOG_ERROR_MACRO("Failed to load account\n");
        return -1;
    }

    // Find free slot in pool
    int free_slot = -1;
    for (int i = 0; i < MAX_POOL_SIZE; i++) {
        if (!account_pool.accounts[i].account.is_initialized) {
            free_slot = i;
            break;
        }
    }

    if (free_slot == -1) {
        LOG_ERROR_MACRO("No free slots in pool\n");
        return -1;
    }

    if (!account_index_insert(temp_account.address, free_slot)) {
        LOG_ERROR_MACRO("Failed to insert into account index table\n");
        return -1;
    }

    // Copy account to pool
    memcpy(&account_pool.accounts[free_slot].account, &temp_account, sizeof(Account));
    account_pool.accounts[free_slot].account.use_count = 0;
    account_pool.accounts[free_slot].account.is_initialized = true;

    LOG_DEBUG_MACRO("Account successfully loaded to pool at index %d\n", free_slot);
    return free_slot;
}

int ecall_unload_account_from_pool(const char* account_id) {
    LOG_INFO_MACRO("Unloading account %s from pool...\n", account_id);
    
    if (!account_id) {
        LOG_ERROR_MACRO("Invalid account ID\n");
        return -1;
    }

    // Convert hex string to bytes
    uint8_t address[20];
    if (strlen(account_id) != 42 || account_id[0] != '0' || account_id[1] != 'x') {
        LOG_ERROR_MACRO("Invalid account ID format\n");
        return -1;
    }
    
    hex_to_bytes(account_id, address, sizeof(address));

    // Find account in pool
    int pool_index;
    if (find_account_in_pool(address, &pool_index) < 0) {
        LOG_WARN_MACRO("WARNING: Account not found in pool\n");
        return -1;
    }
    LOG_DEBUG_MACRO("Found account at pool index %d\n", pool_index);

    if(!account_index_remove(address)) {
        LOG_ERROR_MACRO("Failed to remove account from index table\n");
        return -1;
    }

    // Securely clear the slot
    secure_memzero(&account_pool.accounts[pool_index].account, sizeof(Account));
    account_pool.accounts[pool_index].account.use_count = 0;
    account_pool.accounts[pool_index].account.is_initialized = false;
    LOG_DEBUG_MACRO("Account slot cleared at index %d\n", pool_index);

    // Verify account was removed
    if (find_account_in_pool(address, NULL) >= 0) {
        LOG_ERROR_MACRO("Failed to verify account removal\n");
        return -1;
    }

    LOG_INFO_MACRO("Account successfully unloaded from pool\n");
    return 0;
}

int ecall_sign_with_pool_account(const char* account_id, const uint8_t* message, size_t message_len, uint8_t* signature, size_t signature_len) {
    LOG_DEBUG_MACRO("Signing message with pool account %s...\n", account_id);
    
    if (!account_id || !message || !signature || message_len == 0 || signature_len < 65) {  // Changed from 64 to 65 to accommodate v
        LOG_ERROR_MACRO("Invalid parameters\n");
        return -1;
    }

    // Convert hex string to bytes
    uint8_t address[20];
    if (strlen(account_id) != 42 || account_id[0] != '0' || account_id[1] != 'x') {
        LOG_ERROR_MACRO("Invalid account ID format\n");
        return -1;
    }

    hex_to_bytes(account_id, address, sizeof(address));

    // Find account in pool
    int pool_index = find_account_in_pool(address, NULL);
    if (pool_index == -1) {
        LOG_ERROR_MACRO("Account not found in pool\n");
        return -1;
    }
    LOG_DEBUG_MACRO("Found account at pool index %d\n", pool_index);

    // Create secp256k1 context
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!ctx) {
        LOG_ERROR_MACRO("Failed to create secp256k1 context\n");
        return -1;
    }

    // 1. Create recoverable signature
    secp256k1_ecdsa_recoverable_signature rsig;
    if (!secp256k1_ecdsa_sign_recoverable(ctx, &rsig, message, account_pool.accounts[pool_index].account.private_key, NULL, NULL)) {
        LOG_ERROR_MACRO("Failed to create recoverable signature\n");
        secp256k1_context_destroy(ctx);
        return -1;
    }

    // 2. Extract recid before normalization
    int recid;
    uint8_t tmp_sig[64];
    if (!secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, tmp_sig, &recid, &rsig)) {
        LOG_ERROR_MACRO("Failed to serialize recoverable signature\n");
        secp256k1_context_destroy(ctx);
        return -1;
    }

    // 3. Convert to non-recoverable signature
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_recoverable_signature_convert(ctx, &sig, &rsig)) {
        LOG_ERROR_MACRO("Failed to convert to non-recoverable signature\n");
        secp256k1_context_destroy(ctx);
        return -1;
    }

    // 4. Normalize s
    secp256k1_ecdsa_signature norm_sig;
    int normalized = secp256k1_ecdsa_signature_normalize(ctx, &norm_sig, &sig);
    if (normalized < 0) {
        LOG_ERROR_MACRO("Failed to normalize signature\n");
        secp256k1_context_destroy(ctx);
        return -1;
    }

    // 5. Invert recid if s was changed
    if (normalized) {
        recid ^= 1;  // flip recovery id
        LOG_DEBUG_MACRO("Signature normalized: yes, recid adjusted to %d\n", recid);
    } else {
        LOG_DEBUG_MACRO("Signature normalized: no, recid remains %d\n", recid);
    }

    // 6. Serialize normalized signature
    if (!secp256k1_ecdsa_signature_serialize_compact(ctx, signature, &norm_sig)) {
        LOG_ERROR_MACRO("Failed to serialize normalized signature\n");
        secp256k1_context_destroy(ctx);
        return -1;
    }

    // 7. Add Ethereum-compatible v = 27 + recid
    uint8_t v = (uint8_t)(27 + recid);
    
    // Validate v value
    if (v != 27 && v != 28) {
        LOG_ERROR_MACRO("Critical error: Invalid v value %d (must be 27 or 28)\n", v);
        secp256k1_context_destroy(ctx);
        return -1;
    }
    
    signature[64] = v;

    // Increment use count in Account
    account_pool.accounts[pool_index].account.use_count++;
    LOG_DEBUG_MACRO("Use count incremented to %u\n", account_pool.accounts[pool_index].account.use_count);

    // Save account state to persist use_count
    int save_result = save_account_to_pool(account_id, &account_pool.accounts[pool_index].account);
    if (save_result != 0) {
        LOG_ERROR_MACRO("Failed to save account state after signing\n");
        secp256k1_context_destroy(ctx);
        return -1;
    }

    secp256k1_context_destroy(ctx);
    LOG_INFO_MACRO("Message signing completed successfully\n");
    return 0;
}

int ecall_get_pool_status(uint32_t* total_accounts, uint32_t* active_accounts, char* account_addresses) {
    LOG_INFO_MACRO("Getting pool status...\n");
    
    if (!total_accounts || !active_accounts || !account_addresses) {
        LOG_ERROR_MACRO("Invalid parameters: total_accounts=%p, active_accounts=%p, account_addresses=%p\n", 
               total_accounts, active_accounts, account_addresses);
        return -1;
    }

    // Count total and active accounts
    *total_accounts = 0;
    *active_accounts = 0;
    account_addresses[0] = '\0';  // Initialize empty string
    
    for (int i = 0; i < MAX_POOL_SIZE; i++) {
        if (account_pool.accounts[i].account.is_initialized) {
            // Convert address to hex string
            char address[43];
            snprintf(address, sizeof(address), "0x");
            for (int j = 0; j < 20; j++) {
                snprintf(address + 2 + j * 2, 3, "%02x", account_pool.accounts[i].account.address[j]);
            }
            
            // Add to total count
            (*total_accounts)++;
            
            // Add to active count if used
            if (account_pool.accounts[i].account.use_count > 0) {
                (*active_accounts)++;
            }
            
            // Add to comma-separated list
            if ((*total_accounts) > 1) {
                my_strcat(account_addresses, ",");
            }
            my_strcat(account_addresses, address);
            
            LOG_DEBUG_MACRO("Found account at index %d: %s (use_count: %u)\n", 
                   i, address, account_pool.accounts[i].account.use_count);
        }
    }
    
    LOG_INFO_MACRO("Pool status: total accounts=%u, active accounts=%u\n", *total_accounts, *active_accounts);
    return 0;
}

int ecall_generate_account_to_pool(char* account_address) {
    LOG_INFO_MACRO("Generating new account in pool...\n");
    
    if (!account_address) {
        LOG_ERROR_MACRO("Invalid account_address parameter\n");
        return -1;
    }

    // Generate new account
    Account new_account = {0};
    if (generate_account(&new_account) != 0) {
        LOG_ERROR_MACRO("Failed to generate account\n");
        return -1;
    }
    LOG_INFO_MACRO("Account generated successfully\n");

    // Format address as hex string in the provided buffer
    snprintf(account_address, 43, "0x");
    for (int i = 0; i < 20; i++) {
        snprintf(account_address + 2 + i * 2, 3, "%02x", new_account.address[i]);
    }

    // Find free slot in pool
    int free_slot = -1;
    for (int i = 0; i < MAX_POOL_SIZE; i++) {
        if (!account_pool.accounts[i].account.is_initialized) {
            free_slot = i;
            break;
        }
    }

    if (free_slot == -1) {
        LOG_ERROR_MACRO("No free slots in pool\n");
        return -1;
    }
    LOG_INFO_MACRO("Found free slot at index %d\n", free_slot);

    if (!account_index_insert(new_account.address, free_slot)) {
        LOG_ERROR_MACRO("Failed to insert into account index table\n");
        return -1;
    }

    // Copy account to pool
    memcpy(&account_pool.accounts[free_slot].account, &new_account, sizeof(Account));
    account_pool.accounts[free_slot].account.use_count = 0;
    account_pool.accounts[free_slot].account.is_initialized = true;
    LOG_INFO_MACRO("Account copied to pool at index %d\n", free_slot);

    // Verify the account was inserted correctly
    int verify_index;
    bool found = find_account_in_pool(new_account.address, &verify_index) >= 0;
    if (!found || verify_index != free_slot) {
        LOG_ERROR_MACRO("Account verification failed: expected index %d, got %d (found=%d)\n", 
                       free_slot, verify_index, found);
        return -1;
    }

    LOG_INFO_MACRO("Account successfully generated in pool at index %d\n", free_slot);

    // Save account to disk
    int ret = 0;
    char filename[256];
    snprintf(filename, sizeof(filename), "%s.account", account_address);
    
    // Save account using its address as filename
    sgx_status_t status = ocall_save_to_file(&ret, (uint8_t*)&new_account, sizeof(Account), filename);
    if (status != SGX_SUCCESS || ret != 0) {
        LOG_ERROR_MACRO("Failed to save account file: status=%d, ret=%d\n", status, ret);
        return -1;
    }

    return free_slot;
}

// Функция-обертка над sgx_read_rand для BearSSL
static size_t enclave_rng(void* ctx, unsigned char* out, size_t len) {
    (void)ctx;  // unused
    if (sgx_read_rand(out, (uint32_t)len) != SGX_SUCCESS) {
        return 0;
    }
    return len;
}

// Структура PRNG для BearSSL
static const br_prng_class enclave_prng_class = {
    .context_size = 0,
    .init = NULL,
    .generate = [](const br_prng_class** ctx, void* out, size_t len) -> void {
        (void)ctx;  // unused
        sgx_status_t status = sgx_read_rand((uint8_t*)out, (uint32_t)len);
        if (status != SGX_SUCCESS) {
            LOG_ERROR_MACRO("Failed to generate random data: %d\n", status);
            // В случае ошибки заполняем буфер нулями
            memset(out, 0, len);
        }
    }
};

// Функция для RSA шифрования данных с использованием BearSSL
static sgx_status_t rsa_encrypt(const uint8_t* data, size_t data_len,
                              const uint8_t* modulus, size_t modulus_len,
                              const uint8_t* exponent, size_t exponent_len,
                              uint8_t* encrypted_data, size_t* encrypted_data_len) {
    if (!data || !modulus || !exponent || !encrypted_data || !encrypted_data_len) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // Check for RSA-3072 (384 bytes)
    if (modulus_len != 384) {
        LOG_ERROR_MACRO("Invalid modulus size: %zu bytes (expected 384 bytes for RSA-3072)\n", modulus_len);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // Debug: Print data before encryption
    LOG_INFO_MACRO("Debug: Data before encryption:\n");
    LOG_INFO_MACRO("Private key: ");
    for (int i = 0; i < 32; i++) {
        LOG_INFO_MACRO("%02x", data[i]);
    }
    LOG_INFO_MACRO("\nPublic key: ");
    for (int i = 32; i < 97; i++) {
        LOG_INFO_MACRO("%02x", data[i]);
    }
    LOG_INFO_MACRO("\n");

    // Initialize BearSSL RSA public key
    br_rsa_public_key pk;
    pk.n = (unsigned char*)modulus;
    pk.nlen = (uint32_t)modulus_len;
    pk.e = (unsigned char*)exponent;
    pk.elen = (uint32_t)exponent_len;

    LOG_INFO_MACRO("Debug: RSA key lengths - modulus: %zu, exponent: %zu\n", modulus_len, exponent_len);
    LOG_INFO_MACRO("Debug: RSA key values:\n");
    LOG_INFO_MACRO("Modulus: ");
    for (size_t i = 0; i < modulus_len; i++) {
        LOG_INFO_MACRO("%02x", pk.n[i]);
    }
    LOG_INFO_MACRO("\nExponent: ");
    for (size_t i = 0; i < exponent_len; i++) {
        LOG_INFO_MACRO("%02x", pk.e[i]);
    }
    LOG_INFO_MACRO("\n");

    // Check OAEP padding conditions
    size_t hlen = br_sha256_SIZE;  // 32 bytes for SHA-256
    if (modulus_len < ((hlen << 1) + 2)) {
        LOG_ERROR_MACRO("Modulus too short for OAEP padding\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    size_t max_src_len = modulus_len - (hlen << 1) - 2;
    if (data_len > max_src_len) {
        LOG_ERROR_MACRO("Data too long for OAEP padding (max %zu bytes)\n", max_src_len);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // Ensure output buffer is exactly modulus size
    if (*encrypted_data_len < modulus_len) {
        LOG_ERROR_MACRO("Output buffer too small (need %zu bytes)\n", modulus_len);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // Проверяем значение экспоненты, а не её длину
    uint32_t e_value = 0;
    for (size_t i = 0; i < exponent_len; i++) {
        e_value = (e_value << 8) | exponent[i];
    }

    if (e_value != 0x10001) {  // 65537
        LOG_ERROR_MACRO("Invalid exponent value: must be 0x10001 (65537)\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // Clear output buffer
    memset(encrypted_data, 0, *encrypted_data_len);

    // Encrypt with RSA OAEP
    const br_prng_class* prng = &enclave_prng_class;
    size_t out_len = br_rsa_i31_oaep_encrypt(
        &prng,             // Use our PRNG class
        &br_sha256_vtable, // Hash function for OAEP
        NULL,              // Label
        0,                 // Label length
        &pk,               // RSA public key
        encrypted_data,    // Output buffer (dst)
        modulus_len,       // Output buffer size (must be exactly modulus size)
        data,              // Data to encrypt (src)
        data_len           // Data length (src_len)
    );

    if (out_len == 0) {
        LOG_ERROR_MACRO("BearSSL RSA encryption failed\n");
        return SGX_ERROR_UNEXPECTED;
    }

    // Verify output length matches modulus size
    if (out_len != modulus_len) {
        LOG_ERROR_MACRO("Unexpected output length: got %zu, expected %zu\n", out_len, modulus_len);
        return SGX_ERROR_UNEXPECTED;
    }

    // Debug: Print encrypted data
    LOG_INFO_MACRO("Debug: Encrypted data (length: %zu):\n", out_len);
    for (int i = 0; i < out_len; i++) {
        LOG_INFO_MACRO("%02x", encrypted_data[i]);
    }
    LOG_INFO_MACRO("\n");

    *encrypted_data_len = out_len;
    return SGX_SUCCESS;
}

int ecall_generate_account_with_recovery(const char* modulus_hex, const char* exponent_hex, char* out_address) {
    LOG_INFO_MACRO("[Enclave] generate_account_with_recovery: Starting\n");
    LOG_INFO_MACRO("[Enclave] generate_account_with_recovery: Input modulus: %s\n", modulus_hex);
    LOG_INFO_MACRO("[Enclave] generate_account_with_recovery: Input exponent: %s\n", exponent_hex);

    // Validate input parameters
    if (!modulus_hex || !exponent_hex || !out_address) {
        LOG_ERROR_MACRO("[Enclave] generate_account_with_recovery: Invalid input parameters\n");
        return -1;
    }

    // Validate modulus length (should be 384 bytes = 768 hex chars)
    size_t modulus_len = strlen(modulus_hex);
    if (modulus_len != 768) {
        LOG_ERROR_MACRO("[Enclave] generate_account_with_recovery: Invalid modulus length: %zu hex chars (expected 768 for RSA-3072)\n", modulus_len);
        return -1;
    }

    // Validate exponent format
    if (strcmp(exponent_hex, "00010001") != 0) {
        LOG_ERROR_MACRO("[Enclave] generate_account_with_recovery: Invalid exponent. Expected: 00010001\n");
        return -1;
    }

    // Convert hex strings to bytes
    uint8_t modulus_bytes[384];
    uint8_t exponent_bytes[4];  // Changed from 3 to 4 bytes for 32-bit exponent

    if (!hex_to_bytes(modulus_hex, modulus_bytes, sizeof(modulus_bytes))) {
        LOG_ERROR_MACRO("[Enclave] generate_account_with_recovery: Failed to convert modulus to bytes\n");
        return -1;
    }

    if (!hex_to_bytes(exponent_hex, exponent_bytes, sizeof(exponent_bytes))) {
        LOG_ERROR_MACRO("[Enclave] generate_account_with_recovery: Failed to convert exponent to bytes\n");
        return -1;
    }

    // Generate new account
    Account new_account = {0};
    if (generate_account(&new_account) != 0) {
        LOG_ERROR_MACRO("[Enclave] generate_account_with_recovery: Failed to generate account\n");
        return -1;
    }

    // Format address as hex string
    snprintf(out_address, 43, "0x");
    for (int i = 0; i < 20; i++) {
        snprintf(out_address + 2 + i * 2, 3, "%02x", new_account.address[i]);
    }

    // Prepare recovery data (private key + public key)
    uint8_t recovery_data[97];  // 32 bytes private key + 65 bytes public key
    memcpy(recovery_data, new_account.private_key, 32);
    memcpy(recovery_data + 32, new_account.public_key, 65);

    // Encrypt recovery data
    uint8_t encrypted_data[384];  // RSA-3072 output size
    size_t encrypted_len = sizeof(encrypted_data);
    sgx_status_t status = rsa_encrypt(recovery_data, sizeof(recovery_data),
                                    modulus_bytes, sizeof(modulus_bytes),
                                    exponent_bytes, sizeof(exponent_bytes),
                                    encrypted_data, &encrypted_len);

    if (status != SGX_SUCCESS) {
        LOG_ERROR_MACRO("[Enclave] generate_account_with_recovery: Failed to encrypt recovery data\n");
        return -1;
    }

    // Save recovery file
    char recovery_filename[256];
    snprintf(recovery_filename, sizeof(recovery_filename), "%s.account.recovery", out_address);
    
    int ret = 0;
    status = ocall_save_to_file(&ret, encrypted_data, encrypted_len, recovery_filename);
    if (status != SGX_SUCCESS || ret != 0) {
        LOG_ERROR_MACRO("[Enclave] generate_account_with_recovery: Failed to save recovery file\n");
        return -1;
    }

    // Save account file
    char account_filename[256];
    snprintf(account_filename, sizeof(account_filename), "%s.account", out_address);
    
    if (save_account_to_pool(out_address, &new_account) != 0) {
        LOG_ERROR_MACRO("[Enclave] generate_account_with_recovery: Failed to save account file\n");
        return -1;
    }

    LOG_INFO_MACRO("[Enclave] generate_account_with_recovery: Success - account %s generated\n", out_address);
    return 0;
}

#ifdef __cplusplus
}
#endif

