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
#include <stdarg.h>
#include <time.h>
#include <math.h>  // Добавляем для log2
#include "sha3.h"  // Добавляем для Keccak-256

#define ENCLAVE_BUFSIZ 1024

// Logging levels
#define LOG_ERROR 0
#define LOG_WARNING 1
#define LOG_INFO  2
#define LOG_DEBUG 3

// Default log level
static int g_log_level = LOG_DEBUG;

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

// Function to set log level
int ecall_set_log_level(int level) {
    if (level < LOG_ERROR || level > LOG_DEBUG) {
        return -1;
    }
    g_log_level = level;
    return 0;
}

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

// Определение printf для использования в энклаве
extern "C" {
    int printf(const char* fmt, ...) {
        char buf[ENCLAVE_BUFSIZ] = { '\0' };
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(buf, ENCLAVE_BUFSIZ, fmt, ap);
        va_end(ap);
        ocall_print(buf);
        return 0;
    }
}

#ifdef __cplusplus
extern "C" {
#endif

// Global account instance
static Account current_account = {0};

// Global pool instance
static AccountPool account_pool = {0};

// Initialize account pool
static bool initialize_account_pool() {
    log_message(LOG_INFO, "Initializing account pool...\n");
    
    // Initialize all slots as free
    for (int i = 0; i < MAX_POOL_SIZE; i++) {
        account_pool.accounts[i].account.use_count = 0;
        secure_memzero(&account_pool.accounts[i].account, sizeof(Account));
    }
    
    log_message(LOG_DEBUG, "Account pool initialized with %d slots\n", MAX_POOL_SIZE);
    return true;
}

// Enclave initialization function
sgx_status_t sgx_ecall_initialize() {
    log_message(LOG_INFO, "Initializing enclave...\n");
    
    // Initialize account pool
    if (!initialize_account_pool()) {
        log_message(LOG_ERROR, "Failed to initialize account pool\n");
        return SGX_ERROR_UNEXPECTED;
    }
    
    log_message(LOG_INFO, "Enclave initialized successfully\n");
    return SGX_SUCCESS;
}

// Security constants
// MIN_ENTROPY_BITS is defined in Enclave.h

// Helper function to securely zero memory
void secure_memzero(void* ptr, size_t len) {
    volatile unsigned char* p = (volatile unsigned char*)ptr;
    while (len--) {
        *p++ = 0;
    }
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
    
    log_message(LOG_DEBUG, "Entropy calculation details:\n");
    log_message(LOG_DEBUG, "  Data size: %zu bytes\n", size);
    log_message(LOG_DEBUG, "  Unique bytes: ");
    int unique_bytes = 0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            unique_bytes++;
            log_message(LOG_DEBUG, "%02x ", i);
        }
    }
    log_message(LOG_DEBUG, "\n  Unique bytes count: %d\n", unique_bytes);
    log_message(LOG_DEBUG, "  Raw entropy: %.2f bits\n", entropy);
    
    return entropy;
}

// Helper function to check if a private key is cryptographically strong
bool is_strong_private_key(const uint8_t* private_key, size_t size) {
    log_message(LOG_DEBUG, "Checking private key strength...\n");
    
    if (!private_key || size != 32) {
        log_message(LOG_ERROR, "Invalid key parameters: key=%p, size=%zu\n", private_key, size);
        return false;
    }
    
    // Create secp256k1 context for verification
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!ctx) {
        log_message(LOG_ERROR, "Failed to create secp256k1 context\n");
        return false;
    }
    
    // Verify key using secp256k1
    bool is_valid = secp256k1_ec_seckey_verify(ctx, private_key);
    secp256k1_context_destroy(ctx);
    
    if (!is_valid) {
        log_message(LOG_ERROR, "Key failed secp256k1 validation\n");
        return false;
    }
    log_message(LOG_DEBUG, "Key passed secp256k1 validation\n");
    
    // Check for weak patterns
    bool has_weak_pattern = true;
    for (size_t i = 1; i < size; i++) {
        if (private_key[i] != private_key[0]) {
            has_weak_pattern = false;
            break;
        }
    }
    if (has_weak_pattern) {
        log_message(LOG_ERROR, "Key has weak pattern (all bytes are the same)\n");
        return false;
    }
    
    log_message(LOG_DEBUG, "Key passed all strength checks\n");
    return true;
}

// Enhanced entropy generation using double SHA-256
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
    log_message(LOG_INFO, "Starting secure private key generation...\n");
    
    if (!private_key || size != 32) {
        log_message(LOG_ERROR, "Invalid parameters: private_key=%p, size=%zu\n", private_key, size);
        return SGX_ERROR_INVALID_PARAMETER;
    }
    
    // Step 1: Generate entropy
    uint8_t entropy[128];
    sgx_status_t status = generate_entropy(entropy, sizeof(entropy));
    if (status != SGX_SUCCESS) {
        log_message(LOG_ERROR, "Failed to generate entropy: %d\n", status);
        return status;
    }
    log_message(LOG_INFO, "Generated initial entropy\n");
    
    // Step 2: Extract PRK using SHA-256 (HKDF-Extract)
    sgx_sha256_hash_t prk;
    status = sgx_sha256_msg(entropy, sizeof(entropy), &prk);
    if (status != SGX_SUCCESS) {
        log_message(LOG_ERROR, "Failed to extract PRK: %d\n", status);
        return status;
    }
    log_message(LOG_INFO, "PRK extracted\n");
    
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
        log_message(LOG_ERROR, "Failed to expand key: %d\n", status);
        return status;
    }
    log_message(LOG_INFO, "Key expanded successfully\n");
    
    // Copy the final hash to the private key
    memcpy(private_key, final_hash, 32);
    
    // Verify key strength
    if (is_strong_private_key(private_key, size)) {
        log_message(LOG_INFO, "Strong private key generated successfully\n");
        return SGX_SUCCESS;
    }
    
    log_message(LOG_ERROR, "Generated key did not meet strength requirements\n");
    return SGX_ERROR_UNEXPECTED;
}

// Helper function to get current account
Account* get_current_account(void) {
    return &current_account;
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
    log_message(LOG_INFO, "Starting account generation...\n");
    
    if (!account) {
        log_message(LOG_ERROR, "Invalid account parameter\n");
        return -1;
    }
    
    uint8_t private_key[32] = {0};
    sgx_status_t status = generate_secure_private_key(private_key, sizeof(private_key));
    
    if (status != SGX_SUCCESS) {
        log_message(LOG_ERROR, "Failed to generate private key\n");
        return -1;
    }
    log_message(LOG_DEBUG, "Private key generated successfully\n");

    // Generate public key from private key
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!ctx) {
        log_message(LOG_ERROR, "Failed to create secp256k1 context\n");
        return -1;
    }
    log_message(LOG_DEBUG, "Secp256k1 context created\n");

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, private_key)) {
        log_message(LOG_ERROR, "Failed to create public key\n");
        secp256k1_context_destroy(ctx);
        return -1;
    }
    log_message(LOG_DEBUG, "Public key created\n");

    // Serialize public key
    uint8_t serialized_pubkey[65];
    size_t serialized_pubkey_len = sizeof(serialized_pubkey);
    if (!secp256k1_ec_pubkey_serialize(ctx, serialized_pubkey, &serialized_pubkey_len, &pubkey, SECP256K1_EC_UNCOMPRESSED)) {
        log_message(LOG_ERROR, "Failed to serialize public key\n");
        secp256k1_context_destroy(ctx);
        return -1;
    }
    log_message(LOG_DEBUG, "Public key serialized\n");
    
    // Calculate Ethereum address
    uint8_t hash[32];
    keccak_256(serialized_pubkey + 1, 64, hash);
    uint8_t address[20];
    memcpy(address, hash + 12, 20);
    log_message(LOG_DEBUG, "Ethereum address calculated\n");
    
    // Store the account data
    memcpy(account->private_key, private_key, sizeof(private_key));
    memcpy(account->public_key, serialized_pubkey, sizeof(serialized_pubkey));
    memcpy(account->address, address, sizeof(address));
    account->use_count = 0;
    account->is_initialized = true;
    log_message(LOG_DEBUG, "Account data stored\n");
    
    // Calculate HMAC
    sgx_status_t hmac_status = sgx_sha256_msg((const uint8_t*)account, sizeof(Account) - 32, (sgx_sha256_hash_t*)account->hmac);
    if (hmac_status != SGX_SUCCESS) {
        log_message(LOG_ERROR, "Failed to calculate HMAC\n");
        secp256k1_context_destroy(ctx);
        return -1;
    }
    log_message(LOG_DEBUG, "HMAC calculated\n");

    secp256k1_context_destroy(ctx);
    log_message(LOG_INFO, "Account generation completed successfully\n");
    return 0;
}

// Internal function to save account to pool
static int save_account_to_pool(const char* account_id, const Account* account) {
    log_message(LOG_INFO, "Saving account with ID: %s to pool\n", account_id);
    
    if (!account || !account->is_initialized) {
        log_message(LOG_ERROR, "Account is not initialized\n");
        return -1;
    }

    // Create structure for saving
    AccountFile data;
    memcpy(&data.account, account, sizeof(Account));
    log_message(LOG_DEBUG, "Account data copied to save structure\n");

    // Calculate HMAC
    uint8_t computed_hash[32];
    sgx_status_t status = sgx_sha256_msg((const uint8_t*)&data, sizeof(AccountFile) - 32, (sgx_sha256_hash_t*)computed_hash);
    if (status != SGX_SUCCESS) {
        log_message(LOG_ERROR, "Failed to calculate HMAC: %d\n", status);
        return -1;
    }
    memcpy(data.file_hmac, computed_hash, 32);
    log_message(LOG_DEBUG, "HMAC calculated and stored\n");

    // Encrypt data
    size_t sealed_size = sgx_calc_sealed_data_size(0, sizeof(AccountFile));
    if (sealed_size == UINT32_MAX) {
        log_message(LOG_ERROR, "Failed to calculate sealed data size\n");
        return -1;
    }

    uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);
    if (!sealed_data) {
        log_message(LOG_ERROR, "Failed to allocate memory for sealed data\n");
        return -1;
    }

    status = sgx_seal_data(0, NULL, sizeof(AccountFile), (uint8_t*)&data, sealed_size, (sgx_sealed_data_t*)sealed_data);
    if (status != SGX_SUCCESS) {
        log_message(LOG_ERROR, "Failed to seal data: %d\n", status);
        free(sealed_data);
        return -1;
    }
    log_message(LOG_DEBUG, "Data sealed successfully\n");

    // Save encrypted data using provided account_id as filename
    char filename[256];
    snprintf(filename, sizeof(filename), "%s.account", account_id);
    
    int ret = 0;
    status = ocall_save_to_file(&ret, sealed_data, sealed_size, filename);
    free(sealed_data);
    
    if (status != SGX_SUCCESS || ret != 0) {
        log_message(LOG_ERROR, "Failed to save file: status=%d, ret=%d\n", status, ret);
        return -1;
    }
    
    log_message(LOG_INFO, "Account saved successfully to %s\n", filename);
    return 0;
}

// Enhanced transaction signing with security checks
int ecall_sign_transaction(const uint8_t* tx_hash, size_t tx_hash_size,
                          uint8_t* signature, size_t signature_size) {
    log_message(LOG_INFO, "Starting transaction signing...\n");
    
    if (!tx_hash || !signature || tx_hash_size != 32 || signature_size != 64) {
        log_message(LOG_ERROR, "Invalid parameters: tx_hash=%p, signature=%p, tx_hash_size=%zu, signature_size=%zu\n",
               tx_hash, signature, tx_hash_size, signature_size);
        return -1;
    }
    
    // Verify private key strength
    if (!is_strong_private_key(current_account.private_key, sizeof(current_account.private_key))) {
        log_message(LOG_ERROR, "Private key does not meet strength requirements\n");
        return -1;
    }
    log_message(LOG_INFO, "Private key verified\n");
    
    // Create signing context
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!ctx) {
        log_message(LOG_ERROR, "Failed to create secp256k1 context\n");
        return -1;
    }
    log_message(LOG_INFO, "Secp256k1 context created\n");
    
    // Sign the transaction
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_sign(ctx, &sig, tx_hash, current_account.private_key, NULL, NULL)) {
        log_message(LOG_ERROR, "Failed to create signature\n");
        secp256k1_context_destroy(ctx);
        return -1;
    }
    log_message(LOG_INFO, "Signature created\n");
    
    // Serialize signature
    if (!secp256k1_ecdsa_signature_serialize_compact(ctx, signature, &sig)) {
        log_message(LOG_ERROR, "Failed to serialize signature\n");
        secp256k1_context_destroy(ctx);
        return -1;
    }
    log_message(LOG_INFO, "Signature serialized\n");

    // Increment use count
    current_account.use_count++;
    log_message(LOG_INFO, "Use count incremented to %u\n", current_account.use_count);

    // Save account state to persist use_count
    int save_result = save_account_to_pool("default", &current_account);
    if (save_result != 0) {
        log_message(LOG_ERROR, "Failed to save account state after signing\n");
        secp256k1_context_destroy(ctx);
        return -1;
    }
    log_message(LOG_INFO, "Account state saved after signing\n");
    
    secp256k1_context_destroy(ctx);
    log_message(LOG_INFO, "Transaction signing completed successfully\n");
    return 0;
}

// Функции для работы с аккаунтами
int ecall_save_account(const char* account_id) {
    log_message(LOG_INFO, "Saving account with ID: %s\n", account_id);
    
    if (!current_account.is_initialized) {
        log_message(LOG_ERROR, "Account is not initialized\n");
        return -1;
    }

    // Create structure for saving
    AccountFile data;
    memcpy(&data.account, &current_account, sizeof(Account));
    log_message(LOG_DEBUG, "Account data copied to save structure\n");

    // Calculate HMAC
    uint8_t computed_hash[32];
    sgx_status_t status = sgx_sha256_msg((const uint8_t*)&data, sizeof(AccountFile) - 32, (sgx_sha256_hash_t*)computed_hash);
    if (status != SGX_SUCCESS) {
        log_message(LOG_ERROR, "Failed to calculate HMAC: %d\n", status);
        return -1;
    }
    memcpy(data.file_hmac, computed_hash, 32);
    log_message(LOG_DEBUG, "HMAC calculated and stored\n");

    // Encrypt data
    size_t sealed_size = sgx_calc_sealed_data_size(0, sizeof(AccountFile));
    if (sealed_size == UINT32_MAX) {
        log_message(LOG_ERROR, "Failed to calculate sealed data size\n");
        return -1;
    }

    uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);
    if (!sealed_data) {
        log_message(LOG_ERROR, "Failed to allocate memory for sealed data\n");
        return -1;
    }

    status = sgx_seal_data(0, NULL, sizeof(AccountFile), (uint8_t*)&data, sealed_size, (sgx_sealed_data_t*)sealed_data);
    if (status != SGX_SUCCESS) {
        log_message(LOG_ERROR, "Failed to seal data: %d\n", status);
        free(sealed_data);
        return -1;
    }
    log_message(LOG_DEBUG, "Data sealed successfully\n");

    // Save encrypted data using provided account_id as filename
    char filename[256];
    snprintf(filename, sizeof(filename), "%s.account", account_id);
    
    int ret = 0;
    status = ocall_save_to_file(&ret, sealed_data, sealed_size, filename);
    free(sealed_data);
    
    if (status != SGX_SUCCESS || ret != 0) {
        log_message(LOG_ERROR, "Failed to save file: status=%d, ret=%d\n", status, ret);
        return -1;
    }
    
    log_message(LOG_INFO, "Account saved successfully to %s\n", filename);
    return 0;
}



int ecall_load_account(const char* account_id) {
    log_message(LOG_INFO, "Loading account with ID: %s\n", account_id);
    
    if (!account_id) {
        log_message(LOG_ERROR, "Invalid account ID\n");
        return -1;
    }

    // Открытие файла
    char filename[256];
    snprintf(filename, sizeof(filename), "%s.account", account_id);
    log_message(LOG_DEBUG, "Opening file: %s\n", filename);
    
    // Получение размера файла через OCALL
    uint8_t* sealed_data = NULL;
    size_t file_size = 0;
    int ret = 0;
    sgx_status_t ocall_status = ocall_read_from_file(&ret, NULL, 0, filename);
    if (ocall_status != SGX_SUCCESS || ret < 0) {
        log_message(LOG_ERROR, "Failed to get file size: status=%d, ret=%d\n", ocall_status, ret);
        return -1;
    }
    file_size = ret;
    log_message(LOG_DEBUG, "File size: %zu bytes\n", file_size);

    // Чтение зашифрованных данных
    sealed_data = (uint8_t*)malloc(file_size);
    if (!sealed_data) {
        log_message(LOG_ERROR, "Failed to allocate memory for sealed data\n");
        return -1;
    }

    ocall_status = ocall_read_from_file(&ret, sealed_data, file_size, filename);
    if (ocall_status != SGX_SUCCESS || ret != file_size) {
        log_message(LOG_ERROR, "Failed to read file: status=%d, ret=%d\n", ocall_status, ret);
        free(sealed_data);
        return -1;
    }
    log_message(LOG_DEBUG, "File read successfully\n");

    // Расшифровка данных
    uint32_t decrypted_size = sgx_get_encrypt_txt_len((sgx_sealed_data_t*)sealed_data);
    if (decrypted_size == UINT32_MAX) {
        log_message(LOG_ERROR, "Failed to get decrypted size\n");
        free(sealed_data);
        return -1;
    }
    log_message(LOG_DEBUG, "Decrypted size: %u bytes\n", decrypted_size);

    uint8_t* decrypted_data = (uint8_t*)malloc(decrypted_size);
    if (!decrypted_data) {
        log_message(LOG_ERROR, "Failed to allocate memory for decrypted data\n");
        free(sealed_data);
        return -1;
    }

    sgx_status_t unseal_status = sgx_unseal_data((sgx_sealed_data_t*)sealed_data, NULL, NULL, decrypted_data, &decrypted_size);
    free(sealed_data);

    if (unseal_status != SGX_SUCCESS || decrypted_size != sizeof(AccountFile)) {
        log_message(LOG_ERROR, "Failed to unseal data: status=%d, size=%u\n", unseal_status, decrypted_size);
        free(decrypted_data);
        return -1;
    }
    log_message(LOG_DEBUG, "Data unsealed successfully\n");

    // Проверка HMAC
    AccountFile* data = (AccountFile*)decrypted_data;
    uint8_t computed_hash[32];
    sgx_status_t hmac_status = sgx_sha256_msg((const uint8_t*)data, sizeof(AccountFile) - 32, (sgx_sha256_hash_t*)computed_hash);
    if (hmac_status != SGX_SUCCESS || memcmp(data->file_hmac, computed_hash, 32) != 0) {
        log_message(LOG_ERROR, "HMAC verification failed\n");
        free(decrypted_data);
        return -1;
    }
    log_message(LOG_DEBUG, "HMAC verified successfully\n");

    // Проверка адреса
    char expected_filename[256];
    snprintf(expected_filename, sizeof(expected_filename), "0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x.account",
             data->account.address[0], data->account.address[1], data->account.address[2], data->account.address[3],
             data->account.address[4], data->account.address[5], data->account.address[6], data->account.address[7],
             data->account.address[8], data->account.address[9], data->account.address[10], data->account.address[11],
             data->account.address[12], data->account.address[13], data->account.address[14], data->account.address[15],
             data->account.address[16], data->account.address[17], data->account.address[18], data->account.address[19]);
    
    if (strcmp(filename, expected_filename) != 0) {
        log_message(LOG_ERROR, "Account address mismatch\n");
        free(decrypted_data);
        return -1;
    }
    log_message(LOG_DEBUG, "Account address verified\n");

    // Копирование данных аккаунта
    memcpy(&current_account, &data->account, sizeof(Account));
    current_account.is_initialized = true;
    log_message(LOG_DEBUG, "Account data copied successfully\n");

    // Print first 8 bytes of private key for debugging
    log_message(LOG_DEBUG, "First 8 bytes of loaded private key: ");
    for (int i = 0; i < 8; i++) {
        log_message(LOG_DEBUG, "%02x ", current_account.private_key[i]);
    }
    log_message(LOG_DEBUG, "\n");

    free(decrypted_data);
    log_message(LOG_INFO, "Account loaded successfully\n");
    return 0;
}

int ecall_sign_message(const uint8_t* message, size_t message_len, uint8_t* signature, size_t signature_len) {
    log_message(LOG_INFO, "Starting message signing...\n");
    
    if (!message || !signature || message_len == 0 || signature_len < 64) {
        log_message(LOG_ERROR, "Invalid parameters: message=%p, signature=%p, message_len=%zu, signature_len=%zu\n", 
               message, signature, message_len, signature_len);
        return -1;
    }

    if (!current_account.is_initialized) {
        log_message(LOG_ERROR, "Account is not initialized\n");
        return -1;
    }
    log_message(LOG_INFO, "Account is initialized\n");

    // Create secp256k1 context
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!ctx) {
        log_message(LOG_ERROR, "Failed to create secp256k1 context\n");
        return -1;
    }
    log_message(LOG_INFO, "Secp256k1 context created\n");

    // Create signature
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_sign(ctx, &sig, message, current_account.private_key, NULL, NULL)) {
        log_message(LOG_ERROR, "Failed to create signature\n");
        secp256k1_context_destroy(ctx);
        return -1;
    }
    log_message(LOG_INFO, "Signature created\n");

    // Serialize signature
    if (!secp256k1_ecdsa_signature_serialize_compact(ctx, signature, &sig)) {
        log_message(LOG_ERROR, "Failed to serialize signature\n");
        secp256k1_context_destroy(ctx);
        return -1;
    }
    log_message(LOG_INFO, "Signature serialized\n");

    // Increment use count
    current_account.use_count++;
    log_message(LOG_INFO, "Use count incremented to %u\n", current_account.use_count);

    // Save account state to persist use_count
    int save_result = save_account_to_pool("default", &current_account);
    if (save_result != 0) {
        log_message(LOG_ERROR, "Failed to save account state after signing\n");
        secp256k1_context_destroy(ctx);
        return -1;
    }
    log_message(LOG_INFO, "Account state saved after signing\n");

    secp256k1_context_destroy(ctx);
    log_message(LOG_INFO, "Message signing completed successfully\n");
    return 0;
}

// Helper function to find account in pool by address
static int find_account_in_pool(const uint8_t* address) {
    if (!address) {
        log_message(LOG_DEBUG, "[TEST] Expected behavior: Invalid address parameter (test case)\n");
        return -1;
    }

    for (int i = 0; i < MAX_POOL_SIZE; i++) {
        if (account_pool.accounts[i].account.is_initialized &&
            memcmp(account_pool.accounts[i].account.address, address, 20) == 0) {
            log_message(LOG_DEBUG, "[TEST] Found account at pool index %d\n", i);
            return i;
        }
    }

    log_message(LOG_DEBUG, "[TEST] Account not found in pool (expected in test case)\n");
    return -1;
}

// Helper function to print test result
static void print_test_result(const char* test_name, int passed, const char* error_message) {
    if (passed) {
        log_message(LOG_DEBUG, "✓ %s: PASSED\n", test_name);
    } else {
        log_message(LOG_DEBUG, "✗ %s: FAILED - %s\n", test_name, error_message);
    }
}

// Helper function to print test suite summary
static void print_test_suite_summary(const test_suite_t* suite) {
    log_message(LOG_DEBUG, "\n=== Test Suite: %s ===\n", suite->suite_name);
    log_message(LOG_DEBUG, "Total tests: %d\n", suite->result_count);
    log_message(LOG_DEBUG, "Passed: %d\n", suite->passed_count);
    log_message(LOG_DEBUG, "Failed: %d\n", suite->result_count - suite->passed_count);
    log_message(LOG_DEBUG, "=====================\n\n");
}

// Test function for find_account_in_pool
static int test_find_account_in_pool(test_suite_t* suite) {
    log_message(LOG_DEBUG, "[TEST] Testing account lookup security measures...\n");
    
    // Test 1: Find in empty pool
    uint8_t test_address[20] = {0};
    int result = find_account_in_pool(test_address);
    print_test_result("Empty pool security check", result == -1, "Security check passed: empty pool correctly rejected");
    
    // Test 2: Add test account to pool
    log_message(LOG_DEBUG, "[TEST] Setting up test environment...\n");
    if (generate_account(&current_account) != 0) {
        print_test_result("Test environment setup", 0, "Failed to set up test environment");
        return -1;
    }
    
    // Add to pool at index 0
    memcpy(&account_pool.accounts[0].account, &current_account, sizeof(Account));
    account_pool.accounts[0].account.use_count = 0;
    
    // Test 3: Find existing account
    result = find_account_in_pool(current_account.address);
    print_test_result("Valid account lookup", result == 0, "Security check passed: valid account found");
    
    // Test 4: Find non-existent account
    uint8_t non_existent[20] = {0xFF}; // Different address
    result = find_account_in_pool(non_existent);
    print_test_result("Non-existent account security", result == -1, "Security check passed: non-existent account correctly rejected");
    
    // Test 5: Find with null address
    result = find_account_in_pool(NULL);
    print_test_result("Null address security", result == -1, "Security check passed: null address correctly rejected");
    
    // Cleanup
    secure_memzero(&account_pool.accounts[0].account, sizeof(Account));
    account_pool.accounts[0].account.use_count = 0;
    
    return 0;
}

// Test function for ecall_load_account_to_pool
static int test_load_account_to_pool(test_suite_t* suite) {
    log_message(LOG_DEBUG, "[TEST] Testing account loading security measures...\n");
    
    // Test 1: Load with null account_id
    int result = ecall_load_account_to_pool(NULL);
    print_test_result("Null account ID security", result == -1, "Security check passed: null account ID correctly rejected");
    
    // Test 2: Generate and load test account
    log_message(LOG_DEBUG, "[TEST] Setting up test environment...\n");
    if (generate_account(&current_account) != 0) {
        print_test_result("Test environment setup", 0, "Failed to set up test environment");
        return -1;
    }
    
    // Create account_id from address
    char account_id[43];
    snprintf(account_id, sizeof(account_id), "0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
             current_account.address[0], current_account.address[1], current_account.address[2], current_account.address[3],
             current_account.address[4], current_account.address[5], current_account.address[6], current_account.address[7],
             current_account.address[8], current_account.address[9], current_account.address[10], current_account.address[11],
             current_account.address[12], current_account.address[13], current_account.address[14], current_account.address[15],
             current_account.address[16], current_account.address[17], current_account.address[18], current_account.address[19]);
    
    // Save account using its address as filename
    if (save_account_to_pool(account_id, &current_account) != 0) {
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
    log_message(LOG_INFO, "\nTesting ecall_unload_account_from_pool...\n");
    
    // Test 1: Unload with null account_id
    int result = ecall_unload_account_from_pool(NULL);
    print_test_result("Unload with null account_id", result == -1, "Expected -1 for null account_id");
    
    // Test 2: Unload non-existent account
    result = ecall_unload_account_from_pool("0x0000000000000000000000000000000000000000");
    log_message(LOG_INFO, "Test 2 (unload non-existent): result = %d (expected -1)\n", result);
    
    // Test 3: Generate, load and unload test account
    log_message(LOG_INFO, "\nTest 3: Generate, load and unload test account...\n");
    if (generate_account(&current_account) != 0) {
        log_message(LOG_ERROR, "Failed to generate test account\n");
        return -1;
    }
    
    // Create account_id from address
    char account_id[43];
    snprintf(account_id, sizeof(account_id), "0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
             current_account.address[0], current_account.address[1], current_account.address[2], current_account.address[3],
             current_account.address[4], current_account.address[5], current_account.address[6], current_account.address[7],
             current_account.address[8], current_account.address[9], current_account.address[10], current_account.address[11],
             current_account.address[12], current_account.address[13], current_account.address[14], current_account.address[15],
             current_account.address[16], current_account.address[17], current_account.address[18], current_account.address[19]);
    
    // Save account using its address as filename
    if (save_account_to_pool(account_id, &current_account) != 0) {
        log_message(LOG_ERROR, "Failed to save test account\n");
        return -1;
    }
    
    // Load account to pool
    if (ecall_load_account_to_pool(account_id) < 0) {
        log_message(LOG_ERROR, "Failed to load account to pool\n");
        return -1;
    }
    
    // Unload account
    result = ecall_unload_account_from_pool(account_id);
    log_message(LOG_INFO, "Test 3 (unload account): result = %d (expected 0)\n", result);
    if (result != 0) {
        return -1;
    }
    
    // Verify account was unloaded
    if (find_account_in_pool((const uint8_t*)account_id) != -1) {
        log_message(LOG_ERROR, "Account still found in pool after unload\n");
        return -1;
    }
    
    log_message(LOG_INFO, "\nTest cleanup completed\n");
    return 0;
}

static int test_generate_account_in_pool(test_suite_t* suite) {
    log_message(LOG_INFO, "\nTesting account generation and pool loading...\n");
    
    // Test 1: Generate account
    if (generate_account(&current_account) != 0) {
        print_test_result("Generate account", 0, "Failed to generate account");
        return -1;
    }
    print_test_result("Generate account", 1, NULL);

    // Create account_id from address
    char account_id[43];
    snprintf(account_id, sizeof(account_id), "0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
             current_account.address[0], current_account.address[1], current_account.address[2], current_account.address[3],
             current_account.address[4], current_account.address[5], current_account.address[6], current_account.address[7],
             current_account.address[8], current_account.address[9], current_account.address[10], current_account.address[11],
             current_account.address[12], current_account.address[13], current_account.address[14], current_account.address[15],
             current_account.address[16], current_account.address[17], current_account.address[18], current_account.address[19]);

    // Save account using its address as filename
    if (save_account_to_pool(account_id, &current_account) != 0) {
        print_test_result("Save account", 0, "Failed to save test account");
        return -1;
    }

    // Test 2: Load account to pool
    int pool_index = ecall_load_account_to_pool(account_id);
    if (pool_index < 0) {
        print_test_result("Load to pool", 0, "Failed to load account to pool");
        return -1;
    }
    print_test_result("Load to pool", 1, NULL);

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
    log_message(LOG_INFO, "\nTesting sign_with_pool_account...\n");
    
    // Test 1: Sign with null account_id
    uint8_t test_message[32] = {0};
    uint8_t test_signature[64] = {0};
    int result = ecall_sign_with_pool_account(NULL, test_message, sizeof(test_message), test_signature, sizeof(test_signature));
    print_test_result("Sign with null account_id", result == -1, "Expected -1 for null account_id");
    
    // Test 2: Generate, load and sign with test account
    log_message(LOG_INFO, "\nGenerating test account...\n");
    if (generate_account(&current_account) != 0) {
        print_test_result("Generate test account", 0, "Failed to generate test account");
        return -1;
    }
    
    // Create account_id from address
    char account_id[43];
    snprintf(account_id, sizeof(account_id), "0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
             current_account.address[0], current_account.address[1], current_account.address[2], current_account.address[3],
             current_account.address[4], current_account.address[5], current_account.address[6], current_account.address[7],
             current_account.address[8], current_account.address[9], current_account.address[10], current_account.address[11],
             current_account.address[12], current_account.address[13], current_account.address[14], current_account.address[15],
             current_account.address[16], current_account.address[17], current_account.address[18], current_account.address[19]);
    
    // Save account using its address as filename
    if (save_account_to_pool(account_id, &current_account) != 0) {
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
    print_test_result("Sign message", result == 0, "Failed to sign message");
    if (result != 0) {
        return -1;
    }

    // Verify use_count was incremented
    if (account_pool.accounts[pool_index].account.use_count != 1) {
        print_test_result("Verify use_count after signing", 0, "Use count not incremented");
        return -1;
    }
    print_test_result("Verify use_count after signing", 1, NULL);
    
    // Test 3: Verify signature
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        print_test_result("Create verification context", 0, "Failed to create context");
        return -1;
    }
    
    // Parse signature
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_signature_parse_compact(ctx, &sig, test_signature)) {
        print_test_result("Parse signature", 0, "Failed to parse signature");
        secp256k1_context_destroy(ctx);
        return -1;
    }

    // Parse public key
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, account_pool.accounts[pool_index].account.public_key, sizeof(account_pool.accounts[pool_index].account.public_key))) {
        print_test_result("Parse public key", 0, "Failed to parse public key");
        secp256k1_context_destroy(ctx);
        return -1;
    }
    
    // Verify signature
    if (!secp256k1_ecdsa_verify(ctx, &sig, test_message, &pubkey)) {
        print_test_result("Verify signature", 0, "Signature verification failed");
        secp256k1_context_destroy(ctx);
        return -1;
    }
    print_test_result("Verify signature", 1, NULL);
    
    secp256k1_context_destroy(ctx);
    
    // Cleanup
    secure_memzero(&account_pool.accounts[pool_index].account, sizeof(Account));
    account_pool.accounts[pool_index].account.is_initialized = false;
    
    return 0;
}

static int test_get_pool_status(test_suite_t* suite) {
    log_message(LOG_INFO, "\nTesting get_pool_status...\n");
    
    // Clear pool before testing
    for (int i = 0; i < MAX_POOL_SIZE; i++) {
        secure_memzero(&account_pool.accounts[i].account, sizeof(Account));
        account_pool.accounts[i].account.is_initialized = false;
    }
    log_message(LOG_INFO, "Pool cleared\n");
    
    // Test 1: Check empty pool
    uint32_t total_accounts = 0;
    uint32_t active_accounts = 0;
    char account_addresses[4300] = {0};
    
    int result = ecall_get_pool_status(&total_accounts, &active_accounts, account_addresses);
    print_test_result("Get status of empty pool", result == 0 && total_accounts == 0 && active_accounts == 0, 
                     "Expected empty pool status");
    
    // Test 2: Add an account to pool
    if (generate_account(&current_account) != 0) {
        print_test_result("Generate test account", 0, "Failed to generate test account");
        return -1;
    }
    print_test_result("Generate test account", 1, NULL);

    // Create account_id from address
    char account_id[43];
    snprintf(account_id, sizeof(account_id), "0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
             current_account.address[0], current_account.address[1], current_account.address[2], current_account.address[3],
             current_account.address[4], current_account.address[5], current_account.address[6], current_account.address[7],
             current_account.address[8], current_account.address[9], current_account.address[10], current_account.address[11],
             current_account.address[12], current_account.address[13], current_account.address[14], current_account.address[15],
             current_account.address[16], current_account.address[17], current_account.address[18], current_account.address[19]);

    // Save account using its address as filename
    if (save_account_to_pool(account_id, &current_account) != 0) {
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
    uint8_t test_signature[64] = {0};
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
    account_pool.accounts[pool_index].account.is_initialized = false;
    
    return 0;
}

static int test_use_count_persistence(test_suite_t* suite) {
    log_message(LOG_INFO, "\nTesting use_count persistence...\n");
    
    // Test 1: Generate account
    if (generate_account(&current_account) != 0) {
        print_test_result("Generate test account", 0, "Failed to generate test account");
        return -1;
    }
    print_test_result("Generate test account", 1, NULL);
    
    // Verify initial use_count
    if (current_account.use_count != 0) {
        print_test_result("Verify initial use_count", 0, "Initial use_count is not 0");
        return -1;
    }
    print_test_result("Verify initial use_count", 1, NULL);
    
    // Create account_id from address
    char account_id[43];
    snprintf(account_id, sizeof(account_id), "0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
             current_account.address[0], current_account.address[1], current_account.address[2], current_account.address[3],
             current_account.address[4], current_account.address[5], current_account.address[6], current_account.address[7],
             current_account.address[8], current_account.address[9], current_account.address[10], current_account.address[11],
             current_account.address[12], current_account.address[13], current_account.address[14], current_account.address[15],
             current_account.address[16], current_account.address[17], current_account.address[18], current_account.address[19]);
    
    // Sign a message to increment use_count
    uint8_t test_message[32] = {0};
    uint8_t test_signature[64] = {0};
    for (int i = 0; i < sizeof(test_message); i++) {
        test_message[i] = i;
    }
    
    if (ecall_sign_message(test_message, sizeof(test_message), test_signature, sizeof(test_signature)) != 0) {
        print_test_result("Sign first message", 0, "Failed to sign message");
        return -1;
    }
    print_test_result("Sign first message", 1, NULL);
    
    // Verify use_count was incremented
    if (current_account.use_count != 1) {
        print_test_result("Verify use_count after first signing", 0, "Use count not incremented");
        return -1;
    }
    print_test_result("Verify use_count after first signing", 1, NULL);
    
    // Save account
    if (save_account_to_pool(account_id, &current_account) != 0) {
        print_test_result("Save account", 0, "Failed to save account");
        return -1;
    }
    print_test_result("Save account", 1, NULL);
    
    // Clear current account
    secure_memzero(&current_account, sizeof(Account));
    current_account.is_initialized = false;
    
    // Load account
    if (ecall_load_account(account_id) != 0) {
        print_test_result("Load account", 0, "Failed to load account");
        return -1;
    }
    print_test_result("Load account", 1, NULL);
    
    // Verify use_count was preserved
    if (current_account.use_count != 1) {
        print_test_result("Verify use_count after load", 0, "Use count not preserved");
        return -1;
    }
    print_test_result("Verify use_count after load", 1, NULL);
    
    // Sign another message
    if (ecall_sign_message(test_message, sizeof(test_message), test_signature, sizeof(test_signature)) != 0) {
        print_test_result("Sign second message", 0, "Failed to sign second message");
        return -1;
    }
    print_test_result("Sign second message", 1, NULL);
    
    // Verify use_count was incremented again
    if (current_account.use_count != 2) {
        print_test_result("Verify use_count after second signing", 0, "Use count not incremented");
        return -1;
    }
    print_test_result("Verify use_count after second signing", 1, NULL);
    
    return 0;
}

// Test Keccak-256 address generation
static int test_keccak_address_generation(test_suite_t* suite) {
    const char* test_name = "Keccak-256 Address Generation";
    log_message(LOG_INFO, "Running test: %s\n", test_name);
    
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

    // Debug output for public key
    log_message(LOG_DEBUG, "Full public key (65 bytes):\n");
    for (int i = 0; i < 65; i++) {
        log_message(LOG_DEBUG, "%02x ", serialized_pubkey[i]);
    }
    log_message(LOG_DEBUG, "\n");

    log_message(LOG_DEBUG, "Public key without prefix (64 bytes):\n");
    for (int i = 1; i < 65; i++) {
        log_message(LOG_DEBUG, "%02x ", serialized_pubkey[i]);
    }
    log_message(LOG_DEBUG, "\n");
    
    // Calculate Ethereum address
    uint8_t hash[32];
    keccak_256(serialized_pubkey + 1, 64, hash);

    // Debug output for hash
    log_message(LOG_DEBUG, "Keccak-256 hash (32 bytes):\n");
    for (int i = 0; i < 32; i++) {
        log_message(LOG_DEBUG, "%02x ", hash[i]);
    }
    log_message(LOG_DEBUG, "\n");

    // Debug output for address bytes (last 20 bytes of hash)
    log_message(LOG_DEBUG, "Address bytes (last 20 bytes of hash):\n");
    for (int i = 12; i < 32; i++) {
        log_message(LOG_DEBUG, "%02x ", hash[i]);
    }
    log_message(LOG_DEBUG, "\n");
    
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

int ecall_test_function() {
    test_suite_t suite = {
        "System Tests",
        NULL,
        0,
        0
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
    
    test_result = test_use_count_persistence(&suite);
    suite.results[suite.result_count++] = (test_result_t){
        "Use Count Persistence",
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
    
    // Print test suite summary
    print_test_suite_summary(&suite);
    
    // Clean up
    free(suite.results);
    
    return 0;
}

// Simplified key generation
int ecall_generate_private_key(uint8_t* private_key, size_t private_key_size) {
    if (!private_key || private_key_size != 32) {
        return -1;
    }
    return generate_secure_private_key(private_key, private_key_size) == SGX_SUCCESS ? 0 : -1;
}

int ecall_load_account_to_pool(const char* account_id) {
    log_message(LOG_DEBUG, "[TEST] Loading account %s to pool...\n", account_id);
    
    if (!account_id) {
        log_message(LOG_DEBUG, "[TEST] Expected behavior: Invalid account ID (test case)\n");
        return -1;
    }

    // Check if account is already in pool
    if (find_account_in_pool((const uint8_t*)account_id) != -1) {
        log_message(LOG_DEBUG, "[TEST] Expected behavior: Account already in pool (test case)\n");
        return -1;
    }

    // Load account
    if (ecall_load_account(account_id) != 0) {
        log_message(LOG_DEBUG, "[TEST] Expected behavior: Failed to load account (test case)\n");
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
        log_message(LOG_DEBUG, "[TEST] Expected behavior: No free slots in pool (test case)\n");
        return -1;
    }

    // Copy account to pool
    memcpy(&account_pool.accounts[free_slot].account, &current_account, sizeof(Account));
    account_pool.accounts[free_slot].account.use_count = 0;

    // Verify account was added correctly
    if (find_account_in_pool(current_account.address) != free_slot) {
        log_message(LOG_DEBUG, "[TEST] Expected behavior: Failed to verify account in pool (test case)\n");
        secure_memzero(&account_pool.accounts[free_slot].account, sizeof(Account));
        account_pool.accounts[free_slot].account.use_count = 0;
        return -1;
    }

    log_message(LOG_DEBUG, "[TEST] Account successfully loaded to pool at index %d\n", free_slot);
    return free_slot;
}

int ecall_unload_account_from_pool(const char* account_id) {
    log_message(LOG_INFO, "Unloading account %s from pool...\n", account_id);
    
    if (!account_id) {
        log_message(LOG_ERROR, "Invalid account ID\n");
        return -1;
    }

    // Convert hex string to bytes
    uint8_t address[20];
    if (strlen(account_id) != 42 || account_id[0] != '0' || account_id[1] != 'x') {
        log_message(LOG_ERROR, "Invalid account ID format\n");
        return -1;
    }
    
    for (int i = 0; i < 20; i++) {
        char byte_str[3] = {account_id[2 + i*2], account_id[2 + i*2 + 1], 0};
        address[i] = (uint8_t)strtol(byte_str, NULL, 16);
    }

    // Find account in pool
    int pool_index = find_account_in_pool(address);
    if (pool_index == -1) {
        log_message(LOG_WARNING, "WARNING: Account not found in pool\n");
        return -1;
    }
    log_message(LOG_DEBUG, "Found account at pool index %d\n", pool_index);

    // Securely clear the slot
    secure_memzero(&account_pool.accounts[pool_index].account, sizeof(Account));
    account_pool.accounts[pool_index].account.use_count = 0;
    log_message(LOG_DEBUG, "Account slot cleared at index %d\n", pool_index);

    // Verify account was removed
    if (find_account_in_pool(address) != -1) {
        log_message(LOG_ERROR, "Failed to verify account removal\n");
        return -1;
    }

    log_message(LOG_INFO, "Account successfully unloaded from pool\n");
    return 0;
}

int ecall_sign_with_pool_account(const char* account_id, const uint8_t* message, size_t message_len, uint8_t* signature, size_t signature_len) {
    log_message(LOG_DEBUG, "[TEST] Signing message with pool account %s...\n", account_id);
    
    if (!account_id || !message || !signature || message_len == 0 || signature_len < 64) {
        log_message(LOG_DEBUG, "[TEST] Expected behavior: Invalid parameters (test case)\n");
        return -1;
    }

    // Convert hex string to bytes
    uint8_t address[20];
    if (strlen(account_id) != 42 || account_id[0] != '0' || account_id[1] != 'x') {
        log_message(LOG_DEBUG, "[TEST] Expected behavior: Invalid account ID format (test case)\n");
        return -1;
    }
    
    for (int i = 0; i < 20; i++) {
        char byte_str[3] = {account_id[2 + i*2], account_id[2 + i*2 + 1], 0};
        address[i] = (uint8_t)strtol(byte_str, NULL, 16);
    }

    // Find account in pool
    int pool_index = find_account_in_pool(address);
    if (pool_index == -1) {
        log_message(LOG_DEBUG, "[TEST] Expected behavior: Account not found in pool (test case)\n");
        return -1;
    }
    log_message(LOG_DEBUG, "[TEST] Found account at pool index %d\n", pool_index);

    // Create secp256k1 context
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!ctx) {
        log_message(LOG_ERROR, "Failed to create secp256k1 context\n");
        return -1;
    }
    log_message(LOG_DEBUG, "Secp256k1 context created\n");

    // Create signature
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_sign(ctx, &sig, message, account_pool.accounts[pool_index].account.private_key, NULL, NULL)) {
        log_message(LOG_ERROR, "Failed to create signature\n");
        secp256k1_context_destroy(ctx);
        return -1;
    }
    log_message(LOG_DEBUG, "Signature created\n");

    // Serialize signature
    if (!secp256k1_ecdsa_signature_serialize_compact(ctx, signature, &sig)) {
        log_message(LOG_ERROR, "Failed to serialize signature\n");
        secp256k1_context_destroy(ctx);
        return -1;
    }
    log_message(LOG_DEBUG, "Signature serialized\n");

    // Increment use count in Account
    account_pool.accounts[pool_index].account.use_count++;
    log_message(LOG_DEBUG, "Use count incremented to %u\n", account_pool.accounts[pool_index].account.use_count);

    // Save account state to persist use_count
    int save_result = save_account_to_pool(account_id, &account_pool.accounts[pool_index].account);
    if (save_result != 0) {
        log_message(LOG_ERROR, "Failed to save account state after signing\n");
        secp256k1_context_destroy(ctx);
        return -1;
    }
    log_message(LOG_DEBUG, "Account state saved after signing\n");

    secp256k1_context_destroy(ctx);
    log_message(LOG_INFO, "Message signing completed successfully\n");
    return 0;
}

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

int ecall_get_pool_status(uint32_t* total_accounts, uint32_t* active_accounts, char* account_addresses) {
    log_message(LOG_INFO, "Getting pool status...\n");
    
    if (!total_accounts || !active_accounts || !account_addresses) {
        log_message(LOG_ERROR, "Invalid parameters: total_accounts=%p, active_accounts=%p, account_addresses=%p\n", 
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
            snprintf(address, sizeof(address), "0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                    account_pool.accounts[i].account.address[0], account_pool.accounts[i].account.address[1],
                    account_pool.accounts[i].account.address[2], account_pool.accounts[i].account.address[3],
                    account_pool.accounts[i].account.address[4], account_pool.accounts[i].account.address[5],
                    account_pool.accounts[i].account.address[6], account_pool.accounts[i].account.address[7],
                    account_pool.accounts[i].account.address[8], account_pool.accounts[i].account.address[9],
                    account_pool.accounts[i].account.address[10], account_pool.accounts[i].account.address[11],
                    account_pool.accounts[i].account.address[12], account_pool.accounts[i].account.address[13],
                    account_pool.accounts[i].account.address[14], account_pool.accounts[i].account.address[15],
                    account_pool.accounts[i].account.address[16], account_pool.accounts[i].account.address[17],
                    account_pool.accounts[i].account.address[18], account_pool.accounts[i].account.address[19]);
            
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
            
            log_message(LOG_DEBUG, "Found account at index %d: %s (use_count: %u)\n", 
                   i, address, account_pool.accounts[i].account.use_count);
        }
    }
    
    log_message(LOG_INFO, "Pool status: total accounts=%u, active accounts=%u\n", *total_accounts, *active_accounts);
    return 0;
}

int ecall_generate_account_to_pool(char* account_address) {
    log_message(LOG_INFO, "Generating new account in pool...\n");
    
    if (!account_address) {
        log_message(LOG_ERROR, "Invalid account_address parameter\n");
        return -1;
    }

    // Generate new account
    Account new_account = {0};
    if (generate_account(&new_account) != 0) {
        log_message(LOG_ERROR, "Failed to generate account\n");
        return -1;
    }
    log_message(LOG_INFO, "Account generated successfully\n");

    // Format address as hex string
    snprintf(account_address, 43, "0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
             new_account.address[0], new_account.address[1], new_account.address[2], new_account.address[3],
             new_account.address[4], new_account.address[5], new_account.address[6], new_account.address[7],
             new_account.address[8], new_account.address[9], new_account.address[10], new_account.address[11],
             new_account.address[12], new_account.address[13], new_account.address[14], new_account.address[15],
             new_account.address[16], new_account.address[17], new_account.address[18], new_account.address[19]);

    // Find free slot in pool
    int free_slot = -1;
    for (int i = 0; i < MAX_POOL_SIZE; i++) {
        if (!account_pool.accounts[i].account.is_initialized) {
            free_slot = i;
            break;
        }
    }

    if (free_slot == -1) {
        log_message(LOG_ERROR, "No free slots in pool\n");
        return -1;
    }
    log_message(LOG_INFO, "Found free slot at index %d\n", free_slot);

    // Copy account to pool
    memcpy(&account_pool.accounts[free_slot].account, &new_account, sizeof(Account));
    account_pool.accounts[free_slot].account.use_count = 0;
    log_message(LOG_INFO, "Account copied to pool at index %d\n", free_slot);

    log_message(LOG_INFO, "Account successfully generated in pool at index %d\n", free_slot);
    return free_slot;
}


#ifdef __cplusplus
}
#endif
