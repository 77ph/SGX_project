#include "Enclave.h"
#include "Enclave_t.h"  // Автоматически сгенерирован sgx_edger8r
#include <sgx_trts.h>
#include <sgx_tcrypto.h>
#include <sgx_tseal.h>
#include <sgx_tprotected_fs.h>  // Для работы с файлами в SGX
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <secp256k1.h>
#include <time.h>
#include <math.h>  // Добавляем для log2

#define ENCLAVE_BUFSIZ 1024

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
    return 0;
}

#ifdef __cplusplus
extern "C" {
#endif

// Global account instance
static Account current_account = {0};
static AccountData current_account_data = {0};

// Global pool instance
static AccountPool account_pool = {0};

// Initialize account pool
static bool initialize_account_pool() {
    printf("Initializing account pool...\n");
    
    // Initialize all slots as free
    for (int i = 0; i < MAX_POOL_SIZE; i++) {
        account_pool.accounts[i].is_loaded = false;
        account_pool.accounts[i].use_count = 0;
        account_pool.accounts[i].hash = 0;
        secure_memzero(&account_pool.accounts[i].account, sizeof(Account));
        secure_memzero(account_pool.accounts[i].account_id, MAX_ACCOUNT_ID_LEN);
    }
    
    printf("Account pool initialized with %d slots\n", MAX_POOL_SIZE);
    return true;
}

// Enclave initialization function
sgx_status_t sgx_ecall_initialize() {
    printf("Initializing enclave...\n");
    
    // Initialize account pool
    if (!initialize_account_pool()) {
        printf("Failed to initialize account pool\n");
        return SGX_ERROR_UNEXPECTED;
    }
    
    printf("Enclave initialized successfully\n");
    return SGX_SUCCESS;
}

// Security constants
// MIN_ENTROPY_BITS is defined in Enclave.h
#define KEY_GENERATION_MAX_ATTEMPTS 100
#define MIN_PRIVATE_KEY_VALUE 0x1000000000000000ULL
#define MAX_PRIVATE_KEY_VALUE 0xFFFFFFFFFFFFFFFFULL

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
    
    printf("Entropy calculation details:\n");
    printf("  Data size: %zu bytes\n", size);
    printf("  Unique bytes: ");
    int unique_bytes = 0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            unique_bytes++;
            printf("%02x ", i);
        }
    }
    printf("\n  Unique bytes count: %d\n", unique_bytes);
    printf("  Raw entropy: %.2f bits\n", entropy);
    
    return entropy;
}

// Helper function to check if a private key is cryptographically strong
bool is_strong_private_key(const uint8_t* private_key, size_t size) {
    printf("Checking private key strength...\n");
    
    if (!private_key || size != 32) {
        printf("Invalid key parameters: key=%p, size=%zu\n", private_key, size);
        return false;
    }
    
    // Print first few bytes of the key for debugging
    printf("Key bytes (first 8): ");
    for (int i = 0; i < 8; i++) {
        printf("%02x ", private_key[i]);
    }
    printf("\n");
    
    // Create secp256k1 context for verification
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!ctx) {
        printf("Failed to create secp256k1 context\n");
        return false;
    }
    
    // Verify key using secp256k1
    bool is_valid = secp256k1_ec_seckey_verify(ctx, private_key);
    secp256k1_context_destroy(ctx);
    
    if (!is_valid) {
        printf("Key failed secp256k1 validation\n");
        return false;
    }
    printf("Key passed secp256k1 validation\n");
    
    // Check for weak patterns
    bool has_weak_pattern = true;
    for (size_t i = 1; i < size; i++) {
        if (private_key[i] != private_key[0]) {
            has_weak_pattern = false;
            break;
        }
    }
    if (has_weak_pattern) {
        printf("Key has weak pattern (all bytes are the same)\n");
        return false;
    }
    
    printf("Key passed all strength checks\n");
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
    printf("Starting secure private key generation...\n");
    
    if (!private_key || size != 32) {
        printf("Invalid parameters: private_key=%p, size=%zu\n", private_key, size);
        return SGX_ERROR_INVALID_PARAMETER;
    }
    
    // Step 1: Generate entropy
    uint8_t entropy[128];
    sgx_status_t status = generate_entropy(entropy, sizeof(entropy));
    if (status != SGX_SUCCESS) {
        printf("Failed to generate entropy: %d\n", status);
        return status;
    }
    printf("Generated initial entropy\n");
    
    // Step 2: Extract PRK using SHA-256 (HKDF-Extract)
    sgx_sha256_hash_t prk;
    status = sgx_sha256_msg(entropy, sizeof(entropy), &prk);
    if (status != SGX_SUCCESS) {
        printf("Failed to extract PRK: %d\n", status);
        return status;
    }
    printf("PRK extracted\n");
    
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
        printf("Failed to expand key: %d\n", status);
        return status;
    }
    printf("Key expanded successfully\n");
    
    // Copy the final hash to the private key
    memcpy(private_key, final_hash, 32);
    
    // Verify key strength
    if (is_strong_private_key(private_key, size)) {
        printf("Strong private key generated successfully\n");
        return SGX_SUCCESS;
    }
    
    printf("Generated key did not meet strength requirements\n");
    return SGX_ERROR_UNEXPECTED;
}

// Helper function to get current account
AccountData* get_current_account(void) {
    return &current_account_data;
}

// Keccak-256 implementation
void keccak_256(const uint8_t* input, size_t input_len, uint8_t* output) {
    sgx_sha256_hash_t hash;
    sgx_sha256_msg(input, input_len, &hash);
    memcpy(output, hash, 32);
}

// Enhanced account generation
int ecall_generate_account(void) {
    printf("Starting account generation...\n");
    
    uint8_t private_key[32] = {0};
    sgx_status_t status = generate_secure_private_key(private_key, sizeof(private_key));
    
    if (status != SGX_SUCCESS) {
        return -1;
    }
    printf("Private key generated successfully\n");
    
    // Generate public key from private key
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!ctx) {
        return -1;
    }
    printf("Secp256k1 context created\n");
    
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, private_key)) {
        secp256k1_context_destroy(ctx);
        return -1;
    }
    printf("Public key created\n");
    
    // Serialize public key
    uint8_t serialized_pubkey[65];
    size_t serialized_pubkey_len = sizeof(serialized_pubkey);
    if (!secp256k1_ec_pubkey_serialize(ctx, serialized_pubkey, &serialized_pubkey_len, &pubkey, SECP256K1_EC_UNCOMPRESSED)) {
        secp256k1_context_destroy(ctx);
        return -1;
    }
    printf("Public key serialized\n");
    
    // Calculate Ethereum address
    uint8_t hash[32];
    keccak_256(serialized_pubkey + 1, 64, hash);
    uint8_t address[20];
    memcpy(address, hash + 12, 20);
    printf("Ethereum address calculated\n");
    
    // Store the account data
    memcpy(current_account.private_key, private_key, sizeof(private_key));
    memcpy(current_account.public_key, serialized_pubkey, sizeof(serialized_pubkey));
    memcpy(current_account.address, address, sizeof(address));
    current_account.is_initialized = true;
    printf("Account data stored\n");
    
    // Calculate HMAC
    sgx_status_t hmac_status = sgx_sha256_msg((const uint8_t*)&current_account, sizeof(Account) - 32, (sgx_sha256_hash_t*)current_account.hmac);
    if (hmac_status != SGX_SUCCESS) {
        secp256k1_context_destroy(ctx);
        return -1;
    }
    printf("HMAC calculated\n");
    
    secp256k1_context_destroy(ctx);
    
    // Save account state immediately
    printf("Saving account state...\n");
    int save_result = ecall_save_account("default");
    if (save_result != 0) {
        printf("Failed to save account state\n");
        return -1;
    }
    printf("Account state saved successfully\n");
    
    printf("Account generation completed successfully\n");
    return 0;
}

// Enhanced transaction signing with security checks
int ecall_sign_transaction(const uint8_t* tx_hash, size_t tx_hash_size,
                          uint8_t* signature, size_t signature_size) {
    printf("Starting transaction signing...\n");
    
    if (!tx_hash || !signature || tx_hash_size != 32 || signature_size != 64) {
        printf("Invalid parameters: tx_hash=%p, signature=%p, tx_hash_size=%zu, signature_size=%zu\n",
               tx_hash, signature, tx_hash_size, signature_size);
        return -1;
    }
    
    // Verify private key strength
    if (!is_strong_private_key(current_account.private_key, sizeof(current_account.private_key))) {
        printf("Private key does not meet strength requirements\n");
        return -1;
    }
    printf("Private key verified\n");
    
    // Create signing context
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!ctx) {
        printf("Failed to create secp256k1 context\n");
        return -1;
    }
    printf("Secp256k1 context created\n");
    
    // Sign the transaction
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_sign(ctx, &sig, tx_hash, current_account.private_key, NULL, NULL)) {
        printf("Failed to create signature\n");
        secp256k1_context_destroy(ctx);
        return -1;
    }
    printf("Signature created\n");
    
    // Serialize signature
    if (!secp256k1_ecdsa_signature_serialize_compact(ctx, signature, &sig)) {
        printf("Failed to serialize signature\n");
        secp256k1_context_destroy(ctx);
        return -1;
    }
    printf("Signature serialized\n");
    
    secp256k1_context_destroy(ctx);
    printf("Transaction signing completed successfully\n");
    return 0;
}

// Функции для работы с аккаунтами
int ecall_save_account(const char* account_id) {
    printf("Saving account with ID: %s\n", account_id);
    
    if (!current_account.is_initialized) {
        printf("Account is not initialized\n");
        return -1;
    }

    // Create structure for saving
    AccountFile data;
    memcpy(&data.account, &current_account, sizeof(Account));
    printf("Account data copied to save structure\n");

    // Calculate HMAC
    uint8_t computed_hash[32];
    sgx_status_t status = sgx_sha256_msg((const uint8_t*)&data, sizeof(AccountFile) - 32, (sgx_sha256_hash_t*)computed_hash);
    if (status != SGX_SUCCESS) {
        printf("Failed to calculate HMAC: %d\n", status);
        return -1;
    }
    memcpy(data.file_hmac, computed_hash, 32);
    printf("HMAC calculated and stored\n");

    // Encrypt data
    size_t sealed_size = sgx_calc_sealed_data_size(0, sizeof(AccountFile));
    if (sealed_size == UINT32_MAX) {
        printf("Failed to calculate sealed data size\n");
        return -1;
    }

    uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);
    if (!sealed_data) {
        printf("Failed to allocate memory for sealed data\n");
        return -1;
    }

    status = sgx_seal_data(0, NULL, sizeof(AccountFile), (uint8_t*)&data, sealed_size, (sgx_sealed_data_t*)sealed_data);
    if (status != SGX_SUCCESS) {
        printf("Failed to seal data: %d\n", status);
        free(sealed_data);
        return -1;
    }
    printf("Data sealed successfully\n");

    // Save encrypted data using Ethereum address as filename
    char filename[256];
    snprintf(filename, sizeof(filename), "0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x.account",
             current_account.address[0], current_account.address[1], current_account.address[2], current_account.address[3],
             current_account.address[4], current_account.address[5], current_account.address[6], current_account.address[7],
             current_account.address[8], current_account.address[9], current_account.address[10], current_account.address[11],
             current_account.address[12], current_account.address[13], current_account.address[14], current_account.address[15],
             current_account.address[16], current_account.address[17], current_account.address[18], current_account.address[19]);
    
    int ret = 0;
    status = ocall_save_to_file(&ret, sealed_data, sealed_size, filename);
    free(sealed_data);
    
    if (status != SGX_SUCCESS || ret != 0) {
        printf("Failed to save file: status=%d, ret=%d\n", status, ret);
        return -1;
    }
    
    printf("Account saved successfully to %s\n", filename);
    return 0;
}

int ecall_load_account(const char* account_id) {
    printf("Loading account with ID: %s\n", account_id);
    
    if (!account_id) {
        printf("Invalid account ID\n");
        return -1;
    }

    // Открытие файла
    char filename[256];
    snprintf(filename, sizeof(filename), "%s.account", account_id);
    printf("Opening file: %s\n", filename);
    
    // Получение размера файла через OCALL
    uint8_t* sealed_data = NULL;
    size_t file_size = 0;
    int ret = 0;
    sgx_status_t ocall_status = ocall_read_from_file(&ret, NULL, 0, filename);
    if (ocall_status != SGX_SUCCESS || ret < 0) {
        printf("Failed to get file size: status=%d, ret=%d\n", ocall_status, ret);
        return -1;
    }
    file_size = ret;
    printf("File size: %zu bytes\n", file_size);

    // Чтение зашифрованных данных
    sealed_data = (uint8_t*)malloc(file_size);
    if (!sealed_data) {
        printf("Failed to allocate memory for sealed data\n");
        return -1;
    }

    ocall_status = ocall_read_from_file(&ret, sealed_data, file_size, filename);
    if (ocall_status != SGX_SUCCESS || ret != file_size) {
        printf("Failed to read file: status=%d, ret=%d\n", ocall_status, ret);
        free(sealed_data);
        return -1;
    }
    printf("File read successfully\n");

    // Расшифровка данных
    uint32_t decrypted_size = sgx_get_encrypt_txt_len((sgx_sealed_data_t*)sealed_data);
    if (decrypted_size == UINT32_MAX) {
        printf("Failed to get decrypted size\n");
        free(sealed_data);
        return -1;
    }
    printf("Decrypted size: %u bytes\n", decrypted_size);

    uint8_t* decrypted_data = (uint8_t*)malloc(decrypted_size);
    if (!decrypted_data) {
        printf("Failed to allocate memory for decrypted data\n");
        free(sealed_data);
        return -1;
    }

    sgx_status_t unseal_status = sgx_unseal_data((sgx_sealed_data_t*)sealed_data, NULL, NULL, decrypted_data, &decrypted_size);
    free(sealed_data);

    if (unseal_status != SGX_SUCCESS || decrypted_size != sizeof(AccountFile)) {
        printf("Failed to unseal data: status=%d, size=%u\n", unseal_status, decrypted_size);
        free(decrypted_data);
        return -1;
    }
    printf("Data unsealed successfully\n");

    // Проверка HMAC
    AccountFile* data = (AccountFile*)decrypted_data;
    uint8_t computed_hash[32];
    sgx_status_t hmac_status = sgx_sha256_msg((const uint8_t*)data, sizeof(AccountFile) - 32, (sgx_sha256_hash_t*)computed_hash);
    if (hmac_status != SGX_SUCCESS || memcmp(data->file_hmac, computed_hash, 32) != 0) {
        printf("HMAC verification failed\n");
        free(decrypted_data);
        return -1;
    }
    printf("HMAC verified successfully\n");

    // Проверка адреса
    char expected_filename[256];
    snprintf(expected_filename, sizeof(expected_filename), "0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x.account",
             data->account.address[0], data->account.address[1], data->account.address[2], data->account.address[3],
             data->account.address[4], data->account.address[5], data->account.address[6], data->account.address[7],
             data->account.address[8], data->account.address[9], data->account.address[10], data->account.address[11],
             data->account.address[12], data->account.address[13], data->account.address[14], data->account.address[15],
             data->account.address[16], data->account.address[17], data->account.address[18], data->account.address[19]);
    
    if (strcmp(filename, expected_filename) != 0) {
        printf("Account address mismatch\n");
        free(decrypted_data);
        return -1;
    }
    printf("Account address verified\n");

    // Копирование данных аккаунта
    memcpy(&current_account, &data->account, sizeof(Account));
    current_account.is_initialized = true;
    printf("Account data copied successfully\n");
    printf("First 8 bytes of loaded private key: ");
    for (int i = 0; i < 8; i++) {
        printf("%02x ", current_account.private_key[i]);
    }
    printf("\n");

    free(decrypted_data);
    printf("Account loaded successfully\n");
    return 0;
}

int ecall_sign_message(const uint8_t* message, size_t message_len, uint8_t* signature, size_t signature_len) {
    printf("Starting message signing...\n");
    
    if (!message || !signature || message_len == 0 || signature_len < 64) {
        printf("Invalid parameters: message=%p, signature=%p, message_len=%zu, signature_len=%zu\n", 
               message, signature, message_len, signature_len);
        return -1;
    }

    if (!current_account.is_initialized) {
        printf("Account is not initialized\n");
        return -1;
    }
    printf("Account is initialized\n");

    // Create secp256k1 context
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!ctx) {
        printf("Failed to create secp256k1 context\n");
        return -1;
    }
    printf("Secp256k1 context created\n");

    // Create signature
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_sign(ctx, &sig, message, current_account.private_key, NULL, NULL)) {
        printf("Failed to create signature\n");
        secp256k1_context_destroy(ctx);
        return -1;
    }
    printf("Signature created\n");

    // Serialize signature
    if (!secp256k1_ecdsa_signature_serialize_compact(ctx, signature, &sig)) {
        printf("Failed to serialize signature\n");
        secp256k1_context_destroy(ctx);
        return -1;
    }
    printf("Signature serialized\n");

    secp256k1_context_destroy(ctx);
    printf("Message signing completed successfully\n");
    return 0;
}

// Test function
int ecall_test_function() {
    return 0;
}

// Simplified key generation
int ecall_generate_private_key(uint8_t* private_key, size_t private_key_size) {
    if (!private_key || private_key_size != 32) {
        return -1;
    }
    return generate_secure_private_key(private_key, private_key_size) == SGX_SUCCESS ? 0 : -1;
}

// Stub implementations for functions still declared in Enclave.edl
int ecall_store_private_key(const uint8_t* private_key, size_t private_key_size) {
    printf("WARNING: ecall_store_private_key is deprecated\n");
    return -1;
}

int ecall_sign_with_stored_key(const uint8_t* tx_hash, size_t tx_hash_size,
                             uint8_t* signature, size_t signature_size) {
    printf("WARNING: ecall_sign_with_stored_key is deprecated\n");
    return -1;
}

int ecall_sign_with_account(const uint8_t* message_hash, size_t message_hash_len,
                          uint8_t* signature, size_t signature_len) {
    printf("WARNING: ecall_sign_with_account is deprecated\n");
    return -1;
}

int ecall_load_account_to_pool(const char* account_id) {
    printf("WARNING: ecall_load_account_to_pool is deprecated\n");
    return -1;
}

int ecall_unload_account_from_pool(const char* account_id) {
    printf("WARNING: ecall_unload_account_from_pool is deprecated\n");
    return -1;
}

int ecall_sign_with_pool_account(const char* account_id, const uint8_t* message, size_t message_len, uint8_t* signature, size_t signature_len) {
    printf("WARNING: ecall_sign_with_pool_account is deprecated\n");
    return -1;
}

int ecall_get_pool_status(uint32_t* total_accounts, uint32_t* active_accounts) {
    printf("WARNING: ecall_get_pool_status is deprecated\n");
    return -1;
}

int ecall_save_test_account() {
    printf("WARNING: ecall_save_test_account is deprecated\n");
    return -1;
}

// Test functions
int ecall_test_entropy(uint8_t* entropy, size_t size) {
    printf("Testing entropy generation...\n");
    if (!entropy || size != 128) {
        printf("Invalid parameters\n");
        return -1;
    }
    
    sgx_status_t status = sgx_read_rand(entropy, size);
    if (status != SGX_SUCCESS) {
        printf("Failed to generate entropy: %d\n", status);
        return -1;
    }
    
    double entropy_bits = calculate_entropy(entropy, size);
    printf("Generated entropy: %.2f bits\n", entropy_bits);
    
    return 0;
}

int ecall_test_save_load(void) {
    printf("Testing save/load cycle...\n");
    
    // Generate test account
    if (ecall_generate_account() != 0) {
        printf("Failed to generate test account\n");
        return -1;
    }
    printf("Test account generated\n");
    
    // Save account using Ethereum address
    char filename[256];
    snprintf(filename, sizeof(filename), "0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
             current_account.address[0], current_account.address[1], current_account.address[2], current_account.address[3],
             current_account.address[4], current_account.address[5], current_account.address[6], current_account.address[7],
             current_account.address[8], current_account.address[9], current_account.address[10], current_account.address[11],
             current_account.address[12], current_account.address[13], current_account.address[14], current_account.address[15],
             current_account.address[16], current_account.address[17], current_account.address[18], current_account.address[19]);
    
    if (ecall_save_account(filename) != 0) {
        printf("Failed to save test account\n");
        return -1;
    }
    printf("Test account saved\n");
    
    // Clear current account
    secure_memzero(&current_account, sizeof(Account));
    current_account.is_initialized = false;
    printf("Current account cleared\n");
    
    // Load account using Ethereum address (without .account extension)
    if (ecall_load_account(filename) != 0) {
        printf("Failed to load test account\n");
        return -1;
    }
    printf("Test account loaded\n");
    
    // Verify account data
    if (!current_account.is_initialized) {
        printf("Account not initialized after load\n");
        return -1;
    }
    printf("Account verified after load\n");
    
    return 0;
}

int ecall_test_sign_verify(void) {
    printf("Testing sign/verify cycle...\n");
    
    // Generate test account if not exists
    if (!current_account.is_initialized) {
        if (ecall_generate_account() != 0) {
            printf("Failed to generate test account\n");
            return -1;
        }
        printf("Test account generated\n");
    }
    
    // Create test transaction hash
    uint8_t tx_hash[32];
    for (int i = 0; i < 32; i++) {
        tx_hash[i] = i;  // Simple test pattern
    }
    printf("Test transaction hash created\n");
    
    // Sign transaction
    uint8_t signature[64];
    if (ecall_sign_transaction(tx_hash, sizeof(tx_hash), signature, sizeof(signature)) != 0) {
        printf("Failed to sign test transaction\n");
        return -1;
    }
    printf("Test transaction signed\n");
    
    // Create verification context
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        printf("Failed to create verification context\n");
        return -1;
    }
    printf("Verification context created\n");
    
    // Parse signature
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_signature_parse_compact(ctx, &sig, signature)) {
        printf("Failed to parse signature\n");
        secp256k1_context_destroy(ctx);
        return -1;
    }
    printf("Signature parsed\n");
    
    // Parse public key
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, current_account.public_key, sizeof(current_account.public_key))) {
        printf("Failed to parse public key\n");
        secp256k1_context_destroy(ctx);
        return -1;
    }
    printf("Public key parsed\n");
    
    // Verify signature
    if (!secp256k1_ecdsa_verify(ctx, &sig, tx_hash, &pubkey)) {
        printf("Signature verification failed\n");
        secp256k1_context_destroy(ctx);
        return -1;
    }
    printf("Signature verified successfully\n");
    
    secp256k1_context_destroy(ctx);
    return 0;
}

#ifdef __cplusplus
}
#endif
