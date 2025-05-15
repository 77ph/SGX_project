#include "App.h"
#include "Enclave_u.h"
#include <sgx_urts.h>
#include <sgx_uae_launch.h>
#include <sgx_uae_epid.h>
#include <sgx_uae_quote_ex.h>
#include <sgx_quote.h>
#include <sgx_utils.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <vector>
#include <string>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>

#define BUFLEN 2048
#define MAXPATHLEN 255
#define MAX_PATH FILENAME_MAX
#define MAX_POOL_SIZE 100  // Maximum number of accounts in the pool

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

// Глобальный флаг для тестового режима
static bool g_is_test_mode = false;

// Функции управления тестовым режимом
void cleanup_test_accounts() {
    // Удаляем все файлы из test_accounts
    system("rm -f test_accounts/*");
}

void set_test_mode(bool is_test) {
    g_is_test_mode = is_test;
    if (is_test) {
        // Создаем директорию test_accounts если её нет
        mkdir("test_accounts", 0700);
        // Очищаем старые тестовые аккаунты
        cleanup_test_accounts();
    }
}

// OCall functions
void ocall_print(const char* str) {
    printf("%s", str);
}

int ocall_save_to_file(const uint8_t* data, size_t size, const char* filename) {
    if (!data || !filename) {
        printf("Error: Invalid input parameters\n");
        return -1;
    }

    if (size == 0) {
        printf("Error: Invalid data size\n");
        return -1;
    }

    char full_path[256];
    if (g_is_test_mode) {
        snprintf(full_path, sizeof(full_path), "test_accounts/%s", filename);
    } else {
        snprintf(full_path, sizeof(full_path), "accounts/%s", filename);
    }

    FILE* file = fopen(full_path, "wb");
    if (!file) {
        printf("Error: Failed to open file %s for writing\n", full_path);
        return -1;
    }

    size_t written = fwrite(data, 1, size, file);
    fclose(file);

    if (written != size) {
        printf("Error: Failed to write all data to file %s\n", full_path);
        return -1;
    }

    return 0;
}

int ocall_read_from_file(uint8_t* data, size_t size, const char* filename) {
    if (!filename) {
        printf("Error: Invalid filename\n");
        return -1;
    }

    char full_path[256];
    if (g_is_test_mode) {
        snprintf(full_path, sizeof(full_path), "test_accounts/%s", filename);
    } else {
        snprintf(full_path, sizeof(full_path), "accounts/%s", filename);
    }

    FILE* file = fopen(full_path, "rb");
    if (!file) {
        printf("Error: Failed to open file %s for reading\n", full_path);
        return -1;
    }

    // If data is NULL and size is 0, we're just getting the file size
    if (!data && size == 0) {
        fseek(file, 0, SEEK_END);
        long file_size = ftell(file);
        fclose(file);
        return file_size;
    }

    if (!data || size == 0) {
        printf("Error: Invalid data buffer or size\n");
        fclose(file);
        return -1;
    }

    size_t read = fread(data, 1, size, file);
    fclose(file);

    if (read != size) {
        printf("Error: Failed to read all data from file %s\n", full_path);
        return -1;
    }

    return read;
}

int initialize_enclave(void) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, 1, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    return 0;
}

// Функция для получения списка аккаунтов на диске
void list_account_files() {
    const char* dir_path = g_is_test_mode ? "test_accounts" : "accounts";
    
    // Create directory if it doesn't exist
    if (mkdir(dir_path, 0755) != 0 && errno != EEXIST) {
        printf("Error: Cannot create directory %s\n", dir_path);
        return;
    }
    
    DIR* dir;
    struct dirent* entry;
    
    if ((dir = opendir(dir_path)) != NULL) {
        printf("\nAccount files in %s/:\n", dir_path);
        while ((entry = readdir(dir)) != NULL) {
            // Пропускаем . и ..
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }
            
            // Проверяем, что это файл аккаунта (заканчивается на .account)
            size_t len = strlen(entry->d_name);
            if (len > 8 && strcmp(entry->d_name + len - 8, ".account") == 0) {
                printf("  %s\n", entry->d_name);
            }
        }
        closedir(dir);
    } else {
        printf("Error: Cannot open directory %s\n", dir_path);
    }
}

void print_help() {
    printf("\nAvailable commands:\n");
    printf("  generate_account - Generate a new Ethereum account\n");
    printf("  load_account 0x1234...5678 - Load account by Ethereum address\n");
    printf("  sign_tx 0000000000000000000000000000000000000000000000000000000000000001 - Sign a transaction\n");
    printf("  test_key_strength - Test private key generation and strength\n");
    printf("  test_entropy - Test entropy generation\n");
    printf("  test_save_load - Test the save/load cycle\n");
    printf("  test_sign_verify - Test transaction signing and verification\n");
    printf("  test_mode [on|off] - Enable/disable test mode\n");
    printf("  load_pool 0x1234...5678 - Load account to pool\n");
    printf("  unload_pool 0x1234...5678 - Unload account from pool\n");
    printf("  sign_pool 0x1234...5678 0000000000000000000000000000000000000000000000000000000000000001 - Sign with pool account\n");
    printf("  pool_status - Show pool status\n");
    printf("  generate_pool - Generate new account in pool\n");
    printf("  set_log_level <level> - Set logging level (0=ERROR, 1=WARNING, 2=INFO, 3=DEBUG)\n");
    printf("  run_tests - Run system validation tests\n");
    printf("  help - Show this help message\n");
    printf("  exit - Exit the application\n\n");
}

int main(int argc, char *argv[]) {
    sgx_status_t status;
    sgx_launch_token_t token = {0};
    int updated = 0;
    int retval = 0;

    // Initialize the enclave
    status = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (status != SGX_SUCCESS) {
        printf("Error: Failed to create enclave\n");
        return -1;
    }

    // Start in test mode for the global test suite
    set_test_mode(true);

    printf("\n=== Starting System Tests ===\n");
    printf("Note: During testing, you may see error messages. These are expected and part of the test process.\n");
    printf("The tests are verifying that the system correctly handles various error conditions.\n\n");

    // Test function call
    status = ecall_test_function(global_eid, &retval);
    if (status != SGX_SUCCESS || retval != 0) {
        printf("Error: Test function failed\n");
        sgx_destroy_enclave(global_eid);
        return -1;
    }
    printf("Test function returned: %d\n", retval);
    printf("\n=== System Tests Completed Successfully ===\n");
    printf("All security and functionality tests passed. The system is secure and ready for use.\n\n");

    // Clean up test accounts after successful test completion
    cleanup_test_accounts();

    // Switch to normal mode after tests complete
    set_test_mode(false);

    // Interactive mode
    char command[256];
    char arg[256];
    printf("Enter commands (type 'exit' to quit):\n");
    printf("Available commands:\n");
    printf("  generate_account - Generate a new Ethereum account\n");
    printf("  load_account 0x1234...5678 - Load account by Ethereum address\n");
    printf("  sign_tx 0000000000000000000000000000000000000000000000000000000000000001 - Sign a transaction\n");
    printf("  test_key_strength - Test private key generation and strength\n");
    printf("  test_entropy - Test entropy generation\n");
    printf("  test_save_load - Test the save/load cycle\n");
    printf("  test_sign_verify - Test transaction signing and verification\n");
    printf("  test_mode [on|off] - Enable/disable test mode\n");
    printf("  load_pool 0x1234...5678 - Load account to pool\n");
    printf("  unload_pool 0x1234...5678 - Unload account from pool\n");
    printf("  sign_pool 0x1234...5678 0000000000000000000000000000000000000000000000000000000000000001 - Sign with pool account\n");
    printf("  pool_status - Show pool status\n");
    printf("  generate_pool - Generate new account in pool\n");
    printf("  set_log_level <level> - Set logging level (0=ERROR, 1=WARNING, 2=INFO, 3=DEBUG)\n");
    printf("  run_tests - Run system validation tests\n");
    printf("  help - Show this help message\n");
    printf("  exit - Exit the application\n");

    while (1) {
        printf("> ");
        if (fgets(command, sizeof(command), stdin) == NULL) break;
        
        // Remove newline
        command[strcspn(command, "\n")] = 0;
        
        if (strcmp(command, "exit") == 0) {
            break;
        }
        
        // Parse command and argument
        char* space = strchr(command, ' ');
        if (space) {
            *space = '\0';
            strcpy(arg, space + 1);
        } else {
            arg[0] = '\0';
        }

        if (strcmp(command, "generate_account") == 0) {
            status = ecall_generate_account(global_eid, &retval);
            if (status != SGX_SUCCESS || retval != 0) {
                printf("Error: Failed to generate account\n");
                continue;
            }
            printf("Account generated successfully\n");
        }
        else if (strcmp(command, "load_account") == 0) {
            if (strlen(arg) < 42 || strncmp(arg, "0x", 2) != 0) {
                printf("Error: Invalid Ethereum address format. Expected: 0x followed by 40 hex characters\n");
                continue;
            }
            status = ecall_load_account(global_eid, &retval, arg);
            if (status != SGX_SUCCESS || retval != 0) {
                printf("Error: Failed to load account\n");
                continue;
            }
            printf("Account loaded successfully\n");
        }
        else if (strcmp(command, "sign_tx") == 0) {
            if (strlen(arg) != 64) {
                printf("Error: Transaction hash must be 64 hex characters\n");
                continue;
            }

            // Convert hex string to bytes
            uint8_t tx_hash[32];
            for (int i = 0; i < 32; i++) {
                char byte_str[3] = {arg[i*2], arg[i*2+1], '\0'};
                tx_hash[i] = (uint8_t)strtol(byte_str, NULL, 16);
            }

            uint8_t signature[64];
            status = ecall_sign_transaction(global_eid, &retval, tx_hash, sizeof(tx_hash), signature, sizeof(signature));
            if (status != SGX_SUCCESS || retval != 0) {
                printf("Error: Failed to sign transaction\n");
                continue;
            }

            // Print signature in hex
            printf("Signature: ");
            for (int i = 0; i < 64; i++) {
                printf("%02x", signature[i]);
            }
            printf("\n");
        }
        else if (strcmp(command, "test_key_strength") == 0) {
            printf("Testing key strength...\n");
            uint8_t private_key[32];
            status = ecall_generate_private_key(global_eid, &retval, private_key, sizeof(private_key));
            if (status != SGX_SUCCESS || retval != 0) {
                printf("Error: Failed to generate test key\n");
                continue;
            }
            printf("Test key generated successfully\n");
            printf("First 8 bytes: ");
            for (int i = 0; i < 8; i++) {
                printf("%02x ", private_key[i]);
            }
            printf("\n");
        }
        else if (strcmp(command, "test_entropy") == 0) {
            printf("Testing entropy generation...\n");
            uint8_t entropy[128];
            status = ecall_test_entropy(global_eid, &retval, entropy, sizeof(entropy));
            if (status != SGX_SUCCESS || retval != 0) {
                printf("Error: Failed to generate test entropy\n");
                continue;
            }
            printf("Test entropy generated successfully\n");
            printf("First 16 bytes: ");
            for (int i = 0; i < 16; i++) {
                printf("%02x ", entropy[i]);
            }
            printf("\n");
        }
        else if (strcmp(command, "test_save_load") == 0) {
            printf("Testing save/load cycle...\n");
            status = ecall_test_save_load(global_eid, &retval);
            if (status != SGX_SUCCESS || retval != 0) {
                printf("Error: Save/load test failed\n");
                continue;
            }
            printf("Save/load test completed successfully\n");
        }
        else if (strcmp(command, "test_sign_verify") == 0) {
            status = ecall_test_sign_verify(global_eid, &retval);
            if (status != SGX_SUCCESS || retval != 0) {
                printf("Error: Test sign/verify failed\n");
                continue;
            }
            printf("Test sign/verify completed successfully\n");
        }
        else if (strcmp(command, "test_mode") == 0) {
            if (strcmp(arg, "on") == 0) {
                set_test_mode(true);
                printf("Test mode enabled\n");
            } else if (strcmp(arg, "off") == 0) {
                set_test_mode(false);
                printf("Test mode disabled\n");
            } else {
                printf("Usage: test_mode [on|off]\n");
            }
        }
        else if (strcmp(command, "load_pool") == 0) {
            if (strlen(arg) < 42 || strncmp(arg, "0x", 2) != 0) {
                printf("Error: Invalid Ethereum address format. Expected: 0x followed by 40 hex characters\n");
                continue;
            }
            printf("Loading account %s to pool...\n", arg);
            status = ecall_load_account_to_pool(global_eid, &retval, arg);
            if (status != SGX_SUCCESS) {
                printf("Error: Failed to load account to pool\n");
                continue;
            }
            if (retval < 0) {
                printf("Error: Failed to load account to pool\n");
            } else {
                printf("Account %s successfully loaded to pool at index %d\n", arg, retval);
            }
        }
        else if (strcmp(command, "unload_pool") == 0) {
            if (strlen(arg) < 42 || strncmp(arg, "0x", 2) != 0) {
                printf("Error: Invalid Ethereum address format. Expected: 0x followed by 40 hex characters\n");
                continue;
            }
            status = ecall_unload_account_from_pool(global_eid, &retval, arg);
            if (status != SGX_SUCCESS || retval != 0) {
                printf("Error: Failed to unload account from pool\n");
                continue;
            }
            printf("Account %s unloaded from pool successfully\n", arg);
        }
        else if (strcmp(command, "sign_pool") == 0) {
            char* space = strchr(arg, ' ');
            if (!space) {
                printf("Error: Invalid format. Expected: sign_pool <address> <tx_hash>\n");
                continue;
            }
            *space = '\0';
            char* tx_hash = space + 1;

            if (strlen(arg) < 42 || strncmp(arg, "0x", 2) != 0) {
                printf("Error: Invalid Ethereum address format\n");
                continue;
            }
            if (strlen(tx_hash) != 64) {
                printf("Error: Transaction hash must be 64 hex characters\n");
                continue;
            }

            // Convert hex string to bytes
            uint8_t tx_hash_bytes[32];
            for (int i = 0; i < 32; i++) {
                char byte_str[3] = {tx_hash[i*2], tx_hash[i*2+1], '\0'};
                tx_hash_bytes[i] = (uint8_t)strtol(byte_str, NULL, 16);
            }

            uint8_t signature[64];
            status = ecall_sign_with_pool_account(global_eid, &retval, arg, tx_hash_bytes, sizeof(tx_hash_bytes), signature, sizeof(signature));
            if (status != SGX_SUCCESS || retval != 0) {
                printf("Error: Failed to sign with pool account\n");
                continue;
            }

            // Print signature in hex
            printf("Signature: ");
            for (int i = 0; i < 64; i++) {
                printf("%02x", signature[i]);
            }
            printf("\n");
        }
        else if (strcmp(command, "pool_status") == 0) {
            uint32_t total_accounts = 0;
            uint32_t active_accounts = 0;
            char account_addresses[4300] = {0};
            
            status = ecall_get_pool_status(global_eid, &retval, &total_accounts, &active_accounts, account_addresses);
            if (status != SGX_SUCCESS || retval != 0) {
                printf("Error: Failed to get pool status\n");
                continue;
            }
            
            printf("Pool status:\n");
            printf("Total accounts: %u\n", total_accounts);
            printf("Active accounts: %u\n", active_accounts);
            if (total_accounts > 0) {
                printf("Account addresses: %s\n", account_addresses);
            }
            
            // Display account files from disk
            printf("\nAccount files in %s/:\n", g_is_test_mode ? "test_accounts" : "accounts");
            list_account_files();
        }
        else if (strcmp(command, "generate_pool") == 0) {
            char account_address[43] = {0};
            status = ecall_generate_account_to_pool(global_eid, &retval, account_address);
            if (status != SGX_SUCCESS || retval < 0) {
                printf("Error: Failed to generate account in pool\n");
                continue;
            }
            printf("Account generated in pool at index %d\n", retval);
            printf("Account address: %s\n", account_address);
        }
        else if (strcmp(command, "help") == 0) {
            print_help();
        }
        else if (strcmp(command, "set_log_level") == 0) {
            int level = atoi(arg);
            if (level >= 0 && level <= 3) {
                int retval;
                if (ecall_set_log_level(global_eid, &retval, level) == SGX_SUCCESS && retval == 0) {
                    printf("Log level set to %d\n", level);
                } else {
                    printf("Failed to set log level\n");
                }
            } else {
                printf("Invalid log level. Use 0-3:\n");
                printf("  0: ERROR only\n");
                printf("  1: WARNING and ERROR\n");
                printf("  2: INFO, WARNING and ERROR\n");
                printf("  3: DEBUG, INFO, WARNING and ERROR\n");
            }
        }
        else if (strcmp(command, "run_tests") == 0) {
            // Enable test mode
            set_test_mode(true);
            
            printf("\n=== Starting System Tests ===\n");
            printf("Note: During testing, you may see error messages. These are expected and part of the test process.\n");
            printf("The tests are verifying that the system correctly handles various error conditions.\n\n");
            
            status = ecall_test_function(global_eid, &retval);
            if (status != SGX_SUCCESS || retval != 0) {
                printf("Error: Test function failed\n");
                continue;
            }
            
            printf("\n=== System Tests Completed Successfully ===\n");
            printf("All security and functionality tests passed. The system is secure and ready for use.\n\n");
            
            // Clean up test accounts and disable test mode
            cleanup_test_accounts();
            set_test_mode(false);
        }
        else {
            printf("Unknown command. Type 'help' for available commands.\n");
        }
        printf("\n");
    }

    // Destroy the enclave
    sgx_destroy_enclave(global_eid);
    return 0;
}
