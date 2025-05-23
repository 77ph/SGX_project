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
#include <algorithm>  // Добавляем для std::remove
#include "utils.h"

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
    printf("  load_pool 0x1234...5678 - Load account to pool\n");
    printf("  unload_pool 0x1234...5678 - Unload account from pool\n");
    printf("  sign_pool 0x1234...5678 0000000000000000000000000000000000000000000000000000000000000001 - Sign with pool account\n");
    printf("  pool_status - Show pool status\n");
    printf("  generate_pool - Generate new account in pool\n");
    printf("  generate_pool_recovery <modulus_hex> <exponent_hex> - Generate new account with recovery option (modulus and exponent in hex format)\n");
    printf("  set_log_level <level> - Set logging level (0=ERROR, 1=WARNING, 2=INFO, 3=DEBUG)\n");
    printf("  run_tests - Run system validation tests\n");
    printf("  help - Show this help message\n");
    printf("  exit - Exit the application\n\n");
}

// Функция для преобразования hex строки в байты
bool hex_to_bytes(const char* hex, uint8_t* bytes, size_t bytes_len) {
    printf("[App] hex_to_bytes: Starting conversion\n");
    printf("[App] hex_to_bytes: Input hex string: %s\n", hex);
    printf("[App] hex_to_bytes: Input length: %zu\n", strlen(hex));
    printf("[App] hex_to_bytes: Output buffer size: %zu\n", bytes_len);
    
    if (!hex || !bytes) {
        printf("[App] hex_to_bytes: Error - null input\n");
        return false;
    }
    
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) {
        printf("[App] hex_to_bytes: Error - odd length\n");
        return false;
    }
    
    size_t expected_bytes = hex_len / 2;
    if (expected_bytes > bytes_len) {
        printf("[App] hex_to_bytes: Error - buffer too small (need %zu, have %zu)\n", expected_bytes, bytes_len);
        return false;
    }
    
    printf("[App] hex_to_bytes: Converting %zu hex chars to %zu bytes\n", hex_len, expected_bytes);
    
    for (size_t i = 0; i < hex_len; i += 2) {
        char byte_str[3] = {hex[i], hex[i+1], '\0'};
        char* end_ptr;
        bytes[i/2] = (uint8_t)strtol(byte_str, &end_ptr, 16);
        if (*end_ptr != '\0') {
            printf("[App] hex_to_bytes: Error - invalid hex at position %zu\n", i);
            return false;
        }
    }
    
    printf("[App] hex_to_bytes: Conversion successful\n");
    return true;
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
    char* command = NULL;
    size_t command_len = 0;
    printf("Enter commands (type 'exit' to quit):\n");
    print_help();

    while (1) {
        printf("> ");
        ssize_t read = getline(&command, &command_len, stdin);
        if (read == -1) break;
        
        // Remove newline
        command[strcspn(command, "\n")] = 0;
        
        printf("Debug: Input length: %zu\n", strlen(command));
        
        if (strcmp(command, "exit") == 0) {
            break;
        }
        
        // Parse command and argument
        char* space = strchr(command, ' ');
        if (space) {
            *space = '\0';
            char* arg = space + 1;
            printf("Debug: Command: '%s'\n", command);
            printf("Debug: Arguments: '%s'\n", arg);

            if (strcmp(command, "load_pool") == 0) {
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

                uint8_t signature[65];
                status = ecall_sign_with_pool_account(global_eid, &retval, arg, tx_hash_bytes, sizeof(tx_hash_bytes), signature, sizeof(signature));
                if (status != SGX_SUCCESS || retval != 0) {
                    printf("Error: Failed to sign with pool account\n");
                    continue;
                }

                // Print signature in hex
                printf("Signature: ");
                for (int i = 0; i < 65; i++) {
                    printf("%02x", signature[i]);
                }
                printf("\n");
            }
            else if (strcmp(command, "generate_pool_recovery") == 0) {
                printf("[App] generate_pool_recovery: Starting command processing\n");
                
                // Получаем modulus и exponent из аргументов
                char* modulus_hex = arg;
                char* exponent_hex = NULL;
                
                // Ищем пробел между modulus и exponent
                space = strchr(arg, ' ');
                if (!space) {
                    printf("[App] generate_pool_recovery: Error - invalid format\n");
                    continue;
                }
                
                // Разделяем строку
                *space = '\0';
                exponent_hex = space + 1;
                
                printf("[App] generate_pool_recovery: Parsed arguments:\n");
                printf("[App] generate_pool_recovery: Modulus (hex): %s\n", modulus_hex);
                printf("[App] generate_pool_recovery: Exponent (hex): %s\n", exponent_hex);
                
                // Проверяем длину модуля (должно быть 768 hex символов для RSA-3072)
                if (strlen(modulus_hex) != 768) {
                    printf("Error: Invalid modulus length (%zu). Expected 768 hex characters for RSA-3072\n", strlen(modulus_hex));
                    continue;
                }

                // Проверяем формат экспоненты (должно быть "00010001")
                if (strlen(exponent_hex) != 8 || strcmp(exponent_hex, "00010001") != 0) {
                    printf("Error: Invalid exponent format. Expected '00010001'\n");
                    continue;
                }
                
                // Вызываем Enclave
                char account_address[43] = {0};
                
                printf("[App] generate_pool_recovery: Calling enclave\n");
                status = ecall_generate_account_with_recovery(global_eid, &retval, 
                    modulus_hex, exponent_hex, account_address);
                    
                if (status != SGX_SUCCESS) {
                    printf("[App] generate_pool_recovery: Enclave call failed (status: %d)\n", status);
                    continue;
                }
                
                if (retval < 0) {
                    printf("[App] generate_pool_recovery: Failed to generate account (error: %d)\n", retval);
                    continue;
                }
                
                printf("[App] generate_pool_recovery: Success - account %s generated\n", account_address);
                printf("[App] generate_pool_recovery: Recovery file saved as %s.account.recovery\n", account_address);
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
        } else {
            printf("Debug: Command: '%s' (no arguments)\n", command);
            
            if (strcmp(command, "pool_status") == 0) {
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
        }
        printf("\n");
    }

    // Free the command buffer
    free(command);

    // Destroy the enclave
    sgx_destroy_enclave(global_eid);
    return 0;
} 