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

#define BUFLEN 2048
#define MAXPATHLEN 255
#define MAX_PATH FILENAME_MAX

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

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

    FILE* file = fopen(filename, "wb");
    if (!file) {
        printf("Error: Failed to open file %s for writing\n", filename);
        return -1;
    }

    size_t written = fwrite(data, 1, size, file);
    fclose(file);

    if (written != size) {
        printf("Error: Failed to write all data to file %s\n", filename);
        return -1;
    }

    return 0;
}

int ocall_read_from_file(uint8_t* data, size_t size, const char* filename) {
    if (!filename) {
        printf("Error: Invalid filename\n");
        return -1;
    }

    FILE* file = fopen(filename, "rb");
    if (!file) {
        printf("Error: Failed to open file %s for reading\n", filename);
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
        printf("Error: Failed to read all data from file %s\n", filename);
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

void print_usage() {
    printf("Usage:\n");
    printf("  generate_account - Generate new account\n");
    printf("  save_account_state - Save current account state\n");
    printf("  load_account_state - Load account state\n");
    printf("  sign_tx <tx_hash> - Sign transaction hash (32 bytes in hex)\n");
    printf("  load_account_to_pool <account_id> - Load account to pool\n");
    printf("  unload_account_from_pool <account_id> - Unload account from pool\n");
    printf("  sign_with_pool <account_id> <tx_hash> - Sign transaction with pool account\n");
    printf("  get_pool_status - Get pool status\n");
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

    // Test function call
    status = ecall_test_function(global_eid, &retval);
    if (status != SGX_SUCCESS || retval != 0) {
        printf("Error: Test function failed\n");
        sgx_destroy_enclave(global_eid);
        return -1;
    }
    printf("Test function returned: %d\n\n", retval);

    // Interactive mode
    char command[256];
    char arg[256];
    printf("Enter commands (type 'exit' to quit):\n");
    printf("Available commands:\n");
    printf("  generate_account\n");
    printf("  save_account_state\n");
    printf("  load_account_state\n");
    printf("  sign_tx <tx_hash>\n");
    printf("  test_key_strength - Test private key generation and strength\n");
    printf("  test_entropy - Test entropy generation\n");
    printf("  test_save_load - Test save/load cycle\n");
    printf("  test_sign_verify - Test transaction signing and verification\n");
    printf("  exit\n\n");

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
        else if (strcmp(command, "save_account_state") == 0) {
            status = ecall_save_account_state(global_eid, &retval);
            if (status != SGX_SUCCESS || retval != 0) {
                printf("Error: Failed to save account state\n");
                continue;
            }
            printf("Account state saved successfully\n");
        }
        else if (strcmp(command, "load_account_state") == 0) {
            status = ecall_load_account_state(global_eid, &retval);
            if (status != SGX_SUCCESS || retval != 0) {
                printf("Error: Failed to load account state\n");
                continue;
            }
            printf("Account state loaded successfully\n");
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
            printf("Testing sign/verify cycle...\n");
            status = ecall_test_sign_verify(global_eid, &retval);
            if (status != SGX_SUCCESS || retval != 0) {
                printf("Error: Sign/verify test failed\n");
                continue;
            }
            printf("Sign/verify test completed successfully\n");
        }
        else {
            printf("Unknown command. Available commands:\n");
            printf("  generate_account\n");
            printf("  save_account_state\n");
            printf("  load_account_state\n");
            printf("  sign_tx <tx_hash>\n");
            printf("  test_key_strength - Test private key generation and strength\n");
            printf("  test_entropy - Test entropy generation\n");
            printf("  test_save_load - Test save/load cycle\n");
            printf("  test_sign_verify - Test transaction signing and verification\n");
            printf("  exit\n");
        }
        printf("\n");
    }

    // Destroy the enclave
    sgx_destroy_enclave(global_eid);
    return 0;
}
