#include <cstdio>
#include <cstring>
#include <iostream>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "sgx_urts.h"
#include "sgx_utils.h"

#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret) {
    std::cout << "Error: " << ret << std::endl;
    switch(ret) {
        case SGX_ERROR_UNEXPECTED:
            std::cout << "Unexpected error occurred" << std::endl;
            break;
        case SGX_ERROR_INVALID_PARAMETER:
            std::cout << "Invalid parameter" << std::endl;
            break;
        case SGX_ERROR_OUT_OF_MEMORY:
            std::cout << "Out of memory" << std::endl;
            break;
        case SGX_ERROR_ENCLAVE_LOST:
            std::cout << "Enclave lost" << std::endl;
            break;
        case SGX_ERROR_INVALID_ENCLAVE:
            std::cout << "Invalid enclave" << std::endl;
            break;
        case SGX_ERROR_INVALID_ENCLAVE_ID:
            std::cout << "Invalid enclave ID" << std::endl;
            break;
        case SGX_ERROR_INVALID_SIGNATURE:
            std::cout << "Invalid signature" << std::endl;
            break;
        case SGX_ERROR_NDEBUG_ENCLAVE:
            std::cout << "Enclave is not in debug mode" << std::endl;
            break;
        case SGX_ERROR_OUT_OF_EPC:
            std::cout << "Out of EPC memory" << std::endl;
            break;
        case SGX_ERROR_NO_DEVICE:
            std::cout << "SGX device not found" << std::endl;
            break;
        case SGX_ERROR_MEMORY_MAP_CONFLICT:
            std::cout << "Memory map conflict" << std::endl;
            break;
        case SGX_ERROR_INVALID_METADATA:
            std::cout << "Invalid metadata" << std::endl;
            break;
        case SGX_ERROR_DEVICE_BUSY:
            std::cout << "SGX device is busy" << std::endl;
            break;
        case SGX_ERROR_INVALID_VERSION:
            std::cout << "Invalid version" << std::endl;
            break;
        case SGX_ERROR_MODE_INCOMPATIBLE:
            std::cout << "Mode incompatible" << std::endl;
            break;
        case SGX_ERROR_ENCLAVE_FILE_ACCESS:
            std::cout << "Cannot access enclave file" << std::endl;
            break;
        case SGX_ERROR_INVALID_ATTRIBUTE:
            std::cout << "Invalid attribute" << std::endl;
            break;
        default:
            std::cout << "Unknown error" << std::endl;
            break;
    }
}

int check_sgx_device() {
    std::cout << "Checking SGX device..." << std::endl;
    
#ifndef SGX_SIM
    // Check if SGX device exists
    if (access("/dev/isgx", F_OK) == -1) {
        std::cout << "Error: SGX device not found" << std::endl;
        return -1;
    }
    
    // Check read permissions
    if (access("/dev/isgx", R_OK) == -1) {
        std::cout << "Error: No read permission for SGX device" << std::endl;
        return -1;
    }

    // Check if we can open the device
    int fd = open("/dev/isgx", O_RDONLY);
    if (fd == -1) {
        std::cout << "Error: Cannot open SGX device: " << strerror(errno) << std::endl;
        return -1;
    }
    close(fd);
#endif
    
    std::cout << "SGX device check passed" << std::endl;
    return 0;
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(sgx_enclave_id_t* eid, const std::string& launch_token_path, const std::string& enclave_name) {
    printf("Initializing enclave from: %s\n", enclave_name.c_str());
    printf("Token path: %s\n", launch_token_path.c_str());

    // Check if SGX device is available (only in HW mode)
#ifndef SGX_SIM
    printf("Checking SGX device...\n");
    if (access("/dev/isgx", F_OK) == -1) {
        printf("Error: SGX device not found\n");
        return -1;
    }
    printf("SGX device check passed\n");
#endif

    // Open token file
    printf("Opening token file...\n");
    FILE* token_file = fopen(launch_token_path.c_str(), "rb");
    if (token_file == NULL && (errno != ENOENT)) {
        printf("Error: Could not open token file: %s\n", strerror(errno));
        return -1;
    }

    // Create launch token
    printf("Creating launch token...\n");
    sgx_launch_token_t token = {0};
    int token_updated = 0;
    if (token_file != NULL) {
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), token_file);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            printf("Error: Invalid token file\n");
            fclose(token_file);
            return -1;
        }
        fclose(token_file);
    }

    // Create enclave
    printf("Creating enclave...\n");
    printf("Debug flag: %d\n", SGX_DEBUG_FLAG);
    #ifdef NDEBUG
        printf("NDEBUG is defined\n");
    #else
        printf("NDEBUG is not defined\n");
    #endif
    printf("Token size: %zu\n", sizeof(sgx_launch_token_t));
    printf("Enclave name: %s\n", enclave_name.c_str());

    // Check enclave file
    struct stat st;
    if (stat(enclave_name.c_str(), &st) == 0) {
        printf("Enclave file size: %ld bytes\n", st.st_size);
        printf("Enclave file permissions: %o\n", st.st_mode & 0777);
    } else {
        printf("Error: Could not stat enclave file: %s\n", strerror(errno));
        return -1;
    }

    // Create enclave
    printf("Calling sgx_create_enclave...\n");
    printf("Debug flag: %d\n", SGX_DEBUG_FLAG);
    printf("NDEBUG is %s\n", SGX_DEBUG_FLAG ? "not defined" : "defined");
    printf("Token size: %zu\n", sizeof(sgx_launch_token_t));
    printf("Enclave name: %s\n", enclave_name.c_str());
    printf("Enclave file size: %ld bytes\n", (long)st.st_size);
    printf("Enclave file permissions: %o\n", st.st_mode & 0777);
    
    // Add more detailed error checking
    printf("About to call sgx_create_enclave with parameters:\n");
    printf("- enclave_name: %s\n", enclave_name.c_str());
    printf("- debug: %d\n", SGX_DEBUG_FLAG);
    printf("- token: %p\n", (void*)&token);
    printf("- token_updated: %p\n", (void*)&token_updated);
    printf("- eid: %p\n", (void*)eid);
    
    sgx_status_t ret = sgx_create_enclave(enclave_name.c_str(), SGX_DEBUG_FLAG, &token, &token_updated, eid, NULL);
    
    printf("sgx_create_enclave returned with status: %d\n", ret);
    if (ret != SGX_SUCCESS) {
        printf("Error: Failed to create enclave. Error code: %d\n", ret);
        print_error_message(ret);
        return -1;
    }

    // Save token
    printf("Saving launch token...\n");
    token_file = fopen(launch_token_path.c_str(), "wb");
    if (token_file != NULL) {
        fwrite(token, 1, sizeof(sgx_launch_token_t), token_file);
        fclose(token_file);
    }

    printf("Enclave created successfully\n");
    return 0;
}

bool is_ecall_successful(sgx_status_t sgx_status, const std::string& err_msg,
        sgx_status_t ecall_return_value) {
    if (sgx_status != SGX_SUCCESS || ecall_return_value != SGX_SUCCESS) {
        std::cout << err_msg << std::endl;
        if (sgx_status != SGX_SUCCESS) {
            std::cout << "SGX error: ";
            print_error_message(sgx_status);
        }
        if (ecall_return_value != SGX_SUCCESS) {
            std::cout << "Enclave error: ";
            print_error_message(ecall_return_value);
        }
        return false;
    }
    return true;
}
