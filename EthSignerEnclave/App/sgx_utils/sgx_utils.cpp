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
    std::cerr << "SGX error code: 0x" << std::hex << ret << std::dec << std::endl;
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(sgx_enclave_id_t* eid, const std::string& launch_token_path, const std::string& enclave_name) {
    std::cout << "Initializing enclave..." << std::endl;
    std::cout << "Enclave path: " << enclave_name << std::endl;
    std::cout << "Token path: " << launch_token_path << std::endl;

    // Проверяем доступность устройств SGX
    std::cout << "Checking SGX devices..." << std::endl;
    if (access("/dev/isgx", F_OK) == -1) {
        std::cerr << "Error: SGX device not found" << std::endl;
        return -1;
    }
    if (access("/dev/isgx", R_OK) == -1) {
        std::cerr << "Error: No read permission for SGX device" << std::endl;
        return -1;
    }

    const char* token_path = launch_token_path.c_str();
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;

    /* Step 1: try to retrieve the launch token saved by last transaction
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    std::cout << "Opening token file..." << std::endl;
    FILE* fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        std::cerr << "Warning: Failed to create/open the launch token file \"" << token_path << "\"." << std::endl;
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            std::cerr << "Warning: Invalid launch token read from \"" << token_path << "\"." << std::endl;
        }
    }

    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    std::cout << "Creating enclave..." << std::endl;
    std::cout << "Debug flag: " << SGX_DEBUG << std::endl;
    std::cout << "Token size: " << sizeof(sgx_launch_token_t) << std::endl;
    std::cout << "Enclave name: " << enclave_name << std::endl;

    // Проверяем существование файла энклава
    struct stat st;
    if (stat(enclave_name.c_str(), &st) == -1) {
        std::cerr << "Error: Enclave file not found: " << enclave_name << std::endl;
        if (fp != NULL) fclose(fp);
        return -1;
    }
    std::cout << "Enclave file size: " << st.st_size << " bytes" << std::endl;
    std::cout << "Enclave file permissions: " << std::oct << (st.st_mode & 0777) << std::dec << std::endl;

    // Проверяем права доступа к файлу энклава
    if (access(enclave_name.c_str(), R_OK) == -1) {
        std::cerr << "Error: No read permission for enclave file: " << enclave_name << std::endl;
        if (fp != NULL) fclose(fp);
        return -1;
    }

    std::cout << "Calling sgx_create_enclave..." << std::endl;
    ret = sgx_create_enclave(enclave_name.c_str(), SGX_DEBUG, &token, &updated, eid, NULL);
    std::cout << "sgx_create_enclave returned: 0x" << std::hex << ret << std::dec << std::endl;
    
    if (ret != SGX_SUCCESS) {
        std::cerr << "Failed to create enclave: ";
        print_error_message(ret);
        if (fp != NULL) fclose(fp);
        return -1;
    }

    std::cout << "Enclave created successfully with ID: " << std::hex << *eid << std::dec << std::endl;
    std::cout << "Token updated: " << (updated ? "yes" : "no") << std::endl;

    /* Step 3: save the launch token if it is updated */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    std::cout << "Saving updated token..." << std::endl;
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        std::cerr << "Warning: Failed to save launch token to \"" << token_path << "\"." << std::endl;
    fclose(fp);
    return 0;
}

bool is_ecall_successful(sgx_status_t sgx_status, const std::string& err_msg,
        sgx_status_t ecall_return_value) {
    if (sgx_status != SGX_SUCCESS || ecall_return_value != SGX_SUCCESS) {
        std::cerr << err_msg << std::endl;
        if (sgx_status != SGX_SUCCESS) {
            std::cerr << "SGX error: ";
            print_error_message(sgx_status);
        }
        if (ecall_return_value != SGX_SUCCESS) {
            std::cerr << "Enclave error: ";
            print_error_message(ecall_return_value);
        }
        return false;
    }
    return true;
}
