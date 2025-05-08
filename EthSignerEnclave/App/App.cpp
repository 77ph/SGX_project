#include "App.h"
#include "Enclave_u.h"
#include "sgx_utils/sgx_utils.h"
#include <iostream>
#include <cstring>
#include <string>

#define BUFLEN 2048
#define MAXPATHLEN 255

void ocall_print(const char* str) {
    std::cout << str;
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    /* Initialize the enclave */
    sgx_enclave_id_t eid = 0;
#ifdef SGX_SIM
    const char* enclave_file = "enclave.so";
#else
    const char* enclave_file = "enclave.signed.so";
#endif

    if (initialize_enclave(&eid, "enclave.token", enclave_file) < 0) {
        printf("Failed to initialize enclave\n");
        return -1;
    }

    // Test enclave call
    int retval = 0;
    sgx_status_t ret = ecall_test_function(eid, &retval);
    if (ret != SGX_SUCCESS) {
        printf("Failed to call test function: %d\n", ret);
        return -1;
    }
    printf("Test call successful, retval = %d\n", retval);

    // Generate private key
    uint8_t private_key[32];
    ret = ecall_generate_private_key(eid, &retval, private_key, sizeof(private_key));
    if (ret != SGX_SUCCESS) {
        printf("Failed to call generate_private_key: %d\n", ret);
        return -1;
    }
    if (retval != 0) {
        printf("Failed to generate private key inside enclave: %d\n", retval);
        return -1;
    }
    printf("Private key generated successfully\n");

    // Sign a test transaction
    uint8_t tx_hash[32] = {0}; // Test hash
    uint8_t signature[64];
    ret = ecall_sign_transaction(eid, &retval, tx_hash, sizeof(tx_hash), signature, sizeof(signature));
    if (ret != SGX_SUCCESS) {
        printf("Failed to call sign_transaction: %d\n", ret);
        return -1;
    }
    if (retval != 0) {
        printf("Failed to sign transaction inside enclave: %d\n", retval);
        return -1;
    }
    printf("Transaction signed successfully\n");

    // Destroy the enclave
    sgx_destroy_enclave(eid);
    return 0;
}
