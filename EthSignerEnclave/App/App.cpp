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

#define BUFLEN 2048
#define MAXPATHLEN 255

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

// OCall functions
void ocall_print(const char* str) {
    printf("%s", str);
}

int initialize_enclave(void) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, 1, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("Error: %d\n", ret);
        return -1;
    }

    return 0;
}

/* Application entry */
int main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    /* Initialize the enclave */
    if(initialize_enclave() < 0)
    {
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }
 
    /* Test function */
    int retval;
    sgx_status_t status = ecall_test_function(global_eid, &retval);
    if (status != SGX_SUCCESS || retval < 0) {
        printf("Test function failed\n");
        return -1;
    }
    printf("Test function returned: %d\n", retval);

    /* Generate private key */
    uint8_t private_key[32];
    status = ecall_generate_private_key(global_eid, &retval, private_key, sizeof(private_key));
    if (status != SGX_SUCCESS || retval < 0) {
        printf("Failed to generate private key\n");
        return -1;
    }
    printf("Private key generated successfully\n");

    /* Sign transaction */
    uint8_t tx_hash[32] = {0}; // Example transaction hash
    uint8_t signature[64];
    status = ecall_sign_transaction(global_eid, &retval, tx_hash, sizeof(tx_hash),
                                  private_key, sizeof(private_key),
                                  signature, sizeof(signature));
    if (status != SGX_SUCCESS || retval < 0) {
        printf("Failed to sign transaction\n");
        return -1;
    }
    printf("Transaction signed successfully\n");

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    
    printf("Info: SampleEnclave successfully returned.\n");
    printf("Enter a character before exit ...\n");
    getchar();
    return 0;
}
