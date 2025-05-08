#ifndef _APP_H_
#define _APP_H_

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "sgx_urts.h"
#include "sgx_utils/sgx_utils.h"

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(SGX_SIM)
    #define ENCLAVE_FILENAME "enclave.so"
#else
    #define ENCLAVE_FILENAME "enclave.signed.so"
#endif

#if defined(SGX_DEBUG)
    #define SGX_DEBUG_FLAG 1
#else
    #define SGX_DEBUG_FLAG 0
#endif

void ocall_print(const char* str);

#if defined(__cplusplus)
}
#endif

#endif /* !_APP_H_ */ 
