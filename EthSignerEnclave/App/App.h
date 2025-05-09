#ifndef _APP_H_
#define _APP_H_

#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "sgx_utils/sgx_utils.h"

/* Hard-coded filename for the enclave image you will build */
#define ENCLAVE_FILENAME "enclave.signed.so"

#if defined(__cplusplus)
extern "C" {
#endif

void ocall_print(const char* str);

#if defined(__cplusplus)
}
#endif

#endif /* !_APP_H_ */ 
