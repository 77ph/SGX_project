#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t ecall_generate_private_key(void);
sgx_status_t ecall_sign_transaction(uint64_t nonce, uint64_t gas_price, uint64_t gas_limit, uint8_t* to, uint64_t value, uint8_t* data, size_t data_len, uint8_t* signature);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
