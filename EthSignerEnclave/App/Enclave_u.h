#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t ecall_generate_key(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* private_key, uint8_t* public_key);
sgx_status_t ecall_sign_message(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* msg_hash, uint8_t* signature);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
