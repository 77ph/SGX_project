#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_generate_key_t {
	sgx_status_t ms_retval;
	uint8_t* ms_private_key;
	uint8_t* ms_public_key;
} ms_ecall_generate_key_t;

typedef struct ms_ecall_sign_message_t {
	sgx_status_t ms_retval;
	const uint8_t* ms_msg_hash;
	uint8_t* ms_signature;
} ms_ecall_sign_message_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	0,
	{ NULL },
};
sgx_status_t ecall_generate_key(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* private_key, uint8_t* public_key)
{
	sgx_status_t status;
	ms_ecall_generate_key_t ms;
	ms.ms_private_key = private_key;
	ms.ms_public_key = public_key;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_sign_message(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* msg_hash, uint8_t* signature)
{
	sgx_status_t status;
	ms_ecall_sign_message_t ms;
	ms.ms_msg_hash = msg_hash;
	ms.ms_signature = signature;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

