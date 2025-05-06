#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_generate_private_key_t {
	sgx_status_t ms_retval;
} ms_ecall_generate_private_key_t;

typedef struct ms_ecall_sign_transaction_t {
	sgx_status_t ms_retval;
	uint64_t ms_nonce;
	uint64_t ms_gas_price;
	uint64_t ms_gas_limit;
	uint8_t* ms_to;
	uint64_t ms_value;
	uint8_t* ms_data;
	size_t ms_data_len;
	uint8_t* ms_signature;
} ms_ecall_sign_transaction_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	0,
	{ NULL },
};
sgx_status_t ecall_generate_private_key(sgx_enclave_id_t eid, sgx_status_t* retval)
{
	sgx_status_t status;
	ms_ecall_generate_private_key_t ms;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_sign_transaction(sgx_enclave_id_t eid, sgx_status_t* retval, uint64_t nonce, uint64_t gas_price, uint64_t gas_limit, uint8_t* to, uint64_t value, uint8_t* data, size_t data_len, uint8_t* signature)
{
	sgx_status_t status;
	ms_ecall_sign_transaction_t ms;
	ms.ms_nonce = nonce;
	ms.ms_gas_price = gas_price;
	ms.ms_gas_limit = gas_limit;
	ms.ms_to = to;
	ms.ms_value = value;
	ms.ms_data = data;
	ms.ms_data_len = data_len;
	ms.ms_signature = signature;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

