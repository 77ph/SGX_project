#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_ecall_generate_private_key(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_generate_private_key_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_generate_private_key_t* ms = SGX_CAST(ms_ecall_generate_private_key_t*, pms);
	ms_ecall_generate_private_key_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_generate_private_key_t), ms, sizeof(ms_ecall_generate_private_key_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_status_t _in_retval;


	_in_retval = ecall_generate_private_key();
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_sign_transaction(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_sign_transaction_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_sign_transaction_t* ms = SGX_CAST(ms_ecall_sign_transaction_t*, pms);
	ms_ecall_sign_transaction_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_sign_transaction_t), ms, sizeof(ms_ecall_sign_transaction_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_to = __in_ms.ms_to;
	size_t _len_to = 20;
	uint8_t* _in_to = NULL;
	uint8_t* _tmp_data = __in_ms.ms_data;
	size_t _tmp_data_len = __in_ms.ms_data_len;
	size_t _len_data = _tmp_data_len;
	uint8_t* _in_data = NULL;
	uint8_t* _tmp_signature = __in_ms.ms_signature;
	size_t _len_signature = 65;
	uint8_t* _in_signature = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_to, _len_to);
	CHECK_UNIQUE_POINTER(_tmp_data, _len_data);
	CHECK_UNIQUE_POINTER(_tmp_signature, _len_signature);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_to != NULL && _len_to != 0) {
		if ( _len_to % sizeof(*_tmp_to) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_to = (uint8_t*)malloc(_len_to);
		if (_in_to == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_to, _len_to, _tmp_to, _len_to)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_data != NULL && _len_data != 0) {
		if ( _len_data % sizeof(*_tmp_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_data = (uint8_t*)malloc(_len_data);
		if (_in_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_data, _len_data, _tmp_data, _len_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_signature != NULL && _len_signature != 0) {
		if ( _len_signature % sizeof(*_tmp_signature) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_signature = (uint8_t*)malloc(_len_signature)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_signature, 0, _len_signature);
	}
	_in_retval = ecall_sign_transaction(__in_ms.ms_nonce, __in_ms.ms_gas_price, __in_ms.ms_gas_limit, _in_to, __in_ms.ms_value, _in_data, _tmp_data_len, _in_signature);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_signature) {
		if (memcpy_verw_s(_tmp_signature, _len_signature, _in_signature, _len_signature)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_to) free(_in_to);
	if (_in_data) free(_in_data);
	if (_in_signature) free(_in_signature);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[2];
} g_ecall_table = {
	2,
	{
		{(void*)(uintptr_t)sgx_ecall_generate_private_key, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_sign_transaction, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};


