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

static sgx_status_t SGX_CDECL sgx_ecall_generate_key(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_generate_key_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_generate_key_t* ms = SGX_CAST(ms_ecall_generate_key_t*, pms);
	ms_ecall_generate_key_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_generate_key_t), ms, sizeof(ms_ecall_generate_key_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_private_key = __in_ms.ms_private_key;
	size_t _len_private_key = 32;
	uint8_t* _in_private_key = NULL;
	uint8_t* _tmp_public_key = __in_ms.ms_public_key;
	size_t _len_public_key = 65;
	uint8_t* _in_public_key = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_private_key, _len_private_key);
	CHECK_UNIQUE_POINTER(_tmp_public_key, _len_public_key);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_private_key != NULL && _len_private_key != 0) {
		if ( _len_private_key % sizeof(*_tmp_private_key) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_private_key = (uint8_t*)malloc(_len_private_key)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_private_key, 0, _len_private_key);
	}
	if (_tmp_public_key != NULL && _len_public_key != 0) {
		if ( _len_public_key % sizeof(*_tmp_public_key) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_public_key = (uint8_t*)malloc(_len_public_key)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_public_key, 0, _len_public_key);
	}
	_in_retval = ecall_generate_key(_in_private_key, _in_public_key);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_private_key) {
		if (memcpy_verw_s(_tmp_private_key, _len_private_key, _in_private_key, _len_private_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_public_key) {
		if (memcpy_verw_s(_tmp_public_key, _len_public_key, _in_public_key, _len_public_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_private_key) free(_in_private_key);
	if (_in_public_key) free(_in_public_key);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_sign_message(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_sign_message_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_sign_message_t* ms = SGX_CAST(ms_ecall_sign_message_t*, pms);
	ms_ecall_sign_message_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_sign_message_t), ms, sizeof(ms_ecall_sign_message_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_msg_hash = __in_ms.ms_msg_hash;
	size_t _len_msg_hash = 32;
	uint8_t* _in_msg_hash = NULL;
	uint8_t* _tmp_signature = __in_ms.ms_signature;
	size_t _len_signature = 64;
	uint8_t* _in_signature = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_msg_hash, _len_msg_hash);
	CHECK_UNIQUE_POINTER(_tmp_signature, _len_signature);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_msg_hash != NULL && _len_msg_hash != 0) {
		if ( _len_msg_hash % sizeof(*_tmp_msg_hash) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_msg_hash = (uint8_t*)malloc(_len_msg_hash);
		if (_in_msg_hash == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_msg_hash, _len_msg_hash, _tmp_msg_hash, _len_msg_hash)) {
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
	_in_retval = ecall_sign_message((const uint8_t*)_in_msg_hash, _in_signature);
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
	if (_in_msg_hash) free(_in_msg_hash);
	if (_in_signature) free(_in_signature);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[2];
} g_ecall_table = {
	2,
	{
		{(void*)(uintptr_t)sgx_ecall_generate_key, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_sign_message, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};


