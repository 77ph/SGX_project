#ifndef _SGX_UTILS_H_
#define _SGX_UTILS_H_

#include <string>
#include "sgx_urts.h"

#ifdef NDEBUG
#define SGX_DEBUG_FLAG 0
#else
#define SGX_DEBUG_FLAG 1
#endif

void print_error_message(sgx_status_t ret);
int check_sgx_device();
int initialize_enclave(sgx_enclave_id_t* eid, const std::string& launch_token_path, const std::string& enclave_name);
bool is_ecall_successful(sgx_status_t sgx_status, const std::string& err_msg, sgx_status_t ecall_return_value);

#endif // _SGX_UTILS_H_
