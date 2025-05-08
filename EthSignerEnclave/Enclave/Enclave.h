#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <stdlib.h>
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

// Глобальные переменные для SGX
extern void* g_global_data_sim;
extern void* g_global_data;
extern void* g_peak_heap_used;
extern void* g_peak_rsrv_mem_committed;

// Наша собственная функция для вывода в энклаве
int enclave_printf(const char *fmt, ...);

#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE_H_ */ 
