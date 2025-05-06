#include "sgx_stubs.h"
#include <stddef.h>

// Stub functions for SGX compatibility
FILE* stderr = NULL;

int printf(const char* format, ...) {
    return 0;
}

int fprintf(FILE* stream, const char* format, ...) {
    return 0;
}

int vfprintf(FILE* stream, const char* format, va_list ap) {
    return 0;
}

int vprintf(const char* format, va_list ap) {
    return 0;
} 
