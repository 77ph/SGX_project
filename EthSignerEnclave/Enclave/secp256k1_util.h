#ifndef SECP256K1_UTIL_H
#define SECP256K1_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <limits.h>

// Stub implementations for stdio functions
static inline int printf(const char* fmt, ...) {
    return 0;
}

static inline int fprintf(void* stream, const char* fmt, ...) {
    return 0;
}

static void* stderr = NULL;

// Basic utility functions
static inline void *checked_malloc(const void* ctx, size_t size) {
    void* ret = malloc(size);
    if (ret == NULL) {
        fprintf(stderr, "Out of memory\n");
    }
    return ret;
}

static inline void *checked_realloc(const void* ctx, void* ptr, size_t size) {
    void* ret = realloc(ptr, size);
    if (ret == NULL) {
        fprintf(stderr, "Out of memory\n");
    }
    return ret;
}

static inline void checked_free(const void* ctx, void* ptr) {
    free(ptr);
}

// Callback functions
typedef void (*secp256k1_callback_fn)(const char* text, void* data);
typedef struct {
    secp256k1_callback_fn fn;
    void* data;
} secp256k1_callback;

static void secp256k1_default_illegal_callback_fn(const char* str, void* data) {
    fprintf(stderr, "[libsecp256k1] illegal argument: %s\n", str);
}

static void secp256k1_default_error_callback_fn(const char* str, void* data) {
    fprintf(stderr, "[libsecp256k1] internal consistency check failed: %s\n", str);
}

#endif /* SECP256K1_UTIL_H */ 
