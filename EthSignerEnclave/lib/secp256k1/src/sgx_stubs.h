#ifndef SGX_STUBS_H
#define SGX_STUBS_H

#include <stdarg.h>

// Forward declarations for stdio types
typedef struct _iobuf FILE;

// Stub declarations
extern FILE* stderr;

int printf(const char* format, ...);
int fprintf(FILE* stream, const char* format, ...);
int vfprintf(FILE* stream, const char* format, va_list ap);
int vprintf(const char* format, va_list ap);

#endif // SGX_STUBS_H 
