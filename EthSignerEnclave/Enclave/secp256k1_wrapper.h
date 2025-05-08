#ifndef SECP256K1_WRAPPER_H
#define SECP256K1_WRAPPER_H

#include <stdint.h>
#include <stddef.h>

// Context creation flags
#define SECP256K1_CONTEXT_SIGN (1 << 0)
#define SECP256K1_CONTEXT_VERIFY (1 << 1)

// Opaque data structures
typedef struct secp256k1_context_struct secp256k1_context;
typedef struct {
    unsigned char data[64];
} secp256k1_ecdsa_signature;

// Function declarations
secp256k1_context* secp256k1_context_create(unsigned int flags);
void secp256k1_context_destroy(secp256k1_context* ctx);
int secp256k1_ec_seckey_verify(const secp256k1_context* ctx, const unsigned char *seckey);
int secp256k1_ecdsa_sign(const secp256k1_context* ctx, secp256k1_ecdsa_signature *sig, const unsigned char *msg32, const unsigned char *seckey, void *noncefp, const void *ndata);
int secp256k1_ecdsa_signature_serialize_compact(const secp256k1_context* ctx, unsigned char *output64, const secp256k1_ecdsa_signature* sig);

#endif // SECP256K1_WRAPPER_H 
