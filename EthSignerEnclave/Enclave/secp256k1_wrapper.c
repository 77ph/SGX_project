#include "secp256k1_wrapper.h"
#include "secp256k1.h"
#include "secp256k1_ecdsa.h"

secp256k1_context* secp256k1_context_create(unsigned int flags) {
    return secp256k1_context_create(flags);
}

void secp256k1_context_destroy(secp256k1_context* ctx) {
    secp256k1_context_destroy(ctx);
}

int secp256k1_ec_seckey_verify(const secp256k1_context* ctx, const unsigned char *seckey) {
    return secp256k1_ec_seckey_verify(ctx, seckey);
}

int secp256k1_ecdsa_sign(const secp256k1_context* ctx, secp256k1_ecdsa_signature *sig, const unsigned char *msg32, const unsigned char *seckey, void *noncefp, const void *ndata) {
    return secp256k1_ecdsa_sign(ctx, sig, msg32, seckey, noncefp, ndata);
}

int secp256k1_ecdsa_signature_serialize_compact(const secp256k1_context* ctx, unsigned char *output64, const secp256k1_ecdsa_signature* sig) {
    return secp256k1_ecdsa_signature_serialize_compact(ctx, output64, sig);
} 
