#include "../include/secp256k1.h"
#include "secp256k1_recovery.h"
#include "util.h"
#include "field_impl.h"
#include "scalar.h"
#include "scalar_impl.h"
#include "group.h"
#include "group_impl.h"
#include "ecmult.h"
#include "ecmult_impl.h"
#include "ecmult_const.h"
#include "ecmult_const_impl.h"
#include "ecmult_gen.h"
#include "ecmult_gen_impl.h"
#include "ecdsa.h"
#include "ecdsa_impl.h"
#include <string.h>

int secp256k1_ecdsa_sign_recoverable(const secp256k1_context* ctx, secp256k1_ecdsa_recoverable_signature *signature, const unsigned char *msghash32, const unsigned char *seckey, secp256k1_nonce_function noncefp, const void* noncedata) {
    int ret = 0;
    int recid = 0;

    if (ctx == NULL || msghash32 == NULL || signature == NULL || seckey == NULL) {
        return 0;
    }

    ret = secp256k1_ecdsa_sign(ctx, (secp256k1_ecdsa_signature*)signature, msghash32, seckey, noncefp, noncedata);
    if (ret) {
        secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, NULL, &recid, signature);
        signature->data[64] = recid;
    }
    return ret;
}

int secp256k1_ecdsa_recoverable_signature_serialize_compact(const secp256k1_context* ctx, unsigned char *output64, int *recid, const secp256k1_ecdsa_recoverable_signature* signature) {
    if (ctx == NULL || signature == NULL || recid == NULL) {
        return 0;
    }

    if (output64 != NULL) {
        memcpy(output64, signature->data, 64);
    }
    *recid = signature->data[64];
    return 1;
}

int secp256k1_ecdsa_recoverable_signature_parse_compact(const secp256k1_context* ctx, secp256k1_ecdsa_recoverable_signature* signature, const unsigned char *input64, int recid) {
    if (ctx == NULL || signature == NULL || input64 == NULL || recid < 0 || recid > 3) {
        return 0;
    }

    memcpy(signature->data, input64, 64);
    signature->data[64] = recid;
    return 1;
} 
