#ifndef SECP256K1_RECOVERY_H
#define SECP256K1_RECOVERY_H

#include "secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque data structured that holds a parsed ECDSA signature,
 *  supporting pubkey recovery.
 *
 *  The exact representation of data inside is implementation defined and not
 *  guaranteed to be portable between different platforms or versions. It is
 *  however guaranteed to be 65 bytes in size, and can be safely copied/moved.
 *  If you need to convert to a format suitable for storage or transmission, use
 *  the secp256k1_ecdsa_signature_serialize_* and
 *  secp256k1_ecdsa_signature_parse_* functions.
 */
typedef struct {
    unsigned char data[65];
} secp256k1_ecdsa_recoverable_signature;

/** Create a recoverable signature.
 *
 *  Returns: 1: signature created
 *           0: the nonce generation function failed, or the private key was invalid.
 *  Args:    ctx:       pointer to a context object, initialized for signing (cannot be NULL)
 *  Out:     signature: pointer to an array where the signature will be placed (cannot be NULL)
 *  In:      msghash32: the 32-byte message hash being signed (cannot be NULL)
 *           seckey:    pointer to a 32-byte secret key (cannot be NULL)
 *           noncefp:   pointer to a nonce generation function. If NULL, secp256k1_nonce_function_default is used
 *           ndata:     pointer to arbitrary data used by the nonce generation function (can be NULL)
 */
int secp256k1_ecdsa_sign_recoverable(const secp256k1_context* ctx, secp256k1_ecdsa_recoverable_signature *signature, const unsigned char *msghash32, const unsigned char *seckey, secp256k1_nonce_function noncefp, const void* noncedata);

/** Serialize an ECDSA signature in compact format (64 bytes + recovery id).
 *
 *  Returns: 1
 *  Args: ctx:      a secp256k1 context object
 *  Out:  output64: a pointer to a 64-byte array to store the compact signature
 *        recid:    a pointer to an integer to store the recovery id
 *  In:   sig:      a pointer to an initialized signature object
 */
int secp256k1_ecdsa_recoverable_signature_serialize_compact(const secp256k1_context* ctx, unsigned char *output64, int *recid, const secp256k1_ecdsa_recoverable_signature* signature);

/** Parse a compact ECDSA signature (64 bytes + recovery id).
 *
 *  Returns: 1 when the signature could be parsed, 0 otherwise
 *  Args: ctx:      a secp256k1 context object
 *  Out:  signature: a pointer to a signature object
 *  In:   input64:  a pointer to a 64-byte compact signature
 *        recid:    the recovery id (0, 1, 2 or 3)
 */
int secp256k1_ecdsa_recoverable_signature_parse_compact(const secp256k1_context* ctx, secp256k1_ecdsa_recoverable_signature* signature, const unsigned char *input64, int recid);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_RECOVERY_H */ 
