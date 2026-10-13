/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef CRYPTLIB_FAULT_H
#define CRYPTLIB_FAULT_H

#include "hal/base.h"

/* The operations that a forwarder in cryptlib_fault_forward.c belongs to. ANY is every operation
 * that can fail. The order matches the LIBSPDM_ERR_CRYPTO_* targets in spdm_unit_test.h. */
typedef enum {
    LIBSPDM_CRYPTO_FAULT_OP_ANY,
    LIBSPDM_CRYPTO_FAULT_OP_HASH_ALL,
    LIBSPDM_CRYPTO_FAULT_OP_HASH_NEW,
    LIBSPDM_CRYPTO_FAULT_OP_HASH_INIT,
    LIBSPDM_CRYPTO_FAULT_OP_HASH_UPDATE,
    LIBSPDM_CRYPTO_FAULT_OP_HASH_FINAL,
    LIBSPDM_CRYPTO_FAULT_OP_HASH_DUPLICATE,
    LIBSPDM_CRYPTO_FAULT_OP_HMAC,
    LIBSPDM_CRYPTO_FAULT_OP_HKDF_EXTRACT,
    LIBSPDM_CRYPTO_FAULT_OP_HKDF_EXPAND,
    LIBSPDM_CRYPTO_FAULT_OP_AEAD_ENCRYPT,
    LIBSPDM_CRYPTO_FAULT_OP_AEAD_DECRYPT,
    LIBSPDM_CRYPTO_FAULT_OP_RANDOM,
    LIBSPDM_CRYPTO_FAULT_OP_ASYM_KEY,
    LIBSPDM_CRYPTO_FAULT_OP_ASYM_SIGN,
    LIBSPDM_CRYPTO_FAULT_OP_ASYM_VERIFY,
    LIBSPDM_CRYPTO_FAULT_OP_DHE_NEW,
    LIBSPDM_CRYPTO_FAULT_OP_DHE_GENERATE,
    LIBSPDM_CRYPTO_FAULT_OP_DHE_COMPUTE,
    LIBSPDM_CRYPTO_FAULT_OP_KEM_NEW,
    LIBSPDM_CRYPTO_FAULT_OP_KEM_GENERATE,
    LIBSPDM_CRYPTO_FAULT_OP_KEM_ENCAPSULATE,
    LIBSPDM_CRYPTO_FAULT_OP_KEM_DECAPSULATE,
    LIBSPDM_CRYPTO_FAULT_OP_X509_PARSE,
    LIBSPDM_CRYPTO_FAULT_OP_X509_VERIFY,
    LIBSPDM_CRYPTO_FAULT_OP_CSR,
    LIBSPDM_CRYPTO_FAULT_OP_COUNT
} libspdm_crypto_fault_op_t;

typedef enum {
    LIBSPDM_CRYPTO_FAULT_ACTION_NONE,
    /* Returns false or NULL without calling the backend. */
    LIBSPDM_CRYPTO_FAULT_ACTION_FAIL,
    /* Calls the backend, then flips one bit of the output. */
    LIBSPDM_CRYPTO_FAULT_ACTION_CORRUPT_OUTPUT
} libspdm_crypto_fault_action_t;

/**
 * Counts a call of an operation and returns the action to apply to it. A CORRUPT_OUTPUT fault does
 * not apply to a call that cannot corrupt its output.
 *
 * @param  op           The operation of the forwarder.
 * @param  can_corrupt  Whether the forwarder can corrupt its output.
 **/
libspdm_crypto_fault_action_t libspdm_crypto_fault_hit(libspdm_crypto_fault_op_t op,
                                                       bool can_corrupt);

/**
 * Flips the lowest bit of the first byte of an output, if it has one.
 **/
void libspdm_crypto_fault_corrupt(uint8_t *output, size_t output_size);

/**
 * Applies the action to count calls of the operation after the next skip calls. The counts start
 * again from 0.
 **/
void libspdm_crypto_fault_force(libspdm_crypto_fault_op_t op, uint32_t skip, uint32_t count,
                                libspdm_crypto_fault_action_t action);

/**
 * Stops applying an action to the operation and zeroes its counts. ANY releases every operation.
 **/
void libspdm_crypto_fault_release(libspdm_crypto_fault_op_t op);

/**
 * Returns the number of calls of the operation that the action applied to since it was forced.
 **/
uint32_t libspdm_crypto_fault_get_applied_count(libspdm_crypto_fault_op_t op);

/**
 * Returns the number of calls of the operation since it was last forced or released.
 **/
uint32_t libspdm_crypto_fault_get_call_count(libspdm_crypto_fault_op_t op);

/**
 * While suspended, calls are neither counted nor faulted. Suspensions nest.
 **/
void libspdm_crypto_fault_suspend(void);
void libspdm_crypto_fault_resume(void);

#endif /* CRYPTLIB_FAULT_H */
