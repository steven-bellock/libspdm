/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#if LIBSPDM_CRYPTO_FAULT_INJECTION
#include "cryptlib_fault.h"
#endif /* LIBSPDM_CRYPTO_FAULT_INJECTION */

static bool m_error_acquire_sender_buffer = false;
static bool m_error_acquire_receiver_buffer = false;
static uint32_t m_error_acquire_sender_buffer_count = 0;
static uint32_t m_error_acquire_receiver_buffer_count = 0;

#if LIBSPDM_CRYPTO_FAULT_INJECTION
static libspdm_crypto_fault_op_t get_crypto_fault_op(libspdm_error_target_t target)
{
    assert_true((target >= LIBSPDM_ERR_CRYPTO_ANY) && (target <= LIBSPDM_ERR_CRYPTO_CSR));

    switch (target) {
    case LIBSPDM_ERR_CRYPTO_ANY:
        return LIBSPDM_CRYPTO_FAULT_OP_ANY;
    case LIBSPDM_ERR_CRYPTO_HASH_ALL:
        return LIBSPDM_CRYPTO_FAULT_OP_HASH_ALL;
    case LIBSPDM_ERR_CRYPTO_HASH_NEW:
        return LIBSPDM_CRYPTO_FAULT_OP_HASH_NEW;
    case LIBSPDM_ERR_CRYPTO_HASH_INIT:
        return LIBSPDM_CRYPTO_FAULT_OP_HASH_INIT;
    case LIBSPDM_ERR_CRYPTO_HASH_UPDATE:
        return LIBSPDM_CRYPTO_FAULT_OP_HASH_UPDATE;
    case LIBSPDM_ERR_CRYPTO_HASH_FINAL:
        return LIBSPDM_CRYPTO_FAULT_OP_HASH_FINAL;
    case LIBSPDM_ERR_CRYPTO_HASH_DUPLICATE:
        return LIBSPDM_CRYPTO_FAULT_OP_HASH_DUPLICATE;
    case LIBSPDM_ERR_CRYPTO_HMAC:
        return LIBSPDM_CRYPTO_FAULT_OP_HMAC;
    case LIBSPDM_ERR_CRYPTO_HKDF_EXTRACT:
        return LIBSPDM_CRYPTO_FAULT_OP_HKDF_EXTRACT;
    case LIBSPDM_ERR_CRYPTO_HKDF_EXPAND:
        return LIBSPDM_CRYPTO_FAULT_OP_HKDF_EXPAND;
    case LIBSPDM_ERR_CRYPTO_AEAD_ENCRYPT:
        return LIBSPDM_CRYPTO_FAULT_OP_AEAD_ENCRYPT;
    case LIBSPDM_ERR_CRYPTO_AEAD_DECRYPT:
        return LIBSPDM_CRYPTO_FAULT_OP_AEAD_DECRYPT;
    case LIBSPDM_ERR_CRYPTO_RANDOM:
        return LIBSPDM_CRYPTO_FAULT_OP_RANDOM;
    case LIBSPDM_ERR_CRYPTO_ASYM_KEY:
        return LIBSPDM_CRYPTO_FAULT_OP_ASYM_KEY;
    case LIBSPDM_ERR_CRYPTO_ASYM_SIGN:
        return LIBSPDM_CRYPTO_FAULT_OP_ASYM_SIGN;
    case LIBSPDM_ERR_CRYPTO_ASYM_VERIFY:
        return LIBSPDM_CRYPTO_FAULT_OP_ASYM_VERIFY;
    case LIBSPDM_ERR_CRYPTO_DHE_NEW:
        return LIBSPDM_CRYPTO_FAULT_OP_DHE_NEW;
    case LIBSPDM_ERR_CRYPTO_DHE_GENERATE:
        return LIBSPDM_CRYPTO_FAULT_OP_DHE_GENERATE;
    case LIBSPDM_ERR_CRYPTO_DHE_COMPUTE:
        return LIBSPDM_CRYPTO_FAULT_OP_DHE_COMPUTE;
    case LIBSPDM_ERR_CRYPTO_KEM_NEW:
        return LIBSPDM_CRYPTO_FAULT_OP_KEM_NEW;
    case LIBSPDM_ERR_CRYPTO_KEM_GENERATE:
        return LIBSPDM_CRYPTO_FAULT_OP_KEM_GENERATE;
    case LIBSPDM_ERR_CRYPTO_KEM_ENCAPSULATE:
        return LIBSPDM_CRYPTO_FAULT_OP_KEM_ENCAPSULATE;
    case LIBSPDM_ERR_CRYPTO_KEM_DECAPSULATE:
        return LIBSPDM_CRYPTO_FAULT_OP_KEM_DECAPSULATE;
    case LIBSPDM_ERR_CRYPTO_X509_PARSE:
        return LIBSPDM_CRYPTO_FAULT_OP_X509_PARSE;
    case LIBSPDM_ERR_CRYPTO_X509_VERIFY:
        return LIBSPDM_CRYPTO_FAULT_OP_X509_VERIFY;
    case LIBSPDM_ERR_CRYPTO_CSR:
        return LIBSPDM_CRYPTO_FAULT_OP_CSR;
    default:
        return LIBSPDM_CRYPTO_FAULT_OP_ANY;
    }
}
#endif /* LIBSPDM_CRYPTO_FAULT_INJECTION */

void libspdm_force_error (libspdm_error_target_t target)
{
    switch (target) {
    case LIBSPDM_ERR_ACQUIRE_SENDER_BUFFER:
        m_error_acquire_sender_buffer = true;
        m_error_acquire_sender_buffer_count = 0;
        break;
    case LIBSPDM_ERR_ACQUIRE_RECEIVER_BUFFER:
        m_error_acquire_receiver_buffer = true;
        m_error_acquire_receiver_buffer_count = 0;
        break;
    default:
        libspdm_force_error_ex(target, 0, UINT32_MAX, LIBSPDM_ERR_ACTION_FAIL);
        break;
    }
}

void libspdm_release_error (libspdm_error_target_t target)
{
    switch (target) {
    case LIBSPDM_ERR_ACQUIRE_SENDER_BUFFER:
        m_error_acquire_sender_buffer = false;
        m_error_acquire_sender_buffer_count = 0;
        break;
    case LIBSPDM_ERR_ACQUIRE_RECEIVER_BUFFER:
        m_error_acquire_receiver_buffer = false;
        m_error_acquire_receiver_buffer_count = 0;
        break;
    default:
        #if LIBSPDM_CRYPTO_FAULT_INJECTION
        libspdm_crypto_fault_release(get_crypto_fault_op(target));
        #endif /* LIBSPDM_CRYPTO_FAULT_INJECTION */
        break;
    }
}

void libspdm_force_error_ex (libspdm_error_target_t target, uint32_t skip, uint32_t count,
                             libspdm_error_action_t action)
{
    #if LIBSPDM_CRYPTO_FAULT_INJECTION
    libspdm_crypto_fault_force(get_crypto_fault_op(target), skip, count,
                               (action == LIBSPDM_ERR_ACTION_FAIL) ?
                               LIBSPDM_CRYPTO_FAULT_ACTION_FAIL :
                               LIBSPDM_CRYPTO_FAULT_ACTION_CORRUPT_OUTPUT);
    #else
    assert_true(LIBSPDM_CRYPTO_FAULT_INJECTION);
    #endif /* LIBSPDM_CRYPTO_FAULT_INJECTION */
}

uint32_t libspdm_get_forced_error_count (libspdm_error_target_t target)
{
    switch (target) {
    case LIBSPDM_ERR_ACQUIRE_SENDER_BUFFER:
        return m_error_acquire_sender_buffer_count;
    case LIBSPDM_ERR_ACQUIRE_RECEIVER_BUFFER:
        return m_error_acquire_receiver_buffer_count;
    default:
        #if LIBSPDM_CRYPTO_FAULT_INJECTION
        return libspdm_crypto_fault_get_applied_count(get_crypto_fault_op(target));
        #else
        return 0;
        #endif /* LIBSPDM_CRYPTO_FAULT_INJECTION */
    }
}

uint32_t libspdm_get_crypto_call_count (libspdm_error_target_t target)
{
    #if LIBSPDM_CRYPTO_FAULT_INJECTION
    return libspdm_crypto_fault_get_call_count(get_crypto_fault_op(target));
    #else
    assert_true(LIBSPDM_CRYPTO_FAULT_INJECTION);
    return 0;
    #endif /* LIBSPDM_CRYPTO_FAULT_INJECTION */
}

void libspdm_suspend_crypto_errors (void)
{
    #if LIBSPDM_CRYPTO_FAULT_INJECTION
    libspdm_crypto_fault_suspend();
    #endif /* LIBSPDM_CRYPTO_FAULT_INJECTION */
}

void libspdm_resume_crypto_errors (void)
{
    #if LIBSPDM_CRYPTO_FAULT_INJECTION
    libspdm_crypto_fault_resume();
    #endif /* LIBSPDM_CRYPTO_FAULT_INJECTION */
}

bool libspdm_apply_buffer_error (libspdm_error_target_t target)
{
    assert_true((target == LIBSPDM_ERR_ACQUIRE_SENDER_BUFFER) ||
                (target == LIBSPDM_ERR_ACQUIRE_RECEIVER_BUFFER));

    switch (target) {
    case LIBSPDM_ERR_ACQUIRE_SENDER_BUFFER:
        if (m_error_acquire_sender_buffer) {
            m_error_acquire_sender_buffer_count++;
        }
        return m_error_acquire_sender_buffer;
    case LIBSPDM_ERR_ACQUIRE_RECEIVER_BUFFER:
        if (m_error_acquire_receiver_buffer) {
            m_error_acquire_receiver_buffer_count++;
        }
        return m_error_acquire_receiver_buffer;
    default:
        return false;
    }
}
