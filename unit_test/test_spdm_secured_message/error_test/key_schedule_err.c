/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_secured_message_lib.h"

/* Each case fails the crypto calls of a key derivation one at a time. */

#if LIBSPDM_AEAD_AES_256_GCM_SUPPORT && LIBSPDM_SHA256_SUPPORT

#if LIBSPDM_CRYPTO_FAULT_INJECTION
#define OLD_SECRET_BYTE 0xAA
#define OLD_KEY_BYTE    0xBB
#define OLD_SALT_BYTE   0xCC
#define OLD_SEQ_NUMBER  0x42

static libspdm_secured_message_context_t m_secured_message_context;
static uint8_t m_th_hash[LIBSPDM_SHA256_DIGEST_SIZE];

/* Gives the test a new context for a DHE session that uses SHA-256 and AES-256-GCM. It has a
 * shared secret, a handshake secret, and data keys with a recognizable pattern per direction. */
static void init_secured_message_context(void)
{
    libspdm_session_info_struct_application_secret_t *secret;

    libspdm_zero_mem(&m_secured_message_context, sizeof(m_secured_message_context));
    m_secured_message_context.version = SPDM_MESSAGE_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    m_secured_message_context.secured_message_version =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    m_secured_message_context.base_hash_algo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
    m_secured_message_context.aead_cipher_suite = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM;
    m_secured_message_context.session_type = LIBSPDM_SESSION_TYPE_ENC_MAC;
    m_secured_message_context.session_state = LIBSPDM_SESSION_STATE_ESTABLISHED;
    m_secured_message_context.hash_size = LIBSPDM_SHA256_DIGEST_SIZE;
    m_secured_message_context.aead_key_size = 32;
    m_secured_message_context.aead_iv_size = 12;
    m_secured_message_context.shared_key_size = 32;
    libspdm_set_mem(m_secured_message_context.master_secret.shared_secret, 32, 0x5A);
    libspdm_set_mem(m_secured_message_context.master_secret.handshake_secret,
                    LIBSPDM_SHA256_DIGEST_SIZE, 0x3C);

    secret = &m_secured_message_context.application_secret;
    libspdm_set_mem(secret->request_data_secret, LIBSPDM_SHA256_DIGEST_SIZE, OLD_SECRET_BYTE);
    libspdm_set_mem(secret->request_data_encryption_key, 32, OLD_KEY_BYTE);
    libspdm_set_mem(secret->request_data_salt, 12, OLD_SALT_BYTE);
    secret->request_data_sequence_number = OLD_SEQ_NUMBER;
    libspdm_set_mem(secret->response_data_secret, LIBSPDM_SHA256_DIGEST_SIZE, OLD_SECRET_BYTE);
    libspdm_set_mem(secret->response_data_encryption_key, 32, OLD_KEY_BYTE);
    libspdm_set_mem(secret->response_data_salt, 12, OLD_SALT_BYTE);
    secret->response_data_sequence_number = OLD_SEQ_NUMBER;

    libspdm_set_mem(m_th_hash, sizeof(m_th_hash), 0x77);
}

/* Asserts that the data keys of the given direction hold the pattern from before the update. */
static void assert_old_keys(libspdm_key_update_action_t action)
{
    const libspdm_session_info_struct_application_secret_t *secret;
    const uint8_t *data_secret;
    const uint8_t *encryption_key;
    const uint8_t *salt;
    uint64_t sequence_number;
    size_t index;

    secret = &m_secured_message_context.application_secret;
    if (action == LIBSPDM_KEY_UPDATE_ACTION_REQUESTER) {
        data_secret = secret->request_data_secret;
        encryption_key = secret->request_data_encryption_key;
        salt = secret->request_data_salt;
        sequence_number = secret->request_data_sequence_number;
    } else {
        data_secret = secret->response_data_secret;
        encryption_key = secret->response_data_encryption_key;
        salt = secret->response_data_salt;
        sequence_number = secret->response_data_sequence_number;
    }

    for (index = 0; index < LIBSPDM_SHA256_DIGEST_SIZE; index++) {
        assert_int_equal(data_secret[index], OLD_SECRET_BYTE);
    }
    for (index = 0; index < 32; index++) {
        assert_int_equal(encryption_key[index], OLD_KEY_BYTE);
    }
    for (index = 0; index < 12; index++) {
        assert_int_equal(salt[index], OLD_SALT_BYTE);
    }
    assert_int_equal(sequence_number, OLD_SEQ_NUMBER);
}

/* Fails the crypto call after skipping call_index of them. */
static void force_crypto_error(uint32_t call_index)
{
    libspdm_force_error_ex(LIBSPDM_ERR_CRYPTO_ANY, call_index, 1, LIBSPDM_ERR_ACTION_FAIL);
}

/* Releases the crypto error and returns the number of calls that failed, which is 0 once
 * call_index reaches the number of crypto calls that the derivation makes. */
static uint32_t release_crypto_error(void)
{
    uint32_t error_count;

    error_count = libspdm_get_forced_error_count(LIBSPDM_ERR_CRYPTO_ANY);
    libspdm_release_error(LIBSPDM_ERR_CRYPTO_ANY);

    return error_count;
}

/* Fails each crypto call of a data key update in turn, and rolls the update back each time. */
static void test_update_session_data_key(libspdm_key_update_action_t action)
{
    bool result;
    bool backup_valid;
    uint32_t call_index;

    for (call_index = 0; ; call_index++) {
        init_secured_message_context();

        /* {ERROR} One crypto call of the update fails. */
        force_crypto_error(call_index);
        result = libspdm_create_update_session_data_key(&m_secured_message_context, action);
        if (release_crypto_error() == 0) {
            break;
        }

        assert_false(result);
        if (action == LIBSPDM_KEY_UPDATE_ACTION_REQUESTER) {
            backup_valid = m_secured_message_context.requester_backup_valid;
        } else {
            backup_valid = m_secured_message_context.responder_backup_valid;
        }
        assert_true(backup_valid);

        result = libspdm_activate_update_session_data_key(&m_secured_message_context, action,
                                                          false);
        assert_true(result);
        assert_old_keys(action);
    }
    assert_true(result);
    assert_int_equal(call_index, 3);
}
#endif /* LIBSPDM_CRYPTO_FAULT_INJECTION */

/**
 * Test 1: Each crypto call of libspdm_generate_session_handshake_key fails in turn, for a session
 * whose shared secret comes from DHE.
 * Expected behavior: the derivation returns false. It makes nine crypto calls: HKDF-Extract of the
 * handshake secret, then HKDF-Expand of the two handshake secrets, the two finished keys, and the
 * key and IV of each direction.
 * Skipped if CRYPTO_FAULT_INJECTION is OFF.
 **/
static void libspdm_test_secured_message_key_schedule_err_case1(void **state)
{
#if LIBSPDM_CRYPTO_FAULT_INJECTION
    bool result;
    uint32_t call_index;

    for (call_index = 0; ; call_index++) {
        init_secured_message_context();

        /* {ERROR} One crypto call of the derivation fails. */
        force_crypto_error(call_index);
        result = libspdm_generate_session_handshake_key(&m_secured_message_context, m_th_hash);
        if (release_crypto_error() == 0) {
            break;
        }

        assert_false(result);
    }
    assert_true(result);
    assert_int_equal(call_index, 9);
#else
    skip();
#endif
}

/**
 * Test 2: Each crypto call of libspdm_generate_session_data_key fails in turn, for a session whose
 * handshake secret comes from DHE.
 * Expected behavior: the derivation returns false. It makes nine crypto calls: HKDF-Expand of the
 * salt, HKDF-Extract of the master secret, then HKDF-Expand of the two data secrets, the export
 * master secret, and the key and IV of each direction.
 * Skipped if CRYPTO_FAULT_INJECTION is OFF.
 **/
static void libspdm_test_secured_message_key_schedule_err_case2(void **state)
{
#if LIBSPDM_CRYPTO_FAULT_INJECTION
    bool result;
    uint32_t call_index;

    for (call_index = 0; ; call_index++) {
        init_secured_message_context();

        /* {ERROR} One crypto call of the derivation fails. */
        force_crypto_error(call_index);
        result = libspdm_generate_session_data_key(&m_secured_message_context, m_th_hash);
        if (release_crypto_error() == 0) {
            break;
        }

        assert_false(result);
    }
    assert_true(result);
    assert_int_equal(call_index, 9);
#else
    skip();
#endif
}

/**
 * Test 3: Each crypto call of libspdm_create_update_session_data_key fails in turn while it updates
 * the Requester's data keys.
 * Expected behavior: the update returns false with the old keys backed up, and
 * libspdm_activate_update_session_data_key restores them. The update makes three crypto calls:
 * HKDF-Expand of the data secret, the key and the IV.
 * Skipped if CRYPTO_FAULT_INJECTION is OFF.
 **/
static void libspdm_test_secured_message_key_schedule_err_case3(void **state)
{
#if LIBSPDM_CRYPTO_FAULT_INJECTION
    test_update_session_data_key(LIBSPDM_KEY_UPDATE_ACTION_REQUESTER);
#else
    skip();
#endif
}

/**
 * Test 4: Each crypto call of libspdm_create_update_session_data_key fails in turn while it updates
 * the Responder's data keys.
 * Expected behavior: the same as for the Requester's data keys in test 3.
 * Skipped if CRYPTO_FAULT_INJECTION is OFF.
 **/
static void libspdm_test_secured_message_key_schedule_err_case4(void **state)
{
#if LIBSPDM_CRYPTO_FAULT_INJECTION
    test_update_session_data_key(LIBSPDM_KEY_UPDATE_ACTION_RESPONDER);
#else
    skip();
#endif
}

int libspdm_secured_message_key_schedule_error_test_main(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(libspdm_test_secured_message_key_schedule_err_case1),
        cmocka_unit_test(libspdm_test_secured_message_key_schedule_err_case2),
        cmocka_unit_test(libspdm_test_secured_message_key_schedule_err_case3),
        cmocka_unit_test(libspdm_test_secured_message_key_schedule_err_case4),
    };

    return cmocka_run_group_tests(test_cases, NULL, NULL);
}

#endif /* LIBSPDM_AEAD_AES_256_GCM_SUPPORT && LIBSPDM_SHA256_SUPPORT */
