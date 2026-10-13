/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_AEAD_AES_256_GCM_SUPPORT

#if LIBSPDM_CRYPTO_FAULT_INJECTION
#define LIBSPDM_TEST_SESSION_ID 0x00112233
#define LIBSPDM_TEST_APP_MESSAGE_SIZE 16

static uint8_t m_secured_message[0x1000];
static uint8_t m_app_message_buffer[0x1000];
static libspdm_secured_message_context_t m_secured_message_context;
static libspdm_secured_message_callbacks_t m_secured_message_callbacks;
static uint32_t m_max_random_number_count;

static uint8_t get_sequence_number(uint64_t sequence_number, uint8_t *sequence_number_buffer)
{
    libspdm_copy_mem(sequence_number_buffer, sizeof(sequence_number), &sequence_number,
                     sizeof(sequence_number));

    return sizeof(sequence_number);
}

static uint32_t get_max_random_number_count(void)
{
    return m_max_random_number_count;
}

static spdm_version_number_t get_secured_spdm_version(spdm_version_number_t secured_message_version)
{
    return secured_message_version;
}

/* Gives the test a new context for an established session of the given type, whose request keys
 * both encode and decode use, with the sequence number endianness already determined and no
 * random padding. */
static void init_secured_message_context(libspdm_session_type_t session_type)
{
    libspdm_zero_mem(&m_secured_message_context, sizeof(m_secured_message_context));
    m_secured_message_context.secured_message_version =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    m_secured_message_context.aead_cipher_suite = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM;
    m_secured_message_context.session_type = session_type;
    m_secured_message_context.session_state = LIBSPDM_SESSION_STATE_ESTABLISHED;
    m_secured_message_context.aead_tag_size = 16;
    m_secured_message_context.aead_key_size = 32;
    m_secured_message_context.aead_iv_size = 12;
    libspdm_set_mem(m_secured_message_context.application_secret.request_data_encryption_key,
                    32, 0x5A);
    libspdm_set_mem(m_secured_message_context.application_secret.request_data_salt, 12, 0xA5);
    m_secured_message_context.max_spdm_session_sequence_number = UINT64_MAX;
    m_secured_message_context.sequence_number_endian =
        LIBSPDM_DATA_SESSION_SEQ_NUM_ENC_LITTLE_DEC_LITTLE;

    m_max_random_number_count = 0;
    m_secured_message_callbacks.get_sequence_number = get_sequence_number;
    m_secured_message_callbacks.get_max_random_number_count = get_max_random_number_count;
    m_secured_message_callbacks.get_secured_spdm_version = get_secured_spdm_version;
}

/* Encodes a request into m_secured_message and returns its size through secured_message_size. */
static libspdm_return_t encode_request(size_t *secured_message_size)
{
    uint8_t *app_message;

    app_message = m_app_message_buffer + sizeof(spdm_secured_message_cipher_header_t);
    libspdm_set_mem(app_message, LIBSPDM_TEST_APP_MESSAGE_SIZE, 0x11);
    *secured_message_size = sizeof(m_secured_message);

    return libspdm_encode_secured_message(&m_secured_message_context, LIBSPDM_TEST_SESSION_ID,
                                          true, LIBSPDM_TEST_APP_MESSAGE_SIZE, app_message,
                                          secured_message_size, m_secured_message,
                                          &m_secured_message_callbacks);
}

/* Encodes a request with the given sequence number, and rewinds the sequence number so that
 * decode_request expects that request. */
static void encode_request_for_decode(uint64_t sequence_number, size_t *secured_message_size)
{
    m_secured_message_context.application_secret.request_data_sequence_number = sequence_number;
    assert_int_equal(encode_request(secured_message_size), LIBSPDM_STATUS_SUCCESS);
    m_secured_message_context.application_secret.request_data_sequence_number = sequence_number;
}

static libspdm_return_t decode_request(size_t secured_message_size)
{
    void *app_message;
    size_t app_message_size;

    app_message = m_app_message_buffer;
    app_message_size = sizeof(m_app_message_buffer);

    return libspdm_decode_secured_message(&m_secured_message_context, LIBSPDM_TEST_SESSION_ID,
                                          true, secured_message_size, m_secured_message,
                                          &app_message_size, &app_message,
                                          &m_secured_message_callbacks);
}

/* Asserts the last SPDM error that the decode recorded. */
static void assert_last_spdm_error(uint8_t error_code, uint32_t session_id)
{
    libspdm_error_struct_t last_spdm_error;

    libspdm_secured_message_get_last_spdm_error_struct(&m_secured_message_context,
                                                       &last_spdm_error);
    assert_int_equal(last_spdm_error.error_code, error_code);
    assert_int_equal(last_spdm_error.session_id, session_id);
}
#endif /* LIBSPDM_CRYPTO_FAULT_INJECTION */

/**
 * Test 1: The AEAD encryption of an ENC_MAC session's request fails.
 * Expected behavior: libspdm_encode_secured_message returns LIBSPDM_STATUS_CRYPTO_ERROR.
 * Skipped if CRYPTO_FAULT_INJECTION is OFF.
 **/
static void libspdm_test_secured_message_encode_decode_err_case1(void **state)
{
#if LIBSPDM_CRYPTO_FAULT_INJECTION
    libspdm_return_t status;
    size_t secured_message_size;
    uint32_t error_count;

    init_secured_message_context(LIBSPDM_SESSION_TYPE_ENC_MAC);

    /* {ERROR} The AEAD encryption fails. */
    libspdm_force_error(LIBSPDM_ERR_CRYPTO_AEAD_ENCRYPT);
    status = encode_request(&secured_message_size);
    error_count = libspdm_get_forced_error_count(LIBSPDM_ERR_CRYPTO_AEAD_ENCRYPT);
    libspdm_release_error(LIBSPDM_ERR_CRYPTO_AEAD_ENCRYPT);

    assert_int_equal(error_count, 1);
    assert_int_equal(status, LIBSPDM_STATUS_CRYPTO_ERROR);
#else
    skip();
#endif
}

/**
 * Test 2: The AEAD computation of a MAC_ONLY session's request fails.
 * Expected behavior: libspdm_encode_secured_message returns LIBSPDM_STATUS_CRYPTO_ERROR.
 * Skipped if CRYPTO_FAULT_INJECTION is OFF.
 **/
static void libspdm_test_secured_message_encode_decode_err_case2(void **state)
{
#if LIBSPDM_CRYPTO_FAULT_INJECTION
    libspdm_return_t status;
    size_t secured_message_size;
    uint32_t error_count;

    init_secured_message_context(LIBSPDM_SESSION_TYPE_MAC_ONLY);

    /* {ERROR} The AEAD computation of the MAC fails. */
    libspdm_force_error(LIBSPDM_ERR_CRYPTO_AEAD_ENCRYPT);
    status = encode_request(&secured_message_size);
    error_count = libspdm_get_forced_error_count(LIBSPDM_ERR_CRYPTO_AEAD_ENCRYPT);
    libspdm_release_error(LIBSPDM_ERR_CRYPTO_AEAD_ENCRYPT);

    assert_int_equal(error_count, 1);
    assert_int_equal(status, LIBSPDM_STATUS_CRYPTO_ERROR);
#else
    skip();
#endif
}

/**
 * Test 3: The random number generator fails to choose the number of random padding bytes of an
 * ENC_MAC session's request.
 * Expected behavior: libspdm_encode_secured_message returns LIBSPDM_STATUS_LOW_ENTROPY.
 * Skipped if CRYPTO_FAULT_INJECTION is OFF.
 **/
static void libspdm_test_secured_message_encode_decode_err_case3(void **state)
{
#if LIBSPDM_CRYPTO_FAULT_INJECTION
    libspdm_return_t status;
    size_t secured_message_size;
    uint32_t error_count;

    init_secured_message_context(LIBSPDM_SESSION_TYPE_ENC_MAC);
    m_max_random_number_count = 32;

    /* {ERROR} The random number generator fails for the padding size. */
    libspdm_force_error(LIBSPDM_ERR_CRYPTO_RANDOM);
    status = encode_request(&secured_message_size);
    error_count = libspdm_get_forced_error_count(LIBSPDM_ERR_CRYPTO_RANDOM);
    libspdm_release_error(LIBSPDM_ERR_CRYPTO_RANDOM);

    assert_int_equal(error_count, 1);
    assert_int_equal(status, LIBSPDM_STATUS_LOW_ENTROPY);
#else
    skip();
#endif
}

/**
 * Test 4: The random number generator fails to generate the random padding bytes of an ENC_MAC
 * session's request.
 * Expected behavior: libspdm_encode_secured_message returns LIBSPDM_STATUS_LOW_ENTROPY.
 * Skipped if CRYPTO_FAULT_INJECTION is OFF.
 **/
static void libspdm_test_secured_message_encode_decode_err_case4(void **state)
{
#if LIBSPDM_CRYPTO_FAULT_INJECTION
    libspdm_return_t status;
    size_t secured_message_size;
    uint32_t error_count;

    init_secured_message_context(LIBSPDM_SESSION_TYPE_ENC_MAC);
    m_max_random_number_count = 32;

    /* {ERROR} The random number generator fails for the padding bytes, its second call. */
    libspdm_force_error_ex(LIBSPDM_ERR_CRYPTO_RANDOM, 1, 1, LIBSPDM_ERR_ACTION_FAIL);
    status = encode_request(&secured_message_size);
    error_count = libspdm_get_forced_error_count(LIBSPDM_ERR_CRYPTO_RANDOM);
    libspdm_release_error(LIBSPDM_ERR_CRYPTO_RANDOM);

    assert_int_equal(error_count, 1);
    assert_int_equal(status, LIBSPDM_STATUS_LOW_ENTROPY);
#else
    skip();
#endif
}

/**
 * Test 5: The AEAD decryption of an ENC_MAC session's request fails.
 * Expected behavior: libspdm_decode_secured_message returns LIBSPDM_STATUS_CRYPTO_ERROR and records
 * a DecryptError for the session.
 * Skipped if CRYPTO_FAULT_INJECTION is OFF.
 **/
static void libspdm_test_secured_message_encode_decode_err_case5(void **state)
{
#if LIBSPDM_CRYPTO_FAULT_INJECTION
    libspdm_return_t status;
    size_t secured_message_size;
    uint32_t error_count;

    init_secured_message_context(LIBSPDM_SESSION_TYPE_ENC_MAC);
    encode_request_for_decode(0, &secured_message_size);

    /* {ERROR} The AEAD decryption fails. */
    libspdm_force_error(LIBSPDM_ERR_CRYPTO_AEAD_DECRYPT);
    status = decode_request(secured_message_size);
    error_count = libspdm_get_forced_error_count(LIBSPDM_ERR_CRYPTO_AEAD_DECRYPT);
    libspdm_release_error(LIBSPDM_ERR_CRYPTO_AEAD_DECRYPT);

    assert_int_equal(error_count, 1);
    assert_int_equal(status, LIBSPDM_STATUS_CRYPTO_ERROR);
    assert_last_spdm_error(SPDM_ERROR_CODE_DECRYPT_ERROR, LIBSPDM_TEST_SESSION_ID);
#else
    skip();
#endif
}

/**
 * Test 6: The AEAD verification of a MAC_ONLY session's request fails.
 * Expected behavior: libspdm_decode_secured_message returns LIBSPDM_STATUS_CRYPTO_ERROR and records
 * a DecryptError for the session.
 * Skipped if CRYPTO_FAULT_INJECTION is OFF.
 **/
static void libspdm_test_secured_message_encode_decode_err_case6(void **state)
{
#if LIBSPDM_CRYPTO_FAULT_INJECTION
    libspdm_return_t status;
    size_t secured_message_size;
    uint32_t error_count;

    init_secured_message_context(LIBSPDM_SESSION_TYPE_MAC_ONLY);
    encode_request_for_decode(0, &secured_message_size);

    /* {ERROR} The AEAD verification of the MAC fails. */
    libspdm_force_error(LIBSPDM_ERR_CRYPTO_AEAD_DECRYPT);
    status = decode_request(secured_message_size);
    error_count = libspdm_get_forced_error_count(LIBSPDM_ERR_CRYPTO_AEAD_DECRYPT);
    libspdm_release_error(LIBSPDM_ERR_CRYPTO_AEAD_DECRYPT);

    assert_int_equal(error_count, 1);
    assert_int_equal(status, LIBSPDM_STATUS_CRYPTO_ERROR);
    assert_last_spdm_error(SPDM_ERROR_CODE_DECRYPT_ERROR, LIBSPDM_TEST_SESSION_ID);
#else
    skip();
#endif
}

/**
 * Test 7: The AEAD decryption of an ENC_MAC session's request fails while the Requester's keys
 * from before a key update are still kept.
 * Expected behavior: libspdm_decode_secured_message returns
 * LIBSPDM_STATUS_SESSION_TRY_DISCARD_KEY_UPDATE, so that the caller can retry with the old keys,
 * and records no error.
 * Skipped if CRYPTO_FAULT_INJECTION is OFF.
 **/
static void libspdm_test_secured_message_encode_decode_err_case7(void **state)
{
#if LIBSPDM_CRYPTO_FAULT_INJECTION
    libspdm_return_t status;
    size_t secured_message_size;
    uint32_t error_count;

    init_secured_message_context(LIBSPDM_SESSION_TYPE_ENC_MAC);
    encode_request_for_decode(0, &secured_message_size);
    m_secured_message_context.requester_backup_valid = true;

    /* {ERROR} The AEAD decryption fails. */
    libspdm_force_error(LIBSPDM_ERR_CRYPTO_AEAD_DECRYPT);
    status = decode_request(secured_message_size);
    error_count = libspdm_get_forced_error_count(LIBSPDM_ERR_CRYPTO_AEAD_DECRYPT);
    libspdm_release_error(LIBSPDM_ERR_CRYPTO_AEAD_DECRYPT);

    assert_int_equal(error_count, 1);
    assert_int_equal(status, LIBSPDM_STATUS_SESSION_TRY_DISCARD_KEY_UPDATE);
    assert_last_spdm_error(0, 0);
#else
    skip();
#endif
}

/**
 * Test 8: The first AEAD decryption of an ENC_MAC session's request with sequence number 1 fails
 * while the sequence number endianness is not yet determined, so the decode retries with the other
 * endianness, which does not match the request.
 * Expected behavior: libspdm_decode_secured_message returns LIBSPDM_STATUS_CRYPTO_ERROR, and the
 * endianness is still not determined.
 * Skipped if CRYPTO_FAULT_INJECTION is OFF.
 **/
static void libspdm_test_secured_message_encode_decode_err_case8(void **state)
{
#if LIBSPDM_CRYPTO_FAULT_INJECTION
    libspdm_return_t status;
    size_t secured_message_size;
    uint32_t error_count;
    uint32_t call_count;

    init_secured_message_context(LIBSPDM_SESSION_TYPE_ENC_MAC);
    m_secured_message_context.sequence_number_endian =
        LIBSPDM_DATA_SESSION_SEQ_NUM_ENC_LITTLE_DEC_BOTH;
    encode_request_for_decode(1, &secured_message_size);

    /* {ERROR} The first AEAD decryption fails. */
    libspdm_force_error_ex(LIBSPDM_ERR_CRYPTO_AEAD_DECRYPT, 0, 1, LIBSPDM_ERR_ACTION_FAIL);
    status = decode_request(secured_message_size);
    error_count = libspdm_get_forced_error_count(LIBSPDM_ERR_CRYPTO_AEAD_DECRYPT);
    call_count = libspdm_get_crypto_call_count(LIBSPDM_ERR_CRYPTO_AEAD_DECRYPT);
    libspdm_release_error(LIBSPDM_ERR_CRYPTO_AEAD_DECRYPT);

    assert_int_equal(error_count, 1);
    assert_int_equal(call_count, 2);
    assert_int_equal(status, LIBSPDM_STATUS_CRYPTO_ERROR);
    assert_int_equal(m_secured_message_context.sequence_number_endian,
                     LIBSPDM_DATA_SESSION_SEQ_NUM_ENC_LITTLE_DEC_BOTH);
#else
    skip();
#endif
}

int libspdm_secured_message_encode_decode_error_test_main(void)
{
    const struct CMUnitTest test_cases[] = {
        /* Encoding fails */
        cmocka_unit_test(libspdm_test_secured_message_encode_decode_err_case1),
        cmocka_unit_test(libspdm_test_secured_message_encode_decode_err_case2),
        cmocka_unit_test(libspdm_test_secured_message_encode_decode_err_case3),
        cmocka_unit_test(libspdm_test_secured_message_encode_decode_err_case4),
        /* Decoding fails */
        cmocka_unit_test(libspdm_test_secured_message_encode_decode_err_case5),
        cmocka_unit_test(libspdm_test_secured_message_encode_decode_err_case6),
        cmocka_unit_test(libspdm_test_secured_message_encode_decode_err_case7),
        cmocka_unit_test(libspdm_test_secured_message_encode_decode_err_case8),
    };

    return cmocka_run_group_tests(test_cases, NULL, NULL);
}

#endif /* LIBSPDM_AEAD_AES_256_GCM_SUPPORT */
