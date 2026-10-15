/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_secured_message_lib.h"

/* Each case fails the crypto calls of a transcript append one at a time. The append hashes the
 * transcript as it goes, unless LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT records it instead. */

#if (LIBSPDM_CRYPTO_FAULT_INJECTION) && !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT)

#define LIBSPDM_TEST_SESSION_ID 0xFFFEFFFE

static const uint8_t m_vca[] = { 0x10, 0x11, 0x12 };

/* Gives the test a new SPDM context of the given version, with m_vca as its VCA transcript. */
static libspdm_context_t *new_context(void **state, uint8_t version)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    assert_int_equal(libspdm_unit_test_reset_context(state), 0);
    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = version << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    assert_int_equal(libspdm_append_message_a(spdm_context, m_vca, sizeof(m_vca)),
                     LIBSPDM_STATUS_SUCCESS);

    return spdm_context;
}

static libspdm_session_info_t *start_session(libspdm_context_t *spdm_context)
{
    libspdm_session_info_t *session_info;

    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, LIBSPDM_TEST_SESSION_ID,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, false);

    return session_info;
}

/* Fails the crypto call after skipping call_index of them. */
static void force_crypto_error(uint32_t call_index)
{
    libspdm_force_error_ex(LIBSPDM_ERR_CRYPTO_ANY, call_index, 1, LIBSPDM_ERR_ACTION_FAIL);
}

/* Releases the crypto error and returns the number of calls that failed, which is 0 once
 * call_index reaches the number of crypto calls that the append makes. */
static uint32_t release_crypto_error(void)
{
    uint32_t error_count;

    error_count = libspdm_get_forced_error_count(LIBSPDM_ERR_CRYPTO_ANY);
    libspdm_release_error(LIBSPDM_ERR_CRYPTO_ANY);

    return error_count;
}
#endif /* (LIBSPDM_CRYPTO_FAULT_INJECTION) && !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT) */

/**
 * Test 1: Each crypto call of libspdm_append_message_b fails in turn, starting the M1/M2
 * transcript of an SPDM 1.2 connection.
 * Expected behavior: the append returns LIBSPDM_STATUS_CRYPTO_ERROR and frees the M1/M2 hash
 * context. The append makes four crypto calls: new, init, and an update for the VCA and for the
 * message.
 * Skipped if CRYPTO_FAULT_INJECTION is OFF or LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT is enabled.
 **/
static void libspdm_test_common_context_data_err_case1(void **state)
{
#if (LIBSPDM_CRYPTO_FAULT_INJECTION) && !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT)
    libspdm_context_t *spdm_context;
    uint8_t message[] = { SPDM_MESSAGE_VERSION_12, SPDM_GET_DIGESTS, 0, 0 };
    libspdm_return_t status;
    uint32_t call_index;

    for (call_index = 0; ; call_index++) {
        spdm_context = new_context(state, SPDM_MESSAGE_VERSION_12);

        /* {ERROR} One crypto call of the append fails. */
        force_crypto_error(call_index);
        status = libspdm_append_message_b(spdm_context, message, sizeof(message));
        if (release_crypto_error() == 0) {
            break;
        }

        assert_int_equal(status, LIBSPDM_STATUS_CRYPTO_ERROR);
        assert_null(spdm_context->transcript.digest_context_m1m2);
    }
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(call_index, 4);
#else
    skip();
#endif
}

/**
 * Test 2: Each crypto call of libspdm_append_message_c fails in turn, starting the M1/M2
 * transcript of an SPDM 1.2 connection.
 * Expected behavior: the append returns LIBSPDM_STATUS_CRYPTO_ERROR and frees the M1/M2 hash
 * context. The append makes four crypto calls.
 * Skipped if CRYPTO_FAULT_INJECTION is OFF or LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT is enabled.
 **/
static void libspdm_test_common_context_data_err_case2(void **state)
{
#if (LIBSPDM_CRYPTO_FAULT_INJECTION) && !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT)
    libspdm_context_t *spdm_context;
    uint8_t message[] = { SPDM_MESSAGE_VERSION_12, SPDM_CHALLENGE, 0, 0 };
    libspdm_return_t status;
    uint32_t call_index;

    for (call_index = 0; ; call_index++) {
        spdm_context = new_context(state, SPDM_MESSAGE_VERSION_12);

        /* {ERROR} One crypto call of the append fails. */
        force_crypto_error(call_index);
        status = libspdm_append_message_c(spdm_context, message, sizeof(message));
        if (release_crypto_error() == 0) {
            break;
        }

        assert_int_equal(status, LIBSPDM_STATUS_CRYPTO_ERROR);
        assert_null(spdm_context->transcript.digest_context_m1m2);
    }
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(call_index, 4);
#else
    skip();
#endif
}

/**
 * Test 3: Each crypto call of libspdm_append_message_mut_b fails in turn, starting the mutual
 * authentication M1/M2 transcript of an SPDM 1.2 connection.
 * Expected behavior: the append returns LIBSPDM_STATUS_CRYPTO_ERROR and frees the hash context.
 * The append makes four crypto calls.
 * Skipped if CRYPTO_FAULT_INJECTION is OFF or LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT is enabled.
 **/
static void libspdm_test_common_context_data_err_case3(void **state)
{
#if (LIBSPDM_CRYPTO_FAULT_INJECTION) && !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT)
    libspdm_context_t *spdm_context;
    uint8_t message[] = { SPDM_MESSAGE_VERSION_12, SPDM_GET_DIGESTS, 0, 0 };
    libspdm_return_t status;
    uint32_t call_index;

    for (call_index = 0; ; call_index++) {
        spdm_context = new_context(state, SPDM_MESSAGE_VERSION_12);

        /* {ERROR} One crypto call of the append fails. */
        force_crypto_error(call_index);
        status = libspdm_append_message_mut_b(spdm_context, message, sizeof(message));
        if (release_crypto_error() == 0) {
            break;
        }

        assert_int_equal(status, LIBSPDM_STATUS_CRYPTO_ERROR);
        assert_null(spdm_context->transcript.digest_context_mut_m1m2);
    }
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(call_index, 4);
#else
    skip();
#endif
}

/**
 * Test 4: Each crypto call of libspdm_append_message_mut_c fails in turn, starting the mutual
 * authentication M1/M2 transcript of an SPDM 1.2 connection.
 * Expected behavior: the append returns LIBSPDM_STATUS_CRYPTO_ERROR and frees the hash context.
 * The append makes four crypto calls.
 * Skipped if CRYPTO_FAULT_INJECTION is OFF or LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT is enabled.
 **/
static void libspdm_test_common_context_data_err_case4(void **state)
{
#if (LIBSPDM_CRYPTO_FAULT_INJECTION) && !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT)
    libspdm_context_t *spdm_context;
    uint8_t message[] = { SPDM_MESSAGE_VERSION_12, SPDM_CHALLENGE, 0, 0 };
    libspdm_return_t status;
    uint32_t call_index;

    for (call_index = 0; ; call_index++) {
        spdm_context = new_context(state, SPDM_MESSAGE_VERSION_12);

        /* {ERROR} One crypto call of the append fails. */
        force_crypto_error(call_index);
        status = libspdm_append_message_mut_c(spdm_context, message, sizeof(message));
        if (release_crypto_error() == 0) {
            break;
        }

        assert_int_equal(status, LIBSPDM_STATUS_CRYPTO_ERROR);
        assert_null(spdm_context->transcript.digest_context_mut_m1m2);
    }
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(call_index, 4);
#else
    skip();
#endif
}

/**
 * Test 5: Each crypto call of libspdm_append_message_m fails in turn, starting the L1/L2
 * transcript of an SPDM 1.2 connection outside a session.
 * Expected behavior: the append returns LIBSPDM_STATUS_CRYPTO_ERROR and frees the L1/L2 hash
 * context. The append makes four crypto calls.
 * Skipped if CRYPTO_FAULT_INJECTION is OFF or LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT is enabled.
 **/
static void libspdm_test_common_context_data_err_case5(void **state)
{
#if (LIBSPDM_CRYPTO_FAULT_INJECTION) && !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT)
    libspdm_context_t *spdm_context;
    uint8_t message[] = { SPDM_MESSAGE_VERSION_12, SPDM_GET_MEASUREMENTS, 0, 0 };
    libspdm_return_t status;
    uint32_t call_index;

    for (call_index = 0; ; call_index++) {
        spdm_context = new_context(state, SPDM_MESSAGE_VERSION_12);

        /* {ERROR} One crypto call of the append fails. */
        force_crypto_error(call_index);
        status = libspdm_append_message_m(spdm_context, NULL, message, sizeof(message));
        if (release_crypto_error() == 0) {
            break;
        }

        assert_int_equal(status, LIBSPDM_STATUS_CRYPTO_ERROR);
        assert_null(spdm_context->transcript.digest_context_l1l2);
    }
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(call_index, 4);
#else
    skip();
#endif
}

/**
 * Test 6: Each crypto call of libspdm_append_message_m fails in turn, starting the L1/L2
 * transcript of a session of an SPDM 1.2 connection.
 * Expected behavior: the append returns LIBSPDM_STATUS_CRYPTO_ERROR and frees the session's L1/L2
 * hash context. The append makes four crypto calls.
 * Skipped if CRYPTO_FAULT_INJECTION is OFF or LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT is enabled.
 **/
static void libspdm_test_common_context_data_err_case6(void **state)
{
#if (LIBSPDM_CRYPTO_FAULT_INJECTION) && !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT)
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uint8_t message[] = { SPDM_MESSAGE_VERSION_12, SPDM_GET_MEASUREMENTS, 0, 0 };
    libspdm_return_t status;
    uint32_t call_index;

    for (call_index = 0; ; call_index++) {
        spdm_context = new_context(state, SPDM_MESSAGE_VERSION_12);
        session_info = start_session(spdm_context);

        /* {ERROR} One crypto call of the append fails. */
        force_crypto_error(call_index);
        status = libspdm_append_message_m(spdm_context, session_info, message, sizeof(message));
        if (release_crypto_error() == 0) {
            break;
        }

        assert_int_equal(status, LIBSPDM_STATUS_CRYPTO_ERROR);
        assert_null(session_info->session_transcript.digest_context_l1l2);
    }
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(call_index, 4);
#else
    skip();
#endif
}

/**
 * Test 7: Each crypto call of libspdm_append_message_k fails in turn, when a Requester starts the
 * transcript of a session with a Responder that negotiated multiple asymmetric keys.
 * Expected behavior: the append returns LIBSPDM_STATUS_CRYPTO_ERROR and frees the session's TH
 * hash context. The append makes six crypto calls: new, init, and an update for the VCA, the
 * DIGESTS, the certificate chain hash and the message.
 * Skipped if CRYPTO_FAULT_INJECTION is OFF or LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT is enabled.
 **/
static void libspdm_test_common_context_data_err_case7(void **state)
{
#if (LIBSPDM_CRYPTO_FAULT_INJECTION) && !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT)
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uint8_t digests[] = { 0x20, 0x21 };
    uint8_t message[] = { SPDM_MESSAGE_VERSION_13, SPDM_KEY_EXCHANGE, 0, 0 };
    uint32_t hash_size;
    libspdm_return_t status;
    uint32_t call_index;

    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    for (call_index = 0; ; call_index++) {
        spdm_context = new_context(state, SPDM_MESSAGE_VERSION_13);
        spdm_context->connection_info.multi_key_conn_rsp = true;
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size = hash_size;
        libspdm_set_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash,
                        hash_size, 0x30);
        assert_int_equal(libspdm_append_message_d(spdm_context, digests, sizeof(digests)),
                         LIBSPDM_STATUS_SUCCESS);
        session_info = start_session(spdm_context);
        session_info->peer_used_cert_chain_slot_id = 0;

        /* {ERROR} One crypto call of the append fails. */
        force_crypto_error(call_index);
        status = libspdm_append_message_k(spdm_context, session_info, true, message,
                                          sizeof(message));
        if (release_crypto_error() == 0) {
            break;
        }

        assert_int_equal(status, LIBSPDM_STATUS_CRYPTO_ERROR);
        assert_null(session_info->session_transcript.digest_context_th);
    }
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(call_index, 6);
#else
    skip();
#endif
}

/**
 * Test 8: Each crypto call of libspdm_append_message_k fails in turn, when a Responder starts the
 * transcript of a session that uses its certificate chain in slot 0.
 * Expected behavior: the append returns LIBSPDM_STATUS_CRYPTO_ERROR and frees the session's TH
 * hash context, if it was created. The append makes six crypto calls: the certificate chain hash,
 * new, init, and an update for the VCA, the certificate chain hash and the message.
 * Skipped if CRYPTO_FAULT_INJECTION is OFF or LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT is enabled.
 **/
static void libspdm_test_common_context_data_err_case8(void **state)
{
#if (LIBSPDM_CRYPTO_FAULT_INJECTION) && !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT)
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uint8_t local_cert_chain[] = { 0x50, 0x51, 0x52, 0x53 };
    uint8_t message[] = { SPDM_MESSAGE_VERSION_12, SPDM_KEY_EXCHANGE, 0, 0 };
    libspdm_return_t status;
    uint32_t call_index;

    for (call_index = 0; ; call_index++) {
        spdm_context = new_context(state, SPDM_MESSAGE_VERSION_12);
        spdm_context->local_context.local_cert_chain_provision[0] = local_cert_chain;
        spdm_context->local_context.local_cert_chain_provision_size[0] =
            sizeof(local_cert_chain);
        session_info = start_session(spdm_context);
        session_info->local_used_cert_chain_slot_id = 0;

        /* {ERROR} One crypto call of the append fails. */
        force_crypto_error(call_index);
        status = libspdm_append_message_k(spdm_context, session_info, false, message,
                                          sizeof(message));
        if (release_crypto_error() == 0) {
            break;
        }

        assert_int_equal(status, LIBSPDM_STATUS_CRYPTO_ERROR);
        assert_null(session_info->session_transcript.digest_context_th);
    }
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(call_index, 6);
    spdm_context->local_context.local_cert_chain_provision[0] = NULL;
    spdm_context->local_context.local_cert_chain_provision_size[0] = 0;
#else
    skip();
#endif
}

/**
 * Test 9: Each crypto call of libspdm_append_message_f fails in turn, when a Requester that
 * negotiated multiple asymmetric keys starts the FINISH transcript of a session with mutual
 * authentication.
 * Expected behavior: the append returns LIBSPDM_STATUS_CRYPTO_ERROR. The append makes eleven
 * crypto calls: the five that start the TH transcript, the hash of the Requester's certificate
 * chain, new and duplicate for the TH backup, and an update for the encapsulated DIGESTS, the
 * certificate chain hash and the message.
 * Skipped if CRYPTO_FAULT_INJECTION is OFF or LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT is enabled.
 **/
static void libspdm_test_common_context_data_err_case9(void **state)
{
#if (LIBSPDM_CRYPTO_FAULT_INJECTION) && !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT)
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uint8_t encap_digests[] = { 0x40, 0x41 };
    uint8_t local_cert_chain[] = { 0x50, 0x51, 0x52, 0x53 };
    uint8_t message[] = { SPDM_MESSAGE_VERSION_13, SPDM_FINISH, 0, 0 };
    uint32_t hash_size;
    libspdm_return_t status;
    uint32_t call_index;

    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    for (call_index = 0; ; call_index++) {
        spdm_context = new_context(state, SPDM_MESSAGE_VERSION_13);
        spdm_context->connection_info.multi_key_conn_req = true;
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size = hash_size;
        libspdm_set_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash,
                        hash_size, 0x30);
        spdm_context->local_context.local_cert_chain_provision[0] = local_cert_chain;
        spdm_context->local_context.local_cert_chain_provision_size[0] =
            sizeof(local_cert_chain);
        session_info = start_session(spdm_context);
        session_info->peer_used_cert_chain_slot_id = 0;
        session_info->local_used_cert_chain_slot_id = 0;
        session_info->mut_auth_requested = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;
        assert_int_equal(libspdm_append_message_encap_d(session_info, encap_digests,
                                                        sizeof(encap_digests)),
                         LIBSPDM_STATUS_SUCCESS);

        /* {ERROR} One crypto call of the append fails. */
        force_crypto_error(call_index);
        status = libspdm_append_message_f(spdm_context, session_info, true, message,
                                          sizeof(message));
        if (release_crypto_error() == 0) {
            break;
        }

        assert_int_equal(status, LIBSPDM_STATUS_CRYPTO_ERROR);
    }
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(call_index, 11);
    spdm_context->local_context.local_cert_chain_provision[0] = NULL;
    spdm_context->local_context.local_cert_chain_provision_size[0] = 0;
#else
    skip();
#endif
}

/**
 * Test 10: Each crypto call of libspdm_append_message_e fails in turn, starting the IL1/IL2
 * transcript of an SPDM 1.3 connection outside a session.
 * Expected behavior: the append returns LIBSPDM_STATUS_CRYPTO_ERROR and frees the IL1/IL2 hash
 * context. The append makes four crypto calls.
 * Skipped if CRYPTO_FAULT_INJECTION is OFF or LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT is enabled.
 **/
static void libspdm_test_common_context_data_err_case10(void **state)
{
#if (LIBSPDM_CRYPTO_FAULT_INJECTION) && !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT)
    libspdm_context_t *spdm_context;
    uint8_t message[] = { SPDM_MESSAGE_VERSION_13, SPDM_GET_ENDPOINT_INFO, 0, 0 };
    libspdm_return_t status;
    uint32_t call_index;

    for (call_index = 0; ; call_index++) {
        spdm_context = new_context(state, SPDM_MESSAGE_VERSION_13);

        /* {ERROR} One crypto call of the append fails. */
        force_crypto_error(call_index);
        status = libspdm_append_message_e(spdm_context, NULL, message, sizeof(message));
        if (release_crypto_error() == 0) {
            break;
        }

        assert_int_equal(status, LIBSPDM_STATUS_CRYPTO_ERROR);
        assert_null(spdm_context->transcript.digest_context_il1il2);
    }
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(call_index, 4);
#else
    skip();
#endif
}

/**
 * Test 11: Each crypto call of libspdm_append_message_e fails in turn, starting the IL1/IL2
 * transcript of a session of an SPDM 1.3 connection.
 * Expected behavior: the append returns LIBSPDM_STATUS_CRYPTO_ERROR and frees the session's
 * IL1/IL2 hash context. The append makes four crypto calls.
 * Skipped if CRYPTO_FAULT_INJECTION is OFF or LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT is enabled.
 **/
static void libspdm_test_common_context_data_err_case11(void **state)
{
#if (LIBSPDM_CRYPTO_FAULT_INJECTION) && !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT)
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uint8_t message[] = { SPDM_MESSAGE_VERSION_13, SPDM_GET_ENDPOINT_INFO, 0, 0 };
    libspdm_return_t status;
    uint32_t call_index;

    for (call_index = 0; ; call_index++) {
        spdm_context = new_context(state, SPDM_MESSAGE_VERSION_13);
        session_info = start_session(spdm_context);

        /* {ERROR} One crypto call of the append fails. */
        force_crypto_error(call_index);
        status = libspdm_append_message_e(spdm_context, session_info, message, sizeof(message));
        if (release_crypto_error() == 0) {
            break;
        }

        assert_int_equal(status, LIBSPDM_STATUS_CRYPTO_ERROR);
        assert_null(session_info->session_transcript.digest_context_il1il2);
    }
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(call_index, 4);
#else
    skip();
#endif
}

/**
 * Test 12: Each crypto call of libspdm_append_message_encap_e fails in turn, starting the
 * encapsulated IL1/IL2 transcript of an SPDM 1.3 connection outside a session.
 * Expected behavior: the append returns LIBSPDM_STATUS_CRYPTO_ERROR and frees the encapsulated
 * IL1/IL2 hash context. The append makes four crypto calls.
 * Skipped if CRYPTO_FAULT_INJECTION is OFF or LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT is enabled.
 **/
static void libspdm_test_common_context_data_err_case12(void **state)
{
#if (LIBSPDM_CRYPTO_FAULT_INJECTION) && !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT)
    libspdm_context_t *spdm_context;
    uint8_t message[] = { SPDM_MESSAGE_VERSION_13, SPDM_GET_ENDPOINT_INFO, 0, 0 };
    libspdm_return_t status;
    uint32_t call_index;

    for (call_index = 0; ; call_index++) {
        spdm_context = new_context(state, SPDM_MESSAGE_VERSION_13);

        /* {ERROR} One crypto call of the append fails. */
        force_crypto_error(call_index);
        status = libspdm_append_message_encap_e(spdm_context, NULL, message, sizeof(message));
        if (release_crypto_error() == 0) {
            break;
        }

        assert_int_equal(status, LIBSPDM_STATUS_CRYPTO_ERROR);
        assert_null(spdm_context->transcript.digest_context_encap_il1il2);
    }
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(call_index, 4);
#else
    skip();
#endif
}

/**
 * Test 13: Each crypto call of libspdm_append_message_encap_e fails in turn, starting the
 * encapsulated IL1/IL2 transcript of a session of an SPDM 1.3 connection.
 * Expected behavior: the append returns LIBSPDM_STATUS_CRYPTO_ERROR and frees the session's
 * encapsulated IL1/IL2 hash context. The append makes four crypto calls.
 * Skipped if CRYPTO_FAULT_INJECTION is OFF or LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT is enabled.
 **/
static void libspdm_test_common_context_data_err_case13(void **state)
{
#if (LIBSPDM_CRYPTO_FAULT_INJECTION) && !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT)
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uint8_t message[] = { SPDM_MESSAGE_VERSION_13, SPDM_GET_ENDPOINT_INFO, 0, 0 };
    libspdm_return_t status;
    uint32_t call_index;

    for (call_index = 0; ; call_index++) {
        spdm_context = new_context(state, SPDM_MESSAGE_VERSION_13);
        session_info = start_session(spdm_context);

        /* {ERROR} One crypto call of the append fails. */
        force_crypto_error(call_index);
        status = libspdm_append_message_encap_e(spdm_context, session_info, message,
                                                sizeof(message));
        if (release_crypto_error() == 0) {
            break;
        }

        assert_int_equal(status, LIBSPDM_STATUS_CRYPTO_ERROR);
        assert_null(session_info->session_transcript.digest_context_encap_il1il2);
    }
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(call_index, 4);
#else
    skip();
#endif
}

int libspdm_common_context_data_error_test_main(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test_setup(libspdm_test_common_context_data_err_case1,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_common_context_data_err_case2,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_common_context_data_err_case3,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_common_context_data_err_case4,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_common_context_data_err_case5,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_common_context_data_err_case6,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_common_context_data_err_case7,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_common_context_data_err_case8,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_common_context_data_err_case9,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_common_context_data_err_case10,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_common_context_data_err_case11,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_common_context_data_err_case12,
                               libspdm_unit_test_reset_context),
        cmocka_unit_test_setup(libspdm_test_common_context_data_err_case13,
                               libspdm_unit_test_reset_context),
    };

    libspdm_test_context_t test_context = {
        LIBSPDM_TEST_CONTEXT_VERSION,
        true,
    };

    libspdm_setup_test_context(&test_context);

    return cmocka_run_group_tests(test_cases,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}
