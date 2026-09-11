/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

#if (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (LIBSPDM_EVENT_RECIPIENT_SUPPORT)

#define LIBSPDM_TEST_SUBSCRIBE_LIST_SIZE 0x20

static uint8_t m_send_buffer[LIBSPDM_MAX_SPDM_MSG_SIZE];
static uint8_t m_receive_buffer[LIBSPDM_MAX_SPDM_MSG_SIZE];
static uint8_t m_subscribe_list[LIBSPDM_TEST_SUBSCRIBE_LIST_SIZE];
static uint32_t m_session_id = 0xFFFFFFFF;

static void set_standard_state(libspdm_context_t *spdm_context)
{
    libspdm_session_info_t *session_info;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;

    /* The Requester is the Event Notifier, so it is the endpoint that sets EVENT_CAP. */
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EVENT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;

    spdm_context->latest_session_id = m_session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = m_session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, m_session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, true);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);

    libspdm_set_mem(m_subscribe_list, sizeof(m_subscribe_list), 0xAA);
}

static size_t build_response(spdm_subscribe_event_types_ack_response_t *spdm_response)
{
    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_response->header.request_response_code = SPDM_SUBSCRIBE_EVENT_TYPES_ACK;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;

    return sizeof(spdm_subscribe_event_types_ack_response_t);
}

/**
 * Test 1: SubscribeEventGroupCount does not agree with the subscription list.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_PARAMETER. A count of zero unsubscribes from
 * everything, so the list shall be absent, and a non-zero count shall be accompanied by a list.
 **/
static void rsp_encap_subscribe_event_types_err_case1(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t request_buffer_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x01;

    set_standard_state(spdm_context);

    /* Count of zero, but a list is supplied. */
    request_buffer_size = sizeof(m_send_buffer);
    assert_int_equal(
        libspdm_get_encap_request_subscribe_event_types(
            spdm_context, m_session_id, 0, sizeof(m_subscribe_list), m_subscribe_list,
            &request_buffer_size, m_send_buffer),
        LIBSPDM_STATUS_INVALID_PARAMETER);

    /* Count of zero, but a non-zero length is supplied. */
    request_buffer_size = sizeof(m_send_buffer);
    assert_int_equal(
        libspdm_get_encap_request_subscribe_event_types(
            spdm_context, m_session_id, 0, sizeof(m_subscribe_list), NULL,
            &request_buffer_size, m_send_buffer),
        LIBSPDM_STATUS_INVALID_PARAMETER);

    /* Non-zero count, but no list. */
    request_buffer_size = sizeof(m_send_buffer);
    assert_int_equal(
        libspdm_get_encap_request_subscribe_event_types(
            spdm_context, m_session_id, 1, sizeof(m_subscribe_list), NULL,
            &request_buffer_size, m_send_buffer),
        LIBSPDM_STATUS_INVALID_PARAMETER);

    /* Non-zero count, but an empty list. */
    request_buffer_size = sizeof(m_send_buffer);
    assert_int_equal(
        libspdm_get_encap_request_subscribe_event_types(
            spdm_context, m_session_id, 1, 0, m_subscribe_list,
            &request_buffer_size, m_send_buffer),
        LIBSPDM_STATUS_INVALID_PARAMETER);
}

/**
 * Test 2: an unknown session is rejected.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_STATE_LOCAL, as SUBSCRIBE_EVENT_TYPES is
 * prohibited outside of a session.
 **/
static void rsp_encap_subscribe_event_types_err_case2(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t request_buffer_size = sizeof(m_send_buffer);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x02;

    set_standard_state(spdm_context);

    assert_int_equal(
        libspdm_get_encap_request_subscribe_event_types(
            spdm_context, 0xDEADBEEF, 1, sizeof(m_subscribe_list), m_subscribe_list,
            &request_buffer_size, m_send_buffer),
        LIBSPDM_STATUS_INVALID_STATE_LOCAL);
}

/**
 * Test 3: the session exists but its handshake has not completed.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_STATE_LOCAL, as the message is only allowed in
 * the Application Phase.
 **/
static void rsp_encap_subscribe_event_types_err_case3(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    size_t request_buffer_size = sizeof(m_send_buffer);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x03;

    set_standard_state(spdm_context);
    session_info = &spdm_context->session_info[0];
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_HANDSHAKING);

    assert_int_equal(
        libspdm_get_encap_request_subscribe_event_types(
            spdm_context, m_session_id, 1, sizeof(m_subscribe_list), m_subscribe_list,
            &request_buffer_size, m_send_buffer),
        LIBSPDM_STATUS_INVALID_STATE_LOCAL);
}

/**
 * Test 4: the connection is earlier than SPDM 1.3, which is the version that introduced events.
 * Expected Behavior: returns LIBSPDM_STATUS_UNSUPPORTED_CAP.
 **/
static void rsp_encap_subscribe_event_types_err_case4(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t request_buffer_size = sizeof(m_send_buffer);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x04;

    set_standard_state(spdm_context);
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    assert_int_equal(
        libspdm_get_encap_request_subscribe_event_types(
            spdm_context, m_session_id, 1, sizeof(m_subscribe_list), m_subscribe_list,
            &request_buffer_size, m_send_buffer),
        LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 5: the Requester did not set EVENT_CAP, so it is not an Event Notifier.
 * Expected Behavior: returns LIBSPDM_STATUS_UNSUPPORTED_CAP. The Requester would answer with
 * ERROR(UnsupportedRequest), so the request is not sent.
 **/
static void rsp_encap_subscribe_event_types_err_case5(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t request_buffer_size = sizeof(m_send_buffer);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x05;

    set_standard_state(spdm_context);
    spdm_context->connection_info.capability.flags &=
        ~SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EVENT_CAP;

    assert_int_equal(
        libspdm_get_encap_request_subscribe_event_types(
            spdm_context, m_session_id, 1, sizeof(m_subscribe_list), m_subscribe_list,
            &request_buffer_size, m_send_buffer),
        LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 6: the subscription list does not fit in the encapsulated request buffer.
 * Expected Behavior: returns LIBSPDM_STATUS_BUFFER_TOO_SMALL. Unlike the other encapsulated
 * requests, the Integrator determines the size of this one, so it can exceed the room that the
 * ENCAPSULATED_REQUEST response has left.
 **/
static void rsp_encap_subscribe_event_types_err_case6(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t request_buffer_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x06;

    set_standard_state(spdm_context);

    /* One byte short of the request that the list requires. */
    request_buffer_size = sizeof(spdm_subscribe_event_types_request_t) +
                          sizeof(m_subscribe_list) - 1;
    assert_int_equal(
        libspdm_get_encap_request_subscribe_event_types(
            spdm_context, m_session_id, 1, sizeof(m_subscribe_list), m_subscribe_list,
            &request_buffer_size, m_send_buffer),
        LIBSPDM_STATUS_BUFFER_TOO_SMALL);

    /* Too small even for the fixed portion of the request. */
    request_buffer_size = sizeof(spdm_message_header_t);
    assert_int_equal(
        libspdm_get_encap_request_subscribe_event_types(
            spdm_context, m_session_id, 1, sizeof(m_subscribe_list), m_subscribe_list,
            &request_buffer_size, m_send_buffer),
        LIBSPDM_STATUS_BUFFER_TOO_SMALL);

    /* The unsubscribe form is only the message header, and even that does not fit. */
    request_buffer_size = sizeof(spdm_message_header_t) - 1;
    assert_int_equal(
        libspdm_get_encap_request_subscribe_event_types(
            spdm_context, m_session_id, 0, 0, NULL, &request_buffer_size, m_send_buffer),
        LIBSPDM_STATUS_BUFFER_TOO_SMALL);
}

/**
 * Test 7: the encapsulated SUBSCRIBE_EVENT_TYPES_ACK is not the negotiated version.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void rsp_encap_subscribe_event_types_err_case7(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_subscribe_event_types_ack_response_t *spdm_response;
    size_t response_size;
    bool need_continue;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x07;

    set_standard_state(spdm_context);

    spdm_response = (spdm_subscribe_event_types_ack_response_t *)m_receive_buffer;
    response_size = build_response(spdm_response);
    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;

    assert_int_equal(
        libspdm_process_encap_response_subscribe_event_types_ack(
            spdm_context, response_size, spdm_response, &need_continue),
        LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 8: the encapsulated response is neither SUBSCRIBE_EVENT_TYPES_ACK nor ERROR.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void rsp_encap_subscribe_event_types_err_case8(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_subscribe_event_types_ack_response_t *spdm_response;
    size_t response_size;
    bool need_continue;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x08;

    set_standard_state(spdm_context);

    spdm_response = (spdm_subscribe_event_types_ack_response_t *)m_receive_buffer;
    response_size = build_response(spdm_response);
    spdm_response->header.request_response_code = SPDM_EVENT_ACK;

    assert_int_equal(
        libspdm_process_encap_response_subscribe_event_types_ack(
            spdm_context, response_size, spdm_response, &need_continue),
        LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 9: the Requester delivers an encapsulated ERROR.
 * Expected Behavior: ErrorCode=ResponseNotReady returns LIBSPDM_STATUS_NOT_READY_PEER, so that the
 * request can be reissued with RESPOND_IF_READY, and every other ErrorCode returns
 * LIBSPDM_STATUS_UNSUPPORTED_CAP.
 **/
static void rsp_encap_subscribe_event_types_err_case9(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_error_response_t *spdm_response;
    bool need_continue;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x09;

    set_standard_state(spdm_context);

    spdm_response = (spdm_error_response_t *)m_receive_buffer;
    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_response->header.request_response_code = SPDM_ERROR;
    spdm_response->header.param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
    spdm_response->header.param2 = 0;

    assert_int_equal(
        libspdm_process_encap_response_subscribe_event_types_ack(
            spdm_context, sizeof(spdm_error_response_t), spdm_response, &need_continue),
        LIBSPDM_STATUS_UNSUPPORTED_CAP);

    spdm_response->header.param1 = SPDM_ERROR_CODE_RESPONSE_NOT_READY;

    assert_int_equal(
        libspdm_process_encap_response_subscribe_event_types_ack(
            spdm_context, sizeof(spdm_error_response_t), spdm_response, &need_continue),
        LIBSPDM_STATUS_NOT_READY_PEER);
}

/**
 * Test 10: the encapsulated SUBSCRIBE_EVENT_TYPES_ACK is not the size the specification defines.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_MSG_SIZE, as the acknowledgement is exactly
 * the message header.
 **/
static void rsp_encap_subscribe_event_types_err_case10(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_subscribe_event_types_ack_response_t *spdm_response;
    size_t response_size;
    bool need_continue;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x0A;

    set_standard_state(spdm_context);

    spdm_response = (spdm_subscribe_event_types_ack_response_t *)m_receive_buffer;
    response_size = build_response(spdm_response);

    assert_int_equal(
        libspdm_process_encap_response_subscribe_event_types_ack(
            spdm_context, response_size + 1, spdm_response, &need_continue),
        LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

/**
 * Test 11: the encapsulated response is delivered outside of a session.
 * Expected Behavior: returns LIBSPDM_STATUS_ERROR_PEER, as the Requester delivered the response on
 * a channel that the request could not have been sent on.
 **/
static void rsp_encap_subscribe_event_types_err_case11(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_subscribe_event_types_ack_response_t *spdm_response;
    size_t response_size;
    bool need_continue;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x0B;

    set_standard_state(spdm_context);

    spdm_response = (spdm_subscribe_event_types_ack_response_t *)m_receive_buffer;
    response_size = build_response(spdm_response);

    spdm_context->last_spdm_request_session_id_valid = false;

    assert_int_equal(
        libspdm_process_encap_response_subscribe_event_types_ack(
            spdm_context, response_size, spdm_response, &need_continue),
        LIBSPDM_STATUS_ERROR_PEER);
}

int libspdm_rsp_encap_subscribe_event_types_error_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(rsp_encap_subscribe_event_types_err_case1),
        cmocka_unit_test(rsp_encap_subscribe_event_types_err_case2),
        cmocka_unit_test(rsp_encap_subscribe_event_types_err_case3),
        cmocka_unit_test(rsp_encap_subscribe_event_types_err_case4),
        cmocka_unit_test(rsp_encap_subscribe_event_types_err_case5),
        cmocka_unit_test(rsp_encap_subscribe_event_types_err_case6),
        cmocka_unit_test(rsp_encap_subscribe_event_types_err_case7),
        cmocka_unit_test(rsp_encap_subscribe_event_types_err_case8),
        cmocka_unit_test(rsp_encap_subscribe_event_types_err_case9),
        cmocka_unit_test(rsp_encap_subscribe_event_types_err_case10),
        cmocka_unit_test(rsp_encap_subscribe_event_types_err_case11),
    };

    libspdm_test_context_t test_context = {
        LIBSPDM_TEST_CONTEXT_VERSION,
        false,
    };

    libspdm_setup_test_context(&test_context);

    return cmocka_run_group_tests(test_cases,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (LIBSPDM_EVENT_RECIPIENT_SUPPORT) */
