/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

#if (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (LIBSPDM_EVENT_RECIPIENT_SUPPORT)

#define LIBSPDM_TEST_EVENT_GROUPS_LIST_SIZE 0x20

static uint8_t m_send_buffer[LIBSPDM_MAX_SPDM_MSG_SIZE];
static uint8_t m_receive_buffer[LIBSPDM_MAX_SPDM_MSG_SIZE];
static uint8_t m_event_groups_list[LIBSPDM_TEST_EVENT_GROUPS_LIST_SIZE];
static uint8_t m_event_group_count;
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
}

static void build_request(libspdm_context_t *spdm_context)
{
    size_t request_buffer_size = sizeof(m_send_buffer);

    libspdm_zero_mem(m_event_groups_list, sizeof(m_event_groups_list));
    m_event_group_count = 0;

    assert_int_equal(
        libspdm_get_encap_request_get_supported_event_types(
            spdm_context, m_session_id, &m_event_group_count, sizeof(m_event_groups_list),
            m_event_groups_list, &request_buffer_size, m_send_buffer),
        LIBSPDM_STATUS_SUCCESS);
}

static size_t build_response(spdm_supported_event_types_response_t *spdm_response,
                             uint8_t event_group_count, uint32_t list_len)
{
    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_response->header.request_response_code = SPDM_SUPPORTED_EVENT_TYPES;
    spdm_response->header.param1 = event_group_count;
    spdm_response->header.param2 = 0;
    spdm_response->supported_event_groups_list_len = list_len;

    libspdm_set_mem((uint8_t *)(spdm_response + 1), list_len, 0xAA);

    return sizeof(spdm_supported_event_types_response_t) + list_len;
}

/**
 * Test 1: the Integrator does not supply somewhere to place the Requester's response.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_PARAMETER. The list and the count that
 * describes it are both required, as the response cannot be reported without them.
 **/
static void rsp_encap_get_supported_event_types_err_case1(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t request_buffer_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x01;

    set_standard_state(spdm_context);

    request_buffer_size = sizeof(m_send_buffer);
    assert_int_equal(
        libspdm_get_encap_request_get_supported_event_types(
            spdm_context, m_session_id, NULL, sizeof(m_event_groups_list), m_event_groups_list,
            &request_buffer_size, m_send_buffer),
        LIBSPDM_STATUS_INVALID_PARAMETER);

    request_buffer_size = sizeof(m_send_buffer);
    assert_int_equal(
        libspdm_get_encap_request_get_supported_event_types(
            spdm_context, m_session_id, &m_event_group_count, sizeof(m_event_groups_list), NULL,
            &request_buffer_size, m_send_buffer),
        LIBSPDM_STATUS_INVALID_PARAMETER);

    request_buffer_size = sizeof(m_send_buffer);
    assert_int_equal(
        libspdm_get_encap_request_get_supported_event_types(
            spdm_context, m_session_id, &m_event_group_count, 0, m_event_groups_list,
            &request_buffer_size, m_send_buffer),
        LIBSPDM_STATUS_INVALID_PARAMETER);
}

/**
 * Test 2: an unknown session is rejected.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_STATE_LOCAL, as
 * GET_SUPPORTED_EVENT_TYPES is prohibited outside of a session.
 **/
static void rsp_encap_get_supported_event_types_err_case2(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t request_buffer_size = sizeof(m_send_buffer);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x02;

    set_standard_state(spdm_context);

    assert_int_equal(
        libspdm_get_encap_request_get_supported_event_types(
            spdm_context, 0xDEADBEEF, &m_event_group_count, sizeof(m_event_groups_list),
            m_event_groups_list, &request_buffer_size, m_send_buffer),
        LIBSPDM_STATUS_INVALID_STATE_LOCAL);
}

/**
 * Test 3: the session exists but its handshake has not completed.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_STATE_LOCAL, as the message is only allowed
 * in the Application Phase.
 **/
static void rsp_encap_get_supported_event_types_err_case3(void **state)
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
        libspdm_get_encap_request_get_supported_event_types(
            spdm_context, m_session_id, &m_event_group_count, sizeof(m_event_groups_list),
            m_event_groups_list, &request_buffer_size, m_send_buffer),
        LIBSPDM_STATUS_INVALID_STATE_LOCAL);
}

/**
 * Test 4: the connection is earlier than SPDM 1.3, which is the version that introduced events.
 * Expected Behavior: returns LIBSPDM_STATUS_UNSUPPORTED_CAP.
 **/
static void rsp_encap_get_supported_event_types_err_case4(void **state)
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
        libspdm_get_encap_request_get_supported_event_types(
            spdm_context, m_session_id, &m_event_group_count, sizeof(m_event_groups_list),
            m_event_groups_list, &request_buffer_size, m_send_buffer),
        LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 5: the Requester did not set EVENT_CAP, so it is not an Event Notifier.
 * Expected Behavior: returns LIBSPDM_STATUS_UNSUPPORTED_CAP. The Requester would answer with
 * ERROR(UnsupportedRequest), so the request is not sent.
 **/
static void rsp_encap_get_supported_event_types_err_case5(void **state)
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
        libspdm_get_encap_request_get_supported_event_types(
            spdm_context, m_session_id, &m_event_group_count, sizeof(m_event_groups_list),
            m_event_groups_list, &request_buffer_size, m_send_buffer),
        LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 6: the encapsulated SUPPORTED_EVENT_TYPES is not the negotiated version.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void rsp_encap_get_supported_event_types_err_case6(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_supported_event_types_response_t *spdm_response;
    size_t response_size;
    bool need_continue;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x06;

    set_standard_state(spdm_context);
    build_request(spdm_context);

    spdm_response = (spdm_supported_event_types_response_t *)m_receive_buffer;
    response_size = build_response(spdm_response, 1, LIBSPDM_TEST_EVENT_GROUPS_LIST_SIZE);
    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;

    assert_int_equal(
        libspdm_process_encap_response_supported_event_types(
            spdm_context, response_size, spdm_response, &need_continue),
        LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 7: the encapsulated response is neither SUPPORTED_EVENT_TYPES nor ERROR.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void rsp_encap_get_supported_event_types_err_case7(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_supported_event_types_response_t *spdm_response;
    size_t response_size;
    bool need_continue;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x07;

    set_standard_state(spdm_context);
    build_request(spdm_context);

    spdm_response = (spdm_supported_event_types_response_t *)m_receive_buffer;
    response_size = build_response(spdm_response, 1, LIBSPDM_TEST_EVENT_GROUPS_LIST_SIZE);
    spdm_response->header.request_response_code = SPDM_SUBSCRIBE_EVENT_TYPES_ACK;

    assert_int_equal(
        libspdm_process_encap_response_supported_event_types(
            spdm_context, response_size, spdm_response, &need_continue),
        LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 8: the Requester delivers an encapsulated ERROR.
 * Expected Behavior: ErrorCode=ResponseNotReady returns LIBSPDM_STATUS_NOT_READY_PEER, so that the
 * request can be reissued with RESPOND_IF_READY, and every other ErrorCode returns
 * LIBSPDM_STATUS_UNSUPPORTED_CAP.
 **/
static void rsp_encap_get_supported_event_types_err_case8(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_error_response_t *spdm_response;
    bool need_continue;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x08;

    set_standard_state(spdm_context);
    build_request(spdm_context);

    spdm_response = (spdm_error_response_t *)m_receive_buffer;
    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_response->header.request_response_code = SPDM_ERROR;
    spdm_response->header.param1 = SPDM_ERROR_CODE_UNSUPPORTED_REQUEST;
    spdm_response->header.param2 = SPDM_GET_SUPPORTED_EVENT_TYPES;

    assert_int_equal(
        libspdm_process_encap_response_supported_event_types(
            spdm_context, sizeof(spdm_error_response_t), spdm_response, &need_continue),
        LIBSPDM_STATUS_UNSUPPORTED_CAP);

    spdm_response->header.param1 = SPDM_ERROR_CODE_RESPONSE_NOT_READY;

    assert_int_equal(
        libspdm_process_encap_response_supported_event_types(
            spdm_context, sizeof(spdm_error_response_t), spdm_response, &need_continue),
        LIBSPDM_STATUS_NOT_READY_PEER);
}

/**
 * Test 9: EventGroupCount and SupportedEventGroupsListLen are each required to be greater than
 * zero.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_MSG_FIELD in both cases.
 **/
static void rsp_encap_get_supported_event_types_err_case9(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_supported_event_types_response_t *spdm_response;
    size_t response_size;
    bool need_continue;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x09;

    set_standard_state(spdm_context);
    build_request(spdm_context);

    spdm_response = (spdm_supported_event_types_response_t *)m_receive_buffer;

    response_size = build_response(spdm_response, 0, LIBSPDM_TEST_EVENT_GROUPS_LIST_SIZE);
    assert_int_equal(
        libspdm_process_encap_response_supported_event_types(
            spdm_context, response_size, spdm_response, &need_continue),
        LIBSPDM_STATUS_INVALID_MSG_FIELD);

    response_size = build_response(spdm_response, 1, 0);
    assert_int_equal(
        libspdm_process_encap_response_supported_event_types(
            spdm_context, response_size, spdm_response, &need_continue),
        LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 10: the size of the encapsulated response does not agree with
 * SupportedEventGroupsListLen.
 * Expected Behavior: returns LIBSPDM_STATUS_INVALID_MSG_SIZE, whether the response is truncated,
 * carries trailing bytes, or is smaller than the fixed portion of the response.
 **/
static void rsp_encap_get_supported_event_types_err_case10(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_supported_event_types_response_t *spdm_response;
    size_t response_size;
    bool need_continue;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x0A;

    set_standard_state(spdm_context);
    build_request(spdm_context);

    spdm_response = (spdm_supported_event_types_response_t *)m_receive_buffer;
    response_size = build_response(spdm_response, 1, LIBSPDM_TEST_EVENT_GROUPS_LIST_SIZE);

    assert_int_equal(
        libspdm_process_encap_response_supported_event_types(
            spdm_context, response_size - 1, spdm_response, &need_continue),
        LIBSPDM_STATUS_INVALID_MSG_SIZE);

    assert_int_equal(
        libspdm_process_encap_response_supported_event_types(
            spdm_context, response_size + 1, spdm_response, &need_continue),
        LIBSPDM_STATUS_INVALID_MSG_SIZE);

    assert_int_equal(
        libspdm_process_encap_response_supported_event_types(
            spdm_context, sizeof(spdm_message_header_t), spdm_response, &need_continue),
        LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

/**
 * Test 11: the encapsulated response is delivered outside of a session.
 * Expected Behavior: returns LIBSPDM_STATUS_ERROR_PEER, as the Requester delivered the response
 * on a channel that the request could not have been sent on.
 **/
static void rsp_encap_get_supported_event_types_err_case11(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_supported_event_types_response_t *spdm_response;
    size_t response_size;
    bool need_continue;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x0B;

    set_standard_state(spdm_context);
    build_request(spdm_context);

    spdm_response = (spdm_supported_event_types_response_t *)m_receive_buffer;
    response_size = build_response(spdm_response, 1, LIBSPDM_TEST_EVENT_GROUPS_LIST_SIZE);

    spdm_context->last_spdm_request_session_id_valid = false;

    assert_int_equal(
        libspdm_process_encap_response_supported_event_types(
            spdm_context, response_size, spdm_response, &need_continue),
        LIBSPDM_STATUS_ERROR_PEER);
}

int libspdm_rsp_encap_get_supported_event_types_error_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(rsp_encap_get_supported_event_types_err_case1),
        cmocka_unit_test(rsp_encap_get_supported_event_types_err_case2),
        cmocka_unit_test(rsp_encap_get_supported_event_types_err_case3),
        cmocka_unit_test(rsp_encap_get_supported_event_types_err_case4),
        cmocka_unit_test(rsp_encap_get_supported_event_types_err_case5),
        cmocka_unit_test(rsp_encap_get_supported_event_types_err_case6),
        cmocka_unit_test(rsp_encap_get_supported_event_types_err_case7),
        cmocka_unit_test(rsp_encap_get_supported_event_types_err_case8),
        cmocka_unit_test(rsp_encap_get_supported_event_types_err_case9),
        cmocka_unit_test(rsp_encap_get_supported_event_types_err_case10),
        cmocka_unit_test(rsp_encap_get_supported_event_types_err_case11),
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
