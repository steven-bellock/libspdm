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

static uint8_t m_handler_last_request_code;
static uint32_t m_handler_call_count;

static void set_standard_state(libspdm_context_t *spdm_context)
{
    libspdm_session_info_t *session_info;
    uint32_t index;

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

    /* libspdm does not parse the subscription list, so its contents only need to be
     * distinguishable. */
    for (index = 0; index < LIBSPDM_TEST_SUBSCRIBE_LIST_SIZE; index++) {
        m_subscribe_list[index] = (uint8_t)(index + 1);
    }
}

/**
 * Populate a SUBSCRIBE_EVENT_TYPES_ACK response.
 **/
static size_t build_response(spdm_subscribe_event_types_ack_response_t *spdm_response)
{
    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_response->header.request_response_code = SPDM_SUBSCRIBE_EVENT_TYPES_ACK;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;

    return sizeof(spdm_subscribe_event_types_ack_response_t);
}

/**
 * Records what libspdm reported for the encapsulated request that has just been answered, and ends
 * the flow. It is only registered by the test that drives a complete exchange.
 **/
static libspdm_return_t encap_flow_handler(void *spdm_context,
                                           const uint32_t *session_id,
                                           libspdm_encap_flow_type_t encap_flow_type,
                                           uint8_t last_request_code,
                                           uint8_t error_code,
                                           bool *terminate_flow,
                                           size_t *encap_request_size,
                                           void *encap_request)
{
    m_handler_call_count++;
    m_handler_last_request_code = last_request_code;

    assert_non_null(session_id);
    assert_int_equal(*session_id, m_session_id);
    assert_int_equal(encap_flow_type, LIBSPDM_ENCAP_FLOW_REQ_INITIATED);
    assert_int_equal(error_code, 0);

    *terminate_flow = true;

    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * Test 1: Responder forms the expected SUBSCRIBE_EVENT_TYPES request message.
 * Expected Behavior: returns LIBSPDM_STATUS_SUCCESS, Param1 carries SubscribeEventGroupCount, and
 * the subscription list follows SubscribeListLen unchanged.
 **/
static void rsp_encap_subscribe_event_types_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t request_buffer_size = sizeof(m_send_buffer);
    const spdm_subscribe_event_types_request_t *spdm_request;
    const uint8_t *list;
    uint32_t index;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x01;

    set_standard_state(spdm_context);

    status = libspdm_get_encap_request_subscribe_event_types(
        spdm_context, m_session_id, 2, sizeof(m_subscribe_list), m_subscribe_list,
        &request_buffer_size, m_send_buffer);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(request_buffer_size,
                     sizeof(spdm_subscribe_event_types_request_t) + sizeof(m_subscribe_list));

    spdm_request = (const spdm_subscribe_event_types_request_t *)m_send_buffer;

    assert_int_equal(spdm_request->header.spdm_version, SPDM_MESSAGE_VERSION_13);
    assert_int_equal(spdm_request->header.request_response_code, SPDM_SUBSCRIBE_EVENT_TYPES);
    assert_int_equal(spdm_request->header.param1, 2);
    assert_int_equal(spdm_request->header.param2, 0);
    assert_int_equal(spdm_request->subscribe_list_len, sizeof(m_subscribe_list));

    list = (const uint8_t *)(spdm_request + 1);
    for (index = 0; index < LIBSPDM_TEST_SUBSCRIBE_LIST_SIZE; index++) {
        assert_int_equal(list[index], (uint8_t)(index + 1));
    }
}

/**
 * Test 2: the Responder unsubscribes from every event type.
 * Expected Behavior: returns LIBSPDM_STATUS_SUCCESS and the request is only the message header, as
 * SubscribeListLen and SubscribeList are absent when SubscribeEventGroupCount is zero.
 **/
static void rsp_encap_subscribe_event_types_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t request_buffer_size = sizeof(m_send_buffer);
    const spdm_subscribe_event_types_request_t *spdm_request;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x02;

    set_standard_state(spdm_context);

    status = libspdm_get_encap_request_subscribe_event_types(
        spdm_context, m_session_id, 0, 0, NULL, &request_buffer_size, m_send_buffer);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(request_buffer_size, sizeof(spdm_message_header_t));

    spdm_request = (const spdm_subscribe_event_types_request_t *)m_send_buffer;

    assert_int_equal(spdm_request->header.spdm_version, SPDM_MESSAGE_VERSION_13);
    assert_int_equal(spdm_request->header.request_response_code, SPDM_SUBSCRIBE_EVENT_TYPES);
    assert_int_equal(spdm_request->header.param1, 0);
    assert_int_equal(spdm_request->header.param2, 0);
}

/**
 * Test 3: the Responder records SUBSCRIBE_EVENT_TYPES as the outstanding encapsulated request.
 * Expected Behavior: last_encap_request_header names SUBSCRIBE_EVENT_TYPES and
 * last_encap_request_size is the size of the request that was built, so that the encapsulated
 * SUBSCRIBE_EVENT_TYPES_ACK is dispatched to the acknowledgement processing function rather than
 * being treated as unsolicited.
 **/
static void rsp_encap_subscribe_event_types_case3(void **state)
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

    /* The flow begins with nothing outstanding, as libspdm_get_response_encapsulated_request
     * leaves it. */
    session_info->encap_context.last_encap_request_size = 0;
    libspdm_zero_mem(&session_info->encap_context.last_encap_request_header,
                     sizeof(session_info->encap_context.last_encap_request_header));

    assert_int_equal(
        libspdm_get_encap_request_subscribe_event_types(
            spdm_context, m_session_id, 1, sizeof(m_subscribe_list), m_subscribe_list,
            &request_buffer_size, m_send_buffer),
        LIBSPDM_STATUS_SUCCESS);

    assert_int_equal(session_info->encap_context.last_encap_request_header.request_response_code,
                     SPDM_SUBSCRIBE_EVENT_TYPES);
    assert_int_equal(session_info->encap_context.last_encap_request_header.spdm_version,
                     SPDM_MESSAGE_VERSION_13);
    assert_int_equal(session_info->encap_context.last_encap_request_size, request_buffer_size);
}

/**
 * Test 4: Responder processes the encapsulated SUBSCRIBE_EVENT_TYPES_ACK response.
 * Expected Behavior: returns LIBSPDM_STATUS_SUCCESS and the flow does not continue, as the
 * acknowledgement carries no payload.
 **/
static void rsp_encap_subscribe_event_types_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_subscribe_event_types_ack_response_t *spdm_response;
    size_t response_size;
    bool need_continue;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x04;

    set_standard_state(spdm_context);

    spdm_response = (spdm_subscribe_event_types_ack_response_t *)m_receive_buffer;
    response_size = build_response(spdm_response);

    need_continue = true;
    status = libspdm_process_encap_response_subscribe_event_types_ack(
        spdm_context, response_size, spdm_response, &need_continue);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_false(need_continue);
}

/**
 * Test 5: a complete exchange, from the encapsulated SUBSCRIBE_EVENT_TYPES request to the
 * Requester's delivery of SUBSCRIBE_EVENT_TYPES_ACK.
 * Expected Behavior: the Responder dispatches the delivered response to the acknowledgement
 * processing function, so the encapsulated flow handler is called with a last_request_code of
 * SUBSCRIBE_EVENT_TYPES. The handler ends the flow, so ENCAPSULATED_RESPONSE_ACK carries no
 * further request.
 **/
static void rsp_encap_subscribe_event_types_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    spdm_deliver_encapsulated_response_request_t *spdm_request;
    spdm_subscribe_event_types_ack_response_t *encap_response;
    const spdm_encapsulated_response_ack_response_t *spdm_ack;
    size_t encap_response_size;
    size_t request_buffer_size = sizeof(m_send_buffer);
    size_t response_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x05;

    set_standard_state(spdm_context);
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    libspdm_register_encap_flow_handler(spdm_context, encap_flow_handler);

    session_info = &spdm_context->session_info[0];
    session_info->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;
    session_info->encap_context.request_id = 0xFF;

    assert_int_equal(
        libspdm_get_encap_request_subscribe_event_types(
            spdm_context, m_session_id, 1, sizeof(m_subscribe_list), m_subscribe_list,
            &request_buffer_size, m_send_buffer),
        LIBSPDM_STATUS_SUCCESS);

    spdm_request = (spdm_deliver_encapsulated_response_request_t *)m_receive_buffer;
    spdm_request->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_request->header.request_response_code = SPDM_DELIVER_ENCAPSULATED_RESPONSE;
    spdm_request->header.param1 = 0xFF;
    spdm_request->header.param2 = 0;

    encap_response = (spdm_subscribe_event_types_ack_response_t *)(spdm_request + 1);
    encap_response_size = build_response(encap_response);

    m_handler_call_count = 0;
    m_handler_last_request_code = 0xFF;

    response_size = sizeof(m_send_buffer);
    status = libspdm_get_response_encapsulated_response_ack(
        spdm_context,
        sizeof(spdm_deliver_encapsulated_response_request_t) + encap_response_size,
        spdm_request, &response_size, m_send_buffer);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_encapsulated_response_ack_response_t));

    spdm_ack = (const spdm_encapsulated_response_ack_response_t *)m_send_buffer;
    assert_int_equal(spdm_ack->header.request_response_code, SPDM_ENCAPSULATED_RESPONSE_ACK);
    assert_int_equal(spdm_ack->header.param2,
                     SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_ABSENT);

    assert_int_equal(m_handler_call_count, 1);
    assert_int_equal(m_handler_last_request_code, SPDM_SUBSCRIBE_EVENT_TYPES);
}

int libspdm_rsp_encap_subscribe_event_types_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(rsp_encap_subscribe_event_types_case1),
        cmocka_unit_test(rsp_encap_subscribe_event_types_case2),
        cmocka_unit_test(rsp_encap_subscribe_event_types_case3),
        cmocka_unit_test(rsp_encap_subscribe_event_types_case4),
        cmocka_unit_test(rsp_encap_subscribe_event_types_case5),
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
