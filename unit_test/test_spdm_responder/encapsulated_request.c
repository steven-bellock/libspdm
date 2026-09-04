/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP

static spdm_get_encapsulated_request_request_t m_libspdm_encapsulated_request_t1 = {
    {SPDM_MESSAGE_VERSION_11, SPDM_GET_ENCAPSULATED_REQUEST, 0, 0}
};
static size_t m_libspdm_encapsulated_request_t1_size = sizeof(m_libspdm_encapsulated_request_t1);

static spdm_get_encapsulated_request_request_t m_libspdm_encapsulated_request_t2 = {
    {SPDM_MESSAGE_VERSION_13, SPDM_GET_ENCAPSULATED_REQUEST, 0, 0}
};
static size_t m_libspdm_encapsulated_request_t2_size = sizeof(m_libspdm_encapsulated_request_t2);

static spdm_deliver_encapsulated_response_request_t m_libspdm_m_deliver_encapsulated_response_request_t1 =
{
    {SPDM_MESSAGE_VERSION_11, SPDM_DELIVER_ENCAPSULATED_RESPONSE, 0, 0}
};
static size_t m_libspdm_m_deliver_encapsulated_response_request_t1_size =
    sizeof(m_libspdm_m_deliver_encapsulated_response_request_t1);

#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
static uint8_t m_libspdm_local_certificate_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */

#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
static spdm_deliver_encapsulated_response_request_t m_libspdm_m_deliver_encapsulated_response_request_t2 =
{
    {SPDM_MESSAGE_VERSION_12, SPDM_DELIVER_ENCAPSULATED_RESPONSE, 0xFF, 0}
};
static size_t m_libspdm_m_deliver_encapsulated_response_request_t2_size =
    sizeof(m_libspdm_m_deliver_encapsulated_response_request_t2);
#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */

static uint32_t m_case_id;
#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
/* Number of encapsulated GET_DIGESTS requests still to be issued by handler case 0x91. */
static uint8_t m_get_digests_rounds;
#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */
/* The request code that handler case 0x9B emits, so that the per-flow legality table can be
 * driven directly rather than through a builder. */
static uint8_t m_legality_request_code;
/* The error_code the handler was last called with, so that a test can show the handler was
 * reached and given the Requester's ErrorCode. */
static uint8_t m_observed_error_code;

static libspdm_return_t encap_flow_handler(
    void *spdm_context, const uint32_t *session_id, libspdm_encap_flow_type_t encap_flow_type,
    uint8_t last_request_code, uint8_t error_code, bool *terminate_flow, size_t *request_size,
    void *request)
{
#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
    libspdm_data_parameter_t parameter;
    uint8_t slot_id;
#endif /* LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP */

    assert_int_not_equal(encap_flow_type, LIBSPDM_ENCAP_FLOW_NONE);

    *terminate_flow = false;
    m_observed_error_code = error_code;

    switch (m_case_id) {
#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
    case 0x1:
        assert_null(session_id);
        assert_int_equal(encap_flow_type, LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH);
        assert_int_equal(last_request_code, 0);

        return libspdm_get_encap_request_get_digests(spdm_context, session_id, request_size, request);
    case 0x2:
        assert_null(session_id);
        assert_int_equal(encap_flow_type, LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH);
        assert_int_equal(last_request_code, 0);

        return libspdm_get_encap_request_get_certificate(
            spdm_context, session_id, 0, sizeof(m_libspdm_local_certificate_chain),
            m_libspdm_local_certificate_chain, request_size, request);
#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */
    case 0x3:
        assert_null(session_id);
        assert_int_equal(encap_flow_type, LIBSPDM_ENCAP_FLOW_REQ_INITIATED);
        assert_int_equal(last_request_code, 0);

        *terminate_flow = true;

        return LIBSPDM_STATUS_SUCCESS;
    case 0x92:
        /* Session-based mutual authentication; end the flow once DIGESTS has been processed. */
        assert_non_null(session_id);
        assert_int_equal(encap_flow_type, LIBSPDM_ENCAP_FLOW_SESS_MUT_AUTH);
        *terminate_flow = true;
        return LIBSPDM_STATUS_SUCCESS;
#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
    case 0x93:
        /* Same, but the Responder examined DIGESTS and designates a different slot than the one
         * chosen at KEY_EXCHANGE time. */
        assert_non_null(session_id);
        assert_int_equal(encap_flow_type, LIBSPDM_ENCAP_FLOW_SESS_MUT_AUTH);

        libspdm_zero_mem(&parameter, sizeof(parameter));
        parameter.location = LIBSPDM_DATA_LOCATION_SESSION;
        libspdm_write_uint32(parameter.additional_data, *session_id);

        /* A slot outside 0..7 is rejected. */
        slot_id = SPDM_MAX_SLOT_COUNT;
        assert_int_equal(libspdm_set_data(spdm_context, LIBSPDM_DATA_SESSION_ENCAP_REQ_SLOT_ID,
                                          &parameter, &slot_id, sizeof(slot_id)),
                         LIBSPDM_STATUS_INVALID_PARAMETER);
        /* So is the wrong data size. */
        assert_int_equal(libspdm_set_data(spdm_context, LIBSPDM_DATA_SESSION_ENCAP_REQ_SLOT_ID,
                                          &parameter, &slot_id, sizeof(uint32_t)),
                         LIBSPDM_STATUS_INVALID_PARAMETER);

        slot_id = 5;
        /* A session that does not exist is rejected. */
        libspdm_write_uint32(parameter.additional_data, 0xDEADBEEF);
        assert_int_equal(libspdm_set_data(spdm_context, LIBSPDM_DATA_SESSION_ENCAP_REQ_SLOT_ID,
                                          &parameter, &slot_id, sizeof(slot_id)),
                         LIBSPDM_STATUS_INVALID_PARAMETER);
        /* And so is any location other than the session. */
        libspdm_write_uint32(parameter.additional_data, *session_id);
        parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
        assert_int_equal(libspdm_set_data(spdm_context, LIBSPDM_DATA_SESSION_ENCAP_REQ_SLOT_ID,
                                          &parameter, &slot_id, sizeof(slot_id)),
                         LIBSPDM_STATUS_INVALID_PARAMETER);

        parameter.location = LIBSPDM_DATA_LOCATION_SESSION;
        assert_int_equal(libspdm_set_data(spdm_context, LIBSPDM_DATA_SESSION_ENCAP_REQ_SLOT_ID,
                                          &parameter, &slot_id, sizeof(slot_id)),
                         LIBSPDM_STATUS_SUCCESS);
        *terminate_flow = true;
        return LIBSPDM_STATUS_SUCCESS;
#endif /* LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP */
#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
    case 0x91:
        /* Issue GET_DIGESTS m_get_digests_rounds times, then terminate. Used to observe how the
         * Responder allocates the Request ID across several encapsulated requests. */
        if (m_get_digests_rounds > 0) {
            m_get_digests_rounds--;
            return libspdm_get_encap_request_get_digests(spdm_context, session_id, request_size,
                                                         request);
        }
        *terminate_flow = true;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x90:
        /* Requester-initiated flow within a secure session. The session is whichever one the
         * GET_ENCAPSULATED_REQUEST arrived on. */
        assert_non_null(session_id);
        assert_int_equal(encap_flow_type, LIBSPDM_ENCAP_FLOW_REQ_INITIATED);
        assert_int_equal(last_request_code, 0);

        return libspdm_get_encap_request_get_digests(spdm_context, session_id, request_size,
                                                     request);
#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */
#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_SEND_CHALLENGE_SUPPORT)
    case 0x5:
        assert_null(session_id);
        assert_int_equal(encap_flow_type, LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH);
        assert_int_equal(last_request_code, 0);

        return libspdm_get_encap_request_challenge(spdm_context, 4, NULL, request_size, request);
#endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_SEND_CHALLENGE_SUPPORT) */
    case 0x6:
        assert_non_null(session_id);
        assert_int_equal(*session_id, 0xFFFFFFFF);
        assert_int_equal(encap_flow_type, LIBSPDM_ENCAP_FLOW_REQ_INITIATED);
        assert_int_equal(last_request_code, 0);

        return libspdm_get_encap_request_key_update(
            spdm_context, *session_id, SPDM_KEY_UPDATE_OPERATIONS_UPDATE_KEY, request_size, request);
    case 0x8E:
        /* UpdateAllKeys is not legal in the encapsulated flow. */
        return libspdm_get_encap_request_key_update(
            spdm_context, *session_id, SPDM_KEY_UPDATE_OPERATIONS_UPDATE_ALL_KEYS,
            request_size, request);
    case 0x7:
        assert_null(session_id);
        assert_int_equal(encap_flow_type, LIBSPDM_ENCAP_FLOW_REQ_INITIATED);
        assert_int_equal(last_request_code, 0);

        *terminate_flow = true;

        return LIBSPDM_STATUS_SUCCESS;
#if LIBSPDM_SEND_GET_ENDPOINT_INFO_SUPPORT
    case 0x8:
        assert_non_null(session_id);
        assert_int_equal(*session_id, 0xFFFFFFFF);
        assert_int_equal(encap_flow_type, LIBSPDM_ENCAP_FLOW_REQ_INITIATED);
        assert_int_equal(last_request_code, 0);

        return libspdm_get_encap_request_get_endpoint_info(
            spdm_context, session_id,
            SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER,
            0,
            SPDM_GET_ENDPOINT_INFO_REQUEST_ATTRIBUTE_SIGNATURE_REQUESTED,
            request_size, request);
    case 0x8B:
        /* GET_ENDPOINT_INFO is not legal in the basic mutual authentication flow. The Responder
         * must reject it rather than send it to the Requester. */
        assert_int_equal(encap_flow_type, LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH);

        return libspdm_get_encap_request_get_endpoint_info(
            spdm_context, session_id,
            SPDM_GET_ENDPOINT_INFO_REQUEST_SUBCODE_DEVICE_CLASS_IDENTIFIER,
            0, 0, request_size, request);
#endif /* LIBSPDM_SEND_GET_ENDPOINT_INFO_SUPPORT */
#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) && \
        (LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT)
    case 0x98:
        /* Session-based mutual authentication with handshake in the clear. The message arrived
         * outside of a session, but the flow belongs to the session. */
        assert_non_null(session_id);
        assert_int_equal(*session_id, 0xFFFFFFFF);
        assert_int_equal(encap_flow_type, LIBSPDM_ENCAP_FLOW_SESS_MUT_AUTH);

        return libspdm_get_encap_request_get_digests(spdm_context, session_id, request_size,
                                                     request);
    case 0x99:
        /* Same message, but without handshake in the clear the non-session context is used, so
         * this is an ordinary Requester-initiated flow outside of a session. */
        assert_null(session_id);
        assert_int_equal(encap_flow_type, LIBSPDM_ENCAP_FLOW_REQ_INITIATED);
        *terminate_flow = true;
        return LIBSPDM_STATUS_SUCCESS;
#endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (..) */
    case 0x9B: {
        /* Emit an arbitrary request code so that libspdm_is_encap_request_legal is exercised
         * for combinations no builder would produce. */
        spdm_message_header_t *header = request;
        header->spdm_version = SPDM_MESSAGE_VERSION_11;
        header->request_response_code = m_legality_request_code;
        header->param1 = 0;
        header->param2 = 0;
        *request_size = sizeof(spdm_message_header_t);
        return LIBSPDM_STATUS_SUCCESS;
    }
    case 0x95: {
        /* Integrator terminates the flow by emitting an ERROR instead of a request. */
        spdm_error_response_t *err = request;
        err->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        err->header.request_response_code = SPDM_ERROR;
        err->header.param1 = SPDM_ERROR_CODE_INVALID_POLICY;
        err->header.param2 = 0;
        *request_size = sizeof(spdm_error_response_t);
        return LIBSPDM_STATUS_SUCCESS;
    }
    case 0x96: {
        /* Same, but the Integrator leaves request_size at the full buffer size. libspdm must
         * bound it rather than copy that many bytes. */
        spdm_error_response_t *err = request;
        err->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        err->header.request_response_code = SPDM_ERROR;
        err->header.param1 = SPDM_ERROR_CODE_INVALID_POLICY;
        err->header.param2 = 0;
        /* deliberately does not set *request_size */
        return LIBSPDM_STATUS_SUCCESS;
    }
    case 0x8C:
        /* The Integrator's handler fails to build a request. */
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
    case 0x8D: {
        /* The Integrator passes a session_id that does not refer to an existing session. */
        uint32_t unknown_session_id = 0xDEADBEEF;

        return libspdm_get_encap_request_get_digests(
            spdm_context, &unknown_session_id, request_size, request);
    }
#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */
    case 0x81:
        assert_null(session_id);
        assert_int_equal(encap_flow_type, LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH);
        assert_int_equal(last_request_code, SPDM_GET_DIGESTS);
        *terminate_flow = true;
        break;
    case 0x82:
        break;
    case 0x83:
        assert_non_null(session_id);
        assert_int_equal(*session_id, 0xFFFFFFFF);
        assert_int_equal(encap_flow_type, LIBSPDM_ENCAP_FLOW_REQ_INITIATED);
        assert_int_equal(last_request_code, SPDM_KEY_UPDATE);
        *terminate_flow = true;
        break;
    case 0x88:
    case 0x89:
    case 0x94:
    case 0x9C:
    case 0xA0:
    case 0xA1:
        *terminate_flow = true;
        break;
    case 0x9D:
        /* Produce no request while leaving the flow running, so that the Responder has to end
         * the flow itself. */
        *request_size = 0;
        break;
    case 0x9E:
        /* The Integrator's handler fails. */
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    case 0x9F: {
        /* Same as case 0x95, but the Integrator reports a size that is smaller than a bare ERROR
         * message. libspdm must reject it rather than propagate a truncated message. */
        spdm_error_response_t *err = request;
        err->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        err->header.request_response_code = SPDM_ERROR;
        err->header.param1 = SPDM_ERROR_CODE_INVALID_POLICY;
        err->header.param2 = 0;
        *request_size = sizeof(spdm_error_response_t) - 1;
        return LIBSPDM_STATUS_SUCCESS;
    }
    default:
        assert_true(false);
        break;
    }

    return LIBSPDM_STATUS_SUCCESS;
}

static void set_standard_state(libspdm_context_t *spdm_context)
{
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_NONE;
#if LIBSPDM_RESPOND_IF_READY_SUPPORT
    spdm_context->encap_context.response_not_ready = false;
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */
    spdm_context->last_spdm_request_session_id_valid = false;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;

    libspdm_register_encap_flow_handler(spdm_context, encap_flow_handler);
}

#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT)
/**
 * Test 1 (GET_ENCAPSULATED_REQUEST)
 * Expected behavior: Responder generates encapsulated GET_DIGESTS request.
 **/
static void rsp_encapsulated_request_case1(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    spdm_encapsulated_request_response_t *spdm_response_requester;
    spdm_get_digest_request_t *spdm_get_digests_request;
    libspdm_context_t *spdm_context;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;
    void *data;
    size_t data_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    m_case_id = spdm_test_context->case_id;

    set_standard_state(spdm_context);

    spdm_context->encap_context.request_id = 0;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data,
                                                         &data_size,
                                                         NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_b(spdm_context);

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_request(spdm_context,
                                                       m_libspdm_encapsulated_request_t1_size,
                                                       &m_libspdm_encapsulated_request_t1,
                                                       &response_size,
                                                       response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_encapsulated_request_response_t) + sizeof(spdm_digest_response_t));
    spdm_response_requester = (void *)response;

    assert_int_equal(spdm_response_requester->header.spdm_version, SPDM_MESSAGE_VERSION_11);
    assert_int_equal(spdm_response_requester->header.request_response_code,
                     SPDM_ENCAPSULATED_REQUEST);
    /* The first encapsulated request of a flow uses Request ID 0. */
    assert_int_equal(spdm_response_requester->header.param1, 0x0);
    assert_int_equal(spdm_response_requester->header.param2, 0);

    spdm_get_digests_request = (spdm_get_digest_request_t *)(spdm_response_requester + 1);
    assert_int_equal(spdm_get_digests_request->header.spdm_version, SPDM_MESSAGE_VERSION_11);
    assert_int_equal(spdm_get_digests_request->header.request_response_code, SPDM_GET_DIGESTS);
    assert_int_equal(spdm_get_digests_request->header.param1, 0);
    assert_int_equal(spdm_get_digests_request->header.param2, 0);
}

/**
 * Test 2 (GET_ENCAPSULATED_REQUEST)
 * Expected behavior: Responder generates encapsulated GET_CERTIFICATE request.
 **/
static void rsp_encapsulated_request_case2(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    spdm_encapsulated_request_response_t *spdm_response_requester;
    spdm_get_certificate_request_t *spdm_get_certificate_request;
    libspdm_context_t *spdm_context;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;
    void *data;
    size_t data_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    m_case_id = spdm_test_context->case_id;

    set_standard_state(spdm_context);

    spdm_context->encap_context.request_id = 0;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH;

    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data,
                                                         &data_size,
                                                         NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_b(spdm_context);

    response_size = sizeof(response);

    status = libspdm_get_response_encapsulated_request(spdm_context,
                                                       m_libspdm_encapsulated_request_t1_size,
                                                       &m_libspdm_encapsulated_request_t1,
                                                       &response_size,
                                                       response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_encapsulated_request_response_t) +
                     sizeof(spdm_certificate_response_t));
    spdm_response_requester = (void *)response;
    assert_int_equal(spdm_response_requester->header.spdm_version, SPDM_MESSAGE_VERSION_11);
    assert_int_equal(spdm_response_requester->header.request_response_code,
                     SPDM_ENCAPSULATED_REQUEST);
    /* The first encapsulated request of a flow uses Request ID 0. */
    assert_int_equal(spdm_response_requester->header.param1, 0x0);
    assert_int_equal(spdm_response_requester->header.param2, 0);

    spdm_get_certificate_request = (spdm_get_certificate_request_t *)(spdm_response_requester + 1);
    assert_int_equal(spdm_get_certificate_request->header.spdm_version, SPDM_MESSAGE_VERSION_11);
    assert_int_equal(spdm_get_certificate_request->header.request_response_code,
                     SPDM_GET_CERTIFICATE);
    assert_int_equal(spdm_get_certificate_request->header.param1, 0);
    assert_int_equal(spdm_get_certificate_request->header.param2, 0);
    assert_int_equal(spdm_get_certificate_request->offset, 0);

    const size_t length = spdm_context->local_context.capability.max_spdm_msg_size -
                          sizeof(spdm_deliver_encapsulated_response_request_t) -
                          sizeof(spdm_get_certificate_request_t);

    assert_int_equal(spdm_get_certificate_request->length, length);
}
#endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT) */

#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT)
/**
 * Test 3 (GET_ENCAPSULATED_REQUEST) response_state is normal and Responder does not need the
 *        encapsulated flow.
 * Expected behavior: Responder generates SPDM_ERROR_CODE_UNEXPECTED_REQUEST.
 **/
static void rsp_encapsulated_request_case3(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    spdm_error_response_t *spdm_response_requester;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t m_local_certificate_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    m_case_id = spdm_test_context->case_id;

    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;

    spdm_context->encap_context.request_id = 0;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] = m_local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        sizeof(m_local_certificate_chain);
    libspdm_set_mem(m_local_certificate_chain, sizeof(m_local_certificate_chain), (uint8_t)(0xFF));
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_request(spdm_context,
                                                       m_libspdm_encapsulated_request_t1_size,
                                                       &m_libspdm_encapsulated_request_t1,
                                                       &response_size,
                                                       response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response_requester = (void *)response;
    assert_int_equal(spdm_response_requester->header.spdm_version, SPDM_MESSAGE_VERSION_11);
    assert_int_equal(spdm_response_requester->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response_requester->header.param1, SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
    assert_int_equal(spdm_response_requester->header.param2, 0);
}

/**
 * Test 4 (GET_ENCAPSULATED_REQUEST) response_state is need_resync.
 * Expected behavior: Responder generates SPDM_ERROR_CODE_REQUEST_RESYNCH.
 **/
static void rsp_encapsulated_request_case4(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    spdm_error_response_t *spdm_response_requester;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t m_local_certificate_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    m_case_id = spdm_test_context->case_id;

    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NEED_RESYNC;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] = m_local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        sizeof(m_local_certificate_chain);
    libspdm_set_mem(m_local_certificate_chain, sizeof(m_local_certificate_chain), (uint8_t)(0xFF));
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_request(spdm_context,
                                                       m_libspdm_encapsulated_request_t1_size,
                                                       &m_libspdm_encapsulated_request_t1,
                                                       &response_size,
                                                       response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response_requester = (void *)response;
    assert_int_equal(spdm_response_requester->header.spdm_version, SPDM_MESSAGE_VERSION_11);
    assert_int_equal(spdm_response_requester->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response_requester->header.param1, SPDM_ERROR_CODE_REQUEST_RESYNCH);
    assert_int_equal(spdm_response_requester->header.param2, 0);
}
#endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT) */

#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_SEND_CHALLENGE_SUPPORT)
/**
 * Test 5 (GET_ENCAPSULATED_REQUEST)
 * Expected behavior: Responder generates encapsulated CHALLENGE request.
 **/
static void rsp_encapsulated_request_case5(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    spdm_encapsulated_request_response_t *spdm_response_requester;
    spdm_challenge_request_t *challenge_request;
    libspdm_context_t *spdm_context;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;
    void *data;
    size_t data_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    m_case_id = spdm_test_context->case_id;

    set_standard_state(spdm_context);

    spdm_context->encap_context.request_id = 0;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH;

    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data,
                                                         &data_size,
                                                         NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_b(spdm_context);

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_request(spdm_context,
                                                       m_libspdm_encapsulated_request_t1_size,
                                                       &m_libspdm_encapsulated_request_t1,
                                                       &response_size,
                                                       response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_encapsulated_request_response_t) +
                     sizeof(spdm_challenge_request_t));

    spdm_response_requester = (void *)response;
    assert_int_equal(spdm_response_requester->header.spdm_version, SPDM_MESSAGE_VERSION_11);
    assert_int_equal(spdm_response_requester->header.request_response_code,
                     SPDM_ENCAPSULATED_REQUEST);
    /* The first encapsulated request of a flow uses Request ID 0. */
    assert_int_equal(spdm_response_requester->header.param1, 0x0);
    assert_int_equal(spdm_response_requester->header.param2, 0);

    challenge_request = (spdm_challenge_request_t *)(spdm_response_requester + 1);
    assert_int_equal(challenge_request->header.spdm_version, SPDM_MESSAGE_VERSION_11);
    assert_int_equal(challenge_request->header.request_response_code, SPDM_CHALLENGE);
    assert_int_equal(challenge_request->header.param1, 4);
    assert_int_equal(challenge_request->header.param2, 0);
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_SEND_CHALLENGE_SUPPORT) */

/**
 * Test 6 (GET_ENCAPSULATED_REQUEST) inside a session.
 * Expected behavior: Responder generates encapsulated KEY_UPDATE request with UpdateKey set.
 **/
static void rsp_encapsulated_request_case6(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    spdm_encapsulated_request_response_t *spdm_response_requester;
    spdm_key_update_request_t *update_request;
    libspdm_context_t *spdm_context;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t data_size;
    void *data;
    size_t response_size;
    uint32_t session_id;
    libspdm_session_info_t *session_info;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    m_case_id = spdm_test_context->case_id;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data,
                                                         &data_size,
                                                         NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_b(spdm_context);

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, true);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);
    libspdm_register_encap_flow_handler(spdm_context, encap_flow_handler);
    session_info->encap_context.request_id = 0;
    session_info->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_request(spdm_context,
                                                       m_libspdm_encapsulated_request_t1_size,
                                                       &m_libspdm_encapsulated_request_t1,
                                                       &response_size,
                                                       response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_encapsulated_request_response_t) +
                     sizeof(spdm_key_update_response_t));
    spdm_response_requester = (void *)response;
    assert_int_equal(spdm_response_requester->header.spdm_version, SPDM_MESSAGE_VERSION_11);
    assert_int_equal(spdm_response_requester->header.request_response_code,
                     SPDM_ENCAPSULATED_REQUEST);
    /* The first encapsulated request of a flow uses Request ID 0. */
    assert_int_equal(spdm_response_requester->header.param1, 0x0);
    assert_int_equal(spdm_response_requester->header.param2, 0);

    update_request = (spdm_key_update_request_t *)(spdm_response_requester + 1);
    assert_int_equal(update_request->header.spdm_version, SPDM_MESSAGE_VERSION_11);
    assert_int_equal(update_request->header.request_response_code, SPDM_KEY_UPDATE);
    assert_int_equal(update_request->header.param1, SPDM_KEY_UPDATE_OPERATIONS_UPDATE_KEY);
    /* Param2 (tag) is not check as it is a random number. */

    free(data);
}

/**
 * Test 7 (GET_ENCAPSULATED_REQUEST) response_state is normal and Responder does not need the
 *        encapsulated flow.
 * Expected behavior: Responder generates SPDM_ERROR_CODE_NO_PENDING_REQUESTS.
 **/
static void rsp_encapsulated_request_case7(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    spdm_error_response_t *spdm_response_requester;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t m_local_certificate_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    m_case_id = spdm_test_context->case_id;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;

    spdm_context->encap_context.request_id = 0;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;
    spdm_context->last_spdm_request_session_id_valid = false;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] = m_local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        sizeof(m_local_certificate_chain);
    libspdm_set_mem(m_local_certificate_chain, sizeof(m_local_certificate_chain), 0xFF);

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_request(spdm_context,
                                                       m_libspdm_encapsulated_request_t2_size,
                                                       &m_libspdm_encapsulated_request_t2,
                                                       &response_size,
                                                       response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response_requester = (void *)response;
    assert_int_equal(spdm_response_requester->header.spdm_version, SPDM_MESSAGE_VERSION_13);
    assert_int_equal(spdm_response_requester->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response_requester->header.param1, SPDM_ERROR_CODE_NO_PENDING_REQUESTS);
    assert_int_equal(spdm_response_requester->header.param2, 0);
    /* No flow is in progress after the Responder declines, so a later request must not be
     * rejected as though one were. */
    assert_int_equal(spdm_context->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);
}

#if LIBSPDM_SEND_GET_ENDPOINT_INFO_SUPPORT
static libspdm_return_t get_endpoint_info_callback_encap_response (
    void *spdm_context,
    uint8_t subcode,
    uint8_t param2,
    uint8_t request_attributes,
    uint32_t endpoint_info_size,
    const void *endpoint_info)
{
    /* should never reach here */
    LIBSPDM_ASSERT (0);
    return LIBSPDM_STATUS_UNSUPPORTED_CAP;
}

/**
 * Test 8 (GET_ENCAPSULATED_REQUEST) within a session.
 * Expected behavior: Responder generates GET_ENDPOINT_INFO.
 **/
static void rsp_encapsulated_request_case8(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    spdm_encapsulated_request_response_t *spdm_response_requester;
    libspdm_context_t *spdm_context;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t data_size;
    void *data;
    size_t response_size;
    uint32_t session_id;
    libspdm_session_info_t *session_info;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;
    m_case_id = spdm_test_context->case_id;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    libspdm_register_encap_flow_handler(spdm_context, encap_flow_handler);

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_req_asym_algo, &data,
                                                         &data_size,
                                                         NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->connection_info.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->get_endpoint_info_callback = get_endpoint_info_callback_encap_response;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size = data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, true);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);

    session_info->encap_context.request_id = 0;
    session_info->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;

    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_encap_e(spdm_context, session_info);

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_request(spdm_context,
                                                       m_libspdm_encapsulated_request_t2_size,
                                                       &m_libspdm_encapsulated_request_t2,
                                                       &response_size,
                                                       response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    assert_int_equal(response_size,
                     sizeof(spdm_encapsulated_request_response_t) +
                     sizeof(spdm_get_endpoint_info_request_t) +
                     SPDM_NONCE_SIZE);
    spdm_response_requester = (void *)response;
    assert_int_equal(spdm_response_requester->header.request_response_code,
                     SPDM_ENCAPSULATED_REQUEST);
    /* The first encapsulated request of a flow uses Request ID 0. */
    assert_int_equal(spdm_response_requester->header.param1, 0x0);
    assert_int_equal(spdm_response_requester->header.param2, 0);
    free(data);
}

/**
 * Test 9 (GET_ENCAPSULATED_REQUEST) where the Integrator returns a request that is not legal in
 * the basic mutual authentication flow.
 * Expected behavior: Responder returns ERROR(Unspecified) and terminates the encapsulated flow.
 **/
static void rsp_encapsulated_request_case9(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    spdm_error_response_t *spdm_response;
    libspdm_context_t *spdm_context;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8B;
    m_case_id = spdm_test_context->case_id;

    set_standard_state(spdm_context);

    spdm_context->encap_context.request_id = 0;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_reset_message_b(spdm_context);

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_request(spdm_context,
                                                       m_libspdm_encapsulated_request_t2_size,
                                                       &m_libspdm_encapsulated_request_t2,
                                                       &response_size,
                                                       response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;

    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSPECIFIED);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);
    assert_int_equal(spdm_context->response_state, LIBSPDM_RESPONSE_STATE_NORMAL);
}
#endif /* LIBSPDM_SEND_GET_ENDPOINT_INFO_SUPPORT */

/**
 * Test 10 (GET_ENCAPSULATED_REQUEST) where the Integrator's handler returns an error.
 * Expected behavior: Responder returns ERROR(Unspecified) and terminates the encapsulated flow.
 **/
static void rsp_encapsulated_request_case10(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    spdm_error_response_t *spdm_response;
    libspdm_context_t *spdm_context;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8C;
    m_case_id = spdm_test_context->case_id;

    set_standard_state(spdm_context);

    spdm_context->encap_context.request_id = 0;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    libspdm_reset_message_b(spdm_context);

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_request(spdm_context,
                                                       m_libspdm_encapsulated_request_t1_size,
                                                       &m_libspdm_encapsulated_request_t1,
                                                       &response_size,
                                                       response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;

    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSPECIFIED);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);
    assert_int_equal(spdm_context->response_state, LIBSPDM_RESPONSE_STATE_NORMAL);
}

#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
/**
 * Test 11 (GET_ENCAPSULATED_REQUEST) where the Integrator builds a request with a session_id that
 * does not refer to an existing session.
 * Expected behavior: Responder returns ERROR(Unspecified) and terminates the encapsulated flow.
 **/
static void rsp_encapsulated_request_case11(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    spdm_error_response_t *spdm_response;
    libspdm_context_t *spdm_context;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8D;
    m_case_id = spdm_test_context->case_id;

    set_standard_state(spdm_context);

    spdm_context->encap_context.request_id = 0;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    libspdm_reset_message_b(spdm_context);

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_request(spdm_context,
                                                       m_libspdm_encapsulated_request_t1_size,
                                                       &m_libspdm_encapsulated_request_t1,
                                                       &response_size,
                                                       response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;

    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSPECIFIED);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);
    assert_int_equal(spdm_context->response_state, LIBSPDM_RESPONSE_STATE_NORMAL);
}

#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */

/**
 * Test 12 (GET_ENCAPSULATED_REQUEST) where the Integrator requests an encapsulated KEY_UPDATE with
 * the UpdateAllKeys operation.
 * Expected behavior: Responder returns ERROR(Unspecified) and terminates the encapsulated flow.
 **/
static void rsp_encapsulated_request_case12(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    spdm_error_response_t *spdm_response;
    libspdm_context_t *spdm_context;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;
    uint32_t session_id;
    libspdm_session_info_t *session_info;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8E;
    m_case_id = spdm_test_context->case_id;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, true);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);
    libspdm_register_encap_flow_handler(spdm_context, encap_flow_handler);
    session_info->encap_context.request_id = 0;
    session_info->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_request(spdm_context,
                                                       m_libspdm_encapsulated_request_t1_size,
                                                       &m_libspdm_encapsulated_request_t1,
                                                       &response_size,
                                                       response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;

    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSPECIFIED);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(session_info->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);
    assert_int_equal(spdm_context->response_state, LIBSPDM_RESPONSE_STATE_NORMAL);
}

#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
static void rsp_encapsulated_response_ack_case1(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_deliver_encapsulated_response_request_t *spdm_response_requester;
    spdm_digest_response_t *spdm_response_requester_digest;
    uint8_t temp_buf[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t spdm_response_requester_size;
    size_t spdm_response_requester_digest_size;
    size_t data_size;
    size_t response_size;
    uint8_t *digest;
    void *data;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x81;
    m_case_id = spdm_test_context->case_id;

    set_standard_state(spdm_context);

    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH;
    spdm_context->encap_context.last_encap_request_header.request_response_code = SPDM_GET_DIGESTS;
    spdm_context->encap_context.request_id = 0;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data,
                                                         &data_size,
                                                         NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    libspdm_reset_message_b(spdm_context);

    spdm_response_requester_size = sizeof(spdm_digest_response_t) +
                                   libspdm_get_hash_size(m_libspdm_use_hash_algo) +
                                   sizeof(spdm_deliver_encapsulated_response_request_t);

    spdm_response_requester = (void *)temp_buf;
    libspdm_copy_mem(spdm_response_requester,
                     sizeof(temp_buf),
                     &m_libspdm_m_deliver_encapsulated_response_request_t1,
                     m_libspdm_m_deliver_encapsulated_response_request_t1_size);

    spdm_response_requester_digest_size = sizeof(spdm_digest_response_t) +
                                          libspdm_get_hash_size(m_libspdm_use_hash_algo);
    spdm_response_requester_digest =
        (void *)(temp_buf + sizeof(spdm_deliver_encapsulated_response_request_t));
    spdm_response_requester_digest->header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_response_requester_digest->header.request_response_code = SPDM_DIGESTS;
    spdm_response_requester_digest->header.param1 = 0;
    spdm_response_requester_digest->header.param2 = 0;

    digest = (void *)(spdm_response_requester_digest + 1);
    libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_certificate_chain,
                     sizeof(m_libspdm_local_certificate_chain), &digest[0]);
    spdm_response_requester_digest->header.param2 |= (0x01 << 0);

    libspdm_set_mem(m_libspdm_local_certificate_chain,
                    sizeof(m_libspdm_local_certificate_chain),
                    (uint8_t)(0xFF));

    libspdm_copy_mem(spdm_response_requester + 1,
                     spdm_response_requester_digest_size,
                     spdm_response_requester_digest,
                     spdm_response_requester_digest_size);

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_response_ack(spdm_context,
                                                            spdm_response_requester_size,
                                                            spdm_response_requester, &response_size,
                                                            response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    free(data);
}

static void rsp_encapsulated_response_ack_case2(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_deliver_encapsulated_response_request_t *spdm_response_requester;
    spdm_certificate_response_t *spdm_response_requester_certificate;
    uint8_t temp_buf[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t spdm_response_requester_size;
    size_t data_size;
    size_t response_size;
    void *data;
    uint16_t portion_length;
    uint16_t remainder_length;
    static size_t calling_index = 0;

    static void *libspdm_local_certificate_chain;
    static size_t libspdm_local_certificate_chain_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x82;
    m_case_id = spdm_test_context->case_id;

    set_standard_state(spdm_context);

    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH;
    spdm_context->encap_context.last_encap_request_header.request_response_code =
        SPDM_GET_CERTIFICATE;
    spdm_context->encap_context.request_id = 0;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->encap_context.cert_chain_buffer = m_libspdm_local_certificate_chain;
    spdm_context->encap_context.cert_chain_buffer_size = 0;
    spdm_context->encap_context.cert_chain_buffer_max_size =
        sizeof(m_libspdm_local_certificate_chain);
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data,
                                                         &data_size,
                                                         NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    libspdm_reset_message_b(spdm_context);

    spdm_response_requester = (void *)temp_buf;
    libspdm_copy_mem(spdm_response_requester,
                     sizeof(temp_buf),
                     &m_libspdm_m_deliver_encapsulated_response_request_t1,
                     m_libspdm_m_deliver_encapsulated_response_request_t1_size);

    spdm_response_requester_certificate =
        (void *)(temp_buf + sizeof(spdm_deliver_encapsulated_response_request_t));

    if (!libspdm_read_responder_public_certificate_chain(
            m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
            &libspdm_local_certificate_chain,
            &libspdm_local_certificate_chain_size, NULL, NULL)) {
        return;
    }

    portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
    remainder_length = (uint16_t)(libspdm_local_certificate_chain_size -
                                  (LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (calling_index + 1)));

    spdm_response_requester_certificate->header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_response_requester_certificate->header.request_response_code = SPDM_CERTIFICATE;
    spdm_response_requester_certificate->header.param1 = 0;
    spdm_response_requester_certificate->header.param2 = 0;
    spdm_response_requester_certificate->portion_length = portion_length;
    spdm_response_requester_certificate->remainder_length = remainder_length;

    libspdm_copy_mem(spdm_response_requester_certificate + 1,
                     sizeof(temp_buf) - sizeof(*spdm_response_requester_certificate),
                     (uint8_t *)libspdm_local_certificate_chain +
                     LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                     portion_length);

    free(libspdm_local_certificate_chain);

    response_size = sizeof(response);
    spdm_response_requester_size = sizeof(spdm_certificate_response_t) + portion_length +
                                   sizeof(spdm_deliver_encapsulated_response_request_t);
    status = libspdm_get_response_encapsulated_response_ack(spdm_context,
                                                            spdm_response_requester_size,
                                                            spdm_response_requester, &response_size,
                                                            response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    free(data);
}
#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */

static void rsp_encapsulated_response_ack_case3(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_deliver_encapsulated_response_request_t *spdm_response_requester;
    spdm_key_update_response_t *spdm_response_requester_key_update;
    uint8_t temp_buf[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t spdm_response_requester_size;
    size_t data_size;
    size_t response_size;
    void *data;
    uint32_t session_id;
    libspdm_session_info_t *session_info;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x83;
    m_case_id = spdm_test_context->case_id;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;

    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data,
                                                         &data_size,
                                                         NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_chain_provision[0] = data;

    libspdm_reset_message_b(spdm_context);
    libspdm_register_encap_flow_handler(spdm_context, encap_flow_handler);

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, true);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);

    session_info->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;
    session_info->encap_context.request_id = 0;

    session_info->encap_context.last_encap_request_header.spdm_version = SPDM_MESSAGE_VERSION_11;
    session_info->encap_context.last_encap_request_header.request_response_code = SPDM_KEY_UPDATE;
    session_info->encap_context.last_encap_request_header.param1 =
        SPDM_KEY_UPDATE_OPERATIONS_VERIFY_NEW_KEY;
    session_info->encap_context.last_encap_request_header.param2 = 0;

    spdm_response_requester = (void *)temp_buf;
    libspdm_copy_mem(spdm_response_requester,
                     sizeof(temp_buf),
                     &m_libspdm_m_deliver_encapsulated_response_request_t1,
                     m_libspdm_m_deliver_encapsulated_response_request_t1_size);

    spdm_response_requester_key_update =
        (void *)(temp_buf + sizeof(spdm_deliver_encapsulated_response_request_t));

    spdm_response_requester_key_update->header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_response_requester_key_update->header.request_response_code = SPDM_KEY_UPDATE_ACK;
    spdm_response_requester_key_update->header.param1 = SPDM_KEY_UPDATE_OPERATIONS_VERIFY_NEW_KEY;
    spdm_response_requester_key_update->header.param2 = 0;

    response_size = sizeof(response);
    spdm_response_requester_size = sizeof(spdm_key_update_response_t) +
                                   sizeof(spdm_deliver_encapsulated_response_request_t);
    status = libspdm_get_response_encapsulated_response_ack(spdm_context,
                                                            spdm_response_requester_size,
                                                            spdm_response_requester, &response_size,
                                                            response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    free(data);
}

static void rsp_encapsulated_response_ack_case4(void **State)
{
    libspdm_return_t status;
    spdm_encapsulated_request_response_t *spdm_response_requester;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_test_context->case_id = 0x84;
    m_case_id = spdm_test_context->case_id;

    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    /* This flow occurs outside of a session, so the connection-wide encapsulated context is
     * used. */
    spdm_context->last_spdm_request_session_id_valid = false;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    libspdm_reset_message_b(spdm_context);

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_response_ack(spdm_context,
                                                            m_libspdm_m_deliver_encapsulated_response_request_t1_size,
                                                            &m_libspdm_m_deliver_encapsulated_response_request_t1,
                                                            &response_size,
                                                            response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response_requester = (void *)response;
    assert_int_equal(spdm_response_requester->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response_requester->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response_requester->header.param2, 0);
}

static void rsp_encapsulated_response_ack_case5(void **State)
{
    libspdm_return_t status;
    spdm_encapsulated_request_response_t *spdm_response_requester;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;
    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    spdm_test_context->case_id = 0x85;
    m_case_id = spdm_test_context->case_id;

    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    /* No encapsulated flow is in progress on this channel. */
    spdm_context->last_spdm_request_session_id_valid = false;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_NONE;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_response_ack(spdm_context,
                                                            m_libspdm_m_deliver_encapsulated_response_request_t1_size,
                                                            &m_libspdm_m_deliver_encapsulated_response_request_t1,
                                                            &response_size,
                                                            response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response_requester = (void *)response;
    assert_int_equal(spdm_response_requester->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response_requester->header.param1, SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
    assert_int_equal(spdm_response_requester->header.param2, 0);
}

static void rsp_encapsulated_response_ack_case6(void **State)
{
    libspdm_return_t status;
    spdm_encapsulated_request_response_t *spdm_response_requester;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;
    size_t data_size;
    void *data;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x86;
    m_case_id = spdm_test_context->case_id;

    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NEED_RESYNC;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;

    status = libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                             m_libspdm_use_asym_algo, &data,
                                                             &data_size,
                                                             NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_response_ack(spdm_context,
                                                            m_libspdm_m_deliver_encapsulated_response_request_t1_size,
                                                            &m_libspdm_m_deliver_encapsulated_response_request_t1,
                                                            &response_size,
                                                            response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response_requester = (void *)response;
    assert_int_equal(spdm_response_requester->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response_requester->header.param1, SPDM_ERROR_CODE_REQUEST_RESYNCH);
    assert_int_equal(spdm_response_requester->header.param2, 0);
}

#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT)
static void rsp_encapsulated_response_ack_case7(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_deliver_encapsulated_response_request_t *spdm_response_requester;
    spdm_certificate_response_t *spdm_response_requester_certificate;
    uint8_t temp_buf[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t spdm_response_requester_size;
    size_t data_size;
    size_t response_size;
    void *data;
    uint16_t portion_length;
    uint16_t remainder_length;
    static size_t calling_index = 0;

    static void *libspdm_local_certificate_chain;
    static size_t libspdm_local_certificate_chain_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x87;
    m_case_id = spdm_test_context->case_id;

    /* This flow occurs outside of a session, so the connection-wide encapsulated
     * context is used. */
    spdm_context->last_spdm_request_session_id_valid = false;
    spdm_context->encap_context.request_id = 0xFF;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data,
                                                         &data_size,
                                                         NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_b(spdm_context);

    spdm_response_requester = (void *)temp_buf;
    libspdm_copy_mem(spdm_response_requester,
                     sizeof(temp_buf),
                     &m_libspdm_m_deliver_encapsulated_response_request_t1,
                     m_libspdm_m_deliver_encapsulated_response_request_t1_size);

    spdm_response_requester_certificate =
        (void *)(temp_buf + sizeof(spdm_deliver_encapsulated_response_request_t));

    if (!libspdm_read_responder_public_certificate_chain(
            m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
            &libspdm_local_certificate_chain,
            &libspdm_local_certificate_chain_size, NULL, NULL)) {
        return;
    }

    portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
    remainder_length = (uint16_t)(libspdm_local_certificate_chain_size -
                                  (LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (calling_index + 1)));

    spdm_response_requester_certificate->header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_response_requester_certificate->header.request_response_code = SPDM_CERTIFICATE;
    spdm_response_requester_certificate->header.param1 = 0;
    spdm_response_requester_certificate->header.param2 = 0;
    spdm_response_requester_certificate->portion_length = portion_length;
    spdm_response_requester_certificate->remainder_length = remainder_length;

    libspdm_copy_mem(spdm_response_requester_certificate + 1,
                     sizeof(temp_buf) - sizeof(*spdm_response_requester_certificate),
                     (uint8_t *)libspdm_local_certificate_chain +
                     LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                     portion_length);

    free(libspdm_local_certificate_chain);

    response_size = sizeof(response);
    spdm_response_requester_size = sizeof(spdm_certificate_response_t) + portion_length +
                                   sizeof(spdm_deliver_encapsulated_response_request_t);
    status = libspdm_get_response_encapsulated_response_ack(spdm_context,
                                                            spdm_response_requester_size,
                                                            spdm_response_requester, &response_size,
                                                            response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response_requester = (void *)response;
    assert_int_equal(spdm_response_requester->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response_requester->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response_requester->header.param2, 0);
    free(data);
}

static void rsp_encapsulated_response_ack_case8(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_encapsulated_response_ack_response_t *spdm_response;
    spdm_deliver_encapsulated_response_request_t *spdm_response_requester;
    spdm_digest_response_t *spdm_response_requester_digest;
    uint8_t temp_buf[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t spdm_response_requester_size;
    size_t spdm_response_requester_digest_size;
    size_t data_size;
    size_t response_size;
    uint8_t *digest;
    void *data;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x88;
    m_case_id = spdm_test_context->case_id;

    /* This flow occurs outside of a session, so the connection-wide encapsulated
     * context is used. */
    spdm_context->last_spdm_request_session_id_valid = false;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->encap_context.request_id = 0xFF;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;

    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH;
    spdm_context->encap_context.last_encap_request_header.request_response_code = SPDM_GET_DIGESTS;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data,
                                                         &data_size,
                                                         NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_b(spdm_context);
    libspdm_register_encap_flow_handler(spdm_context, encap_flow_handler);

    spdm_response_requester_size = sizeof(spdm_digest_response_t) +
                                   libspdm_get_hash_size(m_libspdm_use_hash_algo) +
                                   sizeof(spdm_deliver_encapsulated_response_request_t);

    spdm_response_requester = (void *)temp_buf;
    libspdm_copy_mem(spdm_response_requester,
                     sizeof(temp_buf),
                     &m_libspdm_m_deliver_encapsulated_response_request_t2,
                     m_libspdm_m_deliver_encapsulated_response_request_t2_size);

    spdm_response_requester_digest_size = sizeof(spdm_digest_response_t) +
                                          libspdm_get_hash_size(m_libspdm_use_hash_algo);
    spdm_response_requester_digest =
        (void *)(temp_buf + sizeof(spdm_deliver_encapsulated_response_request_t));
    spdm_response_requester_digest->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_response_requester_digest->header.param1 = 0;
    spdm_response_requester_digest->header.request_response_code = SPDM_DIGESTS;
    spdm_response_requester_digest->header.param2 = 0;

    digest = (void *)(spdm_response_requester_digest + 1);
    libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_certificate_chain,
                     sizeof(m_libspdm_local_certificate_chain), &digest[0]);
    spdm_response_requester_digest->header.param2 |= (0x01 << 0);

    libspdm_set_mem(m_libspdm_local_certificate_chain,
                    sizeof(m_libspdm_local_certificate_chain),
                    (uint8_t)(0xFF));

    libspdm_copy_mem(spdm_response_requester + 1,
                     spdm_response_requester_digest_size,
                     spdm_response_requester_digest,
                     spdm_response_requester_digest_size);

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_response_ack(spdm_context,
                                                            spdm_response_requester_size,
                                                            spdm_response_requester, &response_size,
                                                            response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_encapsulated_response_ack_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ENCAPSULATED_RESPONSE_ACK);
    assert_int_equal(spdm_response->header.param1, 0);
    assert_int_equal(spdm_response->header.param2,
                     SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_ABSENT);
    assert_int_equal(spdm_response->ack_request_id,
                     m_libspdm_m_deliver_encapsulated_response_request_t2.header.param1);
    free(data);
}
#endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT) */

#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
/**
 * Test 9: In an encapsulated request flow, a Responder issue an encapsulated request that can take up to CT time to
 * fulfill, then the Requester deliver an encapsulated ERROR message with a ResponseNotReady error code.
 * Expected behavior: the Responder shall not encapsulate another request by setting Param2 in ENCAPSULATED_RESPONSE_ACK
 * to a value of zero.
 **/
static void rsp_encapsulated_response_ack_case9(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_encapsulated_response_ack_response_t *spdm_response;
    spdm_deliver_encapsulated_response_request_t *spdm_request;
    spdm_error_response_data_response_not_ready_t *EncapsulatedResponse;
    uint8_t temp_buf[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t spdm_request_size;
    size_t EncapsulatedResponse_size;
    size_t response_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x89;
    m_case_id = spdm_test_context->case_id;

    /* This flow occurs outside of a session, so the connection-wide encapsulated
     * context is used. */
    spdm_context->last_spdm_request_session_id_valid = false;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->encap_context.request_id = 0xFF;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;

    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH;
    spdm_context->encap_context.last_encap_request_header.request_response_code = SPDM_GET_DIGESTS;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_reset_message_b(spdm_context);
    libspdm_register_encap_flow_handler(spdm_context, encap_flow_handler);

    spdm_request_size = sizeof(spdm_deliver_encapsulated_response_request_t) +
                        sizeof(spdm_error_response_data_response_not_ready_t);

    spdm_request = (void *)temp_buf;
    libspdm_copy_mem(spdm_request,
                     sizeof(temp_buf),
                     &m_libspdm_m_deliver_encapsulated_response_request_t2,
                     m_libspdm_m_deliver_encapsulated_response_request_t2_size);

    EncapsulatedResponse_size = sizeof(spdm_error_response_data_response_not_ready_t);
    EncapsulatedResponse =
        (void *)(temp_buf + sizeof(spdm_deliver_encapsulated_response_request_t));
    EncapsulatedResponse->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    EncapsulatedResponse->header.request_response_code = SPDM_ERROR;
    EncapsulatedResponse->header.param1 = SPDM_ERROR_CODE_RESPONSE_NOT_READY;
    EncapsulatedResponse->header.param2 = 0;
    EncapsulatedResponse->extend_error_data.rd_exponent = 1;
    EncapsulatedResponse->extend_error_data.rd_tm = 1;
    EncapsulatedResponse->extend_error_data.request_code = SPDM_GET_DIGESTS;
    EncapsulatedResponse->extend_error_data.token = 0;

    libspdm_copy_mem(spdm_request + 1,
                     EncapsulatedResponse_size,
                     EncapsulatedResponse,
                     EncapsulatedResponse_size);

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_response_ack(spdm_context,
                                                            spdm_request_size,
                                                            spdm_request, &response_size,
                                                            response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_encapsulated_response_ack_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ENCAPSULATED_RESPONSE_ACK);
    assert_int_equal(spdm_response->header.param1, 0);
    assert_int_equal(spdm_response->header.param2,
                     SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_ABSENT);
    assert_int_equal(spdm_context->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);
#if LIBSPDM_RESPOND_IF_READY_SUPPORT
    /* The flow is terminated, but the outstanding request and the fields needed to reissue it
     * with RESPOND_IF_READY are retained. */
    assert_true(spdm_context->encap_context.response_not_ready);
    assert_int_equal(spdm_context->encap_context.response_not_ready_flow_type,
                     LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH);
    assert_int_equal(spdm_context->encap_context.response_not_ready_data.request_code,
                     SPDM_GET_DIGESTS);
    assert_int_equal(spdm_context->encap_context.response_not_ready_data.rd_exponent, 1);
    assert_int_equal(spdm_context->encap_context.response_not_ready_data.rd_tm, 1);
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */

    assert_int_equal(spdm_response->ack_request_id,
                     m_libspdm_m_deliver_encapsulated_response_request_t2.header.param1);
}

/**
 * Test 17: the Requester delivers an encapsulated ERROR whose ErrorCode is not ResponseNotReady.
 * Expected behavior: the handler is called with error_code set to that ErrorCode, and libspdm then
 * terminates the encapsulated flow by clearing ENCAPSULATED_RESPONSE_ACK.Param2. No
 * RESPOND_IF_READY state is retained, since there is no outstanding request to reissue.
 **/
static void rsp_encapsulated_response_ack_case17(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_encapsulated_response_ack_response_t *spdm_response;
    spdm_deliver_encapsulated_response_request_t *spdm_request;
    spdm_error_response_t *encap_error;
    uint8_t temp_buf[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t spdm_request_size;
    size_t response_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x94;
    m_case_id = spdm_test_context->case_id;

    /* This flow occurs outside of a session, so the connection-wide encapsulated context is
     * used. */
    spdm_context->last_spdm_request_session_id_valid = false;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->encap_context.request_id = 0xFF;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;

    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH;
    spdm_context->encap_context.last_encap_request_header.request_response_code = SPDM_GET_DIGESTS;
#if LIBSPDM_RESPOND_IF_READY_SUPPORT
    /* An earlier test in this group leaves this set, and the context is shared. */
    spdm_context->encap_context.response_not_ready = false;
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_reset_message_b(spdm_context);
    libspdm_register_encap_flow_handler(spdm_context, encap_flow_handler);

    spdm_request_size = sizeof(spdm_deliver_encapsulated_response_request_t) +
                        sizeof(spdm_error_response_t);

    spdm_request = (void *)temp_buf;
    libspdm_copy_mem(spdm_request, sizeof(temp_buf),
                     &m_libspdm_m_deliver_encapsulated_response_request_t2,
                     m_libspdm_m_deliver_encapsulated_response_request_t2_size);

    encap_error = (void *)(temp_buf + sizeof(spdm_deliver_encapsulated_response_request_t));
    encap_error->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    encap_error->header.request_response_code = SPDM_ERROR;
    encap_error->header.param1 = SPDM_ERROR_CODE_UNSUPPORTED_REQUEST;
    encap_error->header.param2 = 0;

    m_observed_error_code = 0;

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_response_ack(spdm_context,
                                                            spdm_request_size,
                                                            spdm_request, &response_size,
                                                            response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    /* The handler was reached and told which ErrorCode the Requester returned. */
    assert_int_equal(m_observed_error_code, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);

    /* The flow is terminated in the ACK rather than rejected with a top-level ERROR. */
    assert_int_equal(response_size, sizeof(spdm_encapsulated_response_ack_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ENCAPSULATED_RESPONSE_ACK);
    assert_int_equal(spdm_response->header.param1, 0);
    assert_int_equal(spdm_response->header.param2,
                     SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_ABSENT);
    assert_int_equal(spdm_context->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);
#if LIBSPDM_RESPOND_IF_READY_SUPPORT
    /* Only ResponseNotReady leaves a request outstanding. */
    assert_false(spdm_context->encap_context.response_not_ready);
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */

    assert_int_equal(spdm_response->ack_request_id,
                     m_libspdm_m_deliver_encapsulated_response_request_t2.header.param1);
}

#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */

#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_SEND_CHALLENGE_SUPPORT)
/**
 * Test 10: In the basic mutual authentication flow, the Requester delivers the encapsulated
 * CHALLENGE_AUTH response. The Responder must then terminate the encapsulated flow.
 * Expected behavior: ENCAPSULATED_RESPONSE_ACK.Param2 is cleared, the flow is torn down, and the
 * Integrator's handler is not consulted. m_case_id is deliberately a value the handler does not
 * recognize, so consulting it trips the handler's default assert.
 **/
static void rsp_encapsulated_response_ack_case10(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_encapsulated_response_ack_response_t *spdm_response;
    spdm_deliver_encapsulated_response_request_t *deliver;
    spdm_challenge_auth_response_t *challenge_auth;
    uint8_t temp_buf[LIBSPDM_SENDER_BUFFER_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t *ptr;
    size_t sig_size;
    size_t challenge_auth_size;
    size_t deliver_size;
    size_t response_size;
    void *data;
    size_t data_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8A;
    /* Not a case the handler knows about; it must not be reached. */
    m_case_id = spdm_test_context->case_id;

    /* Basic mutual authentication occurs outside of a session. */
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->last_spdm_request_session_id_valid = false;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH;
    spdm_context->encap_context.request_id = 0xFF;
    spdm_context->encap_context.req_slot_id = 0;
    spdm_context->encap_context.last_encap_request_header.request_response_code = SPDM_CHALLENGE;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;

    if (!libspdm_read_requester_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_req_asym_algo, &data,
                                                         &data_size, NULL, NULL)) {
        return;
    }

    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_mut_b(spdm_context);
    libspdm_reset_message_mut_c(spdm_context);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size = data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.req_base_asym_alg,
        data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif

    libspdm_register_encap_flow_handler(spdm_context, encap_flow_handler);

    /* DELIVER_ENCAPSULATED_RESPONSE carrying the encapsulated CHALLENGE_AUTH. */
    deliver = (void *)temp_buf;
    deliver->header.spdm_version = SPDM_MESSAGE_VERSION_11;
    deliver->header.request_response_code = SPDM_DELIVER_ENCAPSULATED_RESPONSE;
    deliver->header.param1 = spdm_context->encap_context.request_id;
    deliver->header.param2 = 0;

    challenge_auth = (void *)(temp_buf + sizeof(spdm_deliver_encapsulated_response_request_t));
    sig_size = libspdm_get_asym_signature_size(m_libspdm_use_req_asym_algo);
    challenge_auth_size = sizeof(spdm_challenge_auth_response_t) +
                          libspdm_get_hash_size(m_libspdm_use_hash_algo) +
                          SPDM_NONCE_SIZE + 0 + sizeof(uint16_t) + 0 + sig_size;
    challenge_auth->header.spdm_version = SPDM_MESSAGE_VERSION_11;
    challenge_auth->header.request_response_code = SPDM_CHALLENGE_AUTH;
    challenge_auth->header.param1 = 0;
    challenge_auth->header.param2 = (1 << 0);

    ptr = (void *)(challenge_auth + 1);
    libspdm_hash_all(m_libspdm_use_hash_algo, data, data_size, ptr);
    ptr += libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
    ptr += SPDM_NONCE_SIZE;
    libspdm_write_uint16(ptr, 0);
    ptr += sizeof(uint16_t);
    libspdm_requester_data_sign(
        spdm_context,
        challenge_auth->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
            0, SPDM_CHALLENGE_AUTH,
            m_libspdm_use_req_asym_algo, m_libspdm_use_req_pqc_asym_algo, m_libspdm_use_hash_algo,
            false, (uint8_t *)challenge_auth, challenge_auth_size - sig_size,
            ptr, &sig_size);

    deliver_size = sizeof(spdm_deliver_encapsulated_response_request_t) + challenge_auth_size;

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_response_ack(spdm_context, deliver_size, temp_buf,
                                                            &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ENCAPSULATED_RESPONSE_ACK);
    /* Param2 cleared: no further encapsulated request is issued. */
    assert_int_equal(spdm_response->header.param2,
                     SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_ABSENT);
    assert_int_equal(spdm_response->header.param1, 0);
    /* The flow is torn down. */
    assert_int_equal(spdm_context->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);
    assert_int_equal(spdm_context->response_state, LIBSPDM_RESPONSE_STATE_NORMAL);

    free(data);
}
#endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_SEND_CHALLENGE_SUPPORT) */

/**
 * Test 11 (DELIVER_ENCAPSULATED_RESPONSE) delivering the KEY_UPDATE_ACK for an encapsulated
 * KEY_UPDATE with the UpdateKey operation.
 * Expected behavior: Responder issues KEY_UPDATE with the VerifyNewKey operation without
 * consulting the Integrator's handler.
 **/
static void rsp_encapsulated_response_ack_case11(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_deliver_encapsulated_response_request_t *spdm_request;
    spdm_key_update_response_t *key_update_ack;
    spdm_encapsulated_response_ack_response_t *spdm_response;
    const spdm_key_update_request_t *verify_new_key;
    uint8_t temp_buf[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t spdm_request_size;
    size_t response_size;
    uint32_t session_id;
    libspdm_session_info_t *session_info;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    /* No handler case is defined for this case_id. If libspdm consults the Integrator's handler
     * then its default branch fails the test. */
    spdm_test_context->case_id = 0x8F;
    m_case_id = spdm_test_context->case_id;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    libspdm_register_encap_flow_handler(spdm_context, encap_flow_handler);

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, true);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);

    session_info->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;
    session_info->encap_context.request_id = 0;

    /* The Responder's outstanding encapsulated request is KEY_UPDATE with UpdateKey. */
    session_info->encap_context.last_encap_request_header.spdm_version = SPDM_MESSAGE_VERSION_11;
    session_info->encap_context.last_encap_request_header.request_response_code = SPDM_KEY_UPDATE;
    session_info->encap_context.last_encap_request_header.param1 =
        SPDM_KEY_UPDATE_OPERATIONS_UPDATE_KEY;
    session_info->encap_context.last_encap_request_header.param2 = 0x5A;

    spdm_request = (void *)temp_buf;
    libspdm_copy_mem(spdm_request, sizeof(temp_buf),
                     &m_libspdm_m_deliver_encapsulated_response_request_t1,
                     m_libspdm_m_deliver_encapsulated_response_request_t1_size);

    key_update_ack = (void *)(temp_buf + sizeof(spdm_deliver_encapsulated_response_request_t));
    key_update_ack->header.spdm_version = SPDM_MESSAGE_VERSION_11;
    key_update_ack->header.request_response_code = SPDM_KEY_UPDATE_ACK;
    key_update_ack->header.param1 = SPDM_KEY_UPDATE_OPERATIONS_UPDATE_KEY;
    key_update_ack->header.param2 = 0x5A;

    spdm_request_size = sizeof(spdm_deliver_encapsulated_response_request_t) +
                        sizeof(spdm_key_update_response_t);
    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_response_ack(spdm_context, spdm_request_size,
                                                            spdm_request, &response_size,
                                                            response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    /* Connection version is 1.1, so the ACK header is a bare SPDM message header. */
    assert_int_equal(response_size,
                     sizeof(spdm_message_header_t) + sizeof(spdm_key_update_request_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ENCAPSULATED_RESPONSE_ACK);
    assert_int_equal(spdm_response->header.param2,
                     SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_PRESENT);
    /* A new encapsulated request is carried, so the Request ID advances from 0 to 1. */
    assert_int_equal(spdm_response->header.param1, 1);
    assert_int_equal(session_info->encap_context.request_id, 1);

    verify_new_key = (const void *)(response + sizeof(spdm_message_header_t));
    assert_int_equal(verify_new_key->header.request_response_code, SPDM_KEY_UPDATE);
    assert_int_equal(verify_new_key->header.param1, SPDM_KEY_UPDATE_OPERATIONS_VERIFY_NEW_KEY);

    /* The flow continues; it is not torn down. */
    assert_int_equal(session_info->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_REQ_INITIATED);
}

#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
/**
 * Test 13 (GET_ENCAPSULATED_REQUEST) in two secure sessions, with both flows open at once.
 * Expected behavior: an encapsulated flow in one session does not prevent a flow from being
 * started in another session, and each session tracks its own flow.
 **/
static void rsp_encapsulated_request_case13(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    spdm_encapsulated_request_response_t *spdm_response_requester;
    libspdm_context_t *spdm_context;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;
    uint32_t session_id_1;
    uint32_t session_id_2;
    libspdm_session_info_t *session_info_1;
    libspdm_session_info_t *session_info_2;
    size_t index;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x90;
    m_case_id = spdm_test_context->case_id;

    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    libspdm_register_encap_flow_handler(spdm_context, encap_flow_handler);

    for (index = 0; index < LIBSPDM_MAX_SESSION_COUNT; index++) {
        spdm_context->session_info[index].encap_context.flow_type = LIBSPDM_ENCAP_FLOW_NONE;
    }

    session_id_1 = 0xFFFFFFFF;
    session_info_1 = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info_1, session_id_1,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, true);
    libspdm_secured_message_set_session_state(session_info_1->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);

    session_id_2 = 0xFFFFFFFE;
    session_info_2 = &spdm_context->session_info[1];
    libspdm_session_info_init(spdm_context, session_info_2, session_id_2,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, true);
    libspdm_secured_message_set_session_state(session_info_2->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);

    /* Session1 starts an encapsulated flow. */
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = session_id_1;
    libspdm_reset_message_b(spdm_context);

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_request(spdm_context,
                                                       m_libspdm_encapsulated_request_t1_size,
                                                       &m_libspdm_encapsulated_request_t1,
                                                       &response_size,
                                                       response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response_requester = (void *)response;
    assert_int_equal(spdm_response_requester->header.request_response_code,
                     SPDM_ENCAPSULATED_REQUEST);
    assert_int_equal(session_info_1->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_REQ_INITIATED);
    /* Session2 is untouched by Session1's flow. */
    assert_int_equal(session_info_2->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);

    /* Session2 starts its own encapsulated flow while Session1's is still open. */
    spdm_context->last_spdm_request_session_id = session_id_2;
    libspdm_reset_message_b(spdm_context);

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_request(spdm_context,
                                                       m_libspdm_encapsulated_request_t1_size,
                                                       &m_libspdm_encapsulated_request_t1,
                                                       &response_size,
                                                       response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response_requester = (void *)response;
    assert_int_equal(spdm_response_requester->header.request_response_code,
                     SPDM_ENCAPSULATED_REQUEST);

    /* Both flows are open simultaneously. */
    assert_int_equal(session_info_1->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_REQ_INITIATED);
    assert_int_equal(session_info_2->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_REQ_INITIATED);
    assert_int_equal(spdm_context->response_state, LIBSPDM_RESPONSE_STATE_NORMAL);

    session_info_1->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_NONE;
    session_info_2->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_NONE;
    spdm_context->last_spdm_request_session_id_valid = false;
}
#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */

#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) && \
    (LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT)
/**
 * Test 14 (GET_ENCAPSULATED_REQUEST) for session-based mutual authentication when both endpoints
 * have set HANDSHAKE_IN_THE_CLEAR_CAP. The encapsulated messages are then sent outside of a
 * session, but the flow belongs to the session that KEY_EXCHANGE_RSP established.
 * Expected behavior: the request received outside of a session resolves to the session's
 * encapsulated context, and the handler is told which session the flow belongs to. Without
 * HANDSHAKE_IN_THE_CLEAR_CAP the same request uses the non-session context instead.
 **/
static void rsp_encapsulated_request_case14(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_encapsulated_request_response_t *spdm_response_requester;
    const spdm_message_header_t *encap_request;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;
    uint32_t session_id;
    libspdm_session_info_t *session_info;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x98;
    m_case_id = spdm_test_context->case_id;

    set_standard_state(spdm_context);
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    libspdm_reset_message_b(spdm_context);

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, true);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_HANDSHAKING);
    spdm_context->latest_session_id = session_id;

    /* The state that KEY_EXCHANGE_RSP with MutAuthRequested bit 1 leaves behind. */
    session_info->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_SESS_MUT_AUTH;
    session_info->encap_context.request_id = 0;
    session_info->encap_context.last_encap_request_size = 0;

    /* The message is sent outside of a session, as the handshake is in the clear. The non-session
     * context is cleared so that it can be shown to be untouched below. */
    spdm_context->last_spdm_request_session_id_valid = false;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_NONE;
    spdm_context->encap_context.last_encap_request_size = 0;

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_request(spdm_context,
                                                       m_libspdm_encapsulated_request_t1_size,
                                                       &m_libspdm_encapsulated_request_t1,
                                                       &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response_requester = (void *)response;
    assert_int_equal(spdm_response_requester->header.request_response_code,
                     SPDM_ENCAPSULATED_REQUEST);

    encap_request = (const void *)(spdm_response_requester + 1);
    assert_int_equal(encap_request->request_response_code, SPDM_GET_DIGESTS);

    /* The flow advanced in the session's context, not the non-session one. */
    assert_int_equal(session_info->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_SESS_MUT_AUTH);
    assert_int_not_equal(session_info->encap_context.last_encap_request_size, 0);
    assert_int_equal(spdm_context->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);
    assert_int_equal(spdm_context->encap_context.last_encap_request_size, 0);

    /* Without handshake in the clear the same message belongs to the non-session context, so a
     * pending session flow must not capture it. */
    spdm_test_context->case_id = 0x99;
    m_case_id = spdm_test_context->case_id;
    spdm_context->connection_info.capability.flags &=
        ~(uint32_t)SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags &=
        ~(uint32_t)SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_request(spdm_context,
                                                       m_libspdm_encapsulated_request_t1_size,
                                                       &m_libspdm_encapsulated_request_t1,
                                                       &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    /* The session's flow was left alone. */
    assert_int_equal(session_info->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_SESS_MUT_AUTH);

    session_info->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_NONE;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_NONE;
    spdm_context->latest_session_id = INVALID_SESSION_ID;
}
#endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (..) */

#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
/**
 * Test 12 (Request ID allocation) across a multi-request encapsulated flow.
 * Expected behavior: the first ENCAPSULATED_REQUEST uses Request ID 0. Each
 * ENCAPSULATED_RESPONSE_ACK that carries another encapsulated request increments it. The ACK that
 * terminates the flow reports 0.
 **/
static void rsp_encapsulated_response_ack_case12(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_encapsulated_request_response_t *encap_request_response;
    spdm_deliver_encapsulated_response_request_t *deliver;
    spdm_digest_response_t *digests;
    spdm_encapsulated_response_ack_response_t *ack;
    uint8_t temp_buf[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t *digest;
    size_t deliver_size;
    size_t digests_size;
    size_t response_size;
    void *data;
    size_t data_size;
    uint8_t round;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x91;
    m_case_id = spdm_test_context->case_id;
    /* One GET_DIGESTS from GET_ENCAPSULATED_REQUEST, then two more from the ACKs. */
    m_get_digests_rounds = 3;

    set_standard_state(spdm_context);
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data,
                                                         &data_size, NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    libspdm_reset_message_b(spdm_context);

    /* GET_ENCAPSULATED_REQUEST starts the flow. The first request carries Request ID 0. */
    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_request(spdm_context,
                                                       m_libspdm_encapsulated_request_t1_size,
                                                       &m_libspdm_encapsulated_request_t1,
                                                       &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    encap_request_response = (void *)response;
    assert_int_equal(encap_request_response->header.request_response_code,
                     SPDM_ENCAPSULATED_REQUEST);
    assert_int_equal(encap_request_response->header.param1, 0);
    assert_int_equal(spdm_context->encap_context.request_id, 0);

    /* Two DELIVER_ENCAPSULATED_RESPONSE rounds, each answered with another encapsulated request.
     * The Request ID advances 0 -> 1 -> 2. */
    for (round = 1; round <= 2; round++) {
        digests_size = sizeof(spdm_digest_response_t) +
                       libspdm_get_hash_size(m_libspdm_use_hash_algo);
        deliver_size = sizeof(spdm_deliver_encapsulated_response_request_t) + digests_size;

        deliver = (void *)temp_buf;
        libspdm_copy_mem(deliver, sizeof(temp_buf),
                         &m_libspdm_m_deliver_encapsulated_response_request_t1,
                         m_libspdm_m_deliver_encapsulated_response_request_t1_size);
        /* The Requester echoes the Request ID of the request it is answering. */
        deliver->header.param1 = (uint8_t)(round - 1);

        digests = (void *)(temp_buf + sizeof(spdm_deliver_encapsulated_response_request_t));
        digests->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        digests->header.request_response_code = SPDM_DIGESTS;
        digests->header.param1 = 0;
        digests->header.param2 = (0x01 << 0);
        digest = (void *)(digests + 1);
        libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_certificate_chain,
                         sizeof(m_libspdm_local_certificate_chain), &digest[0]);

        response_size = sizeof(response);
        status = libspdm_get_response_encapsulated_response_ack(spdm_context, deliver_size,
                                                                temp_buf, &response_size,
                                                                response);
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
        ack = (void *)response;
        assert_int_equal(ack->header.request_response_code, SPDM_ENCAPSULATED_RESPONSE_ACK);
        assert_int_equal(ack->header.param2,
                         SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_PRESENT);
        assert_int_equal(ack->header.param1, round);
        assert_int_equal(spdm_context->encap_context.request_id, round);
    }

    /* The handler now terminates the flow, so the ACK carries no request and reports 0. */
    deliver = (void *)temp_buf;
    deliver->header.param1 = 2;

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_response_ack(spdm_context, deliver_size, temp_buf,
                                                            &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    ack = (void *)response;
    assert_int_equal(ack->header.request_response_code, SPDM_ENCAPSULATED_RESPONSE_ACK);
    assert_int_equal(ack->header.param2,
                     SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_ABSENT);
    assert_int_equal(ack->header.param1, 0);
    assert_int_equal(spdm_context->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);

    free(data);
}

#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */

#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
/**
 * Test 13 (DELIVER_ENCAPSULATED_RESPONSE) in the optimized encapsulated flow, where
 * KEY_EXCHANGE_RSP set MutAuthRequested bit 2 and embedded GET_DIGESTS. The Responder never sent
 * an ENCAPSULATED_REQUEST, so it never provided a Request ID.
 * Expected behavior: DELIVER_ENCAPSULATED_RESPONSE.Param1 must be 0. Any other value is rejected
 * with ERROR(InvalidRequest).
 **/
static void rsp_encapsulated_response_ack_case13(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    spdm_deliver_encapsulated_response_request_t *deliver;
    spdm_digest_response_t *digests;
    spdm_message_header_t *ack;
    uint8_t temp_buf[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t *digest;
    size_t deliver_size;
    size_t response_size;
    uint32_t session_id;
    void *data;
    size_t data_size;
    uint8_t attempt;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x92;
    m_case_id = spdm_test_context->case_id;

    set_standard_state(spdm_context);
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data,
                                                         &data_size, NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_chain_provision[0] = data;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = session_id;
    session_info = &spdm_context->session_info[0];

    /* attempt 0 delivers the legal Param1 of 0; attempt 1 delivers a value the Responder never
     * handed out. */
    for (attempt = 0; attempt <= 1; attempt++) {
        libspdm_session_info_init(spdm_context, session_info, session_id,
                                  SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, true);
        libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                                  LIBSPDM_SESSION_STATE_HANDSHAKING);
        /* This is the state init_encap_state leaves behind for bit 2. */
        session_info->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_SESS_MUT_AUTH;
        /* The slot the Responder designated when it set MutAuthRequested. */
        session_info->encap_context.mut_auth_req_slot_id = 3;
        session_info->encap_context.request_id = 0;
        session_info->encap_context.last_encap_request_header.request_response_code =
            SPDM_GET_DIGESTS;
        libspdm_reset_message_b(spdm_context);
        libspdm_reset_message_mut_b(spdm_context);

        deliver = (void *)temp_buf;
        libspdm_copy_mem(deliver, sizeof(temp_buf),
                         &m_libspdm_m_deliver_encapsulated_response_request_t1,
                         m_libspdm_m_deliver_encapsulated_response_request_t1_size);
        deliver->header.param1 = attempt;

        digests = (void *)(temp_buf + sizeof(spdm_deliver_encapsulated_response_request_t));
        digests->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        digests->header.request_response_code = SPDM_DIGESTS;
        digests->header.param1 = 0;
        digests->header.param2 = (0x01 << 0);
        digest = (void *)(digests + 1);
        libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_certificate_chain,
                         sizeof(m_libspdm_local_certificate_chain), &digest[0]);

        deliver_size = sizeof(spdm_deliver_encapsulated_response_request_t) +
                       sizeof(spdm_digest_response_t) +
                       libspdm_get_hash_size(m_libspdm_use_hash_algo);

        response_size = sizeof(response);
        status = libspdm_get_response_encapsulated_response_ack(spdm_context, deliver_size,
                                                                temp_buf, &response_size,
                                                                response);
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
        ack = (void *)response;

        if (attempt == 0) {
            /* Request ID 0 is the only legal value, so the response is accepted. */
            assert_int_equal(ack->request_response_code, SPDM_ENCAPSULATED_RESPONSE_ACK);
            /* Session-based mutual authentication must end by designating the Requester's
             * certificate slot. The connection is SPDM 1.1, so the ACK header is a bare message
             * header and the slot byte immediately follows it. */
            assert_int_equal(ack->param2,
                             SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_REQ_SLOT_NUMBER);
            assert_int_equal(ack->param1, 0);
            assert_int_equal(response_size, sizeof(spdm_message_header_t) + 1);
            assert_int_equal(*((uint8_t *)response + sizeof(spdm_message_header_t)), 3);
            assert_int_equal(session_info->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);
        } else {
            assert_int_equal(ack->request_response_code, SPDM_ERROR);
            assert_int_equal(ack->param1, SPDM_ERROR_CODE_INVALID_REQUEST);
        }
    }

    spdm_context->last_spdm_request_session_id_valid = false;
    free(data);
}

#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
/**
 * Test 14 (DELIVER_ENCAPSULATED_RESPONSE) where the Integrator designates a different certificate
 * slot than the one chosen at KEY_EXCHANGE time, via
 * libspdm_set_data(LIBSPDM_DATA_SESSION_ENCAP_REQ_SLOT_ID).
 * Expected behavior: the final ENCAPSULATED_RESPONSE_ACK conveys the designated slot. The
 * connection is SPDM 1.2, so the slot byte follows the full 8-byte ACK header.
 **/
static void rsp_encapsulated_response_ack_case14(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    spdm_deliver_encapsulated_response_request_t *deliver;
    spdm_digest_response_t *digests;
    spdm_encapsulated_response_ack_response_t *ack;
    uint8_t temp_buf[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t *digest;
    size_t deliver_size;
    size_t response_size;
    uint32_t session_id;
    void *data;
    size_t data_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x93;
    m_case_id = spdm_test_context->case_id;

    set_standard_state(spdm_context);
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data,
                                                         &data_size, NULL, NULL)) {
        return;
    }
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_chain_provision[0] = data;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, true);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_HANDSHAKING);

    session_info->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_SESS_MUT_AUTH;
    /* KEY_EXCHANGE_RSP designated slot 3; the handler overrides it with slot 5. */
    session_info->encap_context.mut_auth_req_slot_id = 3;
    session_info->encap_context.request_id = 0;
    session_info->encap_context.last_encap_request_header.request_response_code = SPDM_GET_DIGESTS;
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_mut_b(spdm_context);

    deliver = (void *)temp_buf;
    deliver->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    deliver->header.request_response_code = SPDM_DELIVER_ENCAPSULATED_RESPONSE;
    deliver->header.param1 = 0;
    deliver->header.param2 = 0;

    digests = (void *)(temp_buf + sizeof(spdm_deliver_encapsulated_response_request_t));
    digests->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    digests->header.request_response_code = SPDM_DIGESTS;
    digests->header.param1 = 0;
    digests->header.param2 = (0x01 << 0);
    digest = (void *)(digests + 1);
    libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_certificate_chain,
                     sizeof(m_libspdm_local_certificate_chain), &digest[0]);

    deliver_size = sizeof(spdm_deliver_encapsulated_response_request_t) +
                   sizeof(spdm_digest_response_t) +
                   libspdm_get_hash_size(m_libspdm_use_hash_algo);

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_response_ack(spdm_context, deliver_size, temp_buf,
                                                            &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    ack = (void *)response;
    assert_int_equal(ack->header.request_response_code, SPDM_ENCAPSULATED_RESPONSE_ACK);
    assert_int_equal(ack->header.param2,
                     SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_REQ_SLOT_NUMBER);
    assert_int_equal(ack->header.param1, 0);
    /* SPDM 1.2, so the ACK header is the full structure and the slot byte follows it. */
    assert_int_equal(response_size, sizeof(spdm_encapsulated_response_ack_response_t) + 1);
    assert_int_equal(*((uint8_t *)response + sizeof(spdm_encapsulated_response_ack_response_t)), 5);
    assert_int_equal(session_info->encap_context.mut_auth_req_slot_id, 5);
    assert_int_equal(session_info->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);

    spdm_context->last_spdm_request_session_id_valid = false;
    free(data);
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP */

/**
 * Test 15 (DELIVER_ENCAPSULATED_RESPONSE) where the Integrator's handler emits an ERROR instead
 * of another encapsulated request.
 * Expected behavior: the Responder propagates that ERROR verbatim, rather than replacing it with
 * ERROR(Unspecified) from the request-legality check.
 **/
static void rsp_encapsulated_response_ack_case15(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_deliver_encapsulated_response_request_t *deliver;
    spdm_digest_response_t *digests;
    const spdm_error_response_t *err;
    uint8_t temp_buf[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t *digest;
    size_t deliver_size;
    size_t response_size;
    void *data;
    size_t data_size;
    uint8_t attempt;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    if (!libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo, &data,
                                                         &data_size, NULL, NULL)) {
        return;
    }

    /* attempt 0: the handler sets the ERROR size. attempt 1: it does not, so libspdm must reject
     * the oversized copy rather than perform it. */
    for (attempt = 0; attempt <= 1; attempt++) {
        spdm_test_context->case_id = (attempt == 0) ? 0x95 : 0x96;
        m_case_id = spdm_test_context->case_id;

        set_standard_state(spdm_context);
        spdm_context->connection_info.capability.flags |=
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
        spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
        spdm_context->local_context.local_cert_chain_provision[0] = data;
        spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;
        spdm_context->encap_context.request_id = 0;
        spdm_context->encap_context.last_encap_request_header.request_response_code =
            SPDM_GET_DIGESTS;
        libspdm_reset_message_b(spdm_context);

        deliver = (void *)temp_buf;
        libspdm_copy_mem(deliver, sizeof(temp_buf),
                         &m_libspdm_m_deliver_encapsulated_response_request_t1,
                         m_libspdm_m_deliver_encapsulated_response_request_t1_size);
        deliver->header.param1 = 0;

        digests = (void *)(temp_buf + sizeof(spdm_deliver_encapsulated_response_request_t));
        digests->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        digests->header.request_response_code = SPDM_DIGESTS;
        digests->header.param1 = 0;
        digests->header.param2 = (0x01 << 0);
        digest = (void *)(digests + 1);
        libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_certificate_chain,
                         sizeof(m_libspdm_local_certificate_chain), &digest[0]);

        deliver_size = sizeof(spdm_deliver_encapsulated_response_request_t) +
                       sizeof(spdm_digest_response_t) +
                       libspdm_get_hash_size(m_libspdm_use_hash_algo);

        response_size = sizeof(response);
        status = libspdm_get_response_encapsulated_response_ack(spdm_context, deliver_size,
                                                                temp_buf, &response_size,
                                                                response);
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

        err = (const void *)response;
        assert_int_equal(response_size, sizeof(spdm_error_response_t));
        assert_int_equal(err->header.request_response_code, SPDM_ERROR);
        if (attempt == 0) {
            /* The Integrator's own error code reaches the Requester. */
            assert_int_equal(err->header.param1, SPDM_ERROR_CODE_INVALID_POLICY);
        } else {
            /* The malformed size is rejected and the flow is torn down. */
            assert_int_equal(err->header.param1, SPDM_ERROR_CODE_UNSPECIFIED);
            assert_int_equal(spdm_context->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);
        }
    }

    free(data);
}

#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */

#if LIBSPDM_RESPOND_IF_READY_SUPPORT
/**
 * Test 16: after the Requester delivers an encapsulated ERROR(ResponseNotReady), the Responder
 * terminates the flow but must be able to resume it on the next GET_ENCAPSULATED_REQUEST and
 * reissue the outstanding request with RESPOND_IF_READY.
 * Expected behavior: the flow resumes with its original flow type, RESPOND_IF_READY carries the
 * RequestCode and Token the Requester supplied, and the Integrator's handler is not consulted.
 * m_case_id is deliberately a value the handler does not recognize, so consulting it trips the
 * handler's default assert.
 **/
static void rsp_encapsulated_response_ack_case16(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_encapsulated_request_response_t *encap_request_response;
    const spdm_response_if_ready_request_t *respond_if_ready;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x97;
    m_case_id = spdm_test_context->case_id;

    set_standard_state(spdm_context);

    /* The state that an encapsulated ResponseNotReady leaves behind: the flow is terminated but
     * the GET_DIGESTS it interrupted is still outstanding. */
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_NONE;
    spdm_context->encap_context.response_not_ready = true;
    spdm_context->encap_context.response_not_ready_flow_type =
        LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH;
    spdm_context->encap_context.response_not_ready_data.request_code = SPDM_GET_DIGESTS;
    spdm_context->encap_context.response_not_ready_data.token = 0x5A;
    spdm_context->encap_context.response_not_ready_data.rd_exponent = 1;
    spdm_context->encap_context.response_not_ready_data.rd_tm = 1;
    spdm_context->encap_context.last_encap_request_header.request_response_code = SPDM_GET_DIGESTS;
    spdm_context->encap_context.last_encap_request_size = sizeof(spdm_message_header_t);
    spdm_context->encap_context.request_id = 3;

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_request(spdm_context,
                                                       m_libspdm_encapsulated_request_t1_size,
                                                       &m_libspdm_encapsulated_request_t1,
                                                       &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    encap_request_response = (void *)response;
    assert_int_equal(encap_request_response->header.request_response_code,
                     SPDM_ENCAPSULATED_REQUEST);
    assert_int_equal(response_size,
                     sizeof(spdm_encapsulated_request_response_t) +
                     sizeof(spdm_response_if_ready_request_t));

    respond_if_ready = (const void *)(encap_request_response + 1);
    assert_int_equal(respond_if_ready->header.request_response_code, SPDM_RESPOND_IF_READY);
    /* Populated from the ERROR the Requester delivered. */
    assert_int_equal(respond_if_ready->header.param1, SPDM_GET_DIGESTS);
    assert_int_equal(respond_if_ready->header.param2, 0x5A);

    /* The Request ID is unchanged, since the outstanding request is being reissued. */
    assert_int_equal(encap_request_response->header.param1, 3);

    /* The flow resumed with the type it had before, and the outstanding request is preserved so
     * the eventual response is dispatched to it. */
    assert_int_equal(spdm_context->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH);
    assert_int_equal(spdm_context->encap_context.last_encap_request_header.request_response_code,
                     SPDM_GET_DIGESTS);
    /* The ResponseNotReady has been consumed. */
    assert_false(spdm_context->encap_context.response_not_ready);
}
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */

#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP)
/**
 * Test 15: LIBSPDM_DATA_SESSION_ENCAP_REQ_SLOT_ID is only meaningful while session-based mutual
 * authentication is in progress.
 * Expected behavior: a session that is running some other encapsulated flow, or none at all, is
 * rejected with LIBSPDM_STATUS_INVALID_STATE_LOCAL.
 **/
static void rsp_encapsulated_request_case15(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    libspdm_data_parameter_t parameter;
    uint32_t session_id;
    uint8_t slot_id;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9A;
    m_case_id = spdm_test_context->case_id;

    set_standard_state(spdm_context);

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, true);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_SESSION;
    libspdm_write_uint32(parameter.additional_data, session_id);
    slot_id = 5;

    /* No encapsulated flow at all. */
    session_info->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_NONE;
    assert_int_equal(libspdm_set_data(spdm_context, LIBSPDM_DATA_SESSION_ENCAP_REQ_SLOT_ID,
                                      &parameter, &slot_id, sizeof(slot_id)),
                     LIBSPDM_STATUS_INVALID_STATE_LOCAL);

    /* A flow, but not the one the slot belongs to. */
    session_info->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;
    assert_int_equal(libspdm_set_data(spdm_context, LIBSPDM_DATA_SESSION_ENCAP_REQ_SLOT_ID,
                                      &parameter, &slot_id, sizeof(slot_id)),
                     LIBSPDM_STATUS_INVALID_STATE_LOCAL);

    /* The right flow is accepted. */
    session_info->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_SESS_MUT_AUTH;
    session_info->encap_context.mut_auth_req_slot_id = 0;
    assert_int_equal(libspdm_set_data(spdm_context, LIBSPDM_DATA_SESSION_ENCAP_REQ_SLOT_ID,
                                      &parameter, &slot_id, sizeof(slot_id)),
                     LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(session_info->encap_context.mut_auth_req_slot_id, 5);

    session_info->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_NONE;
}
#endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) */

/**
 * Test 16: the per-flow encapsulated request legality table, including the combinations that
 * depend on whether the flow belongs to a session.
 * Expected behavior: a legal request is returned in ENCAPSULATED_REQUEST; an illegal one is
 * rejected with ERROR(Unspecified) and the flow is torn down.
 **/
static void rsp_encapsulated_request_case16(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    spdm_encapsulated_request_response_t *spdm_response_requester;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;
    uint32_t session_id;
    size_t index;
    const struct {
        libspdm_encap_flow_type_t flow_type;
        bool in_session;
        uint8_t request_code;
        bool legal;
    } cases[] = {
        /* Basic mutual authentication is always outside of a session. */
        { LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH, false, SPDM_GET_DIGESTS, true },
        { LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH, false, SPDM_CHALLENGE, true },
        { LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH, true, SPDM_GET_DIGESTS, false },
        { LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH, false, SPDM_KEY_UPDATE, false },

        /* Session-based mutual authentication always belongs to a session, and retrieves only the
         * Requester's certificate chain. */
        { LIBSPDM_ENCAP_FLOW_SESS_MUT_AUTH, true, SPDM_GET_CERTIFICATE, true },
        { LIBSPDM_ENCAP_FLOW_SESS_MUT_AUTH, false, SPDM_GET_DIGESTS, false },
        { LIBSPDM_ENCAP_FLOW_SESS_MUT_AUTH, true, SPDM_CHALLENGE, false },

        /* A Requester-initiated flow permits more, but session management and events only within
         * a session. */
        { LIBSPDM_ENCAP_FLOW_REQ_INITIATED, false, SPDM_GET_DIGESTS, true },
        { LIBSPDM_ENCAP_FLOW_REQ_INITIATED, false, SPDM_GET_ENDPOINT_INFO, true },
        { LIBSPDM_ENCAP_FLOW_REQ_INITIATED, true, SPDM_KEY_UPDATE, true },
        { LIBSPDM_ENCAP_FLOW_REQ_INITIATED, true, SPDM_SEND_EVENT, true },
        { LIBSPDM_ENCAP_FLOW_REQ_INITIATED, false, SPDM_KEY_UPDATE, false },
        { LIBSPDM_ENCAP_FLOW_REQ_INITIATED, false, SPDM_SEND_EVENT, false },
        { LIBSPDM_ENCAP_FLOW_REQ_INITIATED, false, SPDM_CHALLENGE, false },
        { LIBSPDM_ENCAP_FLOW_REQ_INITIATED, false, SPDM_END_SESSION, false },
    };

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9B;
    m_case_id = spdm_test_context->case_id;

    session_id = 0xFFFFFFFF;

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(cases); index++) {
        libspdm_encap_context_t *encap_context;

        set_standard_state(spdm_context);
        spdm_context->connection_info.capability.flags |=
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;

        session_info = &spdm_context->session_info[0];
        libspdm_session_info_init(spdm_context, session_info, session_id,
                                  SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, true);
        libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                                  LIBSPDM_SESSION_STATE_ESTABLISHED);

        /* The flow is placed on whichever channel the request will arrive on. */
        spdm_context->last_spdm_request_session_id_valid = cases[index].in_session;
        spdm_context->last_spdm_request_session_id = session_id;
        encap_context = cases[index].in_session ? &session_info->encap_context
                        : &spdm_context->encap_context;
        encap_context->flow_type = cases[index].flow_type;
        encap_context->request_id = 0;
        encap_context->last_encap_request_size = 0;

        m_legality_request_code = cases[index].request_code;

        response_size = sizeof(response);
        status = libspdm_get_response_encapsulated_request(spdm_context,
                                                           m_libspdm_encapsulated_request_t1_size,
                                                           &m_libspdm_encapsulated_request_t1,
                                                           &response_size, response);
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
        spdm_response_requester = (void *)response;

        if (cases[index].legal) {
            assert_int_equal(spdm_response_requester->header.request_response_code,
                             SPDM_ENCAPSULATED_REQUEST);
            assert_int_equal(encap_context->flow_type, cases[index].flow_type);
        } else {
            assert_int_equal(spdm_response_requester->header.request_response_code, SPDM_ERROR);
            assert_int_equal(spdm_response_requester->header.param1,
                             SPDM_ERROR_CODE_UNSPECIFIED);
            /* An illegal request tears the flow down. */
            assert_int_equal(encap_context->flow_type, LIBSPDM_ENCAP_FLOW_NONE);
        }

        encap_context->flow_type = LIBSPDM_ENCAP_FLOW_NONE;
        spdm_context->last_spdm_request_session_id_valid = false;
    }
}

/**
 * Test 17 (GET_ENCAPSULATED_REQUEST) the Responder itself asked for the flow in CHALLENGE_AUTH, so
 * it cannot then report that no request is pending. Only a Requester-initiated flow may be declined
 * with NoPendingRequests.
 * Expected behavior: Responder generates ERROR(Unspecified) and tears the flow down.
 **/
static void rsp_encapsulated_request_case17(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    spdm_error_response_t *spdm_response_requester;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9C;
    m_case_id = spdm_test_context->case_id;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;

    spdm_context->encap_context.request_id = 0;
    spdm_context->last_spdm_request_session_id_valid = false;

    /* The state that CHALLENGE_AUTH with the basic mutual authentication bit leaves behind. */
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH;
    spdm_context->encap_context.last_encap_request_size = 0;

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_request(spdm_context,
                                                       m_libspdm_encapsulated_request_t2_size,
                                                       &m_libspdm_encapsulated_request_t2,
                                                       &response_size,
                                                       response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response_requester = (void *)response;
    assert_int_equal(spdm_response_requester->header.request_response_code, SPDM_ERROR);
    /* Not NoPendingRequests, which would contradict the Responder's own CHALLENGE_AUTH. */
    assert_int_equal(spdm_response_requester->header.param1, SPDM_ERROR_CODE_UNSPECIFIED);
    assert_int_equal(spdm_response_requester->header.param2, 0);
    assert_int_equal(spdm_context->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);
}

/* Deliver an encapsulated ERROR for an outstanding request of the given code, so that the
 * response-processing dispatch arm for that code is exercised. */
static void deliver_encap_error(libspdm_context_t *spdm_context, uint8_t last_request_code,
                                uint8_t error_code, size_t encap_size,
                                uint8_t *response, size_t *response_size)
{
    spdm_deliver_encapsulated_response_request_t *spdm_request;
    spdm_error_response_t *encap_error;
    uint8_t temp_buf[LIBSPDM_MAX_SPDM_MSG_SIZE];
    libspdm_return_t status;

    /* This flow occurs outside of a session, and an earlier test in this group leaves a session
     * behind. */
    spdm_context->last_spdm_request_session_id_valid = false;
    spdm_context->latest_session_id = INVALID_SESSION_ID;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->encap_context.request_id = 0xFF;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    spdm_context->encap_context.last_encap_request_header.request_response_code = last_request_code;
    spdm_context->encap_context.last_encap_request_size = sizeof(spdm_message_header_t);
#if LIBSPDM_RESPOND_IF_READY_SUPPORT
    spdm_context->encap_context.response_not_ready = false;
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_register_encap_flow_handler(spdm_context, encap_flow_handler);

    spdm_request = (void *)temp_buf;
    spdm_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request->header.request_response_code = SPDM_DELIVER_ENCAPSULATED_RESPONSE;
    spdm_request->header.param1 = 0xFF;
    spdm_request->header.param2 = 0;
    encap_error = (void *)(temp_buf + sizeof(spdm_deliver_encapsulated_response_request_t));
    encap_error->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    encap_error->header.request_response_code = SPDM_ERROR;
    encap_error->header.param1 = error_code;
    encap_error->header.param2 = 0;

    m_observed_error_code = 0;
    status = libspdm_get_response_encapsulated_response_ack(
        spdm_context, sizeof(spdm_deliver_encapsulated_response_request_t) + encap_size,
        spdm_request, response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
}

#if LIBSPDM_SEND_GET_ENDPOINT_INFO_SUPPORT
/**
 * Test 18 (DELIVER_ENCAPSULATED_RESPONSE) the Requester declines an encapsulated
 * GET_ENDPOINT_INFO with an ERROR, so the response is routed to the endpoint information
 * processing function.
 * Expected behavior: the handler learns the ErrorCode and the flow is torn down.
 **/
static void rsp_encapsulated_response_ack_case18(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_encapsulated_response_ack_response_t *spdm_response;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA0;
    m_case_id = spdm_test_context->case_id;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;
    spdm_context->get_endpoint_info_callback = get_endpoint_info_callback_encap_response;

    response_size = sizeof(response);
    deliver_encap_error(spdm_context, SPDM_GET_ENDPOINT_INFO,
                        SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, sizeof(spdm_error_response_t),
                        response, &response_size);

    assert_int_equal(m_observed_error_code, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ENCAPSULATED_RESPONSE_ACK);
    assert_int_equal(spdm_response->header.param2,
                     SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_ABSENT);
    assert_int_equal(spdm_context->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);
}
#endif /* LIBSPDM_SEND_GET_ENDPOINT_INFO_SUPPORT */

#if LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP
/**
 * Test 19 (DELIVER_ENCAPSULATED_RESPONSE) the Requester declines an encapsulated SEND_EVENT with
 * an ERROR, so the response is routed to the event acknowledgement processing function.
 * Expected behavior: the handler learns the ErrorCode and the flow is torn down.
 **/
static void rsp_encapsulated_response_ack_case19(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_encapsulated_response_ack_response_t *spdm_response;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA1;
    m_case_id = spdm_test_context->case_id;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;

    response_size = sizeof(response);
    deliver_encap_error(spdm_context, SPDM_SEND_EVENT,
                        SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, sizeof(spdm_error_response_t),
                        response, &response_size);

    assert_int_equal(m_observed_error_code, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ENCAPSULATED_RESPONSE_ACK);
    assert_int_equal(spdm_context->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP */

#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
/**
 * Test 20 (DELIVER_ENCAPSULATED_RESPONSE) the encapsulated response is neither the expected
 * response nor an ERROR, so there is no ErrorCode to report to the Integrator.
 * Expected behavior: Responder returns ERROR(InvalidResponseCode) and tears the flow down.
 **/
static void rsp_encapsulated_response_ack_case20(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_error_response_t *spdm_response;
    spdm_deliver_encapsulated_response_request_t *spdm_request;
    spdm_message_header_t *encap_response;
    uint8_t temp_buf[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA2;
    m_case_id = spdm_test_context->case_id;

    /* This flow occurs outside of a session, and an earlier test in this group leaves a session
     * behind. */
    spdm_context->last_spdm_request_session_id_valid = false;
    spdm_context->latest_session_id = INVALID_SESSION_ID;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->encap_context.request_id = 0xFF;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;
    spdm_context->encap_context.last_encap_request_header.request_response_code = SPDM_GET_DIGESTS;
    spdm_context->encap_context.last_encap_request_size = sizeof(spdm_message_header_t);
#if LIBSPDM_RESPOND_IF_READY_SUPPORT
    spdm_context->encap_context.response_not_ready = false;
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_register_encap_flow_handler(spdm_context, encap_flow_handler);

    spdm_request = (void *)temp_buf;
    libspdm_copy_mem(spdm_request, sizeof(temp_buf),
                     &m_libspdm_m_deliver_encapsulated_response_request_t2,
                     m_libspdm_m_deliver_encapsulated_response_request_t2_size);
    /* A CERTIFICATE response where DIGESTS was requested. */
    encap_response = (void *)(temp_buf + sizeof(spdm_deliver_encapsulated_response_request_t));
    encap_response->spdm_version = SPDM_MESSAGE_VERSION_12;
    encap_response->request_response_code = SPDM_CERTIFICATE;
    encap_response->param1 = 0;
    encap_response->param2 = 0;

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_response_ack(
        spdm_context,
        sizeof(spdm_deliver_encapsulated_response_request_t) + sizeof(spdm_message_header_t),
        spdm_request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_RESPONSE_CODE);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);
}

#if LIBSPDM_RESPOND_IF_READY_SUPPORT
/**
 * Test 21 (DELIVER_ENCAPSULATED_RESPONSE) the Requester returns ResponseNotReady but the ERROR
 * carries no extended data, so the fields needed to reissue the request are absent.
 * Expected behavior: Responder returns ERROR(InvalidResponseCode) and tears the flow down.
 **/
static void rsp_encapsulated_response_ack_case21(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_error_response_t *spdm_response;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA3;
    m_case_id = spdm_test_context->case_id;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;

    response_size = sizeof(response);
    deliver_encap_error(spdm_context, SPDM_GET_DIGESTS,
                        SPDM_ERROR_CODE_RESPONSE_NOT_READY, sizeof(spdm_error_response_t),
                        response, &response_size);

    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_RESPONSE_CODE);
    assert_int_equal(spdm_context->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);
    assert_false(spdm_context->encap_context.response_not_ready);
}
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */
#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */

/**
 * Test 22 (DELIVER_ENCAPSULATED_RESPONSE) the Integrator's handler fails.
 * Expected behavior: Responder returns ERROR(Unspecified) and tears the flow down.
 **/
static void rsp_encapsulated_response_ack_case22(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_error_response_t *spdm_response;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9E;
    m_case_id = spdm_test_context->case_id;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;

    /* A last request code of zero means no encapsulated response is processed, so the handler is
     * consulted directly. */
    response_size = sizeof(response);
    deliver_encap_error(spdm_context, 0, 0, sizeof(spdm_error_response_t),
                        response, &response_size);

    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSPECIFIED);
    assert_int_equal(spdm_context->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);
}

/**
 * Test 23 (DELIVER_ENCAPSULATED_RESPONSE) the Integrator's handler produces a request that is not
 * legal for the flow in progress.
 * Expected behavior: Responder does not send it and returns ERROR(Unspecified).
 **/
static void rsp_encapsulated_response_ack_case23(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_error_response_t *spdm_response;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9B;
    m_case_id = spdm_test_context->case_id;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;
    /* KEY_UPDATE is only legal within a session, and this flow is outside of one. */
    m_legality_request_code = SPDM_KEY_UPDATE;

    response_size = sizeof(response);
    deliver_encap_error(spdm_context, 0, 0, sizeof(spdm_error_response_t),
                        response, &response_size);

    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSPECIFIED);
    assert_int_equal(spdm_context->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);
}

/**
 * Test 24 (DELIVER_ENCAPSULATED_RESPONSE) the KEY_UPDATE_ACK for the UpdateKey operation is
 * delivered, but the follow-up VerifyNewKey cannot be built because the Requester no longer
 * supports KEY_UPD_CAP.
 * Expected behavior: Responder returns ERROR(Unspecified) and tears the flow down rather than
 * leaving it half-open.
 **/
static void rsp_encapsulated_response_ack_case24(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_deliver_encapsulated_response_request_t *spdm_request;
    spdm_key_update_response_t *key_update_ack;
    spdm_error_response_t *spdm_response;
    uint8_t temp_buf[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;
    uint32_t session_id;
    libspdm_session_info_t *session_info;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    /* No handler case is defined for this case_id, so the test fails if the handler is consulted. */
    spdm_test_context->case_id = 0xA5;
    m_case_id = spdm_test_context->case_id;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    spdm_context->connection_info.capability.flags &=
        ~SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_register_encap_flow_handler(spdm_context, encap_flow_handler);

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, true);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);

    session_info->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;
    session_info->encap_context.request_id = 0;
    session_info->encap_context.last_encap_request_header.spdm_version = SPDM_MESSAGE_VERSION_11;
    session_info->encap_context.last_encap_request_header.request_response_code = SPDM_KEY_UPDATE;
    session_info->encap_context.last_encap_request_header.param1 =
        SPDM_KEY_UPDATE_OPERATIONS_UPDATE_KEY;
    session_info->encap_context.last_encap_request_header.param2 = 0x5A;

    spdm_request = (void *)temp_buf;
    libspdm_copy_mem(spdm_request, sizeof(temp_buf),
                     &m_libspdm_m_deliver_encapsulated_response_request_t1,
                     m_libspdm_m_deliver_encapsulated_response_request_t1_size);

    key_update_ack = (void *)(temp_buf + sizeof(spdm_deliver_encapsulated_response_request_t));
    key_update_ack->header.spdm_version = SPDM_MESSAGE_VERSION_11;
    key_update_ack->header.request_response_code = SPDM_KEY_UPDATE_ACK;
    key_update_ack->header.param1 = SPDM_KEY_UPDATE_OPERATIONS_UPDATE_KEY;
    key_update_ack->header.param2 = 0x5A;

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_response_ack(
        spdm_context,
        sizeof(spdm_deliver_encapsulated_response_request_t) + sizeof(spdm_key_update_response_t),
        spdm_request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSPECIFIED);
    assert_int_equal(session_info->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP;
    spdm_context->last_spdm_request_session_id_valid = false;
}

/**
 * Test 26 (DELIVER_ENCAPSULATED_RESPONSE) the Requester answers an encapsulated KEY_UPDATE with
 * ERROR(DecryptError), which ends the session that the encapsulated flow belongs to.
 * Expected behavior: Responder returns ERROR(Unspecified). The Integrator's handler is not
 * consulted, as neither the flow nor the session it names still exists.
 **/
static void rsp_encapsulated_response_ack_case26(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_deliver_encapsulated_response_request_t *spdm_request;
    spdm_error_response_t *encap_error;
    spdm_error_response_t *spdm_response;
    uint8_t temp_buf[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;
    uint32_t session_id;
    libspdm_session_info_t *session_info;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    /* No handler case is defined for this case_id, so the test fails if the handler is consulted. */
    spdm_test_context->case_id = 0xA6;
    m_case_id = spdm_test_context->case_id;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    libspdm_register_encap_flow_handler(spdm_context, encap_flow_handler);

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, true);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);

    session_info->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;
    session_info->encap_context.request_id = 0;
    session_info->encap_context.last_encap_request_header.spdm_version = SPDM_MESSAGE_VERSION_11;
    session_info->encap_context.last_encap_request_header.request_response_code = SPDM_KEY_UPDATE;
    session_info->encap_context.last_encap_request_header.param1 =
        SPDM_KEY_UPDATE_OPERATIONS_UPDATE_KEY;
    session_info->encap_context.last_encap_request_header.param2 = 0x5A;

    spdm_request = (void *)temp_buf;
    libspdm_copy_mem(spdm_request, sizeof(temp_buf),
                     &m_libspdm_m_deliver_encapsulated_response_request_t1,
                     m_libspdm_m_deliver_encapsulated_response_request_t1_size);

    encap_error = (void *)(temp_buf + sizeof(spdm_deliver_encapsulated_response_request_t));
    encap_error->header.spdm_version = SPDM_MESSAGE_VERSION_11;
    encap_error->header.request_response_code = SPDM_ERROR;
    encap_error->header.param1 = SPDM_ERROR_CODE_DECRYPT_ERROR;
    encap_error->header.param2 = 0;

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_response_ack(
        spdm_context,
        sizeof(spdm_deliver_encapsulated_response_request_t) + sizeof(spdm_error_response_t),
        spdm_request, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSPECIFIED);
    assert_int_equal(spdm_response->header.param2, 0);

    /* DecryptError ends the session, so the flow it belonged to is gone with it. */
    assert_int_equal(session_info->session_id, INVALID_SESSION_ID);
    assert_int_equal(spdm_context->latest_session_id, INVALID_SESSION_ID);
    assert_int_equal(session_info->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);

    spdm_context->last_spdm_request_session_id_valid = false;
}

/**
 * Test 25 (DELIVER_ENCAPSULATED_RESPONSE) the Request ID is at its maximum value and the flow
 * continues with another encapsulated request.
 * Expected behavior: the Request ID wraps to 1 rather than to 0, since Param1 of 0 is reserved for
 * an ENCAPSULATED_RESPONSE_ACK that carries no request.
 **/
static void rsp_encapsulated_response_ack_case25(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_encapsulated_response_ack_response_t *spdm_response;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9B;
    m_case_id = spdm_test_context->case_id;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH;
    /* GET_DIGESTS is legal in this flow, so the request is carried in the acknowledgement. */
    m_legality_request_code = SPDM_GET_DIGESTS;

    /* The helper delivers with Param1 of 0xFF, which is also the outstanding Request ID. */
    response_size = sizeof(response);
    deliver_encap_error(spdm_context, 0, 0, sizeof(spdm_error_response_t),
                        response, &response_size);

    assert_int_equal(response_size,
                     sizeof(spdm_encapsulated_response_ack_response_t) +
                     sizeof(spdm_message_header_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ENCAPSULATED_RESPONSE_ACK);
    assert_int_equal(spdm_response->header.param2,
                     SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_PRESENT);
    assert_int_equal(spdm_response->header.param1, 1);
    assert_int_equal(spdm_context->encap_context.request_id, 1);
}

/**
 * Test 18 (GET_ENCAPSULATED_REQUEST) the Integrator's handler produces no request but does not
 * terminate the flow, so the Responder has nothing to encapsulate.
 * Expected behavior: the flow is torn down and ENCAPSULATED_REQUEST carries no request.
 **/
static void rsp_encapsulated_request_case18(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_encapsulated_request_response_t *spdm_response;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9D;
    m_case_id = spdm_test_context->case_id;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->last_spdm_request_session_id_valid = false;
    spdm_context->latest_session_id = INVALID_SESSION_ID;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_NONE;
    spdm_context->encap_context.last_encap_request_size = 0;
#if LIBSPDM_RESPOND_IF_READY_SUPPORT
    spdm_context->encap_context.response_not_ready = false;
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */
    libspdm_register_encap_flow_handler(spdm_context, encap_flow_handler);

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_request(spdm_context,
                                                       m_libspdm_encapsulated_request_t2_size,
                                                       &m_libspdm_encapsulated_request_t2,
                                                       &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_encapsulated_request_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ENCAPSULATED_REQUEST);
    assert_int_equal(spdm_response->header.param1, 0);
    assert_int_equal(spdm_context->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);
}

#if LIBSPDM_RESPOND_IF_READY_SUPPORT
/**
 * Test 19 (GET_ENCAPSULATED_REQUEST) the flow is marked as awaiting a reissue after
 * ResponseNotReady, but no outstanding request was retained.
 * Expected behavior: Responder returns ERROR(Unspecified) and tears the flow down.
 **/
static void rsp_encapsulated_request_case19(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_error_response_t *spdm_response;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA4;
    m_case_id = spdm_test_context->case_id;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->last_spdm_request_session_id_valid = false;
    spdm_context->latest_session_id = INVALID_SESSION_ID;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_NONE;
    spdm_context->encap_context.response_not_ready = true;
    spdm_context->encap_context.response_not_ready_flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;
    /* Nothing was retained, so there is no request to reissue. */
    spdm_context->encap_context.last_encap_request_size = 0;
    libspdm_register_encap_flow_handler(spdm_context, encap_flow_handler);

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_request(spdm_context,
                                                       m_libspdm_encapsulated_request_t2_size,
                                                       &m_libspdm_encapsulated_request_t2,
                                                       &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSPECIFIED);
    assert_int_equal(spdm_context->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);
    spdm_context->encap_context.response_not_ready = false;
}
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */

/**
 * Test 20 (GET_ENCAPSULATED_REQUEST) the Integrator's handler emits an ERROR but reports a size
 * that is smaller than a bare ERROR message.
 * Expected behavior: Responder does not propagate the truncated message and returns
 * ERROR(Unspecified).
 **/
static void rsp_encapsulated_request_case20(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_error_response_t *spdm_response;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9F;
    m_case_id = spdm_test_context->case_id;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->last_spdm_request_session_id_valid = false;
    spdm_context->latest_session_id = INVALID_SESSION_ID;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_NONE;
    spdm_context->encap_context.last_encap_request_size = 0;
#if LIBSPDM_RESPOND_IF_READY_SUPPORT
    spdm_context->encap_context.response_not_ready = false;
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */
    libspdm_register_encap_flow_handler(spdm_context, encap_flow_handler);

    response_size = sizeof(response);
    status = libspdm_get_response_encapsulated_request(spdm_context,
                                                       m_libspdm_encapsulated_request_t2_size,
                                                       &m_libspdm_encapsulated_request_t2,
                                                       &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    /* Not the Integrator's InvalidPolicy, which was never propagated. */
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSPECIFIED);
    assert_int_equal(spdm_context->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);
}

int libspdm_rsp_encapsulated_request_test(void)
{
    const struct CMUnitTest test_cases[] = {
#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT)
        /*Success Case: Responder generates GET_DIGESTS in BASIC_MUT_AUTH flow*/
        cmocka_unit_test(rsp_encapsulated_request_case1),
        /*Success Case: Responder generates GET_CERTIFICATE in BASIC_MUT_AUTH flow*/
        cmocka_unit_test(rsp_encapsulated_request_case2),
        /*response_state : LIBSPDM_RESPONSE_STATE_NORMAL with UnexpectedRequest error. */
        cmocka_unit_test(rsp_encapsulated_request_case3),
        /*response_state : LIBSPDM_RESPONSE_STATE_NEED_RESYNC */
        cmocka_unit_test(rsp_encapsulated_request_case4),
#endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT) */
#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_SEND_CHALLENGE_SUPPORT)
        /*Success Case: Responder generates CHALLENGE in BASIC_MUT_AUTH flow*/
        cmocka_unit_test(rsp_encapsulated_request_case5),
#endif
        /* Success Case: Responder generates KEY_UPDATE in REQ_INITIATED flow */
        cmocka_unit_test(rsp_encapsulated_request_case6),
        /*response_state : LIBSPDM_RESPONSE_STATE_NORMAL with NoPendingRequests error. */
        cmocka_unit_test(rsp_encapsulated_request_case7),
#if LIBSPDM_SEND_GET_ENDPOINT_INFO_SUPPORT
        /* Success Case: Responder generates GET_ENDPOINT_INFO in REQ_INITIATED flow */
        cmocka_unit_test(rsp_encapsulated_request_case8),
        /* Error Case: Integrator returns a request that is illegal in the basic mutual
         * authentication flow */
        cmocka_unit_test(rsp_encapsulated_request_case9),
#endif /* LIBSPDM_SEND_GET_ENDPOINT_INFO_SUPPORT */
        /* Error Case: Integrator's handler returns an error */
        cmocka_unit_test(rsp_encapsulated_request_case10),
#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
        /* Error Case: Integrator supplies a session_id for a session that does not exist */
        cmocka_unit_test(rsp_encapsulated_request_case11),
#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */
        /* Error Case: Integrator requests KEY_UPDATE with the UpdateAllKeys operation */
        cmocka_unit_test(rsp_encapsulated_request_case12),

#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
        /*Success Case: Responder processes DIGESTS encapsulated response*/
        cmocka_unit_test(rsp_encapsulated_response_ack_case1),
        /*Success Case: Responder processes CERTIFICATE encapsulated response*/
        cmocka_unit_test(rsp_encapsulated_response_ack_case2),
#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */
        /* Success Case: Responder processes KEY_UPDATE_ACK encapsulated response */
        cmocka_unit_test(rsp_encapsulated_response_ack_case3),
        /* No pending request header (no encapsulated response to process) */
        cmocka_unit_test(rsp_encapsulated_response_ack_case4),
        /*response_state : LIBSPDM_RESPONSE_STATE_NORMAL */
        cmocka_unit_test(rsp_encapsulated_response_ack_case5),
        /*response_state : LIBSPDM_RESPONSE_STATE_NEED_RESYNC */
        cmocka_unit_test(rsp_encapsulated_response_ack_case6),
#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT)
        /*spdm_request->header.param1 != spdm_context->encap_context.request_id */
        cmocka_unit_test(rsp_encapsulated_response_ack_case7),
        /*Success Case  When version is greater than V1.2 */
        cmocka_unit_test(rsp_encapsulated_response_ack_case8),
#endif
#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
        /*When the Requester delivers an encapsulated ERROR message with a ResponseNotReady error code*/
        cmocka_unit_test(rsp_encapsulated_response_ack_case9),
        /* An encapsulated ERROR other than ResponseNotReady reaches the handler */
        cmocka_unit_test(rsp_encapsulated_response_ack_case17),
#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */
        #if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_SEND_CHALLENGE_SUPPORT)
        /* Basic mut auth terminates once the encapsulated CHALLENGE_AUTH is delivered */
        cmocka_unit_test(rsp_encapsulated_response_ack_case10),
#endif
        /* Success Case: Responder issues VerifyNewKey after the UpdateKey acknowledgement,
         * without consulting the Integrator */
        cmocka_unit_test(rsp_encapsulated_response_ack_case11),
#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
        /* Request ID starts at 0 and increments for each ACK that carries a request */
        cmocka_unit_test(rsp_encapsulated_response_ack_case12),
#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */
#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
        /* Optimized flow: the Responder never provided a Request ID, so Param1 must be 0 */
        cmocka_unit_test(rsp_encapsulated_response_ack_case13),
        /* Integrator terminates the flow with its own ERROR from the ACK path */
        cmocka_unit_test(rsp_encapsulated_response_ack_case15),
#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */
#if LIBSPDM_RESPOND_IF_READY_SUPPORT
        /* Resume after ResponseNotReady and reissue with RESPOND_IF_READY */
        cmocka_unit_test(rsp_encapsulated_response_ack_case16),
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */
#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT)
        /* LIBSPDM_DATA_SESSION_ENCAP_REQ_SLOT_ID designates the slot in the final ACK */
        cmocka_unit_test(rsp_encapsulated_response_ack_case14),
#endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (..) */
#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
        /* Success Case: concurrent encapsulated flows in two different secure sessions */
        cmocka_unit_test(rsp_encapsulated_request_case13),
#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */
#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) && \
        (LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT)
        /* Success Case: session-based mutual auth with the handshake in the clear */
        cmocka_unit_test(rsp_encapsulated_request_case14),
#endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (..) */
#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP)
        /* LIBSPDM_DATA_SESSION_ENCAP_REQ_SLOT_ID requires a mutual auth flow */
        cmocka_unit_test(rsp_encapsulated_request_case15),
#endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (..) */
        /* Per-flow encapsulated request legality, including the in-session arms */
        cmocka_unit_test(rsp_encapsulated_request_case16),
        /* Only a Requester-initiated flow may be declined with NoPendingRequests */
        cmocka_unit_test(rsp_encapsulated_request_case17),
#if LIBSPDM_SEND_GET_ENDPOINT_INFO_SUPPORT
        /* An encapsulated ERROR is routed to the endpoint information processing function */
        cmocka_unit_test(rsp_encapsulated_response_ack_case18),
#endif /* LIBSPDM_SEND_GET_ENDPOINT_INFO_SUPPORT */
#if LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP
        /* An encapsulated ERROR is routed to the event acknowledgement processing function */
        cmocka_unit_test(rsp_encapsulated_response_ack_case19),
#endif /* LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP */
#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
        /* An encapsulated response that is neither expected nor an ERROR */
        cmocka_unit_test(rsp_encapsulated_response_ack_case20),
#if LIBSPDM_RESPOND_IF_READY_SUPPORT
        /* ResponseNotReady without the extended data needed to reissue the request */
        cmocka_unit_test(rsp_encapsulated_response_ack_case21),
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */
#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */
        /* The Integrator's handler fails on the acknowledgement path */
        cmocka_unit_test(rsp_encapsulated_response_ack_case22),
        /* The Integrator's handler produces an illegal request on the acknowledgement path */
        cmocka_unit_test(rsp_encapsulated_response_ack_case23),
        /* The follow-up request of a multi-message operation cannot be built */
        cmocka_unit_test(rsp_encapsulated_response_ack_case24),
        /* The Request ID wraps to 1 rather than 0 */
        cmocka_unit_test(rsp_encapsulated_response_ack_case25),
        /* An encapsulated ERROR(DecryptError) ends the session the flow belongs to */
        cmocka_unit_test(rsp_encapsulated_response_ack_case26),
        /* The Integrator's handler produces no request without terminating the flow */
        cmocka_unit_test(rsp_encapsulated_request_case18),
#if LIBSPDM_RESPOND_IF_READY_SUPPORT
        /* RESPOND_IF_READY is due but no outstanding request was retained */
        cmocka_unit_test(rsp_encapsulated_request_case19),
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */
        /* The Integrator's ERROR is smaller than a bare ERROR message */
        cmocka_unit_test(rsp_encapsulated_request_case20),
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

#endif /* LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP */
