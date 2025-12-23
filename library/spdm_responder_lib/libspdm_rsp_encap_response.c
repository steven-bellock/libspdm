/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP

void libspdm_register_encap_flow_handler(void *spdm_context,
                                         libspdm_encap_flow_handler_func encap_flow_handler)
{
    libspdm_context_t *context;

    context = spdm_context;

    context->encap_flow_handler_callback = (void *)encap_flow_handler;
}

/**
 * Process the encapsulated response received from the Requester. Dispatches to the correct
 * response processing function based on the last request code.
 **/
static libspdm_return_t libspdm_dispatch_process_encap_response(
    libspdm_context_t *spdm_context, uint8_t last_request_code,
    size_t encap_response_size, const void *encap_response, bool *need_continue)
{
    switch (last_request_code) {
#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
    case SPDM_GET_DIGESTS:
        return libspdm_process_encap_response_digest(
            spdm_context, encap_response_size, encap_response, need_continue);
    case SPDM_GET_CERTIFICATE:
        return libspdm_process_encap_response_certificate(
            spdm_context, encap_response_size, encap_response, need_continue);
#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */
#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_SEND_CHALLENGE_SUPPORT)
    case SPDM_CHALLENGE:
        return libspdm_process_encap_response_challenge_auth(
            spdm_context, encap_response_size, encap_response, need_continue);
#endif
    case SPDM_KEY_UPDATE:
        return libspdm_process_encap_response_key_update(
            spdm_context, encap_response_size, encap_response, need_continue);
#if LIBSPDM_SEND_GET_ENDPOINT_INFO_SUPPORT
    case SPDM_GET_ENDPOINT_INFO:
        return libspdm_process_encap_response_endpoint_info(
            spdm_context, encap_response_size, encap_response, need_continue);
#endif /* LIBSPDM_SEND_GET_ENDPOINT_INFO_SUPPORT */
#if LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP
    case SPDM_SEND_EVENT:
        return libspdm_process_encap_response_event_ack(
            spdm_context, encap_response_size, encap_response, need_continue);
#endif /* LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP */
    default:
        LIBSPDM_ASSERT(false);
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }
}

/**
 * When a multi-message operation (GET_CERTIFICATE or KEY_UPDATE) requires a follow-up request,
 * build the next request without calling the Integrator's handler.
 **/
static libspdm_return_t libspdm_dispatch_encap_need_continue(
    libspdm_context_t *spdm_context, const uint32_t *session_id, uint8_t last_request_code,
    size_t *encap_request_size, void *encap_request)
{
    switch (last_request_code) {
#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
    case SPDM_GET_CERTIFICATE:
        return libspdm_get_encap_request_get_certificate(
            spdm_context, session_id, spdm_context->encap_context.req_slot_id,
            encap_request_size, encap_request);
#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */
    case SPDM_KEY_UPDATE:
        return libspdm_get_encap_request_key_update(
            spdm_context, *session_id, SPDM_KEY_UPDATE_OPERATIONS_VERIFY_NEW_KEY,
            encap_request_size, encap_request);
    default:
        LIBSPDM_ASSERT(false);
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }
}

#define MAX_ERROR_MSG_SIZE 36

libspdm_return_t libspdm_get_response_encapsulated_request(
    libspdm_context_t *spdm_context, size_t request_size, const void *request,
    size_t *response_size, void *response)
{
    spdm_encapsulated_request_response_t *spdm_response;
    void *encap_request;
    size_t encap_request_size;
    libspdm_return_t status;
    const spdm_get_encapsulated_request_request_t *spdm_request;
    spdm_error_response_t *error_response;
    bool terminate_flow;
    uint8_t error_response_buffer[MAX_ERROR_MSG_SIZE];

    spdm_request = request;

    /* LIBSPDM_ASSERT(spdm_request->header.request_response_code == SPDM_GET_ENCAPSULATED_REQUEST);
     */

    if (libspdm_get_connection_version(spdm_context) < SPDM_MESSAGE_VERSION_11) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
                                               SPDM_GET_ENCAPSULATED_REQUEST,
                                               response_size, response);
    }

    if (!libspdm_is_encap_supported(spdm_context)) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            SPDM_GET_ENCAPSULATED_REQUEST, response_size, response);
    }

    if (request_size < sizeof(spdm_get_encapsulated_request_request_t)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    if (spdm_request->header.spdm_version != libspdm_get_connection_version(spdm_context)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_VERSION_MISMATCH, 0,
                                               response_size, response);
    }

    if ((spdm_context->response_state != LIBSPDM_RESPONSE_STATE_PROCESSING_ENCAP) &&
        (spdm_context->response_state != LIBSPDM_RESPONSE_STATE_NORMAL)) {
        return libspdm_responder_handle_response_state(
            spdm_context,
            spdm_request->header.request_response_code,
            response_size, response);
    }

    if (spdm_context->response_state == LIBSPDM_RESPONSE_STATE_NORMAL) {
        if (spdm_context->encap_context.flow_type != LIBSPDM_ENCAP_FLOW_SESS_MUT_AUTH) {
            /* Requester-initiated encap flow; initialize the encap context. */
            spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_REQ_INITIATED;
            spdm_context->encap_context.request_id = 0;
            spdm_context->encap_context.last_encap_request_size = 0;
            libspdm_zero_mem(&spdm_context->encap_context.last_encap_request_header,
                             sizeof(spdm_context->encap_context.last_encap_request_header));
        }
        spdm_context->response_state = LIBSPDM_RESPONSE_STATE_PROCESSING_ENCAP;
    }

    libspdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                                                  spdm_request->header.request_response_code);

    LIBSPDM_ASSERT(*response_size > sizeof(spdm_encapsulated_request_response_t));
    libspdm_zero_mem(response, *response_size);

    spdm_response = response;
    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    spdm_response->header.request_response_code = SPDM_ENCAPSULATED_REQUEST;
    spdm_response->header.param1 = 1;
    spdm_response->header.param2 = 0;

    encap_request_size = *response_size - sizeof(spdm_encapsulated_request_response_t);
    encap_request = spdm_response + 1;
    terminate_flow = false;

    const uint32_t *session_id_ptr = NULL;

    /* If ENCAP_CAP is set then the handler must also be registered. */
    LIBSPDM_ASSERT(spdm_context->encap_flow_handler_callback != NULL);

    if (spdm_context->last_spdm_request_session_id_valid) {
        session_id_ptr = &spdm_context->last_spdm_request_session_id;
    }

    status = ((libspdm_encap_flow_handler_func)spdm_context->encap_flow_handler_callback)(
        spdm_context, session_id_ptr, spdm_context->encap_context.flow_type, 0,
        &terminate_flow, &encap_request_size, encap_request);

    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
        spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_NONE;
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_INVALID_RESPONSE_CODE, 0,
            response_size, response);
    }

    error_response = (spdm_error_response_t *)encap_request;

    if (error_response->header.request_response_code == SPDM_ERROR) {
        /* Handler generated an error response; propagate it directly.
         * Copy to a temporary buffer first since memmove is not available. */
        spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
        spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_NONE;
        libspdm_copy_mem(error_response_buffer, sizeof(error_response_buffer),
                         encap_request, encap_request_size);
        libspdm_copy_mem(response, *response_size, error_response_buffer, encap_request_size);

        *response_size = encap_request_size;
        return LIBSPDM_STATUS_SUCCESS;
    } else if (terminate_flow) {
        spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
        spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_NONE;
        if (libspdm_get_connection_version(spdm_context) >= SPDM_MESSAGE_VERSION_13) {
            return libspdm_generate_error_response(
                spdm_context,
                SPDM_ERROR_CODE_NO_PENDING_REQUESTS, 0,
                response_size, response);
        } else {
            return libspdm_generate_error_response(
                spdm_context,
                SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
                response_size, response);
        }
    } else {
        spdm_context->encap_context.request_id = 1;
        *response_size = sizeof(spdm_encapsulated_request_response_t) + encap_request_size;
    }

    if (encap_request_size == 0) {
        spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
        spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_NONE;
    }

    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_get_response_encapsulated_response_ack(
    libspdm_context_t *spdm_context, size_t request_size, const void *request,
    size_t *response_size, void *response)
{
    const spdm_deliver_encapsulated_response_request_t *spdm_request;
    size_t spdm_request_size;
    spdm_encapsulated_response_ack_response_t *spdm_response;
    const void *encap_response;
    size_t encap_response_size;
    void *encap_request;
    size_t encap_request_size;
    libspdm_return_t status;
    size_t ack_header_size;
    bool terminate_flow;
    bool need_continue;
    uint8_t last_request_code;
    const uint32_t *session_id_ptr;

    spdm_request = request;

    /* LIBSPDM_ASSERT(spdm_request->header.request_response_code ==
     *                SPDM_DELIVER_ENCAPSULATED_RESPONSE); */

    if (libspdm_get_connection_version(spdm_context) < SPDM_MESSAGE_VERSION_11) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
                                               SPDM_DELIVER_ENCAPSULATED_RESPONSE,
                                               response_size, response);
    }

    if (!libspdm_is_encap_supported(spdm_context)) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            SPDM_DELIVER_ENCAPSULATED_RESPONSE, response_size, response);
    }

    if (spdm_context->response_state != LIBSPDM_RESPONSE_STATE_PROCESSING_ENCAP) {
        if (spdm_context->response_state == LIBSPDM_RESPONSE_STATE_NORMAL &&
            spdm_context->encap_context.flow_type == LIBSPDM_ENCAP_FLOW_SESS_MUT_AUTH) {
            /* First DELIVER_ENCAPSULATED_RESPONSE after KEY_EXCHANGE_RSP with bit 2 set.
             * libspdm_build_response already validated this is the expected message. */
            spdm_context->response_state = LIBSPDM_RESPONSE_STATE_PROCESSING_ENCAP;
        } else if (spdm_context->response_state == LIBSPDM_RESPONSE_STATE_NORMAL) {
            return libspdm_generate_error_response(
                spdm_context,
                SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
                response_size, response);
        } else {
            return libspdm_responder_handle_response_state(
                spdm_context,
                spdm_request->header.request_response_code,
                response_size, response);
        }
    }

    if (request_size <= sizeof(spdm_deliver_encapsulated_response_request_t)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    if (spdm_request->header.spdm_version != libspdm_get_connection_version(spdm_context)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_VERSION_MISMATCH, 0,
                                               response_size, response);
    }

    spdm_request_size = request_size;

    if (spdm_request->header.param1 != spdm_context->encap_context.request_id) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    encap_response = spdm_request + 1;
    encap_response_size = spdm_request_size - sizeof(spdm_deliver_encapsulated_response_request_t);

    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        ack_header_size = sizeof(spdm_encapsulated_response_ack_response_t);
    } else {
        ack_header_size = sizeof(spdm_message_header_t);
    }

    LIBSPDM_ASSERT(*response_size > ack_header_size);
    libspdm_zero_mem(response, *response_size);

    spdm_response = response;
    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    spdm_response->header.request_response_code = SPDM_ENCAPSULATED_RESPONSE_ACK;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_PRESENT;

    encap_request_size = *response_size - ack_header_size;
    encap_request = (uint8_t *)spdm_response + ack_header_size;
    if (encap_response_size < sizeof(spdm_message_header_t)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    libspdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                                                  spdm_request->header.request_response_code);

    terminate_flow = false;
    need_continue = false;
    last_request_code =
        spdm_context->encap_context.last_encap_request_header.request_response_code;
    session_id_ptr = NULL;
    if (spdm_context->last_spdm_request_session_id_valid) {
        session_id_ptr = &spdm_context->last_spdm_request_session_id;
    }

    LIBSPDM_ASSERT(spdm_context->encap_flow_handler_callback != NULL);

    if (last_request_code != 0) {
        /* Process the encapsulated response from the Requester before calling the handler. */
        status = libspdm_dispatch_process_encap_response(
            spdm_context, last_request_code,
            encap_response_size, encap_response, &need_continue);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            if (status == LIBSPDM_STATUS_NOT_READY_PEER) {
                /* Terminate the flow when the Requester signals ResponseNotReady. */
                terminate_flow = true;
                status = LIBSPDM_STATUS_SUCCESS;
                goto set_ack_fields;
            }
            spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
            spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_NONE;
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_INVALID_RESPONSE_CODE, 0,
                response_size, response);
        }

        if (need_continue) {
            /* Build the follow-up request (next GET_CERTIFICATE chunk or VerifyNewKey)
             * without invoking the handler. */
            status = libspdm_dispatch_encap_need_continue(
                spdm_context, session_id_ptr, last_request_code,
                &encap_request_size, encap_request);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
                spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_NONE;
                return libspdm_generate_error_response(
                    spdm_context, SPDM_ERROR_CODE_INVALID_RESPONSE_CODE, 0,
                    response_size, response);
            }
            goto set_ack_fields;
        }
    }

    /* All response data processed; ask the Integrator what to do next. */
    status = ((libspdm_encap_flow_handler_func)spdm_context->encap_flow_handler_callback)(
        spdm_context, session_id_ptr, spdm_context->encap_context.flow_type,
        last_request_code, &terminate_flow, &encap_request_size, encap_request);

    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
        spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_NONE;
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_INVALID_RESPONSE_CODE, 0, response_size, response);
    }

set_ack_fields:
    *response_size = ack_header_size + encap_request_size;
    spdm_response->header.param1 = spdm_context->encap_context.request_id;

    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        spdm_response->ack_request_id = spdm_request->header.param1;
    }

    if (terminate_flow) {
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_ABSENT;
        *response_size = sizeof(spdm_encapsulated_response_ack_response_t);
        spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
        spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_NONE;
    } else if (encap_request_size == 0) {
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_ABSENT;
        if ((spdm_context->encap_context.req_slot_id != 0) &&
            (spdm_context->encap_context.req_slot_id != 0xFF)) {
            spdm_response->header.param2 =
                SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_REQ_SLOT_NUMBER;
            *response_size = ack_header_size + 1;
            *(uint8_t *)(spdm_response + 1) = spdm_context->encap_context.req_slot_id;
        }
        spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
        spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_NONE;
    }

    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_handle_encap_error_response_main(uint8_t error_code)
{
    if (error_code == SPDM_ERROR_CODE_RESPONSE_NOT_READY) {
        return LIBSPDM_STATUS_NOT_READY_PEER;
    }

    return LIBSPDM_STATUS_UNSUPPORTED_CAP;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
#if LIBSPDM_SEND_CHALLENGE_SUPPORT
void libspdm_init_basic_mut_auth_encap_state(libspdm_context_t *spdm_context)
{
    spdm_context->encap_context.request_id = 0;
    spdm_context->encap_context.last_encap_request_size = 0;
    libspdm_zero_mem(&spdm_context->encap_context.last_encap_request_header,
                     sizeof(spdm_context->encap_context.last_encap_request_header));
    spdm_context->mut_auth_cert_chain_buffer_size = 0;
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_BASIC_MUT_AUTH;

    /* Clear Cache. */
    libspdm_reset_message_mut_b(spdm_context);
    libspdm_reset_message_mut_c(spdm_context);

    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_PROCESSING_ENCAP;
}
#endif /* LIBSPDM_SEND_CHALLENGE_SUPPORT */

void libspdm_init_mut_auth_encap_state(libspdm_context_t *spdm_context, uint8_t mut_auth_requested)
{
    spdm_context->encap_context.request_id = 0;
    spdm_context->encap_context.last_encap_request_size = 0;
    libspdm_zero_mem(&spdm_context->encap_context.last_encap_request_header,
                     sizeof(spdm_context->encap_context.last_encap_request_header));
    spdm_context->mut_auth_cert_chain_buffer_size = 0;

    /* Clear cache. */
    libspdm_reset_message_mut_b(spdm_context);
    libspdm_reset_message_mut_c(spdm_context);

    /* Session mutual authentication. */
    if (libspdm_is_capabilities_flag_supported(
            spdm_context, false,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP, 0)) {
        LIBSPDM_ASSERT(spdm_context->encap_context.req_slot_id == 0xFF);
        LIBSPDM_ASSERT(mut_auth_requested == SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED);
    } else {
        LIBSPDM_ASSERT(spdm_context->mut_auth_cert_chain_buffer != NULL);
        LIBSPDM_ASSERT(spdm_context->mut_auth_cert_chain_buffer_max_size != 0);
    }

    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_SESS_MUT_AUTH;

    switch (mut_auth_requested) {
    case SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED:
        /* No encapsulation is required. */
        break;
    case SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST:
        LIBSPDM_ASSERT(spdm_context->encap_context.req_slot_id != 0xFF);
        break;
    case SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS:
        /* GET_DIGESTS was embedded in KEY_EXCHANGE_RSP; prime the ACK handler to treat the
         * first DELIVER_ENCAPSULATED_RESPONSE as a DIGESTS reply. */
        LIBSPDM_ASSERT(spdm_context->encap_context.req_slot_id != 0xFF);
        spdm_context->encap_context.last_encap_request_header.request_response_code =
            SPDM_GET_DIGESTS;
        break;
    default:
        LIBSPDM_ASSERT(false);
        break;
    }
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP */
