/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

#if (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (LIBSPDM_EVENT_RECIPIENT_SUPPORT)

libspdm_return_t libspdm_get_encap_request_subscribe_event_types(
    void *context,
    uint32_t session_id,
    uint8_t subscribe_event_group_count,
    uint32_t subscribe_list_len,
    const void *subscribe_list,
    size_t *encap_request_size,
    void *encap_request)
{
    libspdm_context_t *spdm_context;
    libspdm_encap_context_t *encap_context;
    spdm_subscribe_event_types_request_t *spdm_request;
    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;
    size_t request_size;

    spdm_context = context;

    if (subscribe_event_group_count == 0) {
        /* The Responder is unsubscribing from every event type, so SubscribeListLen and
         * SubscribeList are absent. */
        if ((subscribe_list_len != 0) || (subscribe_list != NULL)) {
            return LIBSPDM_STATUS_INVALID_PARAMETER;
        }
    } else {
        if ((subscribe_list_len == 0) || (subscribe_list == NULL)) {
            return LIBSPDM_STATUS_INVALID_PARAMETER;
        }
    }

    encap_context = libspdm_get_encap_context(spdm_context, &session_id);
    if (encap_context == NULL) {
        /* session_id does not refer to an existing session. */
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    encap_context->last_encap_request_size = 0;

    if (libspdm_get_connection_version(spdm_context) < SPDM_MESSAGE_VERSION_13) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, false, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EVENT_CAP, 0)) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    session_info = libspdm_get_session_info_via_session_id(spdm_context, session_id);
    if (session_info == NULL) {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }
    session_state = libspdm_secured_message_get_session_state(
        session_info->secured_message_context);
    if (session_state != LIBSPDM_SESSION_STATE_ESTABLISHED) {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    /* The Integrator chooses the size of the subscription list, so unlike the other encapsulated
     * requests this one can be larger than the buffer. The room is compared against
     * subscribe_list_len rather than against their sum, which a 32-bit size_t could not hold. */
    if (subscribe_event_group_count == 0) {
        request_size = sizeof(spdm_message_header_t);
        if (*encap_request_size < request_size) {
            return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
        }
    } else {
        if ((*encap_request_size < sizeof(spdm_subscribe_event_types_request_t)) ||
            (subscribe_list_len >
             *encap_request_size - sizeof(spdm_subscribe_event_types_request_t))) {
            return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
        }
        request_size = sizeof(spdm_subscribe_event_types_request_t) + subscribe_list_len;
    }

    spdm_request = encap_request;

    spdm_request->header.spdm_version = libspdm_get_connection_version(spdm_context);
    spdm_request->header.request_response_code = SPDM_SUBSCRIBE_EVENT_TYPES;
    spdm_request->header.param1 = subscribe_event_group_count;
    spdm_request->header.param2 = 0;

    if (subscribe_event_group_count != 0) {
        spdm_request->subscribe_list_len = subscribe_list_len;
        libspdm_copy_mem(spdm_request + 1, subscribe_list_len, subscribe_list, subscribe_list_len);
    }

    *encap_request_size = request_size;

    libspdm_copy_mem(&encap_context->last_encap_request_header,
                     sizeof(encap_context->last_encap_request_header),
                     &spdm_request->header, sizeof(spdm_message_header_t));
    encap_context->last_encap_request_size = request_size;

    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_process_encap_response_subscribe_event_types_ack(
    libspdm_context_t *spdm_context, size_t encap_response_size,
    const void *encap_response, bool *need_continue)
{
    libspdm_return_t status;
    const spdm_subscribe_event_types_ack_response_t *spdm_response;
    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;

    if (!spdm_context->last_spdm_request_session_id_valid) {
        return LIBSPDM_STATUS_ERROR_PEER;
    }

    session_info = libspdm_get_session_info_via_session_id(
        spdm_context, spdm_context->last_spdm_request_session_id);
    if (session_info == NULL) {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }
    session_state = libspdm_secured_message_get_session_state(
        session_info->secured_message_context);
    if (session_state != LIBSPDM_SESSION_STATE_ESTABLISHED) {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    spdm_response = encap_response;

    if (spdm_response->header.spdm_version != libspdm_get_connection_version(spdm_context)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    if (spdm_response->header.request_response_code == SPDM_ERROR) {
        status = libspdm_handle_encap_error_response_main(spdm_response->header.param1);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }
    } else if (spdm_response->header.request_response_code != SPDM_SUBSCRIBE_EVENT_TYPES_ACK) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    if (encap_response_size != sizeof(spdm_subscribe_event_types_ack_response_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    *need_continue = false;

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /* (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (LIBSPDM_EVENT_RECIPIENT_SUPPORT) */
