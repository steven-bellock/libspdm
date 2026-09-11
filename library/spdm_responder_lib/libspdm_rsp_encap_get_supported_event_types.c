/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

#if (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (LIBSPDM_EVENT_RECIPIENT_SUPPORT)

libspdm_return_t libspdm_get_encap_request_get_supported_event_types(
    void *context,
    uint32_t session_id,
    uint8_t *event_group_count,
    size_t supported_event_groups_list_size,
    void *supported_event_groups_list,
    size_t *encap_request_size,
    void *encap_request)
{
    libspdm_context_t *spdm_context;
    libspdm_encap_context_t *encap_context;
    spdm_get_supported_event_types_request_t *spdm_request;
    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;

    spdm_context = context;

    if ((event_group_count == NULL) || (supported_event_groups_list == NULL) ||
        (supported_event_groups_list_size == 0)) {
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    encap_context = libspdm_get_encap_context(spdm_context, &session_id);
    if (encap_context == NULL) {
        /* session_id does not refer to an existing session. */
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    encap_context->last_encap_request_size = 0;

    /* The Event Notifier's list of supported event groups is written here once the
     * SUPPORTED_EVENT_TYPES response is verified. */
    encap_context->payload_buffer = supported_event_groups_list;
    encap_context->payload_buffer_max_size = supported_event_groups_list_size;
    encap_context->payload_buffer_size = 0;
    encap_context->event_group_count = event_group_count;

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

    LIBSPDM_ASSERT(*encap_request_size >= sizeof(spdm_get_supported_event_types_request_t));

    spdm_request = encap_request;

    spdm_request->header.spdm_version = libspdm_get_connection_version(spdm_context);
    spdm_request->header.request_response_code = SPDM_GET_SUPPORTED_EVENT_TYPES;
    spdm_request->header.param1 = 0;
    spdm_request->header.param2 = 0;

    *encap_request_size = sizeof(spdm_get_supported_event_types_request_t);

    libspdm_copy_mem(&encap_context->last_encap_request_header,
                     sizeof(encap_context->last_encap_request_header),
                     &spdm_request->header, sizeof(spdm_message_header_t));
    encap_context->last_encap_request_size = *encap_request_size;

    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_process_encap_response_supported_event_types(
    libspdm_context_t *spdm_context, size_t encap_response_size,
    const void *encap_response, bool *need_continue)
{
    libspdm_encap_context_t *encap_context;
    libspdm_return_t status;
    const spdm_supported_event_types_response_t *spdm_response;
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
    } else if (spdm_response->header.request_response_code != SPDM_SUPPORTED_EVENT_TYPES) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    if (encap_response_size < sizeof(spdm_supported_event_types_response_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    /* Both EventGroupCount and SupportedEventGroupsListLen are greater than zero. */
    if ((spdm_response->header.param1 == 0) ||
        (spdm_response->supported_event_groups_list_len == 0)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    if (encap_response_size != sizeof(spdm_supported_event_types_response_t) +
        (uint64_t)spdm_response->supported_event_groups_list_len) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    *need_continue = false;

    encap_context = libspdm_get_encap_context_via_last_request(spdm_context);

    if (spdm_response->supported_event_groups_list_len > encap_context->payload_buffer_max_size) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "supported event groups list buffer too small\n"));
        return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
    }

    libspdm_copy_mem(encap_context->payload_buffer, encap_context->payload_buffer_max_size,
                     spdm_response + 1, spdm_response->supported_event_groups_list_len);
    encap_context->payload_buffer_size = spdm_response->supported_event_groups_list_len;
    *encap_context->event_group_count = spdm_response->header.param1;

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /* (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && (LIBSPDM_EVENT_RECIPIENT_SUPPORT) */
