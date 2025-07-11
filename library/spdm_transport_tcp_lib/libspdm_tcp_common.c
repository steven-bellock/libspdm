/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "library/spdm_transport_tcp_lib.h"
#include "library/spdm_secured_message_lib.h"
#include "hal/library/debuglib.h"
#include "industry_standard/spdm_tcp_binding.h"

/**
 * Encode a normal message or secured message to a transport message.
 *
 * @param  session_id                    Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 * @param  message_size                  size in bytes of the message data buffer.
 * @param  message                      A pointer to a source buffer to store the message.
 * @param  transport_message_size         size in bytes of the transport message data buffer.
 * @param  transport_message             A pointer to a destination buffer to store the transport message.
 *
 * @retval RETURN_SUCCESS               The message is encoded successfully.
 * @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
 **/
libspdm_return_t libspdm_tcp_encode_message(const uint32_t *session_id, size_t message_size,
                                            void *message,
                                            size_t *transport_message_size,
                                            void **transport_message);

/**
 * Decode a transport message to a normal message or secured message.
 *
 * @param  session_id                    Indicates if it is a secured message protected via SPDM session.
 *                                     If *session_id is NULL, it is a normal message.
 *                                     If *session_id is NOT NULL, it is a secured message.
 * @param  transport_message_size         size in bytes of the transport message data buffer.
 * @param  transport_message             A pointer to a source buffer to store the transport message.
 * @param  message_size                  size in bytes of the message data buffer.
 * @param  message                      A pointer to a destination buffer to store the message.
 *
 * @retval RETURN_SUCCESS               The message is encoded successfully.
 * @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
 **/
libspdm_return_t libspdm_tcp_decode_message(uint32_t **session_id,
                                            size_t transport_message_size,
                                            void *transport_message,
                                            size_t *message_size,
                                            void **message);

/**
 * Encode an SPDM or APP message to a transport layer message.
 *
 * For normal SPDM message, it adds the transport layer wrapper.
 * For secured SPDM message, it encrypts a secured message then adds the transport layer wrapper.
 * For secured APP message, it encrypts a secured message then adds the transport layer wrapper.
 *
 * The APP message is encoded to a secured message directly in SPDM session.
 * The APP message format is defined by the transport layer.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 * @param  is_app_message                 Indicates if it is an APP message or SPDM message.
 * @param  is_requester                  Indicates if it is a requester message.
 * @param  message_size                  size in bytes of the message data buffer.
 * @param  message                      A pointer to a source buffer to store the message.
 *                                      For normal message, it shall point to the acquired sender buffer.
 *                                      For secured message, it shall point to the scratch buffer in spdm_context.
 * @param  transport_message_size         size in bytes of the transport message data buffer.
 * @param  transport_message             A pointer to a destination buffer to store the transport message.
 *                                      On input, it shall be msg_buf_ptr from sender buffer.
 *                                      On output, it will point to acquired sender buffer.
 *
 * @retval RETURN_SUCCESS               The message is encoded successfully.
 * @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
 **/
libspdm_return_t libspdm_transport_tcp_encode_message(
    void *spdm_context, const uint32_t *session_id, bool is_app_message,
    bool is_requester, size_t message_size, void *message,
    size_t *transport_message_size, void **transport_message)
{
    libspdm_return_t status;
    void *app_message;
    size_t app_message_size;
    uint8_t *secured_message;
    size_t secured_message_size;
    libspdm_secured_message_callbacks_t spdm_secured_message_callbacks;
    void *secured_message_context;
    size_t app_transport_header_size;
    size_t secure_transport_header_size;

    spdm_secured_message_callbacks.version =
        LIBSPDM_SECURED_MESSAGE_CALLBACKS_VERSION;
    spdm_secured_message_callbacks.get_sequence_number =
        libspdm_tcp_get_sequence_number;
    spdm_secured_message_callbacks.get_max_random_number_count =
        libspdm_tcp_get_max_random_number_count;
    spdm_secured_message_callbacks.get_secured_spdm_version =
        libspdm_tcp_get_secured_spdm_version;

    if (is_app_message && (session_id == NULL)) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    if (session_id != NULL) {
        secured_message_context =
            libspdm_get_secured_message_context_via_session_id(
                spdm_context, *session_id);
        if (secured_message_context == NULL) {
            return LIBSPDM_STATUS_UNSUPPORTED_CAP;
        }

        app_transport_header_size = sizeof(spdm_tcp_binding_header_t);

        if (!is_app_message) {
            /* SPDM message to APP message*/
            app_message = NULL;
            app_message_size = app_transport_header_size + message_size;
            status = libspdm_tcp_encode_message(NULL, message_size,
                                                message,
                                                &app_message_size,
                                                &app_message);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "transport_encode_message - %xu\n", status));
                return status;
            }
        } else {
            app_message = (void *)message;
            app_message_size = message_size;
        }
        /* APP message to secured message*/
        secure_transport_header_size = libspdm_transport_tcp_get_header_size(spdm_context);
        secured_message = (uint8_t *)*transport_message + secure_transport_header_size;
        secured_message_size = *transport_message_size - secure_transport_header_size;
        status = libspdm_encode_secured_message(
            secured_message_context, *session_id, is_requester,
            app_message_size, app_message, &secured_message_size,
            secured_message, &spdm_secured_message_callbacks);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "libspdm_encode_secured_message - %xu\n", status));
            return status;
        }

        /* secured message to secured TCP message*/
        status = libspdm_tcp_encode_message(
            session_id, secured_message_size, secured_message,
            transport_message_size, transport_message);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "transport_encode_message - %xu\n", status));
            return status;
        }
    } else {
        /* SPDM message to normal TCP message*/
        status = libspdm_tcp_encode_message(NULL, message_size, message,
                                            transport_message_size,
                                            transport_message);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "transport_encode_message - %xu\n", status));
            return status;
        }
    }

    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * Decode an SPDM or APP message from a transport layer message.
 *
 * For normal SPDM message, it removes the transport layer wrapper,
 * For secured SPDM message, it removes the transport layer wrapper, then decrypts and verifies a secured message.
 * For secured APP message, it removes the transport layer wrapper, then decrypts and verifies a secured message.
 *
 * The APP message is decoded from a secured message directly in SPDM session.
 * The APP message format is defined by the transport layer.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    Indicates if it is a secured message protected via SPDM session.
 *                                     If *session_id is NULL, it is a normal message.
 *                                     If *session_id is NOT NULL, it is a secured message.
 * @param  is_app_message                 Indicates if it is an APP message or SPDM message.
 * @param  is_requester                  Indicates if it is a requester message.
 * @param  transport_message_size         size in bytes of the transport message data buffer.
 * @param  transport_message             A pointer to a source buffer to store the transport message.
 *                                      For normal message or secured message, it shall point to acquired receiver buffer.
 * @param  message_size                  size in bytes of the message data buffer.
 * @param  message                      A pointer to a destination buffer to store the message.
 *                                      On input, it shall point to the scratch buffer in spdm_context.
 *                                      On output, for normal message, it will point to the original receiver buffer.
 *                                      On output, for secured message, it will point to the scratch buffer in spdm_context.
 *
 * @retval RETURN_SUCCESS               The message is decoded successfully.
 * @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
 * @retval RETURN_UNSUPPORTED           The transport_message is unsupported.
 **/
libspdm_return_t libspdm_transport_tcp_decode_message(
    void *spdm_context, uint32_t **session_id,
    bool *is_app_message, bool is_requester,
    size_t transport_message_size, void *transport_message,
    size_t *message_size, void **message)
{
    libspdm_return_t status;
    uint32_t *secured_message_session_id;
    uint8_t *secured_message;
    size_t secured_message_size;
    uint8_t *app_message;
    size_t app_message_size;
    libspdm_secured_message_callbacks_t spdm_secured_message_callbacks;
    void *secured_message_context;
    libspdm_error_struct_t spdm_error;

    spdm_error.error_code = 0;
    spdm_error.session_id = 0;
    if(spdm_context) {
        libspdm_set_last_spdm_error_struct(spdm_context, &spdm_error);
    }

    spdm_secured_message_callbacks.version =
        LIBSPDM_SECURED_MESSAGE_CALLBACKS_VERSION;
    spdm_secured_message_callbacks.get_sequence_number =
        libspdm_tcp_get_sequence_number;
    spdm_secured_message_callbacks.get_max_random_number_count =
        libspdm_tcp_get_max_random_number_count;
    spdm_secured_message_callbacks.get_secured_spdm_version =
        libspdm_tcp_get_secured_spdm_version;

    if ((session_id == NULL) || (is_app_message == NULL)) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    secured_message_session_id = NULL;
    /* Detect received message*/
    status = libspdm_tcp_decode_message(
        &secured_message_session_id, transport_message_size,
        transport_message, &secured_message_size, (void **)&secured_message);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "transport_decode_message - %xu\n", status));
        return status;
    }

    if (secured_message_session_id != NULL) {
        *session_id = secured_message_session_id;

        secured_message_context =
            libspdm_get_secured_message_context_via_session_id(
                spdm_context, *secured_message_session_id);
        if (secured_message_context == NULL) {
            spdm_error.error_code = SPDM_ERROR_CODE_INVALID_SESSION;
            spdm_error.session_id = *secured_message_session_id;
            libspdm_set_last_spdm_error_struct(spdm_context,
                                               &spdm_error);
            return LIBSPDM_STATUS_UNSUPPORTED_CAP;
        }

        /* Secured message to APP message*/
        app_message = *message;
        app_message_size = *message_size;
        status = libspdm_decode_secured_message(
            secured_message_context, *secured_message_session_id,
            is_requester, secured_message_size, secured_message,
            &app_message_size, (void **)&app_message,
            &spdm_secured_message_callbacks);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "libspdm_decode_secured_message - %xu\n", status));
            libspdm_secured_message_get_last_spdm_error_struct(
                secured_message_context, &spdm_error);
            libspdm_set_last_spdm_error_struct(spdm_context,
                                               &spdm_error);
            return status;
        }

        /* APP message to SPDM message.*/
        status = libspdm_tcp_decode_message(&secured_message_session_id,
                                            app_message_size, app_message,
                                            message_size, message);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            *is_app_message = true;
            /* just return APP message.*/
            *message = app_message;
            *message_size = app_message_size;
            return LIBSPDM_STATUS_SUCCESS;
        } else {
            *is_app_message = false;
            if (secured_message_session_id == NULL) {
                return LIBSPDM_STATUS_SUCCESS;
            } else {
                /* get encapsulated secured message - cannot handle it.*/
                LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                               "transport_decode_message - expect encapsulated normal but got session (%08x)\n",
                               *secured_message_session_id));
                return LIBSPDM_STATUS_UNSUPPORTED_CAP;
            }
        }
    } else {
        /* get non-secured message*/
        status = libspdm_tcp_decode_message(&secured_message_session_id,
                                            transport_message_size,
                                            transport_message,
                                            message_size, message);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "transport_decode_message - %xu\n", status));
            return status;
        }
        LIBSPDM_ASSERT(secured_message_session_id == NULL);
        *session_id = NULL;
        *is_app_message = false;
        return LIBSPDM_STATUS_SUCCESS;
    }
}
