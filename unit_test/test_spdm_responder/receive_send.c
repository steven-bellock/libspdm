/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP

#define CHUNK_GET_UNIT_TEST_OVERRIDE_DATA_TRANSFER_SIZE (64)

typedef struct {
    spdm_message_header_t header;
    /* param1 == RSVD
     * param2 == RSVD*/
    uint16_t standard_id;
    uint8_t len;
    /*uint8_t                vendor_id[len];*/
    uint16_t payload_length;
    /* uint8_t                vendor_defined_payload[payload_length];*/
} my_spdm_vendor_defined_request_msg_t;


libspdm_return_t my_test_get_response_func(
    void *spdm_context, const uint32_t *session_id, bool is_app_message,
    size_t request_size, const void *request, size_t *response_size,
    void *response)
{
    /* response message size is greater than the sending transmit buffer size of responder */
    *response_size = CHUNK_GET_UNIT_TEST_OVERRIDE_DATA_TRANSFER_SIZE + 1;
    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t my_test_get_response_func2(
    void *spdm_context,
    const uint32_t *session_id,
    uint16_t req_standard_id,
    uint8_t req_vendor_id_len,
    const void *req_vendor_id,
    uint32_t req_size,
    const void *req_data,
    uint32_t *resp_size,
    void *resp_data)
{
    /* response message size is greater than the sending transmit buffer size of responder */
    *resp_size = CHUNK_GET_UNIT_TEST_OVERRIDE_DATA_TRANSFER_SIZE + 1;
    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * Test 1: Test Responder Receive Send flow triggers chunk get mode
 * if response buffer is larger than requester data_transfer_size.
 **/
void libspdm_test_responder_receive_send_rsp_case1(void** state)
{
#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
    /* This test case is partially copied from test_requester_get_measurement_case4 */
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    size_t response_size;
    uint8_t* response;
    spdm_error_response_t* spdm_response;
    spdm_get_measurements_request_t spdm_request;
    void* message;
    size_t message_size;
    void* data;
    size_t data_size;
    void* hash;
    size_t hash_size;
    uint32_t transport_header_size;
    uint8_t chunk_handle;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;

    spdm_context->local_context.capability.flags |=
        (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP
         | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP);
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;

    libspdm_read_responder_public_certificate_chain(
        m_libspdm_use_hash_algo,
        m_libspdm_use_asym_algo, &data,
        &data_size,
        &hash, &hash_size);

    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_chain_provision[0] = data;

    libspdm_reset_message_m(spdm_context, NULL);

    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;

    #if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size = data_size;
    libspdm_copy_mem(
        spdm_context->connection_info.peer_used_cert_chain[0].buffer,
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

    spdm_context->connection_info.capability.data_transfer_size =
        CHUNK_GET_UNIT_TEST_OVERRIDE_DATA_TRANSFER_SIZE;

    spdm_context->connection_info.capability.max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request.header.request_response_code = SPDM_GET_MEASUREMENTS;
    spdm_request.header.param1 = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
    spdm_request.header.param2 =
        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS;
    spdm_request.slot_id_param = 0;

    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &spdm_request, sizeof(spdm_request));
    spdm_context->last_spdm_request_size = sizeof(spdm_request);

    assert_int_equal(spdm_context->chunk_context.get.chunk_in_use, false);
    libspdm_acquire_sender_buffer(spdm_context, &message_size, (void**) &message);
    response = message;
    response_size = message_size;
    libspdm_zero_mem(response, response_size);

    status = libspdm_build_response(spdm_context, NULL, false, &response_size, (void**)&response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    transport_header_size = spdm_context->local_context.capability.transport_header_size;

    /* Verify responder returned error large response with chunk_handle == 1
     * and responder is in chunking mode (get.chunk_in_use). */
    spdm_response = (spdm_error_response_t*) ((uint8_t*)message + transport_header_size);
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_LARGE_RESPONSE);
    assert_int_equal(spdm_response->header.param2, 0);

    chunk_handle = *(uint8_t*)(spdm_response + 1);
    assert_int_equal(chunk_handle, spdm_context->chunk_context.get.chunk_handle);
    assert_int_equal(spdm_context->chunk_context.get.chunk_in_use, true);
    libspdm_release_sender_buffer(spdm_context);

    free(data);
    libspdm_reset_message_m(spdm_context, NULL);
    #if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    #else
    libspdm_asym_free(spdm_context->connection_info.algorithm.base_asym_algo,
                      spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
    #endif
#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP */
}

/**
 * Test 2: Test Responder Receive Send flow triggers chunk get mode
 * if response message size is larger than responder sending transmit buffer size.
 **/
void libspdm_test_responder_receive_send_rsp_case2(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    size_t response_size;
    uint8_t* response;
    spdm_error_response_t* spdm_response;
    my_spdm_vendor_defined_request_msg_t spdm_request;
    void* message;
    size_t message_size;
    uint32_t transport_header_size;
    uint8_t chunk_handle;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;

    spdm_context->local_context.capability.flags |=
        (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP
         | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP);
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;

    /* The local Responder transmit buffer size for sending a single and complete SPDM message */
    spdm_context->local_context.capability.sender_data_transfer_size =
        CHUNK_GET_UNIT_TEST_OVERRIDE_DATA_TRANSFER_SIZE;
    /* The peer Requester buffer size for receiving a single and complete SPDM message */
    spdm_context->connection_info.capability.data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;

    spdm_context->connection_info.capability.max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request.header.request_response_code = SPDM_VENDOR_DEFINED_REQUEST;

    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &spdm_request, sizeof(spdm_request));
    spdm_context->last_spdm_request_size = sizeof(spdm_request);

    assert_int_equal(spdm_context->chunk_context.get.chunk_in_use, false);
    libspdm_acquire_sender_buffer(spdm_context, &message_size, (void**) &message);

    response = message;
    response_size = message_size;
    libspdm_zero_mem(response, response_size);

    /* Make response message size greater than the sending transmit buffer size of responder */
    spdm_context->get_response_func = (void *)my_test_get_response_func;

    status = libspdm_build_response(spdm_context, NULL, false, &response_size, (void**)&response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    transport_header_size = spdm_context->local_context.capability.transport_header_size;

    /* Verify responder returned error large response with chunk_handle == 1
     * and responder is in chunking mode (get.chunk_in_use). */
    spdm_response = (spdm_error_response_t*) ((uint8_t*)message + transport_header_size);
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_LARGE_RESPONSE);
    assert_int_equal(spdm_response->header.param2, 0);

    chunk_handle = *(uint8_t*)(spdm_response + 1);
    assert_int_equal(chunk_handle, spdm_context->chunk_context.get.chunk_handle);
    assert_int_equal(spdm_context->chunk_context.get.chunk_in_use, true);
    libspdm_release_sender_buffer(spdm_context);
}


#if LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES
/**
 * Test 3: Test Responder Receive Send flow triggers chunk get mode
 * if response message size is larger than responder sending transmit buffer size.
 **/
void libspdm_test_responder_receive_send_rsp_case3(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    size_t response_size;
    uint8_t* response;
    spdm_error_response_t* spdm_response;
    my_spdm_vendor_defined_request_msg_t spdm_request;
    void* message;
    size_t message_size;
    uint32_t transport_header_size;
    uint8_t chunk_handle;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;

    spdm_context->local_context.capability.flags |=
        (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP
         | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP);
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;

    /* The local Responder transmit buffer size for sending a single and complete SPDM message */
    spdm_context->local_context.capability.sender_data_transfer_size =
        CHUNK_GET_UNIT_TEST_OVERRIDE_DATA_TRANSFER_SIZE;
    /* The peer Requester buffer size for receiving a single and complete SPDM message */
    spdm_context->connection_info.capability.data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;

    spdm_context->connection_info.capability.max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request.header.request_response_code = SPDM_VENDOR_DEFINED_REQUEST;

    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &spdm_request, sizeof(spdm_request));
    spdm_context->last_spdm_request_size = sizeof(spdm_request);

    assert_int_equal(spdm_context->chunk_context.get.chunk_in_use, false);
    libspdm_acquire_sender_buffer(spdm_context, &message_size, (void**) &message);

    response = message;
    response_size = message_size;
    libspdm_zero_mem(response, response_size);

    /* Make response message size greater than the sending transmit buffer size of responder */
    libspdm_register_vendor_callback_func(spdm_context, my_test_get_response_func2);

    status = libspdm_build_response(spdm_context, NULL, false, &response_size, (void**)&response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    transport_header_size = spdm_context->local_context.capability.transport_header_size;

    /* Verify responder returned error large response with chunk_handle == 1
     * and responder is in chunking mode (get.chunk_in_use). */
    spdm_response = (spdm_error_response_t*) ((uint8_t*)message + transport_header_size);
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_LARGE_RESPONSE);
    assert_int_equal(spdm_response->header.param2, 0);

    chunk_handle = *(uint8_t*)(spdm_response + 1);
    assert_int_equal(chunk_handle, spdm_context->chunk_context.get.chunk_handle);
    assert_int_equal(spdm_context->chunk_context.get.chunk_in_use, true);
    libspdm_release_sender_buffer(spdm_context);
}
#endif /* LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES */

/**
 * Test 4: Test Responder Receive Send flow triggers chunk get mode
 * if response buffer is larger than requester max_spdm_msg_size.
 * expect: SPDM_ERROR_CODE_RESPONSE_TOO_LARGE
 **/
void libspdm_test_responder_receive_send_rsp_case4(void** state)
{
#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
    /* This test case is partially copied from test_requester_get_measurement_case4 */
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    size_t response_size;
    uint8_t* response;
    spdm_error_response_t* spdm_response;
    spdm_get_measurements_request_t spdm_request;
    void* message;
    size_t message_size;
    void* data;
    size_t data_size;
    void* hash;
    size_t hash_size;
    uint32_t transport_header_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;

    spdm_context->local_context.capability.flags |=
        (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP
         | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP);
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;

    libspdm_read_responder_public_certificate_chain(
        m_libspdm_use_hash_algo,
        m_libspdm_use_asym_algo, &data,
        &data_size,
        &hash, &hash_size);

    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_chain_provision[0] = data;

    libspdm_reset_message_m(spdm_context, NULL);

    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;

    #if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size = data_size;
    libspdm_copy_mem(
        spdm_context->connection_info.peer_used_cert_chain[0].buffer,
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

    spdm_context->connection_info.capability.data_transfer_size =
        CHUNK_GET_UNIT_TEST_OVERRIDE_DATA_TRANSFER_SIZE;

    /*set requester small max_spdm_msg_size*/
    spdm_context->connection_info.capability.max_spdm_msg_size = 100;

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request.header.request_response_code = SPDM_GET_MEASUREMENTS;
    spdm_request.header.param1 = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
    spdm_request.header.param2 =
        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS;
    spdm_request.slot_id_param = 0;

    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &spdm_request, sizeof(spdm_request));
    spdm_context->last_spdm_request_size = sizeof(spdm_request);

    assert_int_equal(spdm_context->chunk_context.get.chunk_in_use, false);
    libspdm_acquire_sender_buffer(spdm_context, &message_size, (void**) &message);
    response = message;
    response_size = message_size;
    libspdm_zero_mem(response, response_size);

    status = libspdm_build_response(spdm_context, NULL, false, &response_size, (void**)&response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    transport_header_size = spdm_context->local_context.capability.transport_header_size;

    /* Verify responder returned SPDM_ERROR_CODE_RESPONSE_TOO_LARGE response with chunk_handle == 0
     * and responder is not in chunking mode (get.chunk_in_use). */
    spdm_response = (spdm_error_response_t*) ((uint8_t*)message + transport_header_size);
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);

    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_RESPONSE_TOO_LARGE);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(0, spdm_context->chunk_context.get.chunk_handle);
    assert_int_equal(spdm_context->chunk_context.get.chunk_in_use, false);
    libspdm_release_sender_buffer(spdm_context);

    free(data);
    libspdm_reset_message_m(spdm_context, NULL);
    #if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    #else
    libspdm_asym_free(spdm_context->connection_info.algorithm.base_asym_algo,
                      spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
    #endif
#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP */
}

#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP && LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP

/**
 * Set up a session in the HANDSHAKING state for session-based mut_auth enforcement testing.
 * Returns true on success, false if the test should be skipped (e.g. DHE not configured).
 **/
static bool setup_handshaking_session(libspdm_context_t *spdm_context,
                                      libspdm_session_info_t **session_info_out,
                                      uint32_t *session_id_out)
{
    libspdm_session_info_t *session_info;
    libspdm_secured_message_context_t *secured_ctx;
    const uint32_t session_id = 0xFFFFFFFF;
    uint8_t dummy_shared_secret[LIBSPDM_MAX_SHARED_KEY_SIZE];
    uint8_t dummy_th1[LIBSPDM_MAX_HASH_SIZE];

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;

    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, false);

    secured_ctx = (libspdm_secured_message_context_t*)session_info->secured_message_context;
    if (secured_ctx->shared_key_size == 0) {
        return false;
    }
    libspdm_set_mem(dummy_shared_secret, sizeof(dummy_shared_secret), 0xFF);
    libspdm_copy_mem(secured_ctx->master_secret.shared_secret,
                     sizeof(secured_ctx->master_secret.shared_secret),
                     dummy_shared_secret, secured_ctx->shared_key_size);

    libspdm_set_mem(dummy_th1, sizeof(dummy_th1), 0xAA);
    if (!libspdm_generate_session_handshake_key(session_info->secured_message_context,
                                                dummy_th1)) {
        return false;
    }

    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_SESS_MUT_AUTH;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;

    *session_info_out = session_info;
    *session_id_out = session_id;
    return true;
}

/**
 * Verify that an encrypted response in the sender buffer contains UNEXPECTED_REQUEST.
 * Releases the sender buffer, then acquires the receiver buffer to decrypt and check.
 **/
static void verify_unexpected_request_response(libspdm_context_t *spdm_context,
                                               libspdm_session_info_t *session_info,
                                               void *response, size_t response_size)
{
    libspdm_secured_message_context_t *secured_ctx;
    uint8_t saved_response[LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE];
    void *message;
    size_t message_size;
    void *decoded_msg;
    size_t decoded_msg_size;
    void *scratch_buffer;
    size_t scratch_buffer_size;
    uint32_t *decoded_session_id_ptr;
    bool is_app_msg;
    uint32_t transport_header_size;
    spdm_error_response_t *spdm_response;
    libspdm_return_t status;

    /* Save the encrypted response before releasing the sender buffer. */
    libspdm_copy_mem(saved_response, sizeof(saved_response), response, response_size);
    libspdm_release_sender_buffer(spdm_context);

    /* Reset sequence number so decode uses the same sequence (0) as encode. */
    secured_ctx = (libspdm_secured_message_context_t*)session_info->secured_message_context;
    secured_ctx->handshake_secret.response_handshake_sequence_number = 0;

    /* Load the encrypted response into the receiver buffer. */
    libspdm_acquire_receiver_buffer(spdm_context, &message_size, &message);
    libspdm_copy_mem(message, message_size, saved_response, response_size);

    /* Use the scratch buffer's secure-message section as the decryption output area.
     * With CHUNK_CAP the ciphertext lives in the large-sender-receiver section of the
     * same scratch buffer, so the output size must be capped at secure_message_capacity
     * to avoid the zero-on-entry in libspdm_decode_secured_message overwriting the
     * ciphertext before it is read. */
    transport_header_size = spdm_context->local_context.capability.transport_header_size;
    libspdm_get_scratch_buffer(spdm_context, &scratch_buffer, &scratch_buffer_size);
    decoded_msg = (uint8_t*)scratch_buffer + transport_header_size;
    decoded_msg_size = libspdm_get_scratch_buffer_secure_message_capacity(spdm_context) -
                       transport_header_size;
    decoded_session_id_ptr = NULL;
    is_app_msg = false;

    status = spdm_context->transport_decode_message(
        spdm_context, &decoded_session_id_ptr, &is_app_msg, false,
        response_size, message,
        &decoded_msg_size, &decoded_msg);

    libspdm_release_receiver_buffer(spdm_context);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_non_null(decoded_session_id_ptr);
    spdm_response = (spdm_error_response_t*)decoded_msg;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

/**
 * Test 5: Session-based mutual authentication enforcement for MUT_AUTH_REQUESTED (bit 0).
 * After KEY_EXCHANGE_RSP with MUT_AUTH_REQUESTED, the Responder must only accept FINISH.
 * Expected behavior: any other request produces SPDM_ERROR / UNEXPECTED_REQUEST.
 **/
void libspdm_test_responder_receive_send_rsp_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    spdm_message_header_t spdm_request;
    void *message;
    size_t message_size;
    void *response;
    size_t response_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 5;

    if (!setup_handshaking_session(spdm_context, &session_info, &session_id)) {
        return;
    }
    session_info->mut_auth_requested = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;

    /* Wrong request: GET_VERSION instead of FINISH. */
    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_request.request_response_code = SPDM_GET_VERSION;
    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &spdm_request, sizeof(spdm_request));
    spdm_context->last_spdm_request_size = sizeof(spdm_request);

    libspdm_acquire_sender_buffer(spdm_context, &message_size, &message);
    response = message;
    response_size = message_size;
    libspdm_zero_mem(response, response_size);

    status = libspdm_build_response(spdm_context, &session_id, false, &response_size, &response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    verify_unexpected_request_response(spdm_context, session_info, response, response_size);
}

/**
 * Test 6: Session-based mutual authentication enforcement for
 * MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST (bit 1).
 * After KEY_EXCHANGE_RSP with this bit set, the Responder must only accept
 * GET_ENCAPSULATED_REQUEST. Expected behavior: any other request produces
 * SPDM_ERROR / UNEXPECTED_REQUEST.
 **/
void libspdm_test_responder_receive_send_rsp_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    spdm_message_header_t spdm_request;
    void *message;
    size_t message_size;
    void *response;
    size_t response_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 6;

    if (!setup_handshaking_session(spdm_context, &session_info, &session_id)) {
        return;
    }
    session_info->mut_auth_requested =
        SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST;

    /* Wrong request: GET_VERSION instead of GET_ENCAPSULATED_REQUEST. */
    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_request.request_response_code = SPDM_GET_VERSION;
    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &spdm_request, sizeof(spdm_request));
    spdm_context->last_spdm_request_size = sizeof(spdm_request);

    libspdm_acquire_sender_buffer(spdm_context, &message_size, &message);
    response = message;
    response_size = message_size;
    libspdm_zero_mem(response, response_size);

    status = libspdm_build_response(spdm_context, &session_id, false, &response_size, &response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    verify_unexpected_request_response(spdm_context, session_info, response, response_size);
}

/**
 * Test 7: Session-based mutual authentication enforcement for
 * MUT_AUTH_REQUESTED_WITH_GET_DIGESTS (bit 2).
 * After KEY_EXCHANGE_RSP with this bit set, the Responder must only accept
 * DELIVER_ENCAPSULATED_RESPONSE. Expected behavior: any other request produces
 * SPDM_ERROR / UNEXPECTED_REQUEST.
 **/
void libspdm_test_responder_receive_send_rsp_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    spdm_message_header_t spdm_request;
    void *message;
    size_t message_size;
    void *response;
    size_t response_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 7;

    if (!setup_handshaking_session(spdm_context, &session_info, &session_id)) {
        return;
    }
    session_info->mut_auth_requested =
        SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS;

    /* Wrong request: GET_VERSION instead of DELIVER_ENCAPSULATED_RESPONSE. */
    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_request.request_response_code = SPDM_GET_VERSION;
    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &spdm_request, sizeof(spdm_request));
    spdm_context->last_spdm_request_size = sizeof(spdm_request);

    libspdm_acquire_sender_buffer(spdm_context, &message_size, &message);
    response = message;
    response_size = message_size;
    libspdm_zero_mem(response, response_size);

    status = libspdm_build_response(spdm_context, &session_id, false, &response_size, &response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    verify_unexpected_request_response(spdm_context, session_info, response, response_size);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP && LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP */

int libspdm_rsp_receive_send_test(void)
{
    const struct CMUnitTest test_cases[] = {
        /* response message size is larger than requester data_transfer_size */
        cmocka_unit_test(libspdm_test_responder_receive_send_rsp_case1),
        /* response message size is larger than responder sending transmit buffer size */
        cmocka_unit_test_setup(libspdm_test_responder_receive_send_rsp_case2,
                               libspdm_unit_test_group_setup),
        #if LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES
        /* response message size is larger than responder sending transmit buffer size
         * using the new Vendor Defined Message API */
        cmocka_unit_test_setup(libspdm_test_responder_receive_send_rsp_case3,
                               libspdm_unit_test_group_setup),
        #endif /* LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES */
        /* response message size is larger than requester max_spdm_msg_size */
        cmocka_unit_test_setup(libspdm_test_responder_receive_send_rsp_case4,
                               libspdm_unit_test_group_setup),
        #if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP && LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
        /* session-based mutual auth enforcement: MUT_AUTH_REQUESTED (bit 0) */
        cmocka_unit_test_setup(libspdm_test_responder_receive_send_rsp_case5,
                               libspdm_unit_test_group_setup),
        /* session-based mutual auth enforcement: MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST (bit 1) */
        cmocka_unit_test_setup(libspdm_test_responder_receive_send_rsp_case6,
                               libspdm_unit_test_group_setup),
        /* session-based mutual auth enforcement: MUT_AUTH_REQUESTED_WITH_GET_DIGESTS (bit 2) */
        cmocka_unit_test_setup(libspdm_test_responder_receive_send_rsp_case7,
                               libspdm_unit_test_group_setup),
        #endif /* LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP && LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP */
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

#endif /* LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP */
