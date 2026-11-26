/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"

#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && \
    (LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP)

/* CHALLENGE for the Requester's provisioned public key. */
static spdm_challenge_request_t m_libspdm_challenge_request_err1 = {
    {SPDM_MESSAGE_VERSION_11, SPDM_CHALLENGE, 0xFF,
     SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH},
};

/**
 * Test 1: Error case, the Responder requests the Requester's provisioned public key (SlotID 0xFF),
 * but the Requester does not set PUB_KEY_ID_CAP.
 * Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_INVALID_REQUEST.
 **/
static void req_encap_challenge_auth_err_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;
    void *data;
    size_t data_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    /* {ERROR} The Requester does not set PUB_KEY_ID_CAP. */
    spdm_context->local_context.capability.flags = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP;

    if (!libspdm_read_requester_public_key(m_libspdm_use_req_asym_algo, &data, &data_size)) {
        assert_true(false);
        return;
    }
    spdm_context->local_context.local_public_key_provision = data;
    spdm_context->local_context.local_public_key_provision_size = data_size;

    response_size = sizeof(response);
    status = libspdm_get_encap_response_challenge_auth(
        spdm_context, sizeof(m_libspdm_challenge_request_err1), &m_libspdm_challenge_request_err1,
        &response_size, response);

    spdm_context->local_context.local_public_key_provision = NULL;
    spdm_context->local_context.local_public_key_provision_size = 0;
    free(data);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_11);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

/**
 * Test 2: Error case, the Responder requests the Requester's provisioned public key (SlotID 0xFF)
 * and the Requester sets PUB_KEY_ID_CAP, but the Integrator has not provisioned the public key.
 * Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_UNSPECIFIED.
 **/
static void req_encap_challenge_auth_err_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP;
    /* {ERROR} The Integrator has not provisioned the public key. */
    spdm_context->local_context.local_public_key_provision = NULL;
    spdm_context->local_context.local_public_key_provision_size = 0;

    response_size = sizeof(response);
    status = libspdm_get_encap_response_challenge_auth(
        spdm_context, sizeof(m_libspdm_challenge_request_err1), &m_libspdm_challenge_request_err1,
        &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_11);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSPECIFIED);
    assert_int_equal(spdm_response->header.param2, 0);
}

int libspdm_req_encap_challenge_auth_error_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(req_encap_challenge_auth_err_case1),
        cmocka_unit_test(req_encap_challenge_auth_err_case2),
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

#endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (..) */
