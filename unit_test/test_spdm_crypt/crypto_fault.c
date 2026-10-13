/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "hal/library/cryptlib.h"

/* Tests of the crypto error targets of libspdm_force_error() and their counts. */

#if (LIBSPDM_CRYPTO_FAULT_INJECTION) && (LIBSPDM_SHA256_SUPPORT)
static const uint8_t m_data[] = {'f', 'a', 'u', 'l', 't'};

/* Hashes m_data with SHA-256, and returns whether the hash succeeded. */
static bool hash_data(uint8_t *digest)
{
    return libspdm_sha256_hash_all(m_data, sizeof(m_data), digest);
}
#endif /* (LIBSPDM_CRYPTO_FAULT_INJECTION) && (LIBSPDM_SHA256_SUPPORT) */

/**
 * Test 1: Force a crypto target.
 * Expected behavior: every call of the target fails until it is released, and the forced error
 * count is the number of calls that failed.
 * Skipped if CRYPTO_FAULT_INJECTION is OFF or LIBSPDM_SHA256_SUPPORT is disabled.
 **/
static void libspdm_test_crypto_fault_case1(void **state)
{
#if (LIBSPDM_CRYPTO_FAULT_INJECTION) && (LIBSPDM_SHA256_SUPPORT)
    uint8_t digest[LIBSPDM_SHA256_DIGEST_SIZE];
    bool result1;
    bool result2;
    uint32_t error_count;

    libspdm_force_error(LIBSPDM_ERR_CRYPTO_HASH_ALL);
    result1 = hash_data(digest);
    result2 = hash_data(digest);
    error_count = libspdm_get_forced_error_count(LIBSPDM_ERR_CRYPTO_HASH_ALL);
    libspdm_release_error(LIBSPDM_ERR_CRYPTO_HASH_ALL);

    assert_false(result1);
    assert_false(result2);
    assert_int_equal(error_count, 2);
    assert_true(hash_data(digest));
#else
    skip();
#endif /* (LIBSPDM_CRYPTO_FAULT_INJECTION) && (LIBSPDM_SHA256_SUPPORT) */
}

/**
 * Test 2: Force a crypto target to fail one call after skipping two.
 * Expected behavior: the first two calls and the fourth succeed, the third fails, and the call
 * count includes all four.
 * Skipped if CRYPTO_FAULT_INJECTION is OFF or LIBSPDM_SHA256_SUPPORT is disabled.
 **/
static void libspdm_test_crypto_fault_case2(void **state)
{
#if (LIBSPDM_CRYPTO_FAULT_INJECTION) && (LIBSPDM_SHA256_SUPPORT)
    uint8_t digest[LIBSPDM_SHA256_DIGEST_SIZE];
    bool result[4];
    uint32_t error_count;
    uint32_t call_count;
    size_t index;

    libspdm_force_error_ex(LIBSPDM_ERR_CRYPTO_HASH_ALL, 2, 1, LIBSPDM_ERR_ACTION_FAIL);
    for (index = 0; index < LIBSPDM_ARRAY_SIZE(result); index++) {
        result[index] = hash_data(digest);
    }
    error_count = libspdm_get_forced_error_count(LIBSPDM_ERR_CRYPTO_HASH_ALL);
    call_count = libspdm_get_crypto_call_count(LIBSPDM_ERR_CRYPTO_HASH_ALL);
    libspdm_release_error(LIBSPDM_ERR_CRYPTO_HASH_ALL);

    assert_true(result[0]);
    assert_true(result[1]);
    assert_false(result[2]);
    assert_true(result[3]);
    assert_int_equal(error_count, 1);
    assert_int_equal(call_count, 4);
#else
    skip();
#endif /* (LIBSPDM_CRYPTO_FAULT_INJECTION) && (LIBSPDM_SHA256_SUPPORT) */
}

/**
 * Test 3: Force LIBSPDM_ERR_CRYPTO_ANY to fail the second call.
 * Expected behavior: the second crypto call fails, whatever its operation is, and the call count of
 * LIBSPDM_ERR_CRYPTO_ANY includes calls of every operation.
 * Skipped if CRYPTO_FAULT_INJECTION is OFF or LIBSPDM_SHA256_SUPPORT is disabled.
 **/
static void libspdm_test_crypto_fault_case3(void **state)
{
#if (LIBSPDM_CRYPTO_FAULT_INJECTION) && (LIBSPDM_SHA256_SUPPORT)
    uint8_t digest[LIBSPDM_SHA256_DIGEST_SIZE];
    void *sha256_context;
    bool result;
    uint32_t error_count;
    uint32_t call_count;

    libspdm_force_error_ex(LIBSPDM_ERR_CRYPTO_ANY, 1, 1, LIBSPDM_ERR_ACTION_FAIL);
    sha256_context = libspdm_sha256_new();
    result = libspdm_sha256_init(sha256_context);
    error_count = libspdm_get_forced_error_count(LIBSPDM_ERR_CRYPTO_ANY);
    call_count = libspdm_get_crypto_call_count(LIBSPDM_ERR_CRYPTO_ANY);
    libspdm_release_error(LIBSPDM_ERR_CRYPTO_ANY);
    libspdm_sha256_free(sha256_context);

    assert_false(result);
    assert_int_equal(error_count, 1);
    assert_int_equal(call_count, 2);
    assert_true(hash_data(digest));
#else
    skip();
#endif /* (LIBSPDM_CRYPTO_FAULT_INJECTION) && (LIBSPDM_SHA256_SUPPORT) */
}

/**
 * Test 4: Call a forced crypto target while crypto errors are suspended.
 * Expected behavior: the call succeeds and is not counted, and the target fails again once crypto
 * errors are resumed.
 * Skipped if CRYPTO_FAULT_INJECTION is OFF or LIBSPDM_SHA256_SUPPORT is disabled.
 **/
static void libspdm_test_crypto_fault_case4(void **state)
{
#if (LIBSPDM_CRYPTO_FAULT_INJECTION) && (LIBSPDM_SHA256_SUPPORT)
    uint8_t digest[LIBSPDM_SHA256_DIGEST_SIZE];
    bool suspended_result;
    uint32_t suspended_call_count;
    bool resumed_result;

    libspdm_force_error(LIBSPDM_ERR_CRYPTO_HASH_ALL);
    libspdm_suspend_crypto_errors();
    libspdm_suspend_crypto_errors();
    suspended_result = hash_data(digest);
    libspdm_resume_crypto_errors();
    suspended_result = suspended_result && hash_data(digest);
    suspended_call_count = libspdm_get_crypto_call_count(LIBSPDM_ERR_CRYPTO_HASH_ALL);
    libspdm_resume_crypto_errors();
    resumed_result = hash_data(digest);
    libspdm_release_error(LIBSPDM_ERR_CRYPTO_HASH_ALL);

    assert_true(suspended_result);
    assert_int_equal(suspended_call_count, 0);
    assert_false(resumed_result);
#else
    skip();
#endif /* (LIBSPDM_CRYPTO_FAULT_INJECTION) && (LIBSPDM_SHA256_SUPPORT) */
}

/**
 * Test 5: Corrupt the output of a crypto call.
 * Expected behavior: the call succeeds, and its output differs from the correct output only in the
 * lowest bit of the first byte.
 * Skipped if CRYPTO_FAULT_INJECTION is OFF or LIBSPDM_SHA256_SUPPORT is disabled.
 **/
static void libspdm_test_crypto_fault_case5(void **state)
{
#if (LIBSPDM_CRYPTO_FAULT_INJECTION) && (LIBSPDM_SHA256_SUPPORT)
    uint8_t digest[LIBSPDM_SHA256_DIGEST_SIZE];
    uint8_t corrupted_digest[LIBSPDM_SHA256_DIGEST_SIZE];
    bool result;
    uint32_t error_count;

    assert_true(hash_data(digest));

    libspdm_force_error_ex(LIBSPDM_ERR_CRYPTO_HASH_ALL, 0, 1, LIBSPDM_ERR_ACTION_CORRUPT_OUTPUT);
    result = hash_data(corrupted_digest);
    error_count = libspdm_get_forced_error_count(LIBSPDM_ERR_CRYPTO_HASH_ALL);
    libspdm_release_error(LIBSPDM_ERR_CRYPTO_HASH_ALL);

    assert_true(result);
    assert_int_equal(error_count, 1);
    assert_int_equal(corrupted_digest[0], digest[0] ^ 0x01);
    assert_memory_equal(corrupted_digest + 1, digest + 1, sizeof(digest) - 1);
#else
    skip();
#endif /* (LIBSPDM_CRYPTO_FAULT_INJECTION) && (LIBSPDM_SHA256_SUPPORT) */
}

/**
 * Test 6: Force LIBSPDM_ERR_ACTION_CORRUPT_OUTPUT on an operation that has no output to corrupt.
 * Expected behavior: the call succeeds and the forced error count stays 0.
 * Skipped if CRYPTO_FAULT_INJECTION is OFF or LIBSPDM_SHA256_SUPPORT is disabled.
 **/
static void libspdm_test_crypto_fault_case6(void **state)
{
#if (LIBSPDM_CRYPTO_FAULT_INJECTION) && (LIBSPDM_SHA256_SUPPORT)
    void *sha256_context;
    bool result;
    uint32_t error_count;

    sha256_context = libspdm_sha256_new();
    assert_non_null(sha256_context);

    libspdm_force_error_ex(LIBSPDM_ERR_CRYPTO_HASH_INIT, 0, 1, LIBSPDM_ERR_ACTION_CORRUPT_OUTPUT);
    result = libspdm_sha256_init(sha256_context);
    error_count = libspdm_get_forced_error_count(LIBSPDM_ERR_CRYPTO_HASH_INIT);
    libspdm_release_error(LIBSPDM_ERR_CRYPTO_HASH_INIT);
    libspdm_sha256_free(sha256_context);

    assert_true(result);
    assert_int_equal(error_count, 0);
#else
    skip();
#endif /* (LIBSPDM_CRYPTO_FAULT_INJECTION) && (LIBSPDM_SHA256_SUPPORT) */
}

/**
 * Test 7: Fail libspdm_x509_get_validity.
 * Expected behavior: it returns false with both sizes 0, which its header defines as a failure,
 * rather than as a buffer that is too small.
 * Skipped if CRYPTO_FAULT_INJECTION is OFF or LIBSPDM_CERT_PARSE_SUPPORT is disabled.
 **/
static void libspdm_test_crypto_fault_case7(void **state)
{
#if (LIBSPDM_CRYPTO_FAULT_INJECTION) && (LIBSPDM_CERT_PARSE_SUPPORT)
    uint8_t cert[1];
    uint8_t from[64];
    size_t from_size;
    uint8_t to[64];
    size_t to_size;
    bool result;
    uint32_t error_count;

    cert[0] = 0;
    from_size = sizeof(from);
    to_size = sizeof(to);

    libspdm_force_error(LIBSPDM_ERR_CRYPTO_X509_PARSE);
    result = libspdm_x509_get_validity(cert, sizeof(cert), from, &from_size, to, &to_size);
    error_count = libspdm_get_forced_error_count(LIBSPDM_ERR_CRYPTO_X509_PARSE);
    libspdm_release_error(LIBSPDM_ERR_CRYPTO_X509_PARSE);

    assert_false(result);
    assert_int_equal(error_count, 1);
    assert_int_equal(from_size, 0);
    assert_int_equal(to_size, 0);
#else
    skip();
#endif /* (LIBSPDM_CRYPTO_FAULT_INJECTION) && (LIBSPDM_CERT_PARSE_SUPPORT) */
}

/**
 * Test 8: Release LIBSPDM_ERR_CRYPTO_ANY while another crypto target is forced.
 * Expected behavior: the other target is released too, so its next call succeeds.
 * Skipped if CRYPTO_FAULT_INJECTION is OFF or LIBSPDM_SHA256_SUPPORT is disabled.
 **/
static void libspdm_test_crypto_fault_case8(void **state)
{
#if (LIBSPDM_CRYPTO_FAULT_INJECTION) && (LIBSPDM_SHA256_SUPPORT)
    uint8_t digest[LIBSPDM_SHA256_DIGEST_SIZE];

    libspdm_force_error(LIBSPDM_ERR_CRYPTO_HASH_ALL);
    libspdm_release_error(LIBSPDM_ERR_CRYPTO_ANY);

    assert_true(hash_data(digest));
#else
    skip();
#endif /* (LIBSPDM_CRYPTO_FAULT_INJECTION) && (LIBSPDM_SHA256_SUPPORT) */
}

int libspdm_crypto_fault_test_main(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(libspdm_test_crypto_fault_case1),
        cmocka_unit_test(libspdm_test_crypto_fault_case2),
        cmocka_unit_test(libspdm_test_crypto_fault_case3),
        cmocka_unit_test(libspdm_test_crypto_fault_case4),
        cmocka_unit_test(libspdm_test_crypto_fault_case5),
        cmocka_unit_test(libspdm_test_crypto_fault_case6),
        cmocka_unit_test(libspdm_test_crypto_fault_case7),
        cmocka_unit_test(libspdm_test_crypto_fault_case8),
    };

    return cmocka_run_group_tests(test_cases, NULL, NULL);
}
