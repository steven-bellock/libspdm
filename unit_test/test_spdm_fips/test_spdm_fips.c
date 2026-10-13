/**
 *  Copyright Notice:
 *  Copyright 2023-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "library/spdm_crypt_lib.h"
#include "internal/libspdm_common_lib.h"
#include "internal/libspdm_fips_lib.h"

#if LIBSPDM_FIPS_MODE
uint8_t m_selftest_buffer[0x2000];
#endif

#if (LIBSPDM_FIPS_MODE) && (LIBSPDM_CRYPTO_FAULT_INJECTION)
static void init_selftest_context(libspdm_fips_selftest_context_t *fips_selftest_context)
{
    fips_selftest_context->tested_algo = 0;
    fips_selftest_context->self_test_result = 0;
    fips_selftest_context->selftest_buffer = m_selftest_buffer;
    fips_selftest_context->selftest_buffer_size = sizeof(m_selftest_buffer);
}

/* Runs the self-tests on a new context, applying the action to one crypto call after skipping
 * call_index of them. Returns whether the self-tests passed, the number of calls that the action
 * applied to, the number of crypto calls made, and the self-tests that ran and failed. */
static bool run_selftest_with_error(uint32_t call_index, libspdm_error_action_t action,
                                    uint32_t *error_count, uint32_t *call_count,
                                    uint32_t *failed_tests)
{
    libspdm_fips_selftest_context_t fips_selftest_context;
    bool result;

    init_selftest_context(&fips_selftest_context);
    libspdm_force_error_ex(LIBSPDM_ERR_CRYPTO_ANY, call_index, 1, action);
    result = libspdm_fips_run_selftest(&fips_selftest_context);
    *error_count = libspdm_get_forced_error_count(LIBSPDM_ERR_CRYPTO_ANY);
    *call_count = libspdm_get_crypto_call_count(LIBSPDM_ERR_CRYPTO_ANY);
    libspdm_release_error(LIBSPDM_ERR_CRYPTO_ANY);
    *failed_tests = fips_selftest_context.tested_algo & ~fips_selftest_context.self_test_result;

    return result;
}

/* Returns the number of crypto calls that the self-tests make on a new context. */
static uint32_t count_selftest_crypto_calls(void)
{
    libspdm_fips_selftest_context_t fips_selftest_context;
    uint32_t call_count;

    init_selftest_context(&fips_selftest_context);
    libspdm_release_error(LIBSPDM_ERR_CRYPTO_ANY);
    assert_true(libspdm_fips_run_selftest(&fips_selftest_context));
    call_count = libspdm_get_crypto_call_count(LIBSPDM_ERR_CRYPTO_ANY);
    libspdm_release_error(LIBSPDM_ERR_CRYPTO_ANY);

    return call_count;
}
#endif /* (LIBSPDM_FIPS_MODE) && (LIBSPDM_CRYPTO_FAULT_INJECTION) */

/**
 * Test 1: Run the self-tests on a context where none of them have run.
 * Expected behavior: every self-test runs and passes, so libspdm_fips_run_selftest returns true.
 **/
static void libspdm_test_fips_case1(void **state)
{
#if LIBSPDM_FIPS_MODE
    libspdm_fips_selftest_context_t fips_selftest_context;

    fips_selftest_context.tested_algo = 0;
    fips_selftest_context.self_test_result = 0;
    fips_selftest_context.selftest_buffer = m_selftest_buffer;
    fips_selftest_context.selftest_buffer_size = sizeof(m_selftest_buffer);

    assert_true(libspdm_fips_run_selftest(&fips_selftest_context));
#else
    skip();
#endif
}

/**
 * Test 2: Run the self-tests again on a context where all of them have run and passed.
 * Expected behavior: each self-test finds its bit set in tested_algo and returns without running
 * again, so libspdm_fips_run_selftest returns true and leaves the context unchanged.
 **/
static void libspdm_test_fips_case2(void **state)
{
#if LIBSPDM_FIPS_MODE
    libspdm_fips_selftest_context_t fips_selftest_context;
    uint32_t tested_algo;
    uint32_t self_test_result;

    fips_selftest_context.tested_algo = 0;
    fips_selftest_context.self_test_result = 0;
    fips_selftest_context.selftest_buffer = m_selftest_buffer;
    fips_selftest_context.selftest_buffer_size = sizeof(m_selftest_buffer);

    /* Every self-test runs and passes. */
    assert_true(libspdm_fips_run_selftest(&fips_selftest_context));
    tested_algo = fips_selftest_context.tested_algo;
    self_test_result = fips_selftest_context.self_test_result;

    assert_true(libspdm_fips_run_selftest(&fips_selftest_context));
    assert_int_equal(fips_selftest_context.tested_algo, tested_algo);
    assert_int_equal(fips_selftest_context.self_test_result, self_test_result);
#else
    skip();
#endif
}

/**
 * Test 3: Run the self-tests on a context that records a failed AES-GCM self-test.
 * Expected behavior: each self-test finds that an earlier self-test failed and returns without
 * running, so libspdm_fips_run_selftest returns false and leaves the context unchanged.
 **/
static void libspdm_test_fips_case3(void **state)
{
#if LIBSPDM_FIPS_MODE
    libspdm_fips_selftest_context_t fips_selftest_context;

    /* The AES-GCM self-test ran and failed. */
    fips_selftest_context.tested_algo = LIBSPDM_FIPS_SELF_TEST_AES_GCM;
    fips_selftest_context.self_test_result = 0;
    fips_selftest_context.selftest_buffer = m_selftest_buffer;
    fips_selftest_context.selftest_buffer_size = sizeof(m_selftest_buffer);

    assert_false(libspdm_fips_run_selftest(&fips_selftest_context));
    assert_int_equal(fips_selftest_context.tested_algo, LIBSPDM_FIPS_SELF_TEST_AES_GCM);
    assert_int_equal(fips_selftest_context.self_test_result, 0);
#else
    skip();
#endif
}

/**
 * Test 4: Run the self-tests once for each crypto call that they make, failing that call.
 * Expected behavior: the self-test that makes the call fails without making another crypto call,
 * and the self-tests after it return early, so libspdm_fips_run_selftest returns false every time.
 * Skipped if LIBSPDM_FIPS_MODE is disabled or CRYPTO_FAULT_INJECTION is OFF.
 **/
static void libspdm_test_fips_case4(void **state)
{
#if (LIBSPDM_FIPS_MODE) && (LIBSPDM_CRYPTO_FAULT_INJECTION)
    uint32_t call_count;
    uint32_t call_index;
    uint32_t error_count;
    uint32_t run_call_count;
    uint32_t failed_tests;
    bool result;

    call_count = count_selftest_crypto_calls();
    assert_int_not_equal(call_count, 0);

    for (call_index = 0; call_index < call_count; call_index++) {
        /* {ERROR} One crypto call fails. */
        result = run_selftest_with_error(call_index, LIBSPDM_ERR_ACTION_FAIL, &error_count,
                                         &run_call_count, &failed_tests);

        assert_int_equal(error_count, 1);
        assert_false(result);
        /* Exactly one self-test failed, and the failed call was the last crypto call. */
        assert_int_not_equal(failed_tests, 0);
        assert_int_equal(failed_tests & (failed_tests - 1), 0);
        assert_int_equal(run_call_count, call_index + 1);
    }
#else
    skip();
#endif
}

/**
 * Test 5: Run the self-tests once for each crypto call that they make, corrupting the output of
 * that call if it has one.
 * Expected behavior: the self-test that makes the call detects the corrupted output, so
 * libspdm_fips_run_selftest returns false every time an output is corrupted, and only that
 * self-test fails.
 * Skipped if LIBSPDM_FIPS_MODE is disabled or CRYPTO_FAULT_INJECTION is OFF.
 **/
static void libspdm_test_fips_case5(void **state)
{
#if (LIBSPDM_FIPS_MODE) && (LIBSPDM_CRYPTO_FAULT_INJECTION)
    uint32_t call_count;
    uint32_t call_index;
    uint32_t error_count;
    uint32_t run_call_count;
    uint32_t failed_tests;
    uint32_t corrupted_count;
    bool result;

    call_count = count_selftest_crypto_calls();
    assert_int_not_equal(call_count, 0);

    corrupted_count = 0;
    for (call_index = 0; call_index < call_count; call_index++) {
        /* {ERROR} The output of one crypto call is corrupted. */
        result = run_selftest_with_error(call_index, LIBSPDM_ERR_ACTION_CORRUPT_OUTPUT,
                                         &error_count, &run_call_count, &failed_tests);
        if (error_count == 0) {
            /* The call has no output to corrupt. */
            assert_true(result);
            continue;
        }

        assert_int_equal(error_count, 1);
        assert_false(result);
        assert_int_not_equal(failed_tests, 0);
        assert_int_equal(failed_tests & (failed_tests - 1), 0);
        corrupted_count++;
    }
    assert_int_not_equal(corrupted_count, 0);
#else
    skip();
#endif
}

int libspdm_crypt_lib_setup(void **state)
{
    return 0;
}

int libspdm_crypt_lib_teardown(void **state)
{
    return 0;
}

int libspdm_crypt_lib_test_main(void)
{
    const struct CMUnitTest spdm_crypt_lib_tests[] = {
        cmocka_unit_test(libspdm_test_fips_case1),
        cmocka_unit_test(libspdm_test_fips_case2),
        cmocka_unit_test(libspdm_test_fips_case3),
        cmocka_unit_test(libspdm_test_fips_case4),
        cmocka_unit_test(libspdm_test_fips_case5),
    };

    return cmocka_run_group_tests(spdm_crypt_lib_tests,
                                  libspdm_crypt_lib_setup,
                                  libspdm_crypt_lib_teardown);
}

int main(void)
{
    int return_value = 0;

    if (libspdm_crypt_lib_test_main() != 0) {
        return_value = 1;
    }

    return return_value;
}
