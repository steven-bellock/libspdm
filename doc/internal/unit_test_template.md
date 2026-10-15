# Unit Test Template

This document specifies naming schemes, patterns, and layouts for unit tests in
https://github.com/DMTF/libspdm/tree/main/unit_test.

## Test File Names

### Requester / Responder

Test file names for non-encapsulated messages take the form *message_name*.c, where `message_name`
is the request message for Requester tests and response message for Responder tests.

```
// Unit test file names for CHALLENGE request and CHALLENGE_AUTH response.
test_spdm_requester/challenge.c
test_spdm_responder/challenge_auth.c
```

Test file names for encapsulated messages take the form encap_*message_name*.c where `message_name`
is the encapsulated response message for Requester tests and encapsulated request message for
Responder tests.

```
// Unit test file names for encapsulated CHALLENGE_AUTH response and encapsulated CHALLENGE request.
test_spdm_requester/encap_challenge_auth.c
test_spdm_responder/encap_challenge.c
```

#### Error Tests

Test file names for error tests take the form *message_name*\_err.c or encap_*message_name*_err.c.
The files are stored in the `error_test/` directory.

```
// Error unit test file names for CHALLENGE request and CHALLENGE_AUTH response.
test_spdm_requester/error_test/challenge_err.c
test_spdm_responder/error_test/challenge_auth_err.c

// Error unit test file names for encapsulated CHALLENGE_AUTH response and encapsulated CHALLENGE
// request.
test_spdm_requester/error_test/encap_challenge_auth_err.c
test_spdm_responder/error_test/encap_challenge_err.c
```

## Test Layout

Variables with external linkage (global variables) use the `g_` prefix. Variables at file scope use
the `m_` prefix.

In the patterns below, `message_name` is replaced with the name of the message. For example,
Requester testing of the `CHALLENGE` message yields

```C
int libspdm_req_challenge_test(void)
```

### Requester

#### Non-encapsulated Request Messages

```C
extern uint32_t g_some_global_variable;
static uint32_t m_some_file_scope_variable;

static libspdm_return_t send_message(
    void *spdm_context, size_t request_size, const void *request, uint64_t timeout)
{
}

static libspdm_return_t receive_message(
    void *spdm_context, size_t *response_size, void **response, uint64_t timeout)
{
}

/**
 * Test 1: describe the test case.
 * Expected behavior: describe the expected behavior of the unit under test.
 **/
static void req_message_name_case1(void **state)
{
}

int libspdm_req_message_name_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(req_message_name_case1),
    };

    libspdm_test_context_t test_context = {
        LIBSPDM_TEST_CONTEXT_VERSION,
        true,
        send_message,
        receive_message,
    };

    libspdm_setup_test_context(&test_context);

    return cmocka_run_group_tests(test_cases,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}
```

#### Encapsulated Response Messages

Naming pattern is the same as the pattern for the Responder's non-encapsulated messages with the
following differences:
- `rsp` becomes `req`
- `encap_` precedes `message_name`

For example
```C
int libspdm_req_encap_message_name_test(void)
```

### Responder

#### Non-encapsulated Response Messages

```C
/**
 * Test 1: describe the test case.
 * Expected behavior: describe the expected behavior of the unit under test.
 **/
static void rsp_message_name_case1(void **state)
{
}

int libspdm_rsp_message_name_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(rsp_message_name_case1),
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
```

#### Encapsulated Request Messages

Naming pattern is the same as the pattern for the Requester's non-encapsulated messages with the
following differences:
- `req` becomes `rsp`
- `encap_` precedes `message_name`

For example
```C
int libspdm_rsp_encap_message_name_test(void)
```

### Error Tests

Naming patterns are the same as the non-error tests with the following differences:
- the name of the entry function takes the form `*_error_test`
- the name of test cases take the form `*_err_case*`

For example
```C
/**
 * Test 1: describe the test case.
 * Expected behavior: describe the expected behavior of the unit under test.
 **/
static void rsp_message_name_err_case1(void **state)
{
}

int libspdm_rsp_message_name_error_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(rsp_message_name_err_case1),
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
```

When an error condition is injected, a comment should also accompany the error condition. The
comment should begin with the `{ERROR}` token.

For example
```C
set_standard_state(spdm_context);

/* {ERROR} Responder is not an event notifier. */
spdm_context->local_context.capability.flags &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EVENT_CAP;

spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_13;
spdm_request.header.request_response_code = SPDM_GET_SUPPORTED_EVENT_TYPES;
spdm_request.header.param1 = 0;
spdm_request.header.param2 = 0;
```

### Cryptography Error Tests

When the unit tests are built with `CRYPTO_FAULT_INJECTION` ON (see [test.md](../test.md)), a test
can make calls into the cryptography backend fail. `libspdm_force_error()` with a
`LIBSPDM_ERR_CRYPTO_*` target makes every call of that operation fail until the target is released,
while `libspdm_force_error_ex()` instead applies `LIBSPDM_ERR_ACTION_FAIL` or
`LIBSPDM_ERR_ACTION_CORRUPT_OUTPUT` to some calls, after skipping others.

Write cryptography error tests as follows:
- Force the error immediately before the call under test, so that the calls of the setup are not
  counted.
- Read `libspdm_get_forced_error_count()` and release the target before asserting anything, because
  a failed assert leaves the test, and a target that is still forced fails the later tests.
- Assert the forced error count, so that the test fails if the call under test stops making the
  cryptography call.
- Guard the test with `#if LIBSPDM_CRYPTO_FAULT_INJECTION`, and call `skip()` in the `#else` branch.
- Call `libspdm_suspend_crypto_errors()` and `libspdm_resume_crypto_errors()` around test code that
  uses cryptography itself, so that its cryptography calls neither count nor fail.

For example
```C
/**
 * Test 1: describe the test case.
 * Expected behavior: describe the expected behavior of the unit under test.
 * Skipped if CRYPTO_FAULT_INJECTION is OFF.
 **/
static void rsp_message_name_err_case1(void **state)
{
#if LIBSPDM_CRYPTO_FAULT_INJECTION
    ...

    /* {ERROR} The random number generator fails. */
    libspdm_force_error(LIBSPDM_ERR_CRYPTO_RANDOM);
    status = ...;
    error_count = libspdm_get_forced_error_count(LIBSPDM_ERR_CRYPTO_RANDOM);
    libspdm_release_error(LIBSPDM_ERR_CRYPTO_RANDOM);

    assert_int_equal(error_count, 1);
    assert_int_equal(status, LIBSPDM_STATUS_LOW_ENTROPY);
#else
    skip();
#endif /* LIBSPDM_CRYPTO_FAULT_INJECTION */
}
```
