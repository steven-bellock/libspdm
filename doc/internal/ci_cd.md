# Goals and Patterns for Continuous Integration

libspdm is designed to be configurable, both at compile time and at run time. Compile time
configuration enables an Integrator to include the minimal amount of code needed for their SPDM
implementation. Run time configuration enables an Integrator to ship an SPDM device that can operate
in a diversity of environments. However, such configurability places a burden on both the library
implementation and the tests that exercise and check that implementation. This document details
goals and patterns for the automated continuous integration pipeline.

## Compile Time Configuration Knobs

libspdm's compile time configuration knobs that can be adjusted within GitHub's runners include:
- Operating Systems
    - Windows
    - Linux
    - macOS
- Host Hardware (CMake `ARCH`)
    - ia32
    - x64
    - aarch64
- Toolchain (CMake `TOOLCHAIN`)
    - Visual Studio
    - GCC
    - CLANG
- Cryptography Library (CMake `CRYPTO`)
    - Mbed TLS
    - OpenSSL
- Build Target (CMake `TARGET`)
    - Release
    - Debug
- Other CMake Configuration Variables
    - `GCOV`
    - `STACK_USAGE`
    - `BUILD_LINUX_SHARED_LIB`
    - `X509_IGNORE_CRITICAL`
    - `DEVICE`
    - `DISABLE_TESTS`
    - `ENABLE_CODEQL`
    - `MARCH`
    - `USING_LTO`
- Code Configuration Macros
    - All of the macros found in
      https://github.com/DMTF/libspdm/blob/main/include/library/spdm_lib_config.h.

Within the scope of libspdm's CMake build system, the operating system, host hardware, cryptography
library, toolchain, and build target are either detected by CMake or supplied as CMake variables.
Code configuration macros are communicated to libspdm via the `spdm_lib_config.h` header or through
compiler `CFLAGS`.

### Configuration Philosophy

Operating system, host hardware, cryptography library, toolchain, and build target exercise the
platform. Code configuration macros exercise the library. They do not interact directly, and so they
are crossed sparsely where every platform is covered against a few configurations, and
configurations are swept on the cheapest platform, where "cheapest" means a platform with high
availability and fast compilation and test execution times. An example would be Linux running on x64
and compiling with GCC.

One exception for sparse platform combinations is that every combination of `ARCH` and `CRYPTO`
should be exercised, since cryptography libraries often utilize hardware-specific instructions.

### Legal Code Configurations

https://github.com/DMTF/libspdm/blob/main/include/internal/libspdm_macro_check.h specifies illegal
code configuration macros, and so test runners must avoid those configurations.

## Tests

### Unit Tests

Basic unit tests include:
- test_spdm_requester
- test_spdm_responder
- test_spdm_crypt
- test_spdm_secured_message
- test_spdm_common
- test_crypt

Extended unit tests include:
- test_spdm_fips
- test_spdm_tpm

For any configuration, run all basic unit tests. Every job should produce a pass / fail signal. For
example, in the case where `DISABLE_TESTS` is asserted, the runner should check that no libspdm
tests were compiled. Reasonable runner timeouts should be specified so that if a test hangs then the
runner will detect the hang and produce a failing result. For example, if a passing test typically
takes five minutes to build and run to completion, then a 30 minute timeout is reasonable.

### Fuzz Tests

TBD

## Test Utilities

### Sanitizers

Address (ASAN) and undefined behavior (UBSAN) sanitizers monitor the execution of production and
test code and flag illegal operations or behavior. For the purpose of continuous integration, they
should produce a pass / fail signal when illegal behavior is detected. In the case of UBSAN, this
may be accomplished by adding `UBSAN_OPTIONS=halt_on_error=1` so that the test exits with a non-zero
return code to alert the runner of a test failure.

### Reproducers

For tiers two and above (see below), it is essential to be able to reproduce the results of a
failing test. This includes capturing platform and code configuration details, capturing the state
of the repository and its submodules, and generating a runnable reproduction script.

## Frequency and Coverage

Time estimates are given in wall clock time, from the start of the first job to end of the last job.
The estimates assume that the maximum number of simultaneous runners is 20 and that the worst case
time to complete a single job is 20 minutes.

### Tier 1 - Pull Request / Push Coverage

Tests and configurations that run with every pull request or push to `main` should exercise the
standard defaults of the library. These are configurations that follow, for example, the unaltered
values in `spdm_lib_config.h`. They should include all of the operating systems, host hardware,
cryptography libraries, toolchains, and build targets listed above, but need not be exhaustive in
their combinations. In addition, the configurations should alter coarse macros present in
`spdm_lib_config.h`, such as `LIBSPDM_FIPS_MODE`, that greatly alter the size and behavior of the
library.

All tier 1 tests must pass before a pull request is merged into `main`.

For execution time, when all tests pass, the total test time on unencumbered GitHub runners should
be less than 30 minutes.

### Tier 2 - Nightly Coverage

This tier expands on the previous tier by increasing the number of legal combinations, and altering
more of the finer-grained code configuration macros. This tier also includes ASAN and UBSAN
monitoring while tests are run. The tests are run against the latest `HEAD` commit on the `main`
branch.

Test failures at this tier point to bugs rising from:
1. Unforeseen combinations of configuration parameters in library or unit test code.
2. Undefined or implementation-defined behavior that may vary based on compiler or operating system.

Since these tests are run nightly, and the number of new commits would be small, a failure should
be fixed the next day.

For execution time, when all tests pass, the total test time on unencumbered GitHub runners should
be less than two hours.

### Tier 3 - Weekly Coverage

This tier expands on the previous tier by exercising, as much as the time allotment allows, more
legal configuration combinations with ASAN and UBSAN monitoring. In addition, code coverage metrics
are collected and published to https://dmtf.github.io/libspdm/coverage_log/. The tests are run
against the latest `HEAD` commit on the `main` branch.

Test failures at this tier point to more obscure bugs that slipped through nightly testing. Also,
since this tier is run weekly, there may be many commits that need to be examined and bisected
before isolating the offending commit. As such, it may take days to isolate and fix the issue.

For execution time, when all tests pass, the total test time on unencumbered GitHub runners should
be less than five hours.

### Tier 4 - Pre-release Coverage

TBD
