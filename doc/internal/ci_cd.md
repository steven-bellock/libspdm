# Goals and Patterns for CI/CD

libspdm is designed to be configurable, both at compile time and at run time. Compile time
configuration enables an Integrator to include the minimal amount of code needed for their SPDM
implementation. Run time configuration enables an Integrator to ship an SPDM device that can operate
in a diversity of environments. However, such configurability places a burden on both the library
implementation and the tests that exercise and check that implementation. This document details
goals and patterns for the automated CI/CD pipeline.

## Compile Time Configuration Knobs

libspdm's compile time configuration knobs that can be adjusted in GitHub's CI/CD include:
- Operating Systems
    - Windows
    - Linux
    - macOS
- Host Hardware
    - x86/x64
    - aarch64
- Cryptography Library
    - Mbed TLS
    - OpenSSL
- Build Target
    - Release
    - Debug
- Code Configuration Macros
    - Includes all of the macros found in
      https://github.com/DMTF/libspdm/blob/main/include/library/spdm_lib_config.h.

Within the scope of libspdm's CMake build system, the operating system, host hardware, cryptography
library, and build target are either detected by CMake or supplied as CMake variables. Code
configuration macros are communicated to libspdm via the `spdm_lib_config.h` header or through
compiler `CFLAGS`.

## Frequency and Coverage

Time estimates are given in wall clock time. Every job should produce a pass / fail signal. For
example, in the case where `DISABLE_TESTS` is asserted, the runner should check that no libspdm
tests were compiled.

### Tier 1 - Pull Request / Push Coverage

Tests and configurations that run with every pull request or push to `main` should exercise the
standard defaults of the library. These are configurations that follow, for example, the unaltered
values in `spdm_lib_config.h`. They should include all of the operating systems, host hardware,
cryptography libraries, and build targets listed above, but need not be exhaustive in their
permutations. In addition, the configurations should alter coarse macros present in
`spdm_lib_config.h`, such as `LIBSPDM_FIPS_MODE`, that greatly alter the size and behavior of the
library.

Operating system, host hardware, cryptography library, and build target exercise the platform. Code
configuration macros exercise the library. They do not interact directly, and so they are crossed
sparsely where every platform is covered against a few configurations, and configurations are swept
on the cheapest platform.

All tier 1 tests must pass before a pull request is merged to `main`.

For execution time, when all tests pass, the total test time on unencumbered GitHub runners should
be less than 20 minutes.

### Tier 2 - Nightly Coverage

This tier expands on the previous tier by increasing the number of permutations, and altering more
of the finer-grained code configuration macros. This tier also includes ASAN and UBSAN monitoring
while tests are run.

Test failures at this tier point to bugs rising from:
1. Unforeseen combinations of configuration parameters in library or unit test code.
2. Undefined or implementation-defined behavior that may vary based on compiler or operating system.

Since these tests are run nightly, and the number of new commits would be small, a failure should
be fixed the next day.

For execution time, when all tests pass, the total test time on unencumbered GitHub runners should
be less than two hours.

### Tier 3 - Weekly Coverage

This tier expands on the previous tier by, as much as time allotment allows, exercising all possible
legal configuration permutations with ASAN and UBSAN monitoring. In addition, code coverage metrics
are collected and published to https://dmtf.github.io/libspdm/coverage_log/.

Test failures at this tier point to more obscure bugs that slipped through nightly testing. Also,
since this tier is run weekly, there may be many commits that need to be examined and bisected
before isolating the offending commit. As such, it may take days to isolate and fix the issue.

For execution time, when all tests pass, the total test time on unencumbered GitHub runners should
be less than five hours.

### Tier 4 - Pre-release Coverage

TBD
