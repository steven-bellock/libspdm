cmake_minimum_required(VERSION 3.16)

# Crypto fault injection for the unit tests, built when CRYPTO_FAULT_INJECTION is ON. The crypto
# backend is compiled with cryptlib_fault_rename.h, so its definitions take the libspdm_real_*
# names, and the forwarders compiled into it take the API names. Every target that links the
# backend therefore calls through the forwarders.

target_sources(cryptlib_${CRYPTO}
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/cryptlib_fault.c
        ${CMAKE_CURRENT_SOURCE_DIR}/cryptlib_fault_forward.c
)

target_include_directories(cryptlib_${CRYPTO} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_compile_definitions(cryptlib_${CRYPTO} PUBLIC LIBSPDM_CRYPTO_FAULT_INJECTION=1)

if(MSVC OR (CMAKE_C_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC"))
    target_compile_options(cryptlib_${CRYPTO}
        PRIVATE "/FI${CMAKE_CURRENT_SOURCE_DIR}/cryptlib_fault_rename.h")
else()
    target_compile_options(cryptlib_${CRYPTO}
        PRIVATE "SHELL:-include ${CMAKE_CURRENT_SOURCE_DIR}/cryptlib_fault_rename.h")
endif()
