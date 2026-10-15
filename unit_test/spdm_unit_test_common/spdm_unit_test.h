/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef __SPDM_UNIT_TEST_H__
#define __SPDM_UNIT_TEST_H__

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_responder_lib.h"
#include "library/spdm_transport_test_lib.h"
#include "internal/libspdm_common_lib.h"
#include "internal/libspdm_device_secret_lib.h"
#include "internal/libspdm_secured_message_lib.h"

/* need redefine MAX_MESSAGE_x_BUFFER_SIZE macro if TRANSCRIPT_DATA_SUPPORT is 0,
 * because unit test uses it own way to track transcript. */
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT == 0

#ifndef LIBSPDM_MAX_CERT_CHAIN_SIZE
/* MLDSA - 0x8000, SLHDSA - 0x28000 */
#if ((LIBSPDM_SLH_DSA_SHA2_128S_SUPPORT) || \
    (LIBSPDM_SLH_DSA_SHAKE_128S_SUPPORT) || \
    (LIBSPDM_SLH_DSA_SHA2_128F_SUPPORT) || \
    (LIBSPDM_SLH_DSA_SHAKE_128F_SUPPORT) || \
    (LIBSPDM_SLH_DSA_SHA2_192S_SUPPORT) || \
    (LIBSPDM_SLH_DSA_SHAKE_192S_SUPPORT) || \
    (LIBSPDM_SLH_DSA_SHA2_192F_SUPPORT) || \
    (LIBSPDM_SLH_DSA_SHAKE_192F_SUPPORT) || \
    (LIBSPDM_SLH_DSA_SHA2_256S_SUPPORT) || \
    (LIBSPDM_SLH_DSA_SHAKE_256S_SUPPORT) || \
    (LIBSPDM_SLH_DSA_SHA2_256F_SUPPORT) || \
    (LIBSPDM_SLH_DSA_SHAKE_256F_SUPPORT))
#define LIBSPDM_MAX_CERT_CHAIN_SIZE 0x28000
#elif ((LIBSPDM_ML_DSA_44_SUPPORT) || \
    (LIBSPDM_ML_DSA_65_SUPPORT) || \
    (LIBSPDM_ML_DSA_87_SUPPORT))
#define LIBSPDM_MAX_CERT_CHAIN_SIZE 0x8000
#else
#define LIBSPDM_MAX_CERT_CHAIN_SIZE 0x1000
#endif
#endif /* LIBSPDM_MAX_CERT_CHAIN_SIZE */

#define LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE 0x1000
#define LIBSPDM_MAX_ENDPOINT_INFO_LENGTH 1024

#define LIBSPDM_MAX_MESSAGE_B_BUFFER_SIZE (40 + \
                                           (LIBSPDM_MAX_HASH_SIZE + 4) * SPDM_MAX_SLOT_COUNT + \
                                           LIBSPDM_MAX_CERT_CHAIN_SIZE)

#define LIBSPDM_MAX_MESSAGE_C_BUFFER_SIZE (90 + \
                                           LIBSPDM_MAX_HASH_SIZE * 2 + \
                                           LIBSPDM_RSP_SIGNATURE_DATA_MAX_SIZE + \
                                           SPDM_MAX_OPAQUE_DATA_SIZE)

#define LIBSPDM_MAX_MESSAGE_M_BUFFER_SIZE (63 + SPDM_NONCE_SIZE + \
                                           LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE + \
                                           LIBSPDM_RSP_SIGNATURE_DATA_MAX_SIZE + \
                                           SPDM_MAX_OPAQUE_DATA_SIZE)

#define LIBSPDM_MAX_MESSAGE_K_BUFFER_SIZE (84 + LIBSPDM_REQ_EXCHANGE_DATA_MAX_SIZE + \
                                           LIBSPDM_RSP_EXCHANGE_DATA_MAX_SIZE + \
                                           LIBSPDM_MAX_HASH_SIZE * 2 + \
                                           LIBSPDM_RSP_SIGNATURE_DATA_MAX_SIZE + \
                                           SPDM_MAX_OPAQUE_DATA_SIZE * 2)

#define LIBSPDM_MAX_MESSAGE_F_BUFFER_SIZE (12 + LIBSPDM_MAX_HASH_SIZE * 2 + \
                                           LIBSPDM_REQ_SIGNATURE_DATA_MAX_SIZE + \
                                           SPDM_MAX_OPAQUE_DATA_SIZE * 2)

#define LIBSPDM_MAX_MESSAGE_E_BUFFER_SIZE (20 + SPDM_NONCE_SIZE * 2 + \
                                           LIBSPDM_MAX_ENDPOINT_INFO_LENGTH + \
                                           LIBSPDM_RSP_SIGNATURE_DATA_MAX_SIZE)

#define LIBSPDM_MAX_MESSAGE_L1L2_BUFFER_SIZE \
    (LIBSPDM_MAX_MESSAGE_VCA_BUFFER_SIZE + LIBSPDM_MAX_MESSAGE_M_BUFFER_SIZE)

#define LIBSPDM_MAX_MESSAGE_M1M2_BUFFER_SIZE \
    (LIBSPDM_MAX_MESSAGE_VCA_BUFFER_SIZE + \
     LIBSPDM_MAX_MESSAGE_B_BUFFER_SIZE + LIBSPDM_MAX_MESSAGE_C_BUFFER_SIZE)

#define LIBSPDM_MAX_MESSAGE_TH_BUFFER_SIZE \
    (LIBSPDM_MAX_MESSAGE_VCA_BUFFER_SIZE + \
     LIBSPDM_MAX_MESSAGE_D_BUFFER_SIZE + \
     LIBSPDM_MAX_HASH_SIZE + LIBSPDM_MAX_MESSAGE_K_BUFFER_SIZE + \
     LIBSPDM_MAX_MESSAGE_D_BUFFER_SIZE + \
     LIBSPDM_MAX_HASH_SIZE + LIBSPDM_MAX_MESSAGE_F_BUFFER_SIZE)

#define LIBSPDM_MAX_MESSAGE_IL1IL2_BUFFER_SIZE \
    (LIBSPDM_MAX_MESSAGE_VCA_BUFFER_SIZE + LIBSPDM_MAX_MESSAGE_E_BUFFER_SIZE)


typedef struct {
    size_t max_buffer_size;
    size_t buffer_size;
    uint8_t buffer[LIBSPDM_MAX_MESSAGE_TH_BUFFER_SIZE];
} libspdm_th_managed_buffer_t;

#endif

#define LIBSPDM_TRANSPORT_ADDITIONAL_SIZE    (LIBSPDM_TEST_TRANSPORT_HEADER_SIZE + \
                                              LIBSPDM_TEST_TRANSPORT_TAIL_SIZE)

#ifndef LIBSPDM_SENDER_BUFFER_SIZE
#define LIBSPDM_SENDER_BUFFER_SIZE (0x1100 + \
                                    LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#endif
#ifndef LIBSPDM_RECEIVER_BUFFER_SIZE
#define LIBSPDM_RECEIVER_BUFFER_SIZE (0x1200 + \
                                      LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#endif

/* Maximum size of a single SPDM message.
 * It matches DataTransferSize in SPDM specification. */
#define LIBSPDM_SENDER_DATA_TRANSFER_SIZE (LIBSPDM_SENDER_BUFFER_SIZE - \
                                           LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#define LIBSPDM_RECEIVER_DATA_TRANSFER_SIZE (LIBSPDM_RECEIVER_BUFFER_SIZE - \
                                             LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#define LIBSPDM_DATA_TRANSFER_SIZE LIBSPDM_RECEIVER_DATA_TRANSFER_SIZE

#if (LIBSPDM_SENDER_BUFFER_SIZE > LIBSPDM_RECEIVER_BUFFER_SIZE)
#define LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE LIBSPDM_SENDER_BUFFER_SIZE
#else
#define LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE LIBSPDM_RECEIVER_BUFFER_SIZE
#endif

/* Maximum size of a large SPDM message.
 * If chunk is unsupported, it must be same as DATA_TRANSFER_SIZE.
 * If chunk is supported, it must be larger than DATA_TRANSFER_SIZE.
 * It matches MaxSPDMmsgSize in SPDM specification. */
#ifndef LIBSPDM_MAX_SPDM_MSG_SIZE
#define LIBSPDM_MAX_SPDM_MSG_SIZE 0x1200
#endif

/* Partial certificates can be retrieved from a Requester or Responder and through multiple messages
 * the complete certificate chain can be constructed. This value specifies the maximum size,
 * in bytes, of a partial certificate that can be sent or received.
 */
#ifndef LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN
#define LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN 1024
#endif

/* Partial measurement extension log (MEL) can be retrieved from a Responder and through multiple
 * messages the complete MEL can be constructed. This value specifies the maximum size, in bytes, of
 * a partial MEL that can be sent or received.
 */
#ifndef LIBSPDM_MAX_MEL_BLOCK_LEN
#define LIBSPDM_MAX_MEL_BLOCK_LEN 1024
#endif

extern uint8_t m_libspdm_use_measurement_spec;
extern uint8_t m_libspdm_use_mel_spec;
extern uint32_t m_libspdm_use_measurement_hash_algo;
extern uint32_t m_libspdm_use_hash_algo;
extern uint32_t m_libspdm_use_asym_algo;
extern uint32_t m_libspdm_use_pqc_asym_algo;
extern uint16_t m_libspdm_use_req_asym_algo;
extern uint32_t m_libspdm_use_req_pqc_asym_algo;
extern uint16_t m_libspdm_use_dhe_algo;
extern uint16_t m_libspdm_use_aead_algo;
extern uint16_t m_libspdm_use_key_schedule_algo;
extern uint8_t m_libspdm_use_tcb_hash_value[64];


/* SPDM reserved error code
 * They are for unit test only.
 * Please double check if they are still reserved when a new SPDM spec is published.*/

#define LIBSPDM_ERROR_CODE_RESERVED_00             0x00
#define LIBSPDM_ERROR_CODE_RESERVED_0D             0x0D
#define LIBSPDM_ERROR_CODE_RESERVED_3F             0x3F
#define LIBSPDM_ERROR_CODE_RESERVED_FD             0xFD

#define LIBSPDM_ASSERT_INT_EQUAL_CASE(value, expected, case) { \
        if(value != expected) { \
            fprintf(stderr, "[ERRCODE:%02x] ", case); \
        } \
        assert_int_equal(value, expected); \
};

#define LIBSPDM_TEST_CONTEXT_VERSION 0x1

typedef struct {
    uint32_t version;
    bool is_requester;
    libspdm_device_send_message_func send_message;
    libspdm_device_receive_message_func receive_message;
    void *spdm_context;
    void *scratch_buffer;
    size_t scratch_buffer_size;
    uint32_t case_id;
} libspdm_test_context_t;

int libspdm_unit_test_group_setup(void **state);
int libspdm_unit_test_group_teardown(void **state);

int libspdm_unit_test_reset_context(void **state);
void libspdm_setup_test_context(libspdm_test_context_t *spdm_test_context);
libspdm_test_context_t *libspdm_get_test_context(void);

/* Release the scratch buffer that the test context currently owns and replace it with one sized
 * for the SPDM context's present capabilities. A test that changes max_spdm_msg_size must call
 * this rather than allocating a replacement itself, otherwise the buffer that
 * libspdm_unit_test_group_setup allocated is leaked.
 *
 * spdm_test_context->scratch_buffer must be NULL or a pointer returned by malloc, since this
 * function and libspdm_unit_test_group_teardown both release it with free. */
void libspdm_unit_test_resize_scratch_buffer(libspdm_test_context_t *spdm_test_context);

void libspdm_dump_hex_str(const uint8_t *buffer, size_t buffer_size);
void libspdm_dump_data(const uint8_t *buffer, size_t buffer_size);
void libspdm_dump_hex(const uint8_t *buffer, size_t buffer_size);
bool libspdm_read_input_file(const char *file_name, void **file_data, size_t *file_size);

/* Set to 1 when the unit tests are built with CRYPTO_FAULT_INJECTION ON. */
#ifndef LIBSPDM_CRYPTO_FAULT_INJECTION
#define LIBSPDM_CRYPTO_FAULT_INJECTION 0
#endif

typedef enum
{
    LIBSPDM_ERR_ACQUIRE_SENDER_BUFFER,
    LIBSPDM_ERR_ACQUIRE_RECEIVER_BUFFER,

    /* Crypto backend operations, which need LIBSPDM_CRYPTO_FAULT_INJECTION. */
    LIBSPDM_ERR_CRYPTO_ANY,             /* every operation that can fail */
    LIBSPDM_ERR_CRYPTO_HASH_ALL,
    LIBSPDM_ERR_CRYPTO_HASH_NEW,
    LIBSPDM_ERR_CRYPTO_HASH_INIT,
    LIBSPDM_ERR_CRYPTO_HASH_UPDATE,
    LIBSPDM_ERR_CRYPTO_HASH_FINAL,
    LIBSPDM_ERR_CRYPTO_HASH_DUPLICATE,
    LIBSPDM_ERR_CRYPTO_HMAC,            /* hmac_*: all, new, set_key, update and final */
    LIBSPDM_ERR_CRYPTO_HKDF_EXTRACT,
    LIBSPDM_ERR_CRYPTO_HKDF_EXPAND,     /* hkdf_*_expand and hkdf_*_extract_and_expand */
    LIBSPDM_ERR_CRYPTO_AEAD_ENCRYPT,
    LIBSPDM_ERR_CRYPTO_AEAD_DECRYPT,
    LIBSPDM_ERR_CRYPTO_RANDOM,
    LIBSPDM_ERR_CRYPTO_ASYM_KEY,        /* key contexts and keys, and keys from DER, PEM or X.509 */
    LIBSPDM_ERR_CRYPTO_ASYM_SIGN,
    LIBSPDM_ERR_CRYPTO_ASYM_VERIFY,
    LIBSPDM_ERR_CRYPTO_DHE_NEW,
    LIBSPDM_ERR_CRYPTO_DHE_GENERATE,
    LIBSPDM_ERR_CRYPTO_DHE_COMPUTE,
    LIBSPDM_ERR_CRYPTO_KEM_NEW,
    LIBSPDM_ERR_CRYPTO_KEM_GENERATE,
    LIBSPDM_ERR_CRYPTO_KEM_ENCAPSULATE,
    LIBSPDM_ERR_CRYPTO_KEM_DECAPSULATE,
    LIBSPDM_ERR_CRYPTO_X509_PARSE,      /* asn1_get_tag, x509_get_* and x509_set_date_time */
    LIBSPDM_ERR_CRYPTO_X509_VERIFY,     /* x509_verify_cert and x509_verify_cert_chain */
    LIBSPDM_ERR_CRYPTO_CSR              /* gen_x509_csr and x509_construct_certificate */
} libspdm_error_target_t;

typedef enum
{
    LIBSPDM_ERR_ACTION_FAIL,            /* return false or NULL */
    LIBSPDM_ERR_ACTION_CORRUPT_OUTPUT   /* succeed, then flip one bit of the output */
} libspdm_error_action_t;

/* The target fails every time until it is released. For a crypto target this is
 * libspdm_force_error_ex(target, 0, UINT32_MAX, LIBSPDM_ERR_ACTION_FAIL). */
void libspdm_force_error (libspdm_error_target_t target);

/* Releasing a crypto target also zeroes its counts. Releasing LIBSPDM_ERR_CRYPTO_ANY releases every
 * crypto target. */
void libspdm_release_error (libspdm_error_target_t target);

/* For a crypto target, lets the next skip calls of the target succeed, then applies the action to
 * the count calls after them. */
void libspdm_force_error_ex (libspdm_error_target_t target, uint32_t skip, uint32_t count,
                             libspdm_error_action_t action);

/* Returns the number of calls that the forced error applied to since the target was forced. */
uint32_t libspdm_get_forced_error_count (libspdm_error_target_t target);

/* For a crypto target, returns the number of calls of the target since it was last forced or
 * released, whether or not they failed. */
uint32_t libspdm_get_crypto_call_count (libspdm_error_target_t target);

/* While suspended, crypto calls are neither counted nor failed, for test code that uses crypto
 * itself. Suspensions nest. */
void libspdm_suspend_crypto_errors (void);
void libspdm_resume_crypto_errors (void);

/* Returns whether a buffer target is forced, and counts the error if it is. For the harness's
 * device buffer functions. */
bool libspdm_apply_buffer_error (libspdm_error_target_t target);

void generate_dmtf_event_group(void *buffer, uint8_t *total_bytes, uint32_t attributes,
                               bool inc_event_lost, bool inc_meas_changed,
                               bool inc_meas_pre_update, bool inc_cert_changed);

void generate_dmtf_event_data(void *buffer, uint8_t *total_bytes, uint32_t event_instance_id,
                              uint16_t event_type_id, void *event_detail);

#endif
