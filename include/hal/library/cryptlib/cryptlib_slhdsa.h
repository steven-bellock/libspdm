/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef CRYPTLIB_SLHDSA_H
#define CRYPTLIB_SLHDSA_H

#if LIBSPDM_SLH_DSA_SUPPORT

/**
 * Allocates and initializes one DSA context for subsequent use.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the DSA context that has been initialized.
 **/
extern void *libspdm_slhdsa_new(size_t nid);

/**
 * Release the specified DSA context.
 *
 * @param[in]  dsa_context  Pointer to the DSA context to be released.
 **/
extern void libspdm_slhdsa_free(void *dsa_context);

/**
 * Sets the key component into the established DSA context.
 *
 * @param[in, out]  dsa_context  Pointer to DSA context being set.
 * @param[in]       key_data     Pointer to octet integer buffer.
 * @param[in]       key_size     Size of big number buffer in bytes.
 *
 * @retval  true   DSA key component was set successfully.
 **/
extern bool libspdm_slhdsa_set_pubkey(void *dsa_context, const uint8_t *key_data, size_t key_size);

/**
 * Gets the key component from the established DSA context.
 *
 * @param[in, out]  dsa_context  Pointer to DSA context being set.
 * @param[in]       key_data     Pointer to octet integer buffer.
 * @param[in]       key_size     Size of big number buffer in bytes.
 *
 * @retval  true   DSA key component was set successfully.
 **/
bool libspdm_slhdsa_get_pubkey(void *dsa_context, uint8_t *key_data, size_t *key_size);

/**
 * Sets the key component into the established DSA context.
 *
 * @param[in, out]  dsa_context  Pointer to DSA context being set.
 * @param[in]       key_data     Pointer to octet integer buffer.
 * @param[in]       key_size     Size of big number buffer in bytes.
 *
 * @retval  true   DSA key component was set successfully.
 **/
extern bool libspdm_slhdsa_set_privkey(void *dsa_context, const uint8_t *key_data, size_t key_size);

/**
 * Generates DSA context from DER-encoded public key data.
 *
 * The public key is ASN.1 DER-encoded as RFC7250 describes,
 * namely, the SubjectPublicKeyInfo structure of a X.509 certificate.
 *
 * OID is defined in https://datatracker.ietf.org/doc/draft-ietf-lamps-x509-slhdsa
 *
 * @param[in]  der_data     Pointer to the DER-encoded public key data.
 * @param[in]  der_size     Size of the DER-encoded public key data in bytes.
 * @param[out] dsa_context  Pointer to newly generated DSA context which contains the
 *                          DSA public key component.
 *                          Use libspdm_slhdsa_free() function to free the resource.
 *
 * If der_data is NULL, then return false.
 * If dsa_context is NULL, then return false.
 *
 * @retval  true   DSA context was generated successfully.
 * @retval  false  Invalid DER public key data.
 *
 **/
extern bool libspdm_slhdsa_get_public_key_from_der(const uint8_t *der_data,
                                                   size_t der_size,
                                                   void **dsa_context);

/**
 * Carries out the SLHDSA signature generation.
 *
 * @param[in]      dsa_context   Pointer to DSA context for signature generation.
 * @param[in]      context       The SLHDSA signing context.
 * @param[in]      context_size  Size of SLHDSA signing context.
 * @param[in]      message       Pointer to octet message to be signed.
 * @param[in]      message_size  Size of the message in bytes.
 * @param[out]     signature     Pointer to buffer to receive DSA signature.
 * @param[in, out] sig_size      On input, the size of signature buffer in bytes.
 *                               On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   signature successfully generated.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 * @retval  false  This interface is not supported.
 **/
extern bool libspdm_slhdsa_sign(void *dsa_context,
                                const uint8_t *context, size_t context_size,
                                const uint8_t *message, size_t message_size,
                                uint8_t *signature, size_t *sig_size);

/**
 * Verifies the SLHDSA signature.
 *
 * @param[in]  dsa_context   Pointer to DSA context for signature verification.
 * @param[in]  context       The SLHDSA signing context.
 * @param[in]  context_size  Size of SLHDSA signing context.
 * @param[in]  message       Pointer to octet message to be checked.
 * @param[in]  message_size  Size of the message in bytes.
 * @param[in]  signature     Pointer to DSA signature to be verified.
 * @param[in]  sig_size      Size of signature in bytes.
 *
 * @retval  true   Valid signature encoded.
 * @retval  false  Invalid signature or invalid DSA context.
 **/
extern bool libspdm_slhdsa_verify(void *dsa_context,
                                  const uint8_t *context, size_t context_size,
                                  const uint8_t *message, size_t message_size,
                                  const uint8_t *signature, size_t sig_size);

#endif /* LIBSPDM_SLH_DSA_SUPPORT */
#endif /* CRYPTLIB_SLHDSA_H */
