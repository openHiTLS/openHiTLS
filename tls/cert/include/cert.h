/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef CERT_H
#define CERT_H

#include <stdint.h>
#include "hitls_type.h"
#include "hitls_cert_type.h"
#include "cipher_suite.h"
#include "cert_mgr.h"
#include "tls.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TLS_DEFAULT_VERIFY_DEPTH 20u

#define MAX_PASS_LEN 256

/* tls.handshake.certificate_length Length of a label */
#define CERT_LEN_TAG_SIZE 3u

/* Used to transfer certificate data in ASN.1 DER format. */
typedef struct CertItem {
    uint32_t dataSize;      /* Data length */
    uint8_t *data;          /* Data content */
    struct CertItem *next;
} CERT_Item;

/**
 * @ingroup hitls_cert_type
 * @brief   used to transfer the signature parameter
 */
typedef struct {
    HITLS_SignAlgo signAlgo;    /* signature algorithm */
    HITLS_HashAlgo hashAlgo;    /* hash algorithm */
    const uint8_t *data;        /* signed data */
    uint32_t dataLen;           /* length of the signed data */
    uint8_t *sign;              /* sign */
    uint32_t signLen;           /* signature length */
} CERT_SignParam;

/**
 * @brief Check if signature algorithm is allowed by protocol version and security policy
 *
 * This function performs comprehensive checks on signature algorithms:
 * - Check if algorithm is in the allowed list (basic intersection)
 * - Security policy compliance (via SECURITY_SslCheck)
 * - TLS 1.3 restrictions (no RSA PKCS#1 v1.5, DSA, SHA1, SHA224)
 * - SM-TLS13 restrictions (only SM2-SM3 allowed)
 *
 * @param ctx [IN] TLS context
 * @param signScheme [IN] Signature scheme to check
 * @param allowList [IN] Allowed signature algorithm list (can be NULL to skip list check)
 * @param allowListSize [IN] Size of the allowed list
 * @return true if the algorithm is allowed, false otherwise
 */
bool SAL_CERT_IsSignAlgorithmAllowed(const TLS_Ctx *ctx, uint16_t signScheme,
    const uint16_t *allowList, uint32_t allowListSize);

/**
 * @brief Encode the certificate chain in ASN.1 DER format.
 *
 * @param ctx     [IN] tls Context
 * @param pkt     [IN/OUT] Context for packing
 *
 * @retval HITLS_SUCCESS                            succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK              No callback is set.
 * @retval HITLS_CERT_ERR_BUILD_CHAIN               Failed to assemble the certificate chain.
 * @retval HITLS_CERT_CTRL_ERR_GET_ENCODE_LEN       Failed to obtain the encoding length.
 * @retval HITLS_CERT_ERR_ENCODE_CERT               Certificate encoding failed.
 */
int32_t SAL_CERT_EncodeCertChain(HITLS_Ctx *ctx, PackPacket *pkt);

/**
 * @brief Decode the certificate in ASN.1 DER format.
 *
 * @param ctx      [IN] tls Context
 * @param item     [IN] Original certificate data, which is a linked list. Each node indicates a certificate.
 * @param certPair [OUT] Certificate chain
 *
 * @retval HITLS_SUCCESS                            succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK              No callback is set.
 * @retval HITLS_MEMALLOC_FAIL                      Insufficient Memory
 * @retval HITLS_CERT_ERR_PARSE_MSG                 Failed to parse the certificate data.
 */
int32_t SAL_CERT_ParseCertChain(HITLS_Ctx *ctx, CERT_Item *item, CERT_Pair **certPair);

/**
 * @brief Verify the certificate chain.
 *
 * @param ctx         [IN] tls Context
 * @param certPair    [IN] Certificate chain
 * @param isGmEncCert [IN] Indicates whether to verify the certificate chain of the encrypted certificate
 *                         of the TLCP. The value is always false
 *                         when the TLCP protocol is not used.
 *
 * @retval HITLS_SUCCESS                            succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK              No callback is set.
 * @retval HITLS_MEMALLOC_FAIL                      Insufficient Memory
 * @retval HITLS_CERT_ERR_VERIFY_CERT_CHAIN         Failed to verify the certificate chain.
 */
int32_t SAL_CERT_VerifyCertChain(HITLS_Ctx *ctx, CERT_Pair *certPair, bool isTlcpEncCert);

/**
 * @brief Obtain the maximum signature length.
 *
 * @param config [IN] TLS link configuration
 * @param key    [IN] Certificate private key
 *
 * @return Signature length
 */
uint32_t SAL_CERT_GetSignMaxLen(HITLS_Config *config, HITLS_CERT_Key *key);

/**
 * @brief Sign with the certificate private key.
 *
 * @param ctx       [IN] tls Context
 * @param key       [IN] Certificate private key
 * @param signParam [IN/OUT] Signature information
 *
 * @retval HITLS_SUCCESS                    succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK      No callback is set.
 * @retval HITLS_CERT_ERR_CREATE_SIGN       Signing failed.
 */
int32_t SAL_CERT_CreateSign(HITLS_Ctx *ctx, HITLS_CERT_Key *key, CERT_SignParam *signParam);

/**
 * @brief Use the certificate public key to verify the signature.
 *
 * @param ctx       [IN] tls Context
 * @param key       [IN] Certificate public key
 * @param signParam [IN] Signature information
 *
 * @retval HITLS_SUCCESS                    succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK      No callback is set.
 * @retval HITLS_CERT_ERR_VERIFY_SIGN       Failed to verify the signature.
 */
int32_t SAL_CERT_VerifySign(HITLS_Ctx *ctx, HITLS_CERT_Key *key, CERT_SignParam *signParam);

/**
 * @ingroup hitls_cert_reg
 * @brief Encrypted by the certificate public key, which is used for the RSA cipher suite.
 *
 * @param ctx    [IN] tls Context
 * @param key    [IN] Certificate public key
 * @param in     [IN] Plaintext
 * @param inLen  [IN] length of plaintext
 * @param out    [IN] Ciphertext
 * @param outLen [IN/OUT] IN: Maximum length of the ciphertext padding. OUT: Length of the ciphertext
 *
 * @retval  HITLS_SUCCESS                   succeeded
 */
int32_t SAL_CERT_KeyEncrypt(HITLS_Ctx *ctx, HITLS_CERT_Key *key, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen);

/**
 * @ingroup hitls_cert_reg
 * @brief Use the certificate private key to decrypt, which is used for the RSA cipher suite.
 *
 * @param ctx    [IN] tls Context
 * @param key    [IN] Certificate private key
 * @param in     [IN] Ciphertext
 * @param inLen  [IN] length of ciphertext
 * @param out    [IN] Plaintext
 * @param outLen [IN/OUT] IN: Maximum length of plaintext padding. OUT: Plaintext length
 *
 * @retval  HITLS_SUCCESS                   succeeded
 */
int32_t SAL_CERT_KeyDecrypt(HITLS_Ctx *ctx, HITLS_CERT_Key *key, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen);

/**
 * @brief Obtain the default signature hash algorithm based on the certificate public key type.
 *
 * @param keyType [IN] Certificate public key type
 *
 * @retval Default signature hash algorithm
 */
HITLS_SignHashAlgo SAL_CERT_GetDefaultSignHashAlgo(HITLS_CERT_KeyType keyType);

/**
 * @ingroup hitls_cert_reg
 * @brief Encoded content of the TLCP encryption certificate obtained by the server.
 *
 * @param ctx    [IN] tls Context
 * @param outLen [OUT] OUT: length after encoding
 *
 * @retval Encoded content
 */
uint8_t *SAL_CERT_SrvrGmEncodeEncCert(HITLS_Ctx *ctx, uint32_t *useLen);

/**
 * @ingroup hitls_cert_reg
 * @brief The client obtains the encoded content of the TLCP encryption certificate.
 *
 * @param ctx       [IN] tls Context
 * @param peerCert  [IN] Peer certificate information
 * @param outLen    [OUT] OUT: length after encoding
 *
 * @retval Encoded content
 */
uint8_t *SAL_CERT_ClntGmEncodeEncCert(HITLS_Ctx *ctx, CERT_Pair *peerCert, uint32_t *useLen);

/**
 * @ingroup hitls_cert_reg
 * @brief Check whether the certificate is an encrypted certificate, a digital signature,
 *        or a permission to issue the certificate.
 *
 * @param ctx [IN] tls Context
 * @param cert [IN] Certificate to be verified
 *
 * @retval true indicates that is the encryption certificate.
 */
bool SAL_CERT_CheckCertKeyUsage(HITLS_Ctx *ctx, HITLS_CERT_X509 *cert, HITLS_CERT_CtrlCmd keyusage);

/**
 * @ingroup hitls_cert_reg
 * @brief Check the secbits of key
 *
 * @param ctx [IN] tls Context
 * @param cert [IN] Certificate
 * @param key [IN] key
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval For other error codes, see hitls_error.h.
 */
int32_t SAL_CERT_CheckKeySecbits(HITLS_Ctx *ctx, HITLS_CERT_X509 *cert, HITLS_CERT_Key *key);

#ifdef __cplusplus
}
#endif
#endif