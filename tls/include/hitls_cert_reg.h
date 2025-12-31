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
 /**
 * @defgroup hitls_cert_reg
 * @ingroup  hitls
 * @brief    Certificate related interfaces to be registered
 */

#ifndef HITLS_CERT_REG_H
#define HITLS_CERT_REG_H

#include <stdint.h>
#include "hitls_crypt_type.h"
#include "hitls_cert_type.h"
#include "hitls_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup hitls_cert_reg
 * @brief   Create a certificate store
 *
 * @param   void
 *
 * @return  Certificate store, the memory is released using CERT_StoreFreeCallBack.
 */
typedef HITLS_CERT_Store *(*CERT_StoreNewCallBack)(void);

/**
 * @ingroup hitls_cert_reg
 * @brief   Duplicate the certificate store.
 *
 * @param   store [IN] Certificate store.
 *
 * @return  New certificate store, the memory is released using CERT_StoreFreeCallBack.
 */
typedef HITLS_CERT_Store *(*CERT_StoreDupCallBack)(HITLS_CERT_Store *store);

/**
 * @ingroup hitls_cert_reg
 * @brief   Release the certificate store.
 *
 * @param   store [IN] Certificate store.
 *
 * @return  void
 */
typedef void (*CERT_StoreFreeCallBack)(HITLS_CERT_Store *store);

/**
 * @ingroup hitls_cert_reg
 * @brief   ctrl interface
 *
 * @param   config [IN] TLS link configuration.
 * @param   store [IN] Certificate store.
 * @param   cmd [IN] Ctrl option.
 * @param   input [IN] Input.
 * @param   output [IN] Output.
 *
 * @return  HITLS_SUCCESS indicates success. Other values are considered as failure.
 */
typedef int32_t (*CERT_StoreCtrlCallBack)(HITLS_Config *config, HITLS_CERT_Store *store, HITLS_CERT_CtrlCmd cmd,
    void *input, void *output);

/**
 * @ingroup hitls_cert_reg
 * @brief   Create a certificate chain based on the device certificate in use.
 * @attention If the function is successful, the certificate in the certificate chain is managed by the HiTLS,
 * and the user does not need to release the memory. Otherwise, the certificate chain is an empty pointer array.
 *
 * @param   config [IN] TLS link configuration
 * @param   store [IN] Certificate store
 * @param   cert [IN] Device certificate
 * @param   certList [OUT] Certificate chain, which is a pointer array. Each element indicates a certificate.
 *  The first element is the device certificate.
 * @param   num [IN/OUT] IN: maximum length of the certificate chain OUT: length of the certificate chain
 *
 * @return  HITLS_SUCCESS indicates success. Other values are considered as failure.
 */
typedef int32_t (*CERT_BuildCertChainCallBack)(HITLS_Config *config, HITLS_CERT_Store *store, HITLS_CERT_X509 *cert,
    HITLS_CERT_X509 **certList, uint32_t *num);

/**
 * @ingroup hitls_cert_reg
 * @brief   Verify the certificate chain
 *
 * @param   ctx [IN] TLS link object
 * @param   store [IN] Certificate store.
 * @param   certList [IN] Certificate chain, a pointer array, each element indicates a certificate.
 * The first element indicates the device certificate.
 * @param   num [IN] Certificate chain length.
 *
 * @return  HITLS_SUCCESS indicates success. Other values are considered as failure.
 */
typedef int32_t (*CERT_VerifyCertChainCallBack)(HITLS_Ctx *ctx, HITLS_CERT_Store *store,
    HITLS_CERT_X509 **certList, uint32_t num);

/**
 * @ingroup hitls_cert_reg
 * @brief   Encode the certificate in ASN.1 DER format.
 *
 * @param   ctx [IN] TLS link object.
 * @param   cert [IN] Certificate.
 * @param   buf [OUT] Certificate encoding data.
 * @param   len [IN] Maximum encoding length.
 * @param   usedLen [OUT] Actual encoding length.
 *
 * @return  HITLS_SUCCESS indicates success. Other values are considered as failure.
 */
typedef int32_t (*CERT_CertEncodeCallBack)(HITLS_Ctx *ctx, HITLS_CERT_X509 *cert, uint8_t *buf, uint32_t len,
    uint32_t *usedLen);

/**
 * @ingroup hitls_cert_reg
 * @brief   Read the certificate.
 * @attention If the data is loaded to config, config points to the TLS configuration.
 * If the data is loaded to the TLS object, the config command is used only for a single link.
 *
 * @param   config [IN] TLS link configuration, which can be used to obtain the passwd callback.
 * @param   buf [IN] Certificate data.
 * @param   len [IN] Certificate data length.
 * @param   type [IN] Parsing type.
 * @param   format [IN] Data format.
 *
 * @return  Certificate
 */
typedef HITLS_CERT_X509 *(*CERT_CertParseCallBack)(HITLS_Config *config, const uint8_t *buf, uint32_t len,
    HITLS_ParseType type, HITLS_ParseFormat format);

/**
 * @ingroup hitls_cert_reg
 * @brief   Duplicate the certificate.
 *
 * @param   cert [IN] Certificate
 *
 * @return  New certificate, the memory is released using CERT_CertFreeCallBack.
 */
typedef HITLS_CERT_X509 *(*CERT_CertDupCallBack)(HITLS_CERT_X509 *cert);

/**
 * @ingroup hitls_cert_reg
 * @brief   Certificate reference counting plus one.
 *
 * @param   cert [IN] Certificate
 *
 * @return certificate, the memory is released using CERT_CertFreeCallBack.
 */
typedef HITLS_CERT_X509 *(*CERT_CertRefCallBack)(HITLS_CERT_X509 *cert);

/**
 * @ingroup hitls_cert_reg
 * @brief   Release the certificate.
 *
 * @param   cert [IN] Certificate
 *
 * @return  void
 */
typedef void (*CERT_CertFreeCallBack)(HITLS_CERT_X509 *cert);

/**
 * @ingroup hitls_cert_reg
 * @brief   Ctrl interface
 *
 * @param   config [IN] TLS link configuration
 * @param   cert [IN] Certificate
 * @param   cmd [IN] Ctrl option
 * @param   input [IN] Input
 * @param   output [IN] Output
 *
 * @return  HITLS_SUCCESS indicates success. Other values are considered as failure.
 */
typedef int32_t (*CERT_CertCtrlCallBack)(HITLS_Config *config, HITLS_CERT_X509 *cert, HITLS_CERT_CtrlCmd cmd,
    void *input, void *output);

/**
 * @ingroup hitls_cert_reg
 * @brief   Read the certificate key.
 * @attention If the data is loaded to config, config points to the TLS configuration.
 * If the data is loaded to the TLS object, the config command applies only to a single link.
 *
 * @param   config [IN] LTS link configuration, which can be used to obtain the passwd callback.
 * @param   buf [IN] Private key data
 * @param   len [IN] Data length
 * @param   type [IN] Parsing type
 * @param   format [IN] Data format
 *
 * @return  Certificate key
 */
typedef HITLS_CERT_Key *(*CERT_KeyParseCallBack)(HITLS_Config *config, const uint8_t *buf, uint32_t len,
    HITLS_ParseType type, HITLS_ParseFormat format);

/**
 * @ingroup hitls_cert_reg
 * @brief   Duplicate the certificate key.
 *
 * @param   key [IN] Certificate key
 *
 * @return  New certificate key, the memory is released using CERT_KeyFreeCallBack.
 */
typedef HITLS_CERT_Key *(*CERT_KeyDupCallBack)(HITLS_CERT_Key *key);

/**
 * @ingroup hitls_cert_reg
 * @brief   Release the certificate key.
 *
 * @param   key [IN] Certificate key
 *
 * @return  void
 */
typedef void (*CERT_KeyFreeCallBack)(HITLS_CERT_Key *key);

/**
 * @ingroup hitls_cert_reg
 * @brief   Ctrl interface
 *
 * @param   config [IN] TLS link configuration.
 * @param   key [IN] Certificate key.
 * @param   cmd [IN] Ctrl option.
 * @param   input [IN] Input.
 * @param   output [IN] Output.
 *
 * @return  HITLS_SUCCESS indicates success. Other values are considered as failure.
 */
typedef int32_t (*CERT_KeyCtrlCallBack)(HITLS_Config *config, HITLS_CERT_Key *key, HITLS_CERT_CtrlCmd cmd,
    void *input, void *output);

/**
 * @ingroup hitls_cert_reg
 * @brief   Signature
 *
 * @param   ctx [IN] TLS link object
 * @param   key [IN] Certificate private key
 * @param   signAlgo [IN] Signature algorithm
 * @param   hashAlgo [IN] Hash algorithm
 * @param   data [IN] Data to be signed
 * @param   dataLen [IN] Data length
 * @param   sign [OUT] Signature
 * @param   signLen [IN/OUT] IN: maximum signature length OUT: actual signature length
 *
 * @return  HITLS_SUCCESS indicates success. Other values are considered as failure.
 */
typedef int32_t (*CERT_CreateSignCallBack)(HITLS_Ctx *ctx, HITLS_CERT_Key *key, HITLS_SignAlgo signAlgo,
    HITLS_HashAlgo hashAlgo, const uint8_t *data, uint32_t dataLen, uint8_t *sign, uint32_t *signLen);

/**
 * @ingroup hitls_cert_reg
 * @brief   Signature verification
 *
 * @param   ctx [IN] TLS link object
 * @param   key [IN] Certificate public key
 * @param   signAlgo [IN] Signature algorithm
 * @param   hashAlgo [IN] Hash algorithm
 * @param   data [IN] Data to be signed
 * @param   dataLen [IN] Data length
 * @param   sign [IN] Signature
 * @param   signLen [IN] Signature length
 *
 * @return  HITLS_SUCCESS indicates success. Other values are considered as failure.
 */
typedef int32_t (*CERT_VerifySignCallBack)(HITLS_Ctx *ctx, HITLS_CERT_Key *key, HITLS_SignAlgo signAlgo,
    HITLS_HashAlgo hashAlgo, const uint8_t *data, uint32_t dataLen, const uint8_t *sign, uint32_t signLen);

/**
 * @ingroup hitls_cert_reg
 * @brief   Encrypted by the certificate public key.
 *
 * @param   ctx [IN] TLS link object.
 * @param   key [IN] Certificate public key.
 * @param   in [IN] Plaintext.
 * @param   inLen [IN] Plaintext length.
 * @param   out [OUT] Ciphertext.
 * @param   outLen [IN/OUT] IN: maximum ciphertext length OUT: actual ciphertext length.
 *
 * @return  HITLS_SUCCESS indicates success. Other values are considered as failure.
 */
typedef int32_t (*CERT_EncryptCallBack)(HITLS_Ctx *ctx, HITLS_CERT_Key *key, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen);

/**
 * @ingroup hitls_cert_reg
 * @brief   Use the certificate private key to decrypt the data.
 *
 * @param   ctx [IN] TLS link object.
 * @param   key [IN] Certificate private key.
 * @param   in [IN] Ciphertext.
 * @param   inLen [IN] Ciphertext length.
 * @param   out [OUT] Plaintext.
 * @param   outLen [IN/OUT] IN: maximum plaintext length OUT: actual plaintext length.
 *
 * @return  HITLS_SUCCESS indicates success. Other values are considered as failure.
 */
typedef int32_t (*CERT_DecryptCallBack)(HITLS_Ctx *ctx, HITLS_CERT_Key *key, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen);

/**
 * @ingroup hitls_cert_reg
 * @brief   Check whether the private key matches the certificate.
 *
 * @param   config [IN] TLS link configuration.
 * @param   cert [IN] Certificate.
 * @param   key [IN] Private key.
 *
 * @return  HITLS_SUCCESS indicates success. Other values are considered as failure.
 */
typedef int32_t (*CERT_CheckPrivateKeyCallBack)(HITLS_Config *config, HITLS_CERT_X509 *cert, HITLS_CERT_Key *key);

/**
 * @ingroup hitls_cert_reg
 * @brief Structure for certificate management methods
 */
typedef struct {
    CERT_StoreNewCallBack certStoreNew;             /**< REQUIRED, Creating a certificate store. */
    CERT_StoreDupCallBack certStoreDup;             /**< REQUIRED, duplicate certificate store. */
    CERT_StoreFreeCallBack certStoreFree;           /**< REQUIRED, release the certificate store. */
    CERT_StoreCtrlCallBack certStoreCtrl;           /**< REQUIRED, certificate interface store ctrl. */
    CERT_BuildCertChainCallBack buildCertChain;     /**< REQUIRED, construct a certificate chain. */
    CERT_VerifyCertChainCallBack verifyCertChain;   /**< REQUIRED, verify certificate chain. */

    CERT_CertEncodeCallBack certEncode;             /**< REQUIRED, certificate encode. */
    CERT_CertParseCallBack certParse;               /**< REQUIRED, certificate decoding. */
    CERT_CertDupCallBack certDup;                   /**< REQUIRED, duplicate the certificate. */
    CERT_CertRefCallBack certRef;                   /**< REQUIRED, Certificate reference counting plus one. */
    CERT_CertFreeCallBack certFree;                 /**< REQUIRED, release certificate. */
    CERT_CertCtrlCallBack certCtrl;                 /**< REQUIRED, certificate interface ctrl. */

    CERT_KeyParseCallBack keyParse;                 /**< REQUIRED, loading key. */
    CERT_KeyDupCallBack keyDup;                     /**< REQUIRED, duplicate key. */
    CERT_KeyFreeCallBack keyFree;                   /**< REQUIRED, Release the key. */
    CERT_KeyCtrlCallBack keyCtrl;                   /**< REQUIRED, key ctrl interface. */
    CERT_CreateSignCallBack createSign;             /**< REQUIRED, signature. */
    CERT_VerifySignCallBack verifySign;             /**< REQUIRED, verification. */
    CERT_EncryptCallBack encrypt;                   /**< OPTIONAL, RSA key exchange REQUIRED, RSA encryption. */
    CERT_DecryptCallBack decrypt;                   /**< OPTIONAL, RSA key exchange REQUIRED, RSA decryption. */

    CERT_CheckPrivateKeyCallBack checkPrivateKey;   /**< REQUIRED, Check whether the certificate matches the key. */
} HITLS_CERT_MgrMethod;

/**
 * @ingroup hitls_cert_reg
 * @brief   Callback function related to certificate registration
 *
 * @param   method [IN] Callback function
 *
 * @retval HITLS_SUCCESS, succeeded.
 * @retval HITLS_NULL_INPUT, the callback function is NULL.
 */
int32_t HITLS_CERT_RegisterMgrMethod(HITLS_CERT_MgrMethod *method);

/**
 * @ingroup hitls_cert_reg
 * @brief   Certificate deregistration callback function
 *
 * @param   method [IN] Callback function
 *
 * @retval
 */
void HITLS_CERT_DeinitMgrMethod(void);

/**
 * @ingroup hitls_cert_reg
 * @brief   Register the private key with the config file and certificate matching Check Interface.
 *
 * @param   config [IN/OUT] Config context
 *
 * @param   checkPrivateKey [IN] API registration
 * @retval  HITLS_SUCCESS.
 * @retval  For other error codes, see hitls_error.h.
*/

int32_t HITLS_CFG_SetCheckPriKeyCb(HITLS_Config *config, CERT_CheckPrivateKeyCallBack checkPrivateKey);

/**
 * @ingroup hitls_cert_reg
 * @brief   Interface for obtaining the registered private key and certificate matching check
 *
 * @param   config [IN]  Config context
 *
 * @retval  The interface for checking whether the registered private key matches the certificate is returned.
 * If the registered private key does not match the certificate, NULL is returned.
 */
CERT_CheckPrivateKeyCallBack HITLS_CFG_GetCheckPriKeyCb(HITLS_Config *config);

/**
 * @ingroup hitls_cert_reg
 * @brief   Get certificate callback function
 *
 * @return Cert callback function
 */
HITLS_CERT_MgrMethod *HITLS_CERT_GetMgrMethod(void);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CERT_REG_H */
