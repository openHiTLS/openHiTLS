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
 * @defgroup hitls_cert
 * @ingroup  hitls
 * @brief    TLS Certificate Operation Interface
 */

#ifndef HITLS_CERT_H
#define HITLS_CERT_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "hitls_type.h"
#include "hitls_cert_type.h"
#include "hitls_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup hitls_cert
 * @brief   Set the verify store used by the TLS configuration, which is used for certificate verification.
 *
 * @param   config [OUT] TLS link configuration.
 * @param   store   [IN] CA certificate store.
 * @param   isClone [IN] Indicates whether deep copy is required. true indicates need, false indicates not need.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetVerifyStore(HITLS_Config *config, HITLS_CERT_Store *store, bool isClone);

/**
 * @ingroup hitls_cert
 * @brief   Obtain the verify store used by the TLS configuration.
 *
 * @attention The user cannot release the memory.
 *
 * @param   config [IN] TLS link configuration
 * @retval  Verify store
 */
HITLS_CERT_Store *HITLS_CFG_GetVerifyStore(const HITLS_Config *config);

/**
 * @ingroup hitls_cert
 * @brief   Set the verify store used by the TLS link for certificate verification.
 *
 * @param   ctx     [OUT] TLS link object
 * @param   store   [IN] CA certificate store
 * @param   isClone [IN] Indicates whether deep copy is required. The options are true and false.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_SetVerifyStore(HITLS_Ctx *ctx, HITLS_CERT_Store *store, bool isClone);

/**
 * @ingroup hitls_cert
 * @brief   Obtain the verify store used by the TLS link.
 *
 * @param   ctx [IN] TLS link object
 * @retval  Verify store
 */
HITLS_CERT_Store *HITLS_GetVerifyStore(const HITLS_Ctx *ctx);

/**
 * @ingroup hitls_cert
 * @brief   Set the chain store used by the TLS configuration, which is used to construct the certificate chain.
 *
 * @param   config [OUT] TLS link configuration
 * @param   store   [IN] Certificate chain store
 * @param   isClone [IN] Indicates whether deep copy is required. The options are as follows: true: yes; false: no.
 * @retval  HITLS_SUCCESS.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetChainStore(HITLS_Config *config, HITLS_CERT_Store *store, bool isClone);

/**
 * @ingroup hitls_cert
 * @brief   Obtain the chain store used by the TLS configuration.
 *
 * @attention The user cannot release the memory.
 * @param   config [IN] TLS link configuration
 * @retval  Chain store
 */
HITLS_CERT_Store *HITLS_CFG_GetChainStore(const HITLS_Config *config);

/**
 * @ingroup hitls_cert
 * @brief   Set the chain store used by the TLS link to construct the certificate chain.
 *
 * @param   ctx    [OUT] TLS link object
 * @param   store   [IN] Certificate chain
 * @param   isClone [IN] Indicates whether deep copy is required. The options are true and false.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_SetChainStore(HITLS_Ctx *ctx, HITLS_CERT_Store *store, bool isClone);

/**
 * @ingroup hitls_cert
 * @brief   Obtain the chain store used by the TLS link.
 *
 * @param   ctx [IN] TLS object
 * @retval  Chain Store
 */
HITLS_CERT_Store *HITLS_GetChainStore(const HITLS_Ctx *ctx);

/**
 * @ingroup hitls_cert
 * @brief   Set the cert store used by the TLS configuration.
 *
 * @attention If verify store is not set, use cert store to verify the certificate.
 *            If chain store is not set, use cert store to construct a certificate chain.
 * @param   config [OUT] TLS link configuration
 * @param   store   [IN] Trust certificate store
 * @param   isClone [IN] Indicates whether deep copy is required. The options are true and false.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetCertStore(HITLS_Config *config, HITLS_CERT_Store *store, bool isClone);

/**
 * @ingroup hitls_cert
 * @brief   Obtain the cert store used by the TLS configuration.
 *
 * @attention The user cannot release the memory.
 * @param   config [IN] TLS link configuration
 * @retval  Cert store
 */
HITLS_CERT_Store *HITLS_CFG_GetCertStore(const HITLS_Config *config);

/**
 * @ingroup hitls_cert
 * @brief   Set the cert store used by the TLS link.
 *
 * @attention If verify store is not set, use cert store to verify the certificate.
 * If chain store is not set, use cert store to construct a certificate chain.
 * @param   ctx    [OUT] TLS link object
 * @param   store   [IN] Trust certificate store
 * @param   isClone [IN] Indicates whether deep copy is required. The options are true and false.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_SetCertStore(HITLS_Ctx *ctx, HITLS_CERT_Store *store, bool isClone);

/**
 * @ingroup hitls_cert
 * @brief   Obtain the cert store used by the TLS link.
 *
 * @param   ctx [IN] TLS link object
 * @retval  Cert store
 */
HITLS_CERT_Store *HITLS_GetCertStore(const HITLS_Ctx *ctx);

/**
 * @ingroup hitls_cert
 * @brief   Set the certificate verification depth.
 *
 * @param   config [OUT] TLS link configuration
 * @param   depth   [IN] Verification depth, type: uint32_t
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
#define HITLS_CFG_SetVerifyDepth(config, depth) \
    HITLS_CFG_CtrlSetVerifyParams(config, NULL, CERT_STORE_CTRL_SET_VERIFY_DEPTH, depth, NULL)

/**
 * @ingroup hitls_cert
 * @brief   Obtain the certificate verification depth.
 *
 * @param   config [IN] TLS link configuration
 * @param   depth  [OUT] Certificate verification depth, type: int32_t *
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
#define HITLS_CFG_GetVerifyDepth(config, depth) \
    HITLS_CFG_CtrlGetVerifyParams((HITLS_Config *)(uintptr_t)(config), NULL, CERT_STORE_CTRL_GET_VERIFY_DEPTH, depth)

/**
 * @ingroup hitls_cert
 * @brief   Set the certificate verification depth.
 *
 * @param   ctx  [OUT] TLS link object
 * @param   depth [IN] Verification depth, type: uint32_t
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
#define HITLS_SetVerifyDepth(ctx, depth) \
    HITLS_CtrlSetVerifyParams(ctx, NULL, CERT_STORE_CTRL_SET_VERIFY_DEPTH, depth, NULL)

/**
 * @ingroup hitls_cert
 * @brief   Obtain the certificate verification depth.
 *
 * @param   ctx   [IN] TLS link object
 * @param   depth [OUT] Certificate verification depth, type: int32_t *
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
#define HITLS_GetVerifyDepth(ctx, depth) \
    HITLS_CtrlGetVerifyParams(ctx, NULL, CERT_STORE_CTRL_GET_VERIFY_DEPTH, depth)

/**
 * @ingroup hitls_cert
 * @brief   Password Callback
 *
 * @attention This callback function must be compatible with OpenSSL and logically the same as OpenSSL.
 * @param   buf    [OUT] Passwd data.
 * @param   bufLen [IN] Maximum buffer length.
 * @param   flag   [IN] r/w flag. The value 0 indicates read, and the value 1 indicates write.
 * @param   userdata [IN] User data.
 *
 * @retval  Passwd Data length
 */
typedef int32_t (*HITLS_PasswordCb)(char *buf, int32_t bufLen, int32_t flag, void *userdata);

/**
 * @ingroup hitls_cert
 * @brief   Set the default password callback, cb can be NULL.
 *
 * @param   config [OUT] TLS link configuration
 * @param   cb     [IN] Password Callback
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetDefaultPasswordCb(HITLS_Config *config, HITLS_PasswordCb cb);

/**
 * @ingroup hitls_cert
 * @brief   Callback for obtaining the default password.
 *
 * @param   config [IN] TLS link configuration.
 * @retval  Password Callback.
 */
HITLS_PasswordCb HITLS_CFG_GetDefaultPasswordCb(HITLS_Config *config);

/**
 * @ingroup hitls_cert
 * @brief   Set the user data used by the password callback.
 *
 * @param   config [OUT] TLS link configuration
 * @param   userdata [IN] User data
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetDefaultPasswordCbUserdata(HITLS_Config *config, void *userdata);

/**
 * @ingroup hitls_cert
 * @brief   Obtain the user data used by the password callback.
 *
 * @param   config [IN] TLS link configuration
 * @retval  User Data
 */
void *HITLS_CFG_GetDefaultPasswordCbUserdata(HITLS_Config *config);

/**
 * @ingroup hitls_cert
 * @brief   Set the default password callback, cb can be NULL
 *
 * @param   ctx [OUT] TLS link object
 * @param   cb  [IN] password Callback
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_SetDefaultPasswordCb(HITLS_Ctx *ctx, HITLS_PasswordCb cb);

/**
 * @ingroup hitls_cert
 * @brief   Callback for obtaining the default password
 *
 * @param   ctx [IN] TLS link object
 * @retval  Password Callback
 */
HITLS_PasswordCb HITLS_GetDefaultPasswordCb(HITLS_Ctx *ctx);

/**
 * @ingroup hitls_cert
 * @brief   Set the user data used by the default password callback.
 *
 * @param   ctx     [OUT] TLS link object
 * @param   userdata [IN] user data
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_SetDefaultPasswordCbUserdata(HITLS_Ctx *ctx, void *userdata);

/**
 * @ingroup hitls_cert
 * @brief   Obtain the user data used by the default password callback.
 *
 * @param   ctx [IN] TLS link object
 * @retval  User data
 */
void *HITLS_GetDefaultPasswordCbUserdata(HITLS_Ctx *ctx);

/**
 * @ingroup hitls_cert
 * @brief   Add the device certificate by the ShangMi(SM) cipher suites.
 *          Only one certificate can be added for each type.
 *
 * @param   config [OUT] TLS link configuration
 * @param   cert   [IN] Device certificate
 * @param   isClone [IN] Indicates whether deep copy is required. The options are as follows: true: yes; false: no.
 * @param   isTlcpEncCert [IN] Indicates whether the certificate is encrypted by China.
 * The options are as follows: true: yes; false: no.
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetTlcpCertificate(HITLS_Config *config, HITLS_CERT_X509 *cert, bool isClone, bool isTlcpEncCert);

/**
 * @ingroup hitls_cert
 * @brief   Add the private key of the device certificate by the ShangMi(SM) cipher suites.
 * Only one private key can be added for each type of certificate.
 *
 * @param   config  [OUT] TLS link configuration
 * @param   privateKey [IN] Certificate private key
 * @param   isClone [IN] Indicates whether deep copy is required. The options are as follows: true: yes; false: no.
 * @param   isTlcpEncCertPriKey [IN] Indicates whether the private key of the encryption certificate is
 * the private key of the encryption certificate. true: yes; false: no.
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetTlcpPrivateKey(HITLS_Config *config, HITLS_CERT_Key *privateKey,
    bool isClone, bool isTlcpEncCertPriKey);

/**
 * @ingroup hitls_cert
 * @brief   Add a device certificate. Only one certificate of each type can be added
 *
 * @param   config [OUT] TLS link configuration
 * @param   cert    [IN] Device certificate
 * @param   isClone [IN] Indicates whether deep copy is required. The options are as follows: true: yes; false: no.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetCertificate(HITLS_Config *config, HITLS_CERT_X509 *cert, bool isClone);

/**
 * @ingroup hitls_cert
 * @brief   Load the device certificate from the file.
 *
 * @param   config  [OUT] TLS link configuration
 * @param   file  [IN] File name
 * @param   type  [IN] File format
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_LoadCertFile(HITLS_Config *config, const char *file, HITLS_ParseFormat format);

/**
 * @ingroup hitls_cert
 * @brief   Read the device certificate from the buffer.
 *
 * @param   config [OUT] TLS link configuration
 * @param   buf    [IN] Certificate data
 * @param   bufLen [IN] Data length
 * @param   format [IN] Data format
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_LoadCertBuffer(HITLS_Config *config, const uint8_t *buf, uint32_t bufLen, HITLS_ParseFormat format);

/**
 * @ingroup hitls_cert
 * @brief   Obtain the device certificate in use.
 *
 * @attention The user cannot release the memory.
 * @param   config [IN] TLS link configuration
 * @retval  Device certificate
 */
HITLS_CERT_X509 *HITLS_CFG_GetCertificate(const HITLS_Config *config);

/**
 * @ingroup hitls_cert
 * @brief   Add a device certificate. Only one certificate can be added for each type.
 *
 * @param   ctx [OUT] TLS link object
 * @param   cert [IN] Device certificate
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_SetCertificate(HITLS_Ctx *ctx, HITLS_CERT_X509 *cert, bool isClone);

/**
 * @ingroup hitls_cert
 * @brief   Use a file to set the device certificate.
 *
 * @param   ctx  [IN/OUT] TLS connection handle
 * @param   file  [IN] File name
 * @param   format  [IN] Data format
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_LoadCertFile(HITLS_Ctx *ctx, const char *file, HITLS_ParseFormat format);

/**
 * @ingroup hitls_cert
 * @brief   Read the device certificate from the buffer.
 *
 * @param   ctx   [OUT] TLS link object
 * @param   buf    [IN] Certificate data
 * @param   bufLen [IN] Data length
 * @param   format [IN] Data format
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_LoadCertBuffer(HITLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HITLS_ParseFormat format);

/**
 * @ingroup hitls_cert
 * @brief   Obtain the local certificate.
 *
 * Returns the most recently added certificate if it is called before the certificate is selected.
 * If no certificate is added, NULL is returned.
 * It returns the certificate selected during the handshake if a certificate selection occurs, or NULL
 * if no certificate is selected (e.g. on a client that does not use a client certificate).
 *
 * @attention: Shallow copy, can be used only during the ctx life cycle, and the caller
 *             must not release the returned pointer.
 * @param   ctx [IN] TLS link object
 * @retval  Device certificate
 */
HITLS_CERT_X509 *HITLS_GetCertificate(const HITLS_Ctx *ctx);

/**
 * @ingroup hitls_cert
 * @brief   Obtain the peer certificate.
 *
 * @attention: Certificate reference increments by one.
 * @param   ctx [IN] hitls Context
 * @retval  Peer certificate
 */
HITLS_CERT_X509 *HITLS_GetPeerCertificate(const HITLS_Ctx *ctx);

/**
 * @ingroup hitls_cert
 * @brief   Add the private key of the device certificate.
 * Only one private key can be added for each type of certificate.
 *
 * @param   config    [OUT] TLS link configuration
 * @param   privateKey [IN] Certificate private key
 * @param   isClone    [IN] Indicates whether deep copy is required. The options are as follows: true: yes; false: no.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetPrivateKey(HITLS_Config *config, HITLS_CERT_Key *privateKey, bool isClone);

/**
 * @ingroup hitls_cert
 * @brief   Load the private key of the device certificate from the file.
 *
 * @param   config  [OUT] TLS link configuration
 * @param   file  [IN] File name
 * @param   format  [IN] Data format
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_LoadKeyFile(HITLS_Config *config, const char *file, HITLS_ParseFormat format);

/**
 * @ingroup hitls_cert
 * @brief   Load the private key of the device certificate from the file, when the provider is used.
 *
 * @param   config  [OUT] TLS link configuration
 * @param   file   [IN] File name
 * @param   format  [IN] Data format. e.g. "PEM", "ASN1", etc.
 * @param   type   [IN] Data type. e.g. "PRIKEY_RSA", "PRIKEY_ECC", "PRIKEY_PKCS8_UNENCRYPT",
 *                "PRIKEY_PKCS8_ENCRYPT", etc.
 */
int32_t HITLS_CFG_ProviderLoadKeyFile(HITLS_Config *config, const char *file, const char *format, const char *type);

/**
 * @ingroup hitls_cert
 * @brief   Read the private key of the device certificate from the buffer.
 *
 * @param   config [OUT] TLS link configuration
 * @param   buf    [IN] Private key data
 * @param   bufLen [IN] Data length
 * @param   format [IN] Data format
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_LoadKeyBuffer(HITLS_Config *config, const uint8_t *buf, uint32_t bufLen, HITLS_ParseFormat format);

/**
 * @ingroup hitls_cert
 * @brief   Load the private key of the device certificate from the buffer, when the provider is used.
 *
 * @param   config [OUT] TLS link configuration
 * @param   buf    [IN] Private key data
 * @param   bufLen [IN] Data length
 * @param   format [IN] Data format
 * @param   type   [IN] Data type
 */
int32_t HITLS_CFG_ProviderLoadKeyBuffer(HITLS_Config *config, const uint8_t *buf, uint32_t bufLen, const char *format,
    const char *type);
/**
 * @ingroup hitls_cert
 * @brief   Obtain the private key of the certificate in use.
 *
 * @attention The user cannot release the memory.
 *
 * @param   config [IN] TLS link configuration
 * @retval  Certificate private key
 */
HITLS_CERT_Key *HITLS_CFG_GetPrivateKey(HITLS_Config *config);

/**
 * @ingroup hitls_cert
 * @brief   Check whether the configured certificate matches the private key.
 *
 * @param   config [IN] TLS link configuration
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_CheckPrivateKey(HITLS_Config *config);

/**
 * @ingroup hitls_cert
 * @brief   Add the private key of the device certificate.
 *
 * Only one private key can be added for each type of certificate.
 *
 * @param   ctx  [OUT] TLS link object.
 * @param   pkey  [IN] Device private key.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_SetPrivateKey(HITLS_Ctx *ctx, HITLS_CERT_Key *key, bool isClone);

/**
 * @ingroup hitls_cert
 * @brief   Use the file to set the device private key.
 *
 * @param   ctx  [IN/OUT] TLS connection handle
 * @param   file  [IN] File name.
 * @param   format  [IN] Data format.
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_LoadKeyFile(HITLS_Ctx *ctx, const char *file, HITLS_ParseFormat format);

/**
 * @ingroup hitls_cert
 * @brief   Load the private key of the device certificate from the file, when the provider is used.
 *
 * @param   ctx  [IN/OUT] TLS connection handle
 * @param   file  [IN] File name.
 * @param   format  [IN] Data format.
 * @param   type  [IN] Data type.
 */
int32_t HITLS_ProviderLoadKeyFile(HITLS_Ctx *ctx, const char *file, const char *format, const char *type);
/**
 * @ingroup hitls_cert
 * @brief   Read the private key of the device certificate from the buffer.
 *
 * @param   ctx   [OUT] TLS link object.
 * @param   buf    [IN] Private key data.
 * @param   bufLen [IN] Data length.
 * @param   format [IN] Data format.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_LoadKeyBuffer(HITLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HITLS_ParseFormat format);

/**
 * @ingroup hitls_cert
 * @brief   Load the private key of the device certificate from the buffer, when the provider is used.
 *
 * @param   ctx  [IN/OUT] TLS connection handle
 * @param   buf    [IN] Private key data.
 * @param   bufLen [IN] Data length.
 * @param   format [IN] Data format.
 * @param   type  [IN] Data type.
 */
int32_t HITLS_ProviderLoadKeyBuffer(HITLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, const char *format,
    const char *type);
/**
 * @ingroup hitls_cert
 * @brief   Obtain the private key of the certificate in use.
 *
 * @attention The user cannot release the memory.
 *
 * @param   ctx  [IN] TLS link object
 * @retval  Certificate private key
 */
HITLS_CERT_Key *HITLS_GetPrivateKey(HITLS_Ctx *ctx);

/**
 * @ingroup hitls_cert
 * @brief   Check whether the configured certificate matches the private key.
 *
 * @param   ctx [IN] TLS link object
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CheckPrivateKey(HITLS_Ctx *ctx);

/**
 * @ingroup hitls_cert
 * @brief   Add the certificate to the certificate chain that is being used by the current config.
 *
 * @param   config  [IN] TLS link configuration
 * @param   cert [IN] Certificate to be added
 * @param   isClone [IN] Indicates whether deep copy is required. The options are true and false.
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_AddChainCert(HITLS_Config *config, HITLS_CERT_X509 *cert, bool isClone);

/**
 * @ingroup hitls_cert
 * @brief   Add the certificate to the certificate store that is being used by the current config.
 *
 * @param   config  [IN] TLS link configuration
 * @param   cert [IN] Certificate to be added
 * @param   storeType [IN] Indicates which store to add cert.
 * @param   isClone [IN] Indicates whether deep copy is required. The options are true and false.
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_AddCertToStore(HITLS_Config *config, HITLS_CERT_X509 *cert,
    HITLS_CERT_StoreType storeType, bool isClone);

/**
 * @ingroup hitls_cert
 * @brief   Parse Certificate file or buffer to X509.
 *
 * @param   config [IN] TLS link configuration
 * @param   buf [IN] Certificate file or buffer
 * @param   len [IN] bufLen
 * @param   type [IN] buf type: file or buffer
 * @param   format [IN] cert type
 *
 * @retval  HITLS_CERT_X509
 */
HITLS_CERT_X509 *HITLS_CFG_ParseCert(HITLS_Config *config, const uint8_t *buf, uint32_t len,
    HITLS_ParseType type, HITLS_ParseFormat format);

/**
 * @ingroup hitls_cert
 * @brief   Parse Certificate file or buffer to X509.
 *
 * @param   config [IN] TLS link configuration
 * @param   buf [IN] Certificate file or buffer
 * @param   len [IN] bufLen
 * @param   type [IN] buf type: file or buffer
 * @param   format [IN] cert type
 *
 * @retval  HITLS_CERT_X509
 */
HITLS_CERT_Key *HITLS_CFG_ParseKey(HITLS_Config *config, const uint8_t *buf, uint32_t len,
    HITLS_ParseType type, HITLS_ParseFormat format);

/**
 * @ingroup hitls_cert
 * @brief   Parse Certificate file or buffer to X509.
 *
 * @param   config [IN] TLS link configuration
 * @param   buf [IN] Certificate file or buffer
 * @param   len [IN] bufLen
 * @param   type [IN] buf type: file or buffer
 * @param   format [IN] cert type
 * @param   encodeType [IN] cert encode type
 *
 * @retval  HITLS_CERT_X509
 */
HITLS_CERT_Key *HITLS_CFG_ProviderParseKey(HITLS_Config *config, const uint8_t *buf, uint32_t len,
    HITLS_ParseType type, const char *format, const char *encodeType);

/**
 * @ingroup hitls_cert
 * @brief   Obtain the certificate chain that is being used by the current config.
 * @param   config  [IN] TLS link configuration
 * @retval  The certificate chain that is currently in use
 */
HITLS_CERT_Chain *HITLS_CFG_GetChainCerts(HITLS_Config *config);

/**
 * @ingroup hitls_cert
 * @brief   Clear the certificate chain associated with the current certificate.
 *
 * @param   config  [IN] TLS link configuration
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_ClearChainCerts(HITLS_Config *config);

/**
 * @ingroup hitls_cert
 * @brief   Clear the certificate in the current certificate.
 *
 * @param   ctx [IN] hitls context
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_ClearChainCerts(HITLS_Ctx *ctx);

/**
 * @ingroup hitls_cert
 * @brief   Release all loaded certificates and private keys.
 *
 * @param   config  [IN] TLS link configuration
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_RemoveCertAndKey(HITLS_Config *config);

/**
 * @ingroup hitls_cert
 * @brief   Release all loaded certificates and private keys.
 *
 * @param   ctx  [IN] TLS link object
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_RemoveCertAndKey(HITLS_Ctx *ctx);

/**
 * @ingroup hitls_cert
 * @brief   Certificate verification callback
 *
 * @attention This callback function must be compatible with OpenSSL and has the same logic as OpenSSL.
 * @param   isPreverifyOk [IN] Indicates whether the relevant certificate has passed the verification
 * (isPreverifyOk=1) or failed (isPreverifyOk=0)
 * @param   storeCtx [IN] Cert store context
 * @retval  1 indicates success. Other values indicate failure.
 */
typedef int (*HITLS_VerifyCb)(int32_t isPreverifyOk, HITLS_CERT_StoreCtx *storeCtx);

/**
 * @ingroup hitls_cert
 * @brief   Set the certificate verification callback function, cb can be NULL.
 *
 * @param   config  [OUT] TLS link configuration
 * @param   callback [IN] Certificate verification callback function
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetVerifyCb(HITLS_Config *config, HITLS_VerifyCb callback);

/**
 * @ingroup hitls_cert
 * @brief   Obtain the certificate verification callback function.
 *
 * @param   config  [OUT] TLS link configuration
 * @return  Certificate verification callback function
 */
HITLS_VerifyCb HITLS_CFG_GetVerifyCb(HITLS_Config *config);

/**
 * @ingroup hitls_cert
 * @brief   Set the certificate verification callback function, cb can be NULL.
 *
 * @param   ctx     [OUT] TLS link object
 * @param   callback [IN] Certificate verification callback function
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_SetVerifyCb(HITLS_Ctx *ctx, HITLS_VerifyCb callback);

/**
 * @ingroup hitls_cert
 * @brief   Obtain the certificate verification callback function.
 *
 * @param   ctx [IN] TLS link object
 * @retval  Certificate verification callback function
 */
HITLS_VerifyCb HITLS_GetVerifyCb(HITLS_Ctx *ctx);

/**
 * @ingroup hitls_cert
 * @brief   Set the peer certificate verification result of the current context.
 *
 * @param   ctx  [IN] TLS connection handle
 * @param   verifyResult [IN] Peer certificate verification result
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_SetVerifyResult(HITLS_Ctx *ctx, HITLS_ERROR verifyResult);

/**
 * @ingroup hitls_cert
 * @brief   Return the peer certificate verification result of the current context.
 *
 * @param   ctx  [IN] TLS connection handle
 * @param   verifyResult [OUT] Peer certificate verification result
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_GetVerifyResult(const HITLS_Ctx *ctx, HITLS_ERROR *verifyResult);

/**
 * @ingroup hitls_cert
 * @brief   Obtain the peer certificate chain.
 *
 * @param   ctx [OUT] TLS connection handle
 * @retval  Peer certificate chain
 */
HITLS_CERT_Chain *HITLS_GetPeerCertChain(const HITLS_Ctx *ctx);

/**
 * @ingroup hitls_cert
 * @brief   Obtain the trusted CA list of the peer end.
 *
 * @param   ctx [OUT] TLS connection handle
 * @retval  Peer CA list
 */
HITLS_TrustedCAList *HITLS_GetPeerCAList(const HITLS_Ctx *ctx);

/**
 * @ingroup hitls_cert
 * @brief   Obtain the trusted CA list of the current context.
 *
 * @param   ctx [OUT] TLS connection handle
 * @retval  Trusted CA list
 */
HITLS_TrustedCAList *HITLS_GetCAList(const HITLS_Ctx *ctx);

/**
 * @ingroup hitls_cert
 * @brief   Set the trusted CA list of the current context.
 *
 * @param   ctx [OUT] TLS connection handle
 * @retval  Trusted CA list
 */
int32_t HITLS_SetCAList(HITLS_Ctx *ctx, HITLS_TrustedCAList *list);

/**
 * @ingroup hitls_cert
 * @brief   Add a certificate to the attached certificate chain.
 *
 * @param   config [OUT] Config handle
 * @param   cert [IN] X509 certificate
 * @retval  0 indicates success. Other values indicate failure.
 */
int32_t HITLS_CFG_AddExtraChainCert(HITLS_Config *config, HITLS_CERT_X509 *cert);

/**
 * @ingroup hitls_cert
 * @brief   Obtain the attached certificate chain.
 *
 * @param   config [IN] Config handle
 * @retval  Attach the certificate chain.
 */
HITLS_CERT_Chain *HITLS_CFG_GetExtraChainCerts(HITLS_Config *config);

/**
 * @ingroup hitls_cert
 * @brief   Release the attached certificate chain.
 *
 * @param   config  [IN] TLS link configuration
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_ClearExtraChainCerts(HITLS_Config *config);

/* If the ClientHello callback is successfully executed, the handshake continues */
#define HITLS_CERT_CALLBACK_SUCCESS 1
/* The  ClientHello callback fails. Send an alert message and terminate the handshake */
#define HITLS_CERT_CALLBACK_FAILED 0
/* The ClientHello callback is suspended. The handshake process is suspended and the callback is called again */
#define HITLS_CERT_CALLBACK_RETRY (-1)

/**
 * @ingroup hitls_cert
 * @brief   Process the certificate callback.
 * @attention This callback function is compatible with OpenSSL and has the same logic as OpenSSL.
 *
 * @param   ctx [IN] TLS link object
 * @param   arg [IN] Related parameters arg
 * @return  HITLS_CERT_CALLBACK_SUCCESS if the callback is successfully executed.
 *          HITLS_CERT_CALLBACK_FAILED if the callback fails.
 *          HITLS_CERT_CALLBACK_RETRY if the callback is suspended.
 */
typedef int32_t (*HITLS_CertCb)(HITLS_Ctx *ctx, void *arg);

/**
 * @ingroup hitls_cert
 * @brief  set the processing certificate callback function, which checks the passed ctx structure and
 * sets or clear any appropriate certificate, cb can be NULL.
 * @param   config [OUT] TLS link configuration
 * @param   certCb [IN] Certificate callback function
 * @param   arg    [IN] Parameters required in the callback function.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetCertCb(HITLS_Config *config, HITLS_CertCb certCb, void *arg);

/**
 * @ingroup hitls_cert
 * @brief  set the processing certificate callback function, which checks the passed ctx structure and
 * sets or clear any appropriate certificate, cb can be NULL.
 * @param   ctx [OUT] TLS link configuration
 * @param   certCb [IN] Certificate callback function
 * @param   arg    [IN] Parameters required in the callback function.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_SetCertCb(HITLS_Ctx *ctx, HITLS_CertCb certCb, void *arg);

/**
 * @ingroup hitls_cert
 * @brief   Key logging callback
 * @attention This callback function must be compatible with OpenSSL and is logically the same as OpenSSL.
 *
 * @param   ctx  [OUT] TLS Link object
 * @param   line [IN] Content to be recorded
 */
typedef void (*HITLS_KeyLogCb)(HITLS_Ctx *ctx, const char *line);

/**
 * @ingroup hitls_cert
 * @brief   Sets the callback for recording TLS keys.
 * @param   config   [OUT] TLS Link Configuration
 * @param   callback [IN] Callback function for recording keys
 *
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetKeyLogCb(HITLS_Config *config, HITLS_KeyLogCb callback);

/**
 * @ingroup hitls_cert
 * @brief   Callback for obtaining TLS key logs
 * @param   config  [OUT] TLS Link Configuration
 *
 * @retval  Callback function for recording key logs
 */
HITLS_KeyLogCb HITLS_CFG_GetKeyLogCb(HITLS_Config *config);

/**
 * @ingroup hitls_cert
 * @brief If logging is enabled, the master key is logged
 *
 * @param ctx           [OUT] TLS Link object.
 * @param label         [IN] Label
 * @param secret        [IN] Key
 * @param secretLen    [IN] Key length.
 *
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_LogSecret(HITLS_Ctx *ctx, const char *label, const uint8_t *secret, size_t secretLen);

/**
 * @ingroup hitls_cert
 * @brief   Load the CA file and parse it into a trusted CA list.
 *
 * @attention The user cannot release the memory.
 * @param   config [OUT] TLS link configuration
 * @param   input  [IN] Input data
 * @param   inputLen [IN] Length of the input data
 * @param   inputType [IN] Type of the input data
 * @param   format [IN] File format
 * @param   caList [OUT] Trusted CA list
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_ParseCAList(HITLS_Config *config, const char *input, uint32_t inputLen, HITLS_ParseType inputType,
                              HITLS_ParseFormat format, HITLS_TrustedCAList **caList);

/**
 * @ingroup hitls_cert
 * @brief  Before establishing a TLS connection, try to form a certificate chain as much as possible according to
 * the flag.
 * @param   config [OUT] TLS link configuration
 * @param   flag [IN] Control how to group certificate chains based on flags, see HITLS_BUILD_CHAIN_FLAG.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_BuildCertChain(HITLS_Config *config, HITLS_BUILD_CHAIN_FLAG flag);

/**
 * @ingroup hitls_cert
 * @brief  Before establishing a TLS connection, try to form a certificate chain as much as possible according to
 * the flag.
 * @param   ctx [OUT] TLS link configuration
 * @param   flag [IN] Control how to group certificate chains based on flags, see HITLS_BUILD_CHAIN_FLAG.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_BuildCertChain(HITLS_Ctx *ctx, HITLS_BUILD_CHAIN_FLAG flag);

/**
 * @ingroup hitls_cert
 * @brief  Set certificate verification parameters.
 * @param   config [OUT] TLS link configuration
 * @param   store  [IN] Certificate store
 * @param   cmd    [IN] Operation command, HITLS_CERT_CtrlCmd enum
 * @param   in     [IN] Input parameter, integer type
 * @param   inArg  [IN] Input parameter, pointer type
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_CtrlSetVerifyParams(
    HITLS_Config *config, HITLS_CERT_Store *store, uint32_t cmd, int64_t in, void *inArg);

/**
 * @ingroup hitls_cert
 * @brief  Get certificate verification parameters.
 * @param   config [IN] TLS link configuration
 * @param   store  [IN] Certificate store
 * @param   cmd    [IN] Operation command, HITLS_CERT_CtrlCmd enum
 * @param   out    [OUT] Output parameter
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_CtrlGetVerifyParams(HITLS_Config *config, HITLS_CERT_Store *store, uint32_t cmd, void *out);

/**
 * @ingroup hitls_cert
 * @brief  Set certificate verification parameters.
 * @param   ctx [OUT] TLS link configuration
 * @param   store  [IN] Certificate store
 * @param   cmd    [IN] Operation command, HITLS_CERT_CtrlCmd enum
 * @param   in     [IN] Input parameter, integer type
 * @param   inArg  [IN] Input parameter, pointer type
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_CtrlSetVerifyParams(HITLS_Ctx *ctx, HITLS_CERT_Store *store, uint32_t cmd, int64_t in, void *inArg);

/**
 * @ingroup hitls_cert
 * @brief  Get certificate verification parameters.
 * @param   ctx [IN] TLS link configuration
 * @param   store  [IN] Certificate store
 * @param   cmd    [IN] Operation command, HITLS_CERT_CtrlCmd enum
 * @param   out    [OUT] Output parameter
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_CtrlGetVerifyParams(HITLS_Ctx *ctx, HITLS_CERT_Store *store, uint32_t cmd, void *out);

/**
 * @ingroup hitls_cert
 * @brief   Load CRL from file and add it into the verify store of the TLS configuration.
 *
 * @param   config [OUT] TLS link configuration
 * @param   file   [IN]  CRL file path
 * @param   format [IN]  Data format, see HITLS_ParseFormat
 * @retval  HITLS_SUCCESS if successful
 * @retval  For other error codes, see hitls_error.h
 */
int32_t HITLS_CFG_LoadCrlFile(HITLS_Config *config, const char *file, HITLS_ParseFormat format);

/**
 * @ingroup hitls_cert
 * @brief   Load CRL from buffer and add it into the verify store of the TLS configuration.
 *
 * @param   config [OUT] TLS link configuration
 * @param   buf    [IN]  CRL data
 * @param   bufLen [IN]  Data length
 * @param   format [IN]  Data format, see HITLS_ParseFormat
 * @retval  HITLS_SUCCESS if successful
 * @retval  For other error codes, see hitls_error.h
 */
int32_t HITLS_CFG_LoadCrlBuffer(HITLS_Config *config, const uint8_t *buf, uint32_t bufLen, HITLS_ParseFormat format);

/**
 * @ingroup hitls_cert
 * @brief   Clear all CRLs in the verify store of the configuration.
 *
 * @param   config [IN] TLS link configuration
 * @retval  HITLS_SUCCESS if successful
 * @retval  For other error codes, see hitls_error.h
 */
int32_t HITLS_CFG_ClearVerifyCrls(HITLS_Config *config);

/**
 * @ingroup hitls_cert
 * @brief   Load CRL from file and add it into the verify store of the TLS context.
 */
int32_t HITLS_LoadCrlFile(HITLS_Ctx *ctx, const char *file, HITLS_ParseFormat format);

/**
 * @ingroup hitls_cert
 * @brief   Load CRL from buffer and add it into the verify store of the TLS context.
 */
int32_t HITLS_LoadCrlBuffer(HITLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HITLS_ParseFormat format);

/**
 * @ingroup hitls_cert
 * @brief   Clear all CRLs in the verify store of the context.
 */
int32_t HITLS_ClearVerifyCrls(HITLS_Ctx *ctx);

/**
 * @ingroup hitls_cert
 * @brief   Set the certificate verification flags.
 *
 * @param   config [OUT] TLS link configuration
 * @param   verifyFlags   [IN] Verification flags, type: uint32_t
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
#define HITLS_CFG_SetVerifyFlags(config, verifyFlags) \
    HITLS_CFG_CtrlSetVerifyParams(config, NULL, CERT_STORE_CTRL_SET_VERIFY_FLAGS, verifyFlags, NULL)

/**
 * @ingroup hitls_cert
 * @brief   Set the certificate verification flags.
 *
 * @param   ctx  [OUT] TLS link object
 * @param   verifyFlags [IN] Verification flags, type: uint32_t
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
#define HITLS_SetVerifyFlags(ctx, verifyFlags) \
    HITLS_CtrlSetVerifyParams(ctx, NULL, CERT_STORE_CTRL_SET_VERIFY_FLAGS, verifyFlags, NULL)

/**
 * @ingroup hitls_cert
 * @brief   Set the certificate verification flags.
 *
 * @param   config [IN] TLS link configuration
 * @param   verifyFlags   [OUT] Verification flags, type: uint32_t *
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
#define HITLS_CFG_GetVerifyFlags(config, verifyFlags) \
    HITLS_CFG_CtrlGetVerifyParams(config, NULL, CERT_STORE_CTRL_GET_VERIFY_FLAGS, verifyFlags)

/**
 * @ingroup hitls_cert
 * @brief   Set the certificate verification flags.
 *
 * @param   ctx  [IN] TLS link object
 * @param   verifyFlags [OUT] Verification flags, type: uint32_t *
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
#define HITLS_GetVerifyFlags(ctx, verifyFlags) \
    HITLS_CtrlGetVerifyParams(ctx, NULL, CERT_STORE_CTRL_GET_VERIFY_FLAGS, verifyFlags)

/**
 * @ingroup hitls_cert
 * @brief   Use the certificate chain file to set the certificate chain.
 *
 * @param   ctx [OUT] TLS link configuration
 * @param   file [IN] Certificate chain file name
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_UseCertificateChainFile(HITLS_Ctx *ctx, const char *file);

/**
 * @ingroup hitls_cert
 * @brief   Use the certificate chain file to set the certificate chain.
 *
 * @param   config [OUT] TLS link configuration
 * @param   file [IN] Certificate chain file name
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_UseCertificateChainFile(HITLS_Config *config, const char *file);

/**
 * @ingroup hitls_cert
 * @brief   Use the certificate chain buffer to set the certificate chain.
 *
 * @param   config [OUT] TLS link configuration
 * @param   buf [IN] Certificate chain buffer data
 * @param   bufLen [IN] Buffer length
 * @param   format [IN] Certificate format (PEM/DER/ASN1)
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_UseCertificateChainBuffer(HITLS_Config *config, const uint8_t *buf,
                                           uint32_t bufLen, HITLS_ParseFormat format);

/**
 * @ingroup hitls_cert
 * @brief   Use the certificate chain buffer to set the certificate chain.
 *
 * @param   ctx [OUT] TLS connection handle
 * @param   buf [IN] Certificate chain buffer data
 * @param   bufLen [IN] Buffer length
 * @param   format [IN] Certificate format (PEM/DER/ASN1)
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_UseCertificateChainBuffer(HITLS_Ctx *ctx, const uint8_t *buf,
                                       uint32_t bufLen, HITLS_ParseFormat format);

/**
 * @ingroup hitls_cert
 * @brief   Load the verification file from the file.
 *
 * @param   config  [OUT] TLS link configuration
 * @param   file  [IN] File name
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_LoadVerifyFile(HITLS_Config *config, const char *file);

/**
 * @ingroup hitls_cert
 * @brief   Load the verification certificates from buffer.
 *
 * @param   config [OUT] TLS link configuration
 * @param   buf [IN] Certificate buffer data
 * @param   bufLen [IN] Buffer length
 * @param   format [IN] Certificate format (PEM/DER/ASN1)
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_LoadVerifyBuffer(HITLS_Config *config, const uint8_t *buf,
                                  uint32_t bufLen, HITLS_ParseFormat format);

/**
 * @ingroup hitls_cert
 * @brief   Load the verification certificates from buffer.
 *
 * @param   ctx [OUT] TLS connection handle
 * @param   buf [IN] Certificate buffer data
 * @param   bufLen [IN] Buffer length
 * @param   format [IN] Certificate format (PEM/DER/ASN1)
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_LoadVerifyBuffer(HITLS_Ctx *ctx, const uint8_t *buf,
                              uint32_t bufLen, HITLS_ParseFormat format);
/**
 * @ingroup hitls_cert
 * @brief   Load the verification file from the directory.
 *
 * @param   config  [OUT] TLS link configuration
 * @param   path  [IN] Directory path
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_LoadVerifyDir(HITLS_Config *config, const char *path);

/**
 * @ingroup hitls_cert
 * @brief   Release the certificate.
 *
 * @param   config [IN] Config handle
 * @param   cert [IN] X509 certificate
 *
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_FreeCert(HITLS_Config *config, HITLS_CERT_X509 *cert);

/**
 * @ingroup hitls_cert
 * @brief   Release the key.
 *
 * @param   config [IN] Config handle
 * @param   key [IN] private key
 *
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_FreeKey(HITLS_Config *config, HITLS_CERT_Key *key);

/**
 * @brief   Load the default CA verification directory path
 * @param   config  [OUT] TLS link configuration
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_LoadDefaultCAPath(HITLS_Config *config);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CERT_H */