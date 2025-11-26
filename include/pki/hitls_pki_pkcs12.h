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

#ifndef HITLS_PKI_PKCS12_H
#define HITLS_PKI_PKCS12_H

#include "hitls_pki_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _HITLS_PKCS12 HITLS_PKCS12;

typedef struct _HITLS_PKCS12_Bag HITLS_PKCS12_Bag;

/**
 * @ingroup pkcs12
 * @brief Allocate a pkcs12 struct.
 *
 * @retval HITLS_PKCS12 *
 */
HITLS_PKCS12 *HITLS_PKCS12_New(void);

/**
 * @ingroup pkcs12
 * @brief Allocate a pkcs12 struct.
 *
 * @param libCtx         [IN] lib context
 * @param attrName       [IN] attribute name
 * @retval HITLS_PKCS12 *
 */
HITLS_PKCS12 *HITLS_PKCS12_ProviderNew(HITLS_PKI_LibCtx *libCtx, const char *attrName);

/**
 * @ingroup pkcs12
 * @brief Release the pkcs12 context.
 *
 * @param csr    [IN] p12 context.
 * @retval void
 */
void HITLS_PKCS12_Free(HITLS_PKCS12 *p12);

/**
 * @ingroup pkcs12
 * @brief Allocate a bag struct, which could store a cert or key and its attributes.
 *
 * @param bagId            [IN] BagId, BSL_CID_PKCS8SHROUDEDKEYBAG/BSL_CID_CERTBAG/BSL_CID_SECRETBAG
 * @param bagType          [IN] BagType, for example, BSL_CID_X509CERTIFICATE is a bagType of BSL_CID_CERTBAG.
 * @param bagValue         [IN] bagValue, the bagValue must match the bag-type. Each Bag only holds one piece of
 *                              information -- a key or a certificate...
 * @retval HITLS_PKCS12_Bag *
 */
HITLS_PKCS12_Bag *HITLS_PKCS12_BagNew(uint32_t bagId, uint32_t bagType, void *bagValue);

/**
 * @ingroup pkcs12
 * @brief Release the bag context.
 *
 * @param bag    [IN] bag context.
 * @retval void
 */
void HITLS_PKCS12_BagFree(HITLS_PKCS12_Bag *bag);

/**
 * @ingroup pkcs12
 * @brief Generic function to set a p12 context.
 *
 * @param bag    [IN] bag context.
 * @param cmd    [IN] HITLS_PKCS12_XXX
 * @param val    [IN/OUT] input and output value
 * @param valType [In] value type or length
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_PKCS12_BagCtrl(HITLS_PKCS12_Bag *bag, int32_t cmd, void *val, uint32_t valType);

/**
 * @ingroup pkcs12
 * @brief Generic function to set a p12 context.
 *
 * @param p12    [IN] p12 context.
 * @param cmd    [IN] HITLS_PKCS12_XXX
 *        cmd                                   val type
 *        HITLS_PKCS12_GEN_LOCALKEYID           AlgId of MD
 *        HITLS_PKCS12_SET_ENTITY_KEYBAG        a pkey bag
 *        HITLS_PKCS12_SET_ENTITY_CERTBAG       a cert bag
 *        HITLS_PKCS12_ADD_CERTBAG              a cert bag
 *        HITLS_PKCS12_GET_ENTITY_CERT          HITLS_X509_Cert**
 *        HITLS_PKCS12_GET_ENTITY_KEY           CRYPT_EAL_PkeyCtx**
 * @param val    [IN/OUT] input and output value
 * @param valLen [In] value length
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_PKCS12_Ctrl(HITLS_PKCS12 *p12, int32_t cmd, void *val, uint32_t valLen);

/**
 * @ingroup pkcs12
 * @brief pkcs12 parse
 * @par Description: parse p12 buffer, and set the p12 struct. When the parameter is
 *  BSL_FORMAT_PEM and BSL_FORMAT_UNKNOWN, the buff of encode needs to end with '\0'
 *
 * @attention Only support to parse p12 buffer in key-integrity and key-privacy protection mode.
 * @param format         [IN] Decoding format: BSL_FORMAT_ASN.
 * @param encode         [IN] encode data
 *        BSL_FORMAT_UNKNOWN/BSL_FORMAT_PEM: the buff of encode needs to end with '\0'
 * @param pwdParam       [IN] include MAC-pwd, enc-pwd, they can be different.
 * @param p12            [OUT] the p12 struct.
 * @param needMacVerify  [IN] true, need verify mac; false, skip mac check.
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_PKCS12_ParseBuff(int32_t format, const BSL_Buffer *encode, const HITLS_PKCS12_PwdParam *pwdParam,
    HITLS_PKCS12 **p12, bool needMacVerify);

/**
 * @ingroup pkcs12
 * @brief pkcs12 parse
 * @par Description: parse p12 buffer, and set the p12 struct.
 *
 * @attention Only support to parse p12 buffer in key-integrity and key-privacy protection mode.
 * @param libCtx         [IN] lib context
 * @param attrName       [IN] attribute name
 * @param format         [IN] Encoding format: "ASN1"
 * @param encode         [IN] encode data
 *        BSL_FORMAT_UNKNOWN/BSL_FORMAT_PEM: the buff of encode needs to end with '\0'
 * @param pwdParam       [IN] include MAC-pwd, enc-pwd, they can be different.
 * @param p12            [OUT] the p12 struct.
 * @param needMacVerify  [IN] true, need verify mac; false, skip mac check.
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_PKCS12_ProviderParseBuff(HITLS_PKI_LibCtx *libCtx, const char *attrName, const char *format,
    const BSL_Buffer *encode, const HITLS_PKCS12_PwdParam *pwdParam, HITLS_PKCS12 **p12, bool needMacVerify);
/**
 * @ingroup pkcs12
 * @par Description: parse p12 file, and set the p12 struct.
 *
 * @attention Only support to parse p12 files in key-integrity and key-privacy protection mode.
 * @param format         [IN] Encoding format: BSL_FORMAT_ASN1
 * @param path           [IN] p12 file path.
 * @param pwdParam       [IN] include MAC-pwd, enc-pwd, they can be different.
 * @param p12            [OUT] the p12 struct.
 * @param needMacVerify  [IN] true, need verify mac; false, skip mac check.
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_PKCS12_ParseFile(int32_t format, const char *path, const HITLS_PKCS12_PwdParam *pwdParam,
    HITLS_PKCS12 **p12, bool needMacVerify);

/**
 * @ingroup pkcs12
 * @brief pkcs12 parse file
 * @par Description: parse p12 file, and set the p12 struct.
 *
 * @attention Only support to parse p12 files in key-integrity and key-privacy protection mode.
 * @param libCtx         [IN] lib context
 * @param attrName       [IN] attribute name
 * @param format         [IN] Encoding format: "ASN1"
 * @param path           [IN] p12 file path.
 * @param pwdParam       [IN] include MAC-pwd, enc-pwd, they can be different.
 * @param p12            [OUT] the p12 struct.
 * @param needMacVerify  [IN] true, need verify mac; false, skip mac check.
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_PKCS12_ProviderParseFile(HITLS_PKI_LibCtx *libCtx, const char *attrName, const char *format,
    const char *path, const HITLS_PKCS12_PwdParam *pwdParam, HITLS_PKCS12 **p12, bool needMacVerify);
/**
 * @ingroup pkcs12
 * @brief pkcs12 gen
 * @par Description: gen p12 buffer.
 *
 * @attention Generate a p12 buffer based on the existing information.
 * @param format          [IN] Encoding format: BSL_FORMAT_ASN1.
 * @param p12             [IN] p12 struct, including entityCert, CA-cert, prvkey, and so on.
 * @param encodeParam     [IN] encode data
 * @param isNeedMac       [IN] Identifies whether macData is required.
 * @param encode          [OUT] result.
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_PKCS12_GenBuff(int32_t format, HITLS_PKCS12 *p12, const HITLS_PKCS12_EncodeParam *encodeParam,
    bool isNeedMac, BSL_Buffer *encode);

/**
 * @ingroup pkcs12
 * @par Description: Generate p12 to store in file
 *
 * @attention Generate a .p12 file based on the existing information.
 * @param format          [IN] Encoding format: BSL_FORMAT_ASN1.
 * @param p12             [IN] p12 struct, including entityCert, CA-cert, prvkey, and so on.
 * @param encodeParam     [IN] encode data
 * @param isNeedMac       [IN] Identifies whether macData is required.
 * @param path            [IN] The path of the generated p12-file.
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_PKCS12_GenFile(int32_t format, HITLS_PKCS12 *p12, const HITLS_PKCS12_EncodeParam *encodeParam,
    bool isNeedMac, const char *path);

#ifdef __cplusplus
}
#endif

#endif // HITLS_PKI_PKCS12_H
