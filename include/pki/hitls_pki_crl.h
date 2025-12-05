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

#ifndef HITLS_PKI_CRL_H
#define HITLS_PKI_CRL_H

#include "hitls_pki_types.h"
#include "crypt_eal_pkey.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _HITLS_X509_Crl HITLS_X509_Crl;

typedef struct _HITLS_X509_CrlEntry HITLS_X509_CrlEntry;

/**
 * @ingroup pki
 * @brief Allocate a crl.
 *
 * @retval HITLS_X509_Crl *
 */
HITLS_X509_Crl *HITLS_X509_CrlNew(void);
/**
 * @ingroup pki
 * @brief Release the CRL.
 * @par Description: Release the memory of the CRL.
 *
 * @attention None
 * @param crl           [IN] CRL after parse.
 * @return Error code
 */
void HITLS_X509_CrlFree(HITLS_X509_Crl *crl);

/**
 * @ingroup pki
 * @brief Crl setting interface.
 * @par Description: Set CRL information.
 *         parameter           data type         Length(len):number of data bytes
 * HITLS_X509_REF_UP       int           The length is sizeof(int), which is used to increase the
 *                                       number of CRL references.
 * @attention None
 * @param crl            [IN] CRL data
 * @param cmd            [IN] Set type.
 * @param val           [OUT] Set data.
 * @param valLen         [IN] The length of val.
 * @return Error code
 */
int32_t HITLS_X509_CrlCtrl(HITLS_X509_Crl *crl, int32_t cmd, void *val, uint32_t valLen);

/**
 * @ingroup pki
 * @brief Parse the CRL in the buffer.
 * @par Description: Parse the CRL in the buffer.
 *  If the parsing is successful, the memory for the crl is requested from within the function,
 *  and the user needs to free it after use. When the parameter is BSL_FORMAT_PEM and
 *  BSL_FORMAT_UNKNOWN, the buff of encode needs to end with '\0'
 * @attention
 *  Support character : UTF8String(only English), PrintableString, TeletexString, T61String,
 *  IA5String.
 * @param format         [IN] Encoding format: BSL_FORMAT_PEM/BSL_FORMAT_ASN1/BSL_FORMAT_UNKNOWN.
 * @param encode         [IN] CRL data.
 *        BSL_FORMAT_UNKNOWN/BSL_FORMAT_PEM: the buff of encode needs to end with '\0'
 *        the dataLen should exclude the end '\0'
 * @param crl           [OUT] CRL after parse.
 * @return Error code
 */
int32_t HITLS_X509_CrlParseBuff(int32_t format, const BSL_Buffer *encode, HITLS_X509_Crl **crl);

/**
 * @ingroup pki
 * @brief Parse multiple CRLs from a buffer.
 * @par Description: Parse multiple CRLs from a buffer.
 *  If parsing is successful, memory for the CRL list is allocated internally,
 *  and the user needs to free it after use.
 * @attention
 *  Support character : UTF8String(only English), PrintableString, TeletexString, T61String,
 *  IA5String.
 * @param format [IN] Encoding format: BSL_FORMAT_PEM/BSL_FORMAT_ASN1/BSL_FORMAT_UNKNOWN.
 * @param encode [IN] CRL data buffer.
 *        BSL_FORMAT_UNKNOWN/BSL_FORMAT_PEM: the buff of encode needs to end with '\0'
 *        the dataLen should exclude the end '\0'
 * @param crlList [OUT] List of parsed CRL objects.
 * @return #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_CrlParseBundleBuff(int32_t format, const BSL_Buffer *encode, HITLS_X509_List **crlList);

/**
 * @ingroup pki
 * @brief Parse the CRL in the file.
 * @par Description: Parse the CRL in the file.
 *  If the parsing is successful, the memory for the crl is requested from within the function,
 *  and the user needs to free it after use.
 * @attention
 *  Support character : UTF8String(only English), PrintableString, TeletexString, T61String,
 *  IA5String.
 * @param format         [IN] Encoding format: BSL_FORMAT_PEM/BSL_FORMAT_ASN1/BSL_FORMAT_UNKNOWN.
 * @param path           [IN] CRL file path.
 * @param crl           [OUT] CRL after parse.
 * @return Error code
 */
int32_t HITLS_X509_CrlParseFile(int32_t format, const char *path, HITLS_X509_Crl **crl);

/**
 * @ingroup pki
 * @brief Parse the CRLs in the file.
 * @par Description: Parse multiple CRLs in the file.
 *  If the parsing is successful, the memory for the crllist is requested from within the function,
 *  and the user needs to free it after use.
 * @attention
 *  Support character : UTF8String(only English), PrintableString, TeletexString, T61String,
 *  IA5String.
 * @param format         [IN] Encoding format: BSL_FORMAT_PEM/BSL_FORMAT_ASN1/
 *                            BSL_FORMAT_UNKNOWN.
 * @param path           [IN] CRL file path.
 * @param crllist       [OUT] CRL list after parse.
 * @return Error code
 */
int32_t HITLS_X509_CrlParseBundleFile(int32_t format, const char *path, HITLS_X509_List **crlList);

/**
 * @ingroup pki
 * @brief Generate a CRL and encode it.
 * @par Description: This function encodes the CRL into the specified format.
 *  If the encoding is successful, the memory for the encode data is requested from within the function,
 *  and the user needs to free it after use.
 *
 * @attention This function is used after parsing the crl or after signing.
 *
 * @attention None
 * @param format        [IN] Encoding format: BSL_FORMAT_PEM or BSL_FORMAT_ASN1.
 * @param crl           [IN] CRL raw data.
 * @param buff          [OUT] Encode data.
 * @return Error code
 */
int32_t HITLS_X509_CrlGenBuff(int32_t format, HITLS_X509_Crl *crl, BSL_Buffer *buff);

/**
 * @ingroup pki
 * @brief Generate a CRL and encode it to specific file.
 * @par Description: This function encodes the CRL into the specified format.
 *  If the encoding is successful, the memory for the encode data is requested from within the function,
 *  and the user needs to free it after use.
 *
 * @attention This function is used after parsing the crl or after signing.
 *
 * @attention None
 * @param format         [IN] Encoding format: BSL_FORMAT_PEM or BSL_FORMAT_ASN1.
 * @param crl            [IN] CRL raw data.
 * @param path          [OUT] Encoding data file path.
 * @return Error code
 */
int32_t HITLS_X509_CrlGenFile(int32_t format, HITLS_X509_Crl *crl, const char *path);

/**
 * @ingroup pki
 * @brief Verify the integrity of the CRL.
 * @par Description: This function verifies the integrity of the CRL
 *
 * @attention For generated CRLs, must be called after signing.
 *
 * @attention None
 * @param pubkey         [IN] pubkey.
 * @param crl            [IN] CRL info.
 * @return Error code
 */
int32_t HITLS_X509_CrlVerify(void *pubkey, const HITLS_X509_Crl *crl);

/**
 * @ingroup pki
 * @brief Signing a CRL.
 * @par Description: This function is used to sign the CRL.
 *
 * @attention 1. This function can only be used when generating a new crl.
 *            2. Before signing, you need to call the HITLS_X509_CrlCtrl interface to set the CRL information.
 *
 * @attention The interface can be called multiple times, and the signature is regenerated on each call.
 * @param mdId           [IN] hash algorithm.
 * @param prvKey         [IN] private key.
 * @param algParam       [IN] signature parameter, for example, rsa-pss parameter.
 * @param crl            [IN/OUT] CRL info.
 * @return Error code
 */
int32_t HITLS_X509_CrlSign(int32_t mdId, const CRYPT_EAL_PkeyCtx *prvKey, const HITLS_X509_SignAlgParam *algParam,
    HITLS_X509_Crl *crl);

/**
 * @ingroup pki crl
 * @brief Allocate a revoked certificate.
 *
 * @attention None
 * @return HITLS_X509_CrlEntry *
 */
HITLS_X509_CrlEntry *HITLS_X509_CrlEntryNew(void);

/**
 * @ingroup pki
 * @brief Release the CRL certificateRevoke struct .
 * @par Description: Release the memory of the CRL certificateRevoke struct.
 *
 * @attention None
 * @param entry            [IN] entry info.
 * @return Error code
 */
void HITLS_X509_CrlEntryFree(HITLS_X509_CrlEntry *entry);

/**
 * @ingroup pki
 * @brief Control interface for CRL entry.
 * @par Description: This function provides control interface for CRL entry operations.
 * @attention None
 * @param revoked        [IN] CRL entry to control.
 * @param cmd            [IN] Control command.
 * @param val            [IN/OUT] Control value.
 * @param valLen         [IN] Length of control value.
 * @return Error code
 */
int32_t HITLS_X509_CrlEntryCtrl(HITLS_X509_CrlEntry *revoked, int32_t cmd, void *val, uint32_t valLen);

#ifdef __cplusplus
}
#endif

#endif // HITLS_PKI_CRL_H
