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

#ifndef HITLS_APP_CONF_H
#define HITLS_APP_CONF_H

#include <stdint.h>
#include "bsl_obj.h"
#include "bsl_conf.h"
#include "hitls_pki_types.h"
#include "hitls_pki_utils.h"
#include "hitls_pki_csr.h"
#include "hitls_pki_cert.h"
#include "hitls_pki_crl.h"
#include "hitls_pki_x509.h"
#include "hitls_pki_pkcs12.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * x509 v3 extensions
 */
#define HITLS_CFG_X509_EXT_AKI      "authorityKeyIdentifier"
#define HITLS_CFG_X509_EXT_SKI      "subjectKeyIdentifier"
#define HITLS_CFG_X509_EXT_BCONS    "basicConstraints"
#define HITLS_CFG_X509_EXT_KU       "keyUsage"
#define HITLS_CFG_X509_EXT_EXKU     "extendedKeyUsage"
#define HITLS_CFG_X509_EXT_SAN      "subjectAltName"

/* Key usage */
#define HITLS_CFG_X509_EXT_KU_DIGITAL_SIGN      "digitalSignature"
#define HITLS_CFG_X509_EXT_KU_NON_REPUDIATION   "nonRepudiation"
#define HITLS_CFG_X509_EXT_KU_KEY_ENCIPHERMENT  "keyEncipherment"
#define HITLS_CFG_X509_EXT_KU_DATA_ENCIPHERMENT "dataEncipherment"
#define HITLS_CFG_X509_EXT_KU_KEY_AGREEMENT     "keyAgreement"
#define HITLS_CFG_X509_EXT_KU_KEY_CERT_SIGN     "keyCertSign"
#define HITLS_CFG_X509_EXT_KU_CRL_SIGN          "cRLSign"
#define HITLS_CFG_X509_EXT_KU_ENCIPHER_ONLY     "encipherOnly"
#define HITLS_CFG_X509_EXT_KU_DECIPHER_ONLY     "decipherOnly"

/* Extended key usage */
#define HITLS_CFG_X509_EXT_EXKU_SERVER_AUTH     "serverAuth"
#define HITLS_CFG_X509_EXT_EXKU_CLIENT_AUTH     "clientAuth"
#define HITLS_CFG_X509_EXT_EXKU_CODE_SING       "codeSigning"
#define HITLS_CFG_X509_EXT_EXKU_EMAIL_PROT      "emailProtection"
#define HITLS_CFG_X509_EXT_EXKU_TIME_STAMP      "timeStamping"
#define HITLS_CFG_X509_EXT_EXKU_OCSP_SIGN       "OCSPSigning"

/* Subject Alternative Name */
#define HITLS_CFG_X509_EXT_SAN_EMAIL            "email"
#define HITLS_CFG_X509_EXT_SAN_DNS              "DNS"
#define HITLS_CFG_X509_EXT_SAN_DIR_NAME         "dirName"
#define HITLS_CFG_X509_EXT_SAN_URI              "URI"
#define HITLS_CFG_X509_EXT_SAN_IP               "IP"

/* Authority key identifier */
#define HITLS_CFG_X509_EXT_AKI_KID          (1 << 0)
#define HITLS_CFG_X509_EXT_AKI_KID_ALWAYS   (1 << 1)
typedef struct {
    HITLS_X509_ExtAki aki;
    uint32_t flag;
} HITLS_CFG_ExtAki;

/**
 * @ingroup apps
 *
 * @brief Split String by character.
 *        Remove spaces before and after separators.
 *
 * @param str           [IN] String to be split.
 * @param separator     [IN] Separator.
 * @param allowEmpty    [IN] Indicates whether empty substrings can be contained.
 * @param strArr        [OUT] String array. Only the first string needs to be released after use.
 * @param maxArrCnt     [IN] String array. Only the first string needs to be released after use.
 * @param realCnt       [OUT] Number of character strings after splitting。
 *
 * @retval HITLS_APP_SUCCESS
 */
int32_t HITLS_APP_SplitString(const char *str, char separator, bool allowEmpty, char **strArr, uint32_t maxArrCnt,
    uint32_t *realCnt);

/**
 * @ingroup apps
 *
 * @brief Process function of X509 extensions.
 *
 * @param cid         [IN] Cid of extension
 * @param val         [IN] Data pointer.
 * @param ctx         [IN] Context.
 *
 * @retval HITLS_APP_SUCCESS
 */
typedef int32_t (*ProcExtCallBack)(BslCid cid, void *val, void *ctx);

/**
 * @ingroup apps
 *
 * @brief Process function of X509 extensions.
 *
 * @param value         [IN] conf
 * @param section       [IN] The section name of x509 extension
 * @param extCb         [IN] Callback function of one extension.
 * @param ctx           [IN] Context of callback function.
 *
 * @retval HITLS_APP_SUCCESS
 */
int32_t HITLS_APP_CONF_ProcExt(BSL_CONF *cnf, const char *section, ProcExtCallBack extCb, void *ctx);

/**
 * @ingroup apps
 *
 * @brief The callback function to add distinguish name
 *
 * @param ctx       [IN] The context of callback function
 * @param nameList  [IN] The linked list of subject name, the type is HITLS_X509_DN
 *
 * @retval HITLS_APP_SUCCESS
 */
typedef int32_t (*AddDnNameCb)(void *ctx, BslList *nameList);

/**
 * @ingroup apps
 *
 * @brief The callback function to add subject name to csr
 *
 * @param ctx       [IN] The context of callback function
 * @param nameList  [IN] The linked list of subject name, the type is HITLS_X509_DN
 *
 * @retval HITLS_APP_SUCCESS
 */
int32_t HiTLS_AddSubjDnNameToCsr(void *csr, BslList *nameList);

/**
 * @ingroup apps
 *
 * @brief Process distinguish name string.
 *        The distinguish name format is /type0=value0/type1=value1/type2=...
 *
 * @param nameStr       [IN] distinguish name string
 * @param cb            [IN] The callback function to add distinguish name to csr or cert
 * @param ctx           [IN] Context of callback function.
 *
 * @retval HITLS_APP_SUCCESS
 */
int32_t HITLS_APP_CFG_ProcDnName(const char *nameStr, AddDnNameCb cb, void *ctx);

#ifdef __cplusplus
}
#endif
#endif  // HITLS_APP_CONF_H
