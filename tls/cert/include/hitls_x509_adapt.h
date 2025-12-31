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

#ifndef HITLS_X509_ADAPT_LOCAL_H
#define HITLS_X509_ADAPT_LOCAL_H

#include <stdint.h>
#include "hitls_build.h"
#include "hitls_pki_cert.h"
#include "hitls_pki_x509.h"
#include "hitls_type.h"
#include "hitls_cert.h"
#include "hitls_crypt_type.h"
#include "hitls_cert_type.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HITLS_X509_Adapt_StoreNew HITLS_X509_StoreCtxNew
HITLS_CERT_Store *HITLS_X509_Adapt_StoreDup(HITLS_CERT_Store *store);
#define HITLS_X509_Adapt_StoreFree HITLS_X509_StoreCtxFree
int32_t HITLS_X509_Adapt_StoreCtrl(HITLS_Config *config, HITLS_CERT_Store *store, HITLS_CERT_CtrlCmd cmd,
    void *input, void *output);

int32_t HITLS_X509_Adapt_BuildCertChain(HITLS_Config *config, HITLS_CERT_Store *store, HITLS_CERT_X509 *cert,
    HITLS_CERT_X509 **list, uint32_t *num);
int32_t HITLS_X509_Adapt_VerifyCertChain(HITLS_Ctx *ctx, HITLS_CERT_Store *store, HITLS_CERT_X509 **list, uint32_t num);

int32_t HITLS_X509_Adapt_CertEncode(HITLS_Ctx *ctx, HITLS_CERT_X509 *cert, uint8_t *buf, uint32_t len,
    uint32_t *usedLen);
HITLS_CERT_X509 *HITLS_X509_Adapt_CertParse(HITLS_Config *config, const uint8_t *buf, uint32_t len,
    HITLS_ParseType type, HITLS_ParseFormat format);
#ifdef HITLS_TLS_FEATURE_PROVIDER
HITLS_CERT_X509 *HITLS_CERT_ProviderCertParse(HITLS_Lib_Ctx *libCtx, const char *attrName, const uint8_t *buf,
    uint32_t len, HITLS_ParseType type, const char *format);
#endif
HITLS_CERT_Chain *HITLS_X509_Adapt_BundleCertParse(HITLS_Lib_Ctx *libCtx, const char *attrName, const uint8_t *buf,
    uint32_t len, HITLS_ParseType type, const char *format);
#define HITLS_X509_Adapt_CertDup HITLS_X509_Adapt_CertRef
HITLS_CERT_X509 *HITLS_X509_Adapt_CertRef(HITLS_CERT_X509 *cert);
#define HITLS_X509_Adapt_CertFree HITLS_X509_CertFree
int32_t HITLS_X509_Adapt_CertCtrl(HITLS_Config *config, HITLS_CERT_X509 *cert, HITLS_CERT_CtrlCmd cmd,
    void *input, void *output);

HITLS_CERT_Key *HITLS_X509_Adapt_KeyParse(HITLS_Config *config, const uint8_t *buf, uint32_t len,
    HITLS_ParseType type, HITLS_ParseFormat format);
#ifdef HITLS_TLS_FEATURE_PROVIDER
HITLS_CERT_Key *HITLS_X509_Adapt_ProviderKeyParse(HITLS_Config *config, const uint8_t *buf, uint32_t len,
    HITLS_ParseType type, const char *format, const char *encodeType);
#endif
HITLS_CERT_Key *HITLS_X509_Adapt_KeyDup(HITLS_CERT_Key *key);
void HITLS_X509_Adapt_KeyFree(HITLS_CERT_Key *key);
int32_t HITLS_X509_Adapt_KeyCtrl(HITLS_Config *config, HITLS_CERT_Key *key, HITLS_CERT_CtrlCmd cmd,
    void *input, void *output);

int32_t HITLS_X509_Adapt_CreateSign(HITLS_Ctx *ctx, HITLS_CERT_Key *key, HITLS_SignAlgo signAlgo,
    HITLS_HashAlgo hashAlgo, const uint8_t *data, uint32_t dataLen, uint8_t *sign, uint32_t *signLen);
int32_t HITLS_X509_Adapt_VerifySign(HITLS_Ctx *ctx, HITLS_CERT_Key *key, HITLS_SignAlgo signAlgo,
    HITLS_HashAlgo hashAlgo, const uint8_t *data, uint32_t dataLen, const uint8_t *sign, uint32_t signLen);
int32_t HITLS_X509_Adapt_Encrypt(HITLS_Ctx *ctx, HITLS_CERT_Key *key, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen);
int32_t HITLS_X509_Adapt_Decrypt(HITLS_Ctx *ctx, HITLS_CERT_Key *key, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen);
int32_t HITLS_X509_Adapt_CheckPrivateKey(const HITLS_Config *config, HITLS_CERT_X509 *cert, HITLS_CERT_Key *key);

HITLS_CERT_CRLList *HITLS_X509_Adapt_CrlParse(HITLS_Config *config, const uint8_t *buf, uint32_t len,
    HITLS_ParseType type, HITLS_ParseFormat format);
void HITLS_X509_Adapt_CrlFree(HITLS_CERT_CRLList *crlList);

#ifdef __cplusplus
}
#endif

#endif // HITLS_X509_ADAPT_LOCAL_H