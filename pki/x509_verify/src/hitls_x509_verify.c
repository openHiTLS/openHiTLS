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

#include "hitls_build.h"
#if defined(HITLS_PKI_X509_VFY_DEFAULT) || defined(HITLS_PKI_X509_VFY_CB) || defined(HITLS_PKI_X509_VFY_LOCATION) || \
    defined(HITLS_PKI_X509_VFY_IDENTITY)
#include <stdio.h>
#include <string.h>
#include "hitls_pki_x509.h"
#include "hitls_pki_cert.h"
#include "bsl_types.h"
#include "sal_atomic.h"
#include "bsl_err_internal.h"
#include "hitls_crl_local.h"
#include "hitls_cert_local.h"
#include "hitls_x509_local.h"
#include "bsl_obj_internal.h"
#include "hitls_pki_errno.h"
#include "bsl_list.h"
#include "crypt_eal_md.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "hitls_x509_verify.h"
#include "crypt_utils.h"
#ifdef HITLS_PKI_X509_VFY_IDENTITY
#include "sal_ip_util.h"
#endif

#define CRYPT_SHA1_DIGESTSIZE 20
#define MAX_PATH_LEN 4096
#define MAX_HOSTNAME_LEN 255

typedef int32_t (*HITLS_X509_TrvListCallBack)(void *ctx, void *node, int32_t depth);

#ifndef HITLS_PKI_X509_VFY_CRL_LITE
typedef struct {
    HITLS_X509_Crl *baseCrl;
    HITLS_X509_Crl *deltaCrl;
    HITLS_X509_Cert *issuerCert;
    uint32_t newReasons;
    uint32_t reasons;
    uint8_t errorPath;
} HITLS_X509_CrlSelection;

#define HITLS_X509_CRL_ERROR_TIME  0x01
#define HITLS_X509_CRL_ERROR_DIFF_SCOPE   0x02
#define HITLS_X509_CRL_ERROR_CRITICAL_EXT 0x04

#define HITLS_X509_REASON_FLAG_NONE                   0x0000
#endif /* HITLS_PKI_X509_VFY_CRL_LITE */

#ifdef HITLS_PKI_X509_VFY_CB
static int32_t VerifyCbDefault(int32_t errCode, HITLS_X509_StoreCtx *storeCtx)
{
    (void)storeCtx;
    return errCode;
}

static int32_t VerifyCertCbk(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Cert *cert, int32_t errDepth, int32_t errCode)
{
    if (cert != NULL) {
        storeCtx->curCert = cert;
    }
    if (errDepth >= 0) {
        storeCtx->curDepth = errDepth;
    }

    if (errCode != HITLS_PKI_SUCCESS) {
        storeCtx->error = errCode;
    }
    return storeCtx->verifyCb(errCode, storeCtx);
}

#define VFYCBK_FAIL_IF(cond, storeCtx, cert, depth, err)                 \
    do {                                                                 \
        if (cond) {                                                      \
            int32_t cbkRet = VerifyCertCbk(storeCtx, cert, depth, err);  \
            if (cbkRet != HITLS_PKI_SUCCESS) {                           \
                BSL_ERR_PUSH_ERROR(err);                                 \
                return cbkRet;                                           \
            }                                                            \
        }                                                                \
    } while (0)
#else
// When callback feature is disabled, use simple error checking
#define VFYCBK_FAIL_IF(cond, storeCtx, cert, depth, err)                 \
    do {                                                                 \
        if (cond) {                                                      \
            BSL_ERR_PUSH_ERROR(err);                                     \
            return err;                                                  \
        }                                                                \
    } while (0)
#endif /* HITLS_PKI_X509_VFY_CB */

// lists can be cert, ext, and so on.
static int32_t HITLS_X509_TrvList(BslList *list, HITLS_X509_TrvListCallBack callBack, void *ctx)
{
    int32_t ret = HITLS_PKI_SUCCESS;
    int32_t depth = 0;
    for (BslListNode *listNode = BSL_LIST_FirstNode(list); listNode != NULL;
        listNode = BSL_LIST_GetNextNode(list, listNode)) {
        void *node = BSL_LIST_GetData(listNode);
        ret = callBack(ctx, node, depth);
        if (ret != BSL_SUCCESS) {
            return ret;
        }
        depth++;
    }
    return ret;
}

// lists can be cert, ext, and so on.
#define HITLS_X509_MAX_DEPTH 20

void HITLS_X509_StoreCtxFree(HITLS_X509_StoreCtx *storeCtx)
{
    if (storeCtx == NULL) {
        return;
    }
    int ret = 0;
    (void)BSL_SAL_AtomicDownReferences(&storeCtx->references, &ret);
    if (ret > 0) {
        return;
    }

#ifdef HITLS_CRYPTO_SM2
    BSL_SAL_FREE(storeCtx->verifyParam.sm2UserId.data);
#endif
#ifdef HITLS_PKI_X509_VFY_IDENTITY
    BSL_LIST_FREE(storeCtx->verifyParam.hostnames, (BSL_LIST_PFUNC_FREE)BSL_SAL_Free);
    BSL_LIST_FREE(storeCtx->verifyParam.uriIds, (BSL_LIST_PFUNC_FREE)BSL_SAL_Free);
    BSL_LIST_FREE(storeCtx->verifyParam.srvIds, (BSL_LIST_PFUNC_FREE)BSL_SAL_Free);
    BSL_SAL_FREE(storeCtx->verifyParam.ip);
    BSL_SAL_FREE(storeCtx->verifyParam.peername);
#endif
    BSL_LIST_FREE(storeCtx->store, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(storeCtx->crl, (BSL_LIST_PFUNC_FREE)HITLS_X509_CrlFree);
    BSL_LIST_FREE(storeCtx->certChain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);

    // Free CA paths list
#ifdef HITLS_PKI_X509_VFY_LOCATION
    if (storeCtx->caPaths != NULL) {
        BSL_LIST_FREE(storeCtx->caPaths, (BSL_LIST_PFUNC_FREE)BSL_SAL_Free);
    }
#endif

    BSL_SAL_ReferencesFree(&storeCtx->references);
    BSL_SAL_Free(storeCtx);
}

static int32_t X509_CertSignatureCmp(HITLS_X509_Asn1AlgId *certOri, BSL_ASN1_BitString *signOri,
    HITLS_X509_Asn1AlgId *cert, BSL_ASN1_BitString *sign)
{
    if (certOri->algId != cert->algId) {
        return 1;
    }
    if (signOri->len != sign->len) {
        return 1;
    }
    return memcmp(signOri->buff, sign->buff, sign->len);
}

int32_t HITLS_X509_CrlCmp(HITLS_X509_Crl *crlOri, HITLS_X509_Crl *crl)
{
    if (crlOri == crl) {
        return 0;
    }
    if (HITLS_X509_CmpNameNode(crlOri->tbs.issuerName, crl->tbs.issuerName) != 0) {
        return 1;
    }
    if (crlOri->tbs.tbsRawDataLen != crl->tbs.tbsRawDataLen) {
        return 1;
    }
    int32_t ret = memcmp(crlOri->tbs.tbsRawData, crl->tbs.tbsRawData, crl->tbs.tbsRawDataLen);
    if (ret != 0) {
        return 1;
    }
    return X509_CertSignatureCmp(&crlOri->tbs.signAlgId, &crlOri->signature,
        &crl->tbs.signAlgId, &crl->signature);
}

int32_t HITLS_X509_CertCmp(HITLS_X509_Cert *certOri, HITLS_X509_Cert *cert)
{
    if (certOri == cert) {
        return 0;
    }
    if (HITLS_X509_CmpNameNode(certOri->tbs.subjectName, cert->tbs.subjectName) != 0) {
        return 1;
    }
    if (certOri->tbs.tbsRawDataLen != cert->tbs.tbsRawDataLen) {
        return 1;
    }
    int32_t ret = memcmp(certOri->tbs.tbsRawData, cert->tbs.tbsRawData, cert->tbs.tbsRawDataLen);
    if (ret != 0) {
        return 1;
    }
    return X509_CertSignatureCmp(&certOri->tbs.signAlgId, &certOri->signature,
        &cert->tbs.signAlgId, &cert->signature);
}

HITLS_X509_StoreCtx *HITLS_X509_StoreCtxNew(void)
{
    HITLS_X509_StoreCtx *ctx = (HITLS_X509_StoreCtx *)BSL_SAL_Malloc(sizeof(HITLS_X509_StoreCtx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }

    (void)memset(ctx, 0, sizeof(HITLS_X509_StoreCtx));
    ctx->store = BSL_LIST_New(sizeof(HITLS_X509_Cert));
    if (ctx->store == NULL) {
        BSL_SAL_Free(ctx);
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }
    ctx->crl = BSL_LIST_New(sizeof(HITLS_X509_Crl));
    if (ctx->crl == NULL) {
        BSL_SAL_FREE(ctx->store);
        BSL_SAL_Free(ctx);
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }

    // Initialize CA paths list
#ifdef HITLS_PKI_X509_VFY_LOCATION
    ctx->caPaths = BSL_LIST_New(sizeof(char *));
    if (ctx->caPaths == NULL) {
        BSL_SAL_FREE(ctx->store);
        BSL_SAL_FREE(ctx->crl);
        BSL_SAL_Free(ctx);
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }
#endif

    ctx->verifyParam.maxDepth = HITLS_X509_MAX_DEPTH;
    ctx->verifyParam.securityBits = 0; // 0: The default number of secure bits.
    ctx->certChain = NULL; // Initialize to NULL, will be created when needed
#ifdef HITLS_PKI_X509_VFY_CB
    ctx->verifyCb = VerifyCbDefault;
#endif
    BSL_SAL_ReferencesInit(&(ctx->references));
    return ctx;
}

static int32_t X509_SetMaxDepth(HITLS_X509_StoreCtx *storeCtx, int32_t *val, uint32_t valLen)
{
    if (valLen != sizeof(int32_t) || *val < 0 || *val > HITLS_X509_MAX_DEPTH) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    storeCtx->verifyParam.maxDepth = *val;
    return HITLS_PKI_SUCCESS;
}

static int32_t X509_GetMaxDepth(HITLS_X509_StoreCtx *storeCtx, int32_t *val, uint32_t valLen)
{
    if (valLen != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    *val = storeCtx->verifyParam.maxDepth;
    return HITLS_PKI_SUCCESS;
}

static int32_t X509_SetParamFlag(HITLS_X509_StoreCtx *storeCtx, const void *val, uint32_t valLen)
{
    if (valLen == sizeof(uint64_t)) {
        storeCtx->verifyParam.flags |= *(const uint64_t *)val;
        return HITLS_PKI_SUCCESS;
    }
    if (valLen == sizeof(uint32_t)) {
        uint64_t temp = (uint64_t)(*(const uint32_t *)val);
        storeCtx->verifyParam.flags |= temp;
        return HITLS_PKI_SUCCESS;
    }
    BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
    return HITLS_X509_ERR_INVALID_PARAM;
}

static int32_t X509_GetParamFlag(HITLS_X509_StoreCtx *storeCtx, uint64_t *val, uint32_t valLen)
{
    if (valLen != sizeof(uint64_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    *val = storeCtx->verifyParam.flags;
    return HITLS_PKI_SUCCESS;
}

static int32_t X509_SetVerifyTime(HITLS_X509_StoreCtx *storeCtx, int64_t *val, uint32_t valLen)
{
    if (valLen != sizeof(int64_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    storeCtx->verifyParam.time = *val;
    storeCtx->verifyParam.flags |= HITLS_X509_VFY_FLAG_TIME;
    return HITLS_PKI_SUCCESS;
}

static int32_t X509_SetVerifySecurityBits(HITLS_X509_StoreCtx *storeCtx, uint32_t *val, uint32_t valLen)
{
    if (valLen != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    storeCtx->verifyParam.securityBits = *val;
    storeCtx->verifyParam.flags |= HITLS_X509_VFY_FLAG_SECBITS;
    return HITLS_PKI_SUCCESS;
}

static int32_t X509_ClearParamFlag(HITLS_X509_StoreCtx *storeCtx, uint64_t *val, uint32_t valLen)
{
    if (valLen != sizeof(uint64_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    storeCtx->verifyParam.flags &= ~(*val);
    return HITLS_PKI_SUCCESS;
}

static int32_t X509_SetPurpose(HITLS_X509_StoreCtx *storeCtx, int32_t *val, uint32_t valLen)
{
    if (valLen != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    storeCtx->verifyParam.purpose = *val;
    return HITLS_PKI_SUCCESS;
}

static int32_t X509_CheckCert(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Cert *cert, HITLS_X509_Cert **findCert)
{
    if (!HITLS_X509_CertIsCA(cert)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CERT_NOT_CA);
        return HITLS_X509_ERR_CERT_NOT_CA;
    }
    HITLS_X509_List *certStore = storeCtx->store;
    HITLS_X509_Cert *tmp = BSL_LIST_SearchDataConst(certStore, cert, (BSL_LIST_PFUNC_CMP)HITLS_X509_CertCmp, NULL);
    if (tmp != NULL) {
        *findCert = tmp;
        return HITLS_X509_ERR_CERT_EXIST;
    }

    return HITLS_PKI_SUCCESS;
}

static int32_t X509_SetCA(HITLS_X509_StoreCtx *storeCtx, void *val, bool isCopy)
{
    HITLS_X509_Cert *findCert = NULL;
    int32_t ret = X509_CheckCert(storeCtx, val, &findCert);
    if (ret == HITLS_X509_ERR_CERT_EXIST) {
        if (findCert == val) {
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CERT_EXIST);
            return HITLS_X509_ERR_CERT_EXIST;
        }
        if (!isCopy) {
            HITLS_X509_CertFree(val);
        }
        return HITLS_PKI_SUCCESS;
    }
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (isCopy) {
        int ref;
        ret = HITLS_X509_CertCtrl(val, HITLS_X509_REF_UP, &ref, sizeof(int));
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
    }

    ret = BSL_LIST_AddElement(storeCtx->store, val, BSL_LIST_POS_BEGIN);
    if (ret != BSL_SUCCESS) {
        if (isCopy) {
            HITLS_X509_CertFree(val);
        }
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t X509_CheckCRL(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Crl *crl)
{
    HITLS_X509_List *crlStore = storeCtx->crl;
    HITLS_X509_Crl *tmp = BSL_LIST_SearchDataConst(crlStore, crl, (BSL_LIST_PFUNC_CMP)HITLS_X509_CrlCmp, NULL);
    if (tmp != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CRL_EXIST);
        return HITLS_X509_ERR_CRL_EXIST;
    }

    return HITLS_PKI_SUCCESS;
}

static int32_t X509_SetCRL(HITLS_X509_StoreCtx *storeCtx, void *val)
{
    int32_t ret = X509_CheckCRL(storeCtx, val);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    int ref;
    ret = HITLS_X509_CrlCtrl(val, HITLS_X509_REF_UP, &ref, sizeof(int));
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = BSL_LIST_AddElement(storeCtx->crl, val, BSL_LIST_POS_BEGIN);
    if (ret != BSL_SUCCESS) {
        HITLS_X509_CrlFree(val);
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

#ifdef HITLS_PKI_X509_VFY_LOCATION
static int32_t X509_AddCAPath(HITLS_X509_StoreCtx *storeCtx, const void *val, uint32_t valLen)
{
    if (valLen == 0 || valLen > MAX_PATH_LEN) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    const char *caPath = (const char *)val;

    for (BslListNode *pathNode = BSL_LIST_FirstNode(storeCtx->caPaths); pathNode != NULL;
        pathNode = BSL_LIST_GetNextNode(storeCtx->caPaths, pathNode)) {
        char *existPath = (char *)BSL_LIST_GetData(pathNode);
        if (strlen(existPath) == valLen && memcmp(existPath, caPath, valLen) == 0) {
            return HITLS_PKI_SUCCESS;
        }
    }

    // Allocate and copy new path
    char *pathCopy = BSL_SAL_Calloc(valLen + 1, sizeof(char));
    if (pathCopy == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    memcpy(pathCopy, caPath, valLen);
    // Add to paths list
    int32_t ret = BSL_LIST_AddElement(storeCtx->caPaths, pathCopy, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_Free(pathCopy);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    return HITLS_PKI_SUCCESS;
}

static int32_t X509_SetDefaultCAPath(HITLS_X509_StoreCtx *storeCtx)
{
    char defaultPath[MAX_PATH_LEN] = {0};
    int n = snprintf(defaultPath, sizeof(defaultPath), "%s/ssl/certs", OPENHITLSDIR);
    if (n < 0 || (size_t)n >= sizeof(defaultPath)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    /* Use X509_AddCAPath to add the default path */
    return X509_AddCAPath(storeCtx, defaultPath, (uint32_t)strlen(defaultPath));
}
#endif /* HITLS_PKI_X509_VFY_LOCATION */

static int32_t X509_ClearCRL(HITLS_X509_StoreCtx *storeCtx)
{
    if (storeCtx->crl == NULL) {
        return HITLS_PKI_SUCCESS;
    }

    BSL_LIST_DeleteAll(storeCtx->crl, (BSL_LIST_PFUNC_FREE)HITLS_X509_CrlFree);
    return HITLS_PKI_SUCCESS;
}

static int32_t X509_RefUp(HITLS_X509_StoreCtx *storeCtx, void *val, uint32_t valLen)
{
    if (valLen != sizeof(int)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    return BSL_SAL_AtomicUpReferences(&storeCtx->references, val);
}

#ifdef HITLS_PKI_X509_VFY_CB
/* New functions for the added fields */
static int32_t X509_SetError(HITLS_X509_StoreCtx *storeCtx, int32_t *val, uint32_t valLen)
{
    if (valLen != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    storeCtx->error = *val;
    return HITLS_PKI_SUCCESS;
}

static int32_t X509_GetError(HITLS_X509_StoreCtx *storeCtx, int32_t *val, uint32_t valLen)
{
    if (valLen != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    *val = storeCtx->error;
    return HITLS_PKI_SUCCESS;
}

static int32_t X509_GetCurrent(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Cert **val, uint32_t valLen)
{
    if (valLen != sizeof(HITLS_X509_Cert *)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    *val = storeCtx->curCert;
    return HITLS_PKI_SUCCESS;
}

static int32_t X509_SetVerifyCb(HITLS_X509_StoreCtx *storeCtx, X509_STORECTX_VerifyCb val, uint32_t valLen)
{
    if (valLen != sizeof(X509_STORECTX_VerifyCb)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    storeCtx->verifyCb = val;
    return HITLS_PKI_SUCCESS;
}

static int32_t X509_GetVerifyCb(HITLS_X509_StoreCtx *storeCtx, X509_STORECTX_VerifyCb *val, uint32_t valLen)
{
    if (valLen != sizeof(X509_STORECTX_VerifyCb)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    *val = storeCtx->verifyCb;
    return HITLS_PKI_SUCCESS;
}

static int32_t X509_SetCurDepth(HITLS_X509_StoreCtx *storeCtx, int32_t *val, uint32_t valLen)
{
    if (valLen != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    storeCtx->curDepth = *val;
    return HITLS_PKI_SUCCESS;
}

static int32_t X509_GetCurDepth(HITLS_X509_StoreCtx *storeCtx, int32_t *val, uint32_t valLen)
{
    if (valLen != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    *val = storeCtx->curDepth;
    return HITLS_PKI_SUCCESS;
}

static int32_t X509_SetUsrData(HITLS_X509_StoreCtx *storeCtx, void *val, uint32_t valLen)
{
    if (valLen != sizeof(void *)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    storeCtx->usrData = val;
    return HITLS_PKI_SUCCESS;
}

static int32_t X509_GetUsrData(HITLS_X509_StoreCtx *storeCtx, void **val, uint32_t valLen)
{
    if (valLen != sizeof(void *)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    *val = storeCtx->usrData;
    return HITLS_PKI_SUCCESS;
}

static int32_t X509_SetPeerCertChain(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *chain, uint32_t chainLen)
{
    if (chainLen != sizeof(HITLS_X509_List *)) {
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    storeCtx->peerCertChain = chain;
    return HITLS_PKI_SUCCESS;
}

static int32_t X509_GetPeerCertChain(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List **chain, uint32_t chainLen)
{
    if (chainLen != sizeof(HITLS_X509_List *)) {
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    *chain = storeCtx->peerCertChain;
    return HITLS_PKI_SUCCESS;
}
#endif /* HITLS_PKI_X509_VFY_CB */

static int32_t X509_GetCertChain(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List **val, uint32_t valLen)
{
    if (valLen != sizeof(HITLS_X509_List *)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    *val = storeCtx->certChain;
    return HITLS_PKI_SUCCESS;
}

#if defined(HITLS_PKI_X509_VFY_IDENTITY) || defined(HITLS_PKI_X509_VFY_LOCATION)

static char *DupString(const char *str)
{
    char *dest = BSL_SAL_Dump(str, strlen(str) + 1);
    if (dest == NULL) {
        return NULL;
    }
    dest[strlen(str)] = '\0';
    return dest;
}

static int32_t X509_CopyStringList(BslList *dst, const BslList *src)
{
    for (BslListNode *node = BSL_LIST_FirstNode(src); node != NULL; node = BSL_LIST_GetNextNode(src, node)) {
        char *value = (char *)BSL_LIST_GetData(node);
        char *copy = DupString(value);
        if (copy == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }
        int32_t ret = BSL_LIST_AddElement(dst, copy, BSL_LIST_POS_END);
        if (ret != BSL_SUCCESS) {
            BSL_SAL_Free(copy);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    return HITLS_PKI_SUCCESS;
}
#endif

#ifdef HITLS_PKI_X509_VFY_IDENTITY
static int32_t X509_SetHostFlags(HITLS_X509_StoreCtx *storeCtx, const uint32_t *val, uint32_t valLen)
{
    if (valLen != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    storeCtx->verifyParam.hostflags |= *val;
    return HITLS_PKI_SUCCESS;
}

static int32_t X509_SetVerifyHost(HITLS_X509_StoreCtx *storeCtx, const char *hostname)
{
    if (hostname == NULL) {
        return HITLS_PKI_SUCCESS;
    }

    char *tmp = DupString(hostname);
    if (tmp == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    if (storeCtx->verifyParam.hostnames == NULL) {
        storeCtx->verifyParam.hostnames = BSL_LIST_New(sizeof(char *));
        if (storeCtx->verifyParam.hostnames == NULL) {
            BSL_SAL_Free(tmp);
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }
    }

    int32_t ret = BSL_LIST_AddElement(storeCtx->verifyParam.hostnames, tmp, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_Free(tmp);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t X509_AddVerifyString(BslList **list, const char *val)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    size_t valLen = strlen(val);
    if (valLen > MAX_PATH_LEN || valLen == 0) {
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    char *tmp = DupString(val);
    if (tmp == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    if (*list == NULL) {
        *list = BSL_LIST_New(sizeof(char *));
        if (*list == NULL) {
            BSL_SAL_Free(tmp);
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }
    }

    int32_t ret = BSL_LIST_AddElement(*list, tmp, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_Free(tmp);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t X509_SetVerifyString(BslList **list, const char *val)
{
    if (val == NULL) {
        BSL_LIST_FREE(*list, (BSL_LIST_PFUNC_FREE)BSL_SAL_Free);
        return HITLS_PKI_SUCCESS;
    }

    BslList *newList = NULL;
    int32_t ret = X509_AddVerifyString(&newList, val);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_LIST_FREE(newList, (BSL_LIST_PFUNC_FREE)BSL_SAL_Free);
        return ret;
    }

    BSL_LIST_FREE(*list, (BSL_LIST_PFUNC_FREE)BSL_SAL_Free);
    *list = newList;
    return HITLS_PKI_SUCCESS;
}

static int32_t X509_SetVerifyIp(HITLS_X509_StoreCtx *storeCtx, unsigned char *ip, int32_t ipLen)
{
    storeCtx->verifyParam.ip = BSL_SAL_Malloc(ipLen);
    if (storeCtx->verifyParam.ip == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    (void)memcpy(storeCtx->verifyParam.ip, ip, ipLen);
    storeCtx->verifyParam.ipLen = ipLen;
    return HITLS_PKI_SUCCESS;
}

static int32_t X509_SetHost(HITLS_X509_StoreCtx *storeCtx, const void *val)
{
    const char *hostname = (const char *)val;
    if (hostname == NULL) {
        BSL_SAL_FREE(storeCtx->verifyParam.ip);
        BSL_LIST_FREE(storeCtx->verifyParam.hostnames, (BSL_LIST_PFUNC_FREE)BSL_SAL_Free);
        return HITLS_PKI_SUCCESS;
    }
    size_t hostnameLen = strlen(hostname);
    if (hostnameLen > MAX_HOSTNAME_LEN || hostnameLen == 0) {
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    unsigned char buff[16];
    int32_t len = sizeof(buff) / sizeof(buff[0]);
    if (SAL_ParseIp(hostname, buff, &len) == BSL_SUCCESS) {
        BSL_SAL_FREE(storeCtx->verifyParam.ip);
        return X509_SetVerifyIp(storeCtx, buff, len);
    }

    BSL_LIST_FREE(storeCtx->verifyParam.hostnames, (BSL_LIST_PFUNC_FREE)BSL_SAL_Free);
    return X509_SetVerifyHost(storeCtx, hostname);
}

static int32_t X509_AddHost(HITLS_X509_StoreCtx *storeCtx, const void *val)
{
    const char *hostname = (const char *)val;
    size_t hostnameLen = strlen(hostname);
    if (hostnameLen > MAX_HOSTNAME_LEN || hostnameLen == 0) {
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    
    unsigned char buff[16];
    int32_t len = sizeof(buff) / sizeof(buff[0]);
    if (SAL_ParseIp(hostname, buff, &len) == BSL_SUCCESS) {
        if (storeCtx->verifyParam.ip != NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_ADD_VERIFY_IP);
            return HITLS_X509_ERR_ADD_VERIFY_IP;
        }
        return X509_SetVerifyIp(storeCtx, buff, len);
    }

    return X509_SetVerifyHost(storeCtx, hostname);
}
#endif

static int32_t X509VfyOtherCtrl(HITLS_X509_StoreCtx *storeCtx, int32_t cmd, void *val, uint32_t valLen)
{
    (void)storeCtx;
    (void)val;
    (void)valLen;
    switch (cmd) {
#ifdef HITLS_PKI_X509_VFY_IDENTITY
        case HITLS_X509_STORECTX_SET_HOST_FLAG:
            return X509_SetHostFlags(storeCtx, val, valLen);
        case HITLS_X509_STORECTX_SET_HOST:
            return X509_SetHost(storeCtx, val);
        case HITLS_X509_STORECTX_ADD_HOST:
            return X509_AddHost(storeCtx, val);
        case HITLS_X509_STORECTX_SET_URI_ID:
            return X509_SetVerifyString(&storeCtx->verifyParam.uriIds, (const char *)val);
        case HITLS_X509_STORECTX_ADD_URI_ID:
            return X509_AddVerifyString(&storeCtx->verifyParam.uriIds, (const char *)val);
        case HITLS_X509_STORECTX_SET_SRV_ID:
            return X509_SetVerifyString(&storeCtx->verifyParam.srvIds, (const char *)val);
        case HITLS_X509_STORECTX_ADD_SRV_ID:
            return X509_AddVerifyString(&storeCtx->verifyParam.srvIds, (const char *)val);
#endif
        default:
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
            return HITLS_X509_ERR_INVALID_PARAM;
    }
}

int32_t X509VfyBeforeCtrl(HITLS_X509_StoreCtx *storeCtx, int32_t cmd, void *val, uint32_t valLen)
{
    switch (cmd) {
        case HITLS_X509_STORECTX_SET_PARAM_DEPTH:
            return X509_SetMaxDepth(storeCtx, val, valLen);
        case HITLS_X509_STORECTX_SET_PARAM_FLAGS:
            return X509_SetParamFlag(storeCtx, val, valLen);
        case HITLS_X509_STORECTX_SET_PURPOSE:
            return X509_SetPurpose(storeCtx, val, valLen);
        case HITLS_X509_STORECTX_SET_TIME:
            return X509_SetVerifyTime(storeCtx, val, valLen);
        case HITLS_X509_STORECTX_SET_SECBITS:
            return X509_SetVerifySecurityBits(storeCtx, val, valLen);
        case HITLS_X509_STORECTX_CLR_PARAM_FLAGS:
            return X509_ClearParamFlag(storeCtx, val, valLen);
        case HITLS_X509_STORECTX_DEEP_COPY_SET_CA:
            return X509_SetCA(storeCtx, val, true);
        case HITLS_X509_STORECTX_SHALLOW_COPY_SET_CA:
            return X509_SetCA(storeCtx, val, false);
        case HITLS_X509_STORECTX_SET_CRL:
            return X509_SetCRL(storeCtx, val);
#ifdef HITLS_CRYPTO_SM2
        case HITLS_X509_STORECTX_SET_VFY_SM2_USERID:
            return HITLS_X509_SetSm2UserId(&storeCtx->verifyParam.sm2UserId, val, valLen);
#endif
#ifdef HITLS_PKI_X509_VFY_CB
        case HITLS_X509_STORECTX_SET_VERIFY_CB:
            return X509_SetVerifyCb(storeCtx, val, valLen);
        case HITLS_X509_STORECTX_SET_USR_DATA:
            return X509_SetUsrData(storeCtx, val, valLen);
        case HITLS_X509_STORECTX_SET_PEER_CERT_CHAIN:
            return X509_SetPeerCertChain(storeCtx, val, valLen);
#endif
#ifdef HITLS_PKI_X509_VFY_LOCATION
        case HITLS_X509_STORECTX_ADD_CA_PATH:
            return X509_AddCAPath(storeCtx, val, valLen);
        case HITLS_X509_STORECTX_SET_DEFAULT_PATH:
            return X509_SetDefaultCAPath(storeCtx);
#endif
        case HITLS_X509_STORECTX_CLEAR_CRL:
            return X509_ClearCRL(storeCtx);
        default:
            return X509VfyOtherCtrl(storeCtx, cmd, val, valLen);
    }
}

int32_t X509VfyAllTimeCtrl(HITLS_X509_StoreCtx *storeCtx, int32_t cmd, void *val, uint32_t valLen)
{
    switch (cmd) {
        case HITLS_X509_STORECTX_REF_UP:
            return X509_RefUp(storeCtx, val, valLen);
        case HITLS_X509_STORECTX_GET_PARAM_DEPTH:
            return X509_GetMaxDepth(storeCtx, val, valLen);
#ifdef HITLS_PKI_X509_VFY_CB
        case HITLS_X509_STORECTX_GET_VERIFY_CB:
            return X509_GetVerifyCb(storeCtx, val, valLen);
        case HITLS_X509_STORECTX_GET_USR_DATA:
            return X509_GetUsrData(storeCtx, val, valLen);
        case HITLS_X509_STORECTX_GET_PEER_CERT_CHAIN:
            return X509_GetPeerCertChain(storeCtx, val, valLen);
#endif
        case HITLS_X509_STORECTX_GET_PARAM_FLAGS:
            return X509_GetParamFlag(storeCtx, val, valLen);
#ifdef HITLS_PKI_X509_VFY_IDENTITY
        case HITLS_X509_STORECTX_GET_PEERNAME:
            {
                *(char **)val = storeCtx->verifyParam.peername;
                return HITLS_PKI_SUCCESS;
            }
#endif
        default:
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
            return HITLS_X509_ERR_INVALID_PARAM;
    }
}

int32_t X509VfyDoingCtrl(HITLS_X509_StoreCtx *storeCtx, int32_t cmd, void *val, uint32_t valLen)
{
    switch (cmd) {
#ifdef HITLS_PKI_X509_VFY_CB
        case HITLS_X509_STORECTX_SET_ERROR:
            return X509_SetError(storeCtx, val, valLen);
        case HITLS_X509_STORECTX_GET_ERROR:
            return X509_GetError(storeCtx, val, valLen);
        case HITLS_X509_STORECTX_GET_CUR_CERT:
            return X509_GetCurrent(storeCtx, val, valLen);
        case HITLS_X509_STORECTX_SET_CUR_DEPTH:
            return X509_SetCurDepth(storeCtx, val, valLen);
        case HITLS_X509_STORECTX_GET_CUR_DEPTH:
            return X509_GetCurDepth(storeCtx, val, valLen);
#endif
        case HITLS_X509_STORECTX_GET_CERT_CHAIN:
            return X509_GetCertChain(storeCtx, val, valLen);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
            return HITLS_X509_ERR_INVALID_PARAM;
    }
}

int32_t HITLS_X509_StoreCtxCtrl(HITLS_X509_StoreCtx *storeCtx, int32_t cmd, void *val, uint32_t valLen)
{
    if (storeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    // Allow val to be NULL only for specific commands like CLEAR_CRL and SET_DEFAULT_PATH
    if (val == NULL && cmd != HITLS_X509_STORECTX_CLEAR_CRL && cmd != HITLS_X509_STORECTX_SET_DEFAULT_PATH &&
        cmd != HITLS_X509_STORECTX_SET_PEER_CERT_CHAIN
#ifdef HITLS_PKI_X509_VFY_IDENTITY
        && cmd != HITLS_X509_STORECTX_SET_HOST
        && cmd != HITLS_X509_STORECTX_SET_URI_ID
        && cmd != HITLS_X509_STORECTX_SET_SRV_ID
#endif
    ) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    if (cmd < HITLS_X509_STORECTX_REF_UP) {
        return X509VfyBeforeCtrl(storeCtx, cmd, val, valLen);
    } else if (cmd < HITLS_X509_STORECTX_SET_ERROR) {
        return X509VfyAllTimeCtrl(storeCtx, cmd, val, valLen);
    } else {
        return X509VfyDoingCtrl(storeCtx, cmd, val, valLen);
    }
}

int32_t HITLS_X509_CheckCertTime(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Cert *cert, int32_t depth,
    const int64_t *time)
{
    (void)depth;
    (void)storeCtx;
    int64_t start = 0;
    int64_t end = 0;
    HITLS_X509_ValidTime *validTime = &cert->tbs.validTime;
    if (time == NULL) {
        return HITLS_PKI_SUCCESS;
    }

    int32_t ret = BSL_SAL_DateToUtcTimeConvert(&validTime->start, &start);
    VFYCBK_FAIL_IF(ret != BSL_SUCCESS, storeCtx, cert, depth, HITLS_X509_ERR_VFY_GET_NOTBEFORE_FAIL);
    VFYCBK_FAIL_IF(start > *time, storeCtx, cert, depth, HITLS_X509_ERR_VFY_NOTBEFORE_IN_FUTURE);

    ret = BSL_SAL_DateToUtcTimeConvert(&validTime->end, &end);
    VFYCBK_FAIL_IF(ret != BSL_SUCCESS, storeCtx, cert, depth, HITLS_X509_ERR_VFY_GET_NOTAFTER_FAIL);
    VFYCBK_FAIL_IF(end < *time, storeCtx, cert, depth, HITLS_X509_ERR_VFY_NOTAFTER_EXPIRED);
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_X509_CheckCrlTime(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Crl *crl, int32_t depth,
    const int64_t *time)
{
    (void)depth;
    (void)storeCtx;
    int64_t start = 0;
    int64_t end = 0;
    HITLS_X509_ValidTime *validTime = &crl->tbs.validTime;
    if (time == NULL) {
        return HITLS_PKI_SUCCESS;
    }

    int32_t ret = BSL_SAL_DateToUtcTimeConvert(&validTime->start, &start);
    VFYCBK_FAIL_IF(ret != BSL_SUCCESS, storeCtx, NULL, depth, HITLS_X509_ERR_VFY_GET_THISUPDATE_FAIL);
    VFYCBK_FAIL_IF(start > *time, storeCtx, NULL, depth, HITLS_X509_ERR_VFY_THISUPDATE_IN_FUTURE);

    if ((validTime->flag & BSL_TIME_AFTER_SET) == 0) {
        return HITLS_PKI_SUCCESS;
    }

    ret = BSL_SAL_DateToUtcTimeConvert(&validTime->end, &end);
    VFYCBK_FAIL_IF(ret != BSL_SUCCESS, storeCtx, NULL, depth, HITLS_X509_ERR_VFY_GET_NEXTUPDATE_FAIL);
    VFYCBK_FAIL_IF(end < *time, storeCtx, NULL, depth, HITLS_X509_ERR_VFY_NEXTUPDATE_EXPIRED);
    return HITLS_PKI_SUCCESS;
}

#ifndef HITLS_PKI_X509_VFY_CRL_LITE
static int32_t X509_CheckCrlTimeWithoutCb(int64_t *time, HITLS_X509_Crl *crl)
{
    // If time is not set, consider it as valid (no time check)
    if (time == NULL) {
        return HITLS_PKI_SUCCESS;
    }
    int64_t start = 0;
    int64_t end = 0;
    HITLS_X509_ValidTime *validTime = &crl->tbs.validTime;
    int32_t ret = BSL_SAL_DateToUtcTimeConvert(&validTime->start, &start);
    if (ret != BSL_SUCCESS) {
        return HITLS_X509_ERR_VFY_GET_THISUPDATE_FAIL;
    }
    if (start > *time) {
        return HITLS_X509_ERR_VFY_THISUPDATE_IN_FUTURE;
    }

    if ((validTime->flag & BSL_TIME_AFTER_SET) == 0) {
        return HITLS_PKI_SUCCESS;
    }

    ret = BSL_SAL_DateToUtcTimeConvert(&validTime->end, &end);
    if (ret != BSL_SUCCESS) {
        return HITLS_X509_ERR_VFY_GET_NEXTUPDATE_FAIL;
    }
    if (end < *time) {
        return HITLS_X509_ERR_VFY_NEXTUPDATE_EXPIRED;
    }
    return HITLS_PKI_SUCCESS;
}
#endif /* HITLS_PKI_X509_VFY_CRL_LITE */

static int32_t X509_AddCertToChain(HITLS_X509_List *chain, HITLS_X509_Cert *cert)
{
    int ref;
    int32_t ret = HITLS_X509_CertCtrl(cert, HITLS_X509_REF_UP, &ref, sizeof(int));
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = BSL_LIST_AddElement(chain, cert, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        HITLS_X509_CertFree(cert);
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

#ifdef HITLS_PKI_X509_VFY_LOCATION
static int32_t CheckAndAddIssuerCert(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Cert *candidateCert,
                                     HITLS_X509_Cert *cert, HITLS_X509_Cert **issue, bool *issueInTrust)
{
    bool res = HITLS_X509_CheckIssued(candidateCert, cert);
    if (res) {
        *issue = candidateCert;
        *issueInTrust = true;
        int32_t ret = X509_SetCA(storeCtx, candidateCert, false);
        if (ret == HITLS_PKI_SUCCESS) {
            return HITLS_PKI_SUCCESS;
        }
    }
    return HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND;
}

static int32_t HITLS_X509_GetCertBySubjectDer(HITLS_X509_StoreCtx *storeCtx, const BSL_ASN1_Buffer *subjectDerData,
                                              HITLS_X509_Cert *cert, HITLS_X509_Cert **issue, bool *issueInTrust)
{
    // Only try on-demand loading from CA paths using hash-based lookup
    if (storeCtx->caPaths == NULL || BSL_LIST_COUNT(storeCtx->caPaths) <= 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND);
        return HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND;
    }

    // Calculate hash from canon-encoded subject DN
    uint32_t hash = 0;
    uint8_t digest[CRYPT_SHA1_DIGESTSIZE];
    uint32_t digestLen = CRYPT_SHA1_DIGESTSIZE;
    int32_t ret = HITLS_PKI_SUCCESS;
    CRYPT_EAL_MdCtx *mdCtx = CRYPT_EAL_ProviderMdNewCtx(storeCtx->libCtx, CRYPT_MD_SHA1, storeCtx->attrName);
    if (mdCtx != NULL) {
        if (CRYPT_EAL_MdInit(mdCtx) == CRYPT_SUCCESS &&
            CRYPT_EAL_MdUpdate(mdCtx, subjectDerData->buff, subjectDerData->len) == CRYPT_SUCCESS) {
            if (CRYPT_EAL_MdFinal(mdCtx, digest, &digestLen) == CRYPT_SUCCESS && digestLen >= 4) {
                hash = (uint32_t)digest[0] | ((uint32_t)digest[1] << 8) |
                       ((uint32_t)digest[2] << 16) | ((uint32_t)digest[3] << 24);
            }
        }
        CRYPT_EAL_MdFreeCtx(mdCtx);
    }

    if (hash == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND);
        return HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND;
    }

    // Try to load certificate using hash-based file lookup from CA paths
    for (BslListNode *pathNode = BSL_LIST_FirstNode(storeCtx->caPaths); pathNode != NULL;
        pathNode = BSL_LIST_GetNextNode(storeCtx->caPaths, pathNode)) {
        char *caPath = (char *)BSL_LIST_GetData(pathNode);
        int32_t seq = 0;
        while (1) {
            char filename[MAX_PATH_LEN] = {0};
            int n = snprintf(filename, sizeof(filename), "%s/%08x.%d", caPath, hash, seq);
            if (n < 0 || (size_t)n >= sizeof(filename)) {
                break;
            }
            HITLS_X509_Cert *candidateCert = NULL;
            ret = HITLS_X509_CertParseFile(BSL_FORMAT_PEM, filename, &candidateCert);
            if (ret != HITLS_PKI_SUCCESS) {
                break;
            }
            if (CheckAndAddIssuerCert(storeCtx, candidateCert, cert, issue, issueInTrust) == HITLS_PKI_SUCCESS) {
                return HITLS_PKI_SUCCESS;
            }
            HITLS_X509_CertFree(candidateCert);
            seq++;
        }
    }
    BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND);
    return HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND;
}

static int32_t FindIssuerByDer(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Cert *cert, HITLS_X509_Cert **issue,
                               bool *issueInTrust)
{
    BslList *rawIssuer = NULL;
    BSL_ASN1_Buffer issuerDerData = {0};
    int32_t ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_ISSUER_DN, &rawIssuer, sizeof(BslList *));
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = HITLS_X509_EncodeCanonNameList(rawIssuer, &issuerDerData);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (issuerDerData.buff == NULL || issuerDerData.len == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND);
        return HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND;
    }

    ret = HITLS_X509_GetCertBySubjectDer(storeCtx, &issuerDerData, cert, issue, issueInTrust);
    BSL_SAL_Free(issuerDerData.buff);
    return ret;
}
#endif /* HITLS_PKI_X509_VFY_LOCATION */

/* The function can only return success and CERT NOT FOUND */
static int32_t X509_FindIssueCert(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *certChain, HITLS_X509_Cert *cert,
    HITLS_X509_Cert **issue, bool *issueInTrust)
{
    // First try to find issuer in explicitly loaded store
    HITLS_X509_List *store = storeCtx->store;
    BSL_ERR_SET_MARK();
    for (BslListNode *certNode = BSL_LIST_FirstNode(store); certNode != NULL;
        certNode = BSL_LIST_GetNextNode(store, certNode)) {
        HITLS_X509_Cert *tmp = (HITLS_X509_Cert *)BSL_LIST_GetData(certNode);
        if (HITLS_X509_CheckIssued(tmp, cert)) {
            *issue = tmp;
            BSL_ERR_POP_TO_MARK();
            *issueInTrust = true;
            return HITLS_PKI_SUCCESS;
        }
    }

#ifdef HITLS_PKI_X509_VFY_LOCATION
    // If we have CA paths set, try on-demand loading based on issuer DER-encoded DN
    if (BSL_LIST_COUNT(storeCtx->caPaths) > 0) {
        int32_t ret = FindIssuerByDer(storeCtx, cert, issue, issueInTrust);
        if (ret == HITLS_PKI_SUCCESS) {
            BSL_ERR_POP_TO_MARK();
            return HITLS_PKI_SUCCESS;
        }
    }
#endif /* HITLS_PKI_X509_VFY_LOCATION */

    // Then try the certificate chain if provided, skipping the cert itself
    if (certChain != NULL) {
        for (BslListNode *certNode = BSL_LIST_FirstNode(certChain); certNode != NULL;
            certNode = BSL_LIST_GetNextNode(certChain, certNode)) {
            HITLS_X509_Cert *tmp = (HITLS_X509_Cert *)BSL_LIST_GetData(certNode);
            if (HITLS_X509_CertCmp(tmp, cert) == 0) {
                continue;
            }
            if (HITLS_X509_CheckIssued(tmp, cert)) {
                *issue = tmp;
                BSL_ERR_POP_TO_MARK();
                *issueInTrust = false;
                return HITLS_PKI_SUCCESS;
            }
        }
    }
    BSL_ERR_POP_TO_MARK();
    BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND);
    return HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND;
}


int32_t X509_BuildChain(bool isVfy, HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *certChain, HITLS_X509_Cert *cert,
    HITLS_X509_List *chain, HITLS_X509_Cert **root)
{
    HITLS_X509_Cert *cur = cert;
    int32_t ret = HITLS_PKI_SUCCESS;
    int32_t maxFindNum = 100; // prevent dead loops caused by circular certificates
#ifdef HITLS_PKI_X509_VFY_CB
    storeCtx->curDepth = 0;
    storeCtx->curCert = cur;
#endif
    while (cur != NULL && maxFindNum > 0) {
        maxFindNum--;
        bool isTrustCa = false;
        HITLS_X509_Cert *issue = NULL;
        ret = X509_FindIssueCert(storeCtx, certChain, cur, &issue, &isTrustCa);
        if (ret != HITLS_PKI_SUCCESS) {
            break;
        }
        // depth
#ifdef HITLS_PKI_X509_VFY_CB
        VFYCBK_FAIL_IF(BSL_LIST_COUNT(chain) + 1 > storeCtx->verifyParam.maxDepth, storeCtx,
            storeCtx->curCert, storeCtx->curDepth, HITLS_X509_ERR_CHAIN_DEPTH_UP_LIMIT);
#else
        VFYCBK_FAIL_IF(BSL_LIST_COUNT(chain) + 1 > storeCtx->verifyParam.maxDepth, NULL, NULL, 0,
            HITLS_X509_ERR_CHAIN_DEPTH_UP_LIMIT);
#endif

        BSL_ERR_SET_MARK();
        if (isVfy && ((storeCtx->verifyParam.flags & HITLS_X509_VFY_FLAG_PARTIAL_CHAIN) != 0) && isTrustCa) {
            if (root != NULL) {
                *root = issue;
            }
            BSL_ERR_POP_TO_MARK();
            return HITLS_PKI_SUCCESS;
        }
        if (issue->isSelfIssued && HITLS_X509_CheckIssuedWithoutName(issue, issue)) {
            if (isTrustCa) {
                if (root != NULL) {
                    *root = issue;
                }
                BSL_ERR_POP_TO_MARK();
                return HITLS_PKI_SUCCESS;
            }
            if (HITLS_X509_CheckSelfSignedSignature(issue)) {
                BSL_ERR_POP_TO_MARK();
                return HITLS_PKI_SUCCESS;
            }
        }
        BSL_ERR_POP_TO_MARK();
        ret = X509_AddCertToChain(chain, issue);
        if (ret != HITLS_PKI_SUCCESS) {
            break;
        }
        cur = issue;
#ifdef HITLS_PKI_X509_VFY_CB
        storeCtx->curDepth++;
        storeCtx->curCert = cur;
#endif
    }
    // Adding VFY_CB is useless. the call point will verify that there must be a trusted root or ignore the error code
    return ret;
}

static HITLS_X509_List *X509_NewCertChain(HITLS_X509_Cert *cert)
{
    HITLS_X509_List *tmpChain = BSL_LIST_New(sizeof(HITLS_X509_Cert));
    if (tmpChain == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }
    int32_t ret = X509_AddCertToChain(tmpChain, cert);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_Free(tmpChain);
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }
    return tmpChain;
}

static int32_t HITLS_X509_CertChainBuildWithRoot(bool isVfy, HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *certChain,
    HITLS_X509_Cert *cert, HITLS_X509_List **chain)
{
    HITLS_X509_List *tmpChain = X509_NewCertChain(cert);
    if (tmpChain == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    HITLS_X509_Cert *root = NULL;
    int32_t ret = X509_BuildChain(isVfy, storeCtx, certChain, cert, tmpChain, &root);
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }
    // The root certificate must be found and trusted
    if (root == NULL) {
        ret = HITLS_X509_ERR_ROOT_CERT_NOT_FOUND;
        goto ERR;
    }
    if (HITLS_X509_CertCmp(cert, root) != 0) {
        ret = X509_AddCertToChain(tmpChain, root);
        if (ret != HITLS_PKI_SUCCESS) {
            goto ERR;
        }
    }
    *chain = tmpChain;
    return HITLS_PKI_SUCCESS;
ERR:
    BSL_LIST_FREE(tmpChain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    return ret;
}

int32_t HITLS_X509_CertChainBuild(HITLS_X509_StoreCtx *storeCtx, bool isWithRoot, HITLS_X509_Cert *cert,
    HITLS_X509_List **chain)
{
    if (storeCtx == NULL || cert == NULL || chain == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    if (isWithRoot) {
        return HITLS_X509_CertChainBuildWithRoot(false, storeCtx, NULL, cert, chain);
    }
    HITLS_X509_List *tmpChain = X509_NewCertChain(cert);
    if (tmpChain == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    bool selfSigned = HITLS_X509_IsSelfSigned(cert);
    *chain = tmpChain;
    if (selfSigned) {
        return HITLS_PKI_SUCCESS;
    }
    BSL_ERR_SET_MARK();
    (void)X509_BuildChain(false, storeCtx, NULL, cert, tmpChain, NULL);
    BSL_ERR_POP_TO_MARK();
    return HITLS_PKI_SUCCESS;
}

static uint32_t HITLS_X509_GetHashAlgSecBits(int32_t mdId)
{
    switch (mdId) {
        case CRYPT_MD_MD5:
            return 39;
        case CRYPT_MD_SHA1:
            return 63;
        case CRYPT_MD_SHA224:
        case CRYPT_MD_SHA3_224:
            return 112;
        case CRYPT_MD_SHA256:
        case CRYPT_MD_SM3:
        case CRYPT_MD_SHA3_256:
            return 128;
        case CRYPT_MD_SHA384:
        case CRYPT_MD_SHA3_384:
            return 192;
        case CRYPT_MD_SHA512:
        case CRYPT_MD_SHA3_512:
            return 256;
        default:
            return 0;
    }
}

static int32_t HITLS_X509_HashAlgSecBitsCheck(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Cert *cert, int32_t depth)
{
    /* Skip the root cert */
    int32_t chainLen = BSL_LIST_COUNT(storeCtx->certChain);
    if (chainLen <= 0 || depth >= chainLen - 1) {
        return HITLS_PKI_SUCCESS;
    }

    int32_t mdId = BSL_CID_UNKNOWN;
    int32_t ret = HITLS_X509_GetSignMdAlg(&cert->signAlgId, &mdId, sizeof(mdId));
    if (ret != HITLS_PKI_SUCCESS) {
        return HITLS_PKI_SUCCESS;
    }

    uint32_t secBits = HITLS_X509_GetHashAlgSecBits(mdId);
    if (secBits == 0) {
        return HITLS_PKI_SUCCESS;
    }

    VFYCBK_FAIL_IF(secBits < storeCtx->verifyParam.securityBits, storeCtx, cert, depth,
        HITLS_X509_ERR_VFY_CHECK_SECBITS);
    return HITLS_PKI_SUCCESS;
}

static int32_t HITLS_X509_SecBitsCheck(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Cert *cert, int32_t depth)
{
    (void)depth;
    uint32_t secBits = CRYPT_EAL_PkeyGetSecurityBits(cert->tbs.ealPubKey);
    VFYCBK_FAIL_IF(secBits < storeCtx->verifyParam.securityBits, storeCtx, cert, depth,
        HITLS_X509_ERR_VFY_CHECK_SECBITS);
    return HITLS_PKI_SUCCESS;
}

static int32_t HITLS_X509_CheckCertExtNode(void *ctx, HITLS_X509_ExtEntry *extNode, int32_t depth)
{
    (void)ctx;
    (void)depth;
    if (extNode->cid != BSL_CID_CE_KEYUSAGE && extNode->cid != BSL_CID_CE_BASICCONSTRAINTS &&
        extNode->cid != BSL_CID_CE_EXTKEYUSAGE && extNode->cid != BSL_CID_CE_SUBJECTALTNAME &&
        extNode->cid != BSL_CID_CE_AUTHORITYKEYIDENTIFIER && extNode->cid != BSL_CID_CE_SUBJECTKEYIDENTIFIER &&
        extNode->cid != BSL_CID_CE_CRLDISTRIBUTIONPOINTS && extNode->critical == true) {
#ifdef HITLS_PKI_X509_VFY_CB
        if (VerifyCertCbk(ctx, NULL, -1, HITLS_X509_ERR_PROCESS_CRITICALEXT) != HITLS_PKI_SUCCESS) {
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_PROCESS_CRITICALEXT);
            return HITLS_X509_ERR_PROCESS_CRITICALEXT; // not process critical ext
        }
#else
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_PROCESS_CRITICALEXT);
        return HITLS_X509_ERR_PROCESS_CRITICALEXT;
#endif
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t HITLS_X509_CheckCrlExtNode(void *ctx, HITLS_X509_ExtEntry *extNode, int32_t depth)
{
    (void)ctx;
    (void)depth;
    switch (extNode->cid) {
        case BSL_CID_CE_AUTHORITYKEYIDENTIFIER:
        case BSL_CID_CE_CRLNUMBER:
        case BSL_CID_CE_ISSUINGDISTRIBUTIONPOINT:
        case BSL_CID_CE_DELTACRLINDICATOR:
            return HITLS_PKI_SUCCESS;
        default:
            if (extNode->critical == true) {
                return HITLS_X509_ERR_PROCESS_CRITICALEXT;
            }
            return HITLS_PKI_SUCCESS;
    }
}

#if defined(HITLS_CRYPTO_MLDSA) || defined(HITLS_CRYPTO_SLH_DSA)
static int32_t CheckPqcSigKeyUsage(HITLS_X509_Cert *cert)
{
    // Check if the certificate's PUBLIC KEY is a PQC signature algorithm (ML-DSA or SLH-DSA)
    // Note: We check the public key type, not the signature algorithm used to sign this certificate
    // This is because keyUsage applies to what the certificate holder's public key can do
    CRYPT_PKEY_AlgId pubKeyAlgId = CRYPT_EAL_PkeyGetId(cert->tbs.ealPubKey);
    bool isPqcSignaturePubKey = false;
#ifdef HITLS_CRYPTO_MLDSA
    if (pubKeyAlgId == CRYPT_PKEY_ML_DSA) {
        isPqcSignaturePubKey = true;
    }
#endif
#ifdef HITLS_CRYPTO_SLH_DSA
    if (pubKeyAlgId == CRYPT_PKEY_SLH_DSA) {
        isPqcSignaturePubKey = true;
    }
#endif
    if (!isPqcSignaturePubKey) {
        return HITLS_PKI_SUCCESS;
    }

    HITLS_X509_CertExt *tmpExt = (HITLS_X509_CertExt *)cert->tbs.ext.extData;
    // keyUsage extension is OPTIONAL, if the extension is not present, no key usage restrictions apply.
    if (tmpExt == NULL || (tmpExt->extFlags & HITLS_X509_EXT_FLAG_KUSAGE) == 0) {
        return HITLS_PKI_SUCCESS;
    }

    uint32_t mustOneOf = (HITLS_X509_EXT_KU_DIGITAL_SIGN |
                          HITLS_X509_EXT_KU_NON_REPUDIATION |
                          HITLS_X509_EXT_KU_KEY_CERT_SIGN |
                          HITLS_X509_EXT_KU_CRL_SIGN);
    uint32_t forbidden = (HITLS_X509_EXT_KU_KEY_ENCIPHERMENT |
                          HITLS_X509_EXT_KU_DATA_ENCIPHERMENT |
                          HITLS_X509_EXT_KU_KEY_AGREEMENT |
                          HITLS_X509_EXT_KU_ENCIPHER_ONLY |
                          HITLS_X509_EXT_KU_DECIPHER_ONLY);
    if ((tmpExt->keyUsage & mustOneOf) == 0) {
        return HITLS_X509_ERR_EXT_KU;
    }
    if ((tmpExt->keyUsage & forbidden) != 0) {
        return HITLS_X509_ERR_EXT_KU;
    }
    return HITLS_PKI_SUCCESS;
}
#endif

#ifdef HITLS_CRYPTO_MLKEM
static int32_t CheckMlKemKeyUsage(HITLS_X509_Cert *cert)
{
    // Check ML-KEM keyUsage according to draft-ietf-lamps-kyber-certificates-11 Section 5
    // keyEncipherment MUST be the only key usage set for ML-KEM-512/768/1024 certificates
    CRYPT_PKEY_AlgId pubKeyId = CRYPT_EAL_PkeyGetId(cert->tbs.ealPubKey);
    if (pubKeyId != CRYPT_PKEY_ML_KEM) {
        return HITLS_PKI_SUCCESS;
    }

    HITLS_X509_CertExt *tmpExt = (HITLS_X509_CertExt *)cert->tbs.ext.extData;
    // keyUsage extension is OPTIONAL.
    // If present in ML-KEM certificates, it MUST be keyEncipherment only (draft-ietf-lamps-kyber-certificates-11).
    if (tmpExt == NULL || (tmpExt->extFlags & HITLS_X509_EXT_FLAG_KUSAGE) == 0) {
        return HITLS_PKI_SUCCESS;
    }

    // ML-KEM certificates MUST have keyEncipherment as the ONLY key usage
    if (tmpExt->keyUsage != HITLS_X509_EXT_KU_KEY_ENCIPHERMENT) {
        return HITLS_X509_ERR_EXT_KU;
    }
    return HITLS_PKI_SUCCESS;
}
#endif

static int32_t HITLS_X509_CheckCertExt(void *ctx, HITLS_X509_Cert *cert, int32_t depth)
{
#ifdef HITLS_PKI_X509_VFY_CB
    HITLS_X509_StoreCtx *storeCtx = (HITLS_X509_StoreCtx *)ctx;
    storeCtx->curCert = cert;
    storeCtx->curDepth = depth;
#else
    (void)depth;
#endif
    /* RFC5280 4.1.2.1: when extensions are used, as expected in this profile, version MUST be 3 (value is 2). */
    if (cert->tbs.version < HITLS_X509_VERSION_3) {
        VFYCBK_FAIL_IF(BSL_LIST_COUNT(cert->tbs.ext.extList) > 0,
            (HITLS_X509_StoreCtx *)ctx, cert, depth, HITLS_X509_ERR_VFY_EXTENSIONS_REQUIRE_V3);
        return HITLS_PKI_SUCCESS;
    }
#if defined(HITLS_CRYPTO_MLDSA) || defined(HITLS_CRYPTO_SLH_DSA)
    int32_t pqcSigKeyUsageRet = CheckPqcSigKeyUsage(cert);
    if (pqcSigKeyUsageRet != HITLS_PKI_SUCCESS) {
        return pqcSigKeyUsageRet;
    }
#endif
#ifdef HITLS_CRYPTO_MLKEM
    int32_t mlkemKeyUsageRet = CheckMlKemKeyUsage(cert);
    if (mlkemKeyUsageRet != HITLS_PKI_SUCCESS) {
        return mlkemKeyUsageRet;
    }
#endif
    return HITLS_X509_TrvList(cert->tbs.ext.extList, (HITLS_X509_TrvListCallBack)HITLS_X509_CheckCertExtNode, ctx);
}

int32_t HITLS_X509_VerifyParamAndExt(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *chain)
{
    // CheckVerifyParam
    if ((storeCtx->verifyParam.flags & HITLS_X509_VFY_FLAG_SECBITS) != 0) {
        int32_t ret = HITLS_X509_TrvList(chain, (HITLS_X509_TrvListCallBack)HITLS_X509_SecBitsCheck, storeCtx);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
        ret = HITLS_X509_TrvList(chain, (HITLS_X509_TrvListCallBack)HITLS_X509_HashAlgSecBitsCheck, storeCtx);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
    }

    return HITLS_X509_TrvList(chain, (HITLS_X509_TrvListCallBack)HITLS_X509_CheckCertExt, storeCtx);
}

int32_t HITLS_X509_CheckCertRevoked(HITLS_X509_Cert *cert, HITLS_X509_CrlEntry *crlEntry, int32_t depth)
{
    (void)depth;
    if (cert->tbs.serialNum.tag == crlEntry->serialNumber.tag &&
        cert->tbs.serialNum.len == crlEntry->serialNumber.len &&
        memcmp(cert->tbs.serialNum.buff, crlEntry->serialNumber.buff, crlEntry->serialNumber.len) == 0) {
        return HITLS_X509_ERR_VFY_CERT_REVOKED;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t X509_StoreCheckSignature(const BSL_Buffer *sm2UserId, const CRYPT_EAL_PkeyCtx *pubKey,
    uint8_t *rawData, uint32_t rawDataLen, HITLS_X509_Asn1AlgId *alg, BSL_ASN1_BitString *signature)
{
#ifdef HITLS_CRYPTO_SM2
    bool isHasUserId = true;
    if (alg->sm2UserId.data == NULL && sm2UserId != NULL) {
        alg->sm2UserId = *sm2UserId;
        isHasUserId = false;
    }
#else
    (void)sm2UserId;
#endif

    int32_t ret = HITLS_X509_CheckSignature(pubKey, rawData, rawDataLen, alg, signature);
#ifdef HITLS_CRYPTO_SM2
    if (!isHasUserId) {
        alg->sm2UserId.data = NULL;
        alg->sm2UserId.dataLen = 0;
    }
#endif
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return ret;
}

#ifndef HITLS_PKI_X509_VFY_CRL_LITE
static const BSL_ASN1_Buffer *X509_GetRawExtnValueByCid(HITLS_X509_Ext *ext, BslCid cid)
{
    if (ext == NULL || ext->extList == NULL) {
        return NULL;
    }
    for (BslListNode *node = BSL_LIST_FirstNode(ext->extList); node != NULL;
        node = BSL_LIST_GetNextNode(ext->extList, node)) {
        HITLS_X509_ExtEntry *entry = (HITLS_X509_ExtEntry *)BSL_LIST_GetData(node);
        if (entry->cid == cid) {
            return &entry->extnValue;
        }
    }
    return NULL;
}

static HITLS_X509_NameNode *NameNodeShallowDup(HITLS_X509_NameNode *node)
{
    HITLS_X509_NameNode *res = (HITLS_X509_NameNode *)BSL_SAL_Calloc(1, sizeof(HITLS_X509_NameNode));
    if (res == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }
    res->layer = node->layer;
    res->nameType = node->nameType;
    res->nameValue = node->nameValue;
    res->utf8Value = node->utf8Value;
    return res;
}

static BslList *X509_AppendIssuerToRelativeName(BslList *relativeName, BslList *issuerName)
{
    // Create a list view of issuerName || relativeName
    BslList *completeName = BSL_LIST_Copy(issuerName, NULL, NULL);
    if (completeName == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }
    for (BslListNode *node = BSL_LIST_FirstNode(relativeName); node != NULL;
        node = BSL_LIST_GetNextNode(relativeName, node)) {
        HITLS_X509_NameNode *nameNode = (HITLS_X509_NameNode *)BSL_LIST_GetData(node);
        HITLS_X509_NameNode *dupNode = NameNodeShallowDup(nameNode);
        if (dupNode == NULL) {
            BSL_LIST_FREE(completeName, NULL);
            return NULL;
        }
        int32_t ret = BSL_LIST_AddElement(completeName, dupNode, BSL_LIST_POS_END);
        if (ret != BSL_SUCCESS) {
            BSL_SAL_Free(dupNode);
            BSL_LIST_FREE(completeName, NULL);
            BSL_ERR_PUSH_ERROR(ret);
            return NULL;
        }
    }
    return completeName;
}

static bool X509_CheckGeneralNameMatch(const HITLS_X509_GeneralName *name1, const HITLS_X509_GeneralName *name2)
{
    if (name1 == NULL || name2 == NULL) {
        return name1 == name2;
    }
    if (name1->type != name2->type) {
        return false;
    }
    if (name1->type == HITLS_X509_GN_DNNAME) {
        return HITLS_X509_CmpNameNode((BslList *)(uintptr_t)name1->value.data,
            (BslList *)(uintptr_t)name2->value.data) == 0;
    }
    if (name1->value.dataLen != name2->value.dataLen) {
        return false;
    }
    if (name1->value.data == NULL || name2->value.data == NULL) {
        return name1->value.data == name2->value.data;
    }
    return memcmp(name1->value.data, name2->value.data, name1->value.dataLen) == 0;
}

static bool X509_CheckRelativeNameInGeneralNames(BslList *relativeName, BslList *issuerName, BslList *generalNames)
{
    if (relativeName == NULL || generalNames == NULL) {
        return false;
    }
    BslList *completeName = X509_AppendIssuerToRelativeName(relativeName, issuerName);
    if (completeName == NULL) {
        return false;
    }
    for (BslListNode *node = BSL_LIST_FirstNode(generalNames); node != NULL;
        node = BSL_LIST_GetNextNode(generalNames, node)) {
        HITLS_X509_GeneralName *name = (HITLS_X509_GeneralName *)BSL_LIST_GetData(node);
        if (name == NULL || name->type != HITLS_X509_GN_DNNAME) {
            continue;
        }
        bool retVal = (HITLS_X509_CmpNameNode(completeName, (BslList *)(uintptr_t)name->value.data) == 0);
        if (retVal) {
            BSL_LIST_FREE(completeName, NULL);
            return true;
        }
    }
    BSL_LIST_FREE(completeName, NULL);
    return false;
}

static bool X509_CheckGeneralNamesMatch(BslList *nameList1, BslList *nameList2)
{
    if (nameList1 == NULL || nameList2 == NULL) {
        return false;
    }
    for (BslListNode *node1 = BSL_LIST_FirstNode(nameList1); node1 != NULL;
        node1 = BSL_LIST_GetNextNode(nameList1, node1)) {
        HITLS_X509_GeneralName *name1 = (HITLS_X509_GeneralName *)BSL_LIST_GetData(node1);
        for (BslListNode *node2 = BSL_LIST_FirstNode(nameList2); node2 != NULL;
            node2 = BSL_LIST_GetNextNode(nameList2, node2)) {
            HITLS_X509_GeneralName *name2 = (HITLS_X509_GeneralName *)BSL_LIST_GetData(node2);
            if (X509_CheckGeneralNameMatch(name1, name2)) {
                return true;
            }
        }
    }
    return false;
}

/*
    1. dp1 == NULL || dp2 == NULL, return true
    2. relative name vs relative name: match if the two relative names are the same
    3. relative name vs full name: match if relative name appended with issuer name is the same as one of the full names
    4. full name vs full name: match if they have at least one same general name
*/
static bool X509_CheckDpNameMatch(HITLS_X509_DistPointName *dp1, BslList *issuerName1, HITLS_X509_DistPointName *dp2,
    BslList *issuerName2)
{
    if (dp1 == NULL || dp2 == NULL) {
        return true;
    } else if (dp1->name == NULL || dp2->name == NULL) {
        // if dp1 != NULL or dp2 != NULL, dp1->name and dp2->name MUST NOT be NULL;
        return false;
    }
    // relative name vs relative name OR relative name vs full name
    if (dp1->type == HITLS_X509_DP_RELATIVENAME) {
        if (dp2->type == HITLS_X509_DP_RELATIVENAME) {
            return HITLS_X509_CmpNameNode(dp1->name, dp2->name) == 0;
        }
        if (dp2->type == HITLS_X509_DP_FULLNAME) {
            return X509_CheckRelativeNameInGeneralNames(dp1->name, issuerName1, dp2->name);
        }
        return false;
    }
    if (dp2->type == HITLS_X509_DP_RELATIVENAME) {
        if (dp1->type == HITLS_X509_DP_FULLNAME) {
            return X509_CheckRelativeNameInGeneralNames(dp2->name, issuerName2, dp1->name);
        }
        return false;
    }
    if (dp1->type != HITLS_X509_DP_FULLNAME || dp2->type != HITLS_X509_DP_FULLNAME) {
        return false;
    }
    // full name vs full name
    return X509_CheckGeneralNamesMatch(dp1->name, dp2->name);
}

static int32_t X509_GetAndCheckIdp(HITLS_X509_Crl *crl, HITLS_X509_ExtIdp *idp)
{
    int32_t ret = X509_ExtCtrl(&crl->tbs.crlExt, HITLS_X509_EXT_GET_IDP, idp, sizeof(HITLS_X509_ExtIdp));
    if (ret == HITLS_PKI_SUCCESS) {
        ret = HITLS_X509_CheckIdp(idp);
        if (ret != HITLS_PKI_SUCCESS) {
            HITLS_X509_ClearIdp(idp);
            return ret;
        }
        // Currently we don't support indirect CRL
        if (idp->indirectCrl) {
            HITLS_X509_ClearIdp(idp);
            return HITLS_X509_ERR_EXT_IDP;
        }
        if (!idp->hasReasons) {
            idp->onlySomeReasons = HITLS_X509_REASON_FLAG_ALL;
        }
        return HITLS_PKI_SUCCESS;
    }
    if (ret == HITLS_X509_ERR_EXT_NOT_FOUND) {
        idp->onlySomeReasons = HITLS_X509_REASON_FLAG_ALL;
        return HITLS_PKI_SUCCESS;
    }
    return ret;
}

static int32_t X509_CheckCertInCrlIdpScope(HITLS_X509_Cert *cert, HITLS_X509_Crl *crl,
    HITLS_X509_ExtIdp *idp)
{
    HITLS_X509_CertExt *certExt = (HITLS_X509_CertExt *)cert->tbs.ext.extData;
    bool isCa = ((certExt->extFlags & HITLS_X509_EXT_FLAG_BCONS) != 0) && certExt->isCa;
    if ((idp->onlyContainsUserCerts && isCa) || (idp->onlyContainsCACerts && !isCa) ||
        idp->onlyContainsAttributeCerts) {
        return HITLS_X509_ERR_VFY_DIFFERENT_CRL_SCOPE;
    }
    HITLS_X509_ExtCdp cdp = {0};
    int32_t ret = X509_ExtCtrl(&cert->tbs.ext, HITLS_X509_EXT_GET_CDP, &cdp, sizeof(cdp));
    if (ret != HITLS_PKI_SUCCESS && ret != HITLS_X509_ERR_EXT_NOT_FOUND) {
        return ret;
    }
    /*
        Reason mask computation:
        1. idp == NULL, cdp == NULL: reason mask = idp->reasons(ALL REASON)
        2. idp == NULL or idp->dpName == NULL, cdp != NULL:
           reason mask = all reasons in cdp, because idp will match with each dp
        3. idp != NULL, cdp == NULL: if idp->dpName != NULL, don't match, else reason mask = idp->reasons;
        4. idp != NULL and idp->dpName != NULL, cdp != NULL; reason mask = interimReasonMask & idp->reasons;
           where interimReasonMask = | dp_i->reasons for dp_i mathces idp;
    */
    if (cdp.points == NULL) {
        if (idp->distPoint != NULL && idp->distPoint->name != NULL) {
            return HITLS_X509_ERR_VFY_DIFFERENT_CRL_SCOPE;
        }
        return HITLS_PKI_SUCCESS;
    }
    uint16_t interimReasonMask = HITLS_X509_REASON_FLAG_NONE;
    bool isDpNameMatched = false;
    for (BslListNode *dpNode = BSL_LIST_FirstNode(cdp.points); dpNode != NULL;
        dpNode = BSL_LIST_GetNextNode(cdp.points, dpNode)) {
        HITLS_X509_CrlDistPoint *dp = (HITLS_X509_CrlDistPoint *)dpNode->data;
        // We do not support indirect CRL, thus crlIssuer field MUST be NULL, and dpName MUST NOT be NULL
        if (dp->crlIssuer != NULL || dp->distPointName == NULL) {
            continue;
        }
        // if idp == NULL or idp->distPoint == NULL, idp will match with each dp;
        if (X509_CheckDpNameMatch(dp->distPointName, cert->tbs.issuerName, idp->distPoint, crl->tbs.issuerName)) {
            isDpNameMatched = true;
            if (!dp->hasReasons) {
                interimReasonMask = HITLS_X509_REASON_FLAG_ALL;
            } else {
                interimReasonMask |= dp->reasons;
            }
        }
    }
    if (!isDpNameMatched) {
        HITLS_X509_ClearCdp(&cdp);
        return HITLS_X509_ERR_VFY_DIFFERENT_CRL_SCOPE;
    }
    idp->onlySomeReasons &= interimReasonMask;
    HITLS_X509_ClearCdp(&cdp);
    return HITLS_PKI_SUCCESS;
}


static bool X509_IsDeltaCrlIssuerMatch(HITLS_X509_Crl *deltaCrl, HITLS_X509_Crl *baseCrl)
{
    return HITLS_X509_CmpNameNode(deltaCrl->tbs.issuerName, baseCrl->tbs.issuerName) == 0;
}

static bool X509_IsDeltaCrlAkiMatch(HITLS_X509_Crl *deltaCrl, HITLS_X509_Crl *baseCrl)
{
    HITLS_X509_ExtAki deltaAki = {0};
    HITLS_X509_ExtAki baseAki = {0};
    int32_t deltaRet = HITLS_X509_CrlCtrl(deltaCrl, HITLS_X509_EXT_GET_AKI, &deltaAki, sizeof(deltaAki));
    int32_t baseRet = HITLS_X509_CrlCtrl(baseCrl, HITLS_X509_EXT_GET_AKI, &baseAki, sizeof(baseAki));
    bool isMatch = false;
    if (deltaRet != HITLS_PKI_SUCCESS || baseRet != HITLS_PKI_SUCCESS) {
        if (deltaRet == baseRet && deltaRet == HITLS_X509_ERR_EXT_NOT_FOUND) {
            isMatch = true;
            goto EXIT;
        }
        goto EXIT;
    }
    isMatch = deltaAki.kid.dataLen == baseAki.kid.dataLen &&
        memcmp(deltaAki.kid.data, baseAki.kid.data, deltaAki.kid.dataLen) == 0;
EXIT:
    HITLS_X509_ClearAuthorityKeyId(&deltaAki);
    HITLS_X509_ClearAuthorityKeyId(&baseAki);
    return isMatch;
}

static bool X509_IsDeltaIndicatorMatchBase(HITLS_X509_Crl *candidate, const HITLS_X509_ExtCrlNumber *baseCrlNumber)
{
    // delta crl indicator <= base crl number
    HITLS_X509_ExtDeltaCrl deltaIndicator = {0};
    // it must be a delta crl
    if (HITLS_X509_CrlCtrl(candidate, HITLS_X509_EXT_GET_DELTA_CRL,
        &deltaIndicator, sizeof(deltaIndicator)) != HITLS_PKI_SUCCESS) {
        return false;
    }
    if (deltaIndicator.crlNumber.dataLen != baseCrlNumber->crlNumber.dataLen) {
        return deltaIndicator.crlNumber.dataLen < baseCrlNumber->crlNumber.dataLen;
    }
    return memcmp(deltaIndicator.crlNumber.data, baseCrlNumber->crlNumber.data,
        deltaIndicator.crlNumber.dataLen) <= 0;
}

static bool X509_IsDeltaCrlIdpMatchBase(HITLS_X509_Crl *candidate, HITLS_X509_Crl *baseCrl)
{
    const BSL_ASN1_Buffer *deltaIdp = X509_GetRawExtnValueByCid(&candidate->tbs.crlExt,
        BSL_CID_CE_ISSUINGDISTRIBUTIONPOINT);
    const BSL_ASN1_Buffer *baseIdp = X509_GetRawExtnValueByCid(&baseCrl->tbs.crlExt,
        BSL_CID_CE_ISSUINGDISTRIBUTIONPOINT);
    if (deltaIdp == NULL || baseIdp == NULL) {
        return deltaIdp == baseIdp;
    }
    return deltaIdp->len == baseIdp->len && memcmp(deltaIdp->buff, baseIdp->buff, deltaIdp->len) == 0;
}

static bool X509_IsDeltaCrlNumberValid(HITLS_X509_Crl *candidate, const HITLS_X509_ExtCrlNumber *baseCrlNumber)
{
    HITLS_X509_ExtCrlNumber deltaCrlNumber = {0};

    if (HITLS_X509_CrlCtrl(candidate, HITLS_X509_EXT_GET_CRLNUMBER,
        &deltaCrlNumber, sizeof(deltaCrlNumber)) != HITLS_PKI_SUCCESS) {
        return false;
    }
    // Delta crl number MUST greater than base crl number
    if (deltaCrlNumber.crlNumber.dataLen != baseCrlNumber->crlNumber.dataLen) {
        return deltaCrlNumber.crlNumber.dataLen > baseCrlNumber->crlNumber.dataLen;
    }
    return memcmp(deltaCrlNumber.crlNumber.data, baseCrlNumber->crlNumber.data, deltaCrlNumber.crlNumber.dataLen) > 0;
}

static HITLS_X509_Crl *X509_FindDeltaCrl(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Crl *baseCrl)
{
    if ((storeCtx->verifyParam.flags & HITLS_X509_VFY_FLAG_CRL_USE_DELTA) == 0) {
        return NULL;
    }
    HITLS_X509_ExtCrlNumber baseCrlNumber = {0};
    int32_t ret = HITLS_X509_CrlCtrl(baseCrl, HITLS_X509_EXT_GET_CRLNUMBER, &baseCrlNumber, sizeof(baseCrlNumber));
    // base must have baseCrlNumber
    if (ret != HITLS_PKI_SUCCESS) {
        return NULL;
    }
    HITLS_X509_Crl *retCrl = NULL;
    // Check rules refer to RFC5280 :https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.4
    for (BslListNode *crlNode = BSL_LIST_FirstNode(storeCtx->crl); crlNode != NULL;
         crlNode = BSL_LIST_GetNextNode(storeCtx->crl, crlNode)) {
        HITLS_X509_Crl *candidate = (HITLS_X509_Crl *)BSL_LIST_GetData(crlNode);
        if (candidate == baseCrl) {
            continue;
        }
        if (!X509_IsDeltaIndicatorMatchBase(candidate, &baseCrlNumber)) {
            continue;
        }
        if (!X509_IsDeltaCrlIssuerMatch(candidate, baseCrl)) {
            continue;
        }
        if (!X509_IsDeltaCrlAkiMatch(candidate, baseCrl)) {
            continue;
        }
        if (!X509_IsDeltaCrlIdpMatchBase(candidate, baseCrl)) {
            continue;
        }
        if (!X509_IsDeltaCrlNumberValid(candidate, &baseCrlNumber)) {
            continue;
        }
        // if there is a newer delta crl candidate, we select the newer one as the final delta crl
        if (retCrl == NULL) {
            retCrl = candidate;
        } else if (BSL_SAL_DateTimeCompare(&candidate->tbs.validTime.start, &retCrl->tbs.validTime.start, NULL) ==
                   BSL_TIME_DATE_AFTER) {
            retCrl = candidate;
        }
    }
    return retCrl;
}

static int32_t X509_CheckCrlCriticalExt(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Crl *crl)
{
    return HITLS_X509_TrvList(crl->tbs.crlExt.extList,
        (HITLS_X509_TrvListCallBack)HITLS_X509_CheckCrlExtNode, storeCtx);
}

static int32_t X509_CheckCrlIsExpire(int64_t *time, HITLS_X509_Crl *baseCrl, HITLS_X509_Crl *deltaCrl)
{
    int32_t baseRet = X509_CheckCrlTimeWithoutCb(time, baseCrl);
    if (deltaCrl != NULL) {
        int32_t deltaRet = X509_CheckCrlTimeWithoutCb(time, deltaCrl);
        // if delta CRL has TIME ERROR, return TIME ERROR
        if (deltaRet != HITLS_PKI_SUCCESS) {
            return HITLS_X509_ERR_VFY_CRL_TIME_ERROR;
        }
        // if delta CRL is valid, ignore NEXTUPDATE_EXPIRED error of base CRL
        if (baseRet == HITLS_PKI_SUCCESS || baseRet == HITLS_X509_ERR_VFY_NEXTUPDATE_EXPIRED) {
            return HITLS_PKI_SUCCESS;
        }
        return HITLS_X509_ERR_VFY_CRL_TIME_ERROR;
    }
    return baseRet == HITLS_PKI_SUCCESS ? HITLS_PKI_SUCCESS : HITLS_X509_ERR_VFY_CRL_TIME_ERROR;
}

static bool X509_CompareWithCurrentCrl(const HITLS_X509_CrlSelection *selection, HITLS_X509_Crl *baseCrl,
    uint8_t errorPath)
{
    if (selection->baseCrl == NULL) {
        return true;
    }
    if (errorPath == selection->errorPath) {
        return BSL_SAL_DateTimeCompare(&baseCrl->tbs.validTime.start,
            &selection->baseCrl->tbs.validTime.start, NULL) == BSL_TIME_DATE_AFTER;
    }
    return errorPath < selection->errorPath;
}

typedef struct {
    uint8_t errorPathBit;
    uint32_t x509VfyErrorCode;
} ErrorPathMap;

static ErrorPathMap g_errorPathMap[] = {
    {HITLS_X509_CRL_ERROR_DIFF_SCOPE, HITLS_X509_ERR_VFY_DIFFERENT_CRL_SCOPE},
    {HITLS_X509_CRL_ERROR_CRITICAL_EXT, HITLS_X509_ERR_PROCESS_CRITICALEXT}
};

static bool X509_CheckIsDeltaCrl(HITLS_X509_Crl *crl)
{
    HITLS_X509_ExtDeltaCrl deltaIndicator = {0};
    int32_t ret = HITLS_X509_CrlCtrl(crl, HITLS_X509_EXT_GET_DELTA_CRL, &deltaIndicator, sizeof(deltaIndicator));
    return ret != HITLS_X509_ERR_EXT_NOT_FOUND;
}

static bool X509_CheckAkiSkiMatch(HITLS_X509_Cert *cert, HITLS_X509_Crl *crl)
{
    if (cert->tbs.version != HITLS_X509_VERSION_3 || crl->tbs.version != 1 ||
        (HITLS_X509_CheckAki(&cert->tbs.ext, &crl->tbs.crlExt, cert->tbs.issuerName, &cert->tbs.serialNum) ==
         HITLS_PKI_SUCCESS)) {
        return true;
    }
    return false;
}

static int32_t X509_FindBaseCrlAndDeltaCrl(HITLS_X509_StoreCtx *storeCtx, int64_t *time, HITLS_X509_Cert *cert,
                                           HITLS_X509_Cert *parent, HITLS_X509_CrlSelection *selection)
{
    for (BslListNode *crlNode = BSL_LIST_FirstNode(storeCtx->crl); crlNode != NULL;
        crlNode = BSL_LIST_GetNextNode(storeCtx->crl, crlNode)) {
        HITLS_X509_Crl *crl = (HITLS_X509_Crl *)BSL_LIST_GetData(crlNode);
        if (X509_CheckIsDeltaCrl(crl)) {
            continue;
        }
        HITLS_X509_Crl *deltaCrl = NULL;
        uint8_t errorPath = 0;
        HITLS_X509_ExtIdp idp = { 0 };
        // If idp is invalid, we ignore this crl
        int32_t ret = X509_GetAndCheckIdp(crl, &idp);
        if (ret != HITLS_PKI_SUCCESS) {
            goto CONTINUE;
        }
        // Check if this crl can cover new reasons
        if ((idp.onlySomeReasons & (~selection->reasons)) == HITLS_X509_REASON_FLAG_NONE) {
            goto CONTINUE;
        }
        // Compare crl issuer name with cert issuer name
        ret = HITLS_X509_CmpNameNode(crl->tbs.issuerName, parent->tbs.subjectName);
        if (ret != HITLS_PKI_SUCCESS) {
            goto CONTINUE;
        }
        if (!X509_CheckAkiSkiMatch(parent, crl)) {
            goto CONTINUE;
        }
        // Check if cert is in crl's scope, and if it matches crl's reasons for revocation
        ret = X509_CheckCertInCrlIdpScope(cert, crl, &idp);
        if (ret != HITLS_PKI_SUCCESS) {
            errorPath |= HITLS_X509_CRL_ERROR_DIFF_SCOPE;
        }
        // if this crl can't cover new reasons, we ignore it
        if ((idp.onlySomeReasons & (~selection->reasons)) == HITLS_X509_REASON_FLAG_NONE) {
            goto CONTINUE;
        }
        ret = X509_CheckCrlCriticalExt(storeCtx, crl);
        if (ret != HITLS_PKI_SUCCESS) {
            errorPath |= HITLS_X509_CRL_ERROR_CRITICAL_EXT;
        }
        // Find a matched delta crl if there exists
        deltaCrl = X509_FindDeltaCrl(storeCtx, crl);
        ret = X509_CheckCrlIsExpire(time, crl, deltaCrl);
        if (ret != HITLS_PKI_SUCCESS) {
            errorPath |= HITLS_X509_CRL_ERROR_TIME;
        }
        /* If the selected crl is better than current crl, then update it;
         * Selection criteria:
         * 1. less severe errors.
         * 2. newer ThisUpdate.
        */
        if (X509_CompareWithCurrentCrl(selection, crl, errorPath)) {
            selection->baseCrl = crl;
            selection->deltaCrl = deltaCrl;
            selection->errorPath = errorPath;
            selection->newReasons = idp.onlySomeReasons;
            selection->issuerCert = parent;
        }
CONTINUE:
        HITLS_X509_ClearIdp(&idp);
    }
    if (selection->baseCrl == NULL) {
        return HITLS_X509_ERR_VFY_CRL_NOT_FOUND;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t X509_VerifyCrlSig(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Cert *issuerCert, HITLS_X509_Crl *crl)
{
    int32_t ret;
    RETURN_RET_IF_ERR(HITLS_X509_CheckSignAlgConsistency(&crl->tbs.signAlgId, &crl->signAlgId), ret);
    RETURN_RET_IF_ERR(HITLS_X509_CheckAlg(issuerCert->tbs.ealPubKey, &crl->tbs.signAlgId), ret);
#ifdef HITLS_CRYPTO_SM2
    ret = X509_StoreCheckSignature(&storeCtx->verifyParam.sm2UserId, issuerCert->tbs.ealPubKey, crl->tbs.tbsRawData,
        crl->tbs.tbsRawDataLen, &(crl->signAlgId), &(crl->signature));
#else
    (void)storeCtx;
    ret = X509_StoreCheckSignature(NULL, issuerCert->tbs.ealPubKey, crl->tbs.tbsRawData,
        crl->tbs.tbsRawDataLen, &(crl->signAlgId), &(crl->signature));
#endif
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return HITLS_X509_ERR_VFY_CRLSIGN_FAIL;
    }
    return ret;
}

static HITLS_X509_CrlEntry *X509_FindRevokedEntry(HITLS_X509_Cert *cert, HITLS_X509_Crl *crl)
{
    if (cert == NULL || crl == NULL || crl->tbs.revokedCerts == NULL) {
        return NULL;
    }
    for (BslListNode *entryNode = BSL_LIST_FirstNode(crl->tbs.revokedCerts); entryNode != NULL;
        entryNode = BSL_LIST_GetNextNode(crl->tbs.revokedCerts, entryNode)) {
        HITLS_X509_CrlEntry *entry = (HITLS_X509_CrlEntry *)BSL_LIST_GetData(entryNode);
        if (entry == NULL) {
            continue;
        }
        if (cert->tbs.serialNum.tag == entry->serialNumber.tag &&
            cert->tbs.serialNum.len == entry->serialNumber.len &&
            memcmp(cert->tbs.serialNum.buff, entry->serialNumber.buff, entry->serialNumber.len) == 0) {
            return entry;
        }
    }
    return NULL;
}

static int32_t X509_CheckCertRevoke(HITLS_X509_Cert *cert, HITLS_X509_CrlSelection *selection)
{
    HITLS_X509_CrlEntry *deltaEntry = X509_FindRevokedEntry(cert, selection->deltaCrl);
    if (deltaEntry != NULL) {
        int32_t reason = -1;
        int32_t ret = HITLS_X509_CrlEntryCtrl(deltaEntry, HITLS_X509_CRL_GET_REVOKED_REASON, &reason, sizeof(reason));
        if (ret == HITLS_PKI_SUCCESS && reason == HITLS_X509_REVOKED_REASON_REMOVE_FROM_CRL) {
            return HITLS_PKI_SUCCESS;
        }
        return HITLS_X509_ERR_VFY_CERT_REVOKED;
    }
    HITLS_X509_CrlEntry *baseEntry = X509_FindRevokedEntry(cert, selection->baseCrl);
    if (baseEntry == NULL) {
        return HITLS_PKI_SUCCESS;
    }
    return HITLS_X509_ERR_VFY_CERT_REVOKED;
}

static int32_t NotifyErrors(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Cert *cert, HITLS_X509_CrlSelection *selection,
    int32_t depth, int64_t *time)
{
#ifndef HITLS_PKI_X509_VFY_CB
    (void)cert;
#endif
    if ((selection->errorPath & HITLS_X509_CRL_ERROR_TIME) != 0) {
        if (selection->deltaCrl != NULL) {
            int32_t ret = HITLS_X509_CheckCrlTime(storeCtx, selection->deltaCrl, depth, time);
            if (ret != HITLS_PKI_SUCCESS) {
                return ret;
            }
        }
        return HITLS_X509_CheckCrlTime(storeCtx, selection->baseCrl, depth, time);
    }
    for (uint32_t i = 0; i < sizeof(g_errorPathMap) / sizeof(g_errorPathMap[0]); ++i) {
        VFYCBK_FAIL_IF((selection->errorPath & g_errorPathMap[i].errorPathBit) != 0,
            storeCtx, cert, depth, g_errorPathMap[i].x509VfyErrorCode);
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t CheckCrlIssuerKeyUsage(HITLS_X509_Cert *issueCert)
{
 // Issuer cert keyusage MUST include HITLS_X509_EXT_KU_CRL_SIGN
    HITLS_X509_CertExt *certExt = (HITLS_X509_CertExt *)issueCert->tbs.ext.extData;
    if (((certExt->extFlags & HITLS_X509_EXT_FLAG_KUSAGE) != 0) &&
        (certExt->keyUsage & HITLS_X509_EXT_KU_CRL_SIGN) == 0) {
        return HITLS_X509_ERR_VFY_KU_NO_CRLSIGN;
    }
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_X509_CheckCertCrl(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Cert *cert, HITLS_X509_Cert *parent,
    int32_t depth, int64_t *time)
{
    int32_t ret;
    uint32_t reasons = HITLS_X509_REASON_FLAG_NONE;
    while (reasons != HITLS_X509_REASON_FLAG_ALL) {
        HITLS_X509_CrlSelection selection = {0};
        selection.reasons = reasons;
        /*
         * The errorPath of the selection is one of:
         * 1. HITLS_X509_CRL_ERROR_TIME
         * 2. HITLS_X509_CRL_ERROR_DIFF_SCOPE
         * 3. HITLS_X509_CRL_ERROR_CRITICAL_EXT
         */
        ret = X509_FindBaseCrlAndDeltaCrl(storeCtx, time, cert, parent, &selection);
        VFYCBK_FAIL_IF(ret != HITLS_PKI_SUCCESS, storeCtx, cert, depth, HITLS_X509_ERR_VFY_CRL_NOT_FOUND);
        if (selection.baseCrl == NULL) {
            return HITLS_PKI_SUCCESS;
        }
        // if the selected crl has errors, we notify these errors to determined if they can be processed
        if (selection.errorPath != 0) {
            RETURN_RET_IF_ERR(NotifyErrors(storeCtx, cert, &selection, depth, time), ret);
        }
        ret = CheckCrlIssuerKeyUsage(selection.issuerCert);
        VFYCBK_FAIL_IF(ret != HITLS_PKI_SUCCESS, storeCtx, cert, depth, HITLS_X509_ERR_VFY_KU_NO_CRLSIGN);
        ret = X509_VerifyCrlSig(storeCtx, selection.issuerCert, selection.baseCrl);
        VFYCBK_FAIL_IF(ret != HITLS_PKI_SUCCESS, storeCtx, cert, depth, ret);
        if (selection.deltaCrl != NULL) {
            // A delta CRL can't be used to revoke a certificate if it has unhandled critical extensions
            ret = X509_CheckCrlCriticalExt(storeCtx, selection.deltaCrl);
            VFYCBK_FAIL_IF(ret != HITLS_PKI_SUCCESS, storeCtx, cert, depth, HITLS_X509_ERR_PROCESS_CRITICALEXT);
            ret = X509_VerifyCrlSig(storeCtx, selection.issuerCert, selection.deltaCrl);
            VFYCBK_FAIL_IF(ret != HITLS_PKI_SUCCESS, storeCtx, cert, depth, HITLS_X509_ERR_VFY_CRLSIGN_FAIL);
        }
        ret = X509_CheckCertRevoke(cert, &selection);
        VFYCBK_FAIL_IF(ret != HITLS_PKI_SUCCESS, storeCtx, cert, depth, HITLS_X509_ERR_VFY_CERT_REVOKED);
        reasons |= selection.newReasons;
    }
    return HITLS_PKI_SUCCESS;
}
#endif /* HITLS_PKI_X509_VFY_CRL_LITE */

static int32_t HITLS_X509_CheckCertCrlLite(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Cert *cert,
                                           HITLS_X509_Cert *parent, int32_t depth, int64_t *time)
{
    int32_t ret = HITLS_X509_ERR_VFY_CRL_NOT_FOUND;
    HITLS_X509_CertExt *certExt = (HITLS_X509_CertExt *)parent->tbs.ext.extData;
    VFYCBK_FAIL_IF((((certExt->extFlags & HITLS_X509_EXT_FLAG_KUSAGE) != 0) &&
                    ((certExt->keyUsage & HITLS_X509_EXT_KU_CRL_SIGN) == 0)),
                   storeCtx, cert, depth, HITLS_X509_ERR_VFY_KU_NO_CRLSIGN);

    for (BslListNode *crlNode = BSL_LIST_FirstNode(storeCtx->crl); crlNode != NULL;
         crlNode = BSL_LIST_GetNextNode(storeCtx->crl, crlNode)) {
        HITLS_X509_Crl *crl = (HITLS_X509_Crl *)BSL_LIST_GetData(crlNode);
        if (HITLS_X509_CmpNameNode(crl->tbs.issuerName, parent->tbs.subjectName) != 0) {
            continue;
        }
        if (parent->tbs.version == HITLS_X509_VERSION_3 && crl->tbs.version == 1) {
            if (HITLS_X509_CheckAki(&parent->tbs.ext, &crl->tbs.crlExt, parent->tbs.issuerName,
                                    &parent->tbs.serialNum) != HITLS_PKI_SUCCESS) {
#ifdef HITLS_PKI_X509_VFY_CB
                if (VerifyCertCbk(storeCtx, cert, depth, HITLS_X509_ERR_VFY_AKI_SKI_NOT_MATCH) != HITLS_PKI_SUCCESS) {
                    continue;
                }
#else
                continue;
#endif
            }
        }
        if (HITLS_X509_CheckCrlTime(storeCtx, crl, depth, time) != HITLS_PKI_SUCCESS) {
            continue;
        }
        ret = HITLS_X509_TrvList(crl->tbs.crlExt.extList, (HITLS_X509_TrvListCallBack)HITLS_X509_CheckCrlExtNode,
                                 storeCtx);
        if (ret != HITLS_PKI_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }

        ret = HITLS_X509_CheckSignAlgConsistency(&crl->tbs.signAlgId, &crl->signAlgId);
        VFYCBK_FAIL_IF(ret != HITLS_PKI_SUCCESS, storeCtx, cert, depth, ret);

        ret = HITLS_X509_CheckAlg(parent->tbs.ealPubKey, &crl->tbs.signAlgId);
        VFYCBK_FAIL_IF(ret != HITLS_PKI_SUCCESS, storeCtx, cert, depth, ret);

#ifdef HITLS_CRYPTO_SM2
        ret = X509_StoreCheckSignature(&storeCtx->verifyParam.sm2UserId, parent->tbs.ealPubKey, crl->tbs.tbsRawData,
                                       crl->tbs.tbsRawDataLen, &(crl->signAlgId), &(crl->signature));
#else
        ret = X509_StoreCheckSignature(NULL, parent->tbs.ealPubKey, crl->tbs.tbsRawData, crl->tbs.tbsRawDataLen,
                                       &(crl->signAlgId), &(crl->signature));
#endif
        VFYCBK_FAIL_IF(ret != HITLS_PKI_SUCCESS, storeCtx, cert, depth, HITLS_X509_ERR_VFY_CRLSIGN_FAIL);

        ret = HITLS_X509_TrvList(crl->tbs.revokedCerts, (HITLS_X509_TrvListCallBack)HITLS_X509_CheckCertRevoked, cert);
        VFYCBK_FAIL_IF(ret != HITLS_PKI_SUCCESS, storeCtx, cert, depth, HITLS_X509_ERR_VFY_CERT_REVOKED);
    }
    VFYCBK_FAIL_IF(ret != HITLS_PKI_SUCCESS, storeCtx, cert, depth, HITLS_X509_ERR_VFY_CRL_NOT_FOUND);
    return HITLS_PKI_SUCCESS;
}


int32_t HITLS_X509_VerifyCrl(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *chain, int64_t *time)
{
    // Check if CRL verification is required by flags
    if ((storeCtx->verifyParam.flags & (HITLS_X509_VFY_FLAG_CRL_ALL | HITLS_X509_VFY_FLAG_CRL_DEV)) == 0) {
        return HITLS_PKI_SUCCESS;
    }

    // Only the self-signed certificate, and the CRL is not verified
    if (BSL_LIST_COUNT(chain) == 1) {
        return HITLS_PKI_SUCCESS;
    }
    bool notCheckAll = (storeCtx->verifyParam.flags & HITLS_X509_VFY_FLAG_CRL_ALL) == 0;
    int32_t ret = HITLS_PKI_SUCCESS;
    int32_t depth = 0;
    for (BslListNode *currNode = BSL_LIST_FirstNode(chain), *nextNode = BSL_LIST_GetNextNode(chain, currNode);
         currNode != NULL && nextNode != NULL;
         currNode = nextNode, nextNode = BSL_LIST_GetNextNode(chain, nextNode), depth++) {
#ifdef HITLS_PKI_X509_VFY_CRL_LITE
        ret = HITLS_X509_CheckCertCrlLite(storeCtx, BSL_LIST_GetData(currNode),
            BSL_LIST_GetData(nextNode), depth, time);
#else
        if ((storeCtx->verifyParam.flags & HITLS_X509_VFY_FLAG_CRL_LITE) != 0) {
            ret = HITLS_X509_CheckCertCrlLite(storeCtx, BSL_LIST_GetData(currNode),
                BSL_LIST_GetData(nextNode), depth, time);
        } else {
            ret = HITLS_X509_CheckCertCrl(storeCtx, BSL_LIST_GetData(currNode),
                BSL_LIST_GetData(nextNode), depth, time);
        }
#endif
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
        // If only checking device certificate, break after the first one
        if (notCheckAll) {
            break;
        }
    }
    return ret;
}

static bool OidInList(BslList *oidList, BslCid target)
{
    if (oidList == NULL) {
        return false;
    }

    for (BslListNode *oidNode = BSL_LIST_FirstNode(oidList); oidNode != NULL;
        oidNode = BSL_LIST_GetNextNode(oidList, oidNode)) {
        BSL_Buffer *buffer = (BSL_Buffer *)BSL_LIST_GetData(oidNode);
        if (buffer->data != NULL && buffer->dataLen > 0) {
            BslCid cid = BSL_OBJ_GetCidFromOidBuff(buffer->data, buffer->dataLen);
            if (cid == target) {
                return true;
            }
        }
    }
    return false;
}

static int32_t X509_VerifyExtKeyUsage(HITLS_X509_Cert *cert, uint16_t requiredKuMask, BslCid requiredEkuOids)
{
    HITLS_X509_CertExt *ext = (HITLS_X509_CertExt *)cert->tbs.ext.extData;

    // KeyUsage check
    if ((ext->extFlags & HITLS_X509_EXT_FLAG_KUSAGE) != 0) {
        if ((ext->keyUsage & requiredKuMask) == 0) {
            return HITLS_X509_ERR_VFY_PURPOSE_UNMATCH;
        }
    }

    // ExtendedKeyUsage check: per RFC 5280 4.2.1.12, if EKU is absent the cert is
    // acceptable for any purpose (subject to KU constraints checked above).
    if ((ext->extFlags & HITLS_X509_EXT_FLAG_EXKUSAGE) != 0) {
        if (OidInList(ext->exKeyUsage.oidList, requiredEkuOids) == false) {
            return HITLS_X509_ERR_VFY_PURPOSE_UNMATCH;
        }
    }

    return HITLS_PKI_SUCCESS;
}

/**
 * RFC 5280 4.2.1.3 (Key Usage) and 4.2.1.12 (Extended Key Usage)
 * The KU/EKU extensions jointly constrain how an end-entity certificate may be used.
 * If both are present, usage must satisfy *both* extensions.  Typical application
 * mappings (serverAuth, clientAuth, emailProtection, codeSigning, OCSPSigning)
 * follow the examples given in RFC 5280 4.2.1.12, Table 1 and text paragraphs.
 */
static int32_t X509_VerifyUsageEE(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Cert *ee)
{
    uint16_t requiredKu = 0;
    BslCid eku = 0;
    int32_t purpose = storeCtx->verifyParam.purpose;
    HITLS_X509_CertExt *ext = (HITLS_X509_CertExt *)ee->tbs.ext.extData;
    if (ext == NULL || purpose == 0 || purpose == HITLS_X509_VFY_PURPOSE_ANY) {
        return HITLS_PKI_SUCCESS;
    }
    switch (purpose) {
        case HITLS_X509_VFY_PURPOSE_TLS_SERVER:
            // id-kp-serverAuth
            // TLS WWW server authentication
            // Key usage bits that may be consistent: digitalSignature,keyEncipherment or keyAgreement
            // GM/T (0015-2023) SM2 certificates allow digital signature, non-repudiation, key encipherment,
            // data encipherment, and key agreement.
            requiredKu =
                (HITLS_X509_EXT_KU_DIGITAL_SIGN | HITLS_X509_EXT_KU_KEY_ENCIPHERMENT | HITLS_X509_EXT_KU_KEY_AGREEMENT |
                HITLS_X509_EXT_KU_NON_REPUDIATION | HITLS_X509_EXT_KU_DATA_ENCIPHERMENT);
            eku = BSL_CID_KP_SERVERAUTH;
            break;
        case HITLS_X509_VFY_PURPOSE_TLS_CLIENT:
            // id-kp-clientAuth
            // TLS WWW client authentication
            // Key usage bits that may be consistent: digitalSignature and/or keyAgreement
            // GM/T (0015-2023) SM2 certificates allow digital signature,non-repudation, key encipherment,
            // data encipherment, and key agreement.
            requiredKu = (HITLS_X509_EXT_KU_DIGITAL_SIGN | HITLS_X509_EXT_KU_KEY_AGREEMENT |
                HITLS_X509_EXT_KU_KEY_ENCIPHERMENT | HITLS_X509_EXT_KU_NON_REPUDIATION |
                HITLS_X509_EXT_KU_DATA_ENCIPHERMENT);
            eku = BSL_CID_KP_CLIENTAUTH;
            break;
        case HITLS_X509_VFY_PURPOSE_EMAIL_SIGN:
            // id-kp-emailProtection
            // Email protection
            // Key usage bits that may be consistent: digitalSignature,nonRepudiation,
            // and/or (keyEncipherment or keyAgreement)
            requiredKu = (HITLS_X509_EXT_KU_DIGITAL_SIGN | HITLS_X509_EXT_KU_NON_REPUDIATION);
            eku = BSL_CID_KP_EMAILPROTECTION;
            break;
        case HITLS_X509_VFY_PURPOSE_EMAIL_ENCRYPT:
            // id-kp-emailProtection
            // Email protection
            // Key usage bits that may be consistent: digitalSignature,nonRepudiation,
            // and/or (keyEncipherment or keyAgreement)
            requiredKu = HITLS_X509_EXT_KU_KEY_ENCIPHERMENT;
            eku = BSL_CID_KP_EMAILPROTECTION;
            break;
        case HITLS_X509_VFY_PURPOSE_CODE_SIGN:
            // id-kp-codeSigning
            // Signing of downloadable executable code
            // Key usage bits that may be consistent: digitalSignature
            requiredKu = HITLS_X509_EXT_KU_DIGITAL_SIGN;
            eku = BSL_CID_KP_CODESIGNING;
            break;
        case HITLS_X509_VFY_PURPOSE_OCSP_SIGN:
            // id-kp-OCSPSigning
            // Signing OCSP responses
            // Key usage bits that may be consistent: digitalSignature and/or nonRepudiation
            requiredKu = (HITLS_X509_EXT_KU_DIGITAL_SIGN | HITLS_X509_EXT_KU_NON_REPUDIATION);
            eku = BSL_CID_KP_OCSPSIGNING;
            break;
        case HITLS_X509_VFY_PURPOSE_TIMESTAMPING:
            // id-kp-timeStamping
            // Binding the hash of an object to a time
            // Key usage bits that may be consistent: digitalSignature and/or nonRepudiation
            requiredKu = (HITLS_X509_EXT_KU_DIGITAL_SIGN | HITLS_X509_EXT_KU_NON_REPUDIATION);
            eku = BSL_CID_KP_TIMESTAMPING;
            break;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_VFY_INVALID_PURPOSE);
            return HITLS_X509_ERR_VFY_INVALID_PURPOSE;
    }

    // Enforce both KU and EKU consistency as per RFC 5280 4.2.1.(12) final paragraph
    return X509_VerifyExtKeyUsage(ee, requiredKu, eku);
}

int32_t X509_VerifyChainCert(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *chain, int64_t *time)
{
    BslListNode *curNode = BSL_LIST_LastNode(chain);
    HITLS_X509_Cert *issue = (HITLS_X509_Cert *)BSL_LIST_GetData(curNode);
    int32_t depth = BSL_LIST_COUNT(chain) - 1;
    int32_t ret;
    if ((storeCtx->verifyParam.flags & HITLS_X509_VFY_FLAG_PARTIAL_CHAIN) != 0) {
        BSL_ERR_SET_MARK();
        bool selfSigned = HITLS_X509_IsSelfSigned(issue);
        BSL_ERR_POP_TO_MARK();
        if (!selfSigned && depth > 0) {
            ret = HITLS_X509_CheckCertTime(storeCtx, issue, depth, time);
            if (ret != HITLS_PKI_SUCCESS) {
                return ret;
            }
            curNode = BSL_LIST_GetPrevNode(curNode);
            depth--;
        }
    }
    while (curNode != NULL) {
        HITLS_X509_Cert *cur = (HITLS_X509_Cert *)BSL_LIST_GetData(curNode);
        ret = HITLS_X509_CheckCertTime(storeCtx, cur, depth, time);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
        ret = HITLS_X509_CheckSignAlgConsistency(&cur->tbs.signAlgId, &cur->signAlgId);
        VFYCBK_FAIL_IF(ret != HITLS_PKI_SUCCESS, storeCtx, cur, depth, ret);

#ifdef HITLS_CRYPTO_SM2
        ret = X509_StoreCheckSignature(&storeCtx->verifyParam.sm2UserId, issue->tbs.ealPubKey, cur->tbs.tbsRawData,
            cur->tbs.tbsRawDataLen, &cur->signAlgId, &cur->signature);
#else
        ret = X509_StoreCheckSignature(NULL, issue->tbs.ealPubKey, cur->tbs.tbsRawData,
            cur->tbs.tbsRawDataLen, &cur->signAlgId, &cur->signature);
#endif
        VFYCBK_FAIL_IF(ret != HITLS_PKI_SUCCESS, storeCtx, cur, depth, HITLS_X509_ERR_VFY_CERT_SIGN_FAIL);

        issue = cur;
        curNode = BSL_LIST_GetPrevNode(curNode);
        depth--;
    }

    return HITLS_PKI_SUCCESS;
}

static int32_t X509_GetVerifyCertChain(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *chain,
    HITLS_X509_List **comChain)
{
    HITLS_X509_Cert *cert = (HITLS_X509_Cert *)BSL_LIST_FirstNodeData(chain);
    if (cert == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    return HITLS_X509_CertChainBuildWithRoot(true, storeCtx, chain, cert, comChain);
}

int32_t X509_CheckExt(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *chain)
{
    BslListNode *curNode = BSL_LIST_LastNode(chain);
    int32_t rootDepth = BSL_LIST_COUNT(chain) - 1;
    int32_t curDepth = rootDepth;
    int32_t maxPathLen = rootDepth;

    while (curNode != NULL) {
        HITLS_X509_Cert *cur = (HITLS_X509_Cert *)BSL_LIST_GetData(curNode);
        HITLS_X509_CertExt *curExt = (HITLS_X509_CertExt *)cur->tbs.ext.extData;

        if (curDepth > 0) { // CA certificates (root and intermediate)
            /** RFC 5280 Section 6.1.4:
             * (k) If certificate i is a version 3 certificate, verify that the basicConstraints extension is
             *     present and that cA is set to TRUE. (If certificate i is a version 1 or version 2 certificate,
             *     then the application MUST either verify that certificate i is a CA certificate through
             *     out-of-band means or reject the certificate. Conforming implementations may choose to reject
             *     all version 1 and version 2 intermediate certificates.)
             */
            if (curDepth == rootDepth) {
                VFYCBK_FAIL_IF(((cur->tbs.version == HITLS_X509_VERSION_3) &&
                    ((curExt->extFlags & HITLS_X509_EXT_FLAG_BCONS) == 0 || !curExt->isCa)),
                    storeCtx, cur, curDepth, HITLS_X509_ERR_VFY_INVALID_CA);
            } else {
                VFYCBK_FAIL_IF(cur->tbs.version != HITLS_X509_VERSION_3,
                    storeCtx, cur, curDepth, HITLS_X509_ERR_VFY_INTERCA_INVALID_VERSION);
                VFYCBK_FAIL_IF((curExt->extFlags & HITLS_X509_EXT_FLAG_BCONS) == 0 || !curExt->isCa,
                    storeCtx, cur, curDepth, HITLS_X509_ERR_VFY_INTERCA_INVALID_BCONS);
            }
            /**
             * Conforming CAs MUST include this extension in certificates that contain public keys
             * that are used to validate digital signatures on other public key certificates or CRLs.
             */
            VFYCBK_FAIL_IF(((curExt->extFlags & HITLS_X509_EXT_FLAG_KUSAGE) != 0) &&
                ((curExt->keyUsage & HITLS_X509_EXT_KU_KEY_CERT_SIGN) == 0),
                storeCtx, cur, curDepth, HITLS_X509_ERR_VFY_KU_NO_CERTSIGN);

            /**
             * RFC5280 6.1.4
             * (l)  If the certificate was not self-issued, verify that max_path_length is greater than zero 
             * and decrement max_path_length by 1.
             * (m)  If pathLenConstraint is present in the certificate and is less than max_path_length,
             * set max_path_length to the value of pathLenConstraint.
             */
            if (!cur->isSelfIssued) {
                VFYCBK_FAIL_IF(maxPathLen <= 0, storeCtx, cur, curDepth,
                    HITLS_X509_ERR_VFY_PATHLEN_EXCEEDED);
                maxPathLen--;
            }
            if (curExt->maxPathLen >= 0 && curExt->maxPathLen < maxPathLen) {
                maxPathLen = curExt->maxPathLen;
            }
        } else {
            int32_t ret = X509_VerifyUsageEE(storeCtx, cur);
            VFYCBK_FAIL_IF(ret != HITLS_PKI_SUCCESS, storeCtx, cur, curDepth, ret);
        }
        curNode = BSL_LIST_GetPrevNode(curNode);
        curDepth--;
    }
    return HITLS_PKI_SUCCESS;
}

#ifdef HITLS_PKI_X509_VFY_IDENTITY
static int32_t CheckHostnames(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *chain)
{
    int32_t ret = HITLS_X509_ERR_VFY_HOSTNAME_FAIL;
    HITLS_X509_Cert *certee = (HITLS_X509_Cert *)BSL_LIST_FirstNodeData(chain);
    for (BslListNode *hostNode = BSL_LIST_FirstNode(storeCtx->verifyParam.hostnames); hostNode != NULL;
        hostNode = BSL_LIST_GetNextNode(storeCtx->verifyParam.hostnames, hostNode)) {
        char *hostname = (char *)BSL_LIST_GetData(hostNode);
        ret = HITLS_X509_VerifyHostname(certee, storeCtx->verifyParam.hostflags, hostname, strlen(hostname));
        if (ret == HITLS_PKI_SUCCESS) {
            storeCtx->verifyParam.peername = DupString(hostname);
            if (storeCtx->verifyParam.peername == NULL) {
                BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
                return BSL_MALLOC_FAIL;
            }
            break;
        }
    }

    return ret;
}

static int32_t CheckIp(HITLS_X509_Cert *cert, unsigned char *ip, int32_t ipLen)
{
    HITLS_X509_ExtSan san = {0};
    int32_t ret = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_GET_SAN, &san, sizeof(san));
    if (ret != HITLS_PKI_SUCCESS || san.names == NULL) {
        return HITLS_X509_ERR_VFY_IP_FAIL;
    }
    ret = HITLS_X509_ERR_VFY_IP_FAIL;
    for (BslListNode *nameNode = BSL_LIST_FirstNode(san.names); nameNode != NULL;
        nameNode = BSL_LIST_GetNextNode(san.names, nameNode)) {
        HITLS_X509_GeneralName *gn = (HITLS_X509_GeneralName *)BSL_LIST_GetData(nameNode);
        if (gn->type == HITLS_X509_GN_IP) {
            if ((uint32_t)ipLen == gn->value.dataLen && memcmp(gn->value.data, ip, gn->value.dataLen) == 0) {
                ret = HITLS_PKI_SUCCESS;
                break;
            }
        }
    }

    HITLS_X509_ClearSubjectAltName(&san);
    return ret;
}

static int32_t CheckIdentityList(HITLS_X509_Cert *cert, BslList *identities, uint32_t flags, uint32_t type)
{
    int32_t ret = HITLS_X509_ERR_VFY_HOSTNAME_FAIL;
    for (BslListNode *node = BSL_LIST_FirstNode(identities); node != NULL; node = BSL_LIST_GetNextNode(identities,
        node)) {
        char *identity = (char *)BSL_LIST_GetData(node);
        ret = HITLS_X509_VerifyIdentity(cert, flags, type, identity, strlen(identity));
        if (ret == HITLS_PKI_SUCCESS) {
            break;
        }
    }

    return ret;
}

static int32_t X509_CheckHost(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *chain)
{
    BSL_SAL_FREE(storeCtx->verifyParam.peername);

    int32_t ret;
    HITLS_X509_Cert *certee = (HITLS_X509_Cert *)BSL_LIST_FirstNodeData(chain);
    if (storeCtx->verifyParam.hostnames != NULL && BSL_LIST_COUNT(storeCtx->verifyParam.hostnames) > 0) {
        ret = CheckHostnames(storeCtx, chain);
        VFYCBK_FAIL_IF(ret != HITLS_PKI_SUCCESS, storeCtx, certee, 0, ret);
    }

    if (storeCtx->verifyParam.ip != NULL) {
        ret = CheckIp(certee, storeCtx->verifyParam.ip, storeCtx->verifyParam.ipLen);
        VFYCBK_FAIL_IF(ret != HITLS_PKI_SUCCESS, storeCtx, certee, 0, ret);
    }

    if (storeCtx->verifyParam.uriIds != NULL && BSL_LIST_COUNT(storeCtx->verifyParam.uriIds) > 0) {
        ret = CheckIdentityList(certee, storeCtx->verifyParam.uriIds, storeCtx->verifyParam.hostflags, HITLS_GEN_URI);
        VFYCBK_FAIL_IF(ret != HITLS_PKI_SUCCESS, storeCtx, certee, 0, ret);
    }

    if (storeCtx->verifyParam.srvIds != NULL && BSL_LIST_COUNT(storeCtx->verifyParam.srvIds) > 0) {
        ret = CheckIdentityList(certee, storeCtx->verifyParam.srvIds, storeCtx->verifyParam.hostflags, HITLS_GEN_SRV);
        VFYCBK_FAIL_IF(ret != HITLS_PKI_SUCCESS, storeCtx, certee, 0, ret);
    }
    return HITLS_PKI_SUCCESS;
}
#endif

static int32_t GetCheckTime(HITLS_X509_StoreCtx *storeCtx, bool *isCheckTime, int64_t *checkTime)
{
    *isCheckTime = true;
    if ((storeCtx->verifyParam.flags & HITLS_X509_VFY_FLAG_TIME) != 0) {
        *checkTime = storeCtx->verifyParam.time;
    } else if ((storeCtx->verifyParam.flags & HITLS_X509_VFY_FLAG_DISABLE_TIME_CHECK) == 0) {
        *checkTime = BSL_SAL_CurrentSysTimeGet();
        if (*checkTime <= 0) {
            return BSL_SAL_TIME_SYS_ERROR;
        }
    } else {
        *isCheckTime = false;
    }
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_X509_CertVerify(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *chain)
{
    if (storeCtx == NULL || chain == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    if (BSL_LIST_COUNT(chain) <= 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CERT_CHAIN_COUNT_IS0);
        return HITLS_X509_ERR_CERT_CHAIN_COUNT_IS0;
    }

    int32_t ret = X509_GetVerifyCertChain(storeCtx, chain, &storeCtx->certChain);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = HITLS_X509_VerifyParamAndExt(storeCtx, storeCtx->certChain);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    ret = X509_CheckExt(storeCtx, storeCtx->certChain);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }

    bool isCheckTime;
    int64_t time = 0;
    ret = GetCheckTime(storeCtx, &isCheckTime, &time);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    ret = HITLS_X509_VerifyCrl(storeCtx, storeCtx->certChain, isCheckTime ? &time : NULL);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    ret = X509_VerifyChainCert(storeCtx, storeCtx->certChain, isCheckTime ? &time : NULL);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
#ifdef HITLS_PKI_X509_VFY_IDENTITY
    ret = X509_CheckHost(storeCtx, storeCtx->certChain);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
#endif
#ifdef HITLS_PKI_X509_VFY_CB
    storeCtx->curCert = (HITLS_X509_Cert *)BSL_LIST_FirstNodeData(chain);
    storeCtx->curDepth = 0;
    ret = VerifyCertCbk(storeCtx, NULL, -1, HITLS_PKI_SUCCESS);
#endif
EXIT:
    BSL_LIST_FREE(storeCtx->certChain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    return ret;
}

int32_t HITLS_X509_CertVerifyByPubKey(HITLS_X509_Cert *cert, CRYPT_EAL_PkeyCtx *pubKey)
{
    if (cert == NULL || pubKey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    int32_t ret = HITLS_X509_CheckSignAlgConsistency(&cert->tbs.signAlgId, &cert->signAlgId);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    return X509_StoreCheckSignature(NULL, pubKey, cert->tbs.tbsRawData,
        cert->tbs.tbsRawDataLen, &cert->signAlgId, &cert->signature);
}

HITLS_X509_StoreCtx *HITLS_X509_ProviderStoreCtxNew(HITLS_PKI_LibCtx *libCtx, const char *attrName)
{
    HITLS_X509_StoreCtx *storeCtx = HITLS_X509_StoreCtxNew();
    if (storeCtx == NULL) {
        return NULL;
    }
    storeCtx->libCtx = libCtx;
    storeCtx->attrName = attrName;
#ifdef HITLS_PKI_X509_VFY_CB
    storeCtx->verifyCb = VerifyCbDefault;
#endif
    return storeCtx;
}

static int32_t X509_RefUpCertItem(void *item)
{
    int ref;
    return HITLS_X509_CertCtrl(item, HITLS_X509_REF_UP, &ref, sizeof(ref));
}

static int32_t X509_RefUpCrlItem(void *item)
{
    int ref;
    return HITLS_X509_CrlCtrl(item, HITLS_X509_REF_UP, &ref, sizeof(ref));
}

static int32_t X509_CopyRefList(BslList *dst, const BslList *src, int32_t (*refUp)(void *), BSL_LIST_PFUNC_FREE freeFn)
{
    for (BslListNode *node = BSL_LIST_FirstNode(src); node != NULL; node = BSL_LIST_GetNextNode(src, node)) {
        void *item = BSL_LIST_GetData(node);
        int32_t ret = refUp(item);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
        ret = BSL_LIST_AddElement(dst, item, BSL_LIST_POS_END);
        if (ret != BSL_SUCCESS) {
            freeFn(item);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    return HITLS_PKI_SUCCESS;
}

#if defined(HITLS_CRYPTO_SM2) || defined(HITLS_PKI_X509_VFY_IDENTITY)
static int32_t X509_CopyBufferData(uint8_t **dst, const uint8_t *src, uint32_t srcLen)
{
    if (src == NULL || srcLen == 0) {
        return HITLS_PKI_SUCCESS;
    }
    *dst = BSL_SAL_Dump(src, srcLen);
    if (*dst == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    return HITLS_PKI_SUCCESS;
}
#endif

static int32_t X509_CopyStoreLists(HITLS_X509_StoreCtx *dst, const HITLS_X509_StoreCtx *src)
{
    int32_t ret;

    ret = X509_CopyRefList(dst->store, src->store, X509_RefUpCertItem, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    ret = X509_CopyRefList(dst->crl, src->crl, X509_RefUpCrlItem, (BSL_LIST_PFUNC_FREE)HITLS_X509_CrlFree);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

#ifdef HITLS_PKI_X509_VFY_LOCATION
    ret = X509_CopyStringList(dst->caPaths, src->caPaths);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
#endif

    return HITLS_PKI_SUCCESS;
}

static int32_t X509_CopyVerifyParams(HITLS_X509_StoreCtx *dst, const HITLS_X509_StoreCtx *src)
{
    dst->verifyParam.maxDepth = src->verifyParam.maxDepth;
    dst->verifyParam.securityBits = src->verifyParam.securityBits;
    dst->verifyParam.time = src->verifyParam.time;
    dst->verifyParam.flags = src->verifyParam.flags;
    dst->verifyParam.purpose = src->verifyParam.purpose;

#ifdef HITLS_CRYPTO_SM2
    int32_t ret = X509_CopyBufferData(&dst->verifyParam.sm2UserId.data, src->verifyParam.sm2UserId.data,
        src->verifyParam.sm2UserId.dataLen);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (dst->verifyParam.sm2UserId.data != NULL) {
        dst->verifyParam.sm2UserId.dataLen = src->verifyParam.sm2UserId.dataLen;
    }
#endif

    return HITLS_PKI_SUCCESS;
}

#ifdef HITLS_PKI_X509_VFY_IDENTITY
static int32_t X509_CopyIdentityParams(HITLS_X509_StoreCtx *dst, const HITLS_X509_StoreCtx *src)
{
    int32_t ret;

    if (src->verifyParam.hostnames != NULL) {
        dst->verifyParam.hostnames = BSL_LIST_New(sizeof(char *));
        if (dst->verifyParam.hostnames == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }
        ret = X509_CopyStringList(dst->verifyParam.hostnames, src->verifyParam.hostnames);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
    }

    if (src->verifyParam.uriIds != NULL) {
        dst->verifyParam.uriIds = BSL_LIST_New(sizeof(char *));
        if (dst->verifyParam.uriIds == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }
        ret = X509_CopyStringList(dst->verifyParam.uriIds, src->verifyParam.uriIds);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
    }

    if (src->verifyParam.srvIds != NULL) {
        dst->verifyParam.srvIds = BSL_LIST_New(sizeof(char *));
        if (dst->verifyParam.srvIds == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }
        ret = X509_CopyStringList(dst->verifyParam.srvIds, src->verifyParam.srvIds);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
    }

    ret = X509_CopyBufferData(&dst->verifyParam.ip, src->verifyParam.ip, (uint32_t)src->verifyParam.ipLen);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (dst->verifyParam.ip != NULL) {
        dst->verifyParam.ipLen = src->verifyParam.ipLen;
    }

    dst->verifyParam.hostflags = src->verifyParam.hostflags;

    return HITLS_PKI_SUCCESS;
}
#endif

HITLS_X509_StoreCtx *HITLS_X509_StoreCtxDup(const HITLS_X509_StoreCtx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    HITLS_X509_StoreCtx *newCtx = HITLS_X509_StoreCtxNew();
    if (newCtx == NULL) {
        return NULL;
    }

    int32_t ret;

    ret = X509_CopyStoreLists(newCtx, ctx);
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }

    ret = X509_CopyVerifyParams(newCtx, ctx);
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }

#ifdef HITLS_PKI_X509_VFY_IDENTITY
    ret = X509_CopyIdentityParams(newCtx, ctx);
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }
#endif

    newCtx->libCtx = ctx->libCtx;
    newCtx->attrName = ctx->attrName;
#ifdef HITLS_PKI_X509_VFY_CB
    newCtx->verifyCb = ctx->verifyCb;
    newCtx->usrData = ctx->usrData;
#endif
    return newCtx;

ERR:
    HITLS_X509_StoreCtxFree(newCtx);
    return NULL;
}

#endif // HITLS_PKI_X509_VFY
