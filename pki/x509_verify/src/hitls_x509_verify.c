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
#if defined(HITLS_PKI_X509_VFY_DEFAULT) || defined(HITLS_PKI_X509_VFY_CB) || defined(HITLS_PKI_X509_VFY_LOCATION)
#include <string.h>
#include "securec.h"
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
#include "bsl_list_internal.h"
#include "crypt_eal_md.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "hitls_x509_verify.h"

#define CRYPT_SHA1_DIGESTSIZE 20
#define MAX_PATH_LEN 4096

typedef int32_t (*HITLS_X509_TrvListCallBack)(void *ctx, void *node, int32_t depth);
typedef int32_t (*HITLS_X509_TrvListWithParentCallBack)(void *ctx, void *node, void *parent, int32_t depth);

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
    void *node = BSL_LIST_GET_FIRST(list);
    int32_t depth = 0;
    while (node != NULL) {
        ret = callBack(ctx, node, depth);
        if (ret != BSL_SUCCESS) {
            return ret;
        }
        node = BSL_LIST_GET_NEXT(list);
        depth++;
    }
    return ret;
}

// lists can be cert, ext, and so on.
static int32_t HITLS_X509_TrvListWithParent(BslList *list, HITLS_X509_TrvListWithParentCallBack callBack, void *ctx)
{
    int32_t ret = HITLS_PKI_SUCCESS;
    void *node = BSL_LIST_GET_FIRST(list);
    void *parentNode = BSL_LIST_GET_NEXT(list);
    int32_t depth = 0;
    while (node != NULL && parentNode != NULL) {
        ret = callBack(ctx, node, parentNode, depth);
        if (ret != BSL_SUCCESS) {
            return ret;
        }
        node = parentNode;
        parentNode = BSL_LIST_GET_NEXT(list);
        depth++;
    }
    return ret;
}

#define HITLS_X509_MAX_DEPTH 20

void HITLS_X509_StoreCtxFree(HITLS_X509_StoreCtx *storeCtx)
{
    if (storeCtx == NULL) {
        return;
    }
    int ret;
    (void)BSL_SAL_AtomicDownReferences(&storeCtx->references, &ret);
    if (ret > 0) {
        return;
    }

#ifdef HITLS_CRYPTO_SM2
    BSL_SAL_FREE(storeCtx->verifyParam.sm2UserId.data);
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

static int32_t X509_CrlCmp(HITLS_X509_Crl *crlOri, HITLS_X509_Crl *crl)
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

static int32_t X509_CertCmp(HITLS_X509_Cert *certOri, HITLS_X509_Cert *cert)
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

    (void)memset_s(ctx, sizeof(HITLS_X509_StoreCtx), 0, sizeof(HITLS_X509_StoreCtx));
    ctx->store = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    if (ctx->store == NULL) {
        BSL_SAL_Free(ctx);
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }
    ctx->crl = BSL_LIST_New(sizeof(HITLS_X509_Crl *));
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
    ctx->verifyParam.securityBits = 128; // 128: The default number of secure bits.
    ctx->certChain = NULL; // Initialize to NULL, will be created when needed
#ifdef HITLS_PKI_X509_VFY_CB
    ctx->verifyCb = VerifyCbDefault;
#endif
    BSL_SAL_ReferencesInit(&(ctx->references));
    return ctx;
}

static int32_t X509_SetMaxDepth(HITLS_X509_StoreCtx *storeCtx, int32_t *val, uint32_t valLen)
{
    if (valLen != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    int32_t depth = *val;
    if (depth > HITLS_X509_MAX_DEPTH) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    storeCtx->verifyParam.maxDepth = depth;
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

static int32_t X509_SetParamFlag(HITLS_X509_StoreCtx *storeCtx, uint64_t *val, uint32_t valLen)
{
    if (valLen != sizeof(uint64_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    storeCtx->verifyParam.flags |= *val;
    return HITLS_PKI_SUCCESS;
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

static int32_t X509_CheckCert(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Cert *cert)
{
    if (!HITLS_X509_CertIsCA(cert)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CERT_NOT_CA);
        return HITLS_X509_ERR_CERT_NOT_CA;
    }
    HITLS_X509_List *certStore = storeCtx->store;
    HITLS_X509_Cert *tmp = BSL_LIST_SearchEx(certStore, cert, (BSL_LIST_PFUNC_CMP)X509_CertCmp);
    if (tmp != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CERT_EXIST);
        return HITLS_X509_ERR_CERT_EXIST;
    }

    return HITLS_PKI_SUCCESS;
}

static int32_t X509_SetCA(HITLS_X509_StoreCtx *storeCtx, void *val, bool isCopy)
{
    int32_t ret = X509_CheckCert(storeCtx, val);
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

    ret = BSL_LIST_AddElement(storeCtx->store, val, BSL_LIST_POS_BEFORE);
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
    HITLS_X509_Crl *tmp = BSL_LIST_SearchEx(crlStore, crl, (BSL_LIST_PFUNC_CMP)X509_CrlCmp);
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
    ret = BSL_LIST_AddElement(storeCtx->crl, val, BSL_LIST_POS_BEFORE);
    if (ret != BSL_SUCCESS) {
        HITLS_X509_CrlFree(val);
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

#ifdef HITLS_PKI_X509_VFY_LOCATION
static int32_t X509_AddCAPath(HITLS_X509_StoreCtx *storeCtx, const void *val, uint32_t valLen)
{
    if (val == NULL || valLen == 0 || valLen > MAX_PATH_LEN) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    const char *caPath = (const char *)val;

    char *existPath = BSL_LIST_GET_FIRST(storeCtx->caPaths);
    while (existPath != NULL) {
        if (strlen(existPath) == valLen && memcmp(existPath, caPath, valLen) == 0) {
            return HITLS_PKI_SUCCESS;
        }
        existPath = BSL_LIST_GET_NEXT(storeCtx->caPaths);
    }

    // Allocate and copy new path
    char *pathCopy = BSL_SAL_Calloc(valLen + 1, sizeof(char));
    if (pathCopy == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    if (memcpy_s(pathCopy, valLen, caPath, valLen) != EOK) {
        BSL_SAL_Free(pathCopy);
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
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
    int32_t ret = snprintf_s(defaultPath, sizeof(defaultPath), sizeof(defaultPath) - 1,
    "%s/ssl/certs", OPENHITLSDIR);
    if (ret < 0) {
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
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
            return HITLS_X509_ERR_INVALID_PARAM;
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
#endif
        case HITLS_X509_STORECTX_GET_PARAM_FLAGS:
            return X509_GetParamFlag(storeCtx, val, valLen);
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
    if (val == NULL && cmd != HITLS_X509_STORECTX_CLEAR_CRL && cmd != HITLS_X509_STORECTX_SET_DEFAULT_PATH) {
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

int32_t HITLS_X509_CheckCertTime(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Cert *cert, int32_t depth)
{
    (void)depth;
    int64_t start = 0;
    int64_t end = 0;
    HITLS_X509_ValidTime *validTime = &cert->tbs.validTime;
    if ((storeCtx->verifyParam.flags & HITLS_X509_VFY_FLAG_TIME) == 0) {
        return HITLS_PKI_SUCCESS;
    }

    int32_t ret = BSL_SAL_DateToUtcTimeConvert(&validTime->start, &start);
    VFYCBK_FAIL_IF(ret != BSL_SUCCESS, storeCtx, cert, depth, HITLS_X509_ERR_VFY_GET_NOTBEFORE_FAIL);
    VFYCBK_FAIL_IF(start > storeCtx->verifyParam.time, storeCtx, cert, depth, HITLS_X509_ERR_VFY_NOTBEFORE_IN_FUTURE);

    ret = BSL_SAL_DateToUtcTimeConvert(&validTime->end, &end);
    VFYCBK_FAIL_IF(ret != BSL_SUCCESS, storeCtx, cert, depth, HITLS_X509_ERR_VFY_GET_NOTAFTER_FAIL);
    VFYCBK_FAIL_IF(end < storeCtx->verifyParam.time, storeCtx, cert, depth, HITLS_X509_ERR_VFY_NOTAFTER_EXPIRED);
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_X509_CheckCrlTime(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Crl *crl, int32_t depth)
{
    (void)depth;
    int64_t start = 0;
    int64_t end = 0;
    HITLS_X509_ValidTime *validTime = &crl->tbs.validTime;
    if ((storeCtx->verifyParam.flags & HITLS_X509_VFY_FLAG_TIME) == 0) {
        return HITLS_PKI_SUCCESS;
    }

    int32_t ret = BSL_SAL_DateToUtcTimeConvert(&validTime->start, &start);
    VFYCBK_FAIL_IF(ret != BSL_SUCCESS, storeCtx, NULL, depth, HITLS_X509_ERR_VFY_GET_THISUPDATE_FAIL);
    VFYCBK_FAIL_IF(start > storeCtx->verifyParam.time, storeCtx, NULL, depth, HITLS_X509_ERR_VFY_THISUPDATE_IN_FUTURE);

    if ((validTime->flag & BSL_TIME_AFTER_SET) == 0) {
        return HITLS_PKI_SUCCESS;
    }

    ret = BSL_SAL_DateToUtcTimeConvert(&validTime->end, &end);
    VFYCBK_FAIL_IF(ret != BSL_SUCCESS, storeCtx, NULL, depth, HITLS_X509_ERR_VFY_GET_NEXTUPDATE_FAIL);
    VFYCBK_FAIL_IF(end < storeCtx->verifyParam.time, storeCtx, NULL, depth, HITLS_X509_ERR_VFY_NEXTUPDATE_EXPIRED);
    return HITLS_PKI_SUCCESS;
}

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

int32_t X509_GetIssueFromChain(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *certChain, HITLS_X509_Cert *cert,
    HITLS_X509_Cert **issue)
{
    (void)storeCtx;
    for (HITLS_X509_Cert *tmp = BSL_LIST_GET_FIRST(certChain); tmp != NULL; tmp = BSL_LIST_GET_NEXT(certChain)) {
        bool res = HITLS_X509_CheckIssued(tmp, cert);
        if (!res) {
            continue;
        }
        *issue = tmp;
        return HITLS_PKI_SUCCESS;
    }
    BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND);
    return HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND;
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
    CRYPT_EAL_MdCTX *mdCtx = CRYPT_EAL_ProviderMdNewCtx(storeCtx->libCtx, CRYPT_MD_SHA1, storeCtx->attrName);
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
    char *caPath = BSL_LIST_GET_FIRST(storeCtx->caPaths);
    while (caPath != NULL) {
        int32_t seq = 0;
        while (1) {
            char filename[MAX_PATH_LEN] = {0};
            if (snprintf_s(filename, sizeof(filename), sizeof(filename) - 1,
                          "%s/%08x.%d", caPath, hash, seq) < 0) {
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
        caPath = BSL_LIST_GET_NEXT(storeCtx->caPaths);
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
    if (issuerDerData.buff != NULL && issuerDerData.len > 0) {
        ret = HITLS_X509_GetCertBySubjectDer(storeCtx, &issuerDerData, cert, issue, issueInTrust);
        BSL_SAL_FREE(issuerDerData.buff);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
    }
    return HITLS_PKI_SUCCESS;
}
#endif /* HITLS_PKI_X509_VFY_LOCATION */

/* The function can only return success and CERT NOT FOUND */
static int32_t X509_FindIssueCert(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *certChain, HITLS_X509_Cert *cert,
    HITLS_X509_Cert **issue, bool *issueInTrust)
{
    // First try to find issuer in explicitly loaded store
    HITLS_X509_List *store = storeCtx->store;
    int32_t ret = X509_GetIssueFromChain(storeCtx, store, cert, issue);
    if (ret == HITLS_PKI_SUCCESS) {
        *issueInTrust = true;
        return ret;
    }

#ifdef HITLS_PKI_X509_VFY_LOCATION
    // If we have CA paths set, try on-demand loading based on issuer DER-encoded DN
    if (BSL_LIST_COUNT(storeCtx->caPaths) > 0) {
        ret = FindIssuerByDer(storeCtx, cert, issue, issueInTrust);
        if (ret == HITLS_PKI_SUCCESS) {
            return HITLS_PKI_SUCCESS;
        }
    }
#endif /* HITLS_PKI_X509_VFY_LOCATION */

    // Then try the certificate chain if provided
    if (certChain != NULL) {
        ret = X509_GetIssueFromChain(storeCtx, certChain, cert, issue);
        if (ret == HITLS_PKI_SUCCESS) {
            *issueInTrust = false;
            return ret;
        }
    }
    BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND);
    return HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND;
}


int32_t X509_BuildChain(bool isVfy, HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *certChain, HITLS_X509_Cert *cert,
    HITLS_X509_List *chain, HITLS_X509_Cert **root)
{
    HITLS_X509_Cert *cur = cert;
    int32_t ret;
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

        if (isVfy && ((storeCtx->verifyParam.flags & HITLS_X509_VFY_FLAG_PARTIAL_CHAIN) != 0) && isTrustCa) {
            if (root != NULL) {
                *root = issue; // set root, possible not a self-signed certificate
            }
            return HITLS_PKI_SUCCESS;
        }
        bool selfSigned = HITLS_X509_CheckIssued(issue, issue);
        if (selfSigned) {
            if (root != NULL && isTrustCa) {
                *root = issue;
            }
            return HITLS_PKI_SUCCESS;
        }
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
    HITLS_X509_List *tmpChain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
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

static int32_t HITLS_X509_CertChainBuildWithRoot(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Cert *cert,
    HITLS_X509_List **chain)
{
    HITLS_X509_List *tmpChain = X509_NewCertChain(cert);
    if (tmpChain == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    HITLS_X509_Cert *root = NULL;
    int32_t ret = X509_BuildChain(false, storeCtx, NULL, cert, tmpChain, &root);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_LIST_FREE(tmpChain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        return ret;
    }
    // The root certificate must be found and trusted
    if (root == NULL) {
        BSL_LIST_FREE(tmpChain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        return HITLS_X509_ERR_ROOT_CERT_NOT_FOUND;
    }
    if (X509_CertCmp(cert, root) != 0) {
        ret = X509_AddCertToChain(tmpChain, root);
        if (ret != HITLS_PKI_SUCCESS) {
            BSL_LIST_FREE(tmpChain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
            return ret;
        }
    }
    *chain = tmpChain;
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_X509_CertChainBuild(HITLS_X509_StoreCtx *storeCtx, bool isWithRoot, HITLS_X509_Cert *cert,
    HITLS_X509_List **chain)
{
    if (storeCtx == NULL || cert == NULL || chain == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    if (isWithRoot) {
        return HITLS_X509_CertChainBuildWithRoot(storeCtx, cert, chain);
    }
    HITLS_X509_List *tmpChain = X509_NewCertChain(cert);
    if (tmpChain == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    bool selfSigned = HITLS_X509_CheckIssued(cert, cert);
    if (selfSigned) {
        *chain = tmpChain;
        return HITLS_PKI_SUCCESS;
    }
    (void)X509_BuildChain(false, storeCtx, NULL, cert, tmpChain, NULL);
    *chain = tmpChain;

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

int32_t HITLS_X509_CheckVerifyParam(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *chain)
{
    if ((storeCtx->verifyParam.flags & HITLS_X509_VFY_FLAG_SECBITS) != 0) {
        return HITLS_X509_TrvList(chain, (HITLS_X509_TrvListCallBack)HITLS_X509_SecBitsCheck, storeCtx);
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t HITLS_X509_CheckCertExtNode(void *ctx, HITLS_X509_ExtEntry *extNode, int32_t depth)
{
    (void)ctx;
    (void)depth;
    if (extNode->cid != BSL_CID_CE_KEYUSAGE && extNode->cid != BSL_CID_CE_BASICCONSTRAINTS &&
        extNode->cid != BSL_CID_CE_EXTKEYUSAGE && extNode->cid != BSL_CID_CE_SUBJECTALTNAME &&
        extNode->cid != BSL_CID_CE_AUTHORITYKEYIDENTIFIER && extNode->cid != BSL_CID_CE_SUBJECTKEYIDENTIFIER &&
        extNode->critical == true) {
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

static int32_t HITLS_X509_CheckCertExt(void *ctx, HITLS_X509_Cert *cert, int32_t depth)
{
    if (cert->tbs.version != 2) { // no ext v1 cert, 2 : X509 v3
        return HITLS_PKI_SUCCESS;
    }
#ifdef HITLS_PKI_X509_VFY_CB
    HITLS_X509_StoreCtx *storeCtx = (HITLS_X509_StoreCtx *)ctx;
    storeCtx->curCert = cert;
    storeCtx->curDepth = depth;
#else
    (void)depth;
#endif
#ifdef HITLS_CRYPTO_MLDSA
if (cert->tbs.signAlgId.algId == BSL_CID_ML_DSA_44 ||
    cert->tbs.signAlgId.algId == BSL_CID_ML_DSA_65 ||
    cert->tbs.signAlgId.algId == BSL_CID_ML_DSA_87) {
    HITLS_X509_CertExt *tmpExt = (HITLS_X509_CertExt *)cert->tbs.ext.extData;
    if (tmpExt != NULL && (tmpExt->extFlags & HITLS_X509_EXT_FLAG_KUSAGE) != 0) {
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
    }
}
#endif
    return HITLS_X509_TrvList(cert->tbs.ext.extList, (HITLS_X509_TrvListCallBack)HITLS_X509_CheckCertExtNode, ctx);
}

int32_t HITLS_X509_VerifyParamAndExt(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *chain)
{
    int32_t ret = HITLS_X509_CheckVerifyParam(storeCtx, chain);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
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
    if (alg->sm2UserId.data == NULL) {
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

int32_t HITLS_X509_CheckCertCrl(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Cert *cert, HITLS_X509_Cert *parent,
    int32_t depth)
{
    int32_t ret = HITLS_X509_ERR_VFY_CRL_NOT_FOUND;
    HITLS_X509_Crl *crl = BSL_LIST_GET_FIRST(storeCtx->crl);
    HITLS_X509_CertExt *certExt = (HITLS_X509_CertExt *)parent->tbs.ext.extData;
    VFYCBK_FAIL_IF((((certExt->extFlags & HITLS_X509_EXT_FLAG_KUSAGE) != 0) &&
        ((certExt->keyUsage & HITLS_X509_EXT_KU_CRL_SIGN) == 0)),
        storeCtx, parent, depth + 1, HITLS_X509_ERR_VFY_KU_NO_CRLSIGN);

    while (crl != NULL) {
        if (HITLS_X509_CmpNameNode(crl->tbs.issuerName, parent->tbs.subjectName) != 0) {
            crl = BSL_LIST_GET_NEXT(storeCtx->crl);
            continue;
        }
        if (cert->tbs.version == HITLS_X509_VERSION_3 && crl->tbs.version == 1) {
            if (HITLS_X509_CheckAki(&parent->tbs.ext, &crl->tbs.crlExt, parent->tbs.issuerName,
                &parent->tbs.serialNum) != HITLS_PKI_SUCCESS) {
#ifdef HITLS_PKI_X509_VFY_CB
                if (VerifyCertCbk(storeCtx, cert, depth, HITLS_X509_ERR_VFY_AKI_SKI_NOT_MATCH) != HITLS_PKI_SUCCESS) {
                    crl = BSL_LIST_GET_NEXT(storeCtx->crl);
                    continue;
                }
#else
                crl = BSL_LIST_GET_NEXT(storeCtx->crl);
                continue;
#endif
            }
        }
        if (HITLS_X509_CheckCrlTime(storeCtx, crl, depth) != HITLS_PKI_SUCCESS) {
            crl = BSL_LIST_GET_NEXT(storeCtx->crl);
            continue;
        }
        ret = HITLS_X509_TrvList(crl->tbs.crlExt.extList,
            (HITLS_X509_TrvListCallBack)HITLS_X509_CheckCertExtNode, storeCtx);
        if (ret != HITLS_PKI_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }

#ifdef HITLS_CRYPTO_SM2
        ret = X509_StoreCheckSignature(&storeCtx->verifyParam.sm2UserId, parent->tbs.ealPubKey, crl->tbs.tbsRawData,
            crl->tbs.tbsRawDataLen, &(crl->signAlgId), &(crl->signature));
#else
        ret = X509_StoreCheckSignature(NULL, parent->tbs.ealPubKey, crl->tbs.tbsRawData,
            crl->tbs.tbsRawDataLen, &(crl->signAlgId), &(crl->signature));
#endif
        VFYCBK_FAIL_IF(ret != HITLS_PKI_SUCCESS, storeCtx, cert, depth, HITLS_X509_ERR_VFY_CRLSIGN_FAIL);

        ret = HITLS_X509_TrvList(crl->tbs.revokedCerts, (HITLS_X509_TrvListCallBack)HITLS_X509_CheckCertRevoked, cert);
        VFYCBK_FAIL_IF(ret != HITLS_PKI_SUCCESS, storeCtx, cert, depth, HITLS_X509_ERR_VFY_CERT_REVOKED);
        crl = BSL_LIST_GET_NEXT(storeCtx->crl);
    }
    VFYCBK_FAIL_IF(ret != HITLS_PKI_SUCCESS, storeCtx, cert, depth, HITLS_X509_ERR_VFY_CRL_NOT_FOUND);
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_X509_VerifyCrl(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *chain)
{
    // Only the self-signed certificate, and the CRL is not verified
    if (BSL_LIST_COUNT(chain) == 1) {
        return HITLS_PKI_SUCCESS;
    }

    if ((storeCtx->verifyParam.flags & HITLS_X509_VFY_FLAG_CRL_ALL) != 0) {
        // Device certificate check is included
        return HITLS_X509_TrvListWithParent(chain,
            (HITLS_X509_TrvListWithParentCallBack)HITLS_X509_CheckCertCrl, storeCtx);
    }

    if ((storeCtx->verifyParam.flags & HITLS_X509_VFY_FLAG_CRL_DEV) != 0) {
        HITLS_X509_Cert *cert = BSL_LIST_GET_FIRST(chain);
        HITLS_X509_Cert *parent = BSL_LIST_GET_NEXT(chain);
        return HITLS_X509_CheckCertCrl(storeCtx, cert, parent, 0);
    }

    return HITLS_PKI_SUCCESS;
}

static bool OidInList(BslList *oidList, BslCid target)
{
    if (oidList == NULL) {
        return false;
    }

    BSL_Buffer *buffer = (BSL_Buffer *)BSL_LIST_GET_FIRST(oidList);
    while (buffer != NULL) {
        if (buffer->data != NULL && buffer->dataLen > 0) {
            BslCid cid = BSL_OBJ_GetCidFromOidBuff(buffer->data, buffer->dataLen);
            if (cid == target) {
                return true;
            }
        }
        buffer = (BSL_Buffer *)BSL_LIST_GET_NEXT(oidList);
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

    // ExtendedKeyUsage check
    if (OidInList(ext->exKeyUsage.oidList, requiredEkuOids) == false) {
        return HITLS_X509_ERR_VFY_PURPOSE_UNMATCH;
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
    if (ext == NULL || (ext->extFlags & HITLS_X509_EXT_FLAG_EXKUSAGE) == 0 || purpose == 0 ||
        purpose == HITLS_X509_VFY_PURPOSE_ANY) {
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

int32_t X509_VerifyChainCert(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *chain)
{
    HITLS_X509_Cert *issue = BSL_LIST_GET_LAST(chain);
    HITLS_X509_Cert *cur = issue;
    int32_t ret;
    int32_t depth = BSL_LIST_COUNT(chain) - 1;
    if ((storeCtx->verifyParam.flags & HITLS_X509_VFY_FLAG_PARTIAL_CHAIN) != 0) {
        bool selfSigned = HITLS_X509_CheckIssued(issue, issue);
        if (!selfSigned && depth > 0) {
            cur = BSL_LIST_GET_PREV(chain);
        }
    }
    while (cur != NULL) {
        if ((storeCtx->verifyParam.flags & HITLS_X509_VFY_FLAG_TIME) != 0) {
            ret = HITLS_X509_CheckCertTime(storeCtx, cur, depth);
            if (ret != HITLS_PKI_SUCCESS) {
                return ret;
            }
        }
#ifdef HITLS_CRYPTO_SM2
        ret = X509_StoreCheckSignature(&storeCtx->verifyParam.sm2UserId, issue->tbs.ealPubKey, cur->tbs.tbsRawData,
                                       cur->tbs.tbsRawDataLen, &cur->signAlgId, &cur->signature);
#else
        ret = X509_StoreCheckSignature(NULL, issue->tbs.ealPubKey, cur->tbs.tbsRawData, cur->tbs.tbsRawDataLen,
                                       &cur->signAlgId, &cur->signature);
#endif
        VFYCBK_FAIL_IF(ret != HITLS_PKI_SUCCESS, storeCtx, cur, depth, HITLS_X509_ERR_VFY_CERT_SIGN_FAIL);

        // next
        issue = cur;
        cur = BSL_LIST_GET_PREV(chain);
        depth--;
    }

    return HITLS_PKI_SUCCESS;
}

static int32_t X509_GetVerifyCertChain(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *chain,
    HITLS_X509_List **comChain)
{
    HITLS_X509_Cert *cert = BSL_LIST_GET_FIRST(chain);
    if (cert == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    HITLS_X509_List *tmpChain = X509_NewCertChain(cert);
    if (tmpChain == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    HITLS_X509_Cert *root = NULL;
    int32_t ret = X509_BuildChain(true, storeCtx, chain, cert, tmpChain, &root);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_LIST_FREE(tmpChain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (root == NULL) {
        BSL_LIST_FREE(tmpChain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_ROOT_CERT_NOT_FOUND);
        return HITLS_X509_ERR_ROOT_CERT_NOT_FOUND;
    }
    // Add root to chain if it is not the end entity
    if (X509_CertCmp(cert, root) != 0) {
        ret = X509_AddCertToChain(tmpChain, root);
        if (ret != HITLS_PKI_SUCCESS) {
            BSL_LIST_FREE(tmpChain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
            return ret;
        }
    }
    *comChain = tmpChain;
    return HITLS_PKI_SUCCESS;
}

int32_t X509_CheckExt(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *chain)
{
    int32_t depth = BSL_LIST_COUNT(chain) - 1;
    int32_t ret;
    HITLS_X509_Cert *cur = BSL_LIST_GET_LAST(chain);

    while (cur != NULL) {
        HITLS_X509_CertExt *curExt = (HITLS_X509_CertExt *)cur->tbs.ext.extData;

        if (depth > 0) {
            /**
             * If the basic constraints extension is not present in a version 3 certificate,
             * or the extension is present but the cA boolean is not asserted,
             * then the certified public key MUST NOT be used to verify certificate signatures.
             */
            VFYCBK_FAIL_IF(((cur->tbs.version == HITLS_X509_VERSION_3) &&
                            ((curExt->extFlags & HITLS_X509_EXT_FLAG_BCONS) == 0 || !curExt->isCa)),
                           storeCtx, cur, depth, HITLS_X509_ERR_VFY_INVALID_CA);
            /**
             * Conforming CAs MUST include this extension in certificates that contain public keys
             * that are used to validate digital signatures on other public key certificates or CRLs.
             */
            VFYCBK_FAIL_IF(((curExt->extFlags & HITLS_X509_EXT_FLAG_KUSAGE) != 0) &&
                               ((curExt->keyUsage & HITLS_X509_EXT_KU_KEY_CERT_SIGN) == 0),
                           storeCtx, cur, depth, HITLS_X509_ERR_VFY_KU_NO_CERTSIGN);

            if ((curExt->extFlags & HITLS_X509_EXT_FLAG_BCONS) != 0 && curExt->isCa && curExt->maxPathLen >= 0) {
                VFYCBK_FAIL_IF(curExt->maxPathLen < depth - 1, storeCtx, cur, depth,
                               HITLS_X509_ERR_VFY_PATHLEN_EXCEEDED);
            }
        } else {
            ret = X509_VerifyUsageEE(storeCtx, cur);
            VFYCBK_FAIL_IF(ret != HITLS_PKI_SUCCESS, storeCtx, cur, depth, ret);
        }
        cur = BSL_LIST_GET_PREV(chain);
        depth--;
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
    ret = HITLS_X509_VerifyCrl(storeCtx, storeCtx->certChain);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    ret = X509_VerifyChainCert(storeCtx, storeCtx->certChain);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
#ifdef HITLS_PKI_X509_VFY_CB
    storeCtx->curCert = BSL_LIST_GET_FIRST(chain);
    storeCtx->curDepth = 0;
    ret = VerifyCertCbk(storeCtx, NULL, -1, HITLS_PKI_SUCCESS);
#endif
EXIT:
    BSL_LIST_FREE(storeCtx->certChain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    storeCtx->certChain = NULL;
    return ret;
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

#endif // HITLS_PKI_X509_VFY
