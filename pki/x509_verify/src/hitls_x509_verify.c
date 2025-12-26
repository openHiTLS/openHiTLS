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
#ifdef HITLS_PKI_X509_VFY
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
#include "hitls_x509_verify.h"
#include "crypt_eal_md.h"
#include "crypt_algid.h"
#include "crypt_errno.h"

#define CRYPT_SHA1_DIGESTSIZE 20
#define MAX_PATH_LEN 4096

typedef int32_t (*HITLS_X509_TrvListCallBack)(void *ctx, void *node);
typedef int32_t (*HITLS_X509_TrvListWithParentCallBack)(void *ctx, void *node, void *parent);

// lists can be cert, ext, and so on.
static int32_t HITLS_X509_TrvList(BslList *list, HITLS_X509_TrvListCallBack callBack, void *ctx)
{
    int32_t ret = HITLS_PKI_SUCCESS;
    void *node = BSL_LIST_GET_FIRST(list);
    while (node != NULL) {
        ret = callBack(ctx, node);
        if (ret != BSL_SUCCESS) {
            return ret;
        }
        node = BSL_LIST_GET_NEXT(list);
    }
    return ret;
}

// lists can be cert, ext, and so on.
static int32_t HITLS_X509_TrvListWithParent(BslList *list, HITLS_X509_TrvListWithParentCallBack callBack, void *ctx)
{
    int32_t ret = HITLS_PKI_SUCCESS;
    void *node = BSL_LIST_GET_FIRST(list);
    void *parentNode = BSL_LIST_GET_NEXT(list);
    while (node != NULL && parentNode != NULL) {
        ret = callBack(ctx, node, parentNode);
        if (ret != BSL_SUCCESS) {
            return ret;
        }
        node = parentNode;
        parentNode = BSL_LIST_GET_NEXT(list);
    }
    return ret;
}

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
    BSL_LIST_FREE(storeCtx->store, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(storeCtx->crl, (BSL_LIST_PFUNC_FREE)HITLS_X509_CrlFree);
    
    // Free CA paths list
    if (storeCtx->caPaths != NULL) {
        BSL_LIST_FREE(storeCtx->caPaths, (BSL_LIST_PFUNC_FREE)BSL_SAL_Free);
    }
    
    BSL_SAL_ReferencesFree(&storeCtx->references);
    BSL_SAL_Free(storeCtx);
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
    return memcmp(crlOri->tbs.tbsRawData, crl->tbs.tbsRawData, crl->tbs.tbsRawDataLen);
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
    return memcmp(certOri->tbs.tbsRawData, cert->tbs.tbsRawData, cert->tbs.tbsRawDataLen);
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
    ctx->caPaths = BSL_LIST_New(sizeof(char *));
    if (ctx->caPaths == NULL) {
        BSL_SAL_FREE(ctx->store);
        BSL_SAL_FREE(ctx->crl);
        BSL_SAL_Free(ctx);
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }

    ctx->verifyParam.maxDepth = HITLS_X509_MAX_DEPTH;
    ctx->verifyParam.securityBits = 128; // 128: The default number of secure bits.
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
    if (depth < 0 || depth > HITLS_X509_MAX_DEPTH) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    storeCtx->verifyParam.maxDepth = depth;
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
    if (ret != HITLS_PKI_SUCCESS) {
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
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_X509_CrlFree(val);
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

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

int32_t HITLS_X509_StoreCtxCtrl(HITLS_X509_StoreCtx *storeCtx, int32_t cmd, void *val, uint32_t valLen)
{
    if (storeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    // Allow val to be NULL only for specific commands like CLEAR_CRL
    if (val == NULL && cmd != HITLS_X509_STORECTX_CLEAR_CRL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    switch (cmd) {
        case HITLS_X509_STORECTX_SET_PARAM_DEPTH:
            return X509_SetMaxDepth(storeCtx, val, valLen);
        case HITLS_X509_STORECTX_SET_PARAM_FLAGS:
            return X509_SetParamFlag(storeCtx, val, valLen);
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
        case HITLS_X509_STORECTX_CLEAR_CRL:
            return X509_ClearCRL(storeCtx);
        case HITLS_X509_STORECTX_REF_UP:
            return X509_RefUp(storeCtx, val, valLen);
#ifdef HITLS_CRYPTO_SM2
        case HITLS_X509_STORECTX_SET_VFY_SM2_USERID:
            return HITLS_X509_SetSm2UserId(&storeCtx->verifyParam.sm2UserId, val, valLen);
#endif
        case HITLS_X509_STORECTX_ADD_CA_PATH:
            return X509_AddCAPath(storeCtx, val, valLen);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
            return HITLS_X509_ERR_INVALID_PARAM;
    }
}

int32_t HITLS_X509_CheckTime(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_ValidTime *validTime)
{
    int64_t start = 0;
    int64_t end = 0;
    if ((storeCtx->verifyParam.flags & HITLS_X509_VFY_FLAG_TIME) == 0) {
        return HITLS_PKI_SUCCESS;
    }

    int32_t ret = BSL_SAL_DateToUtcTimeConvert(&validTime->start, &start);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (start > storeCtx->verifyParam.time) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_TIME_FUTURE);
        return HITLS_X509_ERR_TIME_FUTURE;
    }

    if ((validTime->flag & BSL_TIME_AFTER_SET) == 0) {
        return HITLS_PKI_SUCCESS;
    }

    ret = BSL_SAL_DateToUtcTimeConvert(&validTime->end, &end);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (end < storeCtx->verifyParam.time) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_TIME_EXPIRED);
        return HITLS_X509_ERR_TIME_EXPIRED;
    }
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
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_X509_CertFree(cert);
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t X509_GetIssueFromChain(HITLS_X509_List *certChain, HITLS_X509_Cert *cert, HITLS_X509_Cert **issue)
{
    int32_t ret;
    for (HITLS_X509_Cert *tmp = BSL_LIST_GET_FIRST(certChain); tmp != NULL; tmp = BSL_LIST_GET_NEXT(certChain)) {
        bool res = false;
        ret = HITLS_X509_CheckIssued(tmp, cert, &res);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
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
    bool res = false;
    int32_t ret = HITLS_X509_CheckIssued(candidateCert, cert, &res);
    if (ret == HITLS_PKI_SUCCESS && res) {
        *issue = candidateCert;
        *issueInTrust = true;
        ret = X509_SetCA(storeCtx, candidateCert, false);
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
#endif

int32_t X509_FindIssueCert(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *certChain, HITLS_X509_Cert *cert,
    HITLS_X509_Cert **issue, bool *issueInTrust)
{
    // First try to find issuer in explicitly loaded store
    HITLS_X509_List *store = storeCtx->store;
    int32_t ret = X509_GetIssueFromChain(store, cert, issue);
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
#endif
    // Then try the certificate chain if provided
    if (certChain != NULL) {
        ret = X509_GetIssueFromChain(certChain, cert, issue);
        if (ret == HITLS_PKI_SUCCESS) {
            *issueInTrust = false;
            return ret;
        }
    }
    BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND);
    return ret;
}

int32_t X509_BuildChain(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *certChain, HITLS_X509_Cert *cert,
    HITLS_X509_List *chain, HITLS_X509_Cert **root)
{
    HITLS_X509_Cert *cur = cert;
    int32_t ret;
    while (cur != NULL) {
        HITLS_X509_Cert *issue = NULL;
        bool isTrustCa = false;
        ret = X509_FindIssueCert(storeCtx, certChain, cur, &issue, &isTrustCa);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
        // depth
        if (BSL_LIST_COUNT(chain) + 1 > storeCtx->verifyParam.maxDepth) {
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CHAIN_DEPTH_UP_LIMIT);
            return HITLS_X509_ERR_CHAIN_DEPTH_UP_LIMIT;
        }
        bool selfSigned = false;
        ret = HITLS_X509_CheckIssued(issue, issue, &selfSigned);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
        if (selfSigned) {
            if (root != NULL && isTrustCa) {
                *root = issue;
            }
            break;
        }
        ret = X509_AddCertToChain(chain, issue);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
        cur = issue;
    }
    return HITLS_PKI_SUCCESS;
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
    int32_t ret = X509_BuildChain(storeCtx, NULL, cert, tmpChain, &root);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_LIST_FREE(tmpChain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        return ret;
    }
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
    bool selfSigned = false;
    int32_t ret = HITLS_X509_CheckIssued(cert, cert, &selfSigned);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_LIST_FREE(tmpChain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        return ret;
    }
    if (selfSigned) {
        *chain = tmpChain;
        return HITLS_PKI_SUCCESS;
    }
    (void)X509_BuildChain(storeCtx, NULL, cert, tmpChain, NULL);
    *chain = tmpChain;

    return HITLS_PKI_SUCCESS;
}

static int32_t HITLS_X509_SecBitsCheck(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Cert *cert)
{
    uint32_t secBits = CRYPT_EAL_PkeyGetSecurityBits(cert->tbs.ealPubKey);
    if (secBits < storeCtx->verifyParam.securityBits) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_VFY_CHECK_SECBITS);
        return HITLS_X509_ERR_VFY_CHECK_SECBITS;
    }
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_X509_CheckVerifyParam(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *chain)
{
    if ((storeCtx->verifyParam.flags & HITLS_X509_VFY_FLAG_SECBITS) != 0) {
        return HITLS_X509_TrvList(chain, (HITLS_X509_TrvListCallBack)HITLS_X509_SecBitsCheck, storeCtx);
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t HITLS_X509_CheckCertExtNode(void *ctx, HITLS_X509_ExtEntry *extNode)
{
    (void)ctx;
    if (extNode->cid != BSL_CID_CE_KEYUSAGE && extNode->cid != BSL_CID_CE_BASICCONSTRAINTS &&
        extNode->cid != BSL_CID_CE_EXTKEYUSAGE && extNode->cid != BSL_CID_CE_SUBJECTALTNAME &&
        extNode->cid != BSL_CID_CE_AUTHORITYKEYIDENTIFIER && extNode->cid != BSL_CID_CE_SUBJECTKEYIDENTIFIER &&
        extNode->critical == true) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_PROCESS_CRITICALEXT);
        return HITLS_X509_ERR_PROCESS_CRITICALEXT; // not process critical ext
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t HITLS_X509_CheckCertExt(void *ctx, HITLS_X509_Cert *cert)
{
    (void) ctx;
    if (cert->tbs.version != 2) { // no ext v1 cert
        return HITLS_PKI_SUCCESS;
    }
    return HITLS_X509_TrvList(cert->tbs.ext.extList,
        (HITLS_X509_TrvListCallBack)HITLS_X509_CheckCertExtNode, NULL);
}

int32_t HITLS_X509_VerifyParamAndExt(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *chain)
{
    int32_t ret = HITLS_X509_CheckVerifyParam(storeCtx, chain);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    return HITLS_X509_TrvList(chain, (HITLS_X509_TrvListCallBack)HITLS_X509_CheckCertExt, NULL);
}

int32_t HITLS_X509_CheckCertRevoked(HITLS_X509_Cert *cert, HITLS_X509_CrlEntry *crlEntry)
{
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

int32_t HITLS_X509_CheckCertCrl(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Cert *cert, HITLS_X509_Cert *parent)
{
    int32_t ret = HITLS_X509_ERR_CRL_NOT_FOUND;
    HITLS_X509_Crl *crl = BSL_LIST_GET_FIRST(storeCtx->crl);
    HITLS_X509_CertExt *certExt = (HITLS_X509_CertExt *)parent->tbs.ext.extData;
    if ((certExt->extFlags & HITLS_X509_EXT_FLAG_KUSAGE) != 0) {
        if ((certExt->keyUsage & HITLS_X509_EXT_KU_CRL_SIGN) == 0) {
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_VFY_KU_NO_CRLSIGN);
            return HITLS_X509_ERR_VFY_KU_NO_CRLSIGN;
        }
    }
    while (crl != NULL) {
        if (HITLS_X509_CmpNameNode(crl->tbs.issuerName, parent->tbs.subjectName) != 0) {
            crl = BSL_LIST_GET_NEXT(storeCtx->crl);
            continue;
        }
        if (cert->tbs.version == HITLS_X509_VERSION_3 && crl->tbs.version == 1) {
            if (HITLS_X509_CheckAki(&parent->tbs.ext, &crl->tbs.crlExt, parent->tbs.issuerName,
                &parent->tbs.serialNum) != HITLS_PKI_SUCCESS) {
                crl = BSL_LIST_GET_NEXT(storeCtx->crl);
                continue;
            }
        }
        if (HITLS_X509_CheckTime(storeCtx, &(crl->tbs.validTime)) != HITLS_PKI_SUCCESS) {
            crl = BSL_LIST_GET_NEXT(storeCtx->crl);
            continue;
        }
        ret = HITLS_X509_TrvList(crl->tbs.crlExt.extList,
            (HITLS_X509_TrvListCallBack)HITLS_X509_CheckCertExtNode, NULL);
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
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
        ret = HITLS_X509_TrvList(crl->tbs.revokedCerts, (HITLS_X509_TrvListCallBack)HITLS_X509_CheckCertRevoked, cert);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
        crl = BSL_LIST_GET_NEXT(storeCtx->crl);
    }
    return ret;
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
        return HITLS_X509_CheckCertCrl(storeCtx, cert, parent);
    }

    return HITLS_PKI_SUCCESS;
}

int32_t X509_VerifyChainCert(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *chain)
{
    HITLS_X509_Cert *issue = BSL_LIST_GET_LAST(chain);
    HITLS_X509_Cert *cur = issue;
    int32_t ret;
    while (cur != NULL) {
        if ((storeCtx->verifyParam.flags & HITLS_X509_VFY_FLAG_TIME) != 0) {
            ret = HITLS_X509_CheckTime(storeCtx, &cur->tbs.validTime);
            if (ret != HITLS_PKI_SUCCESS) {
                return ret;
            }
        }
#ifdef HITLS_CRYPTO_SM2
        ret = X509_StoreCheckSignature(&storeCtx->verifyParam.sm2UserId, issue->tbs.ealPubKey, cur->tbs.tbsRawData,
            cur->tbs.tbsRawDataLen, &cur->signAlgId, &cur->signature);
#else
        ret = X509_StoreCheckSignature(NULL, issue->tbs.ealPubKey, cur->tbs.tbsRawData,
            cur->tbs.tbsRawDataLen, &cur->signAlgId, &cur->signature);
#endif
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
        issue = cur;
        cur = BSL_LIST_GET_PREV(chain);
    };
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
    int32_t ret = X509_BuildChain(storeCtx, chain, cert, tmpChain, &root);
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
    HITLS_X509_List *tmpChain = NULL;
    int32_t ret = X509_GetVerifyCertChain(storeCtx, chain, &tmpChain);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = HITLS_X509_VerifyParamAndExt(storeCtx, tmpChain);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_LIST_FREE(tmpChain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        return ret;
    }
    ret = HITLS_X509_VerifyCrl(storeCtx, tmpChain);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_LIST_FREE(tmpChain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        return ret;
    }
    ret = X509_VerifyChainCert(storeCtx, tmpChain);
    BSL_LIST_FREE(tmpChain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    return ret;
}

int32_t HITLS_X509_CertVerifyByPubKey(HITLS_X509_Cert *cert, CRYPT_EAL_PkeyCtx *pubKey)
{
    if (cert == NULL || pubKey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
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
    return storeCtx;
}

#endif // HITLS_PKI_X509_VFY
