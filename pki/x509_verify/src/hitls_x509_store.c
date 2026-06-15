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
#include "bsl_err_internal.h"
#include "bsl_list.h"
#include "bsl_types.h"
#include "crypt_algid.h"
#include "crypt_eal_md.h"
#include "crypt_errno.h"
#include "hitls_cert_local.h"
#include "hitls_crl_local.h"
#include "hitls_pki_cert.h"
#include "hitls_pki_errno.h"
#include "hitls_x509_local.h"
#include "hitls_x509_store_local.h"

#define CRYPT_SHA1_DIGESTSIZE 20
#define MAX_PATH_LEN 4096

static int32_t X509_StoreCheckCert(HITLS_X509_Store *store, HITLS_X509_Cert *cert, HITLS_X509_Cert **findCert) 
{
    if (!HITLS_X509_CertIsCA(cert)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CERT_NOT_CA);
        return HITLS_X509_ERR_CERT_NOT_CA;
    }

    HITLS_X509_Cert *tmp = BSL_LIST_SearchDataConst(store->certs, cert, (BSL_LIST_PFUNC_CMP)HITLS_X509_CertCmp, NULL);
    if (tmp != NULL) {
        *findCert = tmp;
        return HITLS_X509_ERR_CERT_EXIST;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t X509_StoreCheckCRL(HITLS_X509_Store *store, HITLS_X509_Crl *crl)
{
    HITLS_X509_Crl *findCrl = BSL_LIST_SearchDataConst(store->crls, crl, (BSL_LIST_PFUNC_CMP)HITLS_X509_CrlCmp, NULL);
    if (findCrl != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CRL_EXIST);
        return HITLS_X509_ERR_CRL_EXIST;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t X509_SetCA(HITLS_X509_Store *store, HITLS_X509_Cert *cert, bool isCopy)
{
    HITLS_X509_Cert *findCert = NULL;
    int32_t ret = BSL_SAL_ThreadWriteLock(store->rwLock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = X509_StoreCheckCert(store, cert, &findCert);
    if (ret == HITLS_X509_ERR_CERT_EXIST) {
        (void)BSL_SAL_ThreadUnlock(store->rwLock);
        if (findCert == cert) {
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CERT_EXIST);
            return HITLS_X509_ERR_CERT_EXIST;
        }
        if (!isCopy) {
            /* The store already owns an equivalent certificate, so release the transient input object. */
            HITLS_X509_CertFree(cert);
        }
        return HITLS_PKI_SUCCESS;
    }
    if (ret != HITLS_PKI_SUCCESS) {
        (void)BSL_SAL_ThreadUnlock(store->rwLock);
        return ret;
    }
    if (isCopy) {
        int ref = 0;
        /* Deep-copy mode shares the caller certificate object with the store by taking one more reference. */
        ret = HITLS_X509_CertCtrl(cert, HITLS_X509_REF_UP, &ref, sizeof(int));
        if (ret != HITLS_PKI_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            (void)BSL_SAL_ThreadUnlock(store->rwLock);
            return ret;
        }
    }
    ret = BSL_LIST_AddElement(store->certs, cert, BSL_LIST_POS_BEGIN);
    (void)BSL_SAL_ThreadUnlock(store->rwLock);
    if (ret != BSL_SUCCESS) {
        if (isCopy) {
            /* Roll back the reference taken for the store when insertion fails. */
            HITLS_X509_CertFree(cert);
        }
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t X509_StoreSetCRL(HITLS_X509_Store *store, HITLS_X509_Crl *crl)
{
    int32_t ret = BSL_SAL_ThreadWriteLock(store->rwLock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = X509_StoreCheckCRL(store, crl);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    int ref = 0;
    /* The CRL list stores shared objects, so keep one reference on behalf of the store. */
    ret = HITLS_X509_CrlCtrl(crl, HITLS_X509_REF_UP, &ref, sizeof(int));
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    ret = BSL_LIST_AddElement(store->crls, crl, BSL_LIST_POS_BEGIN);
    if (ret != BSL_SUCCESS) {
        /* Drop the store reference when the list insertion fails. */
        HITLS_X509_CrlFree(crl);
        BSL_ERR_PUSH_ERROR(ret);
    }
EXIT:
    (void)BSL_SAL_ThreadUnlock(store->rwLock);
    return ret;
}

#ifdef HITLS_PKI_X509_VFY_LOCATION
static int32_t X509_StoreAddCAPath(HITLS_X509_Store *store, const char *caPath, uint32_t caPathLen)
{
    if (caPathLen == 0 || caPathLen > MAX_PATH_LEN) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    int32_t ret = BSL_SAL_ThreadWriteLock(store->rwLock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    for (BslListNode *pathNode = BSL_LIST_FirstNode(store->caPaths); pathNode != NULL;
        pathNode = BSL_LIST_GetNextNode(store->caPaths, pathNode)) {
        char *existPath = (char *)BSL_LIST_GetData(pathNode);
        if (strlen(existPath) == caPathLen && memcmp(existPath, caPath, caPathLen) == 0) {
            (void)BSL_SAL_ThreadUnlock(store->rwLock);
            return HITLS_PKI_SUCCESS;
        }
    }

    /* Allocate and copy the new CA path before publishing it into the shared store list. */
    char *pathCopy = BSL_SAL_Calloc(caPathLen + 1, sizeof(char));
    if (pathCopy == NULL) {
        (void)BSL_SAL_ThreadUnlock(store->rwLock);
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    (void)memcpy(pathCopy, caPath, caPathLen);
    /* Add the copied path to the shared path list after the duplicate check above. */
    ret = BSL_LIST_AddElement(store->caPaths, pathCopy, BSL_LIST_POS_END);
    (void)BSL_SAL_ThreadUnlock(store->rwLock);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_Free(pathCopy);
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t X509_StoreSetDefaultCAPath(HITLS_X509_Store *store)
{
    char defaultPath[MAX_PATH_LEN] = {0};
    int n = snprintf(defaultPath, sizeof(defaultPath), "%s/ssl/certs", OPENHITLSDIR);
    if (n < 0 || (size_t)n >= sizeof(defaultPath)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    return X509_StoreAddCAPath(store, defaultPath, (uint32_t)strlen(defaultPath));
}
#endif /* HITLS_PKI_X509_VFY_LOCATION */

static int32_t X509_StoreClearCRL(HITLS_X509_Store *store)
{
    int32_t ret = BSL_SAL_ThreadWriteLock(store->rwLock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (store->crls != NULL) {
        BSL_LIST_DeleteAll(store->crls, (BSL_LIST_PFUNC_FREE)HITLS_X509_CrlFree);
    }
    (void)BSL_SAL_ThreadUnlock(store->rwLock);
    return HITLS_PKI_SUCCESS;
}

HITLS_X509_Store *HITLS_X509_StoreNew(void)
{
    HITLS_X509_Store *store = BSL_SAL_Calloc(1, sizeof(HITLS_X509_Store));
    if (store == NULL) {
        return NULL;
    }
    store->certs = BSL_LIST_New(sizeof(HITLS_X509_Cert));
    if (store->certs == NULL) {
        BSL_SAL_Free(store);
        return NULL;
    }
    store->crls = BSL_LIST_New(sizeof(HITLS_X509_Crl));
    if (store->crls == NULL) {
        BSL_SAL_FREE(store->certs);
        BSL_SAL_Free(store);
        return NULL;
    }
#ifdef HITLS_PKI_X509_VFY_LOCATION
    store->caPaths = BSL_LIST_New(sizeof(char *));
    if (store->caPaths == NULL) {
        BSL_SAL_FREE(store->certs);
        BSL_SAL_FREE(store->crls);
        BSL_SAL_Free(store);
        return NULL;
    }
#endif
    /* The shared Store carries its own refcount and lock because multiple StoreCtx objects may point here. */
    if (BSL_SAL_ReferencesInit(&store->references) != BSL_SUCCESS) {
        goto EXIT;
    }
    if (BSL_SAL_ThreadLockNew(&store->rwLock) != BSL_SUCCESS) {
        goto EXIT;
    }
    return store;
EXIT:
    BSL_SAL_FREE(store->certs);
    BSL_SAL_FREE(store->crls);
#ifdef HITLS_PKI_X509_VFY_LOCATION
    BSL_SAL_FREE(store->caPaths);
#endif
    BSL_SAL_ReferencesFree(&store->references);
    BSL_SAL_Free(store);
    return NULL;
}

void HITLS_X509_StoreFree(HITLS_X509_Store *store)
{
    if (store == NULL) {
        return;
    }
    /* Only the last StoreCtx that drops the shared Store reference tears down the shared trust data. */
    int refCount = 0;
    (void)BSL_SAL_AtomicDownReferences(&store->references, &refCount);
    if (refCount > 0) {
        return;
    }
    /* Serialize final cleanup so readers/writers cannot race the shared list destruction. */
    bool isLocked = (BSL_SAL_ThreadWriteLock(store->rwLock) == BSL_SUCCESS);
    BSL_LIST_FREE(store->certs, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(store->crls, (BSL_LIST_PFUNC_FREE)HITLS_X509_CrlFree);
#ifdef HITLS_PKI_X509_VFY_LOCATION
    if (store->caPaths != NULL) {
        BSL_LIST_FREE(store->caPaths, (BSL_LIST_PFUNC_FREE)BSL_SAL_Free);
    }
#endif
    if (isLocked) {
        (void)BSL_SAL_ThreadUnlock(store->rwLock);
    }
    BSL_SAL_ThreadLockFree(store->rwLock);
    BSL_SAL_ReferencesFree(&store->references);
    BSL_SAL_Free(store);
}

int32_t HITLS_X509_StoreUpRef(HITLS_X509_Store *store)
{
    int ref = 0;
    int32_t ret = BSL_SAL_AtomicUpReferences(&store->references, &ref);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

#ifdef HITLS_PKI_X509_VFY_LOCATION
static int32_t X509_StoreGetSubjectHash(HITLS_X509_StoreCtx *storeCtx, const BSL_ASN1_Buffer *subjectDerData,
    uint32_t *hash)
{
    uint8_t digest[CRYPT_SHA1_DIGESTSIZE];
    uint32_t digestLen = CRYPT_SHA1_DIGESTSIZE;
    CRYPT_EAL_MdCtx *mdCtx = CRYPT_EAL_ProviderMdNewCtx(storeCtx->libCtx, CRYPT_MD_SHA1, storeCtx->attrName);
    if (mdCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND);
        return HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND;
    }

    *hash = 0;
    if (CRYPT_EAL_MdInit(mdCtx) == CRYPT_SUCCESS &&
        CRYPT_EAL_MdUpdate(mdCtx, subjectDerData->buff, subjectDerData->len) == CRYPT_SUCCESS &&
        CRYPT_EAL_MdFinal(mdCtx, digest, &digestLen) == CRYPT_SUCCESS && digestLen >= 4) {
        *hash = (uint32_t)digest[0] | ((uint32_t)digest[1] << 8) |
            ((uint32_t)digest[2] << 16) | ((uint32_t)digest[3] << 24);
    }
    CRYPT_EAL_MdFreeCtx(mdCtx);

    if (*hash == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND);
        return HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t CheckAndAddIssuerCert(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Cert *candidateCert,
    HITLS_X509_Cert *cert, HITLS_X509_Cert **issue)
{
    /* This helper always consumes candidateCert: it either frees the transient object or hands it to store->certs. */
    bool res = HITLS_X509_CheckIssued(candidateCert, cert);
    if (!res) {
        HITLS_X509_CertFree(candidateCert);
        return HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND;
    }

    int32_t ret = X509_SetCA(storeCtx->store, candidateCert, false);
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_X509_CertFree(candidateCert);
        return ret;
    }

    ret = BSL_SAL_ThreadReadLock(storeCtx->store->rwLock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    /*
     * X509_SetCA(..., false) may deduplicate by freeing the newly parsed candidate and
     * keeping the existing store object instead. Query the store again so *issue always
     * points to the stable object currently owned by store->certs.
     */
    for (BslListNode *node = BSL_LIST_FirstNode(storeCtx->store->certs); node != NULL;
        node = BSL_LIST_GetNextNode(storeCtx->store->certs, node)) {
        HITLS_X509_Cert *tmp = (HITLS_X509_Cert *)BSL_LIST_GetData(node);
        if (!HITLS_X509_CheckIssued(tmp, cert)) {
            continue;
        }
        *issue = tmp;
        (void)BSL_SAL_ThreadUnlock(storeCtx->store->rwLock);
        return HITLS_PKI_SUCCESS;
    }
    (void)BSL_SAL_ThreadUnlock(storeCtx->store->rwLock);
    return HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND;
}

static int32_t HITLS_X509_GetCertBySubjectDer(HITLS_X509_StoreCtx *storeCtx, BslList *caPathList,
    const BSL_ASN1_Buffer *subjectDerData, HITLS_X509_Cert *cert, HITLS_X509_Cert **issue)
{
    // Calculate hash from canon-encoded subject DN
    uint32_t hash = 0;
    int32_t ret = X509_StoreGetSubjectHash(storeCtx, subjectDerData, &hash);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    // Try to load certificate using hash-based file lookup from CA paths
    for (BslListNode *pathNode = BSL_LIST_FirstNode(caPathList); pathNode != NULL;
        pathNode = BSL_LIST_GetNextNode(caPathList, pathNode)) {
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
            if (CheckAndAddIssuerCert(storeCtx, candidateCert, cert, issue) == HITLS_PKI_SUCCESS) {
                return HITLS_PKI_SUCCESS;
            }
            seq++;
        }
    }
    BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND);
    return HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND;
}

static int32_t FindIssuerByDer(HITLS_X509_StoreCtx *storeCtx, BslList *caPathList, HITLS_X509_Cert *cert,
    HITLS_X509_Cert **issue)
{
    if (storeCtx == NULL) {
        return HITLS_X509_ERR_INVALID_PARAM;
    }
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

    ret = HITLS_X509_GetCertBySubjectDer(storeCtx, caPathList, &issuerDerData, cert, issue);
    BSL_SAL_Free(issuerDerData.buff);
    return ret;
}
#endif

/* The function returns success, CERT NOT FOUND, or propagated internal errors from lock/path lookup. */
int32_t HITLS_X509_StoreFindIssuerInTrust(HITLS_X509_Store *store, HITLS_X509_StoreCtx *storeCtx,
    HITLS_X509_Cert *cert, HITLS_X509_Cert **issue)
{
    if (store == NULL || storeCtx == NULL || cert == NULL || issue == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    // First try to find issuer in explicitly loaded store
    int32_t ret = BSL_SAL_ThreadReadLock(store->rwLock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND;
    for (BslListNode *node = BSL_LIST_FirstNode(store->certs); node != NULL;
        node = BSL_LIST_GetNextNode(store->certs, node)) {
        HITLS_X509_Cert *candidate = (HITLS_X509_Cert *)BSL_LIST_GetData(node);
        if (!HITLS_X509_CheckIssued(candidate, cert)) {
            continue;
        }
        *issue = candidate;
        ret = HITLS_PKI_SUCCESS;
        break;
    }
    (void)BSL_SAL_ThreadUnlock(store->rwLock);
    if (ret == HITLS_PKI_SUCCESS) {
        return HITLS_PKI_SUCCESS;
    }

#ifdef HITLS_PKI_X509_VFY_LOCATION
    // If we have CA paths set, try on-demand loading based on issuer DER-encoded DN
    BslList *caPathList = NULL;
    ret = BSL_SAL_ThreadReadLock(store->rwLock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (store->caPaths != NULL && BSL_LIST_COUNT(store->caPaths) > 0) {
        caPathList = BSL_LIST_New(sizeof(char *));
        if (caPathList == NULL) {
            (void)BSL_SAL_ThreadUnlock(store->rwLock);
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }
        for (BslListNode *pathNode = BSL_LIST_FirstNode(store->caPaths); pathNode != NULL;
            pathNode = BSL_LIST_GetNextNode(store->caPaths, pathNode)) {
            const char *srcPath = (const char *)BSL_LIST_GetData(pathNode);
            uint32_t pathLen = (uint32_t)strlen(srcPath);
            char *pathCopy = BSL_SAL_Calloc(pathLen + 1, sizeof(char));
            if (pathCopy == NULL) {
                (void)BSL_SAL_ThreadUnlock(store->rwLock);
                BSL_LIST_FREE(caPathList, (BSL_LIST_PFUNC_FREE)BSL_SAL_Free);
                BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
                return BSL_MALLOC_FAIL;
            }
            (void)memcpy(pathCopy, srcPath, pathLen);
            ret = BSL_LIST_AddElement(caPathList, pathCopy, BSL_LIST_POS_END);
            if (ret != BSL_SUCCESS) {
                (void)BSL_SAL_ThreadUnlock(store->rwLock);
                BSL_SAL_Free(pathCopy);
                BSL_LIST_FREE(caPathList, (BSL_LIST_PFUNC_FREE)BSL_SAL_Free);
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
        }
    }
    (void)BSL_SAL_ThreadUnlock(store->rwLock);
    if (caPathList != NULL) {
        ret = FindIssuerByDer(storeCtx, caPathList, cert, issue);
        BSL_LIST_FREE(caPathList, (BSL_LIST_PFUNC_FREE)BSL_SAL_Free);
        if (ret == HITLS_PKI_SUCCESS) {
            return HITLS_PKI_SUCCESS;
        }
    }
#endif
    return HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND;
}

int32_t HITLS_X509_StoreGetCrlList(HITLS_X509_Store *store, HITLS_X509_List **crlList)
{
    if (crlList == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    *crlList = BSL_LIST_New(sizeof(HITLS_X509_Crl));
    if (*crlList == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    int32_t ret = BSL_SAL_ThreadReadLock(store->rwLock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_LIST_FREE(*crlList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CrlFree);
        *crlList = NULL;
        return ret;
    }
    for (BslListNode *crlNode = BSL_LIST_FirstNode(store->crls); crlNode != NULL;
        crlNode = BSL_LIST_GetNextNode(store->crls, crlNode)) {
        HITLS_X509_Crl *crl = (HITLS_X509_Crl *)BSL_LIST_GetData(crlNode);
        int ref = 0;
        /* The returned list owns its entries, so each exported CRL needs its own retained reference. */
        ret = HITLS_X509_CrlCtrl(crl, HITLS_X509_REF_UP, &ref, sizeof(int));
        if (ret != HITLS_PKI_SUCCESS) {
            goto EXIT;
        }
        ret = BSL_LIST_AddElement(*crlList, crl, BSL_LIST_POS_END);
        if (ret != BSL_SUCCESS) {
            /* Undo the retained reference when we fail to append the CRL into the snapshot list. */
            HITLS_X509_CrlFree(crl);
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }
    }
    (void)BSL_SAL_ThreadUnlock(store->rwLock);
    return HITLS_PKI_SUCCESS;

EXIT:
    (void)BSL_SAL_ThreadUnlock(store->rwLock);
    BSL_LIST_FREE(*crlList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CrlFree);
    *crlList = NULL;
    return ret;
}

int32_t HITLS_X509_StoreCtrl(HITLS_X509_Store *store, int32_t cmd, void *val, uint32_t valLen)
{
    (void)valLen;
    if (store == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    switch (cmd) {
        case HITLS_X509_STORECTX_DEEP_COPY_SET_CA:
            return X509_SetCA(store, (HITLS_X509_Cert *)val, true);
        case HITLS_X509_STORECTX_SHALLOW_COPY_SET_CA:
            return X509_SetCA(store, (HITLS_X509_Cert *)val, false);
        case HITLS_X509_STORECTX_SET_CRL:
            return X509_StoreSetCRL(store, (HITLS_X509_Crl *)val);
#ifdef HITLS_PKI_X509_VFY_LOCATION
        case HITLS_X509_STORECTX_ADD_CA_PATH:
            return X509_StoreAddCAPath(store, (const char *)val, valLen);
        case HITLS_X509_STORECTX_SET_DEFAULT_PATH:
            return X509_StoreSetDefaultCAPath(store);
#endif
        case HITLS_X509_STORECTX_CLEAR_CRL:
            return X509_StoreClearCRL(store);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
            return HITLS_X509_ERR_INVALID_PARAM;
    }
}
#endif