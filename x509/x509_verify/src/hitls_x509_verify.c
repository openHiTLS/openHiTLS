/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_x509.h"
#include "hitls_verify_local.h"
#include "crypt_eal_pkey.h"
#include "hitls_x509_errno.h"
#include "hitls_cert_local.h"
#include "hitls_crl_local.h"
#include "bsl_err_internal.h"
#include "hitls_x509_local.h"
#include "bsl_obj_internal.h"
#include "crypt_errno.h"
#include "bsl_list.h"
#include <string.h>

typedef int32_t (*HITLS_X509_TrvListCallBack)(void *ctx, void *node);
typedef int32_t (*HITLS_X509_TrvListWithParentCallBack)(void *ctx, void *node, void *parent);

// lists can be cert, ext, and so on.
static int32_t HITLS_X509_TrvList(BslList *list, HITLS_X509_TrvListCallBack callBack, void *ctx)
{
    int32_t ret = HITLS_X509_SUCCESS;
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
    int32_t ret = HITLS_X509_SUCCESS;
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

static int32_t HITLS_X509_SecBitsCheck(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Cert *cert)
{
    uint32_t secBits = CRYPT_EAL_PkeyGetSecurityBits(cert->tbs.ealPubKey);
    if (secBits < storeCtx->verifyParam.securityBits) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CHECK_SECBITS);
        return HITLS_X509_ERR_CHECK_SECBITS;
    }
    return HITLS_X509_SUCCESS;
}

int32_t HITLS_X509_CheckVerifyParam(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *chain)
{
    if (storeCtx->verifyParam.flags & HITLS_X509_VFY_FLAG_SECBITS) {
        return HITLS_X509_TrvList(chain, (HITLS_X509_TrvListCallBack)HITLS_X509_SecBitsCheck, storeCtx);
    }
    return HITLS_X509_SUCCESS;
}

static int32_t HITLS_X509_CheckCertExtNode(void *ctx, HITLS_X509_ExtEntry *extNode)
{
    (void) ctx;
    if (extNode->critical == true) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_PROCESS_CRITICALEXT);
        return HITLS_X509_ERR_PROCESS_CRITICALEXT; // not process critical ext
    }
    return HITLS_X509_SUCCESS;
}

static int32_t HITLS_X509_CheckCertExt(void *ctx, HITLS_X509_Cert *cert)
{
    (void) ctx;
    if (cert->tbs.version != 2) { // no ext v1 cert
        return HITLS_X509_SUCCESS;
    }
    return HITLS_X509_TrvList(cert->tbs.ext.list,
        (HITLS_X509_TrvListCallBack)HITLS_X509_CheckCertExtNode, NULL);
}

int32_t HITLS_X509_VerifyParamAndExt(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *chain)
{
    int32_t ret = HITLS_X509_CheckVerifyParam(storeCtx, chain);
    if (ret != HITLS_X509_SUCCESS) {
        return ret;
    }
    ret = HITLS_X509_TrvList(chain, (HITLS_X509_TrvListCallBack)HITLS_X509_CheckCertExt, NULL);
    if (ret != HITLS_X509_SUCCESS) {
        return ret;
    }
    return ret;
}

static int32_t X509_NodeNameCompare(BSL_ASN1_Buffer *src, BSL_ASN1_Buffer *dest)
{
    if (src->tag != dest->tag) {
        return 1;
    }
    if (src->len != dest->len) {
        return 1;
    }
    return memcmp(src->buff, dest->buff, dest->len);
}

static int32_t X509_NodeNameCaseCompare(BSL_ASN1_Buffer *src, BSL_ASN1_Buffer *dest)
{
    if ((src->tag == BSL_ASN1_TAG_UTF8STRING || src->tag == BSL_ASN1_TAG_PRINTABLESTRING) &&
        (dest->tag == BSL_ASN1_TAG_UTF8STRING || dest->tag == BSL_ASN1_TAG_PRINTABLESTRING)) {
        if (src->len != dest->len) {
            return 1;
        }
        for (size_t i = 0; i < src->len; i++) {
            if (src->buff[i] == dest->buff[i]) {
                continue;
            }
            if ('a' <= src->buff[i] && src->buff[i] <= 'z' && src->buff[i] - dest->buff[i] == 32) {
                continue;
            }
            if ('a' <= dest->buff[i] && dest->buff[i] <= 'z' && dest->buff[i] - src->buff[i] == 32) {
                continue;
            }
            return 1;
        }
        return 0;
    }
    return 1;
}

static int32_t X509_NodeNameValueCompare(BSL_ASN1_Buffer *src, BSL_ASN1_Buffer *dest)
{
    // quick comparison
    if (X509_NodeNameCompare(src, dest) == 0) {
        return 0;
    }
    return X509_NodeNameCaseCompare(src, dest);
}

int32_t HITLS_X509_CmpNameNode(BSL_ASN1_List *src, BSL_ASN1_List *dest)
{
    HITLS_X509_NameNode *nodeSrc = BSL_LIST_GET_FIRST(src);
    HITLS_X509_NameNode *nodeDest = BSL_LIST_GET_FIRST(dest);
    while (nodeSrc != NULL || nodeDest != NULL) {
        if (nodeSrc == NULL || nodeDest == NULL) {
            return 1;
        }
        if (X509_NodeNameCompare(&nodeSrc->nameType, &nodeDest->nameType) != 0) {
            return 1;
        }
        if (nodeSrc->layer != nodeDest->layer) {
            return 1;
        }
        if (X509_NodeNameValueCompare(&nodeSrc->nameValue, &nodeDest->nameValue) != 0) {
            return 1;
        }
        nodeSrc = BSL_LIST_GET_NEXT(src);
        nodeDest = BSL_LIST_GET_NEXT(dest);
    }
    return 0;
}

static uint32_t X509_GetHashId(HITLS_X509_Asn1AlgId *alg)
{
    uint32_t hashId = BSL_OBJ_GetHashIdFromSignId(alg->algId);
    if (hashId != BSL_CID_UNKNOWN) {
        return hashId;
    }
    if (alg->algId == BSL_CID_RSASSAPSS) {
        return alg->rsaPssParam.hash;
    }
    return BSL_CID_UNKNOWN;
}

int32_t HITLS_X509_CheckSignature(const void *pubKey, uint8_t *rawData, uint32_t rawDataLen,
    HITLS_X509_Asn1AlgId *alg, BSL_ASN1_BitString *signature)
{
    uint32_t hashId = X509_GetHashId(alg);
    if (hashId == BSL_CID_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_GET_HASHID);
        return HITLS_X509_ERR_GET_HASHID;
    }

    int32_t ret = CRYPT_EAL_PkeyVerify(pubKey, hashId, rawData, rawDataLen, signature->buff, signature->len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return ret;
}

int32_t HITLS_X509_CheckTime(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_ValidTime *validTime)
{
    int64_t start = 0;
    int64_t end = 0;
    if ((storeCtx->verifyParam.flags & HITLS_X509_VFY_FLAG_TIME) == 0) {
        return HITLS_X509_SUCCESS;
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

    if (validTime->isOptional == true) {
        return HITLS_X509_SUCCESS;
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
    return HITLS_X509_SUCCESS;
}

int32_t HITLS_X509_CheckCertRevoked(HITLS_X509_Cert *cert, HITLS_X509_CrlEntry *crlEntry)
{
    if (cert->tbs.serialNum.tag == crlEntry->serialNumber.tag &&
        cert->tbs.serialNum.len == crlEntry->serialNumber.len &&
        memcmp(cert->tbs.serialNum.buff, crlEntry->serialNumber.buff, crlEntry->serialNumber.len) == 0) {
        return HITLS_X509_ERR_CERT_REVOKED;
    }
    return HITLS_X509_SUCCESS;
}

int32_t HITLS_X509_CheckCertCrl(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Cert *cert, HITLS_X509_Cert *parent)
{
    int32_t ret = HITLS_X509_SUCCESS;
    HITLS_X509_Crl *crl = BSL_LIST_GET_FIRST(storeCtx->crl);
    while (crl != NULL) {
        if (HITLS_X509_CmpNameNode(crl->tbs.issuerName, parent->tbs.subjectName) != 0) {
            crl = BSL_LIST_GET_NEXT(storeCtx->crl);
            continue;
        }
        ret = HITLS_X509_TrvList(crl->tbs.crlExt.extList,
            (HITLS_X509_TrvListCallBack)HITLS_X509_CheckCertExtNode, NULL);
        if (ret != HITLS_X509_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        
        if (parent->tbs.ext.extFlags & HITLS_X509_CERT_EXT_FLAG_KUSAGE) {
            if (cert->tbs.ext.keyUsage & HITLS_X509_EXT_KU_CRL_SIGN) {
                return HITLS_X509_ERR_NO_EXTCRLSIGN;
            }
        }
        ret = HITLS_X509_CheckTime(storeCtx, &(crl->tbs.validTime));
        if (ret != HITLS_X509_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }

        ret = HITLS_X509_CheckSignature(parent->tbs.ealPubKey, crl->tbs.tbsRawData, crl->tbs.tbsRawDataLen,
            &(crl->signAlgId), &(crl->signature));
        if (ret != HITLS_X509_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        ret = HITLS_X509_TrvList(crl->tbs.revokedCerts,
            (HITLS_X509_TrvListCallBack)HITLS_X509_CheckCertRevoked, cert);
        if (ret != HITLS_X509_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
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
        return HITLS_X509_SUCCESS;
    }
    
    if (storeCtx->verifyParam.flags & HITLS_X509_VFY_FLAG_CRL_ALL) {
        // Device certificate check is included
        return HITLS_X509_TrvListWithParent(chain,
            (HITLS_X509_TrvListWithParentCallBack)HITLS_X509_CheckCertCrl, storeCtx);
    }
    
    if (storeCtx->verifyParam.flags & HITLS_X509_VFY_FLAG_CRL_DEV) {
        HITLS_X509_Cert *cert = BSL_LIST_GET_FIRST(chain);
        HITLS_X509_Cert *parent = BSL_LIST_GET_NEXT(chain);
        return HITLS_X509_CheckCertCrl(storeCtx, cert, parent);
    }
    
    return HITLS_X509_SUCCESS;
}
