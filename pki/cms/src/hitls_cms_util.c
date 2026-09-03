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
#ifdef HITLS_PKI_CMS
#include <string.h>
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "bsl_list.h"
#include "bsl_asn1_internal.h"
#include "bsl_obj_internal.h"
#include "crypt_eal_codecs.h"
#include "crypt_eal_md.h"
#include "hitls_pki_errno.h"
#include "hitls_cms_local.h"
#include "hitls_pki_cms.h"
#include "hitls_pki_crl.h"
#include "hitls_pki_x509.h"
#include "hitls_x509_verify.h"
#include "hitls_cms_util.h"
#ifdef HITLS_PKI_CMS_SIGNEDDATA

void CMS_AlgIdFree(void *algId)
{
    if (algId == NULL) {
        return;
    }
    CMS_AlgId *alg = (CMS_AlgId *)algId;
    CRYPT_EAL_MdFreeCtx(alg->mdCtx);
    BSL_SAL_FREE(alg->param.buff);
    BSL_SAL_Free(alg);
}

void HITLS_CMS_SignerInfoFree(void *signerInfo)
{
    if (signerInfo == NULL) {
        return;
    }
    CMS_SignerInfo *si = (CMS_SignerInfo *)signerInfo;
    BSL_SAL_FREE(si->digestAlg.param.buff);
    HITLS_X509_AttrsFree(si->signedAttrs, NULL);
    HITLS_X509_AttrsFree(si->unsignedAttrs, NULL);
    if ((si->flag & HITLS_CMS_FLAG_PARSE) == 0) {
        BSL_LIST_FREE(si->issuerName, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeNameNode);
        BSL_SAL_FREE(si->subjectKeyId.kid.data);
        BSL_SAL_FREE(si->sigValue.data);
        BSL_SAL_FREE(si->signData.data);
        BSL_SAL_FREE(si->certSerialNum.data);
    } else {
        BSL_LIST_FREE(si->issuerName, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeParsedNameNode);
    }
    BSL_SAL_Free(si);
}

int32_t CMS_DecodeAttr(HITLS_X509_Attrs *attrs, BslCid attrCid, CMS_AttrDecoder attrDecode, void *out)
{
    for (BslListNode *attrNode = BSL_LIST_FirstNode(attrs->list); attrNode != NULL;
        attrNode = BSL_LIST_GetNextNode(attrs->list, attrNode)) {
        HITLS_X509_AttrEntry *node = (HITLS_X509_AttrEntry *)BSL_LIST_GetData(attrNode);
        if (node->cid == attrCid) {
            return attrDecode(node, out);
        }
    }
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_SIGNEDDATA_NO_FIND_SIGNERINFO_ATTR);
    return HITLS_CMS_ERR_SIGNEDDATA_NO_FIND_SIGNERINFO_ATTR;
}

static void CMS_SignedDataFree(CMS_SignedData *sd)
{
    if (sd == NULL) {
        return;
    }
    BSL_LIST_FREE(sd->digestAlg, (BSL_LIST_PFUNC_FREE)CMS_AlgIdFree);
    if ((sd->flag & HITLS_CMS_FLAG_PARSE) == 0) {
        BSL_SAL_ClearFree(sd->encapCont.content.data, sd->encapCont.content.dataLen);
    }
    BSL_SAL_FREE(sd->initData);
    BSL_LIST_FREE(sd->certs, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(sd->crls, (BSL_LIST_PFUNC_FREE)HITLS_X509_CrlFree);
    BSL_LIST_FREE(sd->signerInfos, (BSL_LIST_PFUNC_FREE)HITLS_CMS_SignerInfoFree);
    BSL_SAL_Free(sd);
}

void HITLS_CMS_Free(HITLS_CMS *cms)
{
    if (cms == NULL) {
        return;
    }
    switch (cms->dataType) {
        case BSL_CID_PKCS7_SIGNEDDATA:
            CMS_SignedDataFree(cms->ctx.signedData);
            break;
        default:
            break;
    }
    BSL_SAL_Free(cms);
    return;
}

CMS_SignerInfo *CMS_SignerInfoNew(uint32_t flag)
{
    CMS_SignerInfo *si = (CMS_SignerInfo *)BSL_SAL_Calloc(1, sizeof(CMS_SignerInfo));
    if (si == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }
    si->issuerName = BSL_LIST_New(sizeof(HITLS_X509_NameNode));
    if (si->issuerName == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        HITLS_CMS_SignerInfoFree(si);
        return NULL;
    }
    if ((flag & HITLS_CMS_FLAG_NO_SIGNEDATTR) == 0) {
        si->signedAttrs = HITLS_X509_AttrsNew();
        if (si->signedAttrs == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            HITLS_CMS_SignerInfoFree(si);
            return NULL;
        }
    }
    si->unsignedAttrs = HITLS_X509_AttrsNew();
    if (si->unsignedAttrs == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        HITLS_CMS_SignerInfoFree(si);
        return NULL;
    }
    si->flag |= flag;
    return si;
}

static CMS_SignedData *CMS_ProviderSignedDataNew(HITLS_PKI_LibCtx *libCtx, const char *attrName)
{
    CMS_SignedData *sd = (CMS_SignedData *)BSL_SAL_Calloc(1, sizeof(CMS_SignedData));
    if (sd == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }

    sd->digestAlg = BSL_LIST_New((int32_t)sizeof(CMS_AlgId *));
    if (sd->digestAlg == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        BSL_SAL_Free(sd);
        return NULL;
    }

    sd->signerInfos = BSL_LIST_New((int32_t)sizeof(CMS_SignerInfo *));
    if (sd->signerInfos == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        CMS_SignedDataFree(sd);
        return NULL;
    }
    sd->libCtx = libCtx;
    sd->attrName = attrName;
    sd->detached = true; // Default is detached
    return sd;
}

HITLS_CMS *HITLS_CMS_ProviderNew(HITLS_PKI_LibCtx *libCtx, const char *attrName, int32_t dataType)
{
    HITLS_CMS *cms = (HITLS_CMS *)BSL_SAL_Calloc(1, sizeof(HITLS_CMS));
    if (cms == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }
    cms->dataType = dataType;
    switch (dataType) {
        case BSL_CID_PKCS7_SIGNEDDATA: {
            CMS_SignedData *sd = CMS_ProviderSignedDataNew(libCtx, attrName);
            if (sd == NULL) {
                BSL_SAL_Free(cms);
                return NULL;
            }
            cms->ctx.signedData = sd;
            break;
        }
        default:
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_UNSUPPORTED_TYPE);
            BSL_SAL_Free(cms);
            return NULL;
    }
    return cms;
}

typedef int32_t (*HITLS_CMS_ItemCtrlFunc)(void *item, int32_t cmd, void *val, uint32_t valLen);

static int32_t SignedDataAddItem(HITLS_X509_List **ppList, void *item,
    BSL_LIST_PFUNC_CMP pfnCmp, HITLS_CMS_ItemCtrlFunc pfnCtrl, BSL_LIST_PFUNC_FREE pfnFree)
{
    if (item == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (*ppList == NULL) {
        *ppList = BSL_LIST_New(sizeof(void *));
        if (*ppList == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }
    }

    // Check if item already exists
    if (BSL_LIST_SearchDataConst(*ppList, item, pfnCmp, NULL) != NULL) {
        return HITLS_PKI_SUCCESS;
    }

    int ref;
    int32_t ret = pfnCtrl(item, HITLS_X509_REF_UP, &ref, sizeof(int));
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BSL_LIST_AddElement(*ppList, item, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        pfnFree(item);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    return HITLS_PKI_SUCCESS;
}

// Add certificate to SignedData
int32_t HITLS_CMS_AddCert(HITLS_X509_List **list, HITLS_X509_Cert *cert)
{
    return SignedDataAddItem(list, cert,
        (BSL_LIST_PFUNC_CMP)HITLS_X509_CertCmp,
        (HITLS_CMS_ItemCtrlFunc)HITLS_X509_CertCtrl,
        (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}

// Add CRL to SignedData
int32_t HITLS_CMS_AddCrl(HITLS_X509_List **list, HITLS_X509_Crl *crl)
{
    return SignedDataAddItem(list, crl,
        (BSL_LIST_PFUNC_CMP)HITLS_X509_CrlCmp,
        (HITLS_CMS_ItemCtrlFunc)HITLS_X509_CrlCtrl,
        (BSL_LIST_PFUNC_FREE)HITLS_X509_CrlFree);
}

// Compare CMS_AlgId with a uint32_t algorithm ID
static int32_t CmpAlgId(const CMS_AlgId *algId, const int32_t *mdId)
{
    return (algId->id == *mdId) ? 0 : 1;
}

static BSL_ASN1_TemplateItem g_algIdTempl[] = {
    {BSL_ASN1_TAG_OBJECT_ID, 0, 0},
    {BSL_ASN1_TAG_ANY, BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 0},
};

typedef enum {
    HITLS_CMS_ALGORITHM_IDENTIFIER_ALG_IDX,
    HITLS_CMS_ALGORITHM_IDENTIFIER_PARAMS_IDX,
    HITLS_CMS_ALGORITHM_IDENTIFIER_MAX_IDX,
} HITLS_CMS_ALGORITHM_IDENTIFIER_IDX;

int32_t CMS_ParseAlgIdInfo(BSL_ASN1_Buffer *asn, bool copyParam, CMS_AlgId *algId)
{
    BSL_ASN1_Buffer asn1[HITLS_CMS_ALGORITHM_IDENTIFIER_MAX_IDX] = {0};
    uint8_t *temp = asn->buff;
    uint32_t tempLen = asn->len;
    int32_t ret = BSL_ASN1_DecodeItem(&temp, &tempLen,
        &asn1[HITLS_CMS_ALGORITHM_IDENTIFIER_ALG_IDX]);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (asn1[HITLS_CMS_ALGORITHM_IDENTIFIER_ALG_IDX].tag != BSL_ASN1_TAG_OBJECT_ID) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
        return HITLS_CMS_ERR_INVALID_DATA;
    }
    if (tempLen != 0) {
        ret = BSL_ASN1_DecodeItem(&temp, &tempLen,
            &asn1[HITLS_CMS_ALGORITHM_IDENTIFIER_PARAMS_IDX]);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        if (tempLen != 0) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
            return HITLS_CMS_ERR_INVALID_DATA;
        }
    }
    algId->id = BSL_OBJ_GetCidFromOidBuff(asn1[HITLS_CMS_ALGORITHM_IDENTIFIER_ALG_IDX].buff,
        asn1[HITLS_CMS_ALGORITHM_IDENTIFIER_ALG_IDX].len);
    if (algId->id == BSL_CID_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_PARSE_TYPE);
        return HITLS_CMS_ERR_PARSE_TYPE;
    }

    algId->param.tag = asn1[HITLS_CMS_ALGORITHM_IDENTIFIER_PARAMS_IDX].tag;
    algId->param.len = asn1[HITLS_CMS_ALGORITHM_IDENTIFIER_PARAMS_IDX].len;
    if (algId->param.tag == 0 || algId->param.len == 0) {
        return HITLS_PKI_SUCCESS;
    }
    if (!copyParam) {
        algId->param.buff = asn1[HITLS_CMS_ALGORITHM_IDENTIFIER_PARAMS_IDX].buff;
        return HITLS_PKI_SUCCESS;
    }
    algId->param.buff = BSL_SAL_Dump(asn1[HITLS_CMS_ALGORITHM_IDENTIFIER_PARAMS_IDX].buff,
        asn1[HITLS_CMS_ALGORITHM_IDENTIFIER_PARAMS_IDX].len);
    if (algId->param.buff == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
        return BSL_DUMP_FAIL;
    }
    return HITLS_PKI_SUCCESS;
}

int32_t CMS_EncodeAlgIdInfo(const CMS_AlgId *alg, BSL_ASN1_Buffer *asn)
{
    BslOidString *oidStr = BSL_OBJ_GetOID((BslCid)alg->id);
    if (oidStr == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
        return HITLS_CMS_ERR_INVALID_ALGO;
    }
    BSL_ASN1_Buffer items[HITLS_CMS_ALGORITHM_IDENTIFIER_MAX_IDX] = {
        {BSL_ASN1_TAG_OBJECT_ID, oidStr->octetLen, (uint8_t *)oidStr->octs},
        alg->param,
    };
    /* Preserve the ASN.1 type and contents of AlgorithmIdentifier parameters. */
    BSL_ASN1_TemplateItem algIdTempl[] = {g_algIdTempl[0], g_algIdTempl[1]};
    if (alg->param.tag != 0 && alg->param.tag != BSL_ASN1_TAG_ANY) {
        /* An explicitly present parameter can have empty contents, such as
         * RSASSA-PSS-params with every DEFAULT component omitted.
         */
        algIdTempl[HITLS_CMS_ALGORITHM_IDENTIFIER_PARAMS_IDX].flags &= (uint8_t)(~BSL_ASN1_FLAG_OPTIONAL);
    }
    BSL_ASN1_Template templ = {algIdTempl, sizeof(algIdTempl) / sizeof(algIdTempl[0])};
    int32_t ret = BSL_ASN1_EncodeTemplate(&templ, items, HITLS_CMS_ALGORITHM_IDENTIFIER_MAX_IDX,
        &asn->buff, &asn->len);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    asn->tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_CMS_AddMd(HITLS_X509_List *list, int32_t mdId)
{
    if (list == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    // Check if algorithm already exists.
    CMS_AlgId *alg = (CMS_AlgId *)BSL_LIST_SearchDataConst(list, &mdId, (BSL_LIST_PFUNC_CMP)CmpAlgId, NULL);
    if (alg != NULL) {
        return HITLS_PKI_SUCCESS;
    }
    // Add new algorithm
    alg = (CMS_AlgId *)BSL_SAL_Calloc(1, sizeof(CMS_AlgId));
    if (alg == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    alg->id = mdId;
    int32_t ret = BSL_LIST_AddElement(list, alg, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_Free(alg);
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

// Set message digest algorithm
static int32_t SignedDataSetMsgMd(CMS_SignedData *signedData, void *val)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    int32_t mdId = *(int32_t *)val;
    // Check if state is UNINITIALIZED
    if (signedData->state != HITLS_CMS_UNINIT) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_STATE);
        return HITLS_CMS_ERR_INVALID_STATE;
    }
    return HITLS_CMS_AddMd(signedData->digestAlg, mdId);
}

int32_t HITLS_CMS_SignedDataCtrl(HITLS_CMS *cms, int32_t cmd, void *val, uint32_t valLen)
{
    (void)valLen;
    CMS_SignedData *signedData = cms->ctx.signedData;
    if (signedData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    switch (cmd) {
        case HITLS_CMS_SET_MSG_MD:
            return SignedDataSetMsgMd(signedData, val);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
            return HITLS_CMS_ERR_INVALID_PARAM;
    }

    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_CMS_Ctrl(HITLS_CMS *cms, int32_t cmd, void *val, uint32_t valLen)
{
    if (cms == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }

    // Dispatch to appropriate sub-module ctrl function based on CMS dataType
    switch (cms->dataType) {
        case BSL_CID_PKCS7_SIGNEDDATA:
            return HITLS_CMS_SignedDataCtrl(cms, cmd, val, valLen);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_UNSUPPORTED_TYPE);
            return HITLS_CMS_ERR_UNSUPPORTED_TYPE;
    }
}
#endif // HITLS_PKI_CMS_SIGNEDDATA

#endif // HITLS_PKI_CMS
