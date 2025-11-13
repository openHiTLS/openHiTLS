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
#ifdef HITLS_PKI_X509_CRL
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_obj_internal.h"
#include "bsl_log_internal.h"
#ifdef HITLS_BSL_PEM
#include "bsl_pem_internal.h"
#endif
#include "bsl_err_internal.h"
#include "sal_time.h"
#ifdef HITLS_BSL_SAL_FILE
#include "sal_file.h"
#endif
#include "crypt_errno.h"
#include "hitls_pki_errno.h"
#include "hitls_x509_local.h"
#include "hitls_crl_local.h"
#include "hitls_pki_crl.h"

#define HITLS_CRL_CTX_SPECIFIC_TAG_EXTENSION 0
#define HITLS_X509_REVOKED_REASON_UNUSED    7   /** CRLReason: unused reason. */

#ifdef HITLS_PKI_X509_CRL_PARSE
BSL_ASN1_TemplateItem g_crlTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0}, /* x509 */
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 1}, /* tbs */
            /* 2: version */
            {BSL_ASN1_TAG_INTEGER, BSL_ASN1_FLAG_DEFAULT, 2},
            /* 2: signature info */
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 2},
                {BSL_ASN1_TAG_OBJECT_ID, 0, 3},
                {BSL_ASN1_TAG_ANY, BSL_ASN1_FLAG_OPTIONAL, 3}, // 6
            /* 2: issuer */
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_SAME, 2},
            /* 2: validity */
            {BSL_ASN1_TAG_CHOICE, 0, 2},
            {BSL_ASN1_TAG_CHOICE, BSL_ASN1_FLAG_OPTIONAL, 2},
            /* 2: revoked crl list */
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE,
            BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_SAME | BSL_ASN1_FLAG_OPTIONAL, 2},
            /* 2: extension */
            {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | HITLS_CRL_CTX_SPECIFIC_TAG_EXTENSION,
            BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_SAME, 2}, // 11
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1}, /* signAlg */
            {BSL_ASN1_TAG_OBJECT_ID, 0, 2},
            {BSL_ASN1_TAG_ANY, BSL_ASN1_FLAG_OPTIONAL, 2},
        {BSL_ASN1_TAG_BITSTRING, 0, 1} /* sig */
};

typedef enum {
    HITLS_X509_CRL_VERSION_IDX,
    HITLS_X509_CRL_TBS_SIGNALG_OID_IDX,
    HITLS_X509_CRL_TBS_SIGNALG_ANY_IDX,
    HITLS_X509_CRL_ISSUER_IDX,
    HITLS_X509_CRL_BEFORE_VALID_IDX,
    HITLS_X509_CRL_AFTER_VALID_IDX,
    HITLS_X509_CRL_CRL_LIST_IDX,
    HITLS_X509_CRL_EXT_IDX,
    HITLS_X509_CRL_SIGNALG_IDX,
    HITLS_X509_CRL_SIGNALG_ANY_IDX,
    HITLS_X509_CRL_SIGN_IDX,
    HITLS_X509_CRL_MAX_IDX,
} HITLS_X509_CRL_IDX;

int32_t HITLS_X509_CrlTagGetOrCheck(int32_t type, uint32_t idx, void *data, void *expVal)
{
    (void) idx;
    switch (type) {
        case BSL_ASN1_TYPE_CHECK_CHOICE_TAG: {
            uint8_t tag = *(uint8_t *) data;
            if ((tag == BSL_ASN1_TAG_UTCTIME) || (tag == BSL_ASN1_TAG_GENERALIZEDTIME)) {
                *(uint8_t *) expVal = tag;
                return BSL_SUCCESS;
            }
            /**
             * The tag value cannot be changed, use choice tag to resolve this time not optional.
             * Subsequent parsing of the choice ASN item fails.
             */
            return BSL_SUCCESS; // crl next time optional
        }
        case BSL_ASN1_TYPE_GET_ANY_TAG: {
            BSL_ASN1_Buffer *param = (BSL_ASN1_Buffer *) data;
            BslOidString oidStr = {param->len, (char *)param->buff, 0};
            BslCid cid = BSL_OBJ_GetCID(&oidStr);
            if (cid == BSL_CID_UNKNOWN) {
                return HITLS_X509_ERR_GET_ANY_TAG;
            }
            if (cid == BSL_CID_RSASSAPSS) {
                // note: any It can be encoded empty or it can be null
                *(uint8_t *) expVal = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
                return BSL_SUCCESS;
            } else {
                *(uint8_t *) expVal = BSL_ASN1_TAG_NULL; // is null
                return BSL_SUCCESS;
            }
            return HITLS_X509_ERR_GET_ANY_TAG;
        }
        default:
            return HITLS_X509_ERR_INVALID_PARAM;
    }
}
#endif // HITLS_PKI_X509_CRL_PARSE

void HITLS_X509_CrlFree(HITLS_X509_Crl *crl)
{
    if (crl == NULL) {
        return;
    }

    int ret = 0;
    BSL_SAL_AtomicDownReferences(&(crl->references), &ret);
    if (ret > 0) {
        return;
    }
    if ((crl->flag & HITLS_X509_CRL_GEN_FLAG) != 0) {
        BSL_LIST_FREE(crl->tbs.issuerName, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeNameNode);
        BSL_SAL_FREE(crl->tbs.tbsRawData);
        BSL_SAL_FREE(crl->signature.buff);
    } else {
        BSL_LIST_FREE(crl->tbs.issuerName, NULL);
    }
#ifdef HITLS_CRYPTO_SM2
    if (crl->signAlgId.algId == BSL_CID_SM2DSAWITHSM3) {
        BSL_SAL_FREE(crl->signAlgId.sm2UserId.data);
    }
#endif
    BSL_LIST_FREE(crl->tbs.revokedCerts, (BSL_LIST_PFUNC_FREE)HITLS_X509_CrlEntryFree);
    X509_ExtFree(&crl->tbs.crlExt, false);
    BSL_SAL_ReferencesFree(&(crl->references));
    BSL_SAL_FREE(crl->rawData);
    BSL_SAL_Free(crl);
    return;
}

HITLS_X509_Crl *HITLS_X509_CrlNew(void)
{
    HITLS_X509_Crl *crl = NULL;
    BSL_ASN1_List *issuerName = NULL;
    BSL_ASN1_List *entryList = NULL;
    HITLS_X509_Ext *ext = NULL;
    crl = (HITLS_X509_Crl *)BSL_SAL_Calloc(1, sizeof(HITLS_X509_Crl));
    if (crl == NULL) {
        return NULL;
    }

    issuerName = BSL_LIST_New(sizeof(HITLS_X509_NameNode));
    if (issuerName == NULL) {
        goto ERR;
    }

    entryList = BSL_LIST_New(sizeof(HITLS_X509_CrlEntry));
    if (entryList == NULL) {
        goto ERR;
    }
    ext = X509_ExtNew(&crl->tbs.crlExt, HITLS_X509_EXT_TYPE_CRL);
    if (ext == NULL) {
        goto ERR;
    }
    BSL_SAL_ReferencesInit(&(crl->references));
    crl->tbs.issuerName = issuerName;
    crl->tbs.revokedCerts = entryList;
    crl->state = HITLS_X509_CRL_STATE_NEW;
    return crl;
ERR:
    BSL_SAL_Free(crl);
    BSL_SAL_Free(issuerName);
    BSL_SAL_Free(entryList);
    return NULL;
}

#ifdef HITLS_PKI_X509_CRL_PARSE
int32_t HITLS_CRL_ParseExtAsnItem(uint32_t layer, BSL_ASN1_Buffer *asn, void *param, BSL_ASN1_List *list)
{
    (void) param;
    (void) layer;
    HITLS_X509_ExtEntry extEntry = {0};
    int32_t ret = HITLS_X509_ParseExtItem(asn, &extEntry);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    return HITLS_X509_AddListItemDefault(&extEntry, sizeof(HITLS_X509_ExtEntry), list);
}

int32_t HITLS_CRL_ParseExtSeqof(uint32_t layer, BSL_ASN1_Buffer *asn, void *param, BSL_ASN1_List *list)
{
    if (layer == 1) {
        return HITLS_PKI_SUCCESS;
    }
    return HITLS_CRL_ParseExtAsnItem(layer, asn, param, list);
}

int32_t HITLS_X509_ParseCrlExt(BSL_ASN1_Buffer *ext, HITLS_X509_Crl *crl)
{
    if ((crl->tbs.crlExt.flag & HITLS_X509_EXT_FLAG_GEN) != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_PARSE_AFTER_SET);
        return HITLS_X509_ERR_EXT_PARSE_AFTER_SET;
    }
    uint8_t expTag[] = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE,
        BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE};
    BSL_ASN1_DecodeListParam listParam = {2, expTag};
    int32_t ret = BSL_ASN1_DecodeListItem(&listParam, ext, &HITLS_CRL_ParseExtSeqof, crl, crl->tbs.crlExt.extList);
    if (ret != BSL_SUCCESS) {
        BSL_LIST_DeleteAll(crl->tbs.crlExt.extList, NULL);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    crl->tbs.crlExt.flag |= HITLS_X509_EXT_FLAG_PARSE;
    return ret;
}

BSL_ASN1_TemplateItem g_crlEntryTempl[] = {
    {BSL_ASN1_TAG_INTEGER, 0, 0},
    {BSL_ASN1_TAG_CHOICE, 0, 0},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 0}
};

typedef enum {
    HITLS_X509_CRLENTRY_NUM_IDX,
    HITLS_X509_CRLENTRY_TIME_IDX,
    HITLS_X509_CRLENTRY_EXT_IDX,
    HITLS_X509_CRLENTRY_MAX_IDX
} HITLS_X509_CRLENTRY_IDX;
#endif // HITLS_PKI_X509_CRL_PARSE

int32_t HITLS_X509_CrlEntryChoiceCheck(int32_t type, uint32_t idx, void *data, void *expVal)
{
    (void) idx;
    (void) expVal;
    if (type == BSL_ASN1_TYPE_CHECK_CHOICE_TAG) {
        uint8_t tag = *(uint8_t *) data;
        if ((tag & BSL_ASN1_TAG_UTCTIME) != 0 || (tag & BSL_ASN1_TAG_GENERALIZEDTIME) != 0) {
            *(uint8_t *) expVal = tag;
            return BSL_SUCCESS;
        }
        return HITLS_X509_ERR_CHECK_TAG;
    }
    return HITLS_X509_ERR_CHECK_TAG;
}

#ifdef HITLS_PKI_X509_CRL_PARSE
static int32_t DecodeCrlRevokeExt(BSL_ASN1_Buffer *asnArr, HITLS_X509_CrlEntry *crlEntry)
{
    if (asnArr->buff == NULL) {
        return HITLS_PKI_SUCCESS;
    }
    BslList *list = BSL_LIST_New(sizeof(HITLS_X509_ExtEntry));
    if (list == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    uint8_t expTag = (BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE);
    BSL_ASN1_DecodeListParam listParam = {1, &expTag};
    int32_t ret = BSL_ASN1_DecodeListItem(&listParam, asnArr, (BSL_ASN1_ParseListAsnItem)HITLS_CRL_ParseExtAsnItem,
        NULL, list);
    if (ret != BSL_SUCCESS) {
        BSL_LIST_FREE(list, NULL);
        return ret;
    }

    crlEntry->extList = list;
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_CRL_ParseCrlEntry(BSL_ASN1_Buffer *extItem, HITLS_X509_CrlEntry *crlEntry)
{
    uint8_t *temp = extItem->buff;
    uint32_t tempLen = extItem->len;
    BSL_ASN1_Buffer asnArr[HITLS_X509_CRLENTRY_MAX_IDX] = {0};
    BSL_ASN1_Template templ = {g_crlEntryTempl, sizeof(g_crlEntryTempl) / sizeof(g_crlEntryTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, HITLS_X509_CrlEntryChoiceCheck,
        &temp, &tempLen, asnArr, HITLS_X509_CRLENTRY_MAX_IDX);
    if (tempLen != 0) {
        ret = HITLS_X509_ERR_CRL_ENTRY;
    }
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    crlEntry->serialNumber = asnArr[HITLS_X509_CRLENTRY_NUM_IDX];

    ret = BSL_ASN1_DecodePrimitiveItem(&asnArr[HITLS_X509_CRLENTRY_TIME_IDX], &crlEntry->time);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (asnArr[HITLS_X509_CRLENTRY_TIME_IDX].tag == BSL_ASN1_TAG_GENERALIZEDTIME) {
        crlEntry->flag |= BSL_TIME_REVOKE_TIME_IS_GMT;
    }
    ret = DecodeCrlRevokeExt(&asnArr[HITLS_X509_CRLENTRY_EXT_IDX], crlEntry);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }

    return ret;
}

int32_t HITLS_CRL_ParseCrlAsnItem(uint32_t layer, BSL_ASN1_Buffer *asn, void *param, BSL_ASN1_List *list)
{
    (void) param;
    (void) layer;
    HITLS_X509_CrlEntry crlEntry = {0};
    int32_t ret = HITLS_CRL_ParseCrlEntry(asn, &crlEntry);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    crlEntry.flag |= HITLS_X509_CRL_PARSE_FLAG;
    return HITLS_X509_AddListItemDefault(&crlEntry, sizeof(HITLS_X509_CrlEntry), list);
}

int32_t HITLS_X509_ParseCrlList(BSL_ASN1_Buffer *crl, BSL_ASN1_List *list)
{
    // crl is optional
    if (crl->tag == 0) {
        return HITLS_PKI_SUCCESS;
    }

    uint8_t expTag = (BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE);
    BSL_ASN1_DecodeListParam listParam = {1, &expTag};
    int32_t ret = BSL_ASN1_DecodeListItem(&listParam, crl, &HITLS_CRL_ParseCrlAsnItem, NULL, list);
    if (ret != BSL_SUCCESS) {
        BSL_LIST_DeleteAll(list, NULL);
    }
    return ret;
}

int32_t HITLS_X509_ParseCrlTbs(BSL_ASN1_Buffer *asnArr, HITLS_X509_Crl *crl)
{
    int32_t ret;
    if (asnArr[HITLS_X509_CRL_VERSION_IDX].tag != 0) {
        ret = BSL_ASN1_DecodePrimitiveItem(&asnArr[HITLS_X509_CRL_VERSION_IDX], &crl->tbs.version);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    } else {
        crl->tbs.version = 0;
    }

    // sign alg
    ret = HITLS_X509_ParseSignAlgInfo(&asnArr[HITLS_X509_CRL_TBS_SIGNALG_OID_IDX],
        &asnArr[HITLS_X509_CRL_TBS_SIGNALG_ANY_IDX], &crl->tbs.signAlgId);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // issuer name
    ret = HITLS_X509_ParseNameList(&asnArr[HITLS_X509_CRL_ISSUER_IDX], crl->tbs.issuerName);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // validity
    ret = HITLS_X509_ParseTime(&asnArr[HITLS_X509_CRL_BEFORE_VALID_IDX], &asnArr[HITLS_X509_CRL_AFTER_VALID_IDX],
        &crl->tbs.validTime);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    // crl list
    ret = HITLS_X509_ParseCrlList(&asnArr[HITLS_X509_CRL_CRL_LIST_IDX], crl->tbs.revokedCerts);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // ext
    ret = HITLS_X509_ParseCrlExt(&asnArr[HITLS_X509_CRL_EXT_IDX], crl);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    return ret;
ERR:

    BSL_LIST_DeleteAll(crl->tbs.issuerName, NULL);
    BSL_LIST_DeleteAll(crl->tbs.revokedCerts, NULL);
    return ret;
}
#endif // HITLS_PKI_X509_CRL_PARSE

#ifdef HITLS_PKI_X509_CRL_GEN
static void X509_EncodeCrlValidTime(HITLS_X509_ValidTime *crlTime, BSL_ASN1_Buffer *validTime)
{
    validTime[0].tag = (crlTime->flag & BSL_TIME_BEFORE_IS_UTC) != 0 ? BSL_ASN1_TAG_UTCTIME :
        BSL_ASN1_TAG_GENERALIZEDTIME;
    validTime[0].len = sizeof(BSL_TIME);
    validTime[0].buff = (uint8_t *)&(crlTime->start);

    validTime[1].tag = (crlTime->flag & BSL_TIME_AFTER_IS_UTC) != 0 ? BSL_ASN1_TAG_UTCTIME :
        BSL_ASN1_TAG_GENERALIZEDTIME;
    if ((crlTime->flag & BSL_TIME_AFTER_SET) != 0) {
        validTime[1].len = sizeof(BSL_TIME);
        validTime[1].buff = (uint8_t *)&(crlTime->end);
    } else {
        validTime[1].len = 0;
        validTime[1].buff = NULL;
    }
}

static int32_t X509_EncodeCrlEntry(HITLS_X509_CrlEntry *crlEntry, BSL_ASN1_Buffer *asnBuf)
{
    asnBuf[0].tag = crlEntry->serialNumber.tag;
    asnBuf[0].buff = crlEntry->serialNumber.buff;
    asnBuf[0].len = crlEntry->serialNumber.len;
    asnBuf[1].tag = (crlEntry->flag & BSL_TIME_REVOKE_TIME_IS_GMT) != 0 ?
        BSL_ASN1_TAG_GENERALIZEDTIME : BSL_ASN1_TAG_UTCTIME;
    asnBuf[1].buff = (uint8_t *)&(crlEntry->time);
    asnBuf[1].len = sizeof(BSL_TIME);
    if (crlEntry->extList != NULL && BSL_LIST_COUNT(crlEntry->extList) > 0) {
        return HITLS_X509_EncodeExtEntry(crlEntry->extList, &asnBuf[2]); // 2: extensions
    } else {
        asnBuf[2].tag = 0;  // 2: extensions
        asnBuf[2].buff = NULL;  // 2: extensions
        asnBuf[2].len = 0; // 2: extensions
        return HITLS_PKI_SUCCESS;
    }
}

#define X509_CRLENTRY_ELEM_NUMBER 3
int32_t HITLS_X509_EncodeRevokeCrlList(BSL_ASN1_List *crlList, BSL_ASN1_Buffer *revokeBuf)
{
    int32_t count = BSL_LIST_COUNT(crlList);
    if (count <= 0) {
        revokeBuf->buff = NULL;
        revokeBuf->len = 0;
        revokeBuf->tag = BSL_ASN1_TAG_SEQUENCE;
        return HITLS_PKI_SUCCESS;
    }
    BSL_ASN1_Buffer *asnBuf = BSL_SAL_Malloc((uint32_t)count * sizeof(BSL_ASN1_Buffer) * X509_CRLENTRY_ELEM_NUMBER);
    if (asnBuf == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    (void)memset_s(asnBuf, (uint32_t)count * sizeof(BSL_ASN1_Buffer) * X509_CRLENTRY_ELEM_NUMBER, 0,
        (uint32_t)count * sizeof(BSL_ASN1_Buffer) * X509_CRLENTRY_ELEM_NUMBER);
    HITLS_X509_CrlEntry *crlEntry = NULL;
    uint32_t iter = 0;
    int32_t ret;
    for (crlEntry = BSL_LIST_GET_FIRST(crlList); crlEntry != NULL; crlEntry = BSL_LIST_GET_NEXT(crlList)) {
        ret = X509_EncodeCrlEntry(crlEntry, &asnBuf[iter]);
        if (ret != HITLS_PKI_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }
        iter += X509_CRLENTRY_ELEM_NUMBER;
    }
    BSL_ASN1_TemplateItem crlEntryTempl[] = {
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_SAME | BSL_ASN1_FLAG_OPTIONAL, 0},
            {BSL_ASN1_TAG_INTEGER, 0, 1},
            {BSL_ASN1_TAG_CHOICE, 0, 1},
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_OPTIONAL, 1}
    };
    BSL_ASN1_Template templ = {crlEntryTempl, sizeof(crlEntryTempl) / sizeof(crlEntryTempl[0])};
    ret = BSL_ASN1_EncodeListItem(BSL_ASN1_TAG_SEQUENCE, (uint32_t)count, &templ, asnBuf, iter, revokeBuf);
EXIT:
    for (int32_t i = 0; i < count; i++) {
        /**
         * The memory for the extension in CRLentry needs to be freed up.
         * The subscript 2 corresponds to the extension.
         */
        BSL_SAL_Free(asnBuf[i * X509_CRLENTRY_ELEM_NUMBER + 2].buff);
    }
    BSL_SAL_Free(asnBuf);
    return ret;
}

BSL_ASN1_TemplateItem g_crlTbsTempl[] = {
    /* 1: version */
    {BSL_ASN1_TAG_INTEGER, BSL_ASN1_FLAG_DEFAULT, 0},
    /* 2: signature info */
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 0},
    /* 3: issuer */
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_SAME, 0},
    /* 4-5: validity */
    {BSL_ASN1_TAG_CHOICE, 0, 0},
    {BSL_ASN1_TAG_CHOICE, BSL_ASN1_FLAG_OPTIONAL, 0},
    /* 6: revoked crl list */
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE,
        BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_SAME | BSL_ASN1_FLAG_OPTIONAL, 0},
    /* 7: extension */
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | HITLS_CRL_CTX_SPECIFIC_TAG_EXTENSION,
        BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_SAME, 0}, // 11
};

int32_t HITLS_X509_EncodeCrlExt(HITLS_X509_Ext *crlExt, BSL_ASN1_Buffer *ext)
{
    return HITLS_X509_EncodeExt(
        BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | HITLS_CRL_CTX_SPECIFIC_TAG_EXTENSION,
        crlExt->extList, ext);
}
/**
 * RFC 5280 sec 5.1.2.1
 * This optional field describes the version of the encoded CRL.  When
 * extensions are used, as required by this profile, this field MUST be
 * present and MUST specify version 2 (the integer value is 1).
 */
static void X509_EncodeVersion(uint8_t *version, BSL_ASN1_Buffer *asn)
{
    if (*version == 1) {
        asn->tag = BSL_ASN1_TAG_INTEGER;
        asn->len = 1;
        asn->buff = version;
    } else {
        asn->tag = BSL_ASN1_TAG_INTEGER;
        asn->len = 0;
        asn->buff = NULL;
    }
}

#define X509_CRLTBS_ELEM_NUMBER 7
int32_t HITLS_X509_EncodeCrlTbsRaw(HITLS_X509_CrlTbs *crlTbs, BSL_ASN1_Buffer *asn)
{
    BSL_ASN1_Buffer asnArr[X509_CRLTBS_ELEM_NUMBER] = {0};
    uint8_t version = (uint8_t)crlTbs->version;
    X509_EncodeVersion(&version, asnArr); // 0 is version
    BSL_ASN1_Buffer *signAlgAsn = &asnArr[1];  // 1 is signAlg
    BSL_ASN1_Buffer *issuerAsn = &asnArr[2]; // 2 is issuer name
    BSL_ASN1_Buffer *revokeBuf = &asnArr[5]; // 5 is revoke list
    BSL_ASN1_Buffer *crlExt = &asnArr[6]; // 6 is crl extension

    int32_t ret = HITLS_X509_EncodeSignAlgInfo(&crlTbs->signAlgId, signAlgAsn);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = HITLS_X509_EncodeNameList(crlTbs->issuerName, issuerAsn);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    X509_EncodeCrlValidTime(&crlTbs->validTime, &asnArr[3]); // 3 is valid time
    ret = HITLS_X509_EncodeRevokeCrlList(crlTbs->revokedCerts, revokeBuf);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = HITLS_X509_EncodeCrlExt(&(crlTbs->crlExt), crlExt);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    BSL_ASN1_Template templ = {g_crlTbsTempl, sizeof(g_crlTbsTempl) / sizeof(g_crlTbsTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asnArr, X509_CRLTBS_ELEM_NUMBER, &(asn->buff), &(asn->len));
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    asn->tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
EXIT:
    BSL_SAL_Free(signAlgAsn->buff);
    if (issuerAsn->buff != NULL) {
        BSL_SAL_Free(issuerAsn->buff);
    }
    if (revokeBuf->buff != NULL) {
        BSL_SAL_Free(revokeBuf->buff);
    }
    if (crlExt->buff != NULL) {
        BSL_SAL_Free(crlExt->buff);
    }
    return ret;
}

#define X509_CRL_ELEM_NUMBER 3
int32_t EncodeAsn1Crl(HITLS_X509_Crl *crl)
{
    if (crl->signature.buff == NULL || crl->signature.len == 0 ||
        crl->tbs.tbsRawData == NULL || crl->tbs.tbsRawDataLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CRL_NOT_SIGNED);
        return HITLS_X509_ERR_CRL_NOT_SIGNED;
    }
    BSL_ASN1_Buffer asnArr[X509_CRL_ELEM_NUMBER] = {
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, crl->tbs.tbsRawDataLen, crl->tbs.tbsRawData},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, NULL},
        {BSL_ASN1_TAG_BITSTRING, sizeof(BSL_ASN1_BitString), (uint8_t *)&crl->signature},
    };
    uint32_t valLen = 0;
    int32_t ret = BSL_ASN1_DecodeTagLen(asnArr[0].tag, &asnArr[0].buff, &asnArr[0].len, &valLen); // 0 is tbs
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = HITLS_X509_EncodeSignAlgInfo(&crl->signAlgId, &asnArr[1]); // 1 is signAlg
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    BSL_ASN1_TemplateItem crlTempl[] = {
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0}, /* crl */
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 1}, /* tbs */
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 1}, /* signAlg */
            {BSL_ASN1_TAG_BITSTRING, 0, 1} /* sig */
    };
    BSL_ASN1_Template templ = {crlTempl, sizeof(crlTempl) / sizeof(crlTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asnArr, X509_CRL_ELEM_NUMBER, &crl->rawData, &crl->rawDataLen);
    BSL_SAL_Free(asnArr[1].buff);
    return ret;
}

/**
 * @brief Encode ASN.1 crl
 *
 * @param crl [IN] Pointer to the crl structure
 * @param buff [OUT] Pointer to the buffer.
 *             If NULL, only the ASN.1 crl is encoded.
 *             If non-NULL, the DER encoding content of the crl is stored in buff
 * @return int32_t Return value, 0 means success, other values mean failure
 */
int32_t HITLS_X509_EncodeAsn1Crl(HITLS_X509_Crl *crl, BSL_Buffer *buff)
{
    int32_t ret;
    if ((crl->flag & HITLS_X509_CRL_GEN_FLAG) != 0) {
        if (crl->state != HITLS_X509_CRL_STATE_SIGN && crl->state != HITLS_X509_CRL_STATE_GEN) {
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CRL_NOT_SIGNED);
            return HITLS_X509_ERR_CRL_NOT_SIGNED;
        }
        if (crl->state == HITLS_X509_CRL_STATE_SIGN) {
            ret = EncodeAsn1Crl(crl);
            if (ret != HITLS_PKI_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            crl->state = HITLS_X509_CRL_STATE_GEN;
        }
    }
    if (crl->rawData == NULL || crl->rawDataLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CRL_NOT_SIGNED);
        return HITLS_X509_ERR_CRL_NOT_SIGNED;
    }
    if (buff == NULL) {
        return HITLS_PKI_SUCCESS;
    }
    buff->data = BSL_SAL_Dump(crl->rawData, crl->rawDataLen);
    if (buff->data == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
        return BSL_DUMP_FAIL;
    }
    buff->dataLen = crl->rawDataLen;
    return HITLS_PKI_SUCCESS;
}

#ifdef HITLS_BSL_PEM
int32_t HITLS_X509_EncodePemCrl(HITLS_X509_Crl *crl, BSL_Buffer *buff)
{
    int32_t ret = HITLS_X509_EncodeAsn1Crl(crl, NULL);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_PEM_Symbol symbol = {BSL_PEM_CRL_BEGIN_STR, BSL_PEM_CRL_END_STR};
    return BSL_PEM_EncodeAsn1ToPem(crl->rawData, crl->rawDataLen, &symbol, (char **)&buff->data, &buff->dataLen);
}
#endif // HITLS_BSL_PEM

static int32_t X509_CheckCrlRevoke(HITLS_X509_Crl *crl)
{
    BSL_ASN1_List *revokedCerts = crl->tbs.revokedCerts;
    if (revokedCerts != NULL) {
        HITLS_X509_CrlEntry *entry = NULL;
        for (entry = BSL_LIST_GET_FIRST(revokedCerts); entry != NULL; entry = BSL_LIST_GET_NEXT(revokedCerts)) {
            // Check serial number
            if (entry->serialNumber.buff == NULL || entry->serialNumber.len == 0) {
                BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CRL_ENTRY);
                return HITLS_X509_ERR_CRL_ENTRY;
            }

            // Check revocation time
            if (!BSL_DateTimeCheck(&entry->time)) {
                BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CRL_TIME_INVALID);
                return HITLS_X509_ERR_CRL_TIME_INVALID;
            }

            // If entry has extensions and CRL version is v1, that's an error
            if (entry->extList != NULL && BSL_LIST_COUNT(entry->extList) > 0 && crl->tbs.version == 0) {
                BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CRL_INACCURACY_VERSION);
                return HITLS_X509_ERR_CRL_INACCURACY_VERSION;
            }
        }
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t X509_CheckCrlTbs(HITLS_X509_Crl *crl)
{
    int32_t ret;
    if (crl->tbs.version != 0 && crl->tbs.version != 1) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CRL_INACCURACY_VERSION);
        return HITLS_X509_ERR_CRL_INACCURACY_VERSION;
    }
    if (crl->tbs.crlExt.extList != NULL && BSL_LIST_COUNT(crl->tbs.crlExt.extList) > 0) {
        if (crl->tbs.version != 1) {
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CRL_INACCURACY_VERSION);
            return HITLS_X509_ERR_CRL_INACCURACY_VERSION;
        }
    }

    // Check issuer name
    if (crl->tbs.issuerName == NULL || BSL_LIST_COUNT(crl->tbs.issuerName) <= 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CRL_ISSUER_EMPTY);
        return HITLS_X509_ERR_CRL_ISSUER_EMPTY;
    }

    // Check validity time
    if ((crl->tbs.validTime.flag & BSL_TIME_BEFORE_SET) == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CRL_THISUPDATE_UNEXIST);
        return HITLS_X509_ERR_CRL_THISUPDATE_UNEXIST;
    }

    // If nextUpdate is set, check it's after thisUpdate
    if ((crl->tbs.validTime.flag & BSL_TIME_AFTER_SET) != 0) {
        ret = BSL_SAL_DateTimeCompare(&crl->tbs.validTime.start, &crl->tbs.validTime.end, NULL);
        if (ret != BSL_TIME_DATE_BEFORE) {
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CRL_TIME_INVALID);
            return HITLS_X509_ERR_CRL_TIME_INVALID;
        }
    }
    ret = X509_CheckCrlRevoke(crl);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t HITLS_X509_CrlGenBuff(int32_t format, HITLS_X509_Crl *crl, BSL_Buffer *buff)
{
    if (crl == NULL || buff == NULL || buff->data != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    switch (format) {
        case BSL_FORMAT_ASN1:
            return HITLS_X509_EncodeAsn1Crl(crl, buff);
#ifdef HITLS_BSL_PEM
        case BSL_FORMAT_PEM:
            return HITLS_X509_EncodePemCrl(crl, buff);
#endif // HITLS_BSL_PEM
        default:
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
            return HITLS_X509_ERR_INVALID_PARAM;
    }
}

#ifdef HITLS_BSL_SAL_FILE
int32_t HITLS_X509_CrlGenFile(int32_t format, HITLS_X509_Crl *crl, const char *path)
{
    if (path == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    BSL_Buffer buff = {0};
    int32_t ret = HITLS_X509_CrlGenBuff(format, crl, &buff);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BSL_SAL_WriteFile(path, buff.data, buff.dataLen);
    BSL_SAL_Free(buff.data);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}
#endif // HITLS_BSL_SAL_FILE
#endif // HITLS_PKI_X509_CRL_GEN

#ifdef HITLS_PKI_X509_CRL_PARSE
static int32_t HITLS_X509_ParseCrlTemplate(uint8_t **encode, uint32_t *encodeLen,
    BSL_ASN1_Buffer *asnArr, uint32_t asnNum)
{
    BSL_ASN1_Buffer asnTempArr[4]; // tbs, signId, sign param, sign
    uint32_t asnTempArrLen = sizeof(asnTempArr) / sizeof(asnTempArr[0]);
    BSL_ASN1_Template templ = {g_crlTempl, sizeof(g_crlTempl) / sizeof(g_crlTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, HITLS_X509_CrlTagGetOrCheck,
        encode, encodeLen, asnTempArr, asnTempArrLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_ASN1_Template templTbs = {&g_crlTempl[2], 9}; // tbs parse
    ret = BSL_ASN1_DecodeTemplate(&templTbs, HITLS_X509_CrlTagGetOrCheck,
        &(asnTempArr[0].buff), &(asnTempArr[0].len), asnArr, asnNum - 3); // Subtract the already parsed
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    asnArr[HITLS_X509_CRL_SIGNALG_IDX] = asnTempArr[1]; // signId
    asnArr[HITLS_X509_CRL_SIGNALG_ANY_IDX] = asnTempArr[2]; // sign param
    asnArr[HITLS_X509_CRL_SIGN_IDX] = asnTempArr[3]; // signature
    return ret;
}

int32_t HITLS_X509_ParseAsn1Crl(uint8_t *encode, uint32_t encodeLen, HITLS_X509_Crl *crl)
{
    uint8_t *temp = encode;
    uint32_t tempLen = encodeLen;
    crl->rawData = encode; // crl takes over the encode immediately.
    if ((crl->flag & HITLS_X509_CRL_GEN_FLAG) != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    // template parse
    BSL_ASN1_Buffer asnArr[HITLS_X509_CRL_MAX_IDX] = {0};
    int32_t ret = HITLS_X509_ParseCrlTemplate(&temp, &tempLen, asnArr, HITLS_X509_CRL_MAX_IDX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // parse tbs raw data
    ret = HITLS_X509_ParseTbsRawData(encode, encodeLen, &crl->tbs.tbsRawData, &crl->tbs.tbsRawDataLen);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // parse tbs
    ret = HITLS_X509_ParseCrlTbs(asnArr, crl);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    // parse sign alg
    ret = HITLS_X509_ParseSignAlgInfo(&asnArr[HITLS_X509_CRL_SIGNALG_IDX],
        &asnArr[HITLS_X509_CRL_SIGNALG_ANY_IDX], &crl->signAlgId);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    // parse signature
    ret = BSL_ASN1_DecodePrimitiveItem(&asnArr[HITLS_X509_CRL_SIGN_IDX], &crl->signature);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    crl->rawDataLen = encodeLen - tempLen;
    crl->flag |= HITLS_X509_CRL_PARSE_FLAG;
    return HITLS_PKI_SUCCESS;
ERR:
    BSL_LIST_DeleteAll(crl->tbs.issuerName, NULL);
    BSL_LIST_DeleteAll(crl->tbs.revokedCerts, NULL);
    BSL_LIST_DeleteAll(crl->tbs.crlExt.extList, NULL);
    return ret;
}

int32_t HITLS_X509_CrlParseBundleBuff(int32_t format, const BSL_Buffer *encode, HITLS_X509_List **crlList)
{
    if (encode == NULL || encode->data == NULL || encode->dataLen == 0 || crlList == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    X509_ParseFuncCbk crlCbk = {
        .asn1Parse = (HITLS_X509_Asn1Parse)HITLS_X509_ParseAsn1Crl,
        .x509New = (HITLS_X509_New)HITLS_X509_CrlNew,
        .x509Free = (HITLS_X509_Free)HITLS_X509_CrlFree,
    };
    HITLS_X509_List *list = BSL_LIST_New(sizeof(HITLS_X509_Crl));
    if (list == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = HITLS_X509_ParseX509(NULL, NULL, format, encode, false, &crlCbk, list);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_LIST_FREE(list, (BSL_LIST_PFUNC_FREE)HITLS_X509_CrlFree);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *crlList = list;
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_X509_CrlParseBuff(int32_t format, const BSL_Buffer *encode, HITLS_X509_Crl **crl)
{
    HITLS_X509_List *list = NULL;
    if (crl == NULL || *crl != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    int32_t ret = HITLS_X509_CrlParseBundleBuff(format, encode, &list);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    HITLS_X509_Crl *tmp = BSL_LIST_GET_FIRST(list);
    int ref;
    ret = HITLS_X509_CrlCtrl(tmp, HITLS_X509_REF_UP, &ref, sizeof(int));
    BSL_LIST_FREE(list, (BSL_LIST_PFUNC_FREE)HITLS_X509_CrlFree);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    *crl = tmp;
    return HITLS_PKI_SUCCESS;
}

#ifdef HITLS_BSL_SAL_FILE
int32_t HITLS_X509_CrlParseFile(int32_t format, const char *path, HITLS_X509_Crl **crl)
{
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    int32_t ret = BSL_SAL_ReadFile(path, &data, &dataLen);
    if (ret != BSL_SUCCESS) {
        return ret;
    }

    BSL_Buffer encode = {data, dataLen};
    ret = HITLS_X509_CrlParseBuff(format, &encode, crl);
    BSL_SAL_Free(data);
    return ret;
}

int32_t HITLS_X509_CrlParseBundleFile(int32_t format, const char *path, HITLS_X509_List **crlList)
{
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    int32_t ret = BSL_SAL_ReadFile(path, &data, &dataLen);
    if (ret != BSL_SUCCESS) {
        return ret;
    }

    BSL_Buffer encode = {data, dataLen};
    ret = HITLS_X509_CrlParseBundleBuff(format, &encode, crlList);
    BSL_SAL_Free(data);
    return ret;
}
#endif // HITLS_BSL_SAL_FILE

#endif // HITLS_PKI_X509_CRL_PARSE

static int32_t X509_CrlRefUp(HITLS_X509_Crl *crl, int32_t *val, uint32_t valLen)
{
    if (val == NULL || valLen != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    return BSL_SAL_AtomicUpReferences(&crl->references, val);
}

static int32_t X509_CrlGetThisUpdate(HITLS_X509_Crl *crl, BSL_TIME *val, uint32_t valLen)
{
    if (valLen != sizeof(BSL_TIME)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    if ((crl->tbs.validTime.flag & BSL_TIME_BEFORE_SET) == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CRL_THISUPDATE_UNEXIST);
        return HITLS_X509_ERR_CRL_THISUPDATE_UNEXIST;
    }
    *val = crl->tbs.validTime.start;
    return HITLS_PKI_SUCCESS;
}

static int32_t X509_CrlGetNextUpdate(HITLS_X509_Crl *crl, BSL_TIME *val, uint32_t valLen)
{
    if (valLen != sizeof(BSL_TIME)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    if ((crl->tbs.validTime.flag & BSL_TIME_AFTER_SET) == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CRL_NEXTUPDATE_UNEXIST);
        return HITLS_X509_ERR_CRL_NEXTUPDATE_UNEXIST;
    }
    *val = crl->tbs.validTime.end;
    return HITLS_PKI_SUCCESS;
}

static int32_t X509_CrlGetVersion(HITLS_X509_Crl *crl, int32_t *val, uint32_t valLen)
{
    if (valLen != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    // CRL version is stored as v2(1), v1(0)
    *val = crl->tbs.version;

    return HITLS_PKI_SUCCESS;
}

static int32_t X509_CrlGetRevokeList(HITLS_X509_Crl *crl, BSL_ASN1_List **val, uint32_t valLen)
{
    if (valLen != sizeof(BSL_ASN1_List *)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    if (crl->tbs.revokedCerts == NULL) {
        *val = NULL;
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CRL_REVOKELIST_UNEXIST);
        return HITLS_X509_ERR_CRL_REVOKELIST_UNEXIST;
    }

    *val = crl->tbs.revokedCerts;
    return HITLS_PKI_SUCCESS;
}

static int32_t X509_CrlGetCtrl(HITLS_X509_Crl *crl, int32_t cmd, void *val, uint32_t valLen)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    switch (cmd) {
        case HITLS_X509_GET_VERSION:
            return X509_CrlGetVersion(crl, val, valLen);
        case HITLS_X509_GET_BEFORE_TIME:
            return X509_CrlGetThisUpdate(crl, val, valLen);
        case HITLS_X509_GET_AFTER_TIME:
            return X509_CrlGetNextUpdate(crl, val, valLen);
        case HITLS_X509_GET_ISSUER_DN:
            return HITLS_X509_GetList(crl->tbs.issuerName, val, valLen);
        case HITLS_X509_GET_REVOKELIST:
            return X509_CrlGetRevokeList(crl, val, valLen);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
            return HITLS_X509_ERR_INVALID_PARAM;
    }
}

#ifdef HITLS_PKI_X509_CRL_GEN
static int32_t CrlSetTime(void *dest, uint8_t *val, uint32_t valLen)
{
    if (valLen != sizeof(BSL_TIME) || !BSL_DateTimeCheck((BSL_TIME *)val)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    (void)memcpy_s(dest, valLen, val, valLen);
    return HITLS_PKI_SUCCESS;
}

static int32_t CrlSetThisUpdateTime(HITLS_X509_ValidTime *time, uint8_t *val, uint32_t valLen)
{
    int32_t ret = CrlSetTime(&(time->start), val, valLen);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    time->flag |= BSL_TIME_BEFORE_SET;
    /**
     * According to Section 5.1.2.4 of RFC 5280.
     * CRL issuers conforming to this profile MUST encode thisUpdate as UTCTime for dates through the year 2049.
     * CRL issuers conforming to this profile MUST encode thisUpdate as GeneralizedTime for dates in the year
     * 2050 or later.
     */
    if (time->start.year < 2050) {
        time->flag |= BSL_TIME_BEFORE_IS_UTC;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t CrlSetNextUpdateTime(HITLS_X509_ValidTime *time, uint8_t *val, uint32_t valLen)
{
    int32_t ret = CrlSetTime(&(time->end), val, valLen);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    time->flag |= BSL_TIME_AFTER_SET;
    /**
     * According to Section 5.1.2.5 of RFC 5280.
     * CRL issuers conforming to this profile MUST encode nextUpdate as UTCTime for dates through the year 2049.
     * CRL issuers conforming to this profile MUST encode nextUpdate as GeneralizedTime for dates in the year
     * 2050 or later.
     */
    if (time->end.year < 2050) {
        time->flag |= BSL_TIME_AFTER_IS_UTC;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t CrlSetRevokeTime(HITLS_X509_CrlEntry *revoked, uint8_t *val, uint32_t valLen)
{
    int32_t ret = CrlSetTime(&(revoked->time), val, valLen);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    /**
     * According to Section 5.1.2.6 of RFC 5280, "The time for revocationDate MUST be expressed as described in
     * Section 5.1.2.4."
     * CRL issuers conforming to this profile MUST encode revocationDate as UTCTime for dates through the year 2049.
     * CRL issuers conforming to this profile MUST encode revocationDate as GeneralizedTime for dates in the year
     * 2050 or later.
     */
    if (revoked->time.year >= 2050) {
        revoked->flag |= BSL_TIME_REVOKE_TIME_IS_GMT;
    }
    return HITLS_PKI_SUCCESS;
}

static HITLS_X509_CrlEntry *X509_CrlEntryDup(const HITLS_X509_CrlEntry *src)
{
    HITLS_X509_CrlEntry *dest = (HITLS_X509_CrlEntry *)BSL_SAL_Malloc(sizeof(HITLS_X509_CrlEntry));
    if (dest == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }
    (void)memset_s(dest, sizeof(HITLS_X509_CrlEntry), 0, sizeof(HITLS_X509_CrlEntry));

    dest->serialNumber.buff = BSL_SAL_Dump(src->serialNumber.buff, src->serialNumber.len);
    if (dest->serialNumber.buff == NULL) {
        BSL_SAL_Free(dest);
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }

    dest->serialNumber.len = src->serialNumber.len;
    dest->serialNumber.tag = src->serialNumber.tag;

    dest->time = src->time;
    dest->flag = src->flag;
    dest->flag &= ~HITLS_X509_CRL_PARSE_FLAG;
    dest->flag |= HITLS_X509_CRL_GEN_FLAG;

    if (src->extList != NULL) {
        dest->extList = BSL_LIST_Copy(src->extList, (BSL_LIST_PFUNC_DUP)X509_DupExtEntry,
            (BSL_LIST_PFUNC_FREE)HITLS_X509_ExtEntryFree);
        if (dest->extList == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_SET);
            goto ERR;
        }
    }
    return dest;
ERR:
    BSL_SAL_Free(dest->serialNumber.buff);
    BSL_SAL_Free(dest);
    return NULL;
}

static void X509_CrlEntryFree(HITLS_X509_CrlEntry *entry)
{
    if (entry == NULL) {
        return;
    }
    BSL_SAL_Free(entry->serialNumber.buff);
    BSL_LIST_FREE(entry->extList, (BSL_LIST_PFUNC_FREE)HITLS_X509_ExtEntryFree);
    BSL_SAL_Free(entry);
}

int32_t HITLS_X509_CrlAddRevokedCert(HITLS_X509_Crl *crl, void *val)
{
    HITLS_X509_CrlEntry *entry = (HITLS_X509_CrlEntry *)val;

    if (entry->serialNumber.buff == NULL || entry->serialNumber.len == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CRL_ENTRY);
        return HITLS_X509_ERR_CRL_ENTRY;
    }

    if (!BSL_DateTimeCheck(&entry->time)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CRL_ENTRY);
        return HITLS_X509_ERR_CRL_ENTRY;
    }

    if (crl->tbs.revokedCerts == NULL) {
        crl->tbs.revokedCerts = BSL_LIST_New(sizeof(HITLS_X509_CrlEntry));
        if (crl->tbs.revokedCerts == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }
    }
    HITLS_X509_CrlEntry *newEntry = X509_CrlEntryDup(entry);
    if (newEntry == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    int32_t ret = BSL_LIST_AddElement(crl->tbs.revokedCerts, newEntry, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        X509_CrlEntryFree(newEntry);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // If the CRL version is v1 and an extended revocation certificate is added, it needs to be upgraded to v2
    if (crl->tbs.version == 0 && entry->extList != NULL) {
        crl->tbs.version = 1;  // v2
    }

    return HITLS_PKI_SUCCESS;
}

static int32_t X509_CrlSetVersion(HITLS_X509_Crl *crl, int32_t *val, uint32_t valLen)
{
    if (valLen != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    int32_t version = *val;
    if (version != 0 && version != 1) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    crl->tbs.version = version;
    return HITLS_PKI_SUCCESS;
}

static int32_t X509_CrlSetCtrl(HITLS_X509_Crl *crl, int32_t cmd, void *val, uint32_t valLen)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    if ((crl->flag & HITLS_X509_CRL_PARSE_FLAG) != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_SET_AFTER_PARSE);
        return HITLS_X509_ERR_SET_AFTER_PARSE;
    }
    crl->flag |= HITLS_X509_CRL_GEN_FLAG;
    crl->state = HITLS_X509_CRL_STATE_SET;
    switch (cmd) {
        case HITLS_X509_SET_VERSION:
            return X509_CrlSetVersion(crl, val, valLen);
        case HITLS_X509_SET_ISSUER_DN:
            return HITLS_X509_SetNameList(&crl->tbs.issuerName, val, valLen);
        case HITLS_X509_SET_BEFORE_TIME:
            return CrlSetThisUpdateTime(&crl->tbs.validTime, val, valLen);
        case HITLS_X509_SET_AFTER_TIME:
            return CrlSetNextUpdateTime(&crl->tbs.validTime, val, valLen);
        case HITLS_X509_CRL_ADD_REVOKED_CERT:
            return HITLS_X509_CrlAddRevokedCert(crl, val);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
            return HITLS_X509_ERR_INVALID_PARAM;
    }
}
#endif // HITLS_PKI_X509_CRL_GEN

int32_t HITLS_X509_CrlCtrl(HITLS_X509_Crl *crl, int32_t cmd, void *val, uint32_t valLen)
{
    if (crl == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    if (cmd == HITLS_X509_REF_UP) {
        return X509_CrlRefUp(crl, val, valLen);
#ifdef HITLS_CRYPTO_SM2
    } else if (cmd == HITLS_X509_SET_VFY_SM2_USER_ID) {
        if (crl->signAlgId.algId != BSL_CID_SM2DSAWITHSM3) {
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_VFY_SIGNALG_NOT_MATCH);
            return HITLS_X509_ERR_VFY_SIGNALG_NOT_MATCH;
        }
        return HITLS_X509_SetSm2UserId(&crl->signAlgId.sm2UserId, val, valLen);
#endif
    } else if (cmd >= HITLS_X509_GET_ENCODELEN && cmd < HITLS_X509_SET_VERSION) {
        return X509_CrlGetCtrl(crl, cmd, val, valLen);
    } else if (cmd < HITLS_X509_EXT_SET_SKI) {
#ifdef HITLS_PKI_X509_CRL_GEN
        return X509_CrlSetCtrl(crl, cmd, val, valLen);
#else
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_FUNC_UNSUPPORT);
        return HITLS_X509_ERR_FUNC_UNSUPPORT;
#endif
    } else if (cmd <= HITLS_X509_EXT_CHECK_SKI) {
        static int32_t cmdSet[] = {HITLS_X509_EXT_SET_CRLNUMBER, HITLS_X509_EXT_SET_AKI, HITLS_X509_EXT_GET_CRLNUMBER,
            HITLS_X509_EXT_GET_AKI, HITLS_X509_EXT_GET_KUSAGE};
        if (!X509_CheckCmdValid(cmdSet, sizeof(cmdSet) / sizeof(int32_t), cmd)) {
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_UNSUPPORT);
            return HITLS_X509_ERR_EXT_UNSUPPORT;
        }
        return X509_ExtCtrl(&crl->tbs.crlExt, cmd, val, valLen);
    } else {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
}

int32_t HITLS_X509_CrlVerify(void *pubkey, const HITLS_X509_Crl *crl)
{
    if (pubkey == NULL || crl == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    if ((crl->flag & HITLS_X509_CRL_GEN_FLAG) != 0 &&
        (crl->state != HITLS_X509_CRL_STATE_SIGN) && (crl->state != HITLS_X509_CRL_STATE_GEN)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CRL_NOT_SIGNED);
        return HITLS_X509_ERR_CRL_NOT_SIGNED;
    }
    int32_t ret = HITLS_X509_CheckAlg(pubkey, &(crl->signAlgId));
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    ret = HITLS_X509_CheckSignature(pubkey, crl->tbs.tbsRawData, crl->tbs.tbsRawDataLen,
        &(crl->signAlgId), &crl->signature);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

HITLS_X509_CrlEntry *HITLS_X509_CrlEntryNew(void)
{
    HITLS_X509_CrlEntry *entry = BSL_SAL_Malloc(sizeof(HITLS_X509_CrlEntry));
    if (entry == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }

    (void)memset_s(entry, sizeof(HITLS_X509_CrlEntry), 0, sizeof(HITLS_X509_CrlEntry));

    entry->flag |= HITLS_X509_CRL_GEN_FLAG;
    return entry;
}

void HITLS_X509_CrlEntryFree(HITLS_X509_CrlEntry *entry)
{
    if (entry == NULL) {
        return;
    }
    if ((entry->flag & HITLS_X509_CRL_GEN_FLAG) != 0) {
        BSL_SAL_Free(entry->serialNumber.buff);
        BSL_LIST_FREE(entry->extList, (BSL_LIST_PFUNC_FREE)HITLS_X509_ExtEntryFree);
    } else {
        BSL_LIST_FREE(entry->extList, NULL);
    }
    BSL_SAL_Free(entry);
}

static int32_t X509_CrlGetRevokedRevokeTime(HITLS_X509_CrlEntry *entry, void *val, uint32_t valLen)
{
    if (valLen != sizeof(BSL_TIME)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    *(BSL_TIME *)val = entry->time;
    return HITLS_PKI_SUCCESS;
}

#ifdef HITLS_PKI_X509_CRL_GEN
static int32_t X509_CrlSetRevokedExt(HITLS_X509_CrlEntry *entry, BslCid cid, BSL_Buffer *buff, uint32_t exceptLen,
    EncodeExtCb encodeExt)
{
    if (buff->dataLen != exceptLen) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    if (entry->extList == NULL) {
        entry->extList = BSL_LIST_New(sizeof(HITLS_X509_ExtEntry));
        if (entry->extList == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }
    }

    return HITLS_X509_SetExtList(NULL, entry->extList, cid, buff, encodeExt);
}

static int32_t SetExtInvalidTime(void *param, HITLS_X509_ExtEntry *entry, const void *val)
{
    (void)param;
    const HITLS_X509_RevokeExtTime *invalidTime = (const HITLS_X509_RevokeExtTime *)val;
    entry->critical = invalidTime->critical;
    BSL_ASN1_Buffer asns = {0};
    /**
     * According to Section 5.3.2 of RFC 5280.
     * The GeneralizedTime values included in this field MUST be expressed in Greenwich Mean Time (Zulu), and MUST
     * be specified and interpreted as defined in Section 4.1.2.5.2.
     */
    asns.tag = BSL_ASN1_TAG_GENERALIZEDTIME;
    asns.len = sizeof(BSL_TIME);
    asns.buff = (uint8_t *)(uintptr_t)&invalidTime->time;
    BSL_ASN1_TemplateItem templItem = {BSL_ASN1_TAG_CHOICE, 0, 0};
    BSL_ASN1_Template templ = {&templItem, 1};
    int32_t ret = BSL_ASN1_EncodeTemplate(&templ, &asns, 1, &entry->extnValue.buff, &entry->extnValue.len);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t SetExtReason(void *param, HITLS_X509_ExtEntry *extEntry, void *val)
{
    (void)param;
    HITLS_X509_RevokeExtReason *reason = (HITLS_X509_RevokeExtReason *)val;
    if (reason->reason < HITLS_X509_REVOKED_REASON_UNSPECIFIED ||
        reason->reason > HITLS_X509_REVOKED_REASON_AA_COMPROMISE ||
        reason->reason == HITLS_X509_REVOKED_REASON_UNUSED) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    extEntry->critical = reason->critical;
    uint8_t tmp = (uint8_t)reason->reason; // int32_t -> uint8_t: avoid value errors in bit-endian scenario
    BSL_ASN1_Buffer asns = {BSL_ASN1_TAG_ENUMERATED, sizeof(uint8_t), (uint8_t *)&tmp};
    BSL_ASN1_TemplateItem items = {BSL_ASN1_TAG_ENUMERATED, 0, 0};
    BSL_ASN1_Template reasonTempl = {&items, 1};

    int32_t ret = BSL_ASN1_EncodeTemplate(&reasonTempl, &asns, 1, &extEntry->extnValue.buff, &extEntry->extnValue.len);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}
#endif // HITLS_PKI_X509_CRL_GEN

static int32_t SetExtCertificateIssuer(void *param, HITLS_X509_ExtEntry *extEntry, void *val)
{
    (void)param;
    return HITLS_X509_SetGeneralNames(extEntry, val);
}

static int32_t DecodeExtInvalidTime(HITLS_X509_ExtEntry *extEntry, void *val)
{
    uint8_t *temp = extEntry->extnValue.buff;
    uint32_t tempLen = extEntry->extnValue.len;
    BSL_ASN1_Buffer asn = {0};
    BSL_ASN1_TemplateItem item = {BSL_ASN1_TAG_CHOICE, 0, 0};
    BSL_ASN1_Template templ = {&item, 1};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, HITLS_X509_CrlEntryChoiceCheck,
        &temp, &tempLen, &asn, 1);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BSL_ASN1_DecodePrimitiveItem(&asn, val);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }

    return ret;
}

static int32_t DecodeExtReason(HITLS_X509_ExtEntry *extEntry, void *val)
{
    uint8_t *temp = extEntry->extnValue.buff;
    uint32_t tempLen = extEntry->extnValue.len;
    BSL_ASN1_Buffer asn = {0};
    BSL_ASN1_TemplateItem item = {BSL_ASN1_TAG_ENUMERATED, 0, 0};
    BSL_ASN1_Template templ = {&item, 1};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, HITLS_X509_CrlEntryChoiceCheck,
        &temp, &tempLen, &asn, 1);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BSL_ASN1_DecodePrimitiveItem(&asn, val);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }

    return ret;
}

static int32_t DecodeExtCertIssuer(HITLS_X509_ExtEntry *extEntry, BslList **val)
{
    HITLS_X509_ExtSan san = {0};
    int32_t ret = HITLS_X509_ParseSubjectAltName(extEntry, &san);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *val = san.names;
    return HITLS_PKI_SUCCESS;
}

#ifdef HITLS_PKI_X509_CRL_GEN
static int32_t RevokedSet(HITLS_X509_CrlEntry *revoked, int32_t cmd, void *val, uint32_t valLen)
{
    if ((revoked->flag & HITLS_X509_CRL_PARSE_FLAG) != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_SET_AFTER_PARSE);
        return HITLS_X509_ERR_EXT_SET_AFTER_PARSE;
    }
    BSL_Buffer buff = {val, valLen};
    switch (cmd) {
        case HITLS_X509_CRL_SET_REVOKED_SERIALNUM:
            return HITLS_X509_SetSerial(&revoked->serialNumber, val, valLen);
        case HITLS_X509_CRL_SET_REVOKED_REVOKE_TIME:
            return CrlSetRevokeTime(revoked, val, valLen);
        case HITLS_X509_CRL_SET_REVOKED_INVALID_TIME:
            return X509_CrlSetRevokedExt(revoked, BSL_CID_CE_INVALIDITYDATE, &buff, sizeof(HITLS_X509_RevokeExtTime),
                (EncodeExtCb)SetExtInvalidTime);
        case HITLS_X509_CRL_SET_REVOKED_REASON:
            return X509_CrlSetRevokedExt(revoked, BSL_CID_CE_CRLREASONS, &buff, sizeof(HITLS_X509_RevokeExtReason),
                (EncodeExtCb)SetExtReason);
        case HITLS_X509_CRL_SET_REVOKED_CERTISSUER:
            return X509_CrlSetRevokedExt(revoked, BSL_CID_CE_CERTIFICATEISSUER, &buff,
                sizeof(HITLS_X509_RevokeExtCertIssuer), (EncodeExtCb)SetExtCertificateIssuer);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
            return HITLS_X509_ERR_INVALID_PARAM;
    }
}
#endif // HITLS_PKI_X509_CRL_GEN

static int32_t RevokedGet(HITLS_X509_CrlEntry *revoked, int32_t cmd, void *val, uint32_t valLen)
{
    BSL_Buffer buff = {val, valLen};
    switch (cmd) {
        case HITLS_X509_CRL_GET_REVOKED_REVOKE_TIME:
            return X509_CrlGetRevokedRevokeTime(revoked, val, valLen);
        case HITLS_X509_CRL_GET_REVOKED_SERIALNUM:
            return HITLS_X509_GetSerial(&revoked->serialNumber, val, valLen);
        case HITLS_X509_CRL_GET_REVOKED_INVALID_TIME:
            return HITLS_X509_GetExt(revoked->extList, BSL_CID_CE_INVALIDITYDATE, &buff, sizeof(BSL_TIME),
                (DecodeExtCb)DecodeExtInvalidTime);
        case HITLS_X509_CRL_GET_REVOKED_REASON:
            return HITLS_X509_GetExt(revoked->extList, BSL_CID_CE_CRLREASONS, &buff, sizeof(int32_t),
                (DecodeExtCb)DecodeExtReason);
        case HITLS_X509_CRL_GET_REVOKED_CERTISSUER:
            return HITLS_X509_GetExt(revoked->extList, BSL_CID_CE_CERTIFICATEISSUER, &buff, sizeof(BslList *),
                (DecodeExtCb)DecodeExtCertIssuer);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
            return HITLS_X509_ERR_INVALID_PARAM;
    }
}

int32_t HITLS_X509_CrlEntryCtrl(HITLS_X509_CrlEntry *revoked, int32_t cmd, void *val, uint32_t valLen)
{
    if (revoked == NULL || val == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
#ifdef HITLS_PKI_X509_CRL_GEN
    if (cmd < HITLS_X509_CRL_GET_REVOKED_SERIALNUM) {
        return RevokedSet(revoked, cmd, val, valLen);
    }
#endif
    return RevokedGet(revoked, cmd, val, valLen);
}

#ifdef HITLS_PKI_X509_CRL_GEN
static int32_t CrlSignCb(int32_t mdId, CRYPT_EAL_PkeyCtx *prvKey, HITLS_X509_Asn1AlgId *signAlgId, HITLS_X509_Crl *crl)
{
    BSL_Buffer signBuff = {0};
    BSL_ASN1_Buffer tbsCertList = {0};

    crl->signAlgId = *signAlgId;
    crl->tbs.signAlgId = *signAlgId;

    int32_t ret = HITLS_X509_EncodeCrlTbsRaw(&crl->tbs, &tbsCertList);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = HITLS_X509_SignAsn1Data(prvKey, mdId, &tbsCertList, &signBuff, &crl->signature);
    BSL_SAL_Free(tbsCertList.buff);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    crl->tbs.tbsRawData = signBuff.data;
    crl->tbs.tbsRawDataLen = signBuff.dataLen;
    crl->state = HITLS_X509_CRL_STATE_SIGN;
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_X509_CrlSign(int32_t mdId, const CRYPT_EAL_PkeyCtx *prvKey, const HITLS_X509_SignAlgParam *algParam,
    HITLS_X509_Crl *crl)
{
    if (crl == NULL || prvKey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    if ((crl->flag & HITLS_X509_CRL_PARSE_FLAG) != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_SIGN_AFTER_PARSE);
        return HITLS_X509_ERR_SIGN_AFTER_PARSE;
    }
    if (crl->state == HITLS_X509_CRL_STATE_SIGN || crl->state == HITLS_X509_CRL_STATE_GEN) {
        return HITLS_PKI_SUCCESS;
    }

    int32_t ret = X509_CheckCrlTbs(crl);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    BSL_SAL_FREE(crl->signature.buff);
    crl->signature.len = 0;
    BSL_SAL_FREE(crl->tbs.tbsRawData);
    crl->tbs.tbsRawDataLen = 0;
    BSL_SAL_FREE(crl->rawData);
    crl->rawDataLen = 0;

#ifdef HITLS_CRYPTO_SM2
    if (crl->signAlgId.algId == BSL_CID_SM2DSAWITHSM3) {
        BSL_SAL_FREE(crl->signAlgId.sm2UserId.data);
        crl->signAlgId.sm2UserId.dataLen = 0;
    }
#endif
    return HITLS_X509_Sign(mdId, prvKey, algParam, crl, (HITLS_X509_SignCb)CrlSignCb);
}
#endif // HITLS_PKI_X509_CRL_GEN
#endif // HITLS_PKI_X509_CRL
