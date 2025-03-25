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
#ifdef HITLS_CRYPTO_KEY_GEN
#include "securec.h"
#include "bsl_asn1.h"
#include "bsl_err_internal.h"
#include "bsl_obj_internal.h"
#include "crypt_errno.h"
#include "crypt_algid.h"
#include "crypt_encode.h"

int32_t EncodeHashAlg(CRYPT_MD_AlgId mdId, BSL_ASN1_Buffer *asn)
{
    if (mdId == CRYPT_MD_SHA1) {
        asn->tag = BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | CRYPT_ASN1_CTX_SPECIFIC_TAG_RSAPSS_HASH;
        asn->buff = NULL;
        asn->len = 0;
        return CRYPT_SUCCESS;
    }
    BSL_ASN1_Buffer asnArr[2] = {0};
    BslOidString *oidStr = BSL_OBJ_GetOidFromCID((BslCid)mdId);
    if (oidStr == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ERR_ALGID);
        return CRYPT_ERR_ALGID;
    }
    asnArr[0].tag = BSL_ASN1_TAG_OBJECT_ID;
    asnArr[0].len = oidStr->octetLen;
    asnArr[0].buff = (uint8_t *)oidStr->octs;
    asnArr[1].tag = BSL_ASN1_TAG_NULL;

    BSL_ASN1_TemplateItem hashTempl[] = {
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
            {BSL_ASN1_TAG_OBJECT_ID, 0, 1},
            {BSL_ASN1_TAG_ANY, BSL_ASN1_FLAG_OPTIONAL, 1},
    };
    BSL_ASN1_Template templ = {hashTempl, sizeof(hashTempl) / sizeof(hashTempl[0])};
    int32_t ret = BSL_ASN1_EncodeTemplate(&templ, asnArr, 2, &(asn->buff), &(asn->len));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    asn->tag = BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | CRYPT_ASN1_CTX_SPECIFIC_TAG_RSAPSS_HASH;
    return CRYPT_SUCCESS;
}

static int32_t EncodeMgfAlg(CRYPT_MD_AlgId mgfId, BSL_ASN1_Buffer *asn)
{
    if (mgfId == CRYPT_MD_SHA1) {
        asn->tag = BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | CRYPT_ASN1_CTX_SPECIFIC_TAG_RSAPSS_MASKGEN;
        asn->buff = NULL;
        asn->len = 0;
        return CRYPT_SUCCESS;
    }
    BSL_ASN1_Buffer asnArr[3] = {0};
    BslOidString *mgfStr = BSL_OBJ_GetOidFromCID(BSL_CID_MGF1);
    if (mgfStr == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ERR_ALGID);
        return CRYPT_ERR_ALGID;
    }
    asnArr[0].tag = BSL_ASN1_TAG_OBJECT_ID;
    asnArr[0].len =  mgfStr->octetLen;
    asnArr[0].buff = (uint8_t *)mgfStr->octs;
    BslOidString *oidStr = BSL_OBJ_GetOidFromCID((BslCid)mgfId);
    if (oidStr == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ERR_ALGID);
        return CRYPT_ERR_ALGID;
    }
    asnArr[1].tag = BSL_ASN1_TAG_OBJECT_ID;
    asnArr[1].len = oidStr->octetLen;
    asnArr[1].buff = (uint8_t *)oidStr->octs;
    asnArr[2].tag = BSL_ASN1_TAG_NULL; // 2 : param
    BSL_ASN1_TemplateItem mgfTempl[] = {
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
            {BSL_ASN1_TAG_OBJECT_ID, 0, 1},
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1},
                {BSL_ASN1_TAG_OBJECT_ID, 0, 2},
                {BSL_ASN1_TAG_ANY, BSL_ASN1_FLAG_OPTIONAL, 2},
    };
    BSL_ASN1_Template templ = {mgfTempl, sizeof(mgfTempl) / sizeof(mgfTempl[0])};
    int32_t ret = BSL_ASN1_EncodeTemplate(&templ, asnArr, 3, &(asn->buff), &(asn->len));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    asn->tag = BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | CRYPT_ASN1_CTX_SPECIFIC_TAG_RSAPSS_MASKGEN;
    return CRYPT_SUCCESS;
}

static int32_t EncodeSaltLen(int32_t saltLen, BSL_ASN1_Buffer *asn)
{
    if (saltLen == 20) { // 20 : default saltLen
        asn->tag = BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED |
            CRYPT_ASN1_CTX_SPECIFIC_TAG_RSAPSS_SALTLEN;
        asn->buff = NULL;
        asn->len = 0;
        return CRYPT_SUCCESS;
    }
    BSL_ASN1_Buffer saltAsn = {0};
    int32_t ret = BSL_ASN1_EncodeLimb(BSL_ASN1_TAG_INTEGER, (uint64_t)saltLen, &saltAsn);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_ASN1_TemplateItem saltTempl = {BSL_ASN1_TAG_INTEGER, 0, 0};
    BSL_ASN1_Template templ = {&saltTempl, 1};
    ret = BSL_ASN1_EncodeTemplate(&templ, &saltAsn, 1, &(asn->buff), &(asn->len));
    BSL_SAL_Free(saltAsn.buff);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    asn->tag = BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | CRYPT_ASN1_CTX_SPECIFIC_TAG_RSAPSS_SALTLEN;
    return CRYPT_SUCCESS;
}

#define X509_RSAPSS_ELEM_NUMBER 4
int32_t CRYPT_EAL_EncodeRsaPssAlgParam(CRYPT_RSA_PssPara *rsaPssParam, uint8_t **buf, uint32_t *bufLen)
{
    BSL_ASN1_Buffer asnArr[X509_RSAPSS_ELEM_NUMBER] = {0};
    int32_t ret = EncodeHashAlg(rsaPssParam->mdId, &asnArr[0]);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = EncodeMgfAlg(rsaPssParam->mgfId, &asnArr[1]);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }

    ret = EncodeSaltLen(rsaPssParam->saltLen, &asnArr[2]); // 2: saltLength
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    if (asnArr[0].len + asnArr[1].len + asnArr[2].len == 0) { // [0]:hash + [1]:mgf + [2]:salt all default
        return ret;
    }
    // 3 : trailed
    asnArr[3].tag = BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | CRYPT_ASN1_CTX_SPECIFIC_TAG_RSAPSS_TRAILED;
    BSL_ASN1_TemplateItem rsapssTempl[] = {
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | CRYPT_ASN1_CTX_SPECIFIC_TAG_RSAPSS_HASH,
            BSL_ASN1_FLAG_DEFAULT, 0},
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | CRYPT_ASN1_CTX_SPECIFIC_TAG_RSAPSS_MASKGEN,
            BSL_ASN1_FLAG_DEFAULT, 0},
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | CRYPT_ASN1_CTX_SPECIFIC_TAG_RSAPSS_SALTLEN,
            BSL_ASN1_FLAG_DEFAULT, 0},
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | CRYPT_ASN1_CTX_SPECIFIC_TAG_RSAPSS_TRAILED,
            BSL_ASN1_FLAG_DEFAULT, 0},
    };
    BSL_ASN1_Template templ = {rsapssTempl, sizeof(rsapssTempl) / sizeof(rsapssTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asnArr, X509_RSAPSS_ELEM_NUMBER, buf, bufLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
EXIT:
    for (uint32_t i = 0; i < X509_RSAPSS_ELEM_NUMBER; i++) {
        BSL_SAL_Free(asnArr[i].buff);
    }
    return ret;
}

#endif // HITLS_CRYPTO_KEY_GEN
