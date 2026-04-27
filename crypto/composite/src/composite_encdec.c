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
#ifdef HITLS_CRYPTO_COMPOSITE
#include "bsl_asn1.h"
#include "crypt_utils.h"
#include "crypt_types.h"
#include "composite_local.h"


#define BSL_ASN1_TAG_EC_PRIKEY_PARAM 0
#define BSL_ASN1_TAG_EC_PRIKEY_PUBKEY 1

typedef enum {
    CRYPT_RSA_PUB_N_IDX = 0,
    CRYPT_RSA_PUB_E_IDX = 1,
} CRYPT_RSA_PUB_TEMPL_IDX;

typedef enum {
    CRYPT_ECPRIKEY_VERSION_IDX = 0,
    CRYPT_ECPRIKEY_PRIKEY_IDX = 1,
    CRYPT_ECPRIKEY_PARAM_IDX = 2,
    CRYPT_ECPRIKEY_PUBKEY_IDX = 3,
} CRYPT_ECPRIKEY_TEMPL_IDX;

typedef enum {
    CRYPT_RSA_PRV_VERSION_IDX = 0,
    CRYPT_RSA_PRV_N_IDX = 1,
    CRYPT_RSA_PRV_E_IDX = 2,
    CRYPT_RSA_PRV_D_IDX = 3,
    CRYPT_RSA_PRV_P_IDX = 4,
    CRYPT_RSA_PRV_Q_IDX = 5,
    CRYPT_RSA_PRV_DP_IDX = 6,
    CRYPT_RSA_PRV_DQ_IDX = 7,
    CRYPT_RSA_PRV_QINV_IDX = 8,
    CRYPT_RSA_PRV_OTHER_PRIME_IDX = 9
} CRYPT_RSA_PRV_TEMPL_IDX;

static BSL_ASN1_TemplateItem g_rsaPrvTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
    {BSL_ASN1_TAG_INTEGER, 0, 1},
    {BSL_ASN1_TAG_INTEGER, 0, 1},
    {BSL_ASN1_TAG_INTEGER, 0, 1},
    {BSL_ASN1_TAG_INTEGER, 0, 1},
    {BSL_ASN1_TAG_INTEGER, 0, 1},
    {BSL_ASN1_TAG_INTEGER, 0, 1},
    {BSL_ASN1_TAG_INTEGER, 0, 1},
    {BSL_ASN1_TAG_INTEGER, 0, 1},
    {BSL_ASN1_TAG_INTEGER, 0, 1},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE,
        BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_SAME, 1},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 2},
    {BSL_ASN1_TAG_INTEGER, 0, 3},
    {BSL_ASN1_TAG_INTEGER, 0, 3},
    {BSL_ASN1_TAG_INTEGER, 0, 3}
};

static BSL_ASN1_TemplateItem g_rsaPubTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
    {BSL_ASN1_TAG_INTEGER, 0, 1},
    {BSL_ASN1_TAG_INTEGER, 0, 1},
};

static BSL_ASN1_TemplateItem g_ecPriKeyTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
    {BSL_ASN1_TAG_INTEGER, 0, 1},
    {BSL_ASN1_TAG_OCTETSTRING, 0, 1},
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_EC_PRIKEY_PARAM,
        BSL_ASN1_FLAG_OPTIONAL, 1},
    {BSL_ASN1_TAG_OBJECT_ID, 0, 2},
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_EC_PRIKEY_PUBKEY,
        BSL_ASN1_FLAG_OPTIONAL, 1},
    {BSL_ASN1_TAG_BITSTRING, 0, 2},
};

static int32_t CRYPT_CompositeGetMldsaPrvKey(const CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    uint32_t prvLen = ctx->info->pqcPrvkeyLen;
    uint8_t *prv = (uint8_t *)BSL_SAL_Malloc(prvLen);
    RETURN_RET_IF(prv == NULL, CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF(ctx->pqcMethod->ctrl(ctx->pqcCtx, CRYPT_CTRL_GET_MLDSA_SEED, prv, prvLen), ret);
    encode->data = prv;
    encode->dataLen = prvLen;
    return CRYPT_SUCCESS;
ERR:
    BSL_SAL_Free(prv);
    return ret;
}

static int32_t CRYPT_CompositeGetMldsaPubKey(const CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    uint32_t pubLen = ctx->info->pqcPubkeyLen;
    uint8_t *pub = (uint8_t *)BSL_SAL_Malloc(pubLen);
    RETURN_RET_IF(pub == NULL, CRYPT_MEM_ALLOC_FAIL);
    BSL_Param param[2] = {{CRYPT_PARAM_ML_DSA_PUBKEY, BSL_PARAM_TYPE_OCTETS, pub, pubLen, 0}, BSL_PARAM_END};
    GOTO_ERR_IF(ctx->pqcMethod->getPub(ctx->pqcCtx, &param), ret);
    encode->data = pub;
    encode->dataLen = pubLen;
    return CRYPT_SUCCESS;
ERR:
    BSL_SAL_FREE(pub);
    return ret;
}

int32_t CRYPT_CompositeGetPqcPrvKey(const CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    switch (ctx->info->pqcAlg) {
        case CRYPT_PKEY_ML_DSA:
            return CRYPT_CompositeGetMldsaPrvKey(ctx, encode);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
            return CRYPT_NOT_SUPPORT;
    }
}

int32_t CRYPT_CompositeGetPqcPubKey(const CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    switch (ctx->info->pqcAlg) {
        case CRYPT_PKEY_ML_DSA:
            return CRYPT_CompositeGetMldsaPubKey(ctx, encode);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
            return CRYPT_NOT_SUPPORT;
    }
}

int32_t CRYPT_CompositeSetRsaPadding(CRYPT_CompositeCtx *ctx)
{
    int32_t ret;
    if (ctx->info->tradParam == BSL_CID_RSASSAPSS) {
        CRYPT_MD_AlgId mdId = ctx->info->tradHashId;
        CRYPT_MD_AlgId mgfId = ctx->info->tradHashId;
        int32_t saltLen = ctx->info->bits == 4096 ? 48 : 32;
        BSL_Param param[4] = {{CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
                              {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &mgfId, sizeof(mgfId), 0},
                              {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &saltLen, sizeof(saltLen), 0},
                              BSL_PARAM_END};
        ret = ctx->tradMethod->ctrl(ctx->tradCtx, CRYPT_CTRL_SET_RSA_EMSA_PSS, param, 0);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    } else {
        int32_t pkcsv15 = ctx->info->tradHashId;
        ret = ctx->tradMethod->ctrl(ctx->tradCtx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15));
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_CompositeGetRsaPrvKey(const CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    uint32_t bnLen = BITS_TO_BYTES(ctx->info->bits);
    uint32_t prvLen = bnLen * 8;
    uint8_t *pri = (uint8_t *)BSL_SAL_Malloc(prvLen);
    RETURN_RET_IF(pri == NULL, CRYPT_MEM_ALLOC_FAIL);
    BSL_Param param[] = {{CRYPT_PARAM_RSA_N, BSL_PARAM_TYPE_OCTETS, pri, bnLen, 0},
                         {CRYPT_PARAM_RSA_E, BSL_PARAM_TYPE_OCTETS, pri + bnLen, bnLen, 0},
                         {CRYPT_PARAM_RSA_D, BSL_PARAM_TYPE_OCTETS, pri + bnLen * 2, bnLen, 0},
                         {CRYPT_PARAM_RSA_P, BSL_PARAM_TYPE_OCTETS, pri + bnLen * 3, bnLen, 0},
                         {CRYPT_PARAM_RSA_Q, BSL_PARAM_TYPE_OCTETS, pri + bnLen * 4, bnLen, 0},
                         {CRYPT_PARAM_RSA_DP, BSL_PARAM_TYPE_OCTETS, pri + bnLen * 5, bnLen, 0},
                         {CRYPT_PARAM_RSA_DQ, BSL_PARAM_TYPE_OCTETS, pri + bnLen * 6, bnLen, 0},
                         {CRYPT_PARAM_RSA_QINV, BSL_PARAM_TYPE_OCTETS, pri + bnLen * 7, bnLen, 0},
                         BSL_PARAM_END};
    GOTO_ERR_IF(ctx->tradMethod->getPrv(ctx->tradCtx, &param), ret);
    BSL_ASN1_Buffer asn1[CRYPT_RSA_PRV_OTHER_PRIME_IDX + 1] = {0};
    uint8_t version = 0;
    asn1[CRYPT_RSA_PRV_VERSION_IDX].buff = (uint8_t *)&version;
    asn1[CRYPT_RSA_PRV_VERSION_IDX].len = sizeof(version);
    asn1[CRYPT_RSA_PRV_VERSION_IDX].tag = BSL_ASN1_TAG_INTEGER;
    asn1[CRYPT_RSA_PRV_N_IDX].buff = param[CRYPT_RSA_PRV_N_IDX-CRYPT_RSA_PRV_N_IDX].value;
    asn1[CRYPT_RSA_PRV_N_IDX].len = param[CRYPT_RSA_PRV_N_IDX-CRYPT_RSA_PRV_N_IDX].useLen;
    asn1[CRYPT_RSA_PRV_E_IDX].buff = param[CRYPT_RSA_PRV_E_IDX-CRYPT_RSA_PRV_N_IDX].value;
    asn1[CRYPT_RSA_PRV_E_IDX].len = param[CRYPT_RSA_PRV_E_IDX-CRYPT_RSA_PRV_N_IDX].useLen;
    asn1[CRYPT_RSA_PRV_D_IDX].buff = param[CRYPT_RSA_PRV_D_IDX-CRYPT_RSA_PRV_N_IDX].value;
    asn1[CRYPT_RSA_PRV_D_IDX].len = param[CRYPT_RSA_PRV_D_IDX-CRYPT_RSA_PRV_N_IDX].useLen;
    asn1[CRYPT_RSA_PRV_P_IDX].buff = param[CRYPT_RSA_PRV_P_IDX-CRYPT_RSA_PRV_N_IDX].value;
    asn1[CRYPT_RSA_PRV_P_IDX].len = param[CRYPT_RSA_PRV_P_IDX-CRYPT_RSA_PRV_N_IDX].useLen;
    asn1[CRYPT_RSA_PRV_Q_IDX].buff = param[CRYPT_RSA_PRV_Q_IDX-CRYPT_RSA_PRV_N_IDX].value;
    asn1[CRYPT_RSA_PRV_Q_IDX].len = param[CRYPT_RSA_PRV_Q_IDX-CRYPT_RSA_PRV_N_IDX].useLen;
    asn1[CRYPT_RSA_PRV_DP_IDX].buff = param[CRYPT_RSA_PRV_DP_IDX-CRYPT_RSA_PRV_N_IDX].value;
    asn1[CRYPT_RSA_PRV_DP_IDX].len = param[CRYPT_RSA_PRV_DP_IDX-CRYPT_RSA_PRV_N_IDX].useLen;
    asn1[CRYPT_RSA_PRV_DQ_IDX].buff = param[CRYPT_RSA_PRV_DQ_IDX-CRYPT_RSA_PRV_N_IDX].value;
    asn1[CRYPT_RSA_PRV_DQ_IDX].len = param[CRYPT_RSA_PRV_DQ_IDX-CRYPT_RSA_PRV_N_IDX].useLen;
    asn1[CRYPT_RSA_PRV_QINV_IDX].buff = param[CRYPT_RSA_PRV_QINV_IDX-CRYPT_RSA_PRV_N_IDX].value;
    asn1[CRYPT_RSA_PRV_QINV_IDX].len = param[CRYPT_RSA_PRV_QINV_IDX-CRYPT_RSA_PRV_N_IDX].useLen;
    asn1[CRYPT_RSA_PRV_D_IDX].tag = BSL_ASN1_TAG_INTEGER;
    asn1[CRYPT_RSA_PRV_N_IDX].tag = BSL_ASN1_TAG_INTEGER;
    asn1[CRYPT_RSA_PRV_E_IDX].tag = BSL_ASN1_TAG_INTEGER;
    asn1[CRYPT_RSA_PRV_P_IDX].tag = BSL_ASN1_TAG_INTEGER;
    asn1[CRYPT_RSA_PRV_Q_IDX].tag = BSL_ASN1_TAG_INTEGER;
    asn1[CRYPT_RSA_PRV_DP_IDX].tag = BSL_ASN1_TAG_INTEGER;
    asn1[CRYPT_RSA_PRV_DQ_IDX].tag = BSL_ASN1_TAG_INTEGER;
    asn1[CRYPT_RSA_PRV_QINV_IDX].tag = BSL_ASN1_TAG_INTEGER;

    BSL_ASN1_Template templ = {g_rsaPrvTempl, sizeof(g_rsaPrvTempl) / sizeof(g_rsaPrvTempl[0])};
    GOTO_ERR_IF(
        BSL_ASN1_EncodeTemplate(&templ, asn1, CRYPT_RSA_PRV_OTHER_PRIME_IDX + 1, &encode->data, &encode->dataLen), ret);
    BSL_SAL_ClearFree(pri, prvLen);
    return CRYPT_SUCCESS;
ERR:
    BSL_SAL_ClearFree(pri, prvLen);
    return ret;
}

static int32_t CRYPT_CompositeGetRsaPubKey(const CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    uint32_t bnLen = BITS_TO_BYTES(ctx->info->bits);
    uint8_t *n = (uint8_t *)BSL_SAL_Malloc(bnLen);
    RETURN_RET_IF(n == NULL, CRYPT_MEM_ALLOC_FAIL);
    uint8_t *e = (uint8_t *)BSL_SAL_Malloc(bnLen);
    if (e == NULL) {
        BSL_SAL_FREE(n);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    BSL_Param param[3] = {{CRYPT_PARAM_RSA_N, BSL_PARAM_TYPE_OCTETS, n, bnLen, 0},
                          {CRYPT_PARAM_RSA_E, BSL_PARAM_TYPE_OCTETS, e, bnLen, 0},
                          BSL_PARAM_END};
    GOTO_ERR_IF(ctx->tradMethod->getPub(ctx->tradCtx, &param), ret);

    BSL_ASN1_Buffer pubAsn1[CRYPT_RSA_PUB_E_IDX + 1] = {
        {BSL_ASN1_TAG_INTEGER, param[0].useLen, n},
        {BSL_ASN1_TAG_INTEGER, param[1].useLen, e},
    };
    BSL_ASN1_Template pubTempl = {g_rsaPubTempl, sizeof(g_rsaPubTempl) / sizeof(g_rsaPubTempl[0])};
    GOTO_ERR_IF(BSL_ASN1_EncodeTemplate(&pubTempl, pubAsn1, CRYPT_RSA_PUB_E_IDX + 1, &encode->data, &encode->dataLen),
                ret);
    BSL_SAL_FREE(n);
    BSL_SAL_FREE(e);
    return CRYPT_SUCCESS;

ERR:
    BSL_SAL_FREE(n);
    BSL_SAL_FREE(e);
    return ret;
}

static int32_t CRYPT_CompositeGetEcdsaPrvKey(const CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    uint32_t keyLen = 0;
    BslOidString *oid = BSL_OBJ_GetOID((BslCid)ctx->info->tradParam);
    RETURN_RET_IF(oid == NULL, CRYPT_ERR_ALGID);
    RETURN_RET_IF_ERR(ctx->tradMethod->ctrl(ctx->tradCtx, CRYPT_CTRL_GET_PRVKEY_LEN, &keyLen, sizeof(keyLen)), ret);
    RETURN_RET_IF(keyLen == 0, CRYPT_EAL_ALG_NOT_SUPPORT);
    uint8_t *pri = (uint8_t *)BSL_SAL_Malloc(keyLen);
    RETURN_RET_IF(pri == NULL, CRYPT_MEM_ALLOC_FAIL);
    BSL_Param param[2] = {{CRYPT_PARAM_EC_PRVKEY, BSL_PARAM_TYPE_OCTETS, pri, keyLen, 0}, BSL_PARAM_END};
    GOTO_ERR_IF(ctx->tradMethod->getPrv(ctx->tradCtx, &param), ret);
    uint8_t version = 1;
    BSL_ASN1_Buffer asn1[CRYPT_ECPRIKEY_PUBKEY_IDX + 1] = {
        {BSL_ASN1_TAG_INTEGER, sizeof(version), &version}, {0}, {0}, {0}};

    asn1[CRYPT_ECPRIKEY_PARAM_IDX].buff = (uint8_t *)oid->octs;
    asn1[CRYPT_ECPRIKEY_PARAM_IDX].len = oid->octetLen;
    asn1[CRYPT_ECPRIKEY_PARAM_IDX].tag = BSL_ASN1_TAG_OBJECT_ID;

    asn1[CRYPT_ECPRIKEY_PRIKEY_IDX].tag = BSL_ASN1_TAG_OCTETSTRING;
    asn1[CRYPT_ECPRIKEY_PRIKEY_IDX].len = param[0].useLen;
    asn1[CRYPT_ECPRIKEY_PRIKEY_IDX].buff = pri;
    BSL_ASN1_Template templ = {g_ecPriKeyTempl, sizeof(g_ecPriKeyTempl) / sizeof(g_ecPriKeyTempl[0])};
    GOTO_ERR_IF(BSL_ASN1_EncodeTemplate(&templ, asn1, CRYPT_ECPRIKEY_PUBKEY_IDX + 1, &encode->data, &encode->dataLen),
                ret);
    BSL_SAL_ClearFree(pri, keyLen);
    return CRYPT_SUCCESS;
ERR:
    BSL_SAL_ClearFree(pri, keyLen);
    return ret;
}

static int32_t CRYPT_CompositeGetEcdsaPubKey(const CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    uint32_t pubLen = 0;
    RETURN_RET_IF_ERR(ctx->tradMethod->ctrl(ctx->tradCtx, CRYPT_CTRL_GET_PUBKEY_LEN, &pubLen, sizeof(pubLen)), ret);
    RETURN_RET_IF(pubLen == 0, CRYPT_EAL_ALG_NOT_SUPPORT);
    uint8_t *pub = (uint8_t *)BSL_SAL_Malloc(pubLen);
    RETURN_RET_IF(pub == NULL, CRYPT_MEM_ALLOC_FAIL);
    BSL_Param param[2] = {{CRYPT_PARAM_EC_PUBKEY, BSL_PARAM_TYPE_OCTETS, pub, pubLen, 0}, BSL_PARAM_END};
    ret = ctx->tradMethod->getPub(ctx->tradCtx, &param);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_FREE(pub);
        return ret;
    }
    encode->data = pub;
    encode->dataLen = param[0].useLen;
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_CompositeGetEd25519PrvKey(const CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    uint32_t prvLen = 0;
    RETURN_RET_IF_ERR(ctx->tradMethod->ctrl(ctx->tradCtx, CRYPT_CTRL_GET_PRVKEY_LEN, &prvLen, sizeof(prvLen)), ret);
    uint8_t *prv = (uint8_t *)BSL_SAL_Malloc(prvLen);
    RETURN_RET_IF(prv == NULL, CRYPT_MEM_ALLOC_FAIL);
    BSL_Param param[2] = {{CRYPT_PARAM_CURVE25519_PRVKEY, BSL_PARAM_TYPE_OCTETS, prv, prvLen, 0}, BSL_PARAM_END};
    ret = ctx->tradMethod->getPrv(ctx->tradCtx, &param);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_FREE(prv);
        return ret;
    }
    encode->data = param[0].value;
    encode->dataLen = param[0].useLen;
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_CompositeGetEd25519PubKey(const CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    uint32_t pubLen = 0;
    RETURN_RET_IF_ERR(ctx->tradMethod->ctrl(ctx->tradCtx, CRYPT_CTRL_GET_PUBKEY_LEN, &pubLen, sizeof(pubLen)), ret);
    RETURN_RET_IF(pubLen == 0, CRYPT_EAL_ALG_NOT_SUPPORT);
    uint8_t *pub = (uint8_t *)BSL_SAL_Malloc(pubLen);
    RETURN_RET_IF(pub == NULL, CRYPT_MEM_ALLOC_FAIL);
    BSL_Param param[2] = {{CRYPT_PARAM_CURVE25519_PUBKEY, BSL_PARAM_TYPE_OCTETS, pub, pubLen, 0}, BSL_PARAM_END};
    ret = ctx->tradMethod->getPub(ctx->tradCtx, &param);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_FREE(pub);
        return ret;
    }
    encode->data = pub;
    encode->dataLen = param[0].useLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_CompositeGetTradPrvKey(const CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    switch (ctx->info->tradAlg) {
        case CRYPT_PKEY_RSA:
            return CRYPT_CompositeGetRsaPrvKey(ctx, encode);
        case CRYPT_PKEY_ECDSA:
            return CRYPT_CompositeGetEcdsaPrvKey(ctx, encode);
        case CRYPT_PKEY_ED25519:
            return CRYPT_CompositeGetEd25519PrvKey(ctx, encode);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
            return CRYPT_NOT_SUPPORT;
    }
}

int32_t CRYPT_CompositeGetTradPubKey(const CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    switch (ctx->info->tradAlg) {
        case CRYPT_PKEY_RSA:
            return CRYPT_CompositeGetRsaPubKey(ctx, encode);
        case CRYPT_PKEY_ECDSA:
            return CRYPT_CompositeGetEcdsaPubKey(ctx, encode);
        case CRYPT_PKEY_ED25519:
            return CRYPT_CompositeGetEd25519PubKey(ctx, encode);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
            return CRYPT_NOT_SUPPORT;
    }
}

static int32_t CRYPT_CompositeSetMldsaPrvKey(CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    BSL_Param param[2] = {
        {CRYPT_PARAM_ML_DSA_PRVKEY_SEED, BSL_PARAM_TYPE_OCTETS, encode->data, encode->dataLen, 0},
        BSL_PARAM_END};
    RETURN_RET_IF_ERR(ctx->pqcMethod->setPrv(ctx->pqcCtx, &param), ret);
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_CompositeSetMldsaPubKey(CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    BSL_Param param[2] = {
        {CRYPT_PARAM_ML_DSA_PUBKEY, BSL_PARAM_TYPE_OCTETS, encode->data, encode->dataLen, 0},
        BSL_PARAM_END};
    RETURN_RET_IF_ERR(ctx->pqcMethod->setPub(ctx->pqcCtx, &param), ret);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_CompositeSetPqcPrvKey(CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    switch (ctx->info->pqcAlg) {
        case CRYPT_PKEY_ML_DSA:
            return CRYPT_CompositeSetMldsaPrvKey(ctx, encode);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
            return CRYPT_NOT_SUPPORT;
    }
}
int32_t CRYPT_CompositeSetPqcPubKey(CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    switch (ctx->info->pqcAlg) {
        case CRYPT_PKEY_ML_DSA:
            return CRYPT_CompositeSetMldsaPubKey(ctx, encode);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
            return CRYPT_NOT_SUPPORT;
    }
}

static int32_t CRYPT_CompositeSetRsaPrvKey(CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    BSL_ASN1_Buffer asn1[CRYPT_RSA_PRV_OTHER_PRIME_IDX + 1] = {0};
    BSL_ASN1_Template templ = {g_rsaPrvTempl, sizeof(g_rsaPrvTempl) / sizeof(g_rsaPrvTempl[0])};
    RETURN_RET_IF_ERR(
        BSL_ASN1_DecodeTemplate(&templ, NULL, &encode->data, &encode->dataLen, asn1, CRYPT_RSA_PRV_OTHER_PRIME_IDX + 1),
        ret);
    BSL_Param rsaParam[] = {
        {CRYPT_PARAM_RSA_D, BSL_PARAM_TYPE_OCTETS, asn1[CRYPT_RSA_PRV_D_IDX].buff, asn1[CRYPT_RSA_PRV_D_IDX].len, 0},
        {CRYPT_PARAM_RSA_N, BSL_PARAM_TYPE_OCTETS, asn1[CRYPT_RSA_PRV_N_IDX].buff, asn1[CRYPT_RSA_PRV_N_IDX].len, 0},
        {CRYPT_PARAM_RSA_P, BSL_PARAM_TYPE_OCTETS, asn1[CRYPT_RSA_PRV_P_IDX].buff, asn1[CRYPT_RSA_PRV_P_IDX].len, 0},
        {CRYPT_PARAM_RSA_Q, BSL_PARAM_TYPE_OCTETS, asn1[CRYPT_RSA_PRV_Q_IDX].buff, asn1[CRYPT_RSA_PRV_Q_IDX].len, 0},
        {CRYPT_PARAM_RSA_DP, BSL_PARAM_TYPE_OCTETS, asn1[CRYPT_RSA_PRV_DP_IDX].buff, asn1[CRYPT_RSA_PRV_DP_IDX].len, 0},
        {CRYPT_PARAM_RSA_DQ, BSL_PARAM_TYPE_OCTETS, asn1[CRYPT_RSA_PRV_DQ_IDX].buff, asn1[CRYPT_RSA_PRV_DQ_IDX].len, 0},
        {CRYPT_PARAM_RSA_QINV, BSL_PARAM_TYPE_OCTETS, asn1[CRYPT_RSA_PRV_QINV_IDX].buff,
         asn1[CRYPT_RSA_PRV_QINV_IDX].len, 0},
        {CRYPT_PARAM_RSA_E, BSL_PARAM_TYPE_OCTETS, asn1[CRYPT_RSA_PRV_E_IDX].buff, asn1[CRYPT_RSA_PRV_E_IDX].len, 0},
        BSL_PARAM_END};
    RETURN_RET_IF_ERR(ctx->tradMethod->setPrv(ctx->tradCtx, &rsaParam), ret);
    RETURN_RET_IF_ERR(ctx->tradMethod->setPub(ctx->tradCtx, &rsaParam), ret);
    RETURN_RET_IF_ERR(CRYPT_CompositeSetRsaPadding(ctx), ret);
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_CompositeSetRsaPubKey(CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    BSL_ASN1_Buffer asn1[CRYPT_RSA_PUB_E_IDX + 1] = {0};
    BSL_ASN1_Template pubTempl = {g_rsaPubTempl, sizeof(g_rsaPubTempl) / sizeof(g_rsaPubTempl[0])};
    RETURN_RET_IF_ERR(
        BSL_ASN1_DecodeTemplate(&pubTempl, NULL, &encode->data, &encode->dataLen, asn1, CRYPT_RSA_PUB_E_IDX + 1), ret);
    BSL_Param rsaParam[] = {
        {CRYPT_PARAM_RSA_E, BSL_PARAM_TYPE_OCTETS, asn1[CRYPT_RSA_PUB_E_IDX].buff, asn1[CRYPT_RSA_PUB_E_IDX].len, 0},
        {CRYPT_PARAM_RSA_N, BSL_PARAM_TYPE_OCTETS, asn1[CRYPT_RSA_PUB_N_IDX].buff, asn1[CRYPT_RSA_PUB_N_IDX].len, 0},
        BSL_PARAM_END};
    RETURN_RET_IF_ERR(ctx->tradMethod->setPub(ctx->tradCtx, &rsaParam), ret);
    RETURN_RET_IF_ERR(CRYPT_CompositeSetRsaPadding(ctx), ret);
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_CompositeSetEcdsaPrvKey(CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    BSL_ASN1_Buffer asn1[CRYPT_ECPRIKEY_PUBKEY_IDX + 1] = {0};
    BSL_ASN1_Template templ = {g_ecPriKeyTempl, sizeof(g_ecPriKeyTempl) / sizeof(g_ecPriKeyTempl[0])};
    RETURN_RET_IF_ERR(
        BSL_ASN1_DecodeTemplate(&templ, NULL, &encode->data, &encode->dataLen, asn1, CRYPT_ECPRIKEY_PUBKEY_IDX + 1),
        ret);
    BSL_Param ecParam[2] = {{CRYPT_PARAM_EC_PRVKEY, BSL_PARAM_TYPE_OCTETS, asn1[CRYPT_ECPRIKEY_PRIKEY_IDX].buff,
                             asn1[CRYPT_ECPRIKEY_PRIKEY_IDX].len, 0},
                            BSL_PARAM_END};
    RETURN_RET_IF_ERR(ctx->tradMethod->setPrv(ctx->tradCtx, &ecParam), ret);
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_CompositeSetEcdsaPubKey(CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    BSL_Param param[2] = {{CRYPT_PARAM_EC_PUBKEY, BSL_PARAM_TYPE_OCTETS, encode->data, encode->dataLen, 0},
                          BSL_PARAM_END};
    RETURN_RET_IF_ERR(ctx->tradMethod->setPub(ctx->tradCtx, &param), ret);
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_CompositeSetEd25519PrvKey(CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    BSL_Param para[2] = {{CRYPT_PARAM_CURVE25519_PRVKEY, BSL_PARAM_TYPE_OCTETS, encode->data, encode->dataLen, 0},
                         BSL_PARAM_END};
    RETURN_RET_IF_ERR(ctx->tradMethod->setPrv(ctx->tradCtx, &para), ret);
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_CompositeSetEd25519PubKey(CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    BSL_Param param[2] = {{CRYPT_PARAM_CURVE25519_PUBKEY, BSL_PARAM_TYPE_OCTETS, encode->data, encode->dataLen, 0},
                          BSL_PARAM_END};
    RETURN_RET_IF_ERR(ctx->tradMethod->setPub(ctx->tradCtx, &param), ret);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_CompositeSetTradPrvKey(CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    switch (ctx->info->tradAlg) {
        case CRYPT_PKEY_RSA:
            return CRYPT_CompositeSetRsaPrvKey(ctx, encode);
        case CRYPT_PKEY_ECDSA:
            return CRYPT_CompositeSetEcdsaPrvKey(ctx, encode);
        case CRYPT_PKEY_ED25519:
            return CRYPT_CompositeSetEd25519PrvKey(ctx, encode);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
            return CRYPT_NOT_SUPPORT;
    }
}

int32_t CRYPT_CompositeSetTradPubKey(CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    switch (ctx->info->tradAlg) {
        case CRYPT_PKEY_RSA:
            return CRYPT_CompositeSetRsaPubKey(ctx, encode);
        case CRYPT_PKEY_ECDSA:
            return CRYPT_CompositeSetEcdsaPubKey(ctx, encode);
        case CRYPT_PKEY_ED25519:
            return CRYPT_CompositeSetEd25519PubKey(ctx, encode);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
            return CRYPT_NOT_SUPPORT;
    }
}
#endif /* HITLS_CRYPTO_COMPOSITE */
