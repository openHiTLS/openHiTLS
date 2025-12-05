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
#ifdef HITLS_CRYPTO_CODECSKEY

#include "securec.h"
#include "bsl_asn1_internal.h"
#include "bsl_params.h"
#include "bsl_err_internal.h"
#include "bsl_obj_internal.h"
#include "crypt_errno.h"
#include "crypt_types.h"
#include "crypt_algid.h"
#include "crypt_eal_kdf.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_cipher.h"
#include "crypt_params_key.h"
#include "crypt_codecskey.h"
#include "crypt_codecskey_local.h"

#if defined(HITLS_CRYPTO_KEY_EPKI) && defined(HITLS_CRYPTO_KEY_ENCODE)
/**
 *  EncryptedPrivateKeyInfo ::= SEQUENCE {
 *      encryptionAlgorithm  EncryptionAlgorithmIdentifier,
 *      encryptedData        EncryptedData }
 *
 * https://datatracker.ietf.org/doc/html/rfc5208#autoid-6
*/
static BSL_ASN1_TemplateItem g_pk8EncPriKeyTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1}, // EncryptionAlgorithmIdentifier
            {BSL_ASN1_TAG_OBJECT_ID, 0, 2},
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 2},
                {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 3}, // derivation param
                {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 3}, // enc scheme
                    {BSL_ASN1_TAG_OBJECT_ID, 0, 4}, // alg
                    {BSL_ASN1_TAG_OCTETSTRING, 0, 4}, // iv
        {BSL_ASN1_TAG_OCTETSTRING, 0, 1}, // EncryptedData
};
#endif // HITLS_CRYPTO_KEY_EPKI && HITLS_CRYPTO_KEY_ENCODE

#if defined(HITLS_CRYPTO_RSA) && (defined(HITLS_CRYPTO_KEY_ENCODE) || defined(HITLS_CRYPTO_KEY_INFO))
int32_t CRYPT_EAL_GetRsaPssPara(CRYPT_EAL_PkeyCtx *key, CRYPT_RSA_PssPara *para)
{
    int32_t ret = CRYPT_EAL_PkeyCtrl(key, CRYPT_CTRL_GET_RSA_SALTLEN, &para->saltLen, sizeof(para->saltLen));
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CRYPT_EAL_PkeyCtrl(key, CRYPT_CTRL_GET_RSA_MD, &para->mdId, sizeof(para->mdId));
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CRYPT_EAL_PkeyCtrl(key, CRYPT_CTRL_GET_RSA_MGF, &para->mgfId, sizeof(para->mgfId));
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t CRYPT_EAL_InitRsaPrv(const CRYPT_EAL_PkeyCtx *ealPriKey, CRYPT_PKEY_AlgId cid, CRYPT_EAL_PkeyPrv *rsaPrv)
{
    uint32_t bnLen = CRYPT_EAL_PkeyGetKeyLen(ealPriKey);
    if (bnLen == 0) {
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    uint8_t *pri = (uint8_t *)BSL_SAL_Malloc(bnLen * 8); // 8 items
    if (pri == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    rsaPrv->id = cid;
    rsaPrv->key.rsaPrv.d = pri;
    rsaPrv->key.rsaPrv.n = pri + bnLen;
    rsaPrv->key.rsaPrv.p = pri + bnLen * 2; // 2nd buffer
    rsaPrv->key.rsaPrv.q = pri + bnLen * 3; // 3rd buffer
    rsaPrv->key.rsaPrv.dP = pri + bnLen * 4; // 4th buffer
    rsaPrv->key.rsaPrv.dQ = pri + bnLen * 5; // 5th buffer
    rsaPrv->key.rsaPrv.qInv = pri + bnLen * 6; // 6th buffer
    rsaPrv->key.rsaPrv.e = pri + bnLen * 7; // 7th buffer

    rsaPrv->key.rsaPrv.dLen = bnLen;
    rsaPrv->key.rsaPrv.nLen = bnLen;
    rsaPrv->key.rsaPrv.pLen = bnLen;
    rsaPrv->key.rsaPrv.qLen = bnLen;
    rsaPrv->key.rsaPrv.dPLen = bnLen;
    rsaPrv->key.rsaPrv.dQLen = bnLen;
    rsaPrv->key.rsaPrv.qInvLen = bnLen;
    rsaPrv->key.rsaPrv.eLen = bnLen;
    return CRYPT_SUCCESS;
}

void CRYPT_EAL_DeinitRsaPrv(CRYPT_EAL_PkeyPrv *rsaPrv)
{
    BSL_SAL_ClearFree(rsaPrv->key.rsaPrv.d, rsaPrv->key.rsaPrv.dLen * 8); // 8 items
}
#endif // HITLS_CRYPTO_RSA

#ifdef HITLS_CRYPTO_KEY_DECODE
#ifdef HITLS_CRYPTO_RSA
static int32_t ProcRsaPssParam(BSL_ASN1_Buffer *rsaPssParam, CRYPT_EAL_PkeyCtx *ealPriKey)
{
    CRYPT_RsaPadType padType = CRYPT_EMSA_PSS;
    int32_t ret = CRYPT_EAL_PkeyCtrl(ealPriKey, CRYPT_CTRL_SET_RSA_PADDING, &padType, sizeof(CRYPT_RsaPadType));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (rsaPssParam == NULL || rsaPssParam->buff == NULL) {
        return CRYPT_SUCCESS;
    }

    CRYPT_RSA_PssPara para = {0};
    ret = CRYPT_EAL_ParseRsaPssAlgParam(rsaPssParam, &para);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    BSL_Param param[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &para.mdId, sizeof(para.mdId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &para.mgfId, sizeof(para.mgfId), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &para.saltLen, sizeof(para.saltLen), 0},
        BSL_PARAM_END};
    return CRYPT_EAL_PkeyCtrl(ealPriKey, CRYPT_CTRL_SET_RSA_EMSA_PSS, param, 0);
}

static int32_t SetRsaPubKey(const BSL_ASN1_Buffer *n, const BSL_ASN1_Buffer *e, CRYPT_EAL_PkeyCtx *ealPkey)
{
    CRYPT_EAL_PkeyPub rsaPub = {
        .id = CRYPT_PKEY_RSA, .key.rsaPub = {.n = n->buff, .nLen = n->len, .e = e->buff, .eLen = e->len}};
    return CRYPT_EAL_PkeySetPub(ealPkey, &rsaPub);
}

int32_t ParseRsaPubkeyAsn1Buff(CRYPT_EAL_LibCtx *libctx, const char *attrName, uint8_t *buff, uint32_t buffLen,
    BSL_ASN1_Buffer *param, CRYPT_EAL_PkeyCtx **ealPubKey, BslCid cid)
{
    // decode n and e
    BSL_ASN1_Buffer pubAsn1[CRYPT_RSA_PUB_E_IDX + 1] = {0};
    int32_t ret = CRYPT_DECODE_RsaPubkeyAsn1Buff(buff, buffLen, pubAsn1, CRYPT_RSA_PUB_E_IDX + 1);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    CRYPT_EAL_PkeyCtx *pctx = CRYPT_EAL_ProviderPkeyNewCtx(libctx, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_UNKNOWN_OPERATE,
        attrName);
    if (pctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = SetRsaPubKey(pubAsn1 + CRYPT_RSA_PUB_N_IDX, pubAsn1 + CRYPT_RSA_PUB_E_IDX, pctx);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pctx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (cid != BSL_CID_RSASSAPSS) {
        *ealPubKey = pctx;
        return CRYPT_SUCCESS;
    }

    ret = ProcRsaPssParam(param, pctx);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pctx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    *ealPubKey = pctx;
    return ret;
}

static int32_t ProcEalRsaPrivKey(const BSL_ASN1_Buffer *asn1, CRYPT_EAL_PkeyCtx *ealPkey)
{
    CRYPT_EAL_PkeyPrv rsaPrv = {0};
    rsaPrv.id = CRYPT_PKEY_RSA;
    rsaPrv.key.rsaPrv.d = asn1[CRYPT_RSA_PRV_D_IDX].buff;
    rsaPrv.key.rsaPrv.dLen = asn1[CRYPT_RSA_PRV_D_IDX].len;
    rsaPrv.key.rsaPrv.n = asn1[CRYPT_RSA_PRV_N_IDX].buff;
    rsaPrv.key.rsaPrv.nLen = asn1[CRYPT_RSA_PRV_N_IDX].len;
    rsaPrv.key.rsaPrv.e = asn1[CRYPT_RSA_PRV_E_IDX].buff;
    rsaPrv.key.rsaPrv.eLen = asn1[CRYPT_RSA_PRV_E_IDX].len;
    rsaPrv.key.rsaPrv.p = asn1[CRYPT_RSA_PRV_P_IDX].buff;
    rsaPrv.key.rsaPrv.pLen = asn1[CRYPT_RSA_PRV_P_IDX].len;
    rsaPrv.key.rsaPrv.q = asn1[CRYPT_RSA_PRV_Q_IDX].buff;
    rsaPrv.key.rsaPrv.qLen = asn1[CRYPT_RSA_PRV_Q_IDX].len;
    rsaPrv.key.rsaPrv.dP = asn1[CRYPT_RSA_PRV_DP_IDX].buff;
    rsaPrv.key.rsaPrv.dPLen = asn1[CRYPT_RSA_PRV_DP_IDX].len;
    rsaPrv.key.rsaPrv.dQ = asn1[CRYPT_RSA_PRV_DQ_IDX].buff;
    rsaPrv.key.rsaPrv.dQLen = asn1[CRYPT_RSA_PRV_DQ_IDX].len;
    rsaPrv.key.rsaPrv.qInv = asn1[CRYPT_RSA_PRV_QINV_IDX].buff;
    rsaPrv.key.rsaPrv.qInvLen = asn1[CRYPT_RSA_PRV_QINV_IDX].len;

    return CRYPT_EAL_PkeySetPrv(ealPkey, &rsaPrv);
}

static int32_t ProcEalRsaKeyPair(uint8_t *buff, uint32_t buffLen, CRYPT_EAL_PkeyCtx *ealPkey)
{
    // decode n and e
    BSL_ASN1_Buffer asn1[CRYPT_RSA_PRV_OTHER_PRIME_IDX + 1] = {0};
    int32_t ret = CRYPT_DECODE_RsaPrikeyAsn1Buff(buff, buffLen, asn1, CRYPT_RSA_PRV_OTHER_PRIME_IDX + 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = ProcEalRsaPrivKey(asn1, ealPkey);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    return SetRsaPubKey(asn1 + CRYPT_RSA_PRV_N_IDX, asn1 + CRYPT_RSA_PRV_E_IDX, ealPkey);
}

int32_t ParseRsaPrikeyAsn1Buff(CRYPT_EAL_LibCtx *libctx, const char *attrName, uint8_t *buff, uint32_t buffLen,
    BSL_ASN1_Buffer *rsaPssParam, BslCid cid, CRYPT_EAL_PkeyCtx **ealPriKey)
{
    CRYPT_EAL_PkeyCtx *pctx = CRYPT_EAL_ProviderPkeyNewCtx(libctx, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_UNKNOWN_OPERATE,
        attrName);
    if (pctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    int32_t ret = ProcEalRsaKeyPair(buff, buffLen, pctx);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pctx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (cid != BSL_CID_RSASSAPSS) {
        *ealPriKey = pctx;
        return CRYPT_SUCCESS;
    }

    ret = ProcRsaPssParam(rsaPssParam, pctx);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pctx);
        return ret;
    }
    *ealPriKey = pctx;
    return ret;
}
#endif

#if defined(HITLS_CRYPTO_ECDSA) || defined(HITLS_CRYPTO_SM2)
static int32_t EccEalKeyNew(CRYPT_EAL_LibCtx *libctx, const char *attrName, BSL_ASN1_Buffer *ecParamOid,
    int32_t *alg, CRYPT_EAL_PkeyCtx **ealKey)
{
    int32_t algId;
    CRYPT_PKEY_ParaId paraId = (CRYPT_PKEY_ParaId)BSL_OBJ_GetCidFromOidBuff(ecParamOid->buff, ecParamOid->len);
    if (paraId == CRYPT_ECC_SM2) {
        algId = CRYPT_PKEY_SM2;
    } else if (IsEcdsaEcParaId(paraId)) {
        algId = CRYPT_PKEY_ECDSA;
    } else { // scenario ecdh is not considered, and it will be improved in the future
        return CRYPT_DECODE_UNKNOWN_OID;
    }
    CRYPT_EAL_PkeyCtx *key = CRYPT_EAL_ProviderPkeyNewCtx(libctx, algId, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, attrName);
    if (key == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
#ifdef HITLS_CRYPTO_ECDSA
    if (paraId != CRYPT_ECC_SM2) {
        int32_t ret = CRYPT_EAL_PkeySetParaById(key, paraId);
        if (ret != CRYPT_SUCCESS) {
            CRYPT_EAL_PkeyFreeCtx(key);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
#endif
    *ealKey = key;
    *alg = algId;
    return CRYPT_SUCCESS;
}

static int32_t ParseEccPubkeyAsn1Buff(CRYPT_EAL_LibCtx *libctx, const char *attrName, BSL_ASN1_BitString *bitPubkey,
    BSL_ASN1_Buffer *ecParamOid, CRYPT_EAL_PkeyCtx **ealPubKey)
{
    int32_t algId;
    CRYPT_EAL_PkeyCtx *pctx = NULL;
    int32_t ret = EccEalKeyNew(libctx, attrName, ecParamOid, &algId, &pctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    CRYPT_EAL_PkeyPub pub = {.id = algId, .key.eccPub = {.data = bitPubkey->buff, .len = bitPubkey->len}};
    ret = CRYPT_EAL_PkeySetPub(pctx, &pub);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pctx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *ealPubKey = pctx;
    return ret;
}

static int32_t ParseEccPrikeyAsn1(CRYPT_EAL_LibCtx *libctx, const char *attrName, BSL_ASN1_Buffer *encode,
    BSL_ASN1_Buffer *pk8AlgoParam, CRYPT_EAL_PkeyCtx **ealPriKey)
{
    BSL_ASN1_Buffer *prikey = &encode[CRYPT_ECPRIKEY_PRIKEY_IDX]; // the ECC OID
    BSL_ASN1_Buffer *ecParamOid = &encode[CRYPT_ECPRIKEY_PARAM_IDX]; // the parameters OID
    BSL_ASN1_Buffer *pubkey = &encode[CRYPT_ECPRIKEY_PUBKEY_IDX]; // the ECC OID
    BSL_ASN1_Buffer *param = pk8AlgoParam;
    if (ecParamOid->len != 0) {
        // has a valid Algorithm param
        param = ecParamOid;
    } else {
        if (param == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
            return CRYPT_NULL_INPUT;
        }
        if (param->len == 0) {
            BSL_ERR_PUSH_ERROR(CRYPT_DECODE_PKCS8_INVALID_ALGO_PARAM);
            return CRYPT_DECODE_PKCS8_INVALID_ALGO_PARAM;
        }
    }
    int32_t algId;
    CRYPT_EAL_PkeyCtx *pctx = NULL;
    int32_t ret = EccEalKeyNew(libctx, attrName, param, &algId, &pctx); // Changed ecParamOid to param
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    CRYPT_EAL_PkeyPrv prv = {.id = algId, .key.eccPrv = {.data = prikey->buff, .len = prikey->len}};
    ret = CRYPT_EAL_PkeySetPrv(pctx, &prv);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pctx);
        return ret;
    }
    if (pubkey->len > 0) {
        // the tag of public key is BSL_ASN1_TAG_BITSTRING, 1 denote unusedBits
        CRYPT_EAL_PkeyPub pub = {.id = algId, .key.eccPub = {.data = pubkey->buff + 1, .len = pubkey->len - 1}};
        ret = CRYPT_EAL_PkeySetPub(pctx, &pub);
    } else {
        uint32_t flag = CRYPT_ECC_PRIKEY_NO_PUBKEY;
        ret = CRYPT_EAL_PkeyCtrl(pctx, CRYPT_CTRL_SET_FLAG, &flag, sizeof(flag));
        if (ret == CRYPT_SUCCESS) {
            ret = CRYPT_EAL_PkeyCtrl(pctx, CRYPT_CTRL_GEN_ECC_PUBLICKEY, NULL, 0);
        }
    }
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pctx);
        return ret;
    }
    *ealPriKey = pctx;
    return ret;
}

int32_t ParseEccPrikeyAsn1Buff(CRYPT_EAL_LibCtx *libctx, const char *attrName, uint8_t *buff, uint32_t buffLen,
    BSL_ASN1_Buffer *pk8AlgoParam, CRYPT_EAL_PkeyCtx **ealPriKey)
{
    BSL_ASN1_Buffer asn1[CRYPT_ECPRIKEY_PUBKEY_IDX + 1] = {0};
    int32_t ret = CRYPT_DECODE_PrikeyAsn1Buff(buff, buffLen, asn1, CRYPT_ECPRIKEY_PUBKEY_IDX + 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    return ParseEccPrikeyAsn1(libctx, attrName, asn1, pk8AlgoParam, ealPriKey);
}
#endif // HITLS_CRYPTO_ECDSA || HITLS_CRYPTO_SM2

#ifdef HITLS_CRYPTO_ED25519
static int32_t ParseEd25519PrikeyAsn1Buff(CRYPT_EAL_LibCtx *libctx, const char *attrName, uint8_t *buff,
    uint32_t buffLen, CRYPT_EAL_PkeyCtx **ealPriKey)
{
    uint8_t *tmpBuff = buff;
    uint32_t tmpBuffLen = buffLen;

    int32_t ret = BSL_ASN1_DecodeTagLen(BSL_ASN1_TAG_OCTETSTRING, &tmpBuff, &tmpBuffLen, &tmpBuffLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    CRYPT_EAL_PkeyCtx *pctx = CRYPT_EAL_ProviderPkeyNewCtx(libctx, CRYPT_PKEY_ED25519, CRYPT_EAL_PKEY_UNKNOWN_OPERATE,
        attrName);
    if (pctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    CRYPT_EAL_PkeyPrv prv = {.id = CRYPT_PKEY_ED25519, .key.curve25519Prv = {.data = tmpBuff, .len = tmpBuffLen}};
    ret = CRYPT_EAL_PkeySetPrv(pctx, &prv);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pctx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *ealPriKey = pctx;
    return CRYPT_SUCCESS;
}

static int32_t ParseEd25519PubkeyAsn1Buff(CRYPT_EAL_LibCtx *libctx, const char *attrName, uint8_t *buff,
    uint32_t buffLen, CRYPT_EAL_PkeyCtx **ealPubKey)
{
    CRYPT_EAL_PkeyCtx *pctx = CRYPT_EAL_ProviderPkeyNewCtx(libctx, CRYPT_PKEY_ED25519, CRYPT_EAL_PKEY_UNKNOWN_OPERATE,
        attrName);
    if (pctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    CRYPT_EAL_PkeyPub pub = {.id = CRYPT_PKEY_ED25519, .key.curve25519Pub = {.data = buff, .len = buffLen}};
    int32_t ret = CRYPT_EAL_PkeySetPub(pctx, &pub);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pctx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *ealPubKey = pctx;
    return ret;
}
#endif // HITLS_CRYPTO_ED25519

#ifdef HITLS_CRYPTO_MLDSA
static int32_t ParseMldsaPubkeyAsn1Buff(CRYPT_EAL_LibCtx *libctx, const char *attrName, uint8_t *buff,
    uint32_t buffLen, BslCid cid, CRYPT_EAL_PkeyCtx **ealPubKey)
{
    CRYPT_EAL_PkeyCtx *pctx = CRYPT_EAL_ProviderPkeyNewCtx(libctx, CRYPT_PKEY_ML_DSA, CRYPT_EAL_PKEY_UNKNOWN_OPERATE,
        attrName);
    if (pctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    uint32_t ret = CRYPT_EAL_PkeySetParaById(pctx, (uint32_t)cid);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pctx);
        return ret;
    }
    CRYPT_EAL_PkeyPub pub = {.id = CRYPT_PKEY_ML_DSA, .key.mldsaPub = {.data = buff, .len = buffLen}};
    ret = CRYPT_EAL_PkeySetPub(pctx, &pub);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pctx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *ealPubKey = pctx;
    return ret;
}

static int32_t ParseMldsaPrikeyAsn1Buff(CRYPT_EAL_LibCtx *libctx, const char *attrName, uint8_t* buff, uint32_t buffLen,
    BslCid cid, CRYPT_EAL_PkeyCtx** ealPrikey)
{
    uint8_t* tmpBuff = buff;
    uint32_t tmpBuffLen = buffLen;
    BSL_ASN1_Buffer asn1[CRYPT_ML_DSA_PRVKEY_IDX + 1] = {0};
    int32_t ret = CRYPT_DECODE_MldsaPrikeyAsn1Buff(tmpBuff, tmpBuffLen, asn1, CRYPT_ML_DSA_PRVKEY_IDX + 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint8_t* prvKeyBuff = asn1[CRYPT_ML_DSA_PRVKEY_IDX].buff;
    uint32_t prvKeyBuffLen = asn1[CRYPT_ML_DSA_PRVKEY_IDX].len;
    uint8_t* seedBuff = asn1[CRYPT_ML_DSA_PRVKEY_SEED_IDX].buff;
    uint32_t seedBuffLen = asn1[CRYPT_ML_DSA_PRVKEY_SEED_IDX].len;
    CRYPT_EAL_PkeyCtx *pctx = CRYPT_EAL_ProviderPkeyNewCtx(libctx, CRYPT_PKEY_ML_DSA, CRYPT_EAL_PKEY_UNKNOWN_OPERATE,
        attrName);
    if (pctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = CRYPT_EAL_PkeySetParaById(pctx, (uint32_t)cid);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pctx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_Param priParam[3] = {
        {CRYPT_PARAM_ML_DSA_PRVKEY, BSL_PARAM_TYPE_OCTETS, prvKeyBuff, prvKeyBuffLen, 0},
        {CRYPT_PARAM_ML_DSA_PRVKEY_SEED, BSL_PARAM_TYPE_OCTETS, seedBuff, seedBuffLen, 0},
        BSL_PARAM_END
    };
    ret = CRYPT_EAL_PkeySetPrvEx(pctx, priParam);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pctx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *ealPrikey = pctx;
    return CRYPT_SUCCESS;
}

#ifdef HITLS_CRYPTO_MLKEM
static int32_t ParseMlKemPubkeyAsn1Buff(CRYPT_EAL_LibCtx *libctx, const char *attrName,
    uint8_t *buff, uint32_t buffLen, BslCid cid, CRYPT_EAL_PkeyCtx **ealPubKey)
{
    CRYPT_EAL_PkeyCtx *pctx = CRYPT_EAL_ProviderPkeyNewCtx(libctx, CRYPT_PKEY_ML_KEM,
        CRYPT_EAL_PKEY_UNKNOWN_OPERATE, attrName);
    if (pctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    uint32_t ret = CRYPT_EAL_PkeySetParaById(pctx, (uint32_t)cid);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pctx);
        return ret;
    }
    CRYPT_EAL_PkeyPub pub = {.id = CRYPT_PKEY_ML_KEM, .key.kemEk = {.data = buff, .len = buffLen}};
    ret = CRYPT_EAL_PkeySetPub(pctx, &pub);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pctx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *ealPubKey = pctx;
    return ret;
}

static int32_t ParseMlKemPrikeyAsn1Buff(CRYPT_EAL_LibCtx *libctx, const char *attrName,
    uint8_t* buff, uint32_t buffLen, BslCid cid, CRYPT_EAL_PkeyCtx** ealPrikey)
{
    uint8_t* tmpBuff = buff;
    uint32_t tmpBuffLen = buffLen;
    BSL_ASN1_Buffer asn1[CRYPT_ML_KEM_PRVKEY_IDX + 1] = {0};
    int32_t ret = CRYPT_DECODE_MlkemPrikeyAsn1Buff(tmpBuff, tmpBuffLen, asn1, CRYPT_ML_KEM_PRVKEY_IDX + 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint8_t* decapsKeyBuff = asn1[CRYPT_ML_KEM_PRVKEY_IDX].buff;
    uint32_t decapsKeyBuffLen = asn1[CRYPT_ML_KEM_PRVKEY_IDX].len;
    uint8_t* seedBuff = asn1[CRYPT_ML_KEM_PRVKEY_SEED_IDX].buff;
    uint32_t seedBuffLen = asn1[CRYPT_ML_KEM_PRVKEY_SEED_IDX].len;
    CRYPT_EAL_PkeyCtx *pctx = CRYPT_EAL_ProviderPkeyNewCtx(libctx, CRYPT_PKEY_ML_KEM,
        CRYPT_EAL_PKEY_UNKNOWN_OPERATE, attrName);
    if (pctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = CRYPT_EAL_PkeySetParaById(pctx, (uint32_t)cid);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pctx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_Param priParam[3] = {
        {CRYPT_PARAM_ML_KEM_PRVKEY, BSL_PARAM_TYPE_OCTETS, decapsKeyBuff, decapsKeyBuffLen, 0},
        {CRYPT_PARAM_ML_KEM_PRVKEY_SEED, BSL_PARAM_TYPE_OCTETS, seedBuff, seedBuffLen, 0},
        BSL_PARAM_END
    };
    ret = CRYPT_EAL_PkeySetPrvEx(pctx, priParam);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pctx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *ealPrikey = pctx;
    return CRYPT_SUCCESS;
}
#endif

#ifdef HITLS_CRYPTO_XMSS

static int32_t ParseXmssPubKeyAsn1Buff(CRYPT_EAL_LibCtx *libCtx, const char *attrName, BSL_ASN1_BitString *bitPubkey,
     CRYPT_EAL_PkeyCtx **ealPubKey)
{
    uint8_t *p = bitPubkey->buff;
    if (bitPubkey->len <= 4 || bitPubkey->unusedBits != 0x00 || (bitPubkey->len - 4) % 2 != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_INVALID_KEY);
        return CRYPT_XMSS_ERR_INVALID_KEY;
    }
    CRYPT_EAL_PkeyCtx *pctx = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_XMSS, CRYPT_EAL_PKEY_UNKNOWN_OPERATE,
        attrName);
    if (pctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    int32_t ret = CRYPT_EAL_PkeyCtrl(pctx, CRYPT_CTRL_SET_XMSS_XDR_ALG_TYPE, p, 4);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pctx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint32_t hashLen = (bitPubkey->len - 4) / 2;
    uint8_t *data = p + 4;
    CRYPT_EAL_PkeyPub pub = {.id = CRYPT_PKEY_XMSS, .key.xmssPub = {.root = data, .seed = data + hashLen,
        .len = hashLen}};
    ret = CRYPT_EAL_PkeySetPub(pctx, &pub);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pctx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    *ealPubKey = pctx;
    return ret;
}
#endif

#ifdef HITLS_CRYPTO_SLH_DSA
static int32_t ParseSlhDsaPubkeyAsn1Buff(CRYPT_EAL_LibCtx *libctx, const char *attrName, uint8_t *buff,
                                         uint32_t buffLen, BslCid cid, CRYPT_EAL_PkeyCtx **ealPubKey)
{
    CRYPT_EAL_PkeyCtx *pctx =
        CRYPT_EAL_ProviderPkeyNewCtx(libctx, CRYPT_PKEY_SLH_DSA, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, attrName);
    if (pctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    uint32_t ret = CRYPT_EAL_PkeySetParaById(pctx, (uint32_t)cid);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pctx);
        return ret;
    }
    // Get key length (n) for this parameter set
    uint32_t n = 0;
    ret = CRYPT_EAL_PkeyCtrl(pctx, CRYPT_CTRL_GET_SLH_DSA_KEY_LEN, &n, sizeof(uint32_t));
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pctx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (buffLen != n * 2) { // Public key is seed + root (2 * n bytes)
        CRYPT_EAL_PkeyFreeCtx(pctx);
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ASN1_BUFF_FAILED);
        return CRYPT_DECODE_ASN1_BUFF_FAILED;
    }
    CRYPT_SlhDsaPub slhdsaPub = {.seed = buff, .root = buff + n, .len = n};
    CRYPT_EAL_PkeyPub pub = {.id = CRYPT_PKEY_SLH_DSA, .key.slhDsaPub = slhdsaPub};
    ret = CRYPT_EAL_PkeySetPub(pctx, &pub);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pctx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *ealPubKey = pctx;
    return ret;
}

static int32_t ParseSlhDsaPrikeyAsn1Buff(CRYPT_EAL_LibCtx *libctx, const char *attrName, uint8_t *buff,
                                         uint32_t buffLen, BslCid cid, CRYPT_EAL_PkeyCtx **ealPrikey)
{
    uint8_t *tmpBuff = buff;
    uint32_t tmpBuffLen = buffLen;

    CRYPT_EAL_PkeyCtx *pctx =
        CRYPT_EAL_ProviderPkeyNewCtx(libctx, CRYPT_PKEY_SLH_DSA, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, attrName);
    if (pctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = CRYPT_EAL_PkeySetParaById(pctx, (uint32_t)cid);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pctx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // Get key length (n) for this parameter set
    uint32_t n = 0;
    ret = CRYPT_EAL_PkeyCtrl(pctx, CRYPT_CTRL_GET_SLH_DSA_KEY_LEN, &n, sizeof(uint32_t));
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pctx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (tmpBuffLen != n * 4) { // Private key is seed + prf + pub.seed + pub.root (4 * n bytes)
        CRYPT_EAL_PkeyFreeCtx(pctx);
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ASN1_BUFF_FAILED);
        return CRYPT_DECODE_ASN1_BUFF_FAILED;
    }
    CRYPT_SlhDsaPrv slhdsaPrv = {
        .seed = tmpBuff, .prf = tmpBuff + n, .pub = {.seed = tmpBuff + n * 2, .root = tmpBuff + n * 3, .len = n}};
    CRYPT_EAL_PkeyPrv prv = {.id = CRYPT_PKEY_SLH_DSA, .key.slhDsaPrv = slhdsaPrv};
    ret = CRYPT_EAL_PkeySetPrv(pctx, &prv);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pctx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *ealPrikey = pctx;
    return CRYPT_SUCCESS;
}
#endif
#endif

static int32_t ParsePk8PrikeyAsn1(CRYPT_EAL_LibCtx *libctx, const char *attrName,
    CRYPT_ENCODE_DECODE_Pk8PrikeyInfo *pk8PrikeyInfo, CRYPT_EAL_PkeyCtx **ealPriKey)
{
#ifdef HITLS_CRYPTO_RSA
    if (pk8PrikeyInfo->keyType == BSL_CID_RSA || pk8PrikeyInfo->keyType == BSL_CID_RSASSAPSS) {
        return ParseRsaPrikeyAsn1Buff(libctx, attrName, pk8PrikeyInfo->pkeyRawKey, pk8PrikeyInfo->pkeyRawKeyLen,
            &pk8PrikeyInfo->keyParam, pk8PrikeyInfo->keyType, ealPriKey);
    }
#endif
#if defined(HITLS_CRYPTO_ECDSA) || defined(HITLS_CRYPTO_SM2)
    if (pk8PrikeyInfo->keyType == BSL_CID_EC_PUBLICKEY) {
        return ParseEccPrikeyAsn1Buff(libctx, attrName, pk8PrikeyInfo->pkeyRawKey, pk8PrikeyInfo->pkeyRawKeyLen,
            &pk8PrikeyInfo->keyParam, ealPriKey);
    }
#endif
#ifdef HITLS_CRYPTO_ED25519
    if (pk8PrikeyInfo->keyType == BSL_CID_ED25519) {
        return ParseEd25519PrikeyAsn1Buff(libctx, attrName, pk8PrikeyInfo->pkeyRawKey, pk8PrikeyInfo->pkeyRawKeyLen,
            ealPriKey);
    }
#endif
#ifdef HITLS_CRYPTO_MLDSA
    if (pk8PrikeyInfo->keyType == BSL_CID_ML_DSA_44 || pk8PrikeyInfo->keyType == BSL_CID_ML_DSA_65
        || pk8PrikeyInfo->keyType == BSL_CID_ML_DSA_87) {
            return ParseMldsaPrikeyAsn1Buff(libctx, attrName, pk8PrikeyInfo->pkeyRawKey,
                pk8PrikeyInfo->pkeyRawKeyLen, pk8PrikeyInfo->keyType, ealPriKey);
        }
#endif
#ifdef HITLS_CRYPTO_SLH_DSA
        if (pk8PrikeyInfo->keyType >= BSL_CID_SLH_DSA_SHA2_128S &&
            pk8PrikeyInfo->keyType <= BSL_CID_SLH_DSA_SHAKE_256F) {
            return ParseSlhDsaPrikeyAsn1Buff(libctx, attrName,
                pk8PrikeyInfo->pkeyRawKey, pk8PrikeyInfo->pkeyRawKeyLen,
                pk8PrikeyInfo->keyType, ealPriKey);
        }
#endif
#ifdef HITLS_CRYPTO_MLKEM
    if (pk8PrikeyInfo->keyType == BSL_CID_ML_KEM_512 || pk8PrikeyInfo->keyType == BSL_CID_ML_KEM_768 ||
        pk8PrikeyInfo->keyType == BSL_CID_ML_KEM_1024) {
            return ParseMlKemPrikeyAsn1Buff(libctx, attrName,
                pk8PrikeyInfo->pkeyRawKey,
                pk8PrikeyInfo->pkeyRawKeyLen, pk8PrikeyInfo->keyType, ealPriKey);
        }
#endif
    return CRYPT_DECODE_UNSUPPORTED_PKCS8_TYPE;
}

static int32_t ParseSubPubkeyAsn1(CRYPT_EAL_LibCtx *libctx, const char *attrName, BSL_ASN1_Buffer *encode,
    CRYPT_EAL_PkeyCtx **ealPubKey)
{
    uint8_t *algoBuff = encode->buff; // AlgorithmIdentifier Tag and Len, 2 bytes.
    uint32_t algoBuffLen = encode->len;
    BSL_ASN1_Buffer algoId[BSL_ASN1_TAG_ALGOID_ANY_IDX + 1] = {0};
    int32_t ret = CRYPT_DECODE_AlgoIdAsn1Buff(algoBuff, algoBuffLen, NULL, algoId, BSL_ASN1_TAG_ALGOID_ANY_IDX + 1);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    BSL_ASN1_Buffer *oid = algoId; // OID
    BSL_ASN1_Buffer *algParam = algoId + 1; // the parameters
    (void)algParam;
    BSL_ASN1_Buffer *pubkey = &encode[CRYPT_SUBKEYINFO_BITSTRING_IDX]; // the last BSL_ASN1_Buffer, the pubkey
    BSL_ASN1_BitString bitPubkey = {0};
    ret = BSL_ASN1_DecodePrimitiveItem(pubkey, &bitPubkey);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BslCid cid = BSL_OBJ_GetCidFromOidBuff(oid->buff, oid->len);
#if defined(HITLS_CRYPTO_ECDSA) || defined(HITLS_CRYPTO_SM2)
    if (cid == BSL_CID_EC_PUBLICKEY || cid == BSL_CID_SM2PRIME256) {
        return ParseEccPubkeyAsn1Buff(libctx, attrName, &bitPubkey, algParam, ealPubKey);
    }
#endif
#ifdef HITLS_CRYPTO_RSA
    if (cid == BSL_CID_RSA || cid == BSL_CID_RSASSAPSS) {
        return ParseRsaPubkeyAsn1Buff(libctx, attrName, bitPubkey.buff, bitPubkey.len, algParam, ealPubKey, cid);
    }
#endif
#ifdef HITLS_CRYPTO_ED25519
    if (cid == BSL_CID_ED25519) {
        return ParseEd25519PubkeyAsn1Buff(libctx, attrName, bitPubkey.buff, bitPubkey.len, ealPubKey);
    }
#endif
#ifdef HITLS_CRYPTO_MLDSA
    if (cid == BSL_CID_ML_DSA_44 || cid == BSL_CID_ML_DSA_65 || cid == BSL_CID_ML_DSA_87) {
        return ParseMldsaPubkeyAsn1Buff(libctx, attrName, bitPubkey.buff, bitPubkey.len, cid, ealPubKey);
    }
#endif
#ifdef HITLS_CRYPTO_SLH_DSA
    if (cid >= BSL_CID_SLH_DSA_SHA2_128S && cid <= BSL_CID_SLH_DSA_SHAKE_256F) {
        return ParseSlhDsaPubkeyAsn1Buff(libctx, attrName, bitPubkey.buff, bitPubkey.len, cid, ealPubKey);
    }
#endif
#ifdef HITLS_CRYPTO_MLKEM
    if (cid == BSL_CID_ML_KEM_512 || cid == BSL_CID_ML_KEM_768 || cid == BSL_CID_ML_KEM_1024) {
        return ParseMlKemPubkeyAsn1Buff(libctx, attrName, bitPubkey.buff, bitPubkey.len, cid, ealPubKey);
    }
#endif
#ifdef HITLS_CRYPTO_XMSS
    if (cid == BSL_CID_XMSS) {
        return ParseXmssPubKeyAsn1Buff(libctx, attrName, &bitPubkey, ealPubKey);
    }
#endif

    BSL_ERR_PUSH_ERROR(CRYPT_DECODE_UNKNOWN_OID);
    return CRYPT_DECODE_UNKNOWN_OID;
}

int32_t ParsePk8PriKeyBuff(CRYPT_EAL_LibCtx *libctx, const char *attrName, BSL_Buffer *buff,
    CRYPT_EAL_PkeyCtx **ealPriKey)
{
    uint8_t *tmpBuff = buff->data;
    uint32_t tmpBuffLen = buff->dataLen;

    CRYPT_ENCODE_DECODE_Pk8PrikeyInfo pk8PrikeyInfo = {0};
    int32_t ret = CRYPT_DECODE_Pkcs8Info(tmpBuff, tmpBuffLen, NULL, &pk8PrikeyInfo);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return ParsePk8PrikeyAsn1(libctx, attrName, &pk8PrikeyInfo, ealPriKey);
}

#ifdef HITLS_CRYPTO_KEY_EPKI
int32_t ParsePk8EncPriKeyBuff(CRYPT_EAL_LibCtx *libctx, const char *attrName, BSL_Buffer *buff,
    const BSL_Buffer *pwd, CRYPT_EAL_PkeyCtx **ealPriKey)
{
    BSL_Buffer decode = {0};
    int32_t ret = CRYPT_DECODE_Pkcs8PrvDecrypt(libctx, attrName, buff, pwd, NULL, &decode);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = ParsePk8PriKeyBuff(libctx, attrName, &decode, ealPriKey);
    BSL_SAL_ClearFree(decode.data, decode.dataLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}
#endif

int32_t CRYPT_EAL_ParseAsn1SubPubkey(CRYPT_EAL_LibCtx *libctx, const char *attrName, uint8_t *buff, uint32_t buffLen,
    void **ealPubKey, bool isComplete)
{
    // decode sub pubkey info
    BSL_ASN1_Buffer pubAsn1[CRYPT_SUBKEYINFO_BITSTRING_IDX + 1] = {0};
    int32_t ret = CRYPT_DECODE_ParseSubKeyInfo(buff, buffLen, pubAsn1, isComplete);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return ParseSubPubkeyAsn1(libctx, attrName, pubAsn1, (CRYPT_EAL_PkeyCtx **)ealPubKey);
}
#endif // HITLS_CRYPTO_KEY_DECODE

#ifdef HITLS_CRYPTO_KEY_ENCODE

#ifdef HITLS_CRYPTO_RSA
static int32_t EncodePssParam(CRYPT_EAL_PkeyCtx *ealPubKey, BSL_ASN1_Buffer *pssParam)
{
    if (pssParam == NULL) {
        return CRYPT_SUCCESS;
    }
    int32_t padType = 0;
    int32_t ret = CRYPT_EAL_PkeyCtrl(ealPubKey, CRYPT_CTRL_GET_RSA_PADDING, &padType, sizeof(padType));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (padType != CRYPT_EMSA_PSS) {
        pssParam->tag = BSL_ASN1_TAG_NULL;
        return CRYPT_SUCCESS;
    }
    CRYPT_RSA_PssPara rsaPssParam = {0};
    ret = CRYPT_EAL_GetRsaPssPara(ealPubKey, &rsaPssParam);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    pssParam->tag = BSL_ASN1_TAG_SEQUENCE | BSL_ASN1_TAG_CONSTRUCTED;
    return CRYPT_EAL_EncodeRsaPssAlgParam(&rsaPssParam, &pssParam->buff, &pssParam->len);
}

int32_t EncodeRsaPubkeyAsn1Buff(CRYPT_EAL_PkeyCtx *ealPubKey, BSL_ASN1_Buffer *pssParam, BSL_Buffer *encodePub)
{
    uint32_t bnLen = CRYPT_EAL_PkeyGetKeyLen(ealPubKey);
    if (bnLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    CRYPT_EAL_PkeyPub pub = {0};
    pub.id = CRYPT_PKEY_RSA;
    pub.key.rsaPub.n = (uint8_t *)BSL_SAL_Malloc(bnLen);
    if (pub.key.rsaPub.n == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    pub.key.rsaPub.e = (uint8_t *)BSL_SAL_Malloc(bnLen);
    if (pub.key.rsaPub.e == NULL) {
        BSL_SAL_FREE(pub.key.rsaPub.n);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    pub.key.rsaPub.nLen = bnLen;
    pub.key.rsaPub.eLen = bnLen;

    int32_t ret = CRYPT_EAL_PkeyGetPub(ealPubKey, &pub);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_FREE(pub.key.rsaPub.n);
        BSL_SAL_FREE(pub.key.rsaPub.e);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_ASN1_Buffer pubAsn1[CRYPT_RSA_PUB_E_IDX + 1] = {
        {BSL_ASN1_TAG_INTEGER,  pub.key.rsaPub.nLen, pub.key.rsaPub.n},
        {BSL_ASN1_TAG_INTEGER,  pub.key.rsaPub.eLen, pub.key.rsaPub.e},
    };
    ret = CRYPT_ENCODE_RsaPubkeyAsn1Buff(pubAsn1, encodePub);
    BSL_SAL_FREE(pub.key.rsaPub.n);
    BSL_SAL_FREE(pub.key.rsaPub.e);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = EncodePssParam(ealPubKey, pssParam);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_FREE(encodePub->data);
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t EncodeRsaPrvKey(CRYPT_EAL_PkeyCtx *ealPriKey, BSL_ASN1_Buffer *pk8AlgoParam, BSL_Buffer *bitStr,
    CRYPT_PKEY_AlgId *cid)
{
    CRYPT_RsaPadType pad = CRYPT_RSA_PADDINGMAX;
    int32_t ret = CRYPT_EAL_PkeyCtrl(ealPriKey, CRYPT_CTRL_GET_RSA_PADDING, &pad, sizeof(pad));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    CRYPT_RSA_PssPara rsaPssParam = {0};
    BSL_Buffer tmp = {0};
    switch (pad) {
        case CRYPT_EMSA_PSS:
            ret = CRYPT_EAL_GetRsaPssPara(ealPriKey, &rsaPssParam);
            if (ret != BSL_SUCCESS) {
                return ret;
            }
            ret = EncodeRsaPrikeyAsn1Buff(ealPriKey, &tmp);
            if (ret != BSL_SUCCESS) {
                return ret;
            }
            ret = CRYPT_EAL_EncodeRsaPssAlgParam(&rsaPssParam, &pk8AlgoParam->buff, &pk8AlgoParam->len);
            if (ret != BSL_SUCCESS) {
                BSL_SAL_ClearFree(tmp.data, tmp.dataLen);
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            pk8AlgoParam->tag = BSL_ASN1_TAG_SEQUENCE | BSL_ASN1_TAG_CONSTRUCTED;
            *cid = (CRYPT_PKEY_AlgId)BSL_CID_RSASSAPSS;
            break;
        default:
            ret = EncodeRsaPrikeyAsn1Buff(ealPriKey, &tmp);
            if (ret != BSL_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            pk8AlgoParam->tag = BSL_ASN1_TAG_NULL;
            break;
    }
    bitStr->data = tmp.data;
    bitStr->dataLen = tmp.dataLen;
    return CRYPT_SUCCESS;
}

static void SetRsaPrv2Arr(const CRYPT_EAL_PkeyPrv *rsaPrv, BSL_ASN1_Buffer *asn1)
{
    asn1[CRYPT_RSA_PRV_D_IDX].buff = rsaPrv->key.rsaPrv.d;
    asn1[CRYPT_RSA_PRV_D_IDX].len = rsaPrv->key.rsaPrv.dLen;
    asn1[CRYPT_RSA_PRV_N_IDX].buff = rsaPrv->key.rsaPrv.n;
    asn1[CRYPT_RSA_PRV_N_IDX].len = rsaPrv->key.rsaPrv.nLen;
    asn1[CRYPT_RSA_PRV_E_IDX].buff = rsaPrv->key.rsaPrv.e;
    asn1[CRYPT_RSA_PRV_E_IDX].len = rsaPrv->key.rsaPrv.eLen;
    asn1[CRYPT_RSA_PRV_P_IDX].buff = rsaPrv->key.rsaPrv.p;
    asn1[CRYPT_RSA_PRV_P_IDX].len = rsaPrv->key.rsaPrv.pLen;
    asn1[CRYPT_RSA_PRV_Q_IDX].buff = rsaPrv->key.rsaPrv.q;
    asn1[CRYPT_RSA_PRV_Q_IDX].len = rsaPrv->key.rsaPrv.qLen;
    asn1[CRYPT_RSA_PRV_DP_IDX].buff = rsaPrv->key.rsaPrv.dP;
    asn1[CRYPT_RSA_PRV_DP_IDX].len = rsaPrv->key.rsaPrv.dPLen;
    asn1[CRYPT_RSA_PRV_DQ_IDX].buff = rsaPrv->key.rsaPrv.dQ;
    asn1[CRYPT_RSA_PRV_DQ_IDX].len = rsaPrv->key.rsaPrv.dQLen;
    asn1[CRYPT_RSA_PRV_QINV_IDX].buff = rsaPrv->key.rsaPrv.qInv;
    asn1[CRYPT_RSA_PRV_QINV_IDX].len = rsaPrv->key.rsaPrv.qInvLen;

    asn1[CRYPT_RSA_PRV_D_IDX].tag = BSL_ASN1_TAG_INTEGER;
    asn1[CRYPT_RSA_PRV_N_IDX].tag = BSL_ASN1_TAG_INTEGER;
    asn1[CRYPT_RSA_PRV_E_IDX].tag = BSL_ASN1_TAG_INTEGER;
    asn1[CRYPT_RSA_PRV_P_IDX].tag = BSL_ASN1_TAG_INTEGER;
    asn1[CRYPT_RSA_PRV_Q_IDX].tag = BSL_ASN1_TAG_INTEGER;
    asn1[CRYPT_RSA_PRV_DP_IDX].tag = BSL_ASN1_TAG_INTEGER;
    asn1[CRYPT_RSA_PRV_DQ_IDX].tag = BSL_ASN1_TAG_INTEGER;
    asn1[CRYPT_RSA_PRV_QINV_IDX].tag = BSL_ASN1_TAG_INTEGER;
}

int32_t EncodeRsaPrikeyAsn1Buff(CRYPT_EAL_PkeyCtx *ealPriKey, BSL_Buffer *encode)
{
    BSL_ASN1_Buffer asn1[CRYPT_RSA_PRV_OTHER_PRIME_IDX + 1] = {0};

    CRYPT_EAL_PkeyPrv rsaPrv = {0};
    int32_t ret = CRYPT_EAL_InitRsaPrv(ealPriKey, CRYPT_PKEY_RSA, &rsaPrv);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CRYPT_EAL_PkeyGetPrv(ealPriKey, &rsaPrv);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_DeinitRsaPrv(&rsaPrv);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    SetRsaPrv2Arr(&rsaPrv, asn1);
    uint8_t version = 0;
    asn1[CRYPT_RSA_PRV_VERSION_IDX].buff = (uint8_t *)&version;
    asn1[CRYPT_RSA_PRV_VERSION_IDX].len = sizeof(version);
    asn1[CRYPT_RSA_PRV_VERSION_IDX].tag = BSL_ASN1_TAG_INTEGER;
    ret = CRYPT_ENCODE_RsaPrikeyAsn1Buff(asn1, CRYPT_RSA_PRV_OTHER_PRIME_IDX + 1, encode);
    CRYPT_EAL_DeinitRsaPrv(&rsaPrv);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}
#endif

#if defined(HITLS_CRYPTO_ECDSA) || defined(HITLS_CRYPTO_SM2)
static inline void SetAsn1Buffer(BSL_ASN1_Buffer *asn, uint8_t tag, uint32_t len, uint8_t *buff)
{
    asn->tag = tag;
    asn->len = len;
    asn->buff = buff;
}

static int32_t GenAndGetEccPubkey(CRYPT_EAL_PkeyCtx *ealPriKey, CRYPT_PKEY_AlgId cid, uint32_t keyLen,
    uint8_t **pubOut, uint32_t *pubLenOut)
{
    uint8_t *pub = (uint8_t *)BSL_SAL_Malloc(keyLen);
    if (pub == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    CRYPT_EAL_PkeyPub pubKey = {.id = cid, .key.eccPub = {.data = pub, .len = keyLen}};
    int32_t ret = CRYPT_EAL_PkeyCtrl(ealPriKey, CRYPT_CTRL_GEN_ECC_PUBLICKEY, NULL, 0);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_FREE(pub);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CRYPT_EAL_PkeyGetPub(ealPriKey, &pubKey);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_FREE(pub);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *pubOut = pubKey.key.eccPub.data;
    *pubLenOut = pubKey.key.eccPub.len;
    return CRYPT_SUCCESS;
}

static int32_t EncodeEccKeyPair(CRYPT_EAL_PkeyCtx *ealPriKey, CRYPT_PKEY_AlgId cid, BSL_ASN1_Buffer *asn1, BSL_Buffer *encode)
{
    int32_t ret;
    uint32_t flag = 0;
    ret = CRYPT_EAL_PkeyCtrl(ealPriKey, CRYPT_CTRL_GET_FLAG, &flag, sizeof(flag));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    bool includePubKey = flag & CRYPT_ECC_PRIKEY_NO_PUBKEY ? false : true;
    uint32_t keyLen = CRYPT_EAL_PkeyGetKeyLen(ealPriKey);
    if (keyLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    uint8_t *pri = (uint8_t *)BSL_SAL_Malloc(keyLen);
    if (pri == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    CRYPT_EAL_PkeyPrv prv = {.id = cid, .key.eccPrv = {.data = pri, .len = keyLen}};
    uint8_t *pub = NULL;
    do {
        ret = CRYPT_EAL_PkeyGetPrv(ealPriKey, &prv);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            break;
        }
        SetAsn1Buffer(asn1 + CRYPT_ECPRIKEY_PRIKEY_IDX, BSL_ASN1_TAG_OCTETSTRING,
            prv.key.eccPrv.len, prv.key.eccPrv.data);
        if (includePubKey) {
            uint32_t pubLen = 0;
            ret = GenAndGetEccPubkey(ealPriKey, cid, keyLen, &pub, &pubLen);
            if (ret != CRYPT_SUCCESS) {
                break;
            }
            BSL_ASN1_BitString bitStr = {pub, pubLen, 0};
            SetAsn1Buffer(asn1 + CRYPT_ECPRIKEY_PUBKEY_IDX, BSL_ASN1_TAG_BITSTRING,
                sizeof(BSL_ASN1_BitString), (uint8_t *)&bitStr);
            ret = CRYPT_ENCODE_EccPrikeyAsn1Buff(asn1, CRYPT_ECPRIKEY_PUBKEY_IDX + 1, encode);
        } else {
            // Optional placeholder [1] publicKey
            asn1[CRYPT_ECPRIKEY_PUBKEY_IDX].tag = BSL_ASN1_TAG_OCTETSTRING;
            ret = CRYPT_ENCODE_EccPrikeyAsn1Buff(asn1, CRYPT_ECPRIKEY_PUBKEY_IDX + 1, encode);
        }
    } while (0);
    BSL_SAL_ClearFree(pri, keyLen);
    BSL_SAL_FREE(pub);
    return ret;
}

int32_t EncodeEccPrikeyAsn1Buff(CRYPT_EAL_PkeyCtx *ealPriKey, BSL_ASN1_Buffer *pk8AlgoParam, BSL_Buffer *encode)
{
    uint8_t version = 1;
    BSL_ASN1_Buffer asn1[CRYPT_ECPRIKEY_PUBKEY_IDX + 1] = {
        {BSL_ASN1_TAG_INTEGER, sizeof(version), &version}, {0}, {0}, {0}};

    CRYPT_PKEY_AlgId cid = CRYPT_EAL_PkeyGetId(ealPriKey);
    BslOidString *oid = cid == CRYPT_PKEY_SM2 ? BSL_OBJ_GetOID((BslCid)CRYPT_ECC_SM2)
                                              : BSL_OBJ_GetOID((BslCid)CRYPT_EAL_PkeyGetParaId(ealPriKey));
    if (oid == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ERR_ALGID);
        return CRYPT_ERR_ALGID;
    }
    if (pk8AlgoParam != NULL) { // pkcs8
        pk8AlgoParam->buff = (uint8_t *)oid->octs;
        pk8AlgoParam->len = oid->octetLen;
        pk8AlgoParam->tag = BSL_ASN1_TAG_OBJECT_ID;
    } else { // pkcs1
        asn1[CRYPT_ECPRIKEY_PARAM_IDX].buff = (uint8_t *)oid->octs;
        asn1[CRYPT_ECPRIKEY_PARAM_IDX].len = oid->octetLen;
        asn1[CRYPT_ECPRIKEY_PARAM_IDX].tag = BSL_ASN1_TAG_OBJECT_ID;
    }

    return EncodeEccKeyPair(ealPriKey, cid, asn1, encode);
}

static int32_t EncodeEccPubkeyAsn1Buff(CRYPT_EAL_PkeyCtx *ealPubKey, BSL_ASN1_Buffer *ecParamOid, BSL_Buffer *encodePub)
{
    CRYPT_PKEY_ParaId paraId = CRYPT_EAL_PkeyGetParaId(ealPubKey);
    BslOidString *oid = BSL_OBJ_GetOID((BslCid)paraId);
    if (CRYPT_EAL_PkeyGetId(ealPubKey) == CRYPT_PKEY_SM2) {
        oid = BSL_OBJ_GetOID((BslCid)CRYPT_ECC_SM2);
    }
    if (oid == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ERR_ALGID);
        return CRYPT_ERR_ALGID;
    }
    ecParamOid->buff = (uint8_t *)oid->octs;
    ecParamOid->len = oid->octetLen;
    ecParamOid->tag = BSL_ASN1_TAG_OBJECT_ID;

    uint32_t pubLen = CRYPT_EAL_PkeyGetKeyLen(ealPubKey);
    if (pubLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    uint8_t *pub = (uint8_t *)BSL_SAL_Malloc(pubLen);
    if (pub == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    CRYPT_EAL_PkeyPub pubKey = {.id = CRYPT_EAL_PkeyGetId(ealPubKey), .key.eccPub = {.data = pub, .len = pubLen}};
    int32_t ret = CRYPT_EAL_PkeyGetPub(ealPubKey, &pubKey);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_FREE(pub);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    encodePub->data = pubKey.key.eccPub.data;
    encodePub->dataLen = pubKey.key.eccPub.len;
    return ret;
}
#endif // HITLS_CRYPTO_ECDSA || HITLS_CRYPTO_SM2

#ifdef HITLS_CRYPTO_MLDSA
static int32_t EncodeMldsaPubkeyAsn1Buff(CRYPT_EAL_PkeyCtx *ealPubKey, BSL_Buffer *bitStr, BslCid *bslCid)
{
    uint32_t pubLen = 0;
    int ret = CRYPT_EAL_PkeyCtrl(ealPubKey, CRYPT_CTRL_GET_PUBKEY_LEN, &pubLen, sizeof(uint32_t));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CRYPT_EAL_PkeyCtrl(ealPubKey, CRYPT_CTRL_GET_PARAID, bslCid, sizeof(int32_t));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint8_t *pub = (uint8_t *)BSL_SAL_Malloc(pubLen);
    if (pub == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    CRYPT_EAL_PkeyPub pubKey = {.id = CRYPT_PKEY_ML_DSA, .key.mldsaPub = {.data = pub, .len = pubLen}};
    ret = CRYPT_EAL_PkeyGetPub(ealPubKey, &pubKey);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(pub);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    bitStr->data = pubKey.key.mldsaPub.data;
    bitStr->dataLen = pubKey.key.mldsaPub.len;
    return CRYPT_SUCCESS;
}

static int32_t ProcessMldsaPrvkeyBothFormat(BSL_ASN1_Buffer *seedAsn1, BSL_ASN1_Buffer *prvKeyAsn1, BSL_Buffer *bitStr)
{
    BSL_ASN1_TemplateItem items[] = {{BSL_ASN1_TAG_SEQUENCE | BSL_ASN1_TAG_CONSTRUCTED, 0, 0},
                                     {BSL_ASN1_TAG_OCTETSTRING, 0, 1},
                                     {BSL_ASN1_TAG_OCTETSTRING, 0, 1}};
    BSL_ASN1_Template templ = {items, 3};
    seedAsn1->tag = BSL_ASN1_TAG_OCTETSTRING;
    BSL_ASN1_Buffer asn1Arr[2] = {*seedAsn1, *prvKeyAsn1};
    return BSL_ASN1_EncodeTemplate(&templ, asn1Arr, sizeof(asn1Arr) / sizeof(asn1Arr[0]),
        &bitStr->data, &bitStr->dataLen);
}

static int32_t ProcessMldsaPrvkeySeedOnlyFormat(BSL_ASN1_Buffer *seedAsn1, BSL_Buffer *bitStr)
{
    BSL_ASN1_TemplateItem seedItem[] = {{BSL_ASN1_CLASS_CTX_SPECIFIC, 0, 0}};
    BSL_ASN1_Template templ = {seedItem, 1};
    return BSL_ASN1_EncodeTemplate(&templ, seedAsn1, 1, &bitStr->data, &bitStr->dataLen);
}

static int32_t ProcessMldsaPrvkeyOnlyFormat(BSL_ASN1_Buffer *prvKeyAsn1, BSL_Buffer *bitStr)
{
    BSL_ASN1_TemplateItem prvKeyItem[] = {{BSL_ASN1_TAG_OCTETSTRING, 0, 0}};
    BSL_ASN1_Template templ = {prvKeyItem, 1};
    return BSL_ASN1_EncodeTemplate(&templ, prvKeyAsn1, 1, &bitStr->data, &bitStr->dataLen);
}

static int32_t GetMldsaSkInfo(CRYPT_EAL_PkeyCtx *ealPriKey, uint32_t *format, bool *hasSeed, BSL_ASN1_Buffer *seedAsn1,
                              BSL_ASN1_Buffer *prvKeyAsn1)
{
    int32_t ret = CRYPT_EAL_PkeyCtrl(ealPriKey, CRYPT_CTRL_GET_MLDSA_PRVKEY_FORMAT, format, sizeof(uint32_t));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (*format >= (uint32_t)CRYPT_ALGO_MLDSA_PRIV_FORMAT_END) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_PRVKEY_FORMAT_ERROR);
        return CRYPT_MLDSA_PRVKEY_FORMAT_ERROR;
    }
    ret = CRYPT_EAL_PkeyCtrl(ealPriKey, CRYPT_CTRL_GET_MLDSA_SEED, seedAsn1->buff, MLDSA_SEED_BYTES_LEN);
    if (ret == CRYPT_SUCCESS) {
        *hasSeed = true;
    }
    if (*format == (uint32_t)CRYPT_ALGO_MLDSA_PRIV_FORMAT_SEED_ONLY ||
        *format == (uint32_t)CRYPT_ALGO_MLDSA_PRIV_FORMAT_BOTH) {
        if (!(*hasSeed)) {
            BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_PRVKEY_FORMAT_ERROR);
            return CRYPT_MLDSA_PRVKEY_FORMAT_ERROR;
        }
    }
    CRYPT_EAL_PkeyPrv prvKey = {0};
    if (*format != CRYPT_ALGO_MLDSA_PRIV_FORMAT_SEED_ONLY) {
        prvKey.id = CRYPT_PKEY_ML_DSA;
        prvKey.key.mldsaPrv.len = prvKeyAsn1->len;
        prvKey.key.mldsaPrv.data = BSL_SAL_Malloc(prvKeyAsn1->len);
        if (prvKey.key.mldsaPrv.data == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
        ret = CRYPT_EAL_PkeyGetPrv(ealPriKey, &prvKey);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            BSL_SAL_Free(prvKey.key.mldsaPrv.data);
            return ret;
        }
        prvKeyAsn1->buff = prvKey.key.mldsaPrv.data;
    }
    return CRYPT_SUCCESS;
}

static void CleanSeedAndPrivKeyAsn1Buff(BSL_ASN1_Buffer *seedAsn1, BSL_ASN1_Buffer *prvKeyAsn1)
{
    BSL_SAL_CleanseData(seedAsn1->buff, seedAsn1->len);
    if (prvKeyAsn1->buff != NULL) {
        BSL_SAL_CleanseData(prvKeyAsn1->buff, prvKeyAsn1->len);
        BSL_SAL_FREE(prvKeyAsn1->buff);
    }
}

static int32_t ProcessMldsaPrvkeyFormat(CRYPT_EAL_PkeyCtx *ealPriKey, BSL_Buffer *bitStr, uint32_t prvKeyLen)
{
    uint32_t format = 0;
    bool hasSeed = false;
    uint8_t seedBuf[MLDSA_SEED_BYTES_LEN] = {0};
    BSL_ASN1_Buffer seedAsn1 = {BSL_ASN1_CLASS_CTX_SPECIFIC, MLDSA_SEED_BYTES_LEN, seedBuf};
    BSL_ASN1_Buffer prvKeyAsn1 = {BSL_ASN1_TAG_OCTETSTRING, prvKeyLen, NULL};
    // exclude invalid cases
    int32_t ret = GetMldsaSkInfo(ealPriKey, &format, &hasSeed, &seedAsn1, &prvKeyAsn1);
    if (ret != CRYPT_SUCCESS) {
        CleanSeedAndPrivKeyAsn1Buff(&seedAsn1, &prvKeyAsn1);
        return ret;
    }
    if (hasSeed) {
        if (format == (uint32_t)CRYPT_ALGO_MLDSA_PRIV_FORMAT_SEED_ONLY) {
            // seed-only
            ret = ProcessMldsaPrvkeySeedOnlyFormat(&seedAsn1, bitStr);
            CleanSeedAndPrivKeyAsn1Buff(&seedAsn1, &prvKeyAsn1);
            return ret;
        }
        if (format == (uint32_t)CRYPT_ALGO_MLDSA_PRIV_FORMAT_BOTH ||
            format == (uint32_t)CRYPT_ALGO_MLDSA_PRIV_FORMAT_NOT_SET) {
            // both
            ret = ProcessMldsaPrvkeyBothFormat(&seedAsn1, &prvKeyAsn1, bitStr);
            CleanSeedAndPrivKeyAsn1Buff(&seedAsn1, &prvKeyAsn1);
            return ret;
        }
    }
    // priv-only
    ret = ProcessMldsaPrvkeyOnlyFormat(&prvKeyAsn1, bitStr);
    CleanSeedAndPrivKeyAsn1Buff(&seedAsn1, &prvKeyAsn1);
    return ret;
}

static int32_t EncodeMldsaPrikeyAsn1Buff(CRYPT_EAL_PkeyCtx *ealPriKey, BSL_Buffer *bitStr, BslCid *bslCid)
{
    uint32_t prvKeyLen = 0;
    int32_t ret = CRYPT_EAL_PkeyCtrl(ealPriKey, CRYPT_CTRL_GET_PRVKEY_LEN, &prvKeyLen, sizeof(uint32_t));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CRYPT_EAL_PkeyCtrl(ealPriKey, CRYPT_CTRL_GET_PARAID, bslCid, sizeof(int32_t));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return ProcessMldsaPrvkeyFormat(ealPriKey, bitStr, prvKeyLen);
}
#endif  // HITLS_CRYPTO_MLDSA

#ifdef HITLS_CRYPTO_ED25519
static int32_t EncodeEd25519PubkeyAsn1Buff(CRYPT_EAL_PkeyCtx *ealPubKey, BSL_Buffer *bitStr)
{
    uint32_t pubLen = CRYPT_EAL_PkeyGetKeyLen(ealPubKey);
    if (pubLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    uint8_t *pub = (uint8_t *)BSL_SAL_Malloc(pubLen);
    if (pub == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    CRYPT_EAL_PkeyPub pubKey = {.id = CRYPT_PKEY_ED25519, .key.curve25519Pub = {.data = pub, .len = pubLen}};
    int32_t ret = CRYPT_EAL_PkeyGetPub(ealPubKey, &pubKey);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(pub);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    bitStr->data = pubKey.key.curve25519Pub.data;
    bitStr->dataLen = pubKey.key.curve25519Pub.len;
    return CRYPT_SUCCESS;
}

static int32_t EncodeEd25519PrikeyAsn1Buff(CRYPT_EAL_PkeyCtx *ealPriKey, BSL_Buffer *bitStr)
{
    uint8_t keyBuff[32] = {0}; // The length of the ed25519 private key is 32
    CRYPT_EAL_PkeyPrv prv = {.id = CRYPT_PKEY_ED25519, .key.curve25519Prv = {.data = keyBuff, .len = sizeof(keyBuff)}};
    int32_t ret = CRYPT_EAL_PkeyGetPrv(ealPriKey, &prv);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_ASN1_TemplateItem octStr[] = {{BSL_ASN1_TAG_OCTETSTRING, 0, 0}};
    BSL_ASN1_Template templ = {octStr, 1};
    BSL_ASN1_Buffer prvAsn1 = {BSL_ASN1_TAG_OCTETSTRING, prv.key.curve25519Prv.len, prv.key.curve25519Prv.data};
    return BSL_ASN1_EncodeTemplate(&templ, &prvAsn1, 1, &bitStr->data, &bitStr->dataLen);
}
#endif // HITLS_CRYPTO_ED25519

#ifdef HITLS_CRYPTO_SLH_DSA
static int32_t EncodeSlhDsaPubkeyAsn1Buff(CRYPT_EAL_PkeyCtx *ealPubKey, BSL_Buffer *bitStr, BslCid *bslCid)
{
    int32_t ret = CRYPT_EAL_PkeyCtrl(ealPubKey, CRYPT_CTRL_GET_PARAID, bslCid, sizeof(int32_t));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint32_t n = 0;
    ret = CRYPT_EAL_PkeyCtrl(ealPubKey, CRYPT_CTRL_GET_SLH_DSA_KEY_LEN, &n, sizeof(uint32_t));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint32_t pubKeyLen = n * 2; // seed + root
    uint8_t *pub = (uint8_t *)BSL_SAL_Malloc(pubKeyLen);
    if (pub == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    CRYPT_SlhDsaPub slhdsaPub = {.seed = pub, .root = pub + n, .len = n};
    CRYPT_EAL_PkeyPub pubKey = {.id = CRYPT_PKEY_SLH_DSA, .key.slhDsaPub = slhdsaPub};
    ret = CRYPT_EAL_PkeyGetPub(ealPubKey, &pubKey);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(pub);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    bitStr->data = pub;
    bitStr->dataLen = pubKeyLen;
    return CRYPT_SUCCESS;
}

static int32_t EncodeSlhDsaPrikeyAsn1Buff(CRYPT_EAL_PkeyCtx *ealPriKey, BSL_Buffer *bitStr, BslCid *bslCid)
{
    int32_t ret = CRYPT_EAL_PkeyCtrl(ealPriKey, CRYPT_CTRL_GET_PARAID, bslCid, sizeof(int32_t));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint32_t n = 0;
    ret = CRYPT_EAL_PkeyCtrl(ealPriKey, CRYPT_CTRL_GET_SLH_DSA_KEY_LEN, &n, sizeof(uint32_t));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint32_t prvKeyLen = n * 4; // seed + prf + pub.seed + pub.root
    uint8_t *prv = (uint8_t *)BSL_SAL_Malloc(prvKeyLen);
    if (prv == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    CRYPT_SlhDsaPrv slhdsaPrv = {
        .seed = prv, .prf = prv + n, .pub = {.seed = prv + n * 2, .root = prv + n * 3, .len = n}};
    CRYPT_EAL_PkeyPrv prvKey = {.id = CRYPT_PKEY_SLH_DSA, .key.slhDsaPrv = slhdsaPrv};
    ret = CRYPT_EAL_PkeyGetPrv(ealPriKey, &prvKey);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ClearFree(prv, prvKeyLen);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    bitStr->data = prv;
    bitStr->dataLen = prvKeyLen;
    return ret;
}

#endif // HITLS_CRYPTO_SLH_DSA

#ifdef HITLS_CRYPTO_MLKEM
static int32_t EncodeMlKemPubkeyAsn1Buff(CRYPT_EAL_PkeyCtx *ealPubKey, BSL_Buffer *bitStr, BslCid *bslCid)
{
    uint32_t pubLen = 0;
    int32_t ret = CRYPT_EAL_PkeyCtrl(ealPubKey, CRYPT_CTRL_GET_PUBKEY_LEN, &pubLen, sizeof(uint32_t));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CRYPT_EAL_PkeyCtrl(ealPubKey, CRYPT_CTRL_GET_PARAID, bslCid, sizeof(int32_t));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint8_t *pub = (uint8_t *)BSL_SAL_Malloc(pubLen);
    if (pub == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    CRYPT_EAL_PkeyPub pubKey = {.id = CRYPT_PKEY_ML_KEM, .key.kemEk = {.data = pub, .len = pubLen}};
    ret = CRYPT_EAL_PkeyGetPub(ealPubKey, &pubKey);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(pub);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    bitStr->data = pubKey.key.kemEk.data;
    bitStr->dataLen = pubKey.key.kemEk.len;
    return CRYPT_SUCCESS;
}

static int32_t ProcessMlkemPrvkeyBothFormat(BSL_ASN1_Buffer *seedAsn1, BSL_ASN1_Buffer *prvKeyAsn1, BSL_Buffer *bitStr)
{
    BSL_ASN1_TemplateItem items[] = {{BSL_ASN1_TAG_SEQUENCE | BSL_ASN1_TAG_CONSTRUCTED, 0, 0},
                                     {BSL_ASN1_TAG_OCTETSTRING, 0, 1},
                                     {BSL_ASN1_TAG_OCTETSTRING, 0, 1}};
    BSL_ASN1_Template templ = {items, 3};
    seedAsn1->tag = BSL_ASN1_TAG_OCTETSTRING;
    BSL_ASN1_Buffer asn1Arr[2] = {*seedAsn1, *prvKeyAsn1};
    return BSL_ASN1_EncodeTemplate(&templ, asn1Arr, sizeof(asn1Arr) / sizeof(asn1Arr[0]),
        &bitStr->data, &bitStr->dataLen);
}

static int32_t ProcessMlkemPrvkeySeedOnlyFormat(BSL_ASN1_Buffer *seedAsn1, BSL_Buffer *bitStr)
{
    BSL_ASN1_TemplateItem seedItem[] = {{BSL_ASN1_CLASS_CTX_SPECIFIC, 0, 0}};
    BSL_ASN1_Template templ = {seedItem, 1};
    return BSL_ASN1_EncodeTemplate(&templ, seedAsn1, 1, &bitStr->data, &bitStr->dataLen);
}

static int32_t ProcessMlkemPrvkeyDkOnlyFormat(BSL_ASN1_Buffer *prvKeyAsn1, BSL_Buffer *bitStr)
{
    BSL_ASN1_TemplateItem prvKeyItem[] = {{BSL_ASN1_TAG_OCTETSTRING, 0, 0}};
    BSL_ASN1_Template templ = {prvKeyItem, 1};
    return BSL_ASN1_EncodeTemplate(&templ, prvKeyAsn1, 1, &bitStr->data, &bitStr->dataLen);
}

static int32_t GetMlkemDkInfo(CRYPT_EAL_PkeyCtx *ealPriKey, uint32_t *format, bool *hasSeed, BSL_ASN1_Buffer *seedAsn1,
                              BSL_ASN1_Buffer *dkAsn1)
{
    int32_t ret = CRYPT_EAL_PkeyCtrl(ealPriKey, CRYPT_CTRL_GET_MLKEM_DK_FORMAT, format, sizeof(uint32_t));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (*format >= (uint32_t)CRYPT_ALGO_MLKEM_DK_FORMAT_END) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLKEM_DK_FORMAT_ERROR);
        return CRYPT_MLKEM_DK_FORMAT_ERROR;
    }
    ret = CRYPT_EAL_PkeyCtrl(ealPriKey, CRYPT_CTRL_GET_MLKEM_SEED, seedAsn1->buff, MLKEM_SEED_BYTES_LEN);
    if (ret == CRYPT_SUCCESS) {
        *hasSeed = true;
    }
    if (*format == (uint32_t)CRYPT_ALGO_MLKEM_DK_FORMAT_SEED_ONLY ||
        *format == (uint32_t)CRYPT_ALGO_MLKEM_DK_FORMAT_BOTH) {
        if (!(*hasSeed)) {
            BSL_ERR_PUSH_ERROR(CRYPT_MLKEM_DK_FORMAT_ERROR);
            return CRYPT_MLKEM_DK_FORMAT_ERROR;
        }
    }
    CRYPT_EAL_PkeyPrv dk = {0};
    if (*format != CRYPT_ALGO_MLKEM_DK_FORMAT_SEED_ONLY) {
        dk.id = CRYPT_PKEY_ML_KEM;
        dk.key.kemDk.len = dkAsn1->len;
        dk.key.kemDk.data = BSL_SAL_Malloc(dkAsn1->len);
        if (dk.key.kemDk.data == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
        ret = CRYPT_EAL_PkeyGetPrv(ealPriKey, &dk);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            BSL_SAL_Free(dk.key.kemDk.data);
            return ret;
        }
        dkAsn1->buff = dk.key.kemDk.data;
    }
    return CRYPT_SUCCESS;
}

static int32_t ProcessMlkemPrvkeyFormat(CRYPT_EAL_PkeyCtx *ealPriKey, BSL_Buffer *bitStr, uint32_t dkLen)
{
    uint32_t format = 0;
    bool hasSeed = false;
    uint8_t seedBuf[MLKEM_SEED_BYTES_LEN] = {0};
    BSL_ASN1_Buffer seedAsn1 = {BSL_ASN1_CLASS_CTX_SPECIFIC, MLKEM_SEED_BYTES_LEN, seedBuf};
    BSL_ASN1_Buffer dkAsn1 = {BSL_ASN1_TAG_OCTETSTRING, dkLen, NULL};
    // exclude invalid cases
    int32_t ret = GetMlkemDkInfo(ealPriKey, &format, &hasSeed, &seedAsn1, &dkAsn1);
    if (ret != CRYPT_SUCCESS) {
        CleanSeedAndPrivKeyAsn1Buff(&seedAsn1, &dkAsn1);
        return ret;
    }
    if (hasSeed) {
        if (format == (uint32_t)CRYPT_ALGO_MLKEM_DK_FORMAT_SEED_ONLY) {
            // seed-only
            ret = ProcessMlkemPrvkeySeedOnlyFormat(&seedAsn1, bitStr);
            CleanSeedAndPrivKeyAsn1Buff(&seedAsn1, &dkAsn1);
            return ret;
        }
        if (format == (uint32_t)CRYPT_ALGO_MLKEM_DK_FORMAT_BOTH ||
            format == (uint32_t)CRYPT_ALGO_MLKEM_DK_FORMAT_NOT_SET) {
            // both
            ret = ProcessMlkemPrvkeyBothFormat(&seedAsn1, &dkAsn1, bitStr);
            CleanSeedAndPrivKeyAsn1Buff(&seedAsn1, &dkAsn1);
            return ret;
        }
    }
    // dk-only
    ret = ProcessMlkemPrvkeyDkOnlyFormat(&dkAsn1, bitStr);
    CleanSeedAndPrivKeyAsn1Buff(&seedAsn1, &dkAsn1);
    return ret;
}

static int32_t EncodeMlKemPrikeyAsn1Buff(CRYPT_EAL_PkeyCtx *ealPriKey, BSL_Buffer *bitStr, BslCid *bslCid)
{
    uint32_t prvKeyLen = 0;
    int32_t ret = CRYPT_EAL_PkeyCtrl(ealPriKey, CRYPT_CTRL_GET_PRVKEY_LEN, &prvKeyLen, sizeof(uint32_t));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CRYPT_EAL_PkeyCtrl(ealPriKey, CRYPT_CTRL_GET_PARAID, bslCid, sizeof(int32_t));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return ProcessMlkemPrvkeyFormat(ealPriKey, bitStr, prvKeyLen);
}
#endif // HITLS_CRYPTO_MLKEM

#ifdef HITLS_CRYPTO_XMSS
static int32_t EncodeXmssPubkeyAsn1Buff(CRYPT_EAL_PkeyCtx *ealPubKey, BSL_Buffer *bitStr)
{
    uint32_t pubLen = 0;
    uint32_t ret = CRYPT_EAL_PkeyCtrl(ealPubKey, CRYPT_CTRL_GET_PUBKEY_LEN, &pubLen, sizeof(uint32_t));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint32_t hashLen = (pubLen - 4) / 2; // 4 bytes for algorithm type
    uint8_t *pub = (uint8_t *)BSL_SAL_Malloc(pubLen);
    if (pub == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = CRYPT_EAL_PkeyCtrl(ealPubKey, CRYPT_CTRL_GET_XMSS_XDR_ALG_TYPE, pub, 4);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(pub);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    CRYPT_EAL_PkeyPub pubKey = {
        .id = CRYPT_PKEY_XMSS,
        .key.xmssPub = {.seed = pub + 4 + hashLen, .root = pub + 4, .len = hashLen}
    };
    ret = CRYPT_EAL_PkeyGetPub(ealPubKey, &pubKey);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(pub);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    bitStr->data = pub;
    bitStr->dataLen = pubLen;
    return CRYPT_SUCCESS;
}
#endif // HITLS_CRYPTO_XMSS

static int32_t EncodePk8AlgidAny(CRYPT_EAL_PkeyCtx *ealPriKey, BSL_Buffer *bitStr,
    BSL_ASN1_Buffer *keyParam, BslCid *cidOut)
{
    (void)keyParam;
    int32_t ret;
    BSL_Buffer tmp = {0};
    CRYPT_PKEY_AlgId cid = CRYPT_EAL_PkeyGetId(ealPriKey);
    switch (cid) {
#ifdef HITLS_CRYPTO_RSA
        case CRYPT_PKEY_RSA:
            ret = EncodeRsaPrvKey(ealPriKey, keyParam, &tmp, &cid);
            break;
#endif
#if defined(HITLS_CRYPTO_ECDSA) || defined(HITLS_CRYPTO_SM2)
        case CRYPT_PKEY_ECDSA:
        case CRYPT_PKEY_SM2:
            cid = (CRYPT_PKEY_AlgId)BSL_CID_EC_PUBLICKEY;
            ret = EncodeEccPrikeyAsn1Buff(ealPriKey, keyParam, &tmp);
            break;
#endif
#ifdef HITLS_CRYPTO_ED25519
        case CRYPT_PKEY_ED25519:
            ret = EncodeEd25519PrikeyAsn1Buff(ealPriKey, &tmp);
            break;
#endif
#ifdef HITLS_CRYPTO_MLDSA
        case CRYPT_PKEY_ML_DSA:
            ret = EncodeMldsaPrikeyAsn1Buff(ealPriKey, &tmp, (BslCid *)&cid);
            break;
#endif
#ifdef HITLS_CRYPTO_SLH_DSA
        case CRYPT_PKEY_SLH_DSA:
            ret = EncodeSlhDsaPrikeyAsn1Buff(ealPriKey, &tmp, (BslCid *)&cid);
            break;
#endif
#ifdef HITLS_CRYPTO_MLKEM
        case CRYPT_PKEY_ML_KEM:
            ret = EncodeMlKemPrikeyAsn1Buff(ealPriKey, &tmp, (BslCid *)&cid);
            break;
#endif
        default:
            ret = CRYPT_DECODE_NO_SUPPORT_TYPE;
            break;
    }
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    bitStr->data = tmp.data;
    bitStr->dataLen = tmp.dataLen;
    *cidOut = (BslCid)cid;
    return ret;
}

int32_t EncodePk8PriKeyBuff(CRYPT_EAL_PkeyCtx *ealPriKey, BSL_Buffer *asn1)
{
    int32_t ret;
    BSL_Buffer bitStr = {0};
    CRYPT_ENCODE_DECODE_Pk8PrikeyInfo pk8PrikeyInfo = {0};
    do {
        ret = EncodePk8AlgidAny(ealPriKey, &bitStr, &pk8PrikeyInfo.keyParam, &pk8PrikeyInfo.keyType);
        if (ret != CRYPT_SUCCESS) {
            break;
        }
        pk8PrikeyInfo.pkeyRawKey = bitStr.data;
        pk8PrikeyInfo.pkeyRawKeyLen = bitStr.dataLen;
        ret = CRYPT_ENCODE_Pkcs8Info(&pk8PrikeyInfo, asn1);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            break;
        }
    } while (0);
    // rsa-pss mode release buffer
    if (pk8PrikeyInfo.keyParam.tag == (BSL_ASN1_TAG_SEQUENCE | BSL_ASN1_TAG_CONSTRUCTED)) {
        BSL_SAL_FREE(pk8PrikeyInfo.keyParam.buff);
    }
    BSL_SAL_ClearFree(bitStr.data, bitStr.dataLen);
    return ret;
}

#ifdef HITLS_CRYPTO_KEY_EPKI
static int32_t CheckEncodeParam(const CRYPT_EncodeParam *encodeParam)
{
    if (encodeParam == NULL || encodeParam->param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (encodeParam->deriveMode != CRYPT_DERIVE_PBKDF2) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENCODE_NO_SUPPORT_TYPE);
        return CRYPT_ENCODE_NO_SUPPORT_TYPE;
    }
    CRYPT_Pbkdf2Param *pkcsParam = (CRYPT_Pbkdf2Param *)encodeParam->param;
    if (pkcsParam->pwdLen > PWD_MAX_LEN || (pkcsParam->pwd == NULL && pkcsParam->pwdLen != 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    if (pkcsParam->pbesId != BSL_CID_PBES2 || pkcsParam->pbkdfId != BSL_CID_PBKDF2) {
        BSL_ERR_PUSH_ERROR(CRYPT_ERR_ALGID);
        return CRYPT_ERR_ALGID;
    }
    return CRYPT_SUCCESS;
}

int32_t EncodePk8EncPriKeyBuff(CRYPT_EAL_LibCtx *libCtx, const char *attrName, CRYPT_EAL_PkeyCtx *ealPriKey,
    const CRYPT_EncodeParam *encodeParam, BSL_Buffer *encode)
{
    /* EncAlgid */
    int32_t ret = CheckEncodeParam(encodeParam);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    CRYPT_Pbkdf2Param *pkcs8Param = (CRYPT_Pbkdf2Param *)encodeParam->param;
    BSL_Buffer unEncrypted = {0};
    ret = EncodePk8PriKeyBuff(ealPriKey, &unEncrypted);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    BSL_ASN1_Buffer asn1[CRYPT_PKCS_ENCPRIKEY_MAX] = {0};

    ret = CRYPT_ENCODE_PkcsEncryptedBuff(libCtx, attrName, pkcs8Param, &unEncrypted, asn1);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ClearFree(unEncrypted.data, unEncrypted.dataLen);
        return ret;
    }

    BSL_ASN1_Template templ = {g_pk8EncPriKeyTempl, sizeof(g_pk8EncPriKeyTempl) / sizeof(g_pk8EncPriKeyTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asn1, CRYPT_PKCS_ENCPRIKEY_MAX, &encode->data, &encode->dataLen);
    BSL_SAL_ClearFree(unEncrypted.data, unEncrypted.dataLen);
    BSL_SAL_ClearFree(asn1[CRYPT_PKCS_ENCPRIKEY_DERPARAM_IDX].buff, asn1[CRYPT_PKCS_ENCPRIKEY_DERPARAM_IDX].len);
    BSL_SAL_ClearFree(asn1[CRYPT_PKCS_ENCPRIKEY_SYMIV_IDX].buff, asn1[CRYPT_PKCS_ENCPRIKEY_SYMIV_IDX].len);
    BSL_SAL_FREE(asn1[CRYPT_PKCS_ENCPRIKEY_ENCDATA_IDX].buff);
    return ret;
}
#endif // HITLS_CRYPTO_KEY_EPKI

static int32_t CRYPT_EAL_SubPubkeyGetInfo(CRYPT_EAL_PkeyCtx *ealPubKey, BSL_ASN1_Buffer *algo, BSL_Buffer *bitStr)
{
    int32_t ret = CRYPT_ERR_ALGID;
    CRYPT_PKEY_AlgId cid = CRYPT_EAL_PkeyGetId(ealPubKey);
    BSL_Buffer bitTmp = {0};
    BSL_ASN1_Buffer algoId[BSL_ASN1_TAG_ALGOID_ANY_IDX + 1] = {0};
#ifdef HITLS_CRYPTO_RSA
    if (cid == CRYPT_PKEY_RSA) {
        ret = EncodeRsaPubkeyAsn1Buff(ealPubKey, &algoId[BSL_ASN1_TAG_ALGOID_ANY_IDX], &bitTmp);
        if (algoId[BSL_ASN1_TAG_ALGOID_ANY_IDX].tag == (BSL_ASN1_TAG_SEQUENCE | BSL_ASN1_TAG_CONSTRUCTED)) {
            cid = (CRYPT_PKEY_AlgId)BSL_CID_RSASSAPSS;
        }
    }
#endif
#if defined(HITLS_CRYPTO_ECDSA) || defined(HITLS_CRYPTO_SM2)
    if (cid == CRYPT_PKEY_ECDSA || cid == CRYPT_PKEY_SM2) {
        cid = (CRYPT_PKEY_AlgId)BSL_CID_EC_PUBLICKEY;
        ret = EncodeEccPubkeyAsn1Buff(ealPubKey, &algoId[BSL_ASN1_TAG_ALGOID_ANY_IDX], &bitTmp);
    }
#endif
#ifdef HITLS_CRYPTO_ED25519
    if (cid == CRYPT_PKEY_ED25519) {
        ret = EncodeEd25519PubkeyAsn1Buff(ealPubKey, &bitTmp);
    }
#endif
#ifdef HITLS_CRYPTO_MLDSA
    if (cid == CRYPT_PKEY_ML_DSA) {
        ret = EncodeMldsaPubkeyAsn1Buff(ealPubKey, &bitTmp, (BslCid *)&cid);
    }
#endif
#ifdef HITLS_CRYPTO_SLH_DSA
    if (cid == CRYPT_PKEY_SLH_DSA) {
        ret = EncodeSlhDsaPubkeyAsn1Buff(ealPubKey, &bitTmp, (BslCid *)&cid);
    }
#endif
#ifdef HITLS_CRYPTO_MLKEM
    if (cid == CRYPT_PKEY_ML_KEM) {
        ret = EncodeMlKemPubkeyAsn1Buff(ealPubKey, &bitTmp, (BslCid *)&cid);
    }
#endif

#ifdef HITLS_CRYPTO_XMSS
    if (cid == CRYPT_PKEY_XMSS) {
        ret = EncodeXmssPubkeyAsn1Buff(ealPubKey, &bitTmp);
    }
#endif

    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BslOidString *oidStr = BSL_OBJ_GetOID((BslCid)cid);
    if (oidStr == NULL) {
        BSL_SAL_FREE(bitTmp.data);
        ret = CRYPT_ERR_ALGID;
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    algoId[BSL_ASN1_TAG_ALGOID_IDX].buff = (uint8_t *)oidStr->octs;
    algoId[BSL_ASN1_TAG_ALGOID_IDX].len = oidStr->octetLen;
    algoId[BSL_ASN1_TAG_ALGOID_IDX].tag = BSL_ASN1_TAG_OBJECT_ID;
    ret = CRYPT_ENCODE_AlgoIdAsn1Buff(algoId, BSL_ASN1_TAG_ALGOID_ANY_IDX + 1, &algo->buff, &algo->len);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_FREE(bitTmp.data);
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    bitStr->data = bitTmp.data;
    bitStr->dataLen = bitTmp.dataLen;
EXIT:
#ifdef HITLS_CRYPTO_RSA
    if (cid == (CRYPT_PKEY_AlgId)BSL_CID_RSASSAPSS) {
        BSL_SAL_FREE(algoId[BSL_ASN1_TAG_ALGOID_ANY_IDX].buff);
    }
#endif
    return ret;
}

int32_t CRYPT_EAL_EncodeAsn1SubPubkey(CRYPT_EAL_PkeyCtx *ealPubKey, bool isComplete, BSL_Buffer *encodeH)
{
    BSL_ASN1_Buffer algo = {0};
    BSL_Buffer bitStr = {0};
    int32_t ret = CRYPT_EAL_SubPubkeyGetInfo(ealPubKey, &algo, &bitStr);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CRYPT_ENCODE_SubPubkeyByInfo(&algo, &bitStr, encodeH, isComplete);
    BSL_SAL_FREE(bitStr.data);
    BSL_SAL_FREE(algo.buff);
    return ret;
}

#ifdef HITLS_CRYPTO_RSA
int32_t EncodeHashAlg(CRYPT_MD_AlgId mdId, BSL_ASN1_Buffer *asn)
{
    if (mdId == CRYPT_MD_SHA1) {
        asn->tag = BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | CRYPT_ASN1_CTX_SPECIFIC_TAG_RSAPSS_HASH;
        asn->buff = NULL;
        asn->len = 0;
        return CRYPT_SUCCESS;
    }

    BslOidString *oidStr = BSL_OBJ_GetOID((BslCid)mdId);
    if (oidStr == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ERR_ALGID);
        return CRYPT_ERR_ALGID;
    }

    BSL_ASN1_TemplateItem hashTempl[] = {
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
            {BSL_ASN1_TAG_OBJECT_ID, 0, 1},
            {BSL_ASN1_TAG_ANY, BSL_ASN1_FLAG_OPTIONAL, 1},
    };
    BSL_ASN1_Template templ = {hashTempl, sizeof(hashTempl) / sizeof(hashTempl[0])};
    BSL_ASN1_Buffer asnArr[2] = {
        {BSL_ASN1_TAG_OBJECT_ID, oidStr->octetLen, (uint8_t *)oidStr->octs},
        {BSL_ASN1_TAG_NULL, 0, NULL},
    };
    int32_t ret = BSL_ASN1_EncodeTemplate(&templ, asnArr, 2, &(asn->buff), &(asn->len)); // 2: oid and null
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
    BslOidString *mgfStr = BSL_OBJ_GetOID(BSL_CID_MGF1);
    if (mgfStr == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ERR_ALGID);
        return CRYPT_ERR_ALGID;
    }

    BslOidString *oidStr = BSL_OBJ_GetOID((BslCid)mgfId);
    if (oidStr == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ERR_ALGID);
        return CRYPT_ERR_ALGID;
    }

    BSL_ASN1_TemplateItem mgfTempl[] = {
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
            {BSL_ASN1_TAG_OBJECT_ID, 0, 1},
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1},
                {BSL_ASN1_TAG_OBJECT_ID, 0, 2},
                {BSL_ASN1_TAG_ANY, BSL_ASN1_FLAG_OPTIONAL, 2},
    };
    BSL_ASN1_Template templ = {mgfTempl, sizeof(mgfTempl) / sizeof(mgfTempl[0])};
    BSL_ASN1_Buffer asnArr[3] = {
        {BSL_ASN1_TAG_OBJECT_ID, mgfStr->octetLen, (uint8_t *)mgfStr->octs},
        {BSL_ASN1_TAG_OBJECT_ID, oidStr->octetLen, (uint8_t *)oidStr->octs},
        {BSL_ASN1_TAG_NULL, 0, NULL}, // param
    };
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
int32_t CRYPT_EAL_EncodeRsaPssAlgParam(const CRYPT_RSA_PssPara *rsaPssParam, uint8_t **buf, uint32_t *bufLen)
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
#endif // HITLS_CRYPTO_RSA
#endif // HITLS_CRYPTO_KEY_ENCODE

#ifdef HITLS_PKI_PKCS12
#define HITLS_P7_SPECIFIC_ENCONTENTINFO_EXTENSION 0

/**
 * EncryptedContentInfo ::= SEQUENCE {
 *      contentType ContentType,
 *      contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
 *      encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL
 * }
 *
 * https://datatracker.ietf.org/doc/html/rfc5652#section-6.1
 */

static BSL_ASN1_TemplateItem g_enContentInfoTempl[] = {
         /* ContentType */
        {BSL_ASN1_TAG_OBJECT_ID, 0, 0},
         /* ContentEncryptionAlgorithmIdentifier */
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0}, // ContentEncryptionAlgorithmIdentifier
            {BSL_ASN1_TAG_OBJECT_ID, 0, 1},
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1},
                    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 2}, // derivation param
                    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 2}, // enc scheme
                        {BSL_ASN1_TAG_OBJECT_ID, 0, 3}, // alg
                        {BSL_ASN1_TAG_OCTETSTRING, 0, 3}, // iv
         /* encryptedContent */
        {BSL_ASN1_CLASS_CTX_SPECIFIC |  HITLS_P7_SPECIFIC_ENCONTENTINFO_EXTENSION, BSL_ASN1_FLAG_OPTIONAL, 0},
};

typedef enum {
    HITLS_P7_ENC_CONTINFO_TYPE_IDX,
    HITLS_P7_ENC_CONTINFO_ENCALG_IDX,
    HITLS_P7_ENC_CONTINFO_DERIVE_PARAM_IDX,
    HITLS_P7_ENC_CONTINFO_SYMALG_IDX,
    HITLS_P7_ENC_CONTINFO_SYMIV_IDX,
    HITLS_P7_ENC_CONTINFO_ENCONTENT_IDX,
    HITLS_P7_ENC_CONTINFO_MAX_IDX,
} HITLS_P7_ENC_CONTINFO_IDX;

#define HITLS_P7_SPECIFIC_UNPROTECTEDATTRS_EXTENSION 1

/**
 * EncryptedData ::= SEQUENCE {
 *      version CMSVersion,
 *      encryptedContentInfo EncryptedContentInfo,
 *      unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL
 * }
 *
 * https://datatracker.ietf.org/doc/html/rfc5652#page-29
*/
static BSL_ASN1_TemplateItem g_encryptedDataTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        /* version */
        {BSL_ASN1_TAG_INTEGER, 0, 1},
        /* EncryptedContentInfo */
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 1},
        /* unprotectedAttrs */
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET | HITLS_P7_SPECIFIC_UNPROTECTEDATTRS_EXTENSION,
            BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 1},
};

typedef enum {
    HITLS_P7_ENCRYPTDATA_VERSION_IDX,
    HITLS_P7_ENCRYPTDATA_ENCRYPTINFO_IDX,
    HITLS_P7_ENCRYPTDATA_UNPROTECTEDATTRS_IDX,
    HITLS_P7_ENCRYPTDATA_MAX_IDX,
} HITLS_P7_ENCRYPTDATA_IDX;

#ifdef HITLS_PKI_PKCS12_PARSE
static int32_t ParsePKCS7EncryptedContentInfo(CRYPT_EAL_LibCtx *libCtx, const char *attrName, BSL_Buffer *encode,
    const uint8_t *pwd, uint32_t pwdlen, BSL_Buffer *output)
{
    uint8_t *temp = encode->data;
    uint32_t  tempLen = encode->dataLen;
    BSL_ASN1_Buffer asn1[HITLS_P7_ENC_CONTINFO_MAX_IDX] = {0};
    BSL_ASN1_Template templ = {g_enContentInfoTempl, sizeof(g_enContentInfoTempl) / sizeof(g_enContentInfoTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &temp, &tempLen, asn1, HITLS_P7_ENC_CONTINFO_MAX_IDX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BslCid cid = BSL_OBJ_GetCidFromOidBuff(asn1[HITLS_P7_ENC_CONTINFO_TYPE_IDX].buff,
        asn1[HITLS_P7_ENC_CONTINFO_TYPE_IDX].len);
    if (cid != BSL_CID_PKCS7_SIMPLEDATA) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_UNSUPPORTED_PKCS7_TYPE);
        return CRYPT_DECODE_UNSUPPORTED_PKCS7_TYPE;
    }
    cid = BSL_OBJ_GetCidFromOidBuff(asn1[HITLS_P7_ENC_CONTINFO_ENCALG_IDX].buff,
        asn1[HITLS_P7_ENC_CONTINFO_ENCALG_IDX].len);
    if (cid != BSL_CID_PBES2) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_UNSUPPORTED_ENCRYPT_TYPE);
        return CRYPT_DECODE_UNSUPPORTED_ENCRYPT_TYPE;
    }
    // parse sym alg id
    BslCid symId = BSL_OBJ_GetCidFromOidBuff(asn1[HITLS_P7_ENC_CONTINFO_SYMALG_IDX].buff,
        asn1[HITLS_P7_ENC_CONTINFO_SYMALG_IDX].len);
    if (symId == BSL_CID_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_UNKNOWN_OID);
        return CRYPT_DECODE_UNKNOWN_OID;
    }
    BSL_Buffer derivekeyData = {asn1[HITLS_P7_ENC_CONTINFO_DERIVE_PARAM_IDX].buff,
        asn1[HITLS_P7_ENC_CONTINFO_DERIVE_PARAM_IDX].len};
    BSL_Buffer ivData = {asn1[HITLS_P7_ENC_CONTINFO_SYMIV_IDX].buff, asn1[HITLS_P7_ENC_CONTINFO_SYMIV_IDX].len};
    BSL_Buffer enData = {asn1[HITLS_P7_ENC_CONTINFO_ENCONTENT_IDX].buff, asn1[HITLS_P7_ENC_CONTINFO_ENCONTENT_IDX].len};
    EncryptPara encPara = {.derivekeyData = &derivekeyData, .ivData = &ivData, .enData = &enData};
    BSL_Buffer pwdBuffer = {(uint8_t *)(uintptr_t)pwd, pwdlen};
    ret = CRYPT_DECODE_ParseEncDataAsn1(libCtx, attrName, symId, &encPara, &pwdBuffer, NULL, output);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t CRYPT_EAL_ParseAsn1PKCS7EncryptedData(CRYPT_EAL_LibCtx *libCtx, const char *attrName, BSL_Buffer *encode,
    const uint8_t *pwd, uint32_t pwdlen, BSL_Buffer *output)
{
    if (encode == NULL || pwd == NULL || output == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pwdlen > PWD_MAX_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    uint8_t *temp = encode->data;
    uint32_t  tempLen = encode->dataLen;
    BSL_ASN1_Buffer asn1[HITLS_P7_ENCRYPTDATA_MAX_IDX] = {0};
    BSL_ASN1_Template templ = {g_encryptedDataTempl, sizeof(g_encryptedDataTempl) / sizeof(g_encryptedDataTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &temp, &tempLen, asn1, HITLS_P7_ENCRYPTDATA_MAX_IDX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint32_t version = 0;
    ret = BSL_ASN1_DecodePrimitiveItem(&asn1[HITLS_P7_ENCRYPTDATA_VERSION_IDX], &version);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (version == 0 && asn1[HITLS_P7_ENCRYPTDATA_UNPROTECTEDATTRS_IDX].buff != NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_PKCS7_INVALIDE_ENCRYPTDATA_TYPE);
        return CRYPT_DECODE_PKCS7_INVALIDE_ENCRYPTDATA_TYPE;
    }
    // In RFC5652, if the encapsulated content type is other than id-data, then the value of version MUST be 2.
    if (version == 2 && asn1[HITLS_P7_ENCRYPTDATA_UNPROTECTEDATTRS_IDX].buff == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_PKCS7_INVALIDE_ENCRYPTDATA_TYPE);
        return CRYPT_DECODE_PKCS7_INVALIDE_ENCRYPTDATA_TYPE;
    }
    BSL_Buffer encryptInfo = {asn1[HITLS_P7_ENCRYPTDATA_ENCRYPTINFO_IDX].buff,
        asn1[HITLS_P7_ENCRYPTDATA_ENCRYPTINFO_IDX].len};
    ret = ParsePKCS7EncryptedContentInfo(libCtx, attrName, &encryptInfo, pwd, pwdlen, output);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}
#endif // HITLS_PKI_PKCS12_PARSE

#ifdef HITLS_PKI_PKCS12_GEN
/* Encode PKCS7-EncryptData：only support PBES2 + PBKDF2, the param check ref CheckEncodeParam. */
static int32_t EncodePKCS7EncryptedContentInfo(CRYPT_EAL_LibCtx *libCtx, const char *attrName, BSL_Buffer *data,
    const CRYPT_EncodeParam *encodeParam, BSL_Buffer *encode)
{
    /* EncAlgid */
    int32_t ret = CheckEncodeParam(encodeParam);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    CRYPT_Pbkdf2Param *pkcs7Param = (CRYPT_Pbkdf2Param *)encodeParam->param;
    BSL_ASN1_Buffer asn1[CRYPT_PKCS_ENCPRIKEY_MAX] = {0};

    ret = CRYPT_ENCODE_PkcsEncryptedBuff(libCtx, attrName, pkcs7Param, data, asn1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    do {
        BslOidString *oidStr = BSL_OBJ_GetOID(BSL_CID_PKCS7_SIMPLEDATA);
        if (oidStr == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_ERR_ALGID);
            ret = CRYPT_ERR_ALGID;
            break;
        }
        BSL_ASN1_Buffer p7asn[HITLS_P7_ENC_CONTINFO_MAX_IDX] = {
            {BSL_ASN1_TAG_OBJECT_ID, oidStr->octetLen, (uint8_t *)oidStr->octs},
            {asn1[CRYPT_PKCS_ENCPRIKEY_ENCALG_IDX].tag,
                asn1[CRYPT_PKCS_ENCPRIKEY_ENCALG_IDX].len, asn1[CRYPT_PKCS_ENCPRIKEY_ENCALG_IDX].buff},
            {asn1[CRYPT_PKCS_ENCPRIKEY_DERPARAM_IDX].tag,
                asn1[CRYPT_PKCS_ENCPRIKEY_DERPARAM_IDX].len, asn1[CRYPT_PKCS_ENCPRIKEY_DERPARAM_IDX].buff},
            {asn1[CRYPT_PKCS_ENCPRIKEY_SYMALG_IDX].tag,
                asn1[CRYPT_PKCS_ENCPRIKEY_SYMALG_IDX].len, asn1[CRYPT_PKCS_ENCPRIKEY_SYMALG_IDX].buff},
            {asn1[CRYPT_PKCS_ENCPRIKEY_SYMIV_IDX].tag,
                asn1[CRYPT_PKCS_ENCPRIKEY_SYMIV_IDX].len, asn1[CRYPT_PKCS_ENCPRIKEY_SYMIV_IDX].buff},
            {BSL_ASN1_CLASS_CTX_SPECIFIC | HITLS_P7_SPECIFIC_ENCONTENTINFO_EXTENSION,
                asn1[CRYPT_PKCS_ENCPRIKEY_ENCDATA_IDX].len, asn1[CRYPT_PKCS_ENCPRIKEY_ENCDATA_IDX].buff},
        };
        BSL_ASN1_Template templ = {g_enContentInfoTempl,
            sizeof(g_enContentInfoTempl) / sizeof(g_enContentInfoTempl[0])};
        ret = BSL_ASN1_EncodeTemplate(&templ, p7asn, HITLS_P7_ENC_CONTINFO_MAX_IDX, &encode->data, &encode->dataLen);
    } while (0);
    BSL_SAL_ClearFree(asn1[CRYPT_PKCS_ENCPRIKEY_DERPARAM_IDX].buff, asn1[CRYPT_PKCS_ENCPRIKEY_DERPARAM_IDX].len);
    BSL_SAL_ClearFree(asn1[CRYPT_PKCS_ENCPRIKEY_SYMIV_IDX].buff, asn1[CRYPT_PKCS_ENCPRIKEY_SYMIV_IDX].len);
    BSL_SAL_FREE(asn1[CRYPT_PKCS_ENCPRIKEY_ENCDATA_IDX].buff);
    return ret;
}

int32_t CRYPT_EAL_EncodePKCS7EncryptDataBuff(CRYPT_EAL_LibCtx *libCtx, const char *attrName, BSL_Buffer *data,
    const void *encodeParam, BSL_Buffer *encode)
{
    if (data == NULL || encodeParam == NULL || encode == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    BSL_Buffer contentInfo = {0};
    int32_t ret = EncodePKCS7EncryptedContentInfo(libCtx, attrName, data, encodeParam, &contentInfo);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint8_t version = 0;
    BSL_ASN1_Buffer asn1[HITLS_P7_ENCRYPTDATA_MAX_IDX] = {
        {BSL_ASN1_TAG_INTEGER, sizeof(version), &version},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, contentInfo.dataLen, contentInfo.data},
        {0, 0, 0},
    };
    BSL_ASN1_Template templ = {g_encryptedDataTempl, sizeof(g_encryptedDataTempl) / sizeof(g_encryptedDataTempl[0])};
    BSL_Buffer tmp = {0};
    ret = BSL_ASN1_EncodeTemplate(&templ, asn1, HITLS_P7_ENCRYPTDATA_MAX_IDX, &tmp.data, &tmp.dataLen);
    BSL_SAL_FREE(contentInfo.data);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    encode->data = tmp.data;
    encode->dataLen = tmp.dataLen;
    return ret;
}
#endif // HITLS_PKI_PKCS12_GEN

#endif // HITLS_PKI_PKCS12

#endif // HITLS_CRYPTO_CODECSKEY
