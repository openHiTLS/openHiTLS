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
#ifdef HITLS_CRYPTO_ENCODE
#include <stdint.h>
#include <string.h>

#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_asn1.h"
#include "bsl_pem_internal.h"
#include "crypt_ecc.h"
#include "crypt_eal_pkey.h"
#include "crypt_errno.h"
#include "bsl_obj_internal.h"
#include "crypt_eal_encode.h"
#include "crypt_eal_kdf.h"
#include "crypt_eal_cipher.h"
#include "sal_file.h"
#include "bsl_bytes.h"
#include "crypt_types.h"
#include "crypt_eal_rand.h"
#include "crypt_encode.h"
#include "bsl_params.h"
#include "crypt_params_type.h"

#define PATH_MAX_LEN 4096
#define PWD_MAX_LEN 4096

// clang-format off
/**
 * RSAPublicKey  ::=  SEQUENCE  {
 *        modulus            INTEGER,    -- n
 *        publicExponent     INTEGER  }  -- e
 *
 * https://datatracker.ietf.org/doc/html/rfc4055#autoid-3
 */
static BSL_ASN1_TemplateItem rsaPubTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0}, /* ignore seq */
        {BSL_ASN1_TAG_INTEGER, 0, 1}, /* n */
        {BSL_ASN1_TAG_INTEGER, 0, 1}, /* e */
};

typedef enum {
    CRYPT_RSA_PUB_N_IDX = 0,
    CRYPT_RSA_PUB_E_IDX = 1,
} CRYPT_RSA_PUB_TEMPL_IDX;

/**
 *   RSAPrivateKey ::= SEQUENCE {
 *       version           Version,
 *       modulus           INTEGER,  -- n
 *       publicExponent    INTEGER,  -- e
 *       privateExponent   INTEGER,  -- d
 *       prime1            INTEGER,  -- p
 *       prime2            INTEGER,  -- q
 *       exponent1         INTEGER,  -- d mod (p-1)
 *       exponent2         INTEGER,  -- d mod (q-1)
 *       coefficient       INTEGER,  -- (inverse of q) mod p
 *       otherPrimeInfos   OtherPrimeInfos OPTIONAL
 *   }
 *
 * https://datatracker.ietf.org/doc/html/rfc3447#autoid-39
*/

static BSL_ASN1_TemplateItem rsaPrvTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0}, /* ignore seq header */
        {BSL_ASN1_TAG_INTEGER, 0, 1}, /* version */
        {BSL_ASN1_TAG_INTEGER, 0, 1}, /* n */
        {BSL_ASN1_TAG_INTEGER, 0, 1}, /* e */
        {BSL_ASN1_TAG_INTEGER, 0, 1}, /* d */
        {BSL_ASN1_TAG_INTEGER, 0, 1}, /* p */
        {BSL_ASN1_TAG_INTEGER, 0, 1}, /* q */
        {BSL_ASN1_TAG_INTEGER, 0, 1}, /* d mod (p-1) */
        {BSL_ASN1_TAG_INTEGER, 0, 1}, /* d mod (q-1) */
        {BSL_ASN1_TAG_INTEGER, 0, 1}, /* q^-1 mod p */
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE,
         BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_SAME, 1}, /* OtherPrimeInfos OPTIONAL */
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 2}, /* OtherPrimeInfo */
                {BSL_ASN1_TAG_INTEGER, 0, 3}, /* ri */
                {BSL_ASN1_TAG_INTEGER, 0, 3}, /* di */
                {BSL_ASN1_TAG_INTEGER, 0, 3} /* ti */
};

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


/**
 * AlgorithmIdentifier  ::=  SEQUENCE  {
 *      algorithm               OBJECT IDENTIFIER,
 *      parameters              ANY DEFINED BY algorithm OPTIONAL  }
 *
 * https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.1.2
*/
static BSL_ASN1_TemplateItem algoIdTempl[] = {
    {BSL_ASN1_TAG_OBJECT_ID, 0, 0},
    {BSL_ASN1_TAG_ANY, BSL_ASN1_FLAG_OPTIONAL, 0},
};

typedef enum {
    BSL_ASN1_TAG_ALGOID_IDX = 0,
    BSL_ASN1_TAG_ALGOID_ANY_IDX = 1,
} ALGOID_TEMPL_IDX;

/**
 * SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *      algorithm         AlgorithmIdentifier,
 *      subjectPublicKey  BIT STRING
 *    }
 *
 * https://datatracker.ietf.org/doc/html/rfc5480#autoid-3
*/
static BSL_ASN1_TemplateItem subKeyInfoTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 1},
        {BSL_ASN1_TAG_BITSTRING, 0, 1},
};

static BSL_ASN1_TemplateItem subKeyInfoInnerTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 0},
    {BSL_ASN1_TAG_BITSTRING, 0, 0},
};

typedef enum {
    CRYPT_SUBKEYINFO_ALGOID_IDX = 0,
    CRYPT_SUBKEYINFO_BITSTRING_IDX = 1,
} CRYPT_SUBKEYINFO_TEMPL_IDX;


/**
 * ECPrivateKey ::= SEQUENCE {
 *    version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
 *    privateKey     OCTET STRING,
 *    parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
 *    publicKey  [1] BIT STRING OPTIONAL
 *  }
 *
 * https://datatracker.ietf.org/doc/html/rfc5915#autoid-3
 */

#define BSL_ASN1_TAG_EC_PRIKEY_PARAM 0
#define BSL_ASN1_TAG_EC_PRIKEY_PUBKEY 1

static BSL_ASN1_TemplateItem ecPriKeyTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},  // ignore seq header
        {BSL_ASN1_TAG_INTEGER, 0, 1}, /* version */
        {BSL_ASN1_TAG_OCTETSTRING, 0, 1}, /* private key */
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_EC_PRIKEY_PARAM,
         BSL_ASN1_FLAG_OPTIONAL, 1},
            {BSL_ASN1_TAG_OBJECT_ID, 0, 2},
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_EC_PRIKEY_PUBKEY,
         BSL_ASN1_FLAG_OPTIONAL, 1},
            {BSL_ASN1_TAG_BITSTRING, 0, 2},
};

typedef enum {
    CRYPT_ECPRIKEY_VERSION_IDX = 0,
    CRYPT_ECPRIKEY_PRIKEY_IDX = 1,
    CRYPT_ECPRIKEY_PARAM_IDX = 2,
    CRYPT_ECPRIKEY_PUBKEY_IDX = 3,
} CRYPT_ECPRIKEY_TEMPL_IDX;

/**
 *  PrivateKeyInfo ::= SEQUENCE {
 *       version                   INTEGER,
 *       privateKeyAlgorithm       AlgorithmIdentifier,
 *       privateKey                OCTET STRING,
 *       attributes           [0]  IMPLICIT Attributes OPTIONAL }
 *
 * https://datatracker.ietf.org/doc/html/rfc5208#autoid-5
*/
static BSL_ASN1_TemplateItem pk8PriKeyTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0}, // ignore seq header
        {BSL_ASN1_TAG_INTEGER, 0, 1},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 1},
        {BSL_ASN1_TAG_OCTETSTRING, 0, 1},
};

typedef enum {
    CRYPT_PK8_PRIKEY_VERSION_IDX = 0,
    CRYPT_PK8_PRIKEY_ALGID_IDX = 1,
    CRYPT_PK8_PRIKEY_PRIKEY_IDX = 2,
} CRYPT_PK8_PRIKEY_TEMPL_IDX;

/**
 *  EncryptedPrivateKeyInfo ::= SEQUENCE {
 *      encryptionAlgorithm  EncryptionAlgorithmIdentifier,
 *      encryptedData        EncryptedData }
 *
 * https://datatracker.ietf.org/doc/html/rfc5208#autoid-6
*/
static BSL_ASN1_TemplateItem pk8EncPriKeyTempl[] = {
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

static BSL_ASN1_TemplateItem g_pbkdf2DerParamTempl[] = {
    {BSL_ASN1_TAG_OBJECT_ID, 0, 0}, // derive alg
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_OCTETSTRING, 0, 1}, // salt
        {BSL_ASN1_TAG_INTEGER, 0, 1}, // iteration
        {BSL_ASN1_TAG_INTEGER, BSL_ASN1_FLAG_OPTIONAL, 1}, // keyLen
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_DEFAULT | BSL_ASN1_FLAG_HEADERONLY, 1}, // prf
};

typedef enum {
    CRYPT_PKCS_ENCPRIKEY_ENCALG_IDX,
    CRYPT_PKCS_ENCPRIKEY_DERPARAM_IDX,
    CRYPT_PKCS_ENCPRIKEY_SYMALG_IDX,
    CRYPT_PKCS_ENCPRIKEY_SYMIV_IDX,
    CRYPT_PKCS_ENCPRIKEY_ENCDATA_IDX,
    CRYPT_PKCS_ENCPRIKEY_MAX
} CRYPT_PKCS_ENCPRIKEY_TEMPL_IDX;

typedef enum {
    CRYPT_PKCS_ENC_DERALG_IDX,
    CRYPT_PKCS_ENC_DERSALT_IDX,
    CRYPT_PKCS_ENC_DERITER_IDX,
    CRYPT_PKCS_ENC_DERKEYLEN_IDX,
    CRYPT_PKCS_ENC_DERPRF_IDX,
    CRYPT_PKCS_ENC_DERPARAM_MAX
} CRYPT_PKCS_ENC_DERIVEPARAM_IDX;

// clang-format on

static CRYPT_PKEY_ParaId GetParaId(uint8_t *octs, uint32_t octsLen)
{
    BslOidString oidStr = {octsLen, (char *)octs, 0};
    BslCid cid = BSL_OBJ_GetCIDFromOid(&oidStr);
    if (cid == BSL_CID_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return CRYPT_PKEY_PARAID_MAX;
    }
    return (CRYPT_PKEY_ParaId)cid;
}

static int32_t DecSubKeyInfoCb(int32_t type, int32_t idx, void *data, void *expVal)
{
    (void)idx;
    BSL_ASN1_Buffer *param = (BSL_ASN1_Buffer *)data;

    switch (type) {
        case BSL_ASN1_TYPE_GET_ANY_TAG: {
            BslOidString oidStr = {param->len, (char *)param->buff, 0};
            BslCid cid = BSL_OBJ_GetCIDFromOid(&oidStr);
            if (cid == BSL_CID_EC_PUBLICKEY) {
                // note: any It can be encoded empty or it can be null
                *(uint8_t *)expVal = BSL_ASN1_TAG_OBJECT_ID;
            } else if (cid == BSL_CID_RSASSAPSS) {
                *(uint8_t *)expVal = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
            } else {
                *(uint8_t *)expVal = BSL_ASN1_TAG_NULL; // is null
            }
            return CRYPT_SUCCESS;
        }
        default:
            break;
    }
    BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ASN1_BUFF_FAILED);
    return CRYPT_DECODE_ASN1_BUFF_FAILED;
}

static int32_t ParseAlgoIdAsn1Buff(uint8_t *buff, uint32_t buffLen, BSL_ASN1_Buffer *algoId, uint32_t algoIdNum)
{
    uint8_t *tmpBuff = buff;
    uint32_t tmpBuffLen = buffLen;

    BSL_ASN1_Template templ = {algoIdTempl, sizeof(algoIdTempl) / sizeof(algoIdTempl[0])};
    return BSL_ASN1_DecodeTemplate(&templ, DecSubKeyInfoCb, &tmpBuff, &tmpBuffLen, algoId, algoIdNum);
}

static int32_t EncodeAlgoIdAsn1Buff(BSL_ASN1_Buffer *algoId, uint32_t algoIdNum, uint8_t **buff, uint32_t *buffLen)
{
    BSL_ASN1_Template templ = {algoIdTempl, sizeof(algoIdTempl) / sizeof(algoIdTempl[0])};
    return BSL_ASN1_EncodeTemplate(&templ, algoId, algoIdNum, buff, buffLen);
}

static int32_t ProcRsaPssParam(BSL_ASN1_Buffer *rsaPssParam, CRYPT_EAL_PkeyCtx *ealPriKey)
{
    CRYPT_RsaPadType padType = CRYPT_PKEY_EMSA_PSS;
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

    return CRYPT_EAL_PkeyCtrl(ealPriKey, CRYPT_CTRL_SET_RSA_EMSA_PSS, &para, sizeof(CRYPT_RSA_PssPara));
}

static int32_t ParseRsaPubkeyAsn1Buff(uint8_t *buff, uint32_t buffLen, BSL_ASN1_Buffer *param,
    CRYPT_EAL_PkeyCtx **ealPubKey, BslCid cid)
{
    uint8_t *tmpBuff = buff;
    uint32_t tmpBuffLen = buffLen;
    // decode n and e
    BSL_ASN1_Buffer pubAsn1[CRYPT_RSA_PUB_E_IDX + 1] = {0};
    BSL_ASN1_Template pubTempl = {rsaPubTempl, sizeof(rsaPubTempl) / sizeof(rsaPubTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&pubTempl, NULL, &tmpBuff, &tmpBuffLen, pubAsn1, CRYPT_RSA_PUB_E_IDX + 1);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    CRYPT_EAL_PkeyCtx *pctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    if (pctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    CRYPT_EAL_PkeyPub pub;
    pub.id = CRYPT_PKEY_RSA;
    pub.key.rsaPub.n = pubAsn1[CRYPT_RSA_PUB_N_IDX].buff;
    pub.key.rsaPub.nLen = pubAsn1[CRYPT_RSA_PUB_N_IDX].len;
    pub.key.rsaPub.e = pubAsn1[CRYPT_RSA_PUB_E_IDX].buff;
    pub.key.rsaPub.eLen = pubAsn1[CRYPT_RSA_PUB_E_IDX].len;
    ret = CRYPT_EAL_PkeySetPub(pctx, &pub);
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

static bool IsEcdsaEcParaId(int32_t paraId)
{
    if (paraId == CRYPT_ECC_NISTP224 || paraId == CRYPT_ECC_NISTP256 ||
        paraId == CRYPT_ECC_NISTP384 || paraId == CRYPT_ECC_NISTP521 ||
        paraId == CRYPT_ECC_BRAINPOOLP256R1 || paraId == CRYPT_ECC_BRAINPOOLP384R1 ||
        paraId == CRYPT_ECC_BRAINPOOLP512R1) {
        return true;
    }
    return false;
}

static int32_t EccEalKeyNew(BSL_ASN1_Buffer *ecParamOid, int32_t *alg, CRYPT_EAL_PkeyCtx **ealKey)
{
    int32_t algId;
    CRYPT_PKEY_ParaId paraId = GetParaId(ecParamOid->buff, ecParamOid->len);
    if (paraId == CRYPT_ECC_SM2) {
        algId = CRYPT_PKEY_SM2;
    } else if (IsEcdsaEcParaId(paraId)) {
        algId = CRYPT_PKEY_ECDSA;
    } else { // scenario ecdh is not considered, and it will be improved in the future
        return CRYPT_DECODE_UNKNOWN_OID;
    }

    CRYPT_EAL_PkeyCtx *key = CRYPT_EAL_PkeyNewCtx(algId);
    if (key == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (paraId != CRYPT_ECC_SM2) {
        int32_t ret = CRYPT_EAL_PkeySetParaById(key, paraId);
        if (ret != CRYPT_SUCCESS) {
            CRYPT_EAL_PkeyFreeCtx(key);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    *ealKey = key;
    *alg = algId;
    return CRYPT_SUCCESS;
}

static int32_t ParseEccPubkeyAsn1Buff(BSL_ASN1_BitString *bitPubkey, BSL_ASN1_Buffer *ecParamOid,
    CRYPT_EAL_PkeyCtx **ealPubKey)
{
    int32_t algId;
    CRYPT_EAL_PkeyCtx *pctx = NULL;
    int32_t ret = EccEalKeyNew(ecParamOid, &algId, &pctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    CRYPT_EAL_PkeyPub pub;
    pub.id = algId;
    pub.key.eccPub.data = bitPubkey->buff;
    pub.key.eccPub.len = bitPubkey->len;
    ret = CRYPT_EAL_PkeySetPub(pctx, &pub);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pctx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *ealPubKey = pctx;
    return ret;
}

static int32_t ParseSubPubkeyAsn1(BSL_ASN1_Buffer *encode, CRYPT_EAL_PkeyCtx **ealPubKey)
{
    uint8_t *algoBuff = encode->buff; // AlgorithmIdentifier Tag and Len, 2 bytes.
    uint32_t algoBuffLen = encode->len;
    BSL_ASN1_Buffer algoId[BSL_ASN1_TAG_ALGOID_ANY_IDX + 1] = {0};
    int32_t ret = ParseAlgoIdAsn1Buff(algoBuff, algoBuffLen, algoId, BSL_ASN1_TAG_ALGOID_ANY_IDX + 1);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    BSL_ASN1_Buffer *oid = algoId; // OID
    BSL_ASN1_Buffer *algParam = algoId + 1; // the parameters
    BSL_ASN1_Buffer *pubkey = &encode[CRYPT_SUBKEYINFO_BITSTRING_IDX]; // the last BSL_ASN1_Buffer, the pubkey
    BSL_ASN1_BitString bitPubkey = {0};
    ret = BSL_ASN1_DecodePrimitiveItem(pubkey, &bitPubkey);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BslOidString oidStr = {oid->len, (char *)oid->buff, 0};
    BslCid cid = BSL_OBJ_GetCIDFromOid(&oidStr);
    if (cid == BSL_CID_EC_PUBLICKEY || cid == BSL_CID_SM2PRIME256) {
        return ParseEccPubkeyAsn1Buff(&bitPubkey, algParam, ealPubKey);
    } else if (cid == BSL_CID_RSA || cid == BSL_CID_RSASSAPSS) {
        return ParseRsaPubkeyAsn1Buff(bitPubkey.buff, bitPubkey.len, algParam, ealPubKey, cid);
    } else { // ed25519 448 will be added in the future
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_UNKNOWN_OID);
        return CRYPT_DECODE_UNKNOWN_OID;
    }
}

int32_t CRYPT_EAL_ParseAsn1SubPubkey(uint8_t *buff, uint32_t buffLen, void **ealPubKey, bool isComplete)
{
    uint8_t *tmpBuff = buff;
    uint32_t tmpBuffLen = buffLen;
    // decode sub pubkey info
    BSL_ASN1_Buffer pubAsn1[CRYPT_SUBKEYINFO_BITSTRING_IDX + 1] = {0};
    BSL_ASN1_Template pubTempl;
    if (isComplete) {
        pubTempl.templItems = subKeyInfoTempl;
        pubTempl.templNum = sizeof(subKeyInfoTempl) / sizeof(subKeyInfoTempl[0]);
    } else {
        pubTempl.templItems = subKeyInfoInnerTempl;
        pubTempl.templNum = sizeof(subKeyInfoInnerTempl) / sizeof(subKeyInfoInnerTempl[0]);
    }
    int32_t ret = BSL_ASN1_DecodeTemplate(&pubTempl, DecSubKeyInfoCb, &tmpBuff, &tmpBuffLen, pubAsn1,
                                          CRYPT_SUBKEYINFO_BITSTRING_IDX + 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    return ParseSubPubkeyAsn1(pubAsn1, (CRYPT_EAL_PkeyCtx **)ealPubKey);
}

static int32_t ParseEccPrikeyAsn1(BSL_ASN1_Buffer *encode, BSL_ASN1_Buffer *pk8AlgoParam,
                                  CRYPT_EAL_PkeyCtx **ealPriKey)
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
    if (pubkey->len == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ASN1_BUFF_FAILED);
        return CRYPT_DECODE_ASN1_BUFF_FAILED;
    }
    int32_t algId;
    CRYPT_EAL_PkeyCtx *pctx = NULL;
    int32_t ret = EccEalKeyNew(param, &algId, &pctx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    CRYPT_EAL_PkeyPrv prv;
    prv.id = algId;
    prv.key.eccPrv.data = prikey->buff;
    prv.key.eccPrv.len = prikey->len;
    ret = CRYPT_EAL_PkeySetPrv(pctx, &prv);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pctx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    CRYPT_EAL_PkeyPub pub;
    pub.id = algId;
    pub.key.eccPub.data = pubkey->buff + 1; // the tag of public key is BSL_ASN1_TAG_BITSTRING, 1 denote unusedBits
    pub.key.eccPub.len = pubkey->len - 1;
    ret = CRYPT_EAL_PkeySetPub(pctx, &pub);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pctx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *ealPriKey = pctx;
    return ret;
}

static int32_t ParseEccPrikeyAsn1Buff(uint8_t *buff, uint32_t buffLen, BSL_ASN1_Buffer *pk8AlgoParam,
                                      CRYPT_EAL_PkeyCtx **ealPriKey)
{
    uint8_t *tmpBuff = buff;
    uint32_t tmpBuffLen = buffLen;

    BSL_ASN1_Buffer asn1[CRYPT_ECPRIKEY_PUBKEY_IDX + 1] = {0};
    BSL_ASN1_Template templ = {ecPriKeyTempl, sizeof(ecPriKeyTempl) / sizeof(ecPriKeyTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &tmpBuff, &tmpBuffLen, asn1, CRYPT_ECPRIKEY_PUBKEY_IDX + 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    return ParseEccPrikeyAsn1(asn1, pk8AlgoParam, ealPriKey);
}

/**
 * ref: rfc4055
 * RSASSA-PSS-params  ::=  SEQUENCE  {
 *    hashAlgorithm     [0] HashAlgorithm DEFAULT sha1Identifier,
 *    maskGenAlgorithm  [1] MaskGenAlgorithm DEFAULT mgf1SHA1Identifier,
 *    saltLength        [2] INTEGER DEFAULT 20,
 *    trailerField      [3] INTEGER DEFAULT 1
 * }
 * HashAlgorithm  ::=  AlgorithmIdentifier
 * MaskGenAlgorithm  ::=  AlgorithmIdentifier
 */
static BSL_ASN1_TemplateItem g_rsaPssTempl[] = {
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | CRYPT_ASN1_CTX_SPECIFIC_TAG_RSAPSS_HASH,
    BSL_ASN1_FLAG_DEFAULT, 0},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1},
            {BSL_ASN1_TAG_OBJECT_ID, 0, 2},
            {BSL_ASN1_TAG_ANY, BSL_ASN1_FLAG_OPTIONAL, 2},
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | CRYPT_ASN1_CTX_SPECIFIC_TAG_RSAPSS_MASKGEN,
    BSL_ASN1_FLAG_DEFAULT, 0},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1},
            {BSL_ASN1_TAG_OBJECT_ID, 0, 2},
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 2},
                {BSL_ASN1_TAG_OBJECT_ID, 0, 3},
                {BSL_ASN1_TAG_ANY, BSL_ASN1_FLAG_OPTIONAL, 3},
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | CRYPT_ASN1_CTX_SPECIFIC_TAG_RSAPSS_SALTLEN,
    BSL_ASN1_FLAG_DEFAULT, 0},
        {BSL_ASN1_TAG_INTEGER, 0, 1},
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | CRYPT_ASN1_CTX_SPECIFIC_TAG_RSAPSS_TRAILED,
    BSL_ASN1_FLAG_DEFAULT, 0},
        {BSL_ASN1_TAG_INTEGER, 0, 1}
};

typedef enum {
    CRYPT_RSAPSS_HASH_IDX,
    CRYPT_RSAPSS_HASHANY_IDX,
    CRYPT_RSAPSS_MGF1_IDX,
    CRYPT_RSAPSS_MGF1PARAM_IDX,
    CRYPT_RSAPSS_MGF1PARAMANY_IDX,
    CRYPT_RSAPSS_SALTLEN_IDX,
    CRYPT_RSAPSS_TRAILED_IDX,
    CRYPT_RSAPSS_MAX
} CRYPT_RSAPSS_IDX;

static int32_t RsaPssTagGetOrCheck(int32_t type, int32_t idx, void *data, void *expVal)
{
    (void) idx;
    (void) data;
    if (type == BSL_ASN1_TYPE_GET_ANY_TAG) {
        *(uint8_t *) expVal = BSL_ASN1_TAG_NULL; // is null
        return CRYPT_SUCCESS;
    }
    BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ERR_RSSPSS_GET_ANY_TAG);
    return CRYPT_DECODE_ERR_RSSPSS_GET_ANY_TAG;
}

int32_t CRYPT_EAL_ParseRsaPssAlgParam(BSL_ASN1_Buffer *param, CRYPT_RSA_PssPara *para)
{
    para->mdId = (CRYPT_MD_AlgId)BSL_CID_SHA1;  // hashAlgorithm     [0] HashAlgorithm DEFAULT sha1Identifier,
    para->mgfId = (CRYPT_MD_AlgId)BSL_CID_SHA1; // maskGenAlgorithm  [1] MaskGenAlgorithm DEFAULT mgf1SHA1Identifier,
    para->saltLen = 20;                         // saltLength        [2] INTEGER DEFAULT 20

    uint8_t *temp = param->buff;
    uint32_t tempLen = param->len;
    BSL_ASN1_Buffer asns[CRYPT_RSAPSS_MAX] = {0};
    BSL_ASN1_Template templ = {g_rsaPssTempl, sizeof(g_rsaPssTempl) / sizeof(g_rsaPssTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, RsaPssTagGetOrCheck, &temp, &tempLen, asns, CRYPT_RSAPSS_MAX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ERR_RSSPSS);
        return CRYPT_DECODE_ERR_RSSPSS;
    }

    if (asns[CRYPT_RSAPSS_HASH_IDX].tag != 0) {
        BslOidString hashOid = {asns[CRYPT_RSAPSS_HASH_IDX].len, (char *)asns[CRYPT_RSAPSS_HASH_IDX].buff, 0};
        para->mdId = (CRYPT_MD_AlgId)BSL_OBJ_GetCIDFromOid(&hashOid);
        if (para->mdId == (CRYPT_MD_AlgId)BSL_CID_UNKNOWN) {
            BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ERR_RSSPSS_MD);
            return CRYPT_DECODE_ERR_RSSPSS_MD;
        }
    }
    if (asns[CRYPT_RSAPSS_MGF1PARAM_IDX].tag != 0) {
        BslOidString mgf1 = {asns[CRYPT_RSAPSS_MGF1PARAM_IDX].len, (char *)asns[CRYPT_RSAPSS_MGF1PARAM_IDX].buff, 0};
        para->mgfId = (CRYPT_MD_AlgId)BSL_OBJ_GetCIDFromOid(&mgf1);
        if (para->mgfId == (CRYPT_MD_AlgId)BSL_CID_UNKNOWN) {
            BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ERR_RSSPSS_MGF1MD);
            return CRYPT_DECODE_ERR_RSSPSS_MGF1MD;
        }
    }

    if (asns[CRYPT_RSAPSS_SALTLEN_IDX].tag != 0) {
        ret = BSL_ASN1_DecodePrimitiveItem(&asns[CRYPT_RSAPSS_SALTLEN_IDX], &para->saltLen);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    if (asns[CRYPT_RSAPSS_TRAILED_IDX].tag != 0) {
        // trailerField
        ret = BSL_ASN1_DecodePrimitiveItem(&asns[CRYPT_RSAPSS_TRAILED_IDX], &tempLen);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        if (tempLen != 1) {
            BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ERR_RSSPSS_TRAILER);
            return CRYPT_DECODE_ERR_RSSPSS_TRAILER;
        }
    }
    return ret;
}

static int32_t ProcRsaPubKey(const BSL_ASN1_Buffer *asn1, CRYPT_EAL_PkeyCtx *ealPkey)
{
    CRYPT_EAL_PkeyPub rsaPub;
    rsaPub.id = CRYPT_PKEY_RSA;
    rsaPub.key.rsaPub.e = asn1[CRYPT_RSA_PRV_E_IDX].buff;
    rsaPub.key.rsaPub.eLen = asn1[CRYPT_RSA_PRV_E_IDX].len;
    rsaPub.key.rsaPub.n = asn1[CRYPT_RSA_PRV_N_IDX].buff;
    rsaPub.key.rsaPub.nLen = asn1[CRYPT_RSA_PRV_N_IDX].len;
    return CRYPT_EAL_PkeySetPub(ealPkey, &rsaPub);
}

static int32_t ProcRsaPrivKey(const BSL_ASN1_Buffer *asn1, CRYPT_EAL_PkeyCtx *ealPkey)
{
    CRYPT_EAL_PkeyPrv rsaPrv;
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

static int32_t ProcRsaKeyPair(uint8_t *buff, uint32_t buffLen, CRYPT_EAL_PkeyCtx *ealPkey)
{
    uint8_t *tmpBuff = buff;
    uint32_t tmpBuffLen = buffLen;
    // decode n and e
    BSL_ASN1_Buffer asn1[CRYPT_RSA_PRV_OTHER_PRIME_IDX + 1] = {0};
    BSL_ASN1_Template templ = {rsaPrvTempl, sizeof(rsaPrvTempl) / sizeof(rsaPrvTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &tmpBuff, &tmpBuffLen, asn1, CRYPT_RSA_PRV_OTHER_PRIME_IDX + 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = ProcRsaPrivKey(asn1, ealPkey);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    return ProcRsaPubKey(asn1, ealPkey);
}

static int32_t ParseRsaPrikeyAsn1Buff(uint8_t *buff, uint32_t buffLen, BSL_ASN1_Buffer *rsaPssParam, BslCid cid,
    CRYPT_EAL_PkeyCtx **ealPriKey)
{
    CRYPT_EAL_PkeyCtx *pctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    if (pctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    int32_t ret = ProcRsaKeyPair(buff, buffLen, pctx);
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

static int32_t ParsePk8PrikeyAsn1(BSL_ASN1_Buffer *encode, CRYPT_EAL_PkeyCtx **ealPriKey)
{
    BSL_ASN1_Buffer *algo = &encode[CRYPT_PK8_PRIKEY_ALGID_IDX]; // AlgorithmIdentifier
    BSL_ASN1_Buffer *octPriKey = &encode[CRYPT_PK8_PRIKEY_PRIKEY_IDX]; // PrivateKey octet string
    BSL_ASN1_Buffer algoId[BSL_ASN1_TAG_ALGOID_ANY_IDX + 1] = {0};
    int32_t ret = ParseAlgoIdAsn1Buff(algo->buff, algo->len, algoId, BSL_ASN1_TAG_ALGOID_ANY_IDX + 1);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    BslOidString oidStr = {algoId[0].len, (char *)algoId[0].buff, 0};
    BslCid cid = BSL_OBJ_GetCIDFromOid(&oidStr);
    if (cid == BSL_CID_RSA || cid == BSL_CID_RSASSAPSS) {
        return ParseRsaPrikeyAsn1Buff(octPriKey->buff, octPriKey->len, algoId + 1, cid, ealPriKey);
    } else if (cid == BSL_CID_EC_PUBLICKEY) {
        return ParseEccPrikeyAsn1Buff(octPriKey->buff, octPriKey->len, algoId + 1, ealPriKey);
    }
    return CRYPT_DECODE_UNSUPPORTED_PKCS8_TYPE;
}

static int32_t ParsePk8PriKeyBuff(BSL_Buffer *buff, CRYPT_EAL_PkeyCtx **ealPriKey)
{
    uint8_t *tmpBuff = buff->data;
    uint32_t tmpBuffLen = buff->dataLen;

    BSL_ASN1_Buffer asn1[CRYPT_PK8_PRIKEY_PRIKEY_IDX + 1] = {0};
    BSL_ASN1_Template templ = {pk8PriKeyTempl, sizeof(pk8PriKeyTempl) / sizeof(pk8PriKeyTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &tmpBuff, &tmpBuffLen, asn1, CRYPT_PK8_PRIKEY_PRIKEY_IDX + 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    return ParsePk8PrikeyAsn1(asn1, ealPriKey);
}

static int32_t ParseDeriveKeyPrfAlgId(BSL_ASN1_Buffer *asn, int32_t *prfId)
{
    if (asn->len != 0) {
        BSL_ASN1_Buffer algoId[2] = {0};
        int32_t ret = ParseAlgoIdAsn1Buff(asn->buff, asn->len, algoId, 2);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        BslOidString oidStr = {algoId[BSL_ASN1_TAG_ALGOID_IDX].len,
            (char *)algoId[BSL_ASN1_TAG_ALGOID_IDX].buff, 0};
        *prfId = BSL_OBJ_GetCIDFromOid(&oidStr);
        if (*prfId == BSL_CID_UNKNOWN) {
            BSL_ERR_PUSH_ERROR(CRYPT_DECODE_PKCS8_INVALID_ALGO_PARAM);
            return CRYPT_DECODE_PKCS8_INVALID_ALGO_PARAM;
        }
    } else {
        *prfId = BSL_CID_HMAC_SHA1;
    }
    return CRYPT_SUCCESS;
}

static int32_t ParseDeriveKeyParam(BSL_Buffer *derivekeyData, int *iter, int *keyLen, BSL_Buffer *salt, int *prfId)
{
    uint8_t *tmpBuff = derivekeyData->data;
    uint32_t tmpBuffLen = derivekeyData->dataLen;
    BSL_ASN1_Buffer derParam[CRYPT_PKCS_ENC_DERPARAM_MAX] = {0};
    BSL_ASN1_Template templ = {g_pbkdf2DerParamTempl, sizeof(g_pbkdf2DerParamTempl) / sizeof(g_pbkdf2DerParamTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL,
        &tmpBuff, &tmpBuffLen, derParam, CRYPT_PKCS_ENC_DERPARAM_MAX);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BslOidString oidStr = {derParam[CRYPT_PKCS_ENC_DERALG_IDX].len,
        (char *)derParam[CRYPT_PKCS_ENC_DERALG_IDX].buff, 0};
    BslCid cid = BSL_OBJ_GetCIDFromOid(&oidStr);
    if (cid != BSL_CID_PBKDF2) { // only pbkdf2 is supported
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_PKCS8_INVALID_ALGO_PARAM);
        return CRYPT_DECODE_PKCS8_INVALID_ALGO_PARAM;
    }
    ret = BSL_ASN1_DecodePrimitiveItem(&derParam[CRYPT_PKCS_ENC_DERITER_IDX], iter);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_PKCS8_INVALID_ITER);
        return CRYPT_DECODE_PKCS8_INVALID_ITER;
    }
    if (derParam[CRYPT_PKCS_ENC_DERKEYLEN_IDX].len != 0) {
        ret = BSL_ASN1_DecodePrimitiveItem(&derParam[CRYPT_PKCS_ENC_DERKEYLEN_IDX], keyLen);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(CRYPT_DECODE_PKCS8_INVALID_KEYLEN);
            return CRYPT_DECODE_PKCS8_INVALID_KEYLEN;
        }
    }
    salt->data = derParam[CRYPT_PKCS_ENC_DERSALT_IDX].buff;
    salt->dataLen = derParam[CRYPT_PKCS_ENC_DERSALT_IDX].len;
    return ParseDeriveKeyPrfAlgId(&derParam[CRYPT_PKCS_ENC_DERPRF_IDX], prfId);
}

static int32_t DecryptEncData(BSL_Buffer *ivData, BSL_Buffer *enData, int32_t alg, bool isEnc, BSL_Buffer *key,
    uint8_t *output, uint32_t *dataLen)
{
    uint32_t buffLen = *dataLen;
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(alg);
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    int32_t ret = CRYPT_EAL_CipherInit(ctx, key->data, key->dataLen, ivData->data, ivData->dataLen, isEnc);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    uint32_t blockSize;
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_BLOCKSIZE, &blockSize, sizeof(blockSize));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    if (blockSize != 1) {
        ret = CRYPT_EAL_CipherSetPadding(ctx, CRYPT_PADDING_PKCS7);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto ERR;
        }
    }
    ret = CRYPT_EAL_CipherUpdate(ctx, enData->data, enData->dataLen, output, dataLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    buffLen -= *dataLen;
    ret = CRYPT_EAL_CipherFinal(ctx, output + *dataLen, &buffLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    *dataLen += buffLen;
ERR:
    CRYPT_EAL_CipherFreeCtx(ctx);
    return ret;
}

typedef struct {
    BSL_Buffer *derivekeyData;
    BSL_Buffer *ivData;
    BSL_Buffer *enData;
} EncryptPara;

static int32_t PbkdfDeriveKey(int32_t iter, int32_t prfId, BSL_Buffer *salt, const uint8_t *pwd, uint32_t pwdlen, BSL_Buffer *key)
{
    int32_t ret;
    CRYPT_EAL_KdfCTX *kdfCtx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_PBKDF2);
    if (kdfCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_PBKDF2_NOT_SUPPORTED);
        return CRYPT_PBKDF2_NOT_SUPPORTED;
    }

    BSL_Param params[5] = {{0}, {0}, {0}, {0}, BSL_PARAM_END};
    (void)BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, &prfId, sizeof(prfId));
    (void)BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_PASSWORD, BSL_PARAM_TYPE_OCTETS, (uint8_t *)pwd, pwdlen);
    (void)BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS, salt->data, salt->dataLen);
    (void)BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_ITER, BSL_PARAM_TYPE_UINT32, &iter, sizeof(iter));
    ret = CRYPT_EAL_KdfSetParam(kdfCtx, params);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = CRYPT_EAL_KdfDerive(kdfCtx, key->data, key->dataLen);
EXIT:
    CRYPT_EAL_KdfFreeCtx(kdfCtx);
    return ret;
}

static int32_t ParseEncDataAsn1(BslCid symAlg, EncryptPara *encPara, const uint8_t *pwd, uint32_t pwdlen,
    BSL_Buffer *decode)
{
    int32_t iter, prfId;
    int32_t keylen = 0;
    uint8_t key[512] = {0}; // The maximum length of the symmetry algorithm
    BSL_Buffer salt = {0};
    int32_t ret = ParseDeriveKeyParam(encPara->derivekeyData, &iter, &keylen, &salt, &prfId);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint32_t symKeyLen;
    ret = CRYPT_EAL_CipherGetInfo((CRYPT_CIPHER_AlgId)symAlg, CRYPT_INFO_KEY_LEN, &symKeyLen);
    if (keylen != 0 && symKeyLen != (uint32_t)keylen) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_PKCS8_INVALID_KEYLEN);
        return CRYPT_DECODE_PKCS8_INVALID_KEYLEN;
    }
    BSL_Buffer keyBuff = {key, symKeyLen};

    ret = PbkdfDeriveKey(iter, prfId, &salt, pwd, pwdlen, &keyBuff);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (encPara->enData->dataLen != 0) {
        uint8_t *output = BSL_SAL_Malloc(encPara->enData->dataLen);
        if (output == NULL) {
            (void)memset_s(key, sizeof(key), 0, sizeof(key));
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }
        uint32_t dataLen = encPara->enData->dataLen;
        ret = DecryptEncData(encPara->ivData, encPara->enData, symAlg, false, &keyBuff, output, &dataLen);
        if (ret != CRYPT_SUCCESS) {
            (void)memset_s(key, sizeof(key), 0, sizeof(key));
            BSL_SAL_Free(output);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        decode->data = output;
        decode->dataLen = dataLen;
    }
    (void)memset_s(key, sizeof(key), 0, sizeof(key));
    return CRYPT_SUCCESS;
}

static int32_t ParsePk8EncPriKeyBuff(BSL_Buffer *buff, const uint8_t *pwd, uint32_t pwdlen,
    CRYPT_EAL_PkeyCtx **ealPriKey)
{
    if (pwdlen > PWD_MAX_LEN || (pwd == NULL && pwdlen != 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    uint8_t *tmpBuff = buff->data;
    uint32_t tmpBuffLen = buff->dataLen;

    BSL_ASN1_Buffer asn1[CRYPT_PKCS_ENCPRIKEY_MAX] = {0};
    BSL_ASN1_Template templ = {pk8EncPriKeyTempl, sizeof(pk8EncPriKeyTempl) / sizeof(pk8EncPriKeyTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &tmpBuff, &tmpBuffLen, asn1, CRYPT_PKCS_ENCPRIKEY_MAX);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    BslOidString encOidStr = {asn1[CRYPT_PKCS_ENCPRIKEY_ENCALG_IDX].len,
        (char *)asn1[CRYPT_PKCS_ENCPRIKEY_ENCALG_IDX].buff, 0};
    BslCid cid = BSL_OBJ_GetCIDFromOid(&encOidStr);
    if (cid != BSL_CID_PBES2) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_UNKNOWN_OID);
        return CRYPT_DECODE_UNKNOWN_OID;
    }
    // parse sym alg id
    BslOidString symOidStr = {asn1[CRYPT_PKCS_ENCPRIKEY_SYMALG_IDX].len,
        (char *)asn1[CRYPT_PKCS_ENCPRIKEY_SYMALG_IDX].buff, 0};
    BslCid symId = BSL_OBJ_GetCIDFromOid(&symOidStr);
    if (symId == BSL_CID_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_UNKNOWN_OID);
        return CRYPT_DECODE_UNKNOWN_OID;
    }

    BSL_Buffer decode = {0};
    BSL_Buffer derivekeyData = {asn1[CRYPT_PKCS_ENCPRIKEY_DERPARAM_IDX].buff,
        asn1[CRYPT_PKCS_ENCPRIKEY_DERPARAM_IDX].len};
    BSL_Buffer ivData = {asn1[CRYPT_PKCS_ENCPRIKEY_SYMIV_IDX].buff, asn1[CRYPT_PKCS_ENCPRIKEY_SYMIV_IDX].len};
    BSL_Buffer enData = {asn1[CRYPT_PKCS_ENCPRIKEY_ENCDATA_IDX].buff, asn1[CRYPT_PKCS_ENCPRIKEY_ENCDATA_IDX].len};
    EncryptPara encPara = {
        .derivekeyData = &derivekeyData,
        .ivData = &ivData,
        .enData = &enData,
    };
    ret = ParseEncDataAsn1(symId, &encPara, pwd, pwdlen, &decode);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = ParsePk8PriKeyBuff(&decode, ealPriKey);
    BSL_SAL_Free(decode.data);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t CRYPT_EAL_ParseAsn1PubKey(int32_t type, BSL_Buffer *encode, CRYPT_EAL_PkeyCtx **ealPubKey)
{
    switch (type) {
        case CRYPT_PUBKEY_SUBKEY:
            return CRYPT_EAL_ParseAsn1SubPubkey(encode->data, encode->dataLen, (void **)ealPubKey, true);
        default:
            return ParseRsaPubkeyAsn1Buff(encode->data, encode->dataLen, NULL, ealPubKey, BSL_CID_UNKNOWN);
    }
}

static int32_t EAL_GetPemPubKeySymbol(int32_t type, BSL_PEM_Symbol *symbol)
{
    switch (type) {
        case CRYPT_PUBKEY_SUBKEY:
            symbol->head = BSL_PEM_PUB_KEY_BEGIN_STR;
            symbol->tail = BSL_PEM_PUB_KEY_END_STR;
            return CRYPT_SUCCESS;
        case CRYPT_PUBKEY_RSA:
            symbol->head = BSL_PEM_RSA_PUB_KEY_BEGIN_STR;
            symbol->tail = BSL_PEM_RSA_PUB_KEY_END_STR;
            return CRYPT_SUCCESS;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_DECODE_NO_SUPPORT_TYPE);
            return CRYPT_DECODE_NO_SUPPORT_TYPE;
    }
}

int32_t CRYPT_EAL_ParsePemPubKey(int32_t type, BSL_Buffer *encode, CRYPT_EAL_PkeyCtx **ealPubKey)
{
    BSL_PEM_Symbol symbol = {0};
    int32_t ret = EAL_GetPemPubKeySymbol(type, &symbol);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    BSL_Buffer asn1 = {0};
    ret = BSL_PEM_ParsePem2Asn1((char **)&(encode->data), &(encode->dataLen), &symbol, &(asn1.data), &(asn1.dataLen));
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CRYPT_EAL_ParseAsn1PubKey(type, &asn1, ealPubKey);
    BSL_SAL_Free(asn1.data);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_ParseUnknownPubKey(int32_t type, BSL_Buffer *encode, CRYPT_EAL_PkeyCtx **ealPubKey)
{
    bool isPem = BSL_PEM_IsPemFormat((char *)(encode->data), encode->dataLen);
    if (isPem) {
        return CRYPT_EAL_ParsePemPubKey(type, encode, ealPubKey);
    } else {
        return CRYPT_EAL_ParseAsn1PubKey(type, encode, ealPubKey);
    }
}

int32_t CRYPT_EAL_PubKeyParseBuff(BSL_ParseFormat format, int32_t type, BSL_Buffer *encode,
    CRYPT_EAL_PkeyCtx **ealPubKey)
{
    if (encode == NULL || encode->data == NULL || encode->dataLen == 0 || ealPubKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    switch (format) {
        case BSL_FORMAT_ASN1:
            return CRYPT_EAL_ParseAsn1PubKey(type, encode, ealPubKey);
        case BSL_FORMAT_PEM:
            return CRYPT_EAL_ParsePemPubKey(type, encode, ealPubKey);
        case BSL_FORMAT_UNKNOWN:
            return CRYPT_EAL_ParseUnknownPubKey(type, encode, ealPubKey);
        default:
            return CRYPT_DECODE_NO_SUPPORT_FORMAT;
    }
}

int32_t CRYPT_EAL_PubKeyParseFile(BSL_ParseFormat format, int32_t type, const char *path, CRYPT_EAL_PkeyCtx **ealPubKey)
{
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    int32_t ret = BSL_SAL_ReadFile(path, &data, &dataLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_Buffer encode = {data, dataLen};
    ret = CRYPT_EAL_PubKeyParseBuff(format, type, &encode, ealPubKey);
    BSL_SAL_Free(data);
    return ret;
}

int32_t CRYPT_EAL_ParseAsn1PriKey(int32_t type, BSL_Buffer *encode, const uint8_t *pwd, uint32_t pwdlen,
    CRYPT_EAL_PkeyCtx **ealPriKey)
{
    switch (type) {
        case CRYPT_PRIKEY_ECC:
            return ParseEccPrikeyAsn1Buff(encode->data, encode->dataLen, NULL, ealPriKey);
        case CRYPT_PRIKEY_RSA:
            return ParseRsaPrikeyAsn1Buff(encode->data, encode->dataLen, NULL, BSL_CID_UNKNOWN, ealPriKey);
        case CRYPT_PRIKEY_PKCS8_UNENCRYPT:
            return ParsePk8PriKeyBuff(encode, ealPriKey);
        case CRYPT_PRIKEY_PKCS8_ENCRYPT:
            return ParsePk8EncPriKeyBuff(encode, pwd, pwdlen, ealPriKey);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_DECODE_NO_SUPPORT_TYPE);
            return CRYPT_DECODE_NO_SUPPORT_TYPE;
    }
}

static int32_t EAL_GetPemPriKeySymbol(int32_t type, BSL_PEM_Symbol *symbol)
{
    switch (type) {
        case CRYPT_PRIKEY_ECC:
            symbol->head = BSL_PEM_EC_PRI_KEY_BEGIN_STR;
            symbol->tail = BSL_PEM_EC_PRI_KEY_END_STR;
            return CRYPT_SUCCESS;
        case CRYPT_PRIKEY_RSA:
            symbol->head = BSL_PEM_RSA_PRI_KEY_BEGIN_STR;
            symbol->tail = BSL_PEM_RSA_PRI_KEY_END_STR;
            return CRYPT_SUCCESS;
        case CRYPT_PRIKEY_PKCS8_UNENCRYPT:
            symbol->head = BSL_PEM_PRI_KEY_BEGIN_STR;
            symbol->tail = BSL_PEM_PRI_KEY_END_STR;
            return CRYPT_SUCCESS;
        case CRYPT_PRIKEY_PKCS8_ENCRYPT:
            symbol->head = BSL_PEM_P8_PRI_KEY_BEGIN_STR;
            symbol->tail = BSL_PEM_P8_PRI_KEY_END_STR;
            return CRYPT_SUCCESS;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_DECODE_NO_SUPPORT_TYPE);
            return CRYPT_DECODE_NO_SUPPORT_TYPE;
    }
}

int32_t CRYPT_EAL_ParsePemPriKey(int32_t type, BSL_Buffer *encode, const uint8_t *pwd, uint32_t pwdlen,
    CRYPT_EAL_PkeyCtx **ealPriKey)
{
    BSL_PEM_Symbol symbol = {0};
    int32_t ret = EAL_GetPemPriKeySymbol(type, &symbol);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    BSL_Buffer asn1 = {0};
    ret = BSL_PEM_ParsePem2Asn1((char **)&(encode->data), &(encode->dataLen), &symbol, &(asn1.data),
        &(asn1.dataLen));
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CRYPT_EAL_ParseAsn1PriKey(type, &asn1, pwd, pwdlen, ealPriKey);
    BSL_SAL_Free(asn1.data);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_ParseUnknownPriKey(int32_t type, BSL_Buffer *encode, const uint8_t *pwd, uint32_t pwdlen,
    CRYPT_EAL_PkeyCtx **ealPriKey)
{
    bool isPem = BSL_PEM_IsPemFormat((char *)(encode->data), encode->dataLen);
    if (isPem) {
        return CRYPT_EAL_ParsePemPriKey(type, encode, pwd, pwdlen, ealPriKey);
    } else {
        return CRYPT_EAL_ParseAsn1PriKey(type, encode, pwd, pwdlen, ealPriKey);
    }
}

int32_t CRYPT_EAL_PriKeyParseBuff(BSL_ParseFormat format, int32_t type, BSL_Buffer *encode,
    const uint8_t *pwd, uint32_t pwdlen, CRYPT_EAL_PkeyCtx **ealPriKey)
{
    if (encode == NULL || encode->data == NULL || encode->dataLen == 0 || ealPriKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    switch (format) {
        case BSL_FORMAT_ASN1:
            return CRYPT_EAL_ParseAsn1PriKey(type, encode, pwd, pwdlen, ealPriKey);
        case BSL_FORMAT_PEM:
            return CRYPT_EAL_ParsePemPriKey(type, encode, pwd, pwdlen, ealPriKey);
        case BSL_FORMAT_UNKNOWN:
            return CRYPT_EAL_ParseUnknownPriKey(type, encode, pwd, pwdlen, ealPriKey);
        default:
            return CRYPT_DECODE_NO_SUPPORT_FORMAT;
    }
}

int32_t CRYPT_EAL_PriKeyParseFile(BSL_ParseFormat format, int32_t type, const char *path, uint8_t *pwd, uint32_t pwdlen,
    CRYPT_EAL_PkeyCtx **ealPriKey)
{
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    int32_t ret = BSL_SAL_ReadFile(path, &data, &dataLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_Buffer encode = {data, dataLen};
    ret = CRYPT_EAL_PriKeyParseBuff(format, type, &encode, pwd, pwdlen, ealPriKey);
    BSL_SAL_Free(data);
    return ret;
}

static int32_t EncodeEccKeyPair(CRYPT_EAL_PkeyCtx *ealPriKey, CRYPT_PKEY_AlgId cid,
    BSL_ASN1_Buffer *asn1, BSL_Buffer *encode)
{
    int32_t ret;
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
    CRYPT_EAL_PkeyPrv prv = {0};
    prv.id = cid;
    prv.key.eccPrv.data = pri;
    prv.key.eccPrv.len = keyLen;
    uint8_t *pub = NULL;
    do {
        ret = CRYPT_EAL_PkeyGetPrv(ealPriKey, &prv);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            break;
        }
        asn1[CRYPT_ECPRIKEY_PRIKEY_IDX].buff = prv.key.eccPrv.data;
        asn1[CRYPT_ECPRIKEY_PRIKEY_IDX].len = prv.key.eccPrv.len;
        asn1[CRYPT_ECPRIKEY_PRIKEY_IDX].tag = BSL_ASN1_TAG_OCTETSTRING;
        pub = (uint8_t *)BSL_SAL_Malloc(keyLen);
        if (pub == NULL) {
            ret = CRYPT_MEM_ALLOC_FAIL;
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            break;
        }
        CRYPT_EAL_PkeyPub pubKey = {0};
        pubKey.id = cid;
        pubKey.key.eccPub.data = pub;
        pubKey.key.eccPub.len = keyLen;
        ret = CRYPT_EAL_PkeyCtrl(ealPriKey, CRYPT_CTRL_GEN_ECC_PUBLICKEY, NULL, 0);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            break;
        }
        ret = CRYPT_EAL_PkeyGetPub(ealPriKey, &pubKey);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            break;
        }
        BSL_ASN1_BitString bitStr = {pubKey.key.eccPub.data, pubKey.key.eccPub.len, 0};
        asn1[CRYPT_ECPRIKEY_PUBKEY_IDX].buff = (uint8_t *)&bitStr;
        asn1[CRYPT_ECPRIKEY_PUBKEY_IDX].len = sizeof(BSL_ASN1_BitString);
        asn1[CRYPT_ECPRIKEY_PUBKEY_IDX].tag = BSL_ASN1_TAG_BITSTRING;
        BSL_ASN1_Template templ = {ecPriKeyTempl, sizeof(ecPriKeyTempl) / sizeof(ecPriKeyTempl[0])};
        ret = BSL_ASN1_EncodeTemplate(&templ, asn1, CRYPT_ECPRIKEY_PUBKEY_IDX + 1, &encode->data, &encode->dataLen);
    } while (0);
    BSL_SAL_ClearFree(pri, keyLen);
    BSL_SAL_FREE(pub);
    return ret;
}

static int32_t EncodeEccPrikeyAsn1Buff(CRYPT_EAL_PkeyCtx *ealPriKey, BSL_ASN1_Buffer *pk8AlgoParam, BSL_Buffer *encode)
{
    BSL_ASN1_Buffer asn1[CRYPT_ECPRIKEY_PUBKEY_IDX + 1] = {0};
    uint8_t version = 1;
    asn1[CRYPT_ECPRIKEY_VERSION_IDX].buff = &version;
    asn1[CRYPT_ECPRIKEY_VERSION_IDX].len = sizeof(version);
    asn1[CRYPT_ECPRIKEY_VERSION_IDX].tag = BSL_ASN1_TAG_INTEGER;
    BslOidString *oid = NULL;
    CRYPT_PKEY_AlgId cid = CRYPT_EAL_PkeyGetId(ealPriKey);
    if (cid == CRYPT_PKEY_SM2) {
        oid = BSL_OBJ_GetOidFromCID((BslCid)CRYPT_ECC_SM2);
    } else {
        CRYPT_PKEY_ParaId paraId = CRYPT_EAL_PkeyGetParaId(ealPriKey);
        oid = BSL_OBJ_GetOidFromCID((BslCid)paraId);
    }
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

static void DeinitRsaPrvCtx(CRYPT_EAL_PkeyPrv *rsaPrv)
{
    BSL_SAL_ClearFree(rsaPrv->key.rsaPrv.d, rsaPrv->key.rsaPrv.dLen * 8); // 8 items
}

static int32_t InitRsaPrvCtx(const CRYPT_EAL_PkeyCtx *ealPriKey, CRYPT_PKEY_AlgId cid, CRYPT_EAL_PkeyPrv *rsaPrv)
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

static int32_t EncodeRsaPrikeyAsn1Buff(CRYPT_EAL_PkeyCtx *ealPriKey, CRYPT_PKEY_AlgId cid, BSL_Buffer *encode)
{
    int32_t ret;
    BSL_ASN1_Buffer asn1[CRYPT_RSA_PRV_OTHER_PRIME_IDX + 1] = {0};

    CRYPT_EAL_PkeyPrv rsaPrv = {0};
    ret = InitRsaPrvCtx(ealPriKey, cid, &rsaPrv);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CRYPT_EAL_PkeyGetPrv(ealPriKey, &rsaPrv);
    if (ret != CRYPT_SUCCESS) {
        DeinitRsaPrvCtx(&rsaPrv);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    SetRsaPrv2Arr(&rsaPrv, asn1);
    uint8_t version = 0;
    asn1[CRYPT_RSA_PRV_VERSION_IDX].buff = (uint8_t *)&version;
    asn1[CRYPT_RSA_PRV_VERSION_IDX].len = sizeof(version);
    asn1[CRYPT_RSA_PRV_VERSION_IDX].tag = BSL_ASN1_TAG_INTEGER;
    BSL_ASN1_Template templ = {rsaPrvTempl, sizeof(rsaPrvTempl) / sizeof(rsaPrvTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asn1, CRYPT_RSA_PRV_OTHER_PRIME_IDX + 1, &encode->data, &encode->dataLen);
    DeinitRsaPrvCtx(&rsaPrv);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t GetPssParamInfo(CRYPT_EAL_PkeyCtx *ealPriKey, CRYPT_RSA_PssPara *rsaPssParam)
{
    int32_t ret;
    ret = CRYPT_EAL_PkeyCtrl(ealPriKey, CRYPT_CTRL_GET_RSA_SALT, &rsaPssParam->saltLen, sizeof(rsaPssParam->saltLen));
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CRYPT_EAL_PkeyCtrl(ealPriKey, CRYPT_CTRL_GET_RSA_MD, &rsaPssParam->mdId, sizeof(rsaPssParam->mdId));
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CRYPT_EAL_PkeyCtrl(ealPriKey, CRYPT_CTRL_GET_RSA_MGF, &rsaPssParam->mgfId, sizeof(rsaPssParam->mgfId));
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t EncodeRsaPrvKey(CRYPT_EAL_PkeyCtx *ealPriKey, BSL_ASN1_Buffer *algoId, BSL_Buffer *bitStr,
    CRYPT_PKEY_AlgId *cid)
{
    CRYPT_RsaPadType pad = CRYPT_PKEY_RSA_PADDINGMAX;
    int32_t ret = CRYPT_EAL_PkeyCtrl(ealPriKey, CRYPT_CTRL_GET_RSA_PADDING, &pad, sizeof(pad));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    CRYPT_RSA_PssPara rsaPssParam = {0};
    BSL_Buffer tmp = {0};
    switch (pad) {
        case CRYPT_PKEY_EMSA_PSS:
            ret = GetPssParamInfo(ealPriKey, &rsaPssParam);
            if (ret != BSL_SUCCESS) {
                return ret;
            }
            ret = EncodeRsaPrikeyAsn1Buff(ealPriKey, CRYPT_PKEY_RSA, &tmp);
            if (ret != BSL_SUCCESS) {
                return ret;
            }
            ret = CRYPT_EAL_EncodeRsaPssAlgParam(&rsaPssParam, &algoId[BSL_ASN1_TAG_ALGOID_ANY_IDX].buff,
                &algoId[BSL_ASN1_TAG_ALGOID_ANY_IDX].len);
            if (ret != BSL_SUCCESS) {
                BSL_SAL_ClearFree(tmp.data, tmp.dataLen);
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            algoId[BSL_ASN1_TAG_ALGOID_ANY_IDX].tag = BSL_ASN1_TAG_SEQUENCE | BSL_ASN1_TAG_CONSTRUCTED;
            *cid = (CRYPT_PKEY_AlgId)BSL_CID_RSASSAPSS;
            break;
        default:
            ret = EncodeRsaPrikeyAsn1Buff(ealPriKey, CRYPT_PKEY_RSA, &tmp);
            if (ret != BSL_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            algoId[BSL_ASN1_TAG_ALGOID_ANY_IDX].tag = BSL_ASN1_TAG_NULL;
            break;
    }
    bitStr->data = tmp.data;
    bitStr->dataLen = tmp.dataLen;
    return CRYPT_SUCCESS;
}

static int32_t EncodePk8AlgidAny(CRYPT_EAL_PkeyCtx *ealPriKey, BSL_Buffer *bitStr,
    BSL_ASN1_Buffer *algoId, CRYPT_PKEY_AlgId *cidOut)
{
    int32_t ret;
    BSL_Buffer tmp = {0};
    CRYPT_PKEY_AlgId cid = CRYPT_EAL_PkeyGetId(ealPriKey);
    if (cid == CRYPT_PKEY_RSA) {
        ret = EncodeRsaPrvKey(ealPriKey, algoId, &tmp, &cid);
    } else if (cid == CRYPT_PKEY_ECDSA || cid == CRYPT_PKEY_SM2) {
        cid = (CRYPT_PKEY_AlgId)BSL_CID_EC_PUBLICKEY;
        ret = EncodeEccPrikeyAsn1Buff(ealPriKey, &algoId[BSL_ASN1_TAG_ALGOID_ANY_IDX], &tmp);
    } else {
        ret = CRYPT_ERR_ALGID;
    }
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    bitStr->data = tmp.data;
    bitStr->dataLen = tmp.dataLen;
    *cidOut = cid;
    return ret;
}

static int32_t EncodePk8PriKeyBuff(CRYPT_EAL_PkeyCtx *ealPriKey, BSL_Buffer *asn1)
{
    int32_t ret;
    CRYPT_PKEY_AlgId cid;
    BSL_Buffer bitStr = {0};
    BSL_ASN1_Buffer algo = {0};
    BSL_ASN1_Buffer algoId[BSL_ASN1_TAG_ALGOID_ANY_IDX + 1] = {0};
    do {
        ret = EncodePk8AlgidAny(ealPriKey, &bitStr, algoId, &cid);
        if (ret != CRYPT_SUCCESS) {
            break;
        }
        BslOidString *oidStr = BSL_OBJ_GetOidFromCID((BslCid)cid);
        if (oidStr == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_ERR_ALGID);
            ret = CRYPT_ERR_ALGID;
            break;
        }
        algoId[BSL_ASN1_TAG_ALGOID_IDX].buff = (uint8_t *)oidStr->octs;
        algoId[BSL_ASN1_TAG_ALGOID_IDX].len = oidStr->octetLen;
        algoId[BSL_ASN1_TAG_ALGOID_IDX].tag = BSL_ASN1_TAG_OBJECT_ID;
        ret = EncodeAlgoIdAsn1Buff(algoId, BSL_ASN1_TAG_ALGOID_ANY_IDX + 1, &algo.buff, &algo.len);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            break;
        }

        uint8_t version = 0;
        BSL_ASN1_Buffer encode[CRYPT_PK8_PRIKEY_PRIKEY_IDX + 1] = {
            {BSL_ASN1_TAG_INTEGER, sizeof(version), &version},
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, algo.len, algo.buff},
            {BSL_ASN1_TAG_OCTETSTRING, bitStr.dataLen, bitStr.data}
        };

        BSL_ASN1_Template pubTempl = {pk8PriKeyTempl, sizeof(pk8PriKeyTempl) / sizeof(pk8PriKeyTempl[0])};
        ret =  BSL_ASN1_EncodeTemplate(&pubTempl,
            encode, CRYPT_PK8_PRIKEY_PRIKEY_IDX + 1, &asn1->data, &asn1->dataLen);
    } while (0);
    // rsa-pss mode release buffer
    if (algoId[BSL_ASN1_TAG_ALGOID_ANY_IDX].tag == (BSL_ASN1_TAG_SEQUENCE | BSL_ASN1_TAG_CONSTRUCTED)) {
        BSL_SAL_FREE(algoId[BSL_ASN1_TAG_ALGOID_ANY_IDX].buff);
    }
    BSL_SAL_ClearFree(bitStr.data, bitStr.dataLen);
    BSL_SAL_FREE(algo.buff);
    return ret;
}

static int32_t EncodeDeriveKeyParam(CRYPT_Pbkdf2Param *param, BSL_Buffer *encode, BSL_Buffer *salt)
{
    BSL_ASN1_Buffer derParam[CRYPT_PKCS_ENC_DERPRF_IDX + 1] = {0};
    /* deralg */
    BslOidString *oidPbkdf = BSL_OBJ_GetOidFromCID((BslCid)param->pbkdfId);
    if (oidPbkdf == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ERR_ALGID);
        return CRYPT_ERR_ALGID;
    }
    derParam[CRYPT_PKCS_ENC_DERALG_IDX].buff = (uint8_t *)oidPbkdf->octs;
    derParam[CRYPT_PKCS_ENC_DERALG_IDX].len = oidPbkdf->octetLen;
    derParam[CRYPT_PKCS_ENC_DERALG_IDX].tag = BSL_ASN1_TAG_OBJECT_ID;
    /* salt */
    int32_t ret = CRYPT_EAL_Randbytes(salt->data, salt->dataLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    derParam[CRYPT_PKCS_ENC_DERSALT_IDX].buff = salt->data;
    derParam[CRYPT_PKCS_ENC_DERSALT_IDX].len = salt->dataLen;
    derParam[CRYPT_PKCS_ENC_DERSALT_IDX].tag = BSL_ASN1_TAG_OCTETSTRING;
    /* iter */
    ret = BSL_ASN1_EncodeLimb(BSL_ASN1_TAG_INTEGER, param->itCnt, &derParam[CRYPT_PKCS_ENC_DERITER_IDX]);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_ASN1_Template templ = {g_pbkdf2DerParamTempl, sizeof(g_pbkdf2DerParamTempl) / sizeof(g_pbkdf2DerParamTempl[0])};
    if (param->hmacId == CRYPT_MAC_HMAC_SHA1) {
        ret = BSL_ASN1_EncodeTemplate(&templ, derParam, CRYPT_PKCS_ENC_DERPRF_IDX + 1, &encode->data, &encode->dataLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
        }
        BSL_SAL_FREE(derParam[CRYPT_PKCS_ENC_DERITER_IDX].buff);
        return ret;
    }
    BslOidString *oidHmac = BSL_OBJ_GetOidFromCID((BslCid)param->hmacId);
    if (oidHmac == NULL) {
        BSL_SAL_FREE(derParam[CRYPT_PKCS_ENC_DERITER_IDX].buff);
        BSL_ERR_PUSH_ERROR(CRYPT_ERR_ALGID);
        return CRYPT_ERR_ALGID;
    }
    BSL_Buffer algo = {0};
    BSL_ASN1_Buffer algoId[BSL_ASN1_TAG_ALGOID_ANY_IDX + 1] = {
        {BSL_ASN1_TAG_OBJECT_ID, oidHmac->octetLen, (uint8_t *)oidHmac->octs},
        {BSL_ASN1_TAG_NULL, 0, NULL},
    };
    ret = EncodeAlgoIdAsn1Buff(algoId, BSL_ASN1_TAG_ALGOID_ANY_IDX + 1, &algo.data, &algo.dataLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_FREE(derParam[CRYPT_PKCS_ENC_DERITER_IDX].buff);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    derParam[CRYPT_PKCS_ENC_DERPRF_IDX].buff = algo.data;
    derParam[CRYPT_PKCS_ENC_DERPRF_IDX].len = algo.dataLen;
    derParam[CRYPT_PKCS_ENC_DERPRF_IDX].tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;

    ret = BSL_ASN1_EncodeTemplate(&templ,
        derParam, CRYPT_PKCS_ENC_DERPRF_IDX + 1, &encode->data, &encode->dataLen);
    BSL_SAL_FREE(algo.data);
    BSL_SAL_FREE(derParam[CRYPT_PKCS_ENC_DERITER_IDX].buff);
    return ret;
}

static int32_t EncodeEncryptedData(CRYPT_Pbkdf2Param *pkcsParam,
    BSL_Buffer *unEncrypted, BSL_Buffer *salt, BSL_ASN1_Buffer *asn1)
{
    int32_t ret;
    uint8_t *output = NULL;
    BSL_Buffer keyBuff = {0};
    do {
        ret = CRYPT_EAL_CipherGetInfo(pkcsParam->symId, CRYPT_INFO_KEY_LEN, &keyBuff.dataLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            break;
        }
        keyBuff.data = (uint8_t *)BSL_SAL_Malloc(keyBuff.dataLen);
        if (keyBuff.data == NULL) {
            ret = BSL_MALLOC_FAIL;
            BSL_ERR_PUSH_ERROR(ret);
            break;
        }

        ret = PbkdfDeriveKey(pkcsParam->itCnt, pkcsParam->hmacId, salt, pkcsParam->pwd, pkcsParam->pwdLen, &keyBuff);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            break;
        }

        uint32_t pkcsDataLen = unEncrypted->dataLen + 16; // extras 16 for padding.
        output = (uint8_t *)BSL_SAL_Malloc(pkcsDataLen);
        if (output == NULL) {
            ret = BSL_MALLOC_FAIL;
            BSL_ERR_PUSH_ERROR(ret);
            break;
        }
        BSL_Buffer enData = {unEncrypted->data, unEncrypted->dataLen};
        BSL_Buffer ivData = {asn1[CRYPT_PKCS_ENCPRIKEY_SYMIV_IDX].buff, asn1[CRYPT_PKCS_ENCPRIKEY_SYMIV_IDX].len};
        ret = DecryptEncData(&ivData, &enData, pkcsParam->symId, true, &keyBuff, output, &pkcsDataLen);
        if (ret != CRYPT_SUCCESS) {
            break;
        }
        asn1[CRYPT_PKCS_ENCPRIKEY_ENCDATA_IDX].buff = output;
        asn1[CRYPT_PKCS_ENCPRIKEY_ENCDATA_IDX].len = pkcsDataLen;
        asn1[CRYPT_PKCS_ENCPRIKEY_ENCDATA_IDX].tag = BSL_ASN1_TAG_OCTETSTRING;
        BSL_SAL_ClearFree(keyBuff.data, keyBuff.dataLen);
        return ret;
    } while (0);

    BSL_SAL_ClearFree(keyBuff.data, keyBuff.dataLen);
    BSL_SAL_FREE(output);
    return ret;
}

static int32_t GenRandIv(CRYPT_Pbkdf2Param *pkcsParam, BSL_ASN1_Buffer *asn1)
{
    int32_t ret;
    BslOidString *oidSym = BSL_OBJ_GetOidFromCID((BslCid)pkcsParam->symId);
    if (oidSym == NULL) {
        return CRYPT_ERR_ALGID;
    }
    asn1[CRYPT_PKCS_ENCPRIKEY_SYMALG_IDX].buff = (uint8_t *)oidSym->octs;
    asn1[CRYPT_PKCS_ENCPRIKEY_SYMALG_IDX].len = oidSym->octetLen;
    asn1[CRYPT_PKCS_ENCPRIKEY_SYMALG_IDX].tag = BSL_ASN1_TAG_OBJECT_ID;

    uint32_t ivLen;
    ret = CRYPT_EAL_CipherGetInfo(pkcsParam->symId, CRYPT_INFO_IV_LEN, &ivLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (ivLen == 0) {
        asn1[CRYPT_PKCS_ENCPRIKEY_SYMIV_IDX].tag = BSL_ASN1_TAG_OCTETSTRING;
        return CRYPT_SUCCESS;
    }
    uint8_t *iv = (uint8_t *)BSL_SAL_Malloc(ivLen);
    if (iv == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    ret = CRYPT_EAL_Randbytes(iv, ivLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_FREE(iv);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    asn1[CRYPT_PKCS_ENCPRIKEY_SYMIV_IDX].buff = iv;
    asn1[CRYPT_PKCS_ENCPRIKEY_SYMIV_IDX].len = ivLen;
    asn1[CRYPT_PKCS_ENCPRIKEY_SYMIV_IDX].tag = BSL_ASN1_TAG_OCTETSTRING;
    return ret;
}

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

static int32_t EncodePkcsEncryptedBuff(CRYPT_Pbkdf2Param *pkcsParam,
    BSL_Buffer *unEncrypted, BSL_ASN1_Buffer *asn1)
{
    BslOidString *oidPbes = BSL_OBJ_GetOidFromCID((BslCid)pkcsParam->pbesId);
    if (oidPbes == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ERR_ALGID);
        return CRYPT_ERR_ALGID;
    }
    int32_t ret;
    asn1[CRYPT_PKCS_ENCPRIKEY_ENCALG_IDX].buff = (uint8_t *)oidPbes->octs;
    asn1[CRYPT_PKCS_ENCPRIKEY_ENCALG_IDX].len = oidPbes->octetLen;
    asn1[CRYPT_PKCS_ENCPRIKEY_ENCALG_IDX].tag = BSL_ASN1_TAG_OBJECT_ID;
    /* derivation param */
    BSL_Buffer derParam = {0};
    uint8_t *saltData = (uint8_t *)BSL_SAL_Malloc(pkcsParam->saltLen);
    if (saltData == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    do {
        BSL_Buffer salt = {saltData, pkcsParam->saltLen};
        ret = EncodeDeriveKeyParam(pkcsParam, &derParam, &salt);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            break;
        }
        asn1[CRYPT_PKCS_ENCPRIKEY_DERPARAM_IDX].buff = derParam.data;
        asn1[CRYPT_PKCS_ENCPRIKEY_DERPARAM_IDX].len = derParam.dataLen;
        asn1[CRYPT_PKCS_ENCPRIKEY_DERPARAM_IDX].tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
        /* iv */
        ret = GenRandIv(pkcsParam, asn1);
        if (ret != CRYPT_SUCCESS) {
            break;
        }
        /* encryptedData */
        ret = EncodeEncryptedData(pkcsParam, unEncrypted, &salt, asn1);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            break;
        }
        BSL_SAL_FREE(saltData);
        return CRYPT_SUCCESS;
    } while (0);
    BSL_SAL_FREE(saltData);
    BSL_SAL_FREE(asn1[CRYPT_PKCS_ENCPRIKEY_DERPARAM_IDX].buff);
    BSL_SAL_FREE(asn1[CRYPT_PKCS_ENCPRIKEY_SYMIV_IDX].buff);
    BSL_SAL_FREE(asn1[CRYPT_PKCS_ENCPRIKEY_ENCDATA_IDX].buff);
    return ret;
}

static int32_t EncodePk8EncPriKeyBuff(CRYPT_EAL_PkeyCtx *ealPriKey,
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
    do {
        /* code */
        ret = EncodePkcsEncryptedBuff(pkcs8Param, &unEncrypted, asn1);
        if (ret != CRYPT_SUCCESS) {
            break;
        }
        /* encode */
        BSL_ASN1_Template templ = {pk8EncPriKeyTempl, sizeof(pk8EncPriKeyTempl) / sizeof(pk8EncPriKeyTempl[0])};
        ret = BSL_ASN1_EncodeTemplate(&templ, asn1, CRYPT_PKCS_ENCPRIKEY_MAX, &encode->data, &encode->dataLen);
    } while (0);
    BSL_SAL_ClearFree(unEncrypted.data, unEncrypted.dataLen);
    if (ret == CRYPT_SUCCESS) {
        BSL_SAL_FREE(asn1[CRYPT_PKCS_ENCPRIKEY_DERPARAM_IDX].buff);
        BSL_SAL_FREE(asn1[CRYPT_PKCS_ENCPRIKEY_SYMIV_IDX].buff);
        BSL_SAL_FREE(asn1[CRYPT_PKCS_ENCPRIKEY_ENCDATA_IDX].buff);
    }
    return ret;
}

int32_t CRYPT_EAL_EncodeAsn1PriKey(CRYPT_EAL_PkeyCtx *ealPriKey, const CRYPT_EncodeParam *encodeParam,
    int32_t type, BSL_Buffer *encode)
{
    switch (type) {
        case CRYPT_PRIKEY_ECC:
            return EncodeEccPrikeyAsn1Buff(ealPriKey, NULL, encode);
        case CRYPT_PRIKEY_RSA:
            return EncodeRsaPrikeyAsn1Buff(ealPriKey, CRYPT_PKEY_RSA, encode);
        case CRYPT_PRIKEY_PKCS8_UNENCRYPT:
            return EncodePk8PriKeyBuff(ealPriKey, encode);
        case CRYPT_PRIKEY_PKCS8_ENCRYPT:
            return EncodePk8EncPriKeyBuff(ealPriKey, encodeParam, encode);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_ENCODE_NO_SUPPORT_FORMAT);
            return CRYPT_ENCODE_NO_SUPPORT_FORMAT;
    }
}

int32_t CRYPT_EAL_EncodePemPriKey(CRYPT_EAL_PkeyCtx *ealPriKey, const CRYPT_EncodeParam *encodeParam,
    int32_t type, BSL_Buffer *encode)
{
    BSL_Buffer asn1 = {0};
    int32_t ret = CRYPT_EAL_EncodeAsn1PriKey(ealPriKey, encodeParam, type, &asn1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_PEM_Symbol symbol = {0};
    ret = EAL_GetPemPriKeySymbol(type, &symbol);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(asn1.data);
        return ret;
    }
    ret = BSL_PEM_EncodeAsn1ToPem(asn1.data, asn1.dataLen, &symbol, (char **)&encode->data, &encode->dataLen);
    BSL_SAL_Free(asn1.data);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t CRYPT_EAL_PriKeyEncodeBuff(CRYPT_EAL_PkeyCtx *ealPriKey, const CRYPT_EncodeParam *encodeParam,
    BSL_ParseFormat format, int32_t type, BSL_Buffer *encode)
{
    if (ealPriKey == NULL || encode == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    switch (format) {
        case BSL_FORMAT_ASN1:
            return CRYPT_EAL_EncodeAsn1PriKey(ealPriKey, encodeParam, type, encode);
        case BSL_FORMAT_PEM:
            return CRYPT_EAL_EncodePemPriKey(ealPriKey, encodeParam, type, encode);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_ENCODE_NO_SUPPORT_FORMAT);
            return CRYPT_ENCODE_NO_SUPPORT_FORMAT;
    }
}

int32_t CRYPT_EAL_PriKeyEncodeFile(CRYPT_EAL_PkeyCtx *ealPriKey, const CRYPT_EncodeParam *encodeParam,
    BSL_ParseFormat format, int32_t type, const char *path)
{
    BSL_Buffer encode = {0};
    int32_t ret = CRYPT_EAL_PriKeyEncodeBuff(ealPriKey, encodeParam, format, type, &encode);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BSL_SAL_WriteFile(path, encode.data, encode.dataLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    BSL_SAL_Free(encode.data);
    return ret;
}

static int32_t EncodeEccPubkeyAsn1Buff(CRYPT_EAL_PkeyCtx *ealPubKey, BSL_ASN1_Buffer *ecParamOid, BSL_Buffer *encodePub)
{
    int32_t ret;
    CRYPT_PKEY_ParaId paraId = CRYPT_EAL_PkeyGetParaId(ealPubKey);
    BslOidString *oid = BSL_OBJ_GetOidFromCID((BslCid)paraId);
    if (CRYPT_EAL_PkeyGetId(ealPubKey) == CRYPT_PKEY_SM2) {
        oid = BSL_OBJ_GetOidFromCID((BslCid)CRYPT_ECC_SM2);
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
    CRYPT_EAL_PkeyPub pubKey = {0};
    pubKey.id = CRYPT_EAL_PkeyGetId(ealPubKey);
    pubKey.key.eccPub.data = pub;
    pubKey.key.eccPub.len = pubLen;
    ret = CRYPT_EAL_PkeyGetPub(ealPubKey, &pubKey);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_FREE(pub);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    encodePub->data = pubKey.key.eccPub.data;
    encodePub->dataLen = pubKey.key.eccPub.len;
    return ret;
}

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
    if (padType != CRYPT_PKEY_EMSA_PSS) {
        pssParam->tag = BSL_ASN1_TAG_NULL;
        return CRYPT_SUCCESS;
    }
    CRYPT_RSA_PssPara rsaPssParam = {0};
    ret = GetPssParamInfo(ealPubKey, &rsaPssParam);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    pssParam->tag = BSL_ASN1_TAG_SEQUENCE | BSL_ASN1_TAG_CONSTRUCTED;
    return CRYPT_EAL_EncodeRsaPssAlgParam(&rsaPssParam, &pssParam->buff, &pssParam->len);
}

static int32_t EncodeRsaPubkeyAsn1Buff(CRYPT_EAL_PkeyCtx *ealPubKey, BSL_ASN1_Buffer *pssParam, BSL_Buffer *encodePub)
{
    int32_t ret;
    BSL_ASN1_Buffer pubAsn1[CRYPT_RSA_PUB_E_IDX + 1] = {0};
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

    ret = CRYPT_EAL_PkeyGetPub(ealPubKey, &pub);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_FREE(pub.key.rsaPub.n);
        BSL_SAL_FREE(pub.key.rsaPub.e);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    pubAsn1[CRYPT_RSA_PUB_N_IDX].buff = pub.key.rsaPub.n;
    pubAsn1[CRYPT_RSA_PUB_N_IDX].len = pub.key.rsaPub.nLen;
    pubAsn1[CRYPT_RSA_PUB_E_IDX].buff = pub.key.rsaPub.e;
    pubAsn1[CRYPT_RSA_PUB_E_IDX].len = pub.key.rsaPub.eLen;
    pubAsn1[CRYPT_RSA_PUB_N_IDX].tag = BSL_ASN1_TAG_INTEGER;
    pubAsn1[CRYPT_RSA_PUB_E_IDX].tag = BSL_ASN1_TAG_INTEGER;

    BSL_ASN1_Template pubTempl = {rsaPubTempl, sizeof(rsaPubTempl) / sizeof(rsaPubTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&pubTempl, pubAsn1, CRYPT_RSA_PUB_E_IDX + 1, &encodePub->data, &encodePub->dataLen);
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

static int32_t CRYPT_EAL_SubPubkeyGetInfo(CRYPT_EAL_PkeyCtx *ealPubKey, BSL_ASN1_Buffer *algo, BSL_Buffer *bitStr)
{
    int32_t ret;
    CRYPT_PKEY_AlgId cid = CRYPT_EAL_PkeyGetId(ealPubKey);
    BSL_Buffer bitTmp = {0};
    BSL_ASN1_Buffer algoId[BSL_ASN1_TAG_ALGOID_ANY_IDX + 1] = {0};
    if (cid == CRYPT_PKEY_RSA) {
        ret = EncodeRsaPubkeyAsn1Buff(ealPubKey, &algoId[BSL_ASN1_TAG_ALGOID_ANY_IDX], &bitTmp);
        if (algoId[BSL_ASN1_TAG_ALGOID_ANY_IDX].tag == (BSL_ASN1_TAG_SEQUENCE | BSL_ASN1_TAG_CONSTRUCTED)) {
            cid = (CRYPT_PKEY_AlgId)BSL_CID_RSASSAPSS;
        }
    } else if (cid == CRYPT_PKEY_ECDSA || cid == CRYPT_PKEY_SM2) {
        cid = (CRYPT_PKEY_AlgId)BSL_CID_EC_PUBLICKEY;
        ret = EncodeEccPubkeyAsn1Buff(ealPubKey, &algoId[BSL_ASN1_TAG_ALGOID_ANY_IDX], &bitTmp);
    } else {
        BSL_ERR_PUSH_ERROR(CRYPT_ERR_ALGID);
        return CRYPT_ERR_ALGID;
    }
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BslOidString *oidStr = BSL_OBJ_GetOidFromCID((BslCid)cid);
    if (oidStr == NULL) {
        BSL_SAL_FREE(bitTmp.data);
        ret = CRYPT_ERR_ALGID;
        BSL_ERR_PUSH_ERROR(ret);
        goto end;
    }
    algoId[BSL_ASN1_TAG_ALGOID_IDX].buff = (uint8_t *)oidStr->octs;
    algoId[BSL_ASN1_TAG_ALGOID_IDX].len = oidStr->octetLen;
    algoId[BSL_ASN1_TAG_ALGOID_IDX].tag = BSL_ASN1_TAG_OBJECT_ID;
    ret = EncodeAlgoIdAsn1Buff(algoId, BSL_ASN1_TAG_ALGOID_ANY_IDX + 1, &algo->buff, &algo->len);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_FREE(bitTmp.data);
        BSL_ERR_PUSH_ERROR(ret);
        goto end;
    }
    bitStr->data = bitTmp.data;
    bitStr->dataLen = bitTmp.dataLen;
end:
    if (cid == (CRYPT_PKEY_AlgId)BSL_CID_RSASSAPSS) {
        BSL_SAL_FREE(algoId[BSL_ASN1_TAG_ALGOID_ANY_IDX].buff);
    }
    return ret;
}

static int32_t CRYPT_EAL_EncodeAsn1SubPubkey(CRYPT_EAL_PkeyCtx *ealPubKey, bool isComplete, BSL_Buffer *encodeH)
{
    BSL_ASN1_Buffer algo = {0};
    BSL_Buffer bitStr = {0};
    int32_t ret = CRYPT_EAL_SubPubkeyGetInfo(ealPubKey, &algo, &bitStr);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_ASN1_Buffer encode[CRYPT_SUBKEYINFO_BITSTRING_IDX + 1] = {0};
    encode[CRYPT_SUBKEYINFO_ALGOID_IDX].buff = algo.buff;
    encode[CRYPT_SUBKEYINFO_ALGOID_IDX].len = algo.len;
    encode[CRYPT_SUBKEYINFO_ALGOID_IDX].tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
    BSL_ASN1_BitString bitPubkey = {bitStr.data, bitStr.dataLen, 0};
    encode[CRYPT_SUBKEYINFO_BITSTRING_IDX].buff = (uint8_t *)&bitPubkey;
    encode[CRYPT_SUBKEYINFO_BITSTRING_IDX].len = sizeof(BSL_ASN1_BitString);
    encode[CRYPT_SUBKEYINFO_BITSTRING_IDX].tag = BSL_ASN1_TAG_BITSTRING;

    BSL_ASN1_Template pubTempl;
    if (isComplete) {
        pubTempl.templItems = subKeyInfoTempl;
        pubTempl.templNum = sizeof(subKeyInfoTempl) / sizeof(subKeyInfoTempl[0]);
    } else {
        pubTempl.templItems = subKeyInfoInnerTempl;
        pubTempl.templNum = sizeof(subKeyInfoInnerTempl) / sizeof(subKeyInfoInnerTempl[0]);
    }
    ret =  BSL_ASN1_EncodeTemplate(&pubTempl,
        encode, CRYPT_SUBKEYINFO_BITSTRING_IDX + 1, &encodeH->data, &encodeH->dataLen);
    BSL_SAL_FREE(bitStr.data);
    BSL_SAL_FREE(algo.buff);
    return ret;
}

static int32_t CRYPT_EAL_EncodeAsn1PubKey(CRYPT_EAL_PkeyCtx *ealPubKey,
    int32_t type, bool isComplete, BSL_Buffer *encode)
{
    switch (type) {
        case CRYPT_PUBKEY_SUBKEY:
            return CRYPT_EAL_EncodeAsn1SubPubkey(ealPubKey, isComplete, encode);
        case CRYPT_PUBKEY_RSA:
            return EncodeRsaPubkeyAsn1Buff(ealPubKey, NULL, encode);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_ENCODE_NO_SUPPORT_TYPE);
            return CRYPT_ENCODE_NO_SUPPORT_TYPE;
    }
}

static int32_t CRYPT_EAL_EncodePemPubKey(CRYPT_EAL_PkeyCtx *ealPubKey,
    int32_t type, bool isComplete, BSL_Buffer *encode)
{
    BSL_Buffer asn1 = {0};
    int32_t ret = CRYPT_EAL_EncodeAsn1PubKey(ealPubKey, type, isComplete, &asn1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_PEM_Symbol symbol = {0};
    ret = EAL_GetPemPubKeySymbol(type, &symbol);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_FREE(asn1.data);
        return ret;
    }
    ret = BSL_PEM_EncodeAsn1ToPem(asn1.data, asn1.dataLen, &symbol, (char **)&encode->data, &encode->dataLen);
    BSL_SAL_FREE(asn1.data);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t CRYPT_EAL_EncodePubKeyBuffInternal(CRYPT_EAL_PkeyCtx *ealPubKey,
    BSL_ParseFormat format, int32_t type, bool isComplete, BSL_Buffer *encode)
{
    if (ealPubKey == NULL || encode == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    switch (format) {
        case BSL_FORMAT_ASN1:
            return CRYPT_EAL_EncodeAsn1PubKey(ealPubKey, type, isComplete, encode);
        case BSL_FORMAT_PEM:
            return CRYPT_EAL_EncodePemPubKey(ealPubKey, type, isComplete, encode);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_ENCODE_NO_SUPPORT_FORMAT);
            return CRYPT_ENCODE_NO_SUPPORT_FORMAT;
    }
}

int32_t CRYPT_EAL_PubKeyEncodeBuff(CRYPT_EAL_PkeyCtx *ealPubKey,
    BSL_ParseFormat format, int32_t type, BSL_Buffer *encode)
{
    return CRYPT_EAL_EncodePubKeyBuffInternal(ealPubKey, format, type, true, encode);
}

int32_t CRYPT_EAL_PubKeyEncodeFile(CRYPT_EAL_PkeyCtx *ealPubKey,
    BSL_ParseFormat format, int32_t type, const char *path)
{
    BSL_Buffer encode = {0};
    int32_t ret = CRYPT_EAL_PubKeyEncodeBuff(ealPubKey, format, type, &encode);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BSL_SAL_WriteFile(path, encode.data, encode.dataLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    BSL_SAL_FREE(encode.data);
    return ret;
}

int32_t CRYPT_EAL_DecodeBuffKey(int32_t format, int32_t type, BSL_Buffer *encode,
    const uint8_t *pwd, uint32_t pwdlen, CRYPT_EAL_PkeyCtx **ealPKey)
{
    switch (type) {
        case CRYPT_PRIKEY_PKCS8_UNENCRYPT:
        case CRYPT_PRIKEY_PKCS8_ENCRYPT:
        case CRYPT_PRIKEY_RSA:
        case CRYPT_PRIKEY_ECC:
            return CRYPT_EAL_PriKeyParseBuff(format, type, encode, pwd, pwdlen, ealPKey);
        case CRYPT_PUBKEY_SUBKEY:
        case CRYPT_PUBKEY_RSA:
            return CRYPT_EAL_PubKeyParseBuff(format, type, encode, ealPKey);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_DECODE_NO_SUPPORT_TYPE);
            return CRYPT_DECODE_NO_SUPPORT_TYPE;
    }
}

int32_t CRYPT_EAL_DecodeFileKey(int32_t format, int32_t type, const char *path,
    uint8_t *pwd, uint32_t pwdlen, CRYPT_EAL_PkeyCtx **ealPKey)
{
    if (path == NULL || strlen(path) > PATH_MAX_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    switch (type) {
        case CRYPT_PRIKEY_PKCS8_UNENCRYPT:
        case CRYPT_PRIKEY_PKCS8_ENCRYPT:
        case CRYPT_PRIKEY_RSA:
        case CRYPT_PRIKEY_ECC:
            return CRYPT_EAL_PriKeyParseFile(format, type, path, pwd, pwdlen, ealPKey);
        case CRYPT_PUBKEY_SUBKEY:
        case CRYPT_PUBKEY_RSA:
            return CRYPT_EAL_PubKeyParseFile(format, type, path, ealPKey);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_DECODE_NO_SUPPORT_TYPE);
            return CRYPT_DECODE_NO_SUPPORT_TYPE;
    }
}

int32_t CRYPT_EAL_EncodeBuffKey(CRYPT_EAL_PkeyCtx *ealPKey, const CRYPT_EncodeParam *encodeParam,
    int32_t format, int32_t type, BSL_Buffer *encode)
{
    switch (type) {
        case CRYPT_PRIKEY_PKCS8_UNENCRYPT:
        case CRYPT_PRIKEY_PKCS8_ENCRYPT:
        case CRYPT_PRIKEY_RSA:
        case CRYPT_PRIKEY_ECC:
            return CRYPT_EAL_PriKeyEncodeBuff(ealPKey, encodeParam, format, type, encode);
        case CRYPT_PUBKEY_SUBKEY:
        case CRYPT_PUBKEY_RSA:
            return CRYPT_EAL_PubKeyEncodeBuff(ealPKey, format, type, encode);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_ENCODE_NO_SUPPORT_TYPE);
            return CRYPT_ENCODE_NO_SUPPORT_TYPE;
    }
}

int32_t CRYPT_EAL_EncodeFileKey(CRYPT_EAL_PkeyCtx *ealPKey, const CRYPT_EncodeParam *encodeParam,
    int32_t format, int32_t type, const char *path)
{
    if (path == NULL || strlen(path) > PATH_MAX_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    switch (type) {
        case CRYPT_PRIKEY_PKCS8_UNENCRYPT:
        case CRYPT_PRIKEY_PKCS8_ENCRYPT:
        case CRYPT_PRIKEY_RSA:
        case CRYPT_PRIKEY_ECC:
            return CRYPT_EAL_PriKeyEncodeFile(ealPKey, encodeParam, format, type, path);
        case CRYPT_PUBKEY_SUBKEY:
        case CRYPT_PUBKEY_RSA:
            return CRYPT_EAL_PubKeyEncodeFile(ealPKey, format, type, path);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_ENCODE_NO_SUPPORT_TYPE);
            return CRYPT_ENCODE_NO_SUPPORT_TYPE;
    }
}

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

static BSL_ASN1_TemplateItem enContentInfoTempl[] = {
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

static int32_t ParsePKCS7EncryptedContentInfo(BSL_Buffer *encode, const uint8_t *pwd, uint32_t pwdlen,
    BSL_Buffer *output)
{
    uint8_t *temp = encode->data;
    uint32_t  tempLen = encode->dataLen;
    BSL_ASN1_Buffer asn1[HITLS_P7_ENC_CONTINFO_MAX_IDX] = {0};
    BSL_ASN1_Template templ = {enContentInfoTempl, sizeof(enContentInfoTempl) / sizeof(enContentInfoTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &temp, &tempLen, asn1, HITLS_P7_ENC_CONTINFO_MAX_IDX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BslOidString typeOidStr = {asn1[HITLS_P7_ENC_CONTINFO_TYPE_IDX].len,
        (char *)asn1[HITLS_P7_ENC_CONTINFO_TYPE_IDX].buff, 0};
    BslCid cid = BSL_OBJ_GetCIDFromOid(&typeOidStr);
    if (cid != BSL_CID_DATA) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_UNSUPPORTED_PKCS7_TYPE);
        return CRYPT_DECODE_UNSUPPORTED_PKCS7_TYPE;
    }
    BslOidString encOidStr = {asn1[HITLS_P7_ENC_CONTINFO_ENCALG_IDX].len,
        (char *)asn1[HITLS_P7_ENC_CONTINFO_ENCALG_IDX].buff, 0};
    cid = BSL_OBJ_GetCIDFromOid(&encOidStr);
    if (cid != BSL_CID_PBES2) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_UNSUPPORTED_ENCRYPT_TYPE);
        return CRYPT_DECODE_UNSUPPORTED_ENCRYPT_TYPE;
    }
    // parse sym alg id
    BslOidString symOidStr = {asn1[HITLS_P7_ENC_CONTINFO_SYMALG_IDX].len,
        (char *)asn1[HITLS_P7_ENC_CONTINFO_SYMALG_IDX].buff, 0};
    BslCid symId = BSL_OBJ_GetCIDFromOid(&symOidStr);
    if (symId == BSL_CID_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_UNKNOWN_OID);
        return CRYPT_DECODE_UNKNOWN_OID;
    }
    BSL_Buffer derivekeyData = {asn1[HITLS_P7_ENC_CONTINFO_DERIVE_PARAM_IDX].buff,
        asn1[HITLS_P7_ENC_CONTINFO_DERIVE_PARAM_IDX].len};
    BSL_Buffer ivData = {asn1[HITLS_P7_ENC_CONTINFO_SYMIV_IDX].buff, asn1[HITLS_P7_ENC_CONTINFO_SYMIV_IDX].len};
    BSL_Buffer enData = {asn1[HITLS_P7_ENC_CONTINFO_ENCONTENT_IDX].buff, asn1[HITLS_P7_ENC_CONTINFO_ENCONTENT_IDX].len};
    EncryptPara encPara = {
        .derivekeyData = &derivekeyData,
        .ivData = &ivData,
        .enData = &enData,
    };
    ret = ParseEncDataAsn1(symId, &encPara, pwd, pwdlen, output);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

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
static BSL_ASN1_TemplateItem encryptedDataTempl[] = {
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

int32_t CRYPT_EAL_ParseAsn1PKCS7EncryptedData(BSL_Buffer *encode, const uint8_t *pwd, uint32_t pwdlen,
    BSL_Buffer *output)
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
    BSL_ASN1_Template templ = {encryptedDataTempl, sizeof(encryptedDataTempl) / sizeof(encryptedDataTempl[0])};
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
    ret = ParsePKCS7EncryptedContentInfo(&encryptInfo, pwd, pwdlen, output);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

/* Encode PKCS7-EncryptData：only support PBES2 + PBKDF2, the param check ref CheckEncodeParam. */
static int32_t EncodePKCS7EncryptedContentInfo(BSL_Buffer *data, const CRYPT_EncodeParam *encodeParam,
    BSL_Buffer *encode)
{
    /* EncAlgid */
    int32_t ret = CheckEncodeParam(encodeParam);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    CRYPT_Pbkdf2Param *pkcs7Param = (CRYPT_Pbkdf2Param *)encodeParam->param;
    BSL_ASN1_Buffer asn1[CRYPT_PKCS_ENCPRIKEY_MAX] = {0};
    do {
        /* code */
        ret = EncodePkcsEncryptedBuff(pkcs7Param, data, asn1);
        if (ret != CRYPT_SUCCESS) {
            break;
        }
        /* encode */
        BslOidString *oidStr = BSL_OBJ_GetOidFromCID(BSL_CID_DATA);
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
        BSL_ASN1_Template templ = {enContentInfoTempl, sizeof(enContentInfoTempl) / sizeof(enContentInfoTempl[0])};
        ret = BSL_ASN1_EncodeTemplate(&templ, p7asn, HITLS_P7_ENC_CONTINFO_MAX_IDX, &encode->data, &encode->dataLen);
    } while (0);
    BSL_SAL_FREE(asn1[CRYPT_PKCS_ENCPRIKEY_DERPARAM_IDX].buff);
    BSL_SAL_FREE(asn1[CRYPT_PKCS_ENCPRIKEY_SYMIV_IDX].buff);
    BSL_SAL_FREE(asn1[CRYPT_PKCS_ENCPRIKEY_ENCDATA_IDX].buff);
    return ret;
}

int32_t CRYPT_EAL_EncodePKCS7EncryptDataBuff(BSL_Buffer *data, const void *encodeParam, BSL_Buffer *encode)
{
    if (data == NULL || encodeParam == NULL || encode == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    BSL_Buffer contentInfo = {0};
    int32_t ret = EncodePKCS7EncryptedContentInfo(data, encodeParam, &contentInfo);
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
    BSL_ASN1_Template templ = {encryptedDataTempl, sizeof(encryptedDataTempl) / sizeof(encryptedDataTempl[0])};
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

#endif // HITLS_CRYPTO_ENCODE
