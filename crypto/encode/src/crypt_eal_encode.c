/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_ENCODE
#include <stdint.h>
#include <string.h>

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

static BSL_ASN1_TemplateItem g_pk8DerParamTempl[] = {
    {BSL_ASN1_TAG_OBJECT_ID, 0, 0}, // derive alg
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_OCTETSTRING, 0, 1}, // salt
        {BSL_ASN1_TAG_INTEGER, 0, 1}, // iteration
        {BSL_ASN1_TAG_INTEGER, BSL_ASN1_FLAG_OPTIONAL, 1}, // keyLen
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_DEFAULT | BSL_ASN1_FLAG_HEADERONLY, 1}, // prf
};

typedef enum {
    CRYPT_PK8_ENCPRIKEY_ENCALG_IDX,
    CRYPT_PK8_ENCPRIKEY_DERPARAM_IDX,
    CRYPT_PK8_ENCPRIKEY_SYMALG_IDX,
    CRYPT_PK8_ENCPRIKEY_SYMIV_IDX,
    CRYPT_PK8_ENCPRIKEY_ENCDATA_IDX,
    CRYPT_PK8_ENCPRIKEY_MAX
} CRYPT_PK8_ENCPRIKEY_TEMPL_IDX;

typedef enum {
    CRYPT_PK8_ENCPRIKEY_DERALG_IDX,
    CRYPT_PK8_ENCPRIKEY_DERSALT_IDX,
    CRYPT_PK8_ENCPRIKEY_DERITER_IDX,
    CRYPT_PK8_ENCPRIKEY_DERKEYLEN_IDX,
    CRYPT_PK8_ENCPRIKEY_DERPRF_IDX,
    CRYPT_PK8_ENCPRIKEY_DERPARAM_MAX
} CRYPT_PK8_ENCPRIKEY_DERIVEPARAM_IDX;

// clang-format on

static CRYPT_PKEY_ParaId GetParaId(uint8_t *octs, uint32_t octsLen)
{
    BslOidString oidStr = {octsLen, (char *)octs, 0};
    BslCid cid = BSL_OBJ_GetCIDFromOid(&oidStr);
    if (cid == BSL_CID_UNKNOWN) {
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
                return CRYPT_SUCCESS;
            } else { //
                *(uint8_t *)expVal = BSL_ASN1_TAG_NULL; // is null
                return CRYPT_SUCCESS;
            }
        }
        default:
            break;
    }
    return CRYPT_DECODE_ASN1_BUFF_FAILED;
}

static int32_t ParseAlgoIdAsn1Buff(uint8_t *buff, uint32_t buffLen, BSL_ASN1_Buffer *algoId, uint32_t algoIdNum)
{
    uint8_t *tmpBuff = buff;
    uint32_t tmpBuffLen = buffLen;

    BSL_ASN1_Template templ = {algoIdTempl, sizeof(algoIdTempl) / sizeof(algoIdTempl[0])};
    return BSL_ASN1_DecodeTemplate(&templ, DecSubKeyInfoCb, &tmpBuff, &tmpBuffLen, algoId, algoIdNum);
}

static int32_t GetRsaPubKeyPadTypeByCid(BslCid cid)
{
    if (cid == BSL_CID_RSA) {
        return CRYPT_PKEY_EMSA_PKCSV15;
    } else if (cid == BSL_CID_RSASSAPSS) {
        return CRYPT_PKEY_EMSA_PSS;
    }

    return CRYPT_PKEY_RSA_PADDINGMAX;
}

static int32_t ParseRsaPubkeyAsn1Buff(uint8_t *buff, uint32_t buffLen, CRYPT_EAL_PkeyCtx **ealPubKey, BslCid cid)
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
        return ret;
    }

    int32_t padType = GetRsaPubKeyPadTypeByCid(cid);
    if (padType != CRYPT_PKEY_RSA_PADDINGMAX) {
        ret = CRYPT_EAL_PkeyCtrl(pctx, CRYPT_CTRL_SET_RSA_PADDING, &padType, sizeof(padType));
        if (ret != CRYPT_SUCCESS) {
            CRYPT_EAL_PkeyFreeCtx(pctx);
            return ret;
        }
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
    BSL_ASN1_Buffer *ecParamOid = algoId + 1; // the parameters OID
    BSL_ASN1_Buffer *pubkey = &encode[CRYPT_SUBKEYINFO_BITSTRING_IDX]; // the last BSL_ASN1_Buffer, the pubkey
    BSL_ASN1_BitString bitPubkey = {0};
    ret = BSL_ASN1_DecodePrimitiveItem(pubkey, &bitPubkey);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    BslOidString oidStr = {oid->len, (char *)oid->buff, 0};
    BslCid cid = BSL_OBJ_GetCIDFromOid(&oidStr);
    if (cid == BSL_CID_EC_PUBLICKEY) {
        return ParseEccPubkeyAsn1Buff(&bitPubkey, ecParamOid, ealPubKey);
    } else if (cid == BSL_CID_RSA || cid == BSL_CID_RSASSAPSS) {
        return ParseRsaPubkeyAsn1Buff(bitPubkey.buff, bitPubkey.len, ealPubKey, cid);
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
        return ret;
    }

    return ParseSubPubkeyAsn1(pubAsn1, (CRYPT_EAL_PkeyCtx **)ealPubKey);
}

static int32_t ParseEccPrikeyAsn1(BSL_ASN1_Buffer *encode, BSL_ASN1_Buffer *pk8AlgoParam,
                                  CRYPT_EAL_PkeyCtx **ealPriKey)
{
    BSL_ASN1_Buffer *prikey = &encode[CRYPT_ECPRIKEY_PRIKEY_IDX]; // the ECC OID
    BSL_ASN1_Buffer *ecParamOid = &encode[CRYPT_ECPRIKEY_PARAM_IDX]; // the parameters OID
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
        return ret;
    }

    return ParseEccPrikeyAsn1(asn1, pk8AlgoParam, ealPriKey);
}

static int32_t ParseRsaPrikeyAsn1(BSL_ASN1_Buffer *encode, CRYPT_EAL_PkeyCtx **ealPriKey, BslCid cid)
{
    CRYPT_EAL_PkeyPrv rsaPrv;
    rsaPrv.id = CRYPT_PKEY_RSA;
    rsaPrv.key.rsaPrv.d = encode[CRYPT_RSA_PRV_D_IDX].buff;
    rsaPrv.key.rsaPrv.dLen = encode[CRYPT_RSA_PRV_D_IDX].len;
    rsaPrv.key.rsaPrv.n = encode[CRYPT_RSA_PRV_N_IDX].buff;
    rsaPrv.key.rsaPrv.nLen = encode[CRYPT_RSA_PRV_N_IDX].len;
    rsaPrv.key.rsaPrv.e = encode[CRYPT_RSA_PRV_E_IDX].buff;
    rsaPrv.key.rsaPrv.eLen = encode[CRYPT_RSA_PRV_E_IDX].len;
    rsaPrv.key.rsaPrv.p = encode[CRYPT_RSA_PRV_P_IDX].buff;
    rsaPrv.key.rsaPrv.pLen = encode[CRYPT_RSA_PRV_P_IDX].len;
    rsaPrv.key.rsaPrv.q = encode[CRYPT_RSA_PRV_Q_IDX].buff;
    rsaPrv.key.rsaPrv.qLen = encode[CRYPT_RSA_PRV_Q_IDX].len;
    rsaPrv.key.rsaPrv.dP = encode[CRYPT_RSA_PRV_DP_IDX].buff;
    rsaPrv.key.rsaPrv.dPLen = encode[CRYPT_RSA_PRV_DP_IDX].len;
    rsaPrv.key.rsaPrv.dQ = encode[CRYPT_RSA_PRV_DQ_IDX].buff;
    rsaPrv.key.rsaPrv.dQLen = encode[CRYPT_RSA_PRV_DQ_IDX].len;
    rsaPrv.key.rsaPrv.qInv = encode[CRYPT_RSA_PRV_QINV_IDX].buff;
    rsaPrv.key.rsaPrv.qInvLen = encode[CRYPT_RSA_PRV_QINV_IDX].len;

    CRYPT_EAL_PkeyCtx *pctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    if (pctx == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = CRYPT_EAL_PkeySetPrv(pctx, &rsaPrv);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pctx);
        return ret;
    }
    int32_t padType = GetRsaPubKeyPadTypeByCid(cid);
    if (padType != CRYPT_PKEY_RSA_PADDINGMAX) {
        ret = CRYPT_EAL_PkeyCtrl(pctx, CRYPT_CTRL_SET_RSA_PADDING, &padType, sizeof(padType));
        if (ret != CRYPT_SUCCESS) {
            CRYPT_EAL_PkeyFreeCtx(pctx);
            return ret;
        }
    }
    *ealPriKey = pctx;
    return ret;
}

static int32_t ParseRsaPrikeyAsn1Buff(uint8_t *buff, uint32_t buffLen, CRYPT_EAL_PkeyCtx **ealPriKey, BslCid cid)
{
    uint8_t *tmpBuff = buff;
    uint32_t tmpBuffLen = buffLen;
    // decode n and e
    BSL_ASN1_Buffer asn1[CRYPT_RSA_PRV_OTHER_PRIME_IDX + 1] = {0};
    BSL_ASN1_Template templ = {rsaPrvTempl, sizeof(rsaPrvTempl) / sizeof(rsaPrvTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &tmpBuff, &tmpBuffLen, asn1, CRYPT_RSA_PRV_OTHER_PRIME_IDX + 1);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    return ParseRsaPrikeyAsn1(asn1, ealPriKey, cid);
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
        return ParseRsaPrikeyAsn1Buff(octPriKey->buff, octPriKey->len, ealPriKey, cid);
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

static int32_t ParseDriveKeyPrfAlgId(BSL_ASN1_Buffer *asn, int32_t *prfId)
{
    int32_t ret = CRYPT_SUCCESS;
    if (asn->len != 0) {
        BSL_ASN1_Buffer algoId[2] = {0};
        ret = ParseAlgoIdAsn1Buff(asn->buff, asn->len, algoId, 2);
        if (ret != CRYPT_SUCCESS) {
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
    return ret;
}

static int32_t ParseDriveKeyParam(BSL_ASN1_Buffer *asn, int *iter, int *keyLen, BSL_Buffer *salt, int *prfId)
{
    BslOidString oidStr = {asn[CRYPT_PK8_ENCPRIKEY_ENCALG_IDX].len,
        (char *)asn[CRYPT_PK8_ENCPRIKEY_ENCALG_IDX].buff, 0};
    BslCid cid = BSL_OBJ_GetCIDFromOid(&oidStr);
    if (cid != BSL_CID_PBES2) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_UNKNOWN_OID);
        return CRYPT_DECODE_UNKNOWN_OID;
    }

    uint8_t *tmpBuff = asn[CRYPT_PK8_ENCPRIKEY_DERPARAM_IDX].buff;
    uint32_t tmpBuffLen = asn[CRYPT_PK8_ENCPRIKEY_DERPARAM_IDX].len;

    BSL_ASN1_Buffer derParam[CRYPT_PK8_ENCPRIKEY_DERPARAM_MAX] = {0};
    BSL_ASN1_Template templ = {g_pk8DerParamTempl, sizeof(g_pk8DerParamTempl) / sizeof(g_pk8DerParamTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL,
        &tmpBuff, &tmpBuffLen, derParam, CRYPT_PK8_ENCPRIKEY_DERPARAM_MAX);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    oidStr.octedLen = derParam[CRYPT_PK8_ENCPRIKEY_DERALG_IDX].len;
    oidStr.octs = (char *)derParam[CRYPT_PK8_ENCPRIKEY_DERALG_IDX].buff;
    cid = BSL_OBJ_GetCIDFromOid(&oidStr);
    if (cid != BSL_CID_PBKDF2) { // only pbkdf2 is supported
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_PKCS8_INVALID_ALGO_PARAM);
        return CRYPT_DECODE_PKCS8_INVALID_ALGO_PARAM;
    }
    ret = BSL_ASN1_DecodePrimitiveItem(&derParam[CRYPT_PK8_ENCPRIKEY_DERITER_IDX], iter);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_PKCS8_INVALID_ITER);
        return CRYPT_DECODE_PKCS8_INVALID_ITER;
    }
    if (derParam[CRYPT_PK8_ENCPRIKEY_DERKEYLEN_IDX].len != 0) {
        ret = BSL_ASN1_DecodePrimitiveItem(&derParam[CRYPT_PK8_ENCPRIKEY_DERKEYLEN_IDX], keyLen);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(CRYPT_DECODE_PKCS8_INVALID_KEYLEN);
            return CRYPT_DECODE_PKCS8_INVALID_KEYLEN;
        }
    }
    salt->data = derParam[CRYPT_PK8_ENCPRIKEY_DERSALT_IDX].buff;
    salt->dataLen = derParam[CRYPT_PK8_ENCPRIKEY_DERSALT_IDX].len;
    return ParseDriveKeyPrfAlgId(&derParam[CRYPT_PK8_ENCPRIKEY_DERPRF_IDX], prfId);;
}

static int32_t DecryptEncPkcs8Data(BSL_ASN1_Buffer *asn, int32_t alg, BSL_Buffer *key,
    uint8_t *pkcs8Data, uint32_t *pkcs8DataLen)
{
    uint32_t buffLen = *pkcs8DataLen;
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(alg);
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = CRYPT_EAL_CipherInit(ctx, key->data, key->dataLen, asn[CRYPT_PK8_ENCPRIKEY_SYMIV_IDX].buff,
        asn[CRYPT_PK8_ENCPRIKEY_SYMIV_IDX].len, false);
    if (ret != CRYPT_SUCCESS) {
        goto ERR;
    }
    ret = CRYPT_EAL_CipherSetPadding(ctx, CRYPT_PADDING_PKCS7);
    if (ret != CRYPT_SUCCESS) {
        goto ERR;
    }
    ret = CRYPT_EAL_CipherUpdate(ctx, asn[CRYPT_PK8_ENCPRIKEY_ENCDATA_IDX].buff,
        asn[CRYPT_PK8_ENCPRIKEY_ENCDATA_IDX].len, pkcs8Data, pkcs8DataLen);
    if (ret != CRYPT_SUCCESS) {
        goto ERR;
    }
    buffLen -= *pkcs8DataLen;
    ret = CRYPT_EAL_CipherFinal(ctx, pkcs8Data + *pkcs8DataLen, &buffLen);
    if (ret != CRYPT_SUCCESS) {
        goto ERR;
    }
    *pkcs8DataLen += buffLen;
ERR:
    CRYPT_EAL_CipherFreeCtx(ctx);
    return ret;
}

static int32_t ParsePk8EncPrikeyAsn1(BSL_ASN1_Buffer *asn, BSL_Buffer *pass, CRYPT_EAL_PkeyCtx **ealPriKey)
{
    int32_t iter, prfId;
    int32_t keylen = 0;
    uint8_t key[32]; // The maximum length of the symmetry algorithm
    BSL_Buffer salt = {0};
    int32_t ret = ParseDriveKeyParam(asn, &iter, &keylen, &salt, &prfId);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    // parse sym alg id
    BslOidString oidStr = {asn[CRYPT_PK8_ENCPRIKEY_SYMALG_IDX].len,
        (char *)asn[CRYPT_PK8_ENCPRIKEY_SYMALG_IDX].buff, 0};
    BslCid symId = BSL_OBJ_GetCIDFromOid(&oidStr);
    if (symId == BSL_CID_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_UNKNOWN_OID);
        return CRYPT_DECODE_UNKNOWN_OID;
    }
    uint32_t symKeyLen;
    ret = CRYPT_EAL_CipherGetInfo((CRYPT_CIPHER_AlgId)symId, CRYPT_INFO_KEY_LEN, &symKeyLen);
    if (keylen != 0 && symKeyLen != (uint32_t)keylen) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_PKCS8_INVALID_KEYLEN);
        return CRYPT_DECODE_PKCS8_INVALID_KEYLEN;
    }

    CRYPT_EAL_KdfCTX *kdfCtx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_PBKDF2);
    if (kdfCtx == NULL) {
        return CRYPT_PBKDF2_NOT_SUPPORTED;
    }

    CRYPT_Param macAlgIdParam = {CRYPT_KDF_PARAM_MAC_ALG_ID, &prfId, 0};
    if ((ret = CRYPT_EAL_KdfSetParam(kdfCtx, &macAlgIdParam)) != CRYPT_SUCCESS) {
        return ret;
    }

    CRYPT_Param passwordParam = {CRYPT_KDF_PARAM_PASSWORD, pass->data, pass->dataLen};
    if ((ret = CRYPT_EAL_KdfSetParam(kdfCtx, &passwordParam)) != CRYPT_SUCCESS) {
        return ret;
    }

    CRYPT_Param saltParam = {CRYPT_KDF_PARAM_SALT, salt.data, salt.dataLen};
    if ((ret = CRYPT_EAL_KdfSetParam(kdfCtx, &saltParam)) != CRYPT_SUCCESS) {
        return ret;
    }

    CRYPT_Param iterParam = {CRYPT_KDF_PARAM_ITER, &iter, 0};
    if ((ret = CRYPT_EAL_KdfSetParam(kdfCtx, &iterParam)) != CRYPT_SUCCESS) {
        return ret;
    }

    if ((ret = CRYPT_EAL_KdfDerive(kdfCtx, key, symKeyLen)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    CRYPT_EAL_KdfFreeCtx(kdfCtx);

    uint8_t *pkcs8Data = BSL_SAL_Malloc(asn[CRYPT_PK8_ENCPRIKEY_ENCDATA_IDX].len);
    if (pkcs8Data == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    uint32_t pkcs8DataLen = asn[CRYPT_PK8_ENCPRIKEY_ENCDATA_IDX].len;
    BSL_Buffer keyBuff = {key, symKeyLen};
    ret = DecryptEncPkcs8Data(asn, symId, &keyBuff, pkcs8Data, &pkcs8DataLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(pkcs8Data);
        return ret;
    }
    BSL_Buffer encode = {pkcs8Data, pkcs8DataLen};
    ret = ParsePk8PriKeyBuff(&encode, ealPriKey);
    BSL_SAL_Free(pkcs8Data);
    return ret;
}

static int32_t ParsePk8EncPriKeyBuff(BSL_Buffer *buff, BSL_Buffer *pass, CRYPT_EAL_PkeyCtx **ealPriKey)
{
    uint8_t *tmpBuff = buff->data;
    uint32_t tmpBuffLen = buff->dataLen;

    BSL_ASN1_Buffer asn1[CRYPT_PK8_ENCPRIKEY_MAX] = {0};
    BSL_ASN1_Template templ = {pk8EncPriKeyTempl, sizeof(pk8EncPriKeyTempl) / sizeof(pk8EncPriKeyTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &tmpBuff, &tmpBuffLen, asn1, CRYPT_PK8_ENCPRIKEY_MAX);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    return ParsePk8EncPrikeyAsn1(asn1, pass, ealPriKey);
}

int32_t CRYPT_EAL_ParseAsn1PubKey(int32_t type, BSL_Buffer *encode, CRYPT_EAL_PkeyCtx **ealPubKey)
{
    switch (type) {
        case CRYPT_PUBKEY_SUBKEY:
            return CRYPT_EAL_ParseAsn1SubPubkey(encode->data, encode->dataLen, (void **)ealPubKey, true);
        case CRYPT_PUBKEY_RSA:
            return ParseRsaPubkeyAsn1Buff(encode->data, encode->dataLen, ealPubKey, BSL_CID_UNKNOWN);
        default:
            return CRYPT_DECODE_NO_SUPPORT_TYPE;
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
    BSL_PEM_Symbol symbol = {NULL};
    int32_t ret = EAL_GetPemPubKeySymbol(type, &symbol);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    BSL_Buffer asn1 = {NULL};
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

int32_t CRYPT_EAL_ParseBuffPubKey(BSL_ParseFormat format, int32_t type, BSL_Buffer *encode,
    CRYPT_EAL_PkeyCtx **ealPubKey)
{
    int32_t ret;
    if (encode == NULL || encode->data == NULL || encode->dataLen == 0 || ealPubKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    switch (format) {
        case BSL_PARSE_FORMAT_ASN1:
            ret = CRYPT_EAL_ParseAsn1PubKey(type, encode, ealPubKey);
            break;
        case BSL_PARSE_FORMAT_PEM:
            ret = CRYPT_EAL_ParsePemPubKey(type, encode, ealPubKey);
            break;
        case BSL_PARSE_FORMAT_UNKNOWN:
            ret = CRYPT_EAL_ParseUnknownPubKey(type, encode, ealPubKey);
            break;
        default:
            ret = CRYPT_DECODE_NO_SUPPORT_FORMAT;
            break;
    }
    return ret;
}

int32_t CRYPT_EAL_ParseFilePubKey(BSL_ParseFormat format, int32_t type, const char *path, CRYPT_EAL_PkeyCtx **ealPubKey)
{
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    int32_t ret = BSL_SAL_ReadFile(path, &data, &dataLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_Buffer encode = {data, dataLen};
    ret = CRYPT_EAL_ParseBuffPubKey(format, type, &encode, ealPubKey);
    BSL_SAL_Free(data);
    return ret;
}

int32_t CRYPT_EAL_ParseAsn1PriKey(int32_t type, BSL_Buffer *encode, uint8_t *pwd, uint32_t pwdlen,
    CRYPT_EAL_PkeyCtx **ealPriKey)
{
    BSL_Buffer pass = {.data = pwd, .dataLen = pwdlen};
    switch (type) {
        case CRYPT_PRIKEY_ECC:
            return ParseEccPrikeyAsn1Buff(encode->data, encode->dataLen, NULL, ealPriKey);
        case CRYPT_PRIKEY_RSA:
            return ParseRsaPrikeyAsn1Buff(encode->data, encode->dataLen, ealPriKey, BSL_CID_UNKNOWN);
        case CRYPT_PRIKEY_PKCS8_UNENCRYPT:
            return ParsePk8PriKeyBuff(encode, ealPriKey);
        case CRYPT_PRIKEY_PKCS8_ENCRYPT:
            return ParsePk8EncPriKeyBuff(encode, &pass, ealPriKey);
        default:
            return CRYPT_DECODE_NO_SUPPORT_FORMAT;
    }
    return CRYPT_SUCCESS;
}

static int32_t EAL_GetPemPriKeySymbol(int32_t type, BSL_PEM_Symbol *symbol)
{
    switch (type) {
        case CRYPT_PRIKEY_ECC:
            symbol->head = BSL_PEM_EC_PIR_KEY_BEGIN_STR;
            symbol->tail = BSL_PEM_EC_PIR_KEY_END_STR;
            return CRYPT_SUCCESS;
        case CRYPT_PRIKEY_RSA:
            symbol->head = BSL_PEM_RSA_PIR_KEY_BEGIN_STR;
            symbol->tail = BSL_PEM_RSA_PIR_KEY_END_STR;
            return CRYPT_SUCCESS;
        case CRYPT_PRIKEY_PKCS8_UNENCRYPT:
            symbol->head = BSL_PEM_PIR_KEY_BEGIN_STR;
            symbol->tail = BSL_PEM_PIR_KEY_END_STR;
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

int32_t CRYPT_EAL_ParsePemPriKey(int32_t type, BSL_Buffer *encode, uint8_t *pwd, uint32_t pwdlen,
    CRYPT_EAL_PkeyCtx **ealPriKey)
{
    BSL_PEM_Symbol symbol = {NULL};
    int32_t ret = EAL_GetPemPriKeySymbol(type, &symbol);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    BSL_Buffer asn1 = {NULL};
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

int32_t CRYPT_EAL_ParseUnkownPriKey(int32_t type, BSL_Buffer *encode, uint8_t *pwd, uint32_t pwdlen,
    CRYPT_EAL_PkeyCtx **ealPriKey)
{
    bool isPem = BSL_PEM_IsPemFormat((char *)(encode->data), encode->dataLen);
    if (isPem) {
        return CRYPT_EAL_ParsePemPriKey(type, encode, pwd, pwdlen, ealPriKey);
    } else {
        return CRYPT_EAL_ParseAsn1PriKey(type, encode, pwd, pwdlen, ealPriKey);
    }
}

int32_t CRYPT_EAL_ParseBuffPriKey(BSL_ParseFormat format, int32_t type, BSL_Buffer *encode,
    uint8_t *pwd, uint32_t pwdlen, CRYPT_EAL_PkeyCtx **ealPriKey)
{
    int32_t ret;
    if (encode == NULL || encode->data == NULL || encode->dataLen == 0 || ealPriKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    switch (format) {
        case BSL_PARSE_FORMAT_ASN1:
            ret = CRYPT_EAL_ParseAsn1PriKey(type, encode, pwd, pwdlen, ealPriKey);
            break;
        case BSL_PARSE_FORMAT_PEM:
            ret = CRYPT_EAL_ParsePemPriKey(type, encode, pwd, pwdlen, ealPriKey);
            break;
        case BSL_PARSE_FORMAT_UNKNOWN:
            ret = CRYPT_EAL_ParseUnkownPriKey(type, encode, pwd, pwdlen, ealPriKey);
            break;
        default:
            ret = CRYPT_DECODE_NO_SUPPORT_FORMAT;
            break;
    }
    return ret;
}

int32_t CRYPT_EAL_ParseFilePriKey(BSL_ParseFormat format, int32_t type, const char *path, uint8_t *pwd, uint32_t pwdlen,
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
    ret = CRYPT_EAL_ParseBuffPriKey(format, type, &encode, pwd, pwdlen, ealPriKey);
    BSL_SAL_Free(data);
    return ret;
}

#endif // HITLS_CRYPTO_ENCODE
