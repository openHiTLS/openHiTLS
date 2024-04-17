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
#include "crypt_ecc.h"
#include "crypt_eal_pkey.h"
#include "crypt_errno.h"
#include "crypt_eal_encode.h"

/**
 * RSAPublicKey  ::=  SEQUENCE  {
 *        modulus            INTEGER,    -- n
 *        publicExponent     INTEGER  }  -- e
 *
 * https://datatracker.ietf.org/doc/html/rfc4055#autoid-3
 */
static BSL_ASN1_TemplateItem rsaPubTempl[] = {
    //  {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0}, /* ignore seq */
    {BSL_ASN1_TAG_INTEGER, 0, 0}, /* n */
    {BSL_ASN1_TAG_INTEGER, 0, 0}, /* e */
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
    //  {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0}, /* ignore seq header */
    {BSL_ASN1_TAG_INTEGER, 0, 0}, /* version */
    {BSL_ASN1_TAG_INTEGER, 0, 0}, /* n */
    {BSL_ASN1_TAG_INTEGER, 0, 0}, /* e */
    {BSL_ASN1_TAG_INTEGER, 0, 0}, /* d */
    {BSL_ASN1_TAG_INTEGER, 0, 0}, /* p */
    {BSL_ASN1_TAG_INTEGER, 0, 0}, /* q */
    {BSL_ASN1_TAG_INTEGER, 0, 0}, /* d mod (p-1) */
    {BSL_ASN1_TAG_INTEGER, 0, 0}, /* d mod (q-1) */
    {BSL_ASN1_TAG_INTEGER, 0, 0}, /* q^-1 mod p */
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_SAME, 0}, /* OtherPrimeInfos OPTIONAL */
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1}, /* OtherPrimeInfo */
        {BSL_ASN1_TAG_INTEGER, 0, 2}, /* ri */
        {BSL_ASN1_TAG_INTEGER, 0, 2}, /* di */
        {BSL_ASN1_TAG_INTEGER, 0, 2} /* ti */
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
    //{BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},   // ignore seq
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
    //  {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},  // ignore seq header
    {BSL_ASN1_TAG_INTEGER, 0, 0}, /* version */
    {BSL_ASN1_TAG_OCTETSTRING, 0, 0}, /* private key */
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_EC_PRIKEY_PARAM, BSL_ASN1_FLAG_OPTIONAL, 0},
        {BSL_ASN1_TAG_OBJECT_ID, 0, 1},
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_EC_PRIKEY_PUBKEY, BSL_ASN1_FLAG_OPTIONAL, 0},
        {BSL_ASN1_TAG_BITSTRING, 0, 1},
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
    //  {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0}, // ignore seq header
    {BSL_ASN1_TAG_INTEGER, 0, 0},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 0},
    {BSL_ASN1_TAG_OCTETSTRING, 0, 0},
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
    //  {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},   // ignore seq header
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_OBJECT_ID, 0, 1},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 1},
        {BSL_ASN1_TAG_OCTETSTRING, 0, 1},
};

typedef enum {
    CRYPT_PK8_ENCPRIKEY_ENCOID_IDX = 0,
    CRYPT_PK8_ENCPRIKEY_ENCALG_IDX = 1,
    CRYPT_PK8_ENCPRIKEY_ENCDATA_IDX = 2,
} CRYPT_PK8_ENCPRIKEY_TEMPL_IDX;

static BSL_ASN1_TemplateItem seqTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 0},
};
 

static const char *ecPubKey = "\x2a\x86\x48\xce\x3d\x02\01";  // 1.2.840.10045.2.1
static const char *rsaEncryption = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"; // 1.2.840.113549.1.1.1
static const char *rsaPssEncryption = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a";

static const char *ecdsaPrimep256v1 = "\x2a\x86\x48\xce\x3d\x03\x01\x07";
static const char *ecdsaSecp384r1 = "\x2b\x81\x04\x00\x22";  // has '\0', can't use strlen to determine it's lenght.
static const char *ecdsaSecp521r1 = "\x2b\x81\x04\x00\x23";  // has '\0', can't use strlen to determine it's lenght.

// TODO: should replace by API of bsl_obj
static CRYPT_PKEY_ParaId GetParaId(const BSL_ASN1_Buffer *paramOid)
{
    if (memcmp(paramOid->buff, ecdsaPrimep256v1, paramOid->len) == 0) {
        return CRYPT_ECC_NISTP256;
    } else if (memcmp(paramOid->buff, ecdsaSecp384r1, paramOid->len) == 0) {
        return CRYPT_ECC_NISTP384;
    } else if (memcmp(paramOid->buff, ecdsaSecp521r1, paramOid->len) == 0) {
        return CRYPT_ECC_NISTP521;
    }
    return CRYPT_PKEY_PARAID_MAX;
}

static int32_t DecSubKeyInfoCb(int32_t type, int32_t idx, void *data, void *expVal)
{
    (void)idx;
    BSL_ASN1_Buffer *param = (BSL_ASN1_Buffer *) data;
    size_t len = param->len;

    switch (type) {
        case BSL_ASN1_TYPE_GET_ANY_TAG:
            if (strlen(ecPubKey) == len && memcmp(param->buff, ecPubKey, len) == 0) {
                // note: any It can be encoded empty or it can be null
                *(uint8_t *) expVal = BSL_ASN1_TAG_OBJECT_ID; 
                return CRYPT_SUCCESS;
            } else { //
                *(uint8_t *) expVal = BSL_ASN1_TAG_NULL; // is null
                return CRYPT_SUCCESS;
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

static int32_t ParseSeqHeaderOnly(uint8_t *seq, uint32_t seqLen, BSL_Buffer *data)
{
    BSL_ASN1_Buffer seqAsn1[1] = {0};
    BSL_ASN1_Template pubTempl = {seqTempl, sizeof(seqTempl) / sizeof(seqTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&pubTempl, NULL,
        &seq, &seqLen, seqAsn1, 1);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    data->data = seqAsn1->buff;
    data->dataLen = seqAsn1->len;
    return ret;
}

static int32_t ParseRsaPubkeyAsn1Buff(uint8_t *buff, uint32_t buffLen, CRYPT_EAL_PkeyCtx **ealPubKey)
{
    uint8_t *tmpBuff = buff;
    uint32_t tmpBuffLen = buffLen;
    // decode n and e 
    BSL_ASN1_Buffer pubAsn1[CRYPT_RSA_PUB_E_IDX + 1] = {0};
    BSL_ASN1_Template pubTempl = {rsaPubTempl, sizeof(rsaPubTempl) / sizeof(rsaPubTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&pubTempl, NULL,
            &tmpBuff, &tmpBuffLen, pubAsn1, CRYPT_RSA_PUB_E_IDX + 1);
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

    BSL_ASN1_Buffer *oid = algoId;   // OID
    BSL_ASN1_Buffer *ecParamOid = algoId + 1; // the parameters OID
    BSL_ASN1_Buffer *pubkey = encode + 1; // the last BSL_ASN1_Buffer, the pubkey
    BSL_ASN1_BitString bitPubkey = {0};
    ret = BSL_ASN1_DecodePrimitiveItem(pubkey, &bitPubkey);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    CRYPT_EAL_PkeyCtx *pctx = NULL;

    if (oid->tag == BSL_ASN1_TAG_OBJECT_ID) {
        if (oid->len == strlen(ecPubKey) && memcmp(oid->buff, ecPubKey, oid->len) == 0) {
            // ecPubKey
            pctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDSA);
            if (pctx == NULL) {
                return CRYPT_MEM_ALLOC_FAIL;
            }
            CRYPT_PKEY_ParaId paraId = GetParaId(ecParamOid);
            ret = CRYPT_EAL_PkeySetParaById(pctx, paraId);
            if (ret != CRYPT_SUCCESS) {
                goto ERR_OUT;
            }
            CRYPT_EAL_PkeyPub pub;
            pub.id = CRYPT_PKEY_ECDSA;
            pub.key.eccPub.data = bitPubkey.buff;
            pub.key.eccPub.len = bitPubkey.len;
            ret = CRYPT_EAL_PkeySetPub(pctx, &pub);
            if (ret != CRYPT_SUCCESS) {
                goto ERR_OUT;
            }
        } else if (oid->len == strlen(rsaEncryption) && (memcmp(oid->buff, rsaEncryption, oid->len) == 0 ||
            (memcmp(oid->buff, rsaPssEncryption, oid->len) == 0))) {
            // rsa pubkey, remove seq header fist.
            BSL_Buffer data = {0};
            ret = ParseSeqHeaderOnly(bitPubkey.buff, bitPubkey.len, &data);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
            return ParseRsaPubkeyAsn1Buff(data.data, data.dataLen, ealPubKey);
        } else {
            BSL_ERR_PUSH_ERROR(CRYPT_DECODE_UNKNOWN_OID);
            return CRYPT_DECODE_UNKNOWN_OID;
        }
    }
    *ealPubKey = pctx;
    return ret;

ERR_OUT:
    CRYPT_EAL_PkeyFreeCtx(pctx);
    return ret;
}

static int32_t ParseSubPubkeyAsn1Buff(uint8_t *buff, uint32_t buffLen, CRYPT_EAL_PkeyCtx **ealPubKey, bool isComplete)
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
    int32_t ret = BSL_ASN1_DecodeTemplate(&pubTempl, DecSubKeyInfoCb,
        &tmpBuff, &tmpBuffLen, pubAsn1, CRYPT_SUBKEYINFO_BITSTRING_IDX + 1);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    return ParseSubPubkeyAsn1(pubAsn1, ealPubKey);
}

static int32_t ParseEccPrikeyAsn1(BSL_ASN1_Buffer *encode, uint32_t encodeLen,
    BSL_ASN1_Buffer *pk8AlgoParam, CRYPT_EAL_PkeyCtx **ealPriKey)
{
    if (encodeLen < 4) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ASN1_BUFF_NUM_NOT_ENOUGH);
        return CRYPT_DECODE_ASN1_BUFF_NUM_NOT_ENOUGH;
    }

    BSL_ASN1_Buffer *prikey = encode + 1;   // the ECC OID
    BSL_ASN1_Buffer *ecParamOid = encode + 2; // the parameters OID
    BSL_ASN1_Buffer *param = pk8AlgoParam;
    if (ecParamOid->len != 0) {
        // has a valid Algorithm param
        param = ecParamOid;
    } else {
        if (param->len == 0) {
            return CRYPT_DECODE_PKCS8_INVALID_ALGO_PARAM;
        }
    }

    CRYPT_EAL_PkeyCtx *pctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDSA);
    if (pctx == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    CRYPT_PKEY_ParaId paraId = GetParaId(param);
    int32_t ret = CRYPT_EAL_PkeySetParaById(pctx, paraId);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pctx);
        return ret;
    }
    CRYPT_EAL_PkeyPrv prv;
    prv.id = CRYPT_PKEY_ECDSA;
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

static int32_t ParseEccPrikeyAsn1Buff(uint8_t *buff, uint32_t buffLen,
    BSL_ASN1_Buffer *pk8AlgoParam, CRYPT_EAL_PkeyCtx **ealPriKey)
{
    uint8_t *tmpBuff = buff;
    uint32_t tmpBuffLen = buffLen;

    BSL_ASN1_Buffer asn1[CRYPT_ECPRIKEY_PUBKEY_IDX + 1] = {0};
    BSL_ASN1_Template templ = {ecPriKeyTempl, sizeof(ecPriKeyTempl) / sizeof(ecPriKeyTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL,
        &tmpBuff, &tmpBuffLen, asn1, CRYPT_ECPRIKEY_PUBKEY_IDX + 1);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    return ParseEccPrikeyAsn1(asn1, CRYPT_ECPRIKEY_PUBKEY_IDX + 1, pk8AlgoParam, ealPriKey);
}

static int32_t ParseRsaPrikeyAsn1(BSL_ASN1_Buffer *encode, uint32_t encodeLen, CRYPT_EAL_PkeyCtx **ealPriKey)
{
    if (encodeLen <= CRYPT_RSA_PRV_OTHER_PRIME_IDX) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ASN1_BUFF_NUM_NOT_ENOUGH);
        return CRYPT_DECODE_ASN1_BUFF_NUM_NOT_ENOUGH;
    }

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
    *ealPriKey = pctx;
    return ret;
}

static int32_t ParseRsaPrikeyAsn1Buff(uint8_t *buff, uint32_t buffLen, CRYPT_EAL_PkeyCtx **ealPriKey)
{
    uint8_t *tmpBuff = buff;
    uint32_t tmpBuffLen = buffLen;
    // decode n and e 
    BSL_ASN1_Buffer asn1[CRYPT_RSA_PRV_OTHER_PRIME_IDX + 1] = {0};
    BSL_ASN1_Template templ = {rsaPrvTempl, sizeof(rsaPrvTempl) / sizeof(rsaPrvTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL,
        &tmpBuff, &tmpBuffLen, asn1, CRYPT_RSA_PRV_OTHER_PRIME_IDX + 1);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    return ParseRsaPrikeyAsn1(asn1, CRYPT_RSA_PRV_OTHER_PRIME_IDX + 1, ealPriKey);
}

static int32_t ParsePk8PrikeyAsn1(BSL_ASN1_Buffer *encode, CRYPT_EAL_PkeyCtx **ealPriKey)
{
    BSL_ASN1_Buffer *algo = encode + 1;   // AlgorithmIdentifier
    BSL_ASN1_Buffer *octPriKey = encode + 2; // PrivateKey octet string
    BSL_ASN1_Buffer algoId[BSL_ASN1_TAG_ALGOID_ANY_IDX + 1] = {0};
    int32_t ret = ParseAlgoIdAsn1Buff(algo->buff, algo->len, algoId, BSL_ASN1_TAG_ALGOID_ANY_IDX + 1);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    BSL_Buffer tmpBuff = {0};
    ret = ParseSeqHeaderOnly(octPriKey->buff, octPriKey->len, &tmpBuff);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    if (memcmp(algoId[0].buff, rsaEncryption, algoId[0].len) == 0) {
        return ParseRsaPrikeyAsn1Buff(tmpBuff.data, tmpBuff.dataLen, ealPriKey);
    } else if (memcmp(algoId[0].buff, ecPubKey, algoId[0].len) == 0) {
        return ParseEccPrikeyAsn1Buff(tmpBuff.data, tmpBuff.dataLen, algoId + 1,  ealPriKey);
    }
    return CRYPT_DECODE_UNSUPPORTED_PKCS8_TYPE;
}

static int32_t ParsePk8PriKeyBuff(BSL_Buffer *buff, CRYPT_EAL_PkeyCtx **ealPriKey)
{
    uint8_t *tmpBuff = buff->data;
    uint32_t tmpBuffLen = buff->dataLen;

    BSL_ASN1_Buffer asn1[CRYPT_PK8_PRIKEY_PRIKEY_IDX + 1] = {0};
    BSL_ASN1_Template templ = {pk8PriKeyTempl, sizeof(pk8PriKeyTempl) / sizeof(pk8PriKeyTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL,
        &tmpBuff, &tmpBuffLen, asn1, CRYPT_PK8_PRIKEY_PRIKEY_IDX + 1);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    return ParsePk8PrikeyAsn1(asn1, ealPriKey);
}

static int32_t ParsePk8EncPrikeyAsn1(BSL_ASN1_Buffer *encode, uint32_t encodeLen, CRYPT_EAL_PkeyCtx **ealPriKey)
{
    if (encodeLen < 2) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ASN1_BUFF_NUM_NOT_ENOUGH);
        return CRYPT_DECODE_ASN1_BUFF_NUM_NOT_ENOUGH;
    }

    // TODO: decrypt the private key, to be completed
    int32_t ret = ParsePk8PrikeyAsn1(encode, ealPriKey);
    ret = CRYPT_SUCCESS;
    return ret;
}

static int32_t ParsePk8EncPriKeyBuff(BSL_Buffer *buff, BSL_Buffer *pass, CRYPT_EAL_PkeyCtx **ealPriKey)
{
    (void)pass;

    uint8_t *tmpBuff = buff->data;
    uint32_t tmpBuffLen = buff->dataLen;

    BSL_ASN1_Buffer asn1[CRYPT_PK8_ENCPRIKEY_ENCDATA_IDX + 1] = {0};
    BSL_ASN1_Template templ = {pk8EncPriKeyTempl, sizeof(pk8EncPriKeyTempl) / sizeof(pk8EncPriKeyTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL,
        &tmpBuff, &tmpBuffLen, asn1, CRYPT_PK8_ENCPRIKEY_ENCDATA_IDX + 1);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    return ParsePk8EncPrikeyAsn1(asn1, CRYPT_PK8_ENCPRIKEY_ENCDATA_IDX + 1, ealPriKey);
}

int32_t CRYPT_EAL_PubKeyBuffParse(BSL_ParseFormat format, int32_t type,
    BSL_Buffer *encode, CRYPT_EAL_PkeyCtx **ealPubKey)
{
    (void)format;
    switch (type) {
        case CRYPT_PUBKEY_SUBKEY:
            return ParseSubPubkeyAsn1Buff(encode->data, encode->dataLen, ealPubKey, false);
        case CRYPT_PUBKEY_RSA:
            return ParseRsaPubkeyAsn1Buff(encode->data, encode->dataLen, ealPubKey);
        default:
            return CRYPT_INVALID_ARG;
    }
}

static int32_t ReadFile(const char *path, BSL_Buffer *buff)
{
    size_t readLen;
    size_t fileLen = 0;
    int32_t ret = BSL_SAL_FileLength(path, &fileLen);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    bsl_sal_file_handle stream = NULL;
    ret = BSL_SAL_FileOpen(&stream, path, "rb");
    if (ret != BSL_SUCCESS) {
        return ret;
    }

    uint8_t *fileBuff = BSL_SAL_Malloc(fileLen);
    if (fileBuff == NULL) {
        BSL_SAL_FileClose(stream);
        return BSL_MALLOC_FAIL;
    }
    do {
        ret = BSL_SAL_FileRead(stream, fileBuff, 1, fileLen, &readLen);
        BSL_SAL_FileClose(stream);
        if (ret != BSL_SUCCESS) {
            break;
        }
        
        buff->data = fileBuff;
        buff->dataLen = (uint32_t)fileLen;
        return ret;
    } while (0);
    BSL_SAL_FREE(fileBuff);
    return ret;
}

static int32_t ReadKeyFile(BSL_ParseFormat format, int32_t type, const char *path, BSL_Buffer *buff)
{
    (void)type;
    switch (format) {
        case BSL_PARSE_FORMAT_ASN1:
            return ReadFile(path, buff);
        case BSL_PARSE_FORMAT_UNKNOWN:
        case BSL_PARSE_FORMAT_PEM:
        default:
            return CRYPT_DECODE_UNSUPPORTED_FILE_FORMAT;
    }
}

int32_t CRYPT_EAL_PubKeyFileParse(BSL_ParseFormat format, int32_t type, const char *path,
    CRYPT_EAL_PkeyCtx **ealPubKey)
{
    BSL_Buffer buff = {0};
    int32_t ret = ReadKeyFile(format, type, path, &buff);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    // remove header(seq)
    BSL_Buffer tmp = {0};
    if ((ret = ParseSeqHeaderOnly(buff.data, buff.dataLen, &tmp)) != CRYPT_SUCCESS ||
        (ret = CRYPT_EAL_PubKeyBuffParse(format, type, &tmp, ealPubKey)) != CRYPT_SUCCESS) {
        return ret;
    }
    BSL_SAL_FREE(buff.data);
    return ret;
}

int32_t CRYPT_EAL_PriKeyBuffParse(BSL_ParseFormat format, int32_t type,
    BSL_Buffer *encode, uint8_t *pwd, uint32_t pwdlen, CRYPT_EAL_PkeyCtx **ealPriKey)
{
    (void)format;
    BSL_Buffer pass = {.data=pwd, .dataLen = pwdlen};

    switch (type) {
        case CRYPT_PRIKEY_ECC:
            return ParseEccPrikeyAsn1Buff(encode->data, encode->dataLen, NULL, ealPriKey);
        case CRYPT_PRIKEY_RSA:
            return ParseRsaPrikeyAsn1Buff(encode->data, encode->dataLen, ealPriKey);
        case CRYPT_PRIKEY_PKCS8_UNENCRYPT:
            return ParsePk8PriKeyBuff(encode, ealPriKey);
        case CRYPT_PRIKEY_PKCS8_ENCRYPT:            
            return ParsePk8EncPriKeyBuff(encode, &pass, ealPriKey);
        default:
            return CRYPT_INVALID_ARG;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_PriKeyFileParse(BSL_ParseFormat format, int32_t type, const char *path,
    uint8_t *pwd, uint32_t pwdlen, CRYPT_EAL_PkeyCtx **ealPriKey)
{
    BSL_Buffer buff = {0};
    int32_t ret = ReadKeyFile(format, type, path, &buff);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    BSL_Buffer data = {0};
    ret = ParseSeqHeaderOnly(buff.data, buff.dataLen, &data);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = CRYPT_EAL_PriKeyBuffParse(format, type, &data, pwd, pwdlen, ealPriKey);
    BSL_SAL_FREE(buff.data);
    return ret;
}

#endif // HITLS_CRYPTO_ENCODE
