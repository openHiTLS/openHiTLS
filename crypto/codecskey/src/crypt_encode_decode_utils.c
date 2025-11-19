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
#include <stdint.h>
#include "securec.h"
#include "bsl_types.h"
#include "bsl_asn1.h"
#include "bsl_obj_internal.h"
#include "bsl_err_internal.h"
#include "crypt_params_key.h"
#include "crypt_errno.h"
#include "crypt_encode_decode_key.h"
#include "crypt_encode_decode_local.h"
#include "crypt_eal_kdf.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_rand.h"

#ifdef HITLS_CRYPTO_RSA
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

static BSL_ASN1_TemplateItem g_rsaPrvTempl[] = {
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

/**
 * RSAPublicKey  ::=  SEQUENCE  {
 *        modulus            INTEGER,    -- n
 *        publicExponent     INTEGER  }  -- e
 *
 * https://datatracker.ietf.org/doc/html/rfc4055#autoid-3
 */
static BSL_ASN1_TemplateItem g_rsaPubTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0}, /* ignore seq */
    {BSL_ASN1_TAG_INTEGER, 0, 1}, /* n */
    {BSL_ASN1_TAG_INTEGER, 0, 1}, /* e */
};

#ifdef HITLS_CRYPTO_KEY_DECODE
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
#endif // HITLS_CRYPTO_KEY_DECODE

#endif

#if defined(HITLS_CRYPTO_ECDSA) || defined(HITLS_CRYPTO_SM2)
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

static BSL_ASN1_TemplateItem g_ecPriKeyTempl[] = {
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
#endif

/**
 *  PrivateKeyInfo ::= SEQUENCE {
 *       version                   INTEGER,
 *       privateKeyAlgorithm       AlgorithmIdentifier,
 *       privateKey                OCTET STRING,
 *       attributes           [0]  IMPLICIT Attributes OPTIONAL }
 *
 * https://datatracker.ietf.org/doc/html/rfc5208#autoid-5
*/
static BSL_ASN1_TemplateItem g_pk8PriKeyTempl[] = {
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

#ifdef HITLS_CRYPTO_KEY_EPKI
#ifdef HITLS_CRYPTO_KEY_DECODE
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
#endif

static BSL_ASN1_TemplateItem g_pbkdf2DerParamTempl[] = {
    {BSL_ASN1_TAG_OBJECT_ID, 0, 0}, // derive alg
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
    {BSL_ASN1_TAG_OCTETSTRING, 0, 1}, // salt
    {BSL_ASN1_TAG_INTEGER, 0, 1}, // iteration
    {BSL_ASN1_TAG_INTEGER, BSL_ASN1_FLAG_OPTIONAL, 1}, // keyLen
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_DEFAULT | BSL_ASN1_FLAG_HEADERONLY, 1}, // prf
};
#endif // HITLS_CRYPTO_KEY_EPKI
/**
 * SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *      algorithm         AlgorithmIdentifier,
 *      subjectPublicKey  BIT STRING
 *    }
 *
 * https://datatracker.ietf.org/doc/html/rfc5480#autoid-3
*/
static BSL_ASN1_TemplateItem g_subKeyInfoTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 1},
    {BSL_ASN1_TAG_BITSTRING, 0, 1},
};

static BSL_ASN1_TemplateItem g_subKeyInfoInnerTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 0},
    {BSL_ASN1_TAG_BITSTRING, 0, 0},
};

/**
 * AlgorithmIdentifier  ::=  SEQUENCE  {
 *      algorithm               OBJECT IDENTIFIER,
 *      parameters              ANY DEFINED BY algorithm OPTIONAL  }
 *
 * https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.1.2
*/
static BSL_ASN1_TemplateItem g_algoIdTempl[] = {
    {BSL_ASN1_TAG_OBJECT_ID, 0, 0},
    {BSL_ASN1_TAG_ANY, BSL_ASN1_FLAG_OPTIONAL, 0},
};

#ifdef HITLS_CRYPTO_KEY_EPKI
typedef enum {
    CRYPT_PKCS_ENC_DERALG_IDX,
    CRYPT_PKCS_ENC_DERSALT_IDX,
    CRYPT_PKCS_ENC_DERITER_IDX,
    CRYPT_PKCS_ENC_DERKEYLEN_IDX,
    CRYPT_PKCS_ENC_DERPRF_IDX,
    CRYPT_PKCS_ENC_DERPARAM_MAX
} CRYPT_PKCS_ENC_DERIVEPARAM_IDX;

static int32_t CRYPT_ENCODE_DECODE_DecryptEncData(CRYPT_EAL_LibCtx *libctx, const char *attrName, BSL_Buffer *ivData,
    BSL_Buffer *enData, int32_t alg, bool isEnc, BSL_Buffer *key, uint8_t *output, uint32_t *dataLen)
{
    uint32_t buffLen = *dataLen;
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_ProviderCipherNewCtx(libctx, alg, attrName);
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    int32_t ret = CRYPT_EAL_CipherInit(ctx, key->data, key->dataLen, ivData->data, ivData->dataLen, isEnc);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    uint32_t blockSize;
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_BLOCKSIZE, &blockSize, sizeof(blockSize));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    if (blockSize != 1) {
        ret = CRYPT_EAL_CipherSetPadding(ctx, CRYPT_PADDING_PKCS7);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }
    }
    ret = CRYPT_EAL_CipherUpdate(ctx, enData->data, enData->dataLen, output, dataLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    buffLen -= *dataLen;
    ret = CRYPT_EAL_CipherFinal(ctx, output + *dataLen, &buffLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    *dataLen += buffLen;
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
    return ret;
}

static int32_t PbkdfDeriveKey(CRYPT_EAL_LibCtx *libctx, const char *attrName, uint32_t iter, int32_t prfId,
    BSL_Buffer *salt, const uint8_t *pwd, uint32_t pwdLen, BSL_Buffer *key)
{
    CRYPT_EAL_KdfCTX *kdfCtx = CRYPT_EAL_ProviderKdfNewCtx(libctx, CRYPT_KDF_PBKDF2, attrName);
    if (kdfCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_PBKDF2_NOT_SUPPORTED);
        return CRYPT_PBKDF2_NOT_SUPPORTED;
    }

    BSL_Param params[5] = {{0}, {0}, {0}, {0}, BSL_PARAM_END};
    (void)BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, &prfId, sizeof(prfId));
    (void)BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_PASSWORD, BSL_PARAM_TYPE_OCTETS,
        (uint8_t *)(uintptr_t)pwd, pwdLen); // Fixed pwd parameter
    (void)BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS, salt->data, salt->dataLen);
    (void)BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_ITER, BSL_PARAM_TYPE_UINT32, &iter, sizeof(iter));
    int32_t ret = CRYPT_EAL_KdfSetParam(kdfCtx, params);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = CRYPT_EAL_KdfDerive(kdfCtx, key->data, key->dataLen);
EXIT:
    CRYPT_EAL_KdfFreeCtx(kdfCtx);
    return ret;
}
#endif // HITLS_CRYPTO_EPKI
#ifdef HITLS_CRYPTO_KEY_DECODE

#if defined(HITLS_CRYPTO_ECDSA) || defined(HITLS_CRYPTO_SM2)
int32_t CRYPT_DECODE_PrikeyAsn1Buff(uint8_t *buffer, uint32_t bufferLen, BSL_ASN1_Buffer *asn1, uint32_t arrNum)
{
    uint8_t *tmpBuff = buffer;
    uint32_t tmpBuffLen = bufferLen;
    BSL_ASN1_Template templ = {g_ecPriKeyTempl, sizeof(g_ecPriKeyTempl) / sizeof(g_ecPriKeyTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &tmpBuff, &tmpBuffLen, asn1, arrNum);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}
#endif

#ifdef HITLS_CRYPTO_RSA
int32_t CRYPT_DECODE_RsaPubkeyAsn1Buff(uint8_t *buff, uint32_t buffLen, BSL_ASN1_Buffer *pubAsn1, uint32_t arrNum)
{
    if (buff == NULL || pubAsn1 == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    uint8_t *tmpBuff = buff;
    uint32_t tmpBuffLen = buffLen;
    
    BSL_ASN1_Template pubTempl = {g_rsaPubTempl, sizeof(g_rsaPubTempl) / sizeof(g_rsaPubTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&pubTempl, NULL, &tmpBuff, &tmpBuffLen, pubAsn1, arrNum);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }

    return ret;
}

int32_t CRYPT_DECODE_RsaPrikeyAsn1Buff(uint8_t *buff, uint32_t buffLen, BSL_ASN1_Buffer *asn1, uint32_t asn1Num)
{
    uint8_t *tmpBuff = buff;
    uint32_t tmpBuffLen = buffLen;

    BSL_ASN1_Template templ = {g_rsaPrvTempl, sizeof(g_rsaPrvTempl) / sizeof(g_rsaPrvTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &tmpBuff, &tmpBuffLen, asn1, asn1Num);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t RsaPssTagGetOrCheck(int32_t type, uint32_t idx, void *data, void *expVal)
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
        para->mdId = (CRYPT_MD_AlgId)BSL_OBJ_GetCID(&hashOid);
        if (para->mdId == (CRYPT_MD_AlgId)BSL_CID_UNKNOWN) {
            BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ERR_RSSPSS_MD);
            return CRYPT_DECODE_ERR_RSSPSS_MD;
        }
    }
    if (asns[CRYPT_RSAPSS_MGF1PARAM_IDX].tag != 0) {
        BslOidString mgf1 = {asns[CRYPT_RSAPSS_MGF1PARAM_IDX].len, (char *)asns[CRYPT_RSAPSS_MGF1PARAM_IDX].buff, 0};
        para->mgfId = (CRYPT_MD_AlgId)BSL_OBJ_GetCID(&mgf1);
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
#endif

static int32_t DecSubKeyInfoCb(int32_t type, uint32_t idx, void *data, void *expVal)
{
    (void)idx;
    BSL_ASN1_Buffer *param = (BSL_ASN1_Buffer *)data;

    switch (type) {
        case BSL_ASN1_TYPE_GET_ANY_TAG: {
            BslOidString oidStr = {param->len, (char *)param->buff, 0};
            BslCid cid = BSL_OBJ_GetCID(&oidStr);
            if (cid == BSL_CID_EC_PUBLICKEY || cid == BSL_CID_SM2PRIME256) {
                // note: any It can be encoded empty or it can be null
                *(uint8_t *)expVal = BSL_ASN1_TAG_OBJECT_ID;
            } else if (cid == BSL_CID_RSASSAPSS) {
                *(uint8_t *)expVal = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
            } else if (cid == BSL_CID_ED25519) {
                /* RFC8410: Ed25519 has no algorithm parameters */
                *(uint8_t *)expVal = BSL_ASN1_TAG_EMPTY; // is empty
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

int32_t CRYPT_DECODE_ParseSubKeyInfo(uint8_t *buff, uint32_t buffLen, BSL_ASN1_Buffer *pubAsn1, bool isComplete)
{
    uint8_t *tmpBuff = buff;
    uint32_t tmpBuffLen = buffLen;
    // decode sub pubkey info
    BSL_ASN1_Template pubTempl;
    if (isComplete) {
        pubTempl.templItems = g_subKeyInfoTempl;
        pubTempl.templNum = sizeof(g_subKeyInfoTempl) / sizeof(g_subKeyInfoTempl[0]);
    } else {
        pubTempl.templItems = g_subKeyInfoInnerTempl;
        pubTempl.templNum = sizeof(g_subKeyInfoInnerTempl) / sizeof(g_subKeyInfoInnerTempl[0]);
    }
    int32_t ret = BSL_ASN1_DecodeTemplate(&pubTempl, DecSubKeyInfoCb, &tmpBuff, &tmpBuffLen, pubAsn1,
                                          CRYPT_SUBKEYINFO_BITSTRING_IDX + 1);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t CRYPT_DECODE_AlgoIdAsn1Buff(uint8_t *buff, uint32_t buffLen, BSL_ASN1_DecTemplCallBack keyInfoCb,
    BSL_ASN1_Buffer *algoId, uint32_t algoIdNum)
{
    uint8_t *tmpBuff = buff;
    uint32_t tmpBuffLen = buffLen;
    BSL_ASN1_DecTemplCallBack cb = keyInfoCb == NULL ? DecSubKeyInfoCb : keyInfoCb;
    BSL_ASN1_Template templ = {g_algoIdTempl, sizeof(g_algoIdTempl) / sizeof(g_algoIdTempl[0])};
    return BSL_ASN1_DecodeTemplate(&templ, cb, &tmpBuff, &tmpBuffLen, algoId, algoIdNum);
}

int32_t CRYPT_DECODE_SubPubkey(uint8_t *buff, uint32_t buffLen, BSL_ASN1_DecTemplCallBack keyInfoCb,
    CRYPT_DECODE_SubPubkeyInfo *subPubkeyInfo, bool isComplete)
{
    if (buff == NULL || subPubkeyInfo == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    BSL_ASN1_Buffer pubAsn1[CRYPT_SUBKEYINFO_BITSTRING_IDX + 1] = {0};
    BSL_ASN1_BitString bitPubkey = {0};
    BSL_ASN1_Buffer algoId[BSL_ASN1_TAG_ALGOID_ANY_IDX + 1] = {0};
    int32_t ret = CRYPT_DECODE_ParseSubKeyInfo(buff, buffLen, pubAsn1, isComplete);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CRYPT_DECODE_AlgoIdAsn1Buff(pubAsn1->buff, pubAsn1->len, keyInfoCb, algoId, BSL_ASN1_TAG_ALGOID_ANY_IDX + 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_ASN1_Buffer *oid = algoId;
    BSL_ASN1_Buffer *pubkey = &pubAsn1[CRYPT_SUBKEYINFO_BITSTRING_IDX];
    ret = BSL_ASN1_DecodePrimitiveItem(pubkey, &bitPubkey);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BslOidString oidStr = {oid->len, (char *)oid->buff, 0};
    BslCid cid = BSL_OBJ_GetCID(&oidStr);
    if (cid == BSL_CID_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_UNKNOWN_OID);
        return CRYPT_DECODE_UNKNOWN_OID;
    }
    subPubkeyInfo->keyType = cid;
    subPubkeyInfo->keyParam = *(algoId + 1);
    subPubkeyInfo->pubKey = bitPubkey;
    return CRYPT_SUCCESS;
}

static int32_t ParsePk8PriParamAsn1(BSL_ASN1_Buffer *encode, BSL_ASN1_DecTemplCallBack keyInfoCb, BslCid *keyType,
    BSL_ASN1_Buffer *keyParam)
{
    BSL_ASN1_Buffer *algo = &encode[CRYPT_PK8_PRIKEY_ALGID_IDX]; // AlgorithmIdentifier
    BSL_ASN1_Buffer algoId[BSL_ASN1_TAG_ALGOID_ANY_IDX + 1] = {0};
    int32_t ret = CRYPT_DECODE_AlgoIdAsn1Buff(algo->buff, algo->len, keyInfoCb,
        algoId, BSL_ASN1_TAG_ALGOID_ANY_IDX + 1);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    BslOidString oidStr = {algoId[0].len, (char *)algoId[0].buff, 0};
    BslCid cid = BSL_OBJ_GetCID(&oidStr);
    if (cid == BSL_CID_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_UNKNOWN_OID);
        return CRYPT_DECODE_UNKNOWN_OID;
    }

    *keyType = cid;
    *keyParam = *(algoId + 1);

    return CRYPT_SUCCESS;
}

int32_t CRYPT_DECODE_Pkcs8Info(uint8_t *buff, uint32_t buffLen, BSL_ASN1_DecTemplCallBack keyInfoCb,
    CRYPT_ENCODE_DECODE_Pk8PrikeyInfo *pk8PrikeyInfo)
{
    if (buff == NULL || buffLen == 0 || pk8PrikeyInfo == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    uint8_t *tmpBuff = buff;
    uint32_t tmpBuffLen = buffLen;
    int32_t version = 0;
    BslCid keyType = BSL_CID_UNKNOWN;
    BSL_ASN1_Buffer keyParam = {0};
    BSL_ASN1_Buffer asn1[CRYPT_PK8_PRIKEY_PRIKEY_IDX + 1] = {0};
    BSL_ASN1_Template templ = {g_pk8PriKeyTempl, sizeof(g_pk8PriKeyTempl) / sizeof(g_pk8PriKeyTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &tmpBuff, &tmpBuffLen, asn1, CRYPT_PK8_PRIKEY_PRIKEY_IDX + 1);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BSL_ASN1_DecodePrimitiveItem(&asn1[CRYPT_PK8_PRIKEY_VERSION_IDX], &version);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_ASN1_Buffer octPriKey = asn1[CRYPT_PK8_PRIKEY_PRIKEY_IDX];
    ret = ParsePk8PriParamAsn1(asn1, keyInfoCb, &keyType, &keyParam);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    pk8PrikeyInfo->version = version;
    pk8PrikeyInfo->keyType = keyType;
    pk8PrikeyInfo->pkeyRawKey = octPriKey.buff;
    pk8PrikeyInfo->pkeyRawKeyLen = octPriKey.len;
    pk8PrikeyInfo->keyParam = keyParam;
    pk8PrikeyInfo->attrs = NULL;

    return CRYPT_SUCCESS;
}

#ifdef HITLS_CRYPTO_KEY_EPKI
static int32_t ParseDeriveKeyPrfAlgId(BSL_ASN1_Buffer *asn, int32_t *prfId, BSL_ASN1_DecTemplCallBack keyInfoCb)
{
    if (asn->len != 0) {
        BSL_ASN1_Buffer algoId[2] = {0};
        int32_t ret = CRYPT_DECODE_AlgoIdAsn1Buff(asn->buff, asn->len, keyInfoCb, algoId, 2);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        BslOidString oidStr = {algoId[BSL_ASN1_TAG_ALGOID_IDX].len,
            (char *)algoId[BSL_ASN1_TAG_ALGOID_IDX].buff, 0};
        *prfId = BSL_OBJ_GetCID(&oidStr);
        if (*prfId == BSL_CID_UNKNOWN) {
            BSL_ERR_PUSH_ERROR(CRYPT_DECODE_PKCS8_INVALID_ALGO_PARAM);
            return CRYPT_DECODE_PKCS8_INVALID_ALGO_PARAM;
        }
    } else {
        *prfId = BSL_CID_HMAC_SHA1;
    }
    return CRYPT_SUCCESS;
}

static int32_t ParseDeriveKeyParam(BSL_Buffer *derivekeyData, uint32_t *iter, uint32_t *keyLen, BSL_Buffer *salt,
    int32_t *prfId, BSL_ASN1_DecTemplCallBack keyInfoCb)
{
    uint8_t *tmpBuff = derivekeyData->data;
    uint32_t tmpBuffLen = derivekeyData->dataLen;
    BSL_ASN1_Buffer derParam[CRYPT_PKCS_ENC_DERPARAM_MAX] = {0};
    BSL_ASN1_Template templ = {g_pbkdf2DerParamTempl, sizeof(g_pbkdf2DerParamTempl) / sizeof(g_pbkdf2DerParamTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL,
        &tmpBuff, &tmpBuffLen, derParam, CRYPT_PKCS_ENC_DERPARAM_MAX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BslOidString oidStr = {derParam[CRYPT_PKCS_ENC_DERALG_IDX].len,
        (char *)derParam[CRYPT_PKCS_ENC_DERALG_IDX].buff, 0};
    BslCid cid = BSL_OBJ_GetCID(&oidStr);
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
    return ParseDeriveKeyPrfAlgId(&derParam[CRYPT_PKCS_ENC_DERPRF_IDX], prfId, keyInfoCb);
}

int32_t CRYPT_DECODE_ParseEncDataAsn1(CRYPT_EAL_LibCtx *libctx, const char *attrName, BslCid symAlg,
    EncryptPara *encPara, const BSL_Buffer *pwd, BSL_ASN1_DecTemplCallBack keyInfoCb, BSL_Buffer *decode)
{
    uint32_t iter;
    int32_t prfId;
    uint32_t keylen = 0;
    uint8_t key[512] = {0}; // The maximum length of the symmetry algorithm
    BSL_Buffer salt = {0};
    int32_t ret = ParseDeriveKeyParam(encPara->derivekeyData, &iter, &keylen, &salt, &prfId, keyInfoCb);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint32_t symKeyLen;
    ret = CRYPT_EAL_CipherGetInfo((CRYPT_CIPHER_AlgId)symAlg, CRYPT_INFO_KEY_LEN, &symKeyLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (keylen != 0 && symKeyLen != keylen) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_PKCS8_INVALID_KEYLEN);
        return CRYPT_DECODE_PKCS8_INVALID_KEYLEN;
    }
    BSL_Buffer keyBuff = {key, symKeyLen};

    ret = PbkdfDeriveKey(libctx, attrName, iter, prfId, &salt, pwd->data, pwd->dataLen, &keyBuff);
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
        ret = CRYPT_ENCODE_DECODE_DecryptEncData(libctx, attrName, encPara->ivData, encPara->enData, symAlg, false,
            &keyBuff, output, &dataLen);
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

int32_t CRYPT_DECODE_Pkcs8PrvDecrypt(CRYPT_EAL_LibCtx *libctx, const char *attrName, BSL_Buffer *buff,
    const BSL_Buffer *pwd, BSL_ASN1_DecTemplCallBack keyInfoCb, BSL_Buffer *decode)
{
    if (buff == NULL || buff->dataLen == 0 || pwd == NULL || decode == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pwd->dataLen > PWD_MAX_LEN || (pwd->data == NULL && pwd->dataLen != 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    uint8_t *tmpBuff = buff->data;
    uint32_t tmpBuffLen = buff->dataLen;

    BSL_ASN1_Buffer asn1[CRYPT_PKCS_ENCPRIKEY_MAX] = {0};
    BSL_ASN1_Template templ = {g_pk8EncPriKeyTempl, sizeof(g_pk8EncPriKeyTempl) / sizeof(g_pk8EncPriKeyTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &tmpBuff, &tmpBuffLen, asn1, CRYPT_PKCS_ENCPRIKEY_MAX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    BslOidString encOidStr = {asn1[CRYPT_PKCS_ENCPRIKEY_ENCALG_IDX].len,
        (char *)asn1[CRYPT_PKCS_ENCPRIKEY_ENCALG_IDX].buff, 0};
    BslCid cid = BSL_OBJ_GetCID(&encOidStr);
    if (cid != BSL_CID_PBES2) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_UNKNOWN_OID);
        return CRYPT_DECODE_UNKNOWN_OID;
    }
    // parse sym alg id
    BslOidString symOidStr = {asn1[CRYPT_PKCS_ENCPRIKEY_SYMALG_IDX].len,
        (char *)asn1[CRYPT_PKCS_ENCPRIKEY_SYMALG_IDX].buff, 0};
    BslCid symId = BSL_OBJ_GetCID(&symOidStr);
    if (symId == BSL_CID_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_UNKNOWN_OID);
        return CRYPT_DECODE_UNKNOWN_OID;
    }

    BSL_Buffer derivekeyData = {asn1[CRYPT_PKCS_ENCPRIKEY_DERPARAM_IDX].buff,
        asn1[CRYPT_PKCS_ENCPRIKEY_DERPARAM_IDX].len};
    BSL_Buffer ivData = {asn1[CRYPT_PKCS_ENCPRIKEY_SYMIV_IDX].buff, asn1[CRYPT_PKCS_ENCPRIKEY_SYMIV_IDX].len};
    BSL_Buffer enData = {asn1[CRYPT_PKCS_ENCPRIKEY_ENCDATA_IDX].buff, asn1[CRYPT_PKCS_ENCPRIKEY_ENCDATA_IDX].len};
    EncryptPara encPara = {
        .derivekeyData = &derivekeyData,
        .ivData = &ivData,
        .enData = &enData,
    };
    ret = CRYPT_DECODE_ParseEncDataAsn1(libctx, attrName, symId, &encPara, pwd, keyInfoCb, decode);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}
#endif /* HITLS_CRYPTO_KEY_EPKI */

int32_t CRYPT_DECODE_ConstructBufferOutParam(const BSL_Param *inParam, BSL_Param **outParam, uint8_t *buffer,
    uint32_t bufferLen)
{
    uint32_t count = 2;
    const BSL_Param *encParam = BSL_PARAM_FindConstParam(inParam, CRYPT_PARAM_DECODE_PASSWORD);
    if (encParam != NULL) {
        count++;
    }
    BSL_Param *result = BSL_SAL_Calloc(count, sizeof(BSL_Param));
    if (result == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = BSL_PARAM_InitValue(&result[0], CRYPT_PARAM_DECODE_BUFFER_DATA, BSL_PARAM_TYPE_OCTETS,
        buffer, bufferLen);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_Free(result);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (encParam != NULL) {
        ret = BSL_PARAM_InitValue(&result[1], encParam->key, encParam->valueType, encParam->value, encParam->valueLen);
        if (ret != BSL_SUCCESS) {
            BSL_SAL_Free(result);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    *outParam = result;
    return ret;
}
#endif  /* HITLS_CRYPTO_KEY_DECODE */

#ifdef HITLS_CRYPTO_KEY_ENCODE

#if defined(HITLS_CRYPTO_ECDSA) || defined(HITLS_CRYPTO_SM2)
int32_t CRYPT_ENCODE_EccPrikeyAsn1Buff(BSL_ASN1_Buffer *asn1, uint32_t asn1Num, BSL_Buffer *encode)
{
    BSL_ASN1_Template templ = {g_ecPriKeyTempl, sizeof(g_ecPriKeyTempl) / sizeof(g_ecPriKeyTempl[0])};
    return BSL_ASN1_EncodeTemplate(&templ, asn1, asn1Num, &encode->data, &encode->dataLen);
}
#endif /* HITLS_CRYPTO_ECDSA || HITLS_CRYPTO_SM2 */

#ifdef HITLS_CRYPTO_RSA
int32_t CRYPT_ENCODE_RsaPubkeyAsn1Buff(BSL_ASN1_Buffer *pubAsn1, BSL_Buffer *encodePub)
{
    BSL_ASN1_Template pubTempl = {g_rsaPubTempl, sizeof(g_rsaPubTempl) / sizeof(g_rsaPubTempl[0])};
    int32_t ret = BSL_ASN1_EncodeTemplate(&pubTempl, pubAsn1, CRYPT_RSA_PUB_E_IDX + 1,
        &encodePub->data, &encodePub->dataLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t CRYPT_ENCODE_RsaPrikeyAsn1Buff(BSL_ASN1_Buffer *asn1, uint32_t asn1Num, BSL_Buffer *encode)
{
    BSL_ASN1_Template templ = {g_rsaPrvTempl, sizeof(g_rsaPrvTempl) / sizeof(g_rsaPrvTempl[0])};
    int32_t ret = BSL_ASN1_EncodeTemplate(&templ, asn1, asn1Num, &encode->data, &encode->dataLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

#endif

int32_t CRYPT_ENCODE_SubPubkeyByInfo(BSL_ASN1_Buffer *algo, BSL_Buffer *bitStr, BSL_Buffer *encodeH,
    bool isComplete)
{
    BSL_ASN1_Buffer encode[CRYPT_SUBKEYINFO_BITSTRING_IDX + 1] = {0};
    encode[CRYPT_SUBKEYINFO_ALGOID_IDX].buff = algo->buff;
    encode[CRYPT_SUBKEYINFO_ALGOID_IDX].len = algo->len;
    encode[CRYPT_SUBKEYINFO_ALGOID_IDX].tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
    BSL_ASN1_BitString bitPubkey = {bitStr->data, bitStr->dataLen, 0};
    encode[CRYPT_SUBKEYINFO_BITSTRING_IDX].buff = (uint8_t *)&bitPubkey;
    encode[CRYPT_SUBKEYINFO_BITSTRING_IDX].len = sizeof(BSL_ASN1_BitString);
    encode[CRYPT_SUBKEYINFO_BITSTRING_IDX].tag = BSL_ASN1_TAG_BITSTRING;

    BSL_ASN1_Template pubTempl;
    if (isComplete) {
        pubTempl.templItems = g_subKeyInfoTempl;
        pubTempl.templNum = sizeof(g_subKeyInfoTempl) / sizeof(g_subKeyInfoTempl[0]);
    } else {
        pubTempl.templItems = g_subKeyInfoInnerTempl;
        pubTempl.templNum = sizeof(g_subKeyInfoInnerTempl) / sizeof(g_subKeyInfoInnerTempl[0]);
    }
    int32_t ret =  BSL_ASN1_EncodeTemplate(&pubTempl,
        encode, CRYPT_SUBKEYINFO_BITSTRING_IDX + 1, &encodeH->data, &encodeH->dataLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}


int32_t CRYPT_ENCODE_AlgoIdAsn1Buff(BSL_ASN1_Buffer *algoId, uint32_t algoIdNum, uint8_t **buff,
    uint32_t *buffLen)
{
    BSL_ASN1_Template templ = {g_algoIdTempl, sizeof(g_algoIdTempl) / sizeof(g_algoIdTempl[0])};
    return BSL_ASN1_EncodeTemplate(&templ, algoId, algoIdNum, buff, buffLen);
}

#ifdef HITLS_CRYPTO_KEY_EPKI
static int32_t EncodeDeriveKeyParam(CRYPT_EAL_LibCtx *libCtx, CRYPT_Pbkdf2Param *param, BSL_Buffer *encode,
    BSL_Buffer *salt)
{
    BSL_ASN1_Buffer derParam[CRYPT_PKCS_ENC_DERPRF_IDX + 1] = {0};
    /* deralg */
    BslOidString *oidPbkdf = BSL_OBJ_GetOID((BslCid)param->pbkdfId);
    if (oidPbkdf == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ERR_ALGID);
        return CRYPT_ERR_ALGID;
    }
    derParam[CRYPT_PKCS_ENC_DERALG_IDX].buff = (uint8_t *)oidPbkdf->octs;
    derParam[CRYPT_PKCS_ENC_DERALG_IDX].len = oidPbkdf->octetLen;
    derParam[CRYPT_PKCS_ENC_DERALG_IDX].tag = BSL_ASN1_TAG_OBJECT_ID;
    /* salt */
    int32_t ret = CRYPT_EAL_RandbytesEx(libCtx, salt->data, salt->dataLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    derParam[CRYPT_PKCS_ENC_DERSALT_IDX].buff = salt->data;
    derParam[CRYPT_PKCS_ENC_DERSALT_IDX].len = salt->dataLen;
    derParam[CRYPT_PKCS_ENC_DERSALT_IDX].tag = BSL_ASN1_TAG_OCTETSTRING;
    /* iter */
    ret = BSL_ASN1_EncodeLimb(BSL_ASN1_TAG_INTEGER, param->itCnt, &derParam[CRYPT_PKCS_ENC_DERITER_IDX]);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_ASN1_Template templ = {g_pbkdf2DerParamTempl, sizeof(g_pbkdf2DerParamTempl) / sizeof(g_pbkdf2DerParamTempl[0])};
    if (param->hmacId == CRYPT_MAC_HMAC_SHA1) {
        ret = BSL_ASN1_EncodeTemplate(&templ, derParam, CRYPT_PKCS_ENC_DERPRF_IDX + 1, &encode->data, &encode->dataLen);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
        }
        BSL_SAL_FREE(derParam[CRYPT_PKCS_ENC_DERITER_IDX].buff);
        return ret;
    }
    BslOidString *oidHmac = BSL_OBJ_GetOID((BslCid)param->hmacId);
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
    ret = CRYPT_ENCODE_AlgoIdAsn1Buff(algoId, BSL_ASN1_TAG_ALGOID_ANY_IDX + 1, &algo.data, &algo.dataLen);
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

static int32_t EncodeEncryptedData(CRYPT_EAL_LibCtx *libCtx, const char *attrName, CRYPT_Pbkdf2Param *pkcsParam,
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

        ret = PbkdfDeriveKey(libCtx, attrName, pkcsParam->itCnt, pkcsParam->hmacId, salt,
            pkcsParam->pwd, pkcsParam->pwdLen, &keyBuff);
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
        ret = CRYPT_ENCODE_DECODE_DecryptEncData(libCtx, attrName, &ivData, &enData,
            (int32_t)pkcsParam->symId, true, &keyBuff, output, &pkcsDataLen);
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

static int32_t GenRandIv(CRYPT_EAL_LibCtx *libCtx, CRYPT_Pbkdf2Param *pkcsParam, BSL_ASN1_Buffer *asn1)
{
    int32_t ret;
    BslOidString *oidSym = BSL_OBJ_GetOID((BslCid)pkcsParam->symId);
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
    ret = CRYPT_EAL_RandbytesEx(libCtx, iv, ivLen);
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

int32_t CRYPT_ENCODE_PkcsEncryptedBuff(CRYPT_EAL_LibCtx *libCtx, const char *attrName,
    CRYPT_Pbkdf2Param *pkcsParam, BSL_Buffer *unEncrypted, BSL_ASN1_Buffer *asn1)
{
    int32_t ret;
    BslOidString *oidPbes = BSL_OBJ_GetOID((BslCid)pkcsParam->pbesId);
    if (oidPbes == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ERR_ALGID);
        return CRYPT_ERR_ALGID;
    }
    /* derivation param */
    BSL_Buffer derParam = {0};
    uint8_t *saltData = (uint8_t *)BSL_SAL_Malloc(pkcsParam->saltLen);
    if (saltData == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    do {
        BSL_Buffer salt = {saltData, pkcsParam->saltLen};
        ret = EncodeDeriveKeyParam(libCtx, pkcsParam, &derParam, &salt);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            break;
        }
        asn1[CRYPT_PKCS_ENCPRIKEY_DERPARAM_IDX].buff = derParam.data;
        asn1[CRYPT_PKCS_ENCPRIKEY_DERPARAM_IDX].len = derParam.dataLen;
        asn1[CRYPT_PKCS_ENCPRIKEY_DERPARAM_IDX].tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
        /* iv */
        ret = GenRandIv(libCtx, pkcsParam, asn1);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            break;
        }
        /* encryptedData */
        ret = EncodeEncryptedData(libCtx, attrName, pkcsParam, unEncrypted, &salt, asn1);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            break;
        }
        BSL_SAL_ClearFree(saltData, pkcsParam->saltLen);
        asn1[CRYPT_PKCS_ENCPRIKEY_ENCALG_IDX].buff = (uint8_t *)oidPbes->octs;
        asn1[CRYPT_PKCS_ENCPRIKEY_ENCALG_IDX].len = oidPbes->octetLen;
        asn1[CRYPT_PKCS_ENCPRIKEY_ENCALG_IDX].tag = BSL_ASN1_TAG_OBJECT_ID;
        return CRYPT_SUCCESS;
    } while (0);
    BSL_SAL_ClearFree(saltData, pkcsParam->saltLen);
    BSL_SAL_ClearFree(asn1[CRYPT_PKCS_ENCPRIKEY_DERPARAM_IDX].buff, asn1[CRYPT_PKCS_ENCPRIKEY_DERPARAM_IDX].len);
    BSL_SAL_ClearFree(asn1[CRYPT_PKCS_ENCPRIKEY_SYMIV_IDX].buff, asn1[CRYPT_PKCS_ENCPRIKEY_SYMIV_IDX].len);
    return ret;
}
#endif // HITLS_CRYPTO_KEY_EPKI

int32_t CRYPT_ENCODE_Pkcs8Info(CRYPT_ENCODE_DECODE_Pk8PrikeyInfo *pk8PrikeyInfo, BSL_Buffer *asn1)
{
    if (pk8PrikeyInfo == NULL || asn1 == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    int32_t ret;
    BSL_ASN1_Buffer algo = {0};
    BSL_ASN1_Buffer algoId[BSL_ASN1_TAG_ALGOID_ANY_IDX + 1] = {0};
    do {
        BslOidString *oidStr = BSL_OBJ_GetOID((BslCid)pk8PrikeyInfo->keyType);
        if (oidStr == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_ERR_ALGID);
            ret = CRYPT_ERR_ALGID;
            break;
        }
        algoId[BSL_ASN1_TAG_ALGOID_IDX].buff = (uint8_t *)oidStr->octs;
        algoId[BSL_ASN1_TAG_ALGOID_IDX].len = oidStr->octetLen;
        algoId[BSL_ASN1_TAG_ALGOID_IDX].tag = BSL_ASN1_TAG_OBJECT_ID;
        algoId[BSL_ASN1_TAG_ALGOID_ANY_IDX] = pk8PrikeyInfo->keyParam;
        ret = CRYPT_ENCODE_AlgoIdAsn1Buff(algoId, BSL_ASN1_TAG_ALGOID_ANY_IDX + 1, &algo.buff, &algo.len);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            break;
        }

        BSL_ASN1_Buffer encode[CRYPT_PK8_PRIKEY_PRIKEY_IDX + 1] = {
            {BSL_ASN1_TAG_INTEGER, sizeof(pk8PrikeyInfo->version), (uint8_t *)&pk8PrikeyInfo->version},
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, algo.len, algo.buff},
            {BSL_ASN1_TAG_OCTETSTRING, pk8PrikeyInfo->pkeyRawKeyLen, pk8PrikeyInfo->pkeyRawKey}
        };
        BSL_ASN1_Template pubTempl = {g_pk8PriKeyTempl, sizeof(g_pk8PriKeyTempl) / sizeof(g_pk8PriKeyTempl[0])};
        ret =  BSL_ASN1_EncodeTemplate(&pubTempl, encode, CRYPT_PK8_PRIKEY_PRIKEY_IDX + 1, &asn1->data, &asn1->dataLen);
    } while (0);

    BSL_SAL_ClearFree(algo.buff, algo.len);
    return ret;
}

#endif /* HITLS_CRYPTO_KEY_ENCODE */
#endif /* HITLS_CRYPTO_CODECSKEY */
