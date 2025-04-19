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
#ifdef HITLS_CRYPTO_ENCODE_DECODE

#include "securec.h"
#include "bsl_asn1.h"
#include "bsl_params.h"
#include "bsl_err_internal.h"
#include "bsl_obj_internal.h"
#include "crypt_errno.h"
#include "crypt_algid.h"
#include "crypt_eal_kdf.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_cipher.h"
#include "crypt_params_key.h"
#include "crypt_encode_decode.h"
#include "crypt_encode_decode_local.h"

#define PWD_MAX_LEN 4096

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
static BSL_ASN1_TemplateItem g_subKeyInfoTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 1},
        {BSL_ASN1_TAG_BITSTRING, 0, 1},
};

static BSL_ASN1_TemplateItem g_subKeyInfoInnerTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 0},
    {BSL_ASN1_TAG_BITSTRING, 0, 0},
};

typedef enum {
    CRYPT_SUBKEYINFO_ALGOID_IDX = 0,
    CRYPT_SUBKEYINFO_BITSTRING_IDX = 1,
} CRYPT_SUBKEYINFO_TEMPL_IDX;

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

typedef enum {
    CRYPT_ECPRIKEY_VERSION_IDX = 0,
    CRYPT_ECPRIKEY_PRIKEY_IDX = 1,
    CRYPT_ECPRIKEY_PARAM_IDX = 2,
    CRYPT_ECPRIKEY_PUBKEY_IDX = 3,
} CRYPT_ECPRIKEY_TEMPL_IDX;
#endif

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

typedef enum {
    CRYPT_RSA_PUB_N_IDX = 0,
    CRYPT_RSA_PUB_E_IDX = 1,
} CRYPT_RSA_PUB_TEMPL_IDX;

#define CRYPT_ASN1_CTX_SPECIFIC_TAG_RSAPSS_HASH    0
#define CRYPT_ASN1_CTX_SPECIFIC_TAG_RSAPSS_MASKGEN 1
#define CRYPT_ASN1_CTX_SPECIFIC_TAG_RSAPSS_SALTLEN 2
#define CRYPT_ASN1_CTX_SPECIFIC_TAG_RSAPSS_TRAILED 3
#endif // HITLS_CRYPTO_RSA

#ifdef HITLS_CRYPTO_KEY_EPKI
static int32_t DecryptEncData(CRYPT_EAL_LibCtx *libctx, const char *attrName, BSL_Buffer *ivData, BSL_Buffer *enData,
    int32_t alg, bool isEnc, BSL_Buffer *key, uint8_t *output, uint32_t *dataLen)
{
    uint32_t buffLen = *dataLen;
#ifdef HITLS_CRYPTO_PROVIDER
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_ProviderCipherNewCtx(libctx, alg, attrName);
#else
    (void)libctx;
    (void)attrName;
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(alg);
#endif
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

static int32_t PbkdfDeriveKey(CRYPT_EAL_LibCtx *libctx, const char *attrName, int32_t iter, int32_t prfId,
    BSL_Buffer *salt, const uint8_t *pwd, uint32_t pwdLen, BSL_Buffer *key)
{
#ifdef HITLS_CRYPTO_PROVIDER
    CRYPT_EAL_KdfCTX *kdfCtx = CRYPT_EAL_ProviderKdfNewCtx(libctx, CRYPT_KDF_PBKDF2, attrName);
#else
    (void)libctx;
    (void)attrName;
    CRYPT_EAL_KdfCTX *kdfCtx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_PBKDF2);
#endif
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
#endif

#ifdef HITLS_CRYPTO_KEY_DECODE
static inline CRYPT_EAL_PkeyCtx *GetPkeyCtx(CRYPT_EAL_LibCtx *libctx, const char *attrName, int32_t alg)
{
#ifdef HITLS_CRYPTO_PROVIDER
    return CRYPT_EAL_ProviderPkeyNewCtx(libctx, alg, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, attrName);
#else
    (void)libctx;
    (void)attrName;
    return CRYPT_EAL_PkeyNewCtx(alg);
#endif
}

static int32_t DecSubKeyInfoCb(int32_t type, uint32_t idx, void *data, void *expVal)
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

static int32_t ParseAlgoIdAsn1Buff(uint8_t *buff, uint32_t buffLen, BSL_ASN1_Buffer *algoId, uint32_t algoIdNum)
{
    uint8_t *tmpBuff = buff;
    uint32_t tmpBuffLen = buffLen;

    BSL_ASN1_Template templ = {g_algoIdTempl, sizeof(g_algoIdTempl) / sizeof(g_algoIdTempl[0])};
    return BSL_ASN1_DecodeTemplate(&templ, DecSubKeyInfoCb, &tmpBuff, &tmpBuffLen, algoId, algoIdNum);
}

#ifdef HITLS_CRYPTO_RSA
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

int32_t ParseRsaPubkeyAsn1Buff(CRYPT_EAL_LibCtx *libctx, const char *attrName, uint8_t *buff,
    uint32_t buffLen, BSL_ASN1_Buffer *param, CRYPT_EAL_PkeyCtx **ealPubKey, BslCid cid)
{
    uint8_t *tmpBuff = buff;
    uint32_t tmpBuffLen = buffLen;
    // decode n and e
    BSL_ASN1_Buffer pubAsn1[CRYPT_RSA_PUB_E_IDX + 1] = {0};
    BSL_ASN1_Template pubTempl = {g_rsaPubTempl, sizeof(g_rsaPubTempl) / sizeof(g_rsaPubTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&pubTempl, NULL, &tmpBuff, &tmpBuffLen, pubAsn1, CRYPT_RSA_PUB_E_IDX + 1);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    CRYPT_EAL_PkeyCtx *pctx = GetPkeyCtx(libctx, attrName, CRYPT_PKEY_RSA);
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

static int32_t ProcRsaPrivKey(const BSL_ASN1_Buffer *asn1, CRYPT_EAL_PkeyCtx *ealPkey)
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

static int32_t ProcRsaKeyPair(uint8_t *buff, uint32_t buffLen, CRYPT_EAL_PkeyCtx *ealPkey)
{
    uint8_t *tmpBuff = buff;
    uint32_t tmpBuffLen = buffLen;
    // decode n and e
    BSL_ASN1_Buffer asn1[CRYPT_RSA_PRV_OTHER_PRIME_IDX + 1] = {0};
    BSL_ASN1_Template templ = {g_rsaPrvTempl, sizeof(g_rsaPrvTempl) / sizeof(g_rsaPrvTempl[0])};
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

    return SetRsaPubKey(asn1 + CRYPT_RSA_PRV_N_IDX, asn1 + CRYPT_RSA_PRV_E_IDX, ealPkey);
}

int32_t ParseRsaPrikeyAsn1Buff(CRYPT_EAL_LibCtx *libctx, const char *attrName, uint8_t *buff, uint32_t buffLen,
    BSL_ASN1_Buffer *rsaPssParam, BslCid cid, CRYPT_EAL_PkeyCtx **ealPriKey)
{
    CRYPT_EAL_PkeyCtx *pctx = GetPkeyCtx(libctx, attrName, CRYPT_PKEY_RSA);
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
#endif

#if defined(HITLS_CRYPTO_ECDSA) || defined(HITLS_CRYPTO_SM2)
static inline bool IsEcdsaEcParaId(int32_t paraId)
{
    return paraId == CRYPT_ECC_NISTP224 || paraId == CRYPT_ECC_NISTP256 ||
        paraId == CRYPT_ECC_NISTP384 || paraId == CRYPT_ECC_NISTP521 ||
        paraId == CRYPT_ECC_BRAINPOOLP256R1 || paraId == CRYPT_ECC_BRAINPOOLP384R1 ||
        paraId == CRYPT_ECC_BRAINPOOLP512R1;
}

static int32_t EccEalKeyNew(CRYPT_EAL_LibCtx *libctx, const char *attrName, BSL_ASN1_Buffer *ecParamOid,
    int32_t *alg, CRYPT_EAL_PkeyCtx **ealKey)
{
    int32_t algId;
    BslOidString oidStr = {ecParamOid->len, (char *)ecParamOid->buff, 0};
    CRYPT_PKEY_ParaId paraId = (CRYPT_PKEY_ParaId)BSL_OBJ_GetCIDFromOid(&oidStr);

    if (paraId == CRYPT_ECC_SM2) {
        algId = CRYPT_PKEY_SM2;
    } else if (IsEcdsaEcParaId(paraId)) {
        algId = CRYPT_PKEY_ECDSA;
    } else { // scenario ecdh is not considered, and it will be improved in the future
        return CRYPT_DECODE_UNKNOWN_OID;
    }
    CRYPT_EAL_PkeyCtx *key = GetPkeyCtx(libctx, attrName, algId);
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
    if (pubkey->len == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_ASN1_BUFF_FAILED);
        return CRYPT_DECODE_ASN1_BUFF_FAILED;
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
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // the tag of public key is BSL_ASN1_TAG_BITSTRING, 1 denote unusedBits
    CRYPT_EAL_PkeyPub pub = {.id = algId, .key.eccPub = {.data = pubkey->buff + 1,.len = pubkey->len - 1}};
    ret = CRYPT_EAL_PkeySetPub(pctx, &pub);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pctx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *ealPriKey = pctx;
    return ret;
}

int32_t ParseEccPrikeyAsn1Buff(CRYPT_EAL_LibCtx *libctx, const char *attrName, uint8_t *buff, uint32_t buffLen,
    BSL_ASN1_Buffer *pk8AlgoParam, CRYPT_EAL_PkeyCtx **ealPriKey)
{
    uint8_t *tmpBuff = buff;
    uint32_t tmpBuffLen = buffLen;

    BSL_ASN1_Buffer asn1[CRYPT_ECPRIKEY_PUBKEY_IDX + 1] = {0};
    BSL_ASN1_Template templ = {g_ecPriKeyTempl, sizeof(g_ecPriKeyTempl) / sizeof(g_ecPriKeyTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &tmpBuff, &tmpBuffLen, asn1, CRYPT_ECPRIKEY_PUBKEY_IDX + 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    return ParseEccPrikeyAsn1(libctx, attrName, asn1, pk8AlgoParam, ealPriKey);
}
#endif

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

    CRYPT_EAL_PkeyCtx *pctx = GetPkeyCtx(libctx, attrName, CRYPT_PKEY_ED25519);
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
    CRYPT_EAL_PkeyCtx *pctx = GetPkeyCtx(libctx, attrName, CRYPT_PKEY_ED25519);
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
#endif

static int32_t ParsePk8PrikeyAsn1(CRYPT_EAL_LibCtx *libctx, const char *attrName, BSL_ASN1_Buffer *encode,
    CRYPT_EAL_PkeyCtx **ealPriKey)
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
#ifdef HITLS_CRYPTO_RSA
    if (cid == BSL_CID_RSA || cid == BSL_CID_RSASSAPSS) {
        return ParseRsaPrikeyAsn1Buff(libctx, attrName, octPriKey->buff, octPriKey->len, algoId + 1, cid, ealPriKey);
    }
#endif
#if defined(HITLS_CRYPTO_ECDSA) || defined(HITLS_CRYPTO_SM2)
    if (cid == BSL_CID_EC_PUBLICKEY) {
        return ParseEccPrikeyAsn1Buff(libctx, attrName, octPriKey->buff, octPriKey->len, algoId + 1, ealPriKey);
    }
#endif
#ifdef HITLS_CRYPTO_ED25519
    if (cid == BSL_CID_ED25519) {
        return ParseEd25519PrikeyAsn1Buff(libctx, attrName, octPriKey->buff, octPriKey->len, ealPriKey);
    }
#endif
    return CRYPT_DECODE_UNSUPPORTED_PKCS8_TYPE;
}


int32_t ParseSubPubkeyAsn1(CRYPT_EAL_LibCtx *libctx, const char *attrName, BSL_ASN1_Buffer *encode,
    CRYPT_EAL_PkeyCtx **ealPubKey)
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
    (void)algParam;
    if (cid == BSL_CID_ED25519) {
        return ParseEd25519PubkeyAsn1Buff(libctx, attrName, bitPubkey.buff, bitPubkey.len, ealPubKey);
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

    BSL_ASN1_Buffer asn1[CRYPT_PK8_PRIKEY_PRIKEY_IDX + 1] = {0};
    BSL_ASN1_Template templ = {g_pk8PriKeyTempl, sizeof(g_pk8PriKeyTempl) / sizeof(g_pk8PriKeyTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &tmpBuff, &tmpBuffLen, asn1, CRYPT_PK8_PRIKEY_PRIKEY_IDX + 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    return ParsePk8PrikeyAsn1(libctx, attrName, asn1, ealPriKey);
}

#ifdef HITLS_CRYPTO_KEY_EPKI
static int32_t ParseDeriveKeyPrfAlgId(BSL_ASN1_Buffer *asn, int32_t *prfId)
{
    if (asn->len != 0) {
        BSL_ASN1_Buffer algoId[2] = {0};
        int32_t ret = ParseAlgoIdAsn1Buff(asn->buff, asn->len, algoId, 2);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        BslOidString oidStr = {algoId[BSL_ASN1_TAG_ALGOID_IDX].len, (char *)algoId[BSL_ASN1_TAG_ALGOID_IDX].buff, 0};
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

static int32_t ParseDeriveKeyParam(BSL_Buffer *derivekeyData, uint32_t *iter, uint32_t *keyLen, BSL_Buffer *salt,
    int32_t *prfId)
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

static int32_t ParseEncDataAsn1(CRYPT_EAL_LibCtx *libctx, const char *attrName, BslCid symAlg, EncryptPara *encPara,
    const BSL_Buffer *pwd, BSL_Buffer *decode)
{
    uint32_t iter;
    int32_t prfId;
    uint32_t keylen = 0;
    uint8_t key[512] = {0}; // The maximum length of the symmetry algorithm
    BSL_Buffer salt = {0};
    int32_t ret = ParseDeriveKeyParam(encPara->derivekeyData, &iter, &keylen, &salt, &prfId);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint32_t symKeyLen;
    ret = CRYPT_EAL_CipherGetInfo((CRYPT_CIPHER_AlgId)symAlg, CRYPT_INFO_KEY_LEN, &symKeyLen);
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
        ret = DecryptEncData(libctx, attrName, encPara->ivData, encPara->enData, symAlg, false, &keyBuff,
            output, &dataLen);
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

int32_t ParsePk8EncPriKeyBuff(CRYPT_EAL_LibCtx *libctx, const char *attrName, BSL_Buffer *buff,
    const BSL_Buffer *pwd, CRYPT_EAL_PkeyCtx **ealPriKey)
{
    if (pwd == NULL || pwd->dataLen > PWD_MAX_LEN || (pwd->data == NULL && pwd->dataLen != 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    uint8_t *tmpBuff = buff->data;
    uint32_t tmpBuffLen = buff->dataLen;

    BSL_ASN1_Buffer asn1[CRYPT_PKCS_ENCPRIKEY_MAX] = {0};
    BSL_ASN1_Template templ = {g_pk8EncPriKeyTempl, sizeof(g_pk8EncPriKeyTempl) / sizeof(g_pk8EncPriKeyTempl[0])};
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
    EncryptPara encPara = {.derivekeyData = &derivekeyData, .ivData = &ivData, .enData = &enData};
    ret = ParseEncDataAsn1(libctx, attrName, symId, &encPara, pwd, &decode);
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

int32_t CRYPT_EAL_ParseAsn1SubPubkey(CRYPT_EAL_LibCtx *libctx, const char *attrName, uint8_t *buff,
    uint32_t buffLen, void **ealPubKey, bool isComplete)
{
    uint8_t *tmpBuff = buff;
    uint32_t tmpBuffLen = buffLen;
    // decode sub pubkey info
    BSL_ASN1_Buffer pubAsn1[CRYPT_SUBKEYINFO_BITSTRING_IDX + 1] = {0};
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
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    return ParseSubPubkeyAsn1(libctx, attrName, pubAsn1, (CRYPT_EAL_PkeyCtx **)ealPubKey);
}
#endif // HITLS_CRYPTO_KEY_DECODE

#ifdef HITLS_CRYPTO_KEY_ENCODE

static int32_t EncodeAlgoIdAsn1Buff(BSL_ASN1_Buffer *algoId, uint32_t algoIdNum, uint8_t **buff, uint32_t *buffLen)
{
    BSL_ASN1_Template templ = {g_algoIdTempl, sizeof(g_algoIdTempl) / sizeof(g_algoIdTempl[0])};
    return BSL_ASN1_EncodeTemplate(&templ, algoId, algoIdNum, buff, buffLen);
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

static int32_t EncodeDeriveKeyParam(CRYPT_EAL_LibCtx *libCtx, CRYPT_Pbkdf2Param *param, BSL_Buffer *encode,
    BSL_Buffer *salt)
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

static int32_t GenRandIv(CRYPT_EAL_LibCtx *libCtx, CRYPT_Pbkdf2Param *pkcsParam, BSL_ASN1_Buffer *asn1)
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

        ret = PbkdfDeriveKey(libCtx, attrName, pkcsParam->itCnt, pkcsParam->hmacId, salt, pkcsParam->pwd,
            pkcsParam->pwdLen, &keyBuff);
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
        ret = DecryptEncData(libCtx, attrName, &ivData, &enData, pkcsParam->symId, true, &keyBuff, output,
            &pkcsDataLen);
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

static int32_t EncodePkcsEncryptedBuff(CRYPT_EAL_LibCtx *libCtx, const char *attrName, CRYPT_Pbkdf2Param *pkcsParam,
    BSL_Buffer *unEncrypted, BSL_ASN1_Buffer *asn1)
{
    int32_t ret;
    BslOidString *oidPbes = BSL_OBJ_GetOidFromCID((BslCid)pkcsParam->pbesId);
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
#endif

#ifdef HITLS_CRYPTO_RSA
static int32_t GetPssParamInfo(CRYPT_EAL_PkeyCtx *ealPriKey, CRYPT_RSA_PssPara *rsaPssParam)
{
    int32_t ret;
    ret = CRYPT_EAL_PkeyCtrl(ealPriKey, CRYPT_CTRL_GET_RSA_SALTLEN, &rsaPssParam->saltLen,
        sizeof(rsaPssParam->saltLen));
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
    ret = GetPssParamInfo(ealPubKey, &rsaPssParam);
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

    BSL_ASN1_Template pubTempl = {g_rsaPubTempl, sizeof(g_rsaPubTempl) / sizeof(g_rsaPubTempl[0])};
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

static int32_t EncodeRsaPrvKey(CRYPT_EAL_PkeyCtx *ealPriKey, BSL_ASN1_Buffer *algoId, BSL_Buffer *bitStr,
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

static void DeinitRsaPrvCtx(CRYPT_EAL_PkeyPrv *rsaPrv)
{
    BSL_SAL_ClearFree(rsaPrv->key.rsaPrv.d, rsaPrv->key.rsaPrv.dLen * 8); // 8 items
}

int32_t EncodeRsaPrikeyAsn1Buff(CRYPT_EAL_PkeyCtx *ealPriKey, CRYPT_PKEY_AlgId cid, BSL_Buffer *encode)
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
    BSL_ASN1_Template templ = {g_rsaPrvTempl, sizeof(g_rsaPrvTempl) / sizeof(g_rsaPrvTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asn1, CRYPT_RSA_PRV_OTHER_PRIME_IDX + 1, &encode->data, &encode->dataLen);
    DeinitRsaPrvCtx(&rsaPrv);
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
        pub = (uint8_t *)BSL_SAL_Malloc(keyLen);
        if (pub == NULL) {
            ret = CRYPT_MEM_ALLOC_FAIL;
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            break;
        }
        CRYPT_EAL_PkeyPub pubKey = {.id = cid, .key.eccPub = {.data = pub, .len = keyLen}};
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
        SetAsn1Buffer(asn1 + CRYPT_ECPRIKEY_PUBKEY_IDX, BSL_ASN1_TAG_BITSTRING,
            sizeof(BSL_ASN1_BitString), (uint8_t *)&bitStr);
        BSL_ASN1_Template templ = {g_ecPriKeyTempl, sizeof(g_ecPriKeyTempl) / sizeof(g_ecPriKeyTempl[0])};
        ret = BSL_ASN1_EncodeTemplate(&templ, asn1, CRYPT_ECPRIKEY_PUBKEY_IDX + 1, &encode->data, &encode->dataLen);
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
    BslOidString *oid = cid == CRYPT_PKEY_SM2 ? BSL_OBJ_GetOidFromCID((BslCid)CRYPT_ECC_SM2)
                                              : BSL_OBJ_GetOidFromCID((BslCid)CRYPT_EAL_PkeyGetParaId(ealPriKey));
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
    CRYPT_EAL_PkeyPub pubKey = {.id = CRYPT_EAL_PkeyGetId(ealPubKey), .key.eccPub = {.data = pub, .len = pubLen}};
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
#endif

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
#endif

static int32_t EncodePk8AlgidAny(CRYPT_EAL_PkeyCtx *ealPriKey, BSL_Buffer *bitStr,
    BSL_ASN1_Buffer *algoId, CRYPT_PKEY_AlgId *cidOut)
{
    (void)algoId;
    int32_t ret = CRYPT_DECODE_NO_SUPPORT_TYPE;
    BSL_Buffer tmp = {0};
    CRYPT_PKEY_AlgId cid = CRYPT_EAL_PkeyGetId(ealPriKey);
    switch (cid) {
#ifdef HITLS_CRYPTO_RSA
        case CRYPT_PKEY_RSA:
            ret = EncodeRsaPrvKey(ealPriKey, algoId, &tmp, &cid);
            break;
#endif
#if defined(HITLS_CRYPTO_ECDSA) || defined(HITLS_CRYPTO_SM2)
        case CRYPT_PKEY_ECDSA:
        case CRYPT_PKEY_SM2:
            cid = (CRYPT_PKEY_AlgId)BSL_CID_EC_PUBLICKEY;
            ret = EncodeEccPrikeyAsn1Buff(ealPriKey, &algoId[BSL_ASN1_TAG_ALGOID_ANY_IDX], &tmp);
            break;
#endif
#ifdef HITLS_CRYPTO_ED25519
        case CRYPT_PKEY_ED25519:
            ret = EncodeEd25519PrikeyAsn1Buff(ealPriKey, &tmp);
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
    *cidOut = cid;
    return ret;
}

int32_t EncodePk8PriKeyBuff(CRYPT_EAL_PkeyCtx *ealPriKey, BSL_Buffer *asn1)
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

        BSL_ASN1_Template pubTempl = {g_pk8PriKeyTempl, sizeof(g_pk8PriKeyTempl) / sizeof(g_pk8PriKeyTempl[0])};
        ret =  BSL_ASN1_EncodeTemplate(&pubTempl, encode, CRYPT_PK8_PRIKEY_PRIKEY_IDX + 1, &asn1->data, &asn1->dataLen);
    } while (0);
    // rsa-pss mode release buffer
    if (algoId[BSL_ASN1_TAG_ALGOID_ANY_IDX].tag == (BSL_ASN1_TAG_SEQUENCE | BSL_ASN1_TAG_CONSTRUCTED)) {
        BSL_SAL_FREE(algoId[BSL_ASN1_TAG_ALGOID_ANY_IDX].buff);
    }
    BSL_SAL_ClearFree(bitStr.data, bitStr.dataLen);
    BSL_SAL_FREE(algo.buff);
    return ret;
}

#ifdef HITLS_CRYPTO_KEY_EPKI
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

    ret = EncodePkcsEncryptedBuff(libCtx, attrName, pkcs8Param, &unEncrypted, asn1);
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
#endif

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
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BslOidString *oidStr = BSL_OBJ_GetOidFromCID((BslCid)cid);
    if (oidStr == NULL) {
        BSL_SAL_FREE(bitTmp.data);
        ret = CRYPT_ERR_ALGID;
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    algoId[BSL_ASN1_TAG_ALGOID_IDX].buff = (uint8_t *)oidStr->octs;
    algoId[BSL_ASN1_TAG_ALGOID_IDX].len = oidStr->octetLen;
    algoId[BSL_ASN1_TAG_ALGOID_IDX].tag = BSL_ASN1_TAG_OBJECT_ID;
    ret = EncodeAlgoIdAsn1Buff(algoId, BSL_ASN1_TAG_ALGOID_ANY_IDX + 1, &algo->buff, &algo->len);
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
    BSL_ASN1_BitString bitPubkey = {bitStr.data, bitStr.dataLen, 0};
    BSL_ASN1_Buffer encode[CRYPT_SUBKEYINFO_BITSTRING_IDX + 1] = {
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, algo.len, algo.buff},
        {BSL_ASN1_TAG_BITSTRING, sizeof(BSL_ASN1_BitString), (uint8_t *)&bitPubkey}
    };

    BSL_ASN1_Template pubTempl;
    if (isComplete) {
        pubTempl.templItems = g_subKeyInfoTempl;
        pubTempl.templNum = sizeof(g_subKeyInfoTempl) / sizeof(g_subKeyInfoTempl[0]);
    } else {
        pubTempl.templItems = g_subKeyInfoInnerTempl;
        pubTempl.templNum = sizeof(g_subKeyInfoInnerTempl) / sizeof(g_subKeyInfoInnerTempl[0]);
    }
    ret = BSL_ASN1_EncodeTemplate(&pubTempl,
        encode, CRYPT_SUBKEYINFO_BITSTRING_IDX + 1, &encodeH->data, &encodeH->dataLen);
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

    BslOidString *oidStr = BSL_OBJ_GetOidFromCID((BslCid)mdId);
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
    BslOidString *mgfStr = BSL_OBJ_GetOidFromCID(BSL_CID_MGF1);
    if (mgfStr == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ERR_ALGID);
        return CRYPT_ERR_ALGID;
    }

    BslOidString *oidStr = BSL_OBJ_GetOidFromCID((BslCid)mgfId);
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
        {BSL_ASN1_TAG_NULL,0, NULL}, // param
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
    BslOidString typeOidStr = {asn1[HITLS_P7_ENC_CONTINFO_TYPE_IDX].len,
        (char *)asn1[HITLS_P7_ENC_CONTINFO_TYPE_IDX].buff, 0};
    BslCid cid = BSL_OBJ_GetCIDFromOid(&typeOidStr);
    if (cid != BSL_CID_PKCS7_SIMPLEDATA) {
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
    EncryptPara encPara = {.derivekeyData = &derivekeyData, .ivData = &ivData, .enData = &enData};
    BSL_Buffer pwdBuffer = {(uint8_t *)(uintptr_t)pwd, pwdlen};
    ret = ParseEncDataAsn1(libCtx, attrName, symId, &encPara, &pwdBuffer, output);
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

    ret = EncodePkcsEncryptedBuff(libCtx, attrName, pkcs7Param, data, asn1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    do {
        BslOidString *oidStr = BSL_OBJ_GetOidFromCID(BSL_CID_PKCS7_SIMPLEDATA);
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

#endif // HITLS_CRYPTO_ENCODE_DECODE
