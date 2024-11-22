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
#ifdef HITLS_TLS_CALLBACK_CERT
#include <stdio.h>
#include <string.h>
#include "crypt_types.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "hitls_error.h"
#include "hitls_type.h"
#include "hitls_pki.h"
#include "hitls_cert_type.h"
#include "hitls_crypt_type.h"
#include "crypt_algid.h"
#include "crypt_eal_pkey.h"

CRYPT_MD_AlgId GetCryptHashAlgFromCertHashAlg(HITLS_HashAlgo hashAlgo)
{
    typedef struct {
        HITLS_HashAlgo certHashAlg;
        CRYPT_MD_AlgId cryptMdAlgId;
    } CertHashAlgoMap;
    CertHashAlgoMap hashAlgMap[] = {
        { HITLS_HASH_SHA_224, CRYPT_MD_SHA224 },
        { HITLS_HASH_SHA_256, CRYPT_MD_SHA256 },
        { HITLS_HASH_SHA_384, CRYPT_MD_SHA384 },
        { HITLS_HASH_SHA_512, CRYPT_MD_SHA512 },
        { HITLS_HASH_MD5, CRYPT_MD_MD5 },
        { HITLS_HASH_SHA1, CRYPT_MD_SHA1 },
        { HITLS_HASH_SM3, CRYPT_MD_SM3 },
    };
    for (size_t i = 0; i < sizeof(hashAlgMap) / sizeof(hashAlgMap[0]); i++) {
        if (hashAlgMap[i].certHashAlg == hashAlgo) {
            return hashAlgMap[i].cryptMdAlgId;
        }
    }
    return CRYPT_MD_MAX;
}

static int32_t SetRsaEmsa(CRYPT_EAL_PkeyCtx *ctx, HITLS_SignAlgo signAlgo, CRYPT_MD_AlgId mdAlgId)
{
    if (signAlgo == HITLS_SIGN_RSA_PKCS1_V15) {
        CRYPT_RSA_PkcsV15Para pad = { .mdId = mdAlgId };
        return CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pad, sizeof(CRYPT_RSA_PkcsV15Para));
    } else if  (signAlgo == HITLS_SIGN_RSA_PSS_PSS || signAlgo == HITLS_SIGN_RSA_PSS_RSAE) {
        CRYPT_RSA_PssPara pad = { -1, mdAlgId, mdAlgId };
        return CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_RSA_EMSA_PSS, &pad, sizeof(CRYPT_RSA_PssPara));
    }

    return HITLS_SUCCESS;
}

static int32_t SignOrVerifySignPre(CRYPT_EAL_PkeyCtx *ctx, HITLS_SignAlgo signAlgo, HITLS_HashAlgo hashAlgo,
    CRYPT_MD_AlgId *mdAlgId)
{
    *mdAlgId = GetCryptHashAlgFromCertHashAlg(hashAlgo);
    if (*mdAlgId == CRYPT_MD_MAX) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ADAPT_ERR);
        return HITLS_X509_ADAPT_ERR;
    }
    return SetRsaEmsa(ctx, signAlgo, *mdAlgId);
}

int32_t HITLS_X509_Adapt_CreateSign(HITLS_Ctx *ctx, HITLS_CERT_Key *key, HITLS_SignAlgo signAlgo,
    HITLS_HashAlgo hashAlgo, const uint8_t *data, uint32_t dataLen, uint8_t *sign, uint32_t *signLen)
{
    (void)ctx;
    CRYPT_MD_AlgId mdAlgId = CRYPT_MD_MAX;
    if (SignOrVerifySignPre(key, signAlgo, hashAlgo, &mdAlgId) != HITLS_SUCCESS) {
        return HITLS_X509_ADAPT_ERR;
    }
    return CRYPT_EAL_PkeySign(key, mdAlgId, data, dataLen, sign, signLen);
}

int32_t HITLS_X509_Adapt_VerifySign(HITLS_Ctx *ctx, HITLS_CERT_Key *key, HITLS_SignAlgo signAlgo,
    HITLS_HashAlgo hashAlgo, const uint8_t *data, uint32_t dataLen, const uint8_t *sign, uint32_t signLen)
{
    (void)ctx;
    CRYPT_MD_AlgId mdAlgId = CRYPT_MD_MAX;
    if (SignOrVerifySignPre(key, signAlgo, hashAlgo, &mdAlgId) != HITLS_SUCCESS) {
        return HITLS_X509_ADAPT_ERR;
    }
    return CRYPT_EAL_PkeyVerify(key, mdAlgId, data, dataLen, sign, signLen);
}

#if defined(HITLS_TLS_SUITE_KX_RSA) || defined(HITLS_TLS_PROTO_TLCP11)
static int32_t CertSetRsaEncryptionScheme(CRYPT_EAL_PkeyCtx *ctx)
{
    CRYPT_RSA_PkcsV15Para pad = {
        .mdId = CRYPT_MD_SHA256,
    };
    return CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_RSA_RSAES_PKCSV15, &pad, sizeof(CRYPT_RSA_PkcsV15Para));
}

/* only support rsa pkcs1.5 */
int32_t HITLS_X509_Adapt_Encrypt(HITLS_Ctx *ctx, HITLS_CERT_Key *key, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen)
{
    (void)ctx;
    if (CRYPT_EAL_PkeyGetId(key) == CRYPT_PKEY_RSA && CertSetRsaEncryptionScheme(key) != HITLS_SUCCESS) {
        return HITLS_X509_ADAPT_ERR;
    }

    return CRYPT_EAL_PkeyEncrypt(key, in, inLen, out, outLen);
}


int32_t HITLS_X509_Adapt_Decrypt(HITLS_Ctx *ctx, HITLS_CERT_Key *key, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen)
{
    (void)ctx;
    if (CRYPT_EAL_PkeyGetId(key) == CRYPT_PKEY_RSA && CertSetRsaEncryptionScheme(key) != HITLS_SUCCESS) {
        return HITLS_X509_ADAPT_ERR;
    }

    return CRYPT_EAL_PkeyDecrypt(key, in, inLen, out, outLen);
}
#endif

int32_t HITLS_X509_Adapt_CheckPrivateKey(const HITLS_Config *config, HITLS_CERT_X509 *cert, HITLS_CERT_Key *key)
{
    (void)config;
    CRYPT_EAL_PkeyCtx *ealPubKey = NULL;
    CRYPT_EAL_PkeyCtx *ealPrivKey = (CRYPT_EAL_PkeyCtx *)key;
    int32_t ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_PUBKEY, &ealPubKey, 0);
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = CRYPT_EAL_PkeyPairCheck(ealPubKey, ealPrivKey);
    CRYPT_EAL_PkeyFreeCtx(ealPubKey);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}
#endif /* HITLS_TLS_CALLBACK_CERT */
