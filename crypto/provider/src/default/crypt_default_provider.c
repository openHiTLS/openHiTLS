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

#ifdef HITLS_CRYPTO_PROVIDER

#include <stdint.h>
#include "crypt_eal_implprovider.h"
#include "bsl_sal.h"
#include "crypt_algid.h"
#include "crypt_default_provderimpl.h"
#include "crypt_errno.h"
#include "bsl_errno.h"
#include "bsl_err_internal.h"
#include "crypt_default_provider.h"
#include "crypt_provider.h"

#define CRYPT_EAL_DEFAULT_ATTR "provider=default"

static const CRYPT_EAL_AlgInfo g_defMds[] = {
    {CRYPT_MD_MD5, g_defMdMd5, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA1, g_defMdSha1, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA224, g_defMdSha224, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA256, g_defMdSha256, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA384, g_defMdSha384, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA512, g_defMdSha512, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA3_224, g_defMdSha3224, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA3_256, g_defMdSha3256, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA3_384, g_defMdSha3384, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA3_512, g_defMdSha3512, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHAKE128, g_defMdShake128, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHAKE256, g_defMdShake256, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SM3, g_defMdSm3, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};


static const CRYPT_EAL_AlgInfo g_defKdfs[] = {
    {CRYPT_KDF_SCRYPT, g_defKdfScrypt, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_KDF_PBKDF2, g_defKdfPBKdf2, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_KDF_KDFTLS12, g_defKdfKdfTLS12, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_KDF_HKDF, g_defKdfHkdf, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo g_defKeyMgmt[] = {
    {CRYPT_PKEY_DSA, g_defKeyMgmtDsa, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_ED25519, g_defKeyMgmtEd25519, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_X25519, g_defKeyMgmtX25519, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_RSA, g_defKeyMgmtRsa, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_DH, g_defKeyMgmtDh, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_ECDSA, g_defKeyMgmtEcdsa, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_ECDH, g_defKeyMgmtEcdh, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_SM2, g_defKeyMgmtSm2, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_PAILLIER, g_defKeyMgmtPaillier, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo g_defAsymCiphers[] = {
    {CRYPT_PKEY_RSA, g_defAsymCipherRsa, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_SM2, g_defAsymCipherSm2, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_PAILLIER, g_defAsymCipherPaillier, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo g_defKeyExch[] = {
    {CRYPT_PKEY_X25519, g_defExchX25519, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_DH, g_defExchDh, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_ECDH, g_defExchEcdh, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_SM2, g_defExchSm2, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo g_defSigns[] = {
    {CRYPT_PKEY_DSA, g_defSignDsa, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_ED25519, g_defSignEd25519, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_RSA, g_defSignRsa, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_ECDSA, g_defSignEcdsa, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_SM2, g_defSignSm2, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo g_defMacs[] = {
    {CRYPT_MAC_HMAC_MD5, g_defMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SHA1, g_defMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SHA224, g_defMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SHA256, g_defMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SHA384, g_defMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SHA512, g_defMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SHA3_224, g_defMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SHA3_256, g_defMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SHA3_384, g_defMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SHA3_512, g_defMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SM3, g_defMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo g_defRands[] = {
    {CRYPT_RAND_SHA1, g_defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_SHA224, g_defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_SHA256, g_defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_SHA384, g_defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_SHA512, g_defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_HMAC_SHA1, g_defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_HMAC_SHA224, g_defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_HMAC_SHA256, g_defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_HMAC_SHA384, g_defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_HMAC_SHA512, g_defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_AES128_CTR, g_defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_AES192_CTR, g_defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_AES256_CTR, g_defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_AES128_CTR_DF, g_defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_AES192_CTR_DF, g_defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_AES256_CTR_DF, g_defRand, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo g_defCiphers[] = {
    {CRYPT_CIPHER_AES128_CBC, g_defCbc, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES192_CBC, g_defCbc, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES256_CBC, g_defCbc, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES128_CTR, g_defCtr, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES192_CTR, g_defCtr, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES256_CTR, g_defCtr, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES128_ECB, g_defEcb, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES192_ECB, g_defEcb, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES256_ECB, g_defEcb, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES128_CCM, g_defCcm, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES192_CCM, g_defCcm, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES256_CCM, g_defCcm, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES128_GCM, g_defGcm, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES192_GCM, g_defGcm, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES256_GCM, g_defGcm, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_CHACHA20_POLY1305, g_defChaCha, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_SM4_XTS, g_defXts, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_SM4_CBC, g_defCbc, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_SM4_ECB, g_defEcb, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_SM4_CTR, g_defCtr, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_SM4_GCM, g_defGcm, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_SM4_CFB, g_defCfb, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_SM4_OFB, g_defOfb, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES128_CFB, g_defCfb, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES192_CFB, g_defCfb, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES256_CFB, g_defCfb, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES128_OFB, g_defOfb, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES192_OFB, g_defOfb, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES256_OFB, g_defOfb, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static int32_t CRYPT_EAL_DefaultProvQuery(void *provCtx, int32_t operaId, const CRYPT_EAL_AlgInfo **algInfos)
{
    (void) provCtx;
    int32_t ret = CRYPT_SUCCESS;
    switch (operaId) {
        case CRYPT_EAL_OPERAID_SYMMCIPHER:
            *algInfos = g_defCiphers;
            break;
        case CRYPT_EAL_OPERAID_KEYMGMT:
            *algInfos = g_defKeyMgmt;
            break;
        case CRYPT_EAL_OPERAID_SIGN:
            *algInfos = g_defSigns;
            break;
        case CRYPT_EAL_OPERAID_ASYMCIPHER:
            *algInfos = g_defAsymCiphers;
            break;
        case CRYPT_EAL_OPERAID_KEYEXCH:
            *algInfos = g_defKeyExch;
            break;
        case CRYPT_EAL_OPERAID_KEM:
            ret = CRYPT_NOT_SUPPORT;
            break;
        case CRYPT_EAL_OPERAID_HASH:
            *algInfos = g_defMds;
            break;
        case CRYPT_EAL_OPERAID_MAC:
            *algInfos = g_defMacs;
            break;
        case CRYPT_EAL_OPERAID_KDF:
            *algInfos = g_defKdfs;
            break;
        case CRYPT_EAL_OPERAID_RAND:
            *algInfos = g_defRands;
            break;
        default:
            ret = CRYPT_NOT_SUPPORT;
            break;
    }
    return ret;
}

static void CRYPT_EAL_DefaultProvFree(void *provCtx)
{
    BSL_SAL_Free(provCtx);
}

static CRYPT_EAL_Func g_defProvOutFuncs[] = {
    {CRYPT_EAL_PROVCB_QUERY, CRYPT_EAL_DefaultProvQuery},
    {CRYPT_EAL_PROVCB_FREE, CRYPT_EAL_DefaultProvFree},
    {CRYPT_EAL_PROVCB_CTRL, NULL},
    CRYPT_EAL_FUNC_END
};

int32_t CRYPT_EAL_DefaultProvInit(CRYPT_EAL_ProvMgrCtx *mgrCtx, BSL_Param *param,
    CRYPT_EAL_Func *capFuncs, CRYPT_EAL_Func **outFuncs, void **provCtx)
{
    (void) param;
    (void) capFuncs;
    CRYPT_EAL_DefProvCtx *temp = BSL_SAL_Malloc(sizeof(CRYPT_EAL_DefProvCtx));
    if (temp == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    temp->mgrCtxHandle = mgrCtx;
    *provCtx = temp;
    *outFuncs = g_defProvOutFuncs;
    return CRYPT_SUCCESS;
}

#endif /* HITLS_CRYPTO_PROVIDER */