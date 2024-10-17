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

#include <stdint.h>
#include "crypt_eal_implprovider.h"
#include "bsl_sal.h"
#include "crypt_algid.h"
#include "crypt_default_provderimpl.h"
#include "crypt_errno.h"
#include "bsl_errno.h"
#include "bsl_err_internal.h"
#include "crypt_default_provider.h"

#define CRYPT_EAL_DEFAULT_ATTR "provider=default"

static const CRYPT_EAL_AlgInfo defMds[] = {
    {CRYPT_MD_MD5, defMdMd5, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA1, defMdSha1, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA224, defMdSha224, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA256, defMdSha256, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA384, defMdSha384, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA512, defMdSha512, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA3_224, defMdSha3224, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA3_256, defMdSha3256, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA3_384, defMdSha3384, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA3_512, defMdSha3512, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHAKE128, defMdShake128, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHAKE256, defMdShake256, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SM3, defMdSm3, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};


static const CRYPT_EAL_AlgInfo defKdfs[] = {
    {CRYPT_KDF_SCRYPT, defKdfScrypt, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_KDF_PBKDF2, defKdfPBKdf2, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_KDF_KDFTLS12, defKdfKdfTLS12, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_KDF_HKDF, defKdfHkdf, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo defKeyMgmt[] = {
    {CRYPT_PKEY_DSA, defKeyMgmtDsa, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_ED25519, defKeyMgmtEd25519, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_X25519, defKeyMgmtX25519, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_RSA, defKeyMgmtRsa, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_DH, defKeyMgmtDh, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_ECDSA, defKeyMgmtEcdsa, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_ECDH, defKeyMgmtEcdh, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_SM2, defKeyMgmtSm2, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_PAILLIER, defKeyMgmtPaillier, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo defAsymCiphers[] = {
    {CRYPT_PKEY_RSA, defAsymCipherRsa, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_SM2, defAsymCipherSm2, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_PAILLIER, defAsymCipherPaillier, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo defKeyExch[] = {
    {CRYPT_PKEY_X25519, defExchX25519, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_DH, defExchDh, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_ECDH, defExchEcdh, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_SM2, defExchSm2, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo defSigns[] = {
    {CRYPT_PKEY_DSA, defSignDsa, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_ED25519, defSignEd25519, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_RSA, defSignRsa, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_ECDSA, defSignEcdsa, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_SM2, defSignSm2, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo defMacs[] = {
    {CRYPT_MAC_HMAC_MD5, defMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SHA1, defMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SHA224, defMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SHA256, defMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SHA384, defMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SHA512, defMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SHA3_224, defMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SHA3_256, defMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SHA3_384, defMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SHA3_512, defMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SM3, defMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo defRands[] = {
    {CRYPT_RAND_SHA1, defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_SHA224, defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_SHA256, defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_SHA384, defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_SHA512, defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_HMAC_SHA1, defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_HMAC_SHA224, defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_HMAC_SHA256, defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_HMAC_SHA384, defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_HMAC_SHA512, defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_AES128_CTR, defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_AES192_CTR, defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_AES256_CTR, defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_AES128_CTR_DF, defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_AES192_CTR_DF, defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_AES256_CTR_DF, defRand, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static int32_t CRYPT_EAL_DefaultProvQuery(void *provCtx, int32_t operaId, const CRYPT_EAL_AlgInfo **algInfos)
{
    (void) provCtx;
    int32_t ret = CRYPT_SUCCESS;
    switch (operaId) {
        case CRYPT_EAL_OPERAID_SYMMCIPHER:
            break;
        case CRYPT_EAL_OPERAID_KEYMGMT:
            *algInfos = defKeyMgmt;
            break;
        case CRYPT_EAL_OPERAID_SIGN:
            *algInfos = defSigns;
            break;
        case CRYPT_EAL_OPERAID_ASYMCIPHER:
            *algInfos = defAsymCiphers;
            break;
        case CRYPT_EAL_OPERAID_KEYEXCH:
            *algInfos = defKeyExch;
            break;
        case CRYPT_EAL_OPERAID_KEM:
            break;
        case CRYPT_EAL_OPERAID_HASH:
            *algInfos = defMds;
            break;
        case CRYPT_EAL_OPERAID_MAC:
            *algInfos = defMacs;
            break;
        case CRYPT_EAL_OPERAID_KDF:
            *algInfos = defKdfs;
            break;
        case CRYPT_EAL_OPERAID_RAND:
            *algInfos = defRands;
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

static CRYPT_EAL_Func defProvOutFuncs[] = {
    {CRYPT_EAL_PROVCB_QUERY, CRYPT_EAL_DefaultProvQuery},
    {CRYPT_EAL_PROVCB_FREE, CRYPT_EAL_DefaultProvFree},
    {CRYPT_EAL_PROVCB_CTRL, NULL},
    CRYPT_EAL_FUNC_END
};

int32_t CRYPT_EAL_DefaultProvInit(CRYPT_EAL_ProvMgrCtx *mgrCtx, CRYPT_Param *param,
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
    *outFuncs = defProvOutFuncs;
    return CRYPT_SUCCESS;
}