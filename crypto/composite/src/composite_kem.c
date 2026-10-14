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
#ifdef HITLS_CRYPTO_COMPOSITE_KEM

#include "composite_local.h"
#include "crypt_utils.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_md.h"
#include "crypt_util_rand.h"
#include "bsl_sal.h"
#include <string.h>

#define COMPOSITE_KEM_MAX_TRAD_SECRET_LEN 66  /* ECDH P-521 shared secret: ceil(521 / 8) bytes. */
#define COMPOSITE_KEM_SECRET_LEN 32           /* 256-bit ML-KEM secret and SHA3-256 combiner output, in bytes. */

static int32_t CRYPT_CompositeKemCheckParam(const CRYPT_CompositeCtx *ctx, bool encaps)
{
    RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    RETURN_RET_IF(ctx->info->kind != CRYPT_COMPOSITE_KIND_KEM, CRYPT_NOT_SUPPORT);
    RETURN_RET_IF((encaps ? ctx->pubLen : ctx->prvLen) == 0, CRYPT_COMPOSITE_KEY_NOT_SET);
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_CompositeKemCombine(const CRYPT_CompositeCtx *ctx, const uint8_t *pqcSecret,
    const uint8_t *tradSecret, const uint8_t *tradCipher, uint8_t *secret)
{
    BSL_Buffer tradPub = {0};
    int32_t ret = CRYPT_CompositeGetTradPubKey(ctx, &tradPub);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    CRYPT_EAL_MdCtx *md = CRYPT_EAL_ProviderMdNewCtx(ctx->libCtx, ctx->info->alg.kem.combinerHashId, NULL);
    if (md == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
    uint32_t secretLen = COMPOSITE_KEM_SECRET_LEN;
    GOTO_ERR_IF_EX(CRYPT_EAL_MdInit(md), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MdUpdate(md, pqcSecret, COMPOSITE_KEM_SECRET_LEN), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MdUpdate(md, tradSecret, ctx->info->alg.kem.tradSharedLen), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MdUpdate(md, tradCipher, ctx->info->alg.kem.tradCipherLen), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MdUpdate(md, tradPub.data, tradPub.dataLen), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MdUpdate(md, (const uint8_t *)ctx->info->label, strlen(ctx->info->label)), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MdFinal(md, secret, &secretLen), ret);
ERR:
    BSL_SAL_Free(tradPub.data);
    CRYPT_EAL_MdFreeCtx(md);
    return ret;
}

static int32_t CRYPT_CompositeKemDecapsRsa(const CRYPT_CompositeCtx *ctx, const uint8_t *cipher, uint8_t *secret)
{
    uint32_t capacity = ctx->info->alg.kem.tradCipherLen;
    uint32_t plainLen = capacity;
    uint8_t *plain = BSL_SAL_Malloc(capacity);
    RETURN_RET_IF(plain == NULL, CRYPT_MEM_ALLOC_FAIL);
    int32_t ret;
    GOTO_ERR_IF_EX(CRYPT_EAL_PkeyDecrypt(ctx->tradCtx, cipher, capacity, plain, &plainLen), ret);
    if (plainLen != COMPOSITE_KEM_SECRET_LEN) {
        ret = CRYPT_COMPOSITE_KEYLEN_ERROR;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    memcpy(secret, plain, COMPOSITE_KEM_SECRET_LEN);
ERR:
    BSL_SAL_ClearFree(plain, capacity);
    return ret;
}

static int32_t CRYPT_CompositeKemNewTradCtx(const CRYPT_CompositeCtx *ctx, CRYPT_EAL_PkeyCtx **tradCtx)
{
    if (ctx->info->tradAlg == CRYPT_PKEY_RSA) {
        return CRYPT_SUCCESS;
    }
    *tradCtx = CRYPT_EAL_ProviderPkeyNewCtx(ctx->libCtx, ctx->info->tradAlg, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, NULL);
    if (*tradCtx == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = CRYPT_SUCCESS;
    if (ctx->info->tradAlg == CRYPT_PKEY_ECDH) {
        ret = CRYPT_EAL_PkeySetParaById(*tradCtx, ctx->info->tradParam);
        if (ret != CRYPT_SUCCESS) {
            CRYPT_EAL_PkeyFreeCtx(*tradCtx);
            *tradCtx = NULL;
        }
    }
    return ret;
}

static int32_t CRYPT_CompositeKemEncapsTrad(const CRYPT_CompositeCtx *ctx, CRYPT_EAL_PkeyCtx *ephemeral,
    uint8_t *cipher, uint8_t *secret)
{
    uint32_t cipherLen = ctx->info->alg.kem.tradCipherLen;
    int32_t ret;
    if (ctx->info->tradAlg == CRYPT_PKEY_RSA) {
        RETURN_RET_IF_ERR_EX(CRYPT_RandEx(ctx->libCtx, secret, COMPOSITE_KEM_SECRET_LEN), ret);
        return CRYPT_EAL_PkeyEncrypt(ctx->tradCtx, secret, COMPOSITE_KEM_SECRET_LEN, cipher, &cipherLen);
    }
    uint32_t secretLen = COMPOSITE_KEM_MAX_TRAD_SECRET_LEN;
    BSL_Param pub[] = {{ctx->info->tradAlg == CRYPT_PKEY_X25519 ? CRYPT_PARAM_CURVE25519_PUBKEY : CRYPT_PARAM_EC_PUBKEY,
        BSL_PARAM_TYPE_OCTETS, cipher, cipherLen, 0}, BSL_PARAM_END};
    RETURN_RET_IF_ERR_EX(CRYPT_EAL_PkeyGen(ephemeral), ret);
    RETURN_RET_IF_ERR_EX(CRYPT_EAL_PkeyGetPubEx(ephemeral, pub), ret);
    return CRYPT_EAL_PkeyComputeShareKey(ephemeral, ctx->tradCtx, secret, &secretLen);
}

static int32_t CRYPT_CompositeKemDecapsTrad(const CRYPT_CompositeCtx *ctx, CRYPT_EAL_PkeyCtx *peer,
    const uint8_t *cipher, uint8_t *secret)
{
    if (ctx->info->tradAlg == CRYPT_PKEY_RSA) {
        return CRYPT_CompositeKemDecapsRsa(ctx, cipher, secret);
    }
    uint32_t secretLen = COMPOSITE_KEM_MAX_TRAD_SECRET_LEN;
    int32_t ret;
    BSL_Param pub[] = {{ctx->info->tradAlg == CRYPT_PKEY_X25519 ? CRYPT_PARAM_CURVE25519_PUBKEY : CRYPT_PARAM_EC_PUBKEY,
        BSL_PARAM_TYPE_OCTETS, (uint8_t *)(uintptr_t)cipher, ctx->info->alg.kem.tradCipherLen, 0}, BSL_PARAM_END};
    RETURN_RET_IF_ERR_EX(CRYPT_EAL_PkeySetPubEx(peer, pub), ret);
    return CRYPT_EAL_PkeyComputeShareKey(ctx->tradCtx, peer, secret, &secretLen);
}

int32_t CRYPT_COMPOSITE_Encaps(const CRYPT_CompositeCtx *ctx, uint8_t *cipher, uint32_t *cipherLen,
    uint8_t *sharekey, uint32_t *shareLen)
{
    RETURN_RET_IF(ctx == NULL || cipher == NULL || cipherLen == NULL || sharekey == NULL || shareLen == NULL,
        CRYPT_NULL_INPUT);
    int32_t ret = CRYPT_CompositeKemCheckParam(ctx, true);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    uint32_t totalCipherLen = ctx->info->alg.kem.pqcCipherLen + ctx->info->alg.kem.tradCipherLen;
    RETURN_RET_IF(*cipherLen < totalCipherLen || *shareLen < COMPOSITE_KEM_SECRET_LEN, CRYPT_COMPOSITE_LEN_NOT_ENOUGH);
    CRYPT_EAL_PkeyCtx *ephemeral = NULL;
    RETURN_RET_IF_ERR_EX(CRYPT_CompositeKemNewTradCtx(ctx, &ephemeral), ret);
    uint8_t *tmpCipher = BSL_SAL_Malloc(totalCipherLen);
    uint8_t pqcSecret[COMPOSITE_KEM_SECRET_LEN];
    uint8_t tradSecret[COMPOSITE_KEM_MAX_TRAD_SECRET_LEN];
    uint8_t secret[COMPOSITE_KEM_SECRET_LEN];
    uint32_t pqcCipherLen = ctx->info->alg.kem.pqcCipherLen;
    uint32_t pqcSecretLen = sizeof(pqcSecret);
    ret = CRYPT_MEM_ALLOC_FAIL;
    GOTO_ERR_IF_TRUE(tmpCipher == NULL, ret);
    /* Composite ciphertext: PQC ciphertext || traditional ciphertext. */
    uint8_t *tradCipher = tmpCipher + pqcCipherLen;
    GOTO_ERR_IF_EX(CRYPT_EAL_PkeyEncaps(ctx->pqcCtx, tmpCipher, &pqcCipherLen, pqcSecret, &pqcSecretLen), ret);
    GOTO_ERR_IF_EX(CRYPT_CompositeKemEncapsTrad(ctx, ephemeral, tradCipher, tradSecret), ret);
    GOTO_ERR_IF_EX(CRYPT_CompositeKemCombine(ctx, pqcSecret, tradSecret, tradCipher, secret), ret);
    memcpy(cipher, tmpCipher, totalCipherLen);
    memcpy(sharekey, secret, sizeof(secret));
    *cipherLen = totalCipherLen;
    *shareLen = sizeof(secret);
ERR:
    BSL_SAL_CleanseData(pqcSecret, sizeof(pqcSecret));
    BSL_SAL_CleanseData(tradSecret, sizeof(tradSecret));
    BSL_SAL_CleanseData(secret, sizeof(secret));
    BSL_SAL_Free(tmpCipher);
    CRYPT_EAL_PkeyFreeCtx(ephemeral);
    return ret;
}

int32_t CRYPT_COMPOSITE_Decaps(const CRYPT_CompositeCtx *ctx, const uint8_t *cipher, uint32_t cipherLen,
    uint8_t *sharekey, uint32_t *shareLen)
{
    RETURN_RET_IF(ctx == NULL || cipher == NULL || sharekey == NULL || shareLen == NULL, CRYPT_NULL_INPUT);
    int32_t ret = CRYPT_CompositeKemCheckParam(ctx, false);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    uint32_t pqcCipherLen = ctx->info->alg.kem.pqcCipherLen;
    RETURN_RET_IF(cipherLen != pqcCipherLen + ctx->info->alg.kem.tradCipherLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
    RETURN_RET_IF(*shareLen < COMPOSITE_KEM_SECRET_LEN, CRYPT_COMPOSITE_LEN_NOT_ENOUGH);
    RETURN_RET_IF(ctx->info->tradAlg == CRYPT_PKEY_ECDH && cipher[pqcCipherLen] != 0x04, CRYPT_COMPOSITE_KEYLEN_ERROR);
    CRYPT_EAL_PkeyCtx *peer = NULL;
    RETURN_RET_IF_ERR_EX(CRYPT_CompositeKemNewTradCtx(ctx, &peer), ret);
    uint8_t pqcSecret[COMPOSITE_KEM_SECRET_LEN];
    uint8_t tradSecret[COMPOSITE_KEM_MAX_TRAD_SECRET_LEN];
    uint8_t secret[COMPOSITE_KEM_SECRET_LEN];
    uint32_t pqcSecretLen = sizeof(pqcSecret);
    const uint8_t *tradCipher = cipher + pqcCipherLen;
    GOTO_ERR_IF_EX(CRYPT_EAL_PkeyDecaps(ctx->pqcCtx, cipher, pqcCipherLen, pqcSecret, &pqcSecretLen), ret);
    GOTO_ERR_IF_EX(CRYPT_CompositeKemDecapsTrad(ctx, peer, tradCipher, tradSecret), ret);
    GOTO_ERR_IF_EX(CRYPT_CompositeKemCombine(ctx, pqcSecret, tradSecret, tradCipher, secret), ret);
    memcpy(sharekey, secret, sizeof(secret));
    *shareLen = sizeof(secret);
ERR:
    BSL_SAL_CleanseData(pqcSecret, sizeof(pqcSecret));
    BSL_SAL_CleanseData(tradSecret, sizeof(tradSecret));
    BSL_SAL_CleanseData(secret, sizeof(secret));
    CRYPT_EAL_PkeyFreeCtx(peer);
    return ret;
}


int32_t CRYPT_CompositePrepareTradPubKey(CRYPT_CompositeCtx *ctx)
{
    if (ctx->info->tradAlg == CRYPT_PKEY_RSA) {
        return CRYPT_SUCCESS;
    }
    int32_t opt = ctx->info->tradAlg == CRYPT_PKEY_ECDH ?
        CRYPT_CTRL_GEN_ECC_PUBLICKEY : CRYPT_CTRL_GEN_X25519_PUBLICKEY;
    return CRYPT_EAL_PkeyCtrl(ctx->tradCtx, opt, NULL, 0);
}

#endif /* HITLS_CRYPTO_COMPOSITE_KEM */
