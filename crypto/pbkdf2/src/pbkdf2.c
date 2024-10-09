/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_PBKDF2

#include <stdint.h>
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_local_types.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "crypt_pbkdf2.h"


#define PBKDF2_MAX_BLOCKSIZE 64
#define PBKDF2_MAX_KEYLEN 0xFFFFFFFF

typedef struct {
    const EAL_MacMethod *macMeth;
    void *macCtx;
    const uint8_t *salt;
    uint32_t saltLen;
    uint32_t iterCnt;
} CRYPT_PBKDF2_Ctx;

int32_t CRYPT_PBKDF2_U1(const CRYPT_PBKDF2_Ctx *pCtx, uint32_t blockCount, uint8_t *u, uint32_t *blockSize)
{
    int32_t ret;
    const EAL_MacMethod *macMeth = pCtx->macMeth;
    void *macCtx = pCtx->macCtx;
    (void)macMeth->reinit(macCtx);
    if ((ret = macMeth->update(macCtx, pCtx->salt, pCtx->saltLen)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    /* processing the big endian */
    uint32_t blockCnt = CRYPT_HTONL(blockCount);
    if ((ret = macMeth->update(macCtx, (uint8_t *)&blockCnt, sizeof(blockCnt))) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if ((ret = macMeth->final(macCtx, u, blockSize)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_PBKDF2_Un(const CRYPT_PBKDF2_Ctx *pCtx, uint8_t *u, uint32_t *blockSize, uint8_t *t, uint32_t tLen)
{
    int32_t ret;
    const EAL_MacMethod *macMeth = pCtx->macMeth;
    void *macCtx = pCtx->macCtx;

    macMeth->reinit(macCtx);
    if ((ret = macMeth->update(macCtx, u, *blockSize)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if ((ret = macMeth->final(macCtx, u, blockSize)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    DATA_XOR(t, u, t, tLen);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_PBKDF2_CalcT(const CRYPT_PBKDF2_Ctx *pCtx, uint32_t blockCount, uint8_t *t, uint32_t *tlen)
{
    uint8_t u[PBKDF2_MAX_BLOCKSIZE] = {0};
    uint8_t tmpT[PBKDF2_MAX_BLOCKSIZE] = {0};
    uint32_t blockSize = PBKDF2_MAX_BLOCKSIZE;
    int32_t ret;
    uint32_t iterCnt = pCtx->iterCnt;
    /* U1 = PRF(Password, Salt + INT_32_BE(i))
       tmpT = U1 */
    ret = CRYPT_PBKDF2_U1(pCtx, blockCount, u, &blockSize);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    (void)memcpy_s(tmpT, PBKDF2_MAX_BLOCKSIZE, u, blockSize);
    for (uint32_t un = 1; un < iterCnt; un++) {
        /* t = t ^ Un */
        ret = CRYPT_PBKDF2_Un(pCtx, u, &blockSize, tmpT, blockSize);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    uint32_t len = (*tlen > blockSize) ? blockSize : (*tlen);
    (void)memcpy_s(t, *tlen, tmpT, len);
    *tlen = len;
    BSL_SAL_CleanseData(u, PBKDF2_MAX_BLOCKSIZE);
    BSL_SAL_CleanseData(tmpT, PBKDF2_MAX_BLOCKSIZE);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_PBKDF2_GenDk(const CRYPT_PBKDF2_Ctx *pCtx, const uint8_t *key, uint32_t keyLen, uint8_t *dk,
    uint32_t dkLen)
{
    uint32_t curLen;
    uint8_t *t = dk;
    uint32_t tlen;
    uint32_t i;
    int32_t ret;

    ret = pCtx->macMeth->init(pCtx->macCtx, key, keyLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    /* DK = T1 + T2 + ⋯ + Tdklen/hlen */
    for (i = 1, curLen = dkLen; curLen > 0; i++) {
        tlen = curLen;
        ret = CRYPT_PBKDF2_CalcT(pCtx, i, t, &tlen);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        curLen -= tlen;
        t += tlen;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_PBKDF2_HMAC(const EAL_MacMethod *macMeth, const EAL_MdMethod *mdMeth,
    const uint8_t *key, uint32_t keyLen,
    const uint8_t *salt, uint32_t saltLen,
    uint32_t iterCnt, uint8_t *out, uint32_t len)
{
    int32_t ret;
    CRYPT_PBKDF2_Ctx pCtx;

    if (macMeth == NULL || mdMeth == NULL || out == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (key == NULL && keyLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    // add keyLen limit based on rfc2898
    if (mdMeth->mdSize == 0 || (keyLen / mdMeth->mdSize) >= PBKDF2_MAX_KEYLEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_PBKDF2_PARAM_ERROR);
        return CRYPT_PBKDF2_PARAM_ERROR;
    }
    if (salt == NULL && saltLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if ((len == 0) || (iterCnt == 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_PBKDF2_PARAM_ERROR);
        return CRYPT_PBKDF2_PARAM_ERROR;
    }

    void *macCtx = BSL_SAL_Malloc(macMeth->ctxSize);
    if (macCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    ret = macMeth->initCtx(macCtx, mdMeth);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_FREE(macCtx);
        return ret;
    }

    pCtx.macMeth = macMeth;
    pCtx.macCtx = macCtx;
    pCtx.salt = salt;
    pCtx.saltLen = saltLen;
    pCtx.iterCnt = iterCnt;
    ret = CRYPT_PBKDF2_GenDk(&pCtx, key, keyLen, out, len);

    macMeth->deinit(macCtx);
    macMeth->deinitCtx(macCtx);
    BSL_SAL_FREE(macCtx);
    return ret;
}
#endif // HITLS_CRYPTO_PBKDF2
