/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_HKDF

#include <stdint.h>
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_local_types.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "crypt_hkdf.h"

#define HKDF_MAX_HMACSIZE 64

int32_t CRYPT_HKDF_Extract(const EAL_MacMethod *macMeth, const EAL_MdMethod *mdMeth, const uint8_t *key,
    uint32_t keyLen, const uint8_t *salt, uint32_t saltLen, uint8_t *prk, uint32_t *prkLen)
{
    int32_t ret;
    if (macMeth == NULL || mdMeth == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (key == NULL && keyLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (salt == NULL && saltLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    void *macCtx = BSL_SAL_Malloc(macMeth->ctxSize);
    if (macCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    (void)memset_s(macCtx, macMeth->ctxSize, 0, macMeth->ctxSize);

    GOTO_ERR_IF(macMeth->initCtx(macCtx, mdMeth), ret);
    GOTO_ERR_IF(macMeth->init(macCtx, salt, saltLen), ret);
    GOTO_ERR_IF(macMeth->update(macCtx, key, keyLen), ret);
    GOTO_ERR_IF(macMeth->final(macCtx, prk, prkLen), ret);

ERR:
    macMeth->deinit(macCtx);
    macMeth->deinitCtx(macCtx);
    BSL_SAL_FREE(macCtx);
    return ret;
}

static int32_t HKDF_ExpandParamCheck(const EAL_MacMethod *macMeth, const EAL_MdMethod *mdMeth, const uint8_t *prk,
    uint32_t prkLen, const uint8_t *info, uint32_t infoLen, const uint8_t *out, uint32_t outLen)
{
    if (macMeth == NULL || mdMeth == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (prk == NULL && prkLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (info == NULL && infoLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if ((out == NULL) || (outLen == 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (mdMeth->mdSize == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_HKDF_PARAM_ERROR);
        return CRYPT_HKDF_PARAM_ERROR;
    }
    /* len cannot be larger than 255 * hashLen */
    if (outLen > (uint32_t)mdMeth->mdSize * 255) {
        BSL_ERR_PUSH_ERROR(CRYPT_HKDF_DKLEN_OVERFLOW);
        return CRYPT_HKDF_DKLEN_OVERFLOW;
    }

    return CRYPT_SUCCESS;
}

int32_t CRYPT_HKDF_Expand(const EAL_MacMethod *macMeth, const EAL_MdMethod *mdMeth, const uint8_t *prk, uint32_t prkLen,
    const uint8_t *info, uint32_t infoLen, uint8_t *out, uint32_t outLen)
{
    int32_t ret = HKDF_ExpandParamCheck(macMeth, mdMeth, prk, prkLen, info, infoLen, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    uint8_t hash[HKDF_MAX_HMACSIZE];
    uint32_t hashLen = mdMeth->mdSize;
    uint8_t counter = 1;
    uint32_t totalLen = 0;
    uint32_t n;
    void *macCtx = BSL_SAL_Malloc(macMeth->ctxSize);
    if (macCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    GOTO_ERR_IF(macMeth->initCtx(macCtx, mdMeth), ret);
    GOTO_ERR_IF(macMeth->init(macCtx, prk, prkLen), ret);

    /* ceil(a / b) = (a + b - 1) / b */
    n = (outLen + hashLen - 1) / hashLen;
    for (uint32_t i = 1; i <= n; i++, counter++) {
        if (i > 1) {
            macMeth->reinit(macCtx);
            GOTO_ERR_IF(macMeth->update(macCtx, hash, hashLen), ret);
        }
        GOTO_ERR_IF(macMeth->update(macCtx, info, infoLen), ret);
        GOTO_ERR_IF(macMeth->update(macCtx, &counter, 1), ret);
        GOTO_ERR_IF(macMeth->final(macCtx, hash, &hashLen), ret);
        hashLen = hashLen > (outLen - totalLen) ? (outLen - totalLen) : hashLen;
        (void)memcpy_s(out + totalLen, outLen - totalLen, hash, hashLen);
        totalLen += hashLen;
    }

ERR:
    macMeth->deinit(macCtx);
    macMeth->deinitCtx(macCtx);
    BSL_SAL_FREE(macCtx);
    return ret;
}

int32_t CRYPT_HKDF(const EAL_MacMethod *macMeth, const EAL_MdMethod *mdMeth, const uint8_t *key, uint32_t keyLen,
    const uint8_t *salt, uint32_t saltLen, const uint8_t *info, uint32_t infoLen, uint8_t *out, uint32_t len)
{
    int ret;
    uint8_t prk[HKDF_MAX_HMACSIZE];
    uint32_t prkLen = HKDF_MAX_HMACSIZE;
    ret = CRYPT_HKDF_Extract(macMeth, mdMeth, key, keyLen, salt, saltLen, prk, &prkLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = CRYPT_HKDF_Expand(macMeth, mdMeth, prk, prkLen, info, infoLen, out, len);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return CRYPT_SUCCESS;
}
#endif // HITLS_CRYPTO_HKDF
