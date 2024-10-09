/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_KDFTLS12

#include <stdint.h>
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_local_types.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "crypt_kdf_tls12.h"

#define KDFTLS12_MAX_BLOCKSIZE 64

typedef struct {
    const EAL_MacMethod *macMeth;
    const EAL_MdMethod *mdMeth;
    const uint8_t *key;
    uint32_t keyLen;
    const uint8_t *label;
    uint32_t labelLen;
    const uint8_t *seed;
    uint32_t seedLen;
} CRYPT_KDF_Info;

int32_t KDF_Hmac(const EAL_MacMethod *macMeth, void *macCtx, uint8_t *data, uint32_t *len)
{
    int32_t ret;
    macMeth->reinit(macCtx);
    ret = macMeth->update(macCtx, data, *len);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = macMeth->final(macCtx, data, len);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return CRYPT_SUCCESS;
}

// algorithm implementation see https://datatracker.ietf.org/doc/pdf/rfc5246.pdf, chapter 5, p_hash function
int32_t KDF_PHASH(const CRYPT_KDF_Info *kdfInfo, uint8_t *out, uint32_t len)
{
    int32_t ret;
    const EAL_MacMethod *macMeth = kdfInfo->macMeth;
    const EAL_MdMethod *mdMeth = kdfInfo->mdMeth;
    uint32_t totalLen = 0;
    uint8_t nextIn[KDFTLS12_MAX_BLOCKSIZE];
    uint32_t nextInLen = KDFTLS12_MAX_BLOCKSIZE;
    uint8_t outTmp[KDFTLS12_MAX_BLOCKSIZE];
    uint32_t outTmpLen = KDFTLS12_MAX_BLOCKSIZE;

    void *macCtx = BSL_SAL_Malloc(macMeth->ctxSize);
    if (macCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    (void)memset_s(macCtx, macMeth->ctxSize, 0, macMeth->ctxSize);
    GOTO_ERR_IF(macMeth->initCtx(macCtx, mdMeth), ret);

    while (len > totalLen) {
        if (totalLen == 0) {
            GOTO_ERR_IF(macMeth->init(macCtx, kdfInfo->key, kdfInfo->keyLen), ret);
            GOTO_ERR_IF(macMeth->update(macCtx, kdfInfo->label, kdfInfo->labelLen), ret);
            GOTO_ERR_IF(macMeth->update(macCtx, kdfInfo->seed, kdfInfo->seedLen), ret);
            GOTO_ERR_IF(macMeth->final(macCtx, nextIn, &nextInLen), ret);
        } else {
            GOTO_ERR_IF(KDF_Hmac(macMeth, macCtx, nextIn, &nextInLen), ret);
        }

        macMeth->reinit(macCtx);
        GOTO_ERR_IF(macMeth->update(macCtx, nextIn, nextInLen), ret);
        GOTO_ERR_IF(macMeth->update(macCtx, kdfInfo->label, kdfInfo->labelLen), ret);
        GOTO_ERR_IF(macMeth->update(macCtx, kdfInfo->seed, kdfInfo->seedLen), ret);
        GOTO_ERR_IF(macMeth->final(macCtx, outTmp, &outTmpLen), ret);

        uint32_t cpyLen = outTmpLen > (len - totalLen) ? (len - totalLen) : outTmpLen;
        (void)memcpy_s(out + totalLen, len - totalLen, outTmp, cpyLen);
        totalLen += cpyLen;
    }

ERR:
    macMeth->deinit(macCtx);
    macMeth->deinitCtx(macCtx);
    BSL_SAL_FREE(macCtx);
    return ret;
}

int32_t CRYPT_KDF_TLS12(const EAL_MacMethod *macMeth, const EAL_MdMethod *mdMeth, const uint8_t *key, uint32_t keyLen,
    const uint8_t *label, uint32_t labelLen, const uint8_t *seed, uint32_t seedLen, uint8_t *out, uint32_t len)
{
    if (macMeth == NULL || mdMeth == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (key == NULL && keyLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (label == NULL && labelLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (seed == NULL && seedLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if ((out == NULL) || (len == 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    CRYPT_KDF_Info kdfInfo;
    kdfInfo.macMeth = macMeth;
    kdfInfo.mdMeth = mdMeth;
    kdfInfo.key = key;
    kdfInfo.keyLen = keyLen;
    kdfInfo.label = label;
    kdfInfo.labelLen = labelLen;
    kdfInfo.seed = seed;
    kdfInfo.seedLen = seedLen;

    return KDF_PHASH(&kdfInfo, out, len);
}
#endif // HITLS_CRYPTO_KDFTLS12
