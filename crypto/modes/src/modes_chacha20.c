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
#ifdef HITLS_CRYPTO_CHACHA20

#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_modes_chacha20.h"
#include "modes_local.h"

static int32_t Chacha20CipherCtrl(MODES_CipherCommonCtx *commonCtx, int32_t cmd, void *val, uint32_t valLen)
{
    if (commonCtx == NULL || commonCtx->ciphMeth == NULL || commonCtx->ciphMeth->cipherCtrl == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return commonCtx->ciphMeth->cipherCtrl(commonCtx->ciphCtx, cmd, val, valLen);
}

static int32_t Chacha20SetCounter(MODES_CipherCtx *modeCtx, const uint8_t *counter, uint32_t counterLen)
{
    return Chacha20CipherCtrl(&modeCtx->commonCtx, CRYPT_CTRL_SET_COUNT, (void *)(uintptr_t)counter, counterLen);
}

static int32_t Chacha20SetIv(MODES_CipherCtx *modeCtx, const uint8_t *iv, uint32_t ivLen)
{
    return Chacha20CipherCtrl(&modeCtx->commonCtx, CRYPT_CTRL_SET_IV, (void *)(uintptr_t)iv, ivLen);
}

static int32_t Chacha20SetCounterZero(MODES_CipherCtx *modeCtx)
{
    uint8_t counter[sizeof(uint32_t)] = {0};
    return Chacha20SetCounter(modeCtx, counter, sizeof(counter));
}

static int32_t Chacha20CheckMethod(const MODES_CipherCtx *modeCtx)
{
    if (modeCtx == NULL || modeCtx->commonCtx.ciphMeth == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return CRYPT_SUCCESS;
}

int32_t MODES_CHACHA20_InitCtx(MODES_CipherCtx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, void *param, bool enc)
{
    (void)param;
    int32_t ret = Chacha20CheckMethod(modeCtx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    modeCtx->enc = enc;
    SetEncryptKey setKey = enc ? modeCtx->commonCtx.ciphMeth->setEncryptKey :
        modeCtx->commonCtx.ciphMeth->setDecryptKey;
    if (setKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    ret = setKey(modeCtx->commonCtx.ciphCtx, key, keyLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = Chacha20SetIv(modeCtx, iv, ivLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return Chacha20SetCounterZero(modeCtx);
}

int32_t MODES_CHACHA20_Update(MODES_CipherCtx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out,
    uint32_t *outLen)
{
    int32_t ret = Chacha20CheckMethod(modeCtx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    EncryptBlock cryptBlock =
        modeCtx->enc ? modeCtx->commonCtx.ciphMeth->encryptBlock : modeCtx->commonCtx.ciphMeth->decryptBlock;
    if (cryptBlock == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return MODES_CipherStreamProcess(cryptBlock, modeCtx->commonCtx.ciphCtx, in, inLen, out, outLen);
}

int32_t MODES_CHACHA20_Final(MODES_CipherCtx *modeCtx, uint8_t *out, uint32_t *outLen)
{
    if (outLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    (void)modeCtx;
    (void)out;
    *outLen = 0;
    return CRYPT_SUCCESS;
}

int32_t MODES_CHACHA20_Ctrl(MODES_CipherCtx *modeCtx, int32_t cmd, void *val, uint32_t valLen)
{
    if (modeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (cmd) {
        case CRYPT_CTRL_GET_BLOCKSIZE:
            if (val == NULL || valLen != sizeof(uint32_t)) {
                return CRYPT_INVALID_ARG;
            }
            *(uint32_t *)val = 1;
            return CRYPT_SUCCESS;
        case CRYPT_CTRL_REINIT_STATUS: {
            BSL_SAL_CleanseData(modeCtx->data, EAL_MAX_BLOCK_LENGTH);
            modeCtx->dataLen = 0;
            modeCtx->pad = CRYPT_PADDING_NONE;
            int32_t ret = Chacha20SetIv(modeCtx, val, valLen);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
            return Chacha20SetCounterZero(modeCtx);
        }
        default:
            return Chacha20CipherCtrl(&modeCtx->commonCtx, cmd, val, valLen);
    }
}

#endif // HITLS_CRYPTO_CHACHA20
