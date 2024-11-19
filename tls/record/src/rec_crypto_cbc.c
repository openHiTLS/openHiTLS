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
#ifdef HITLS_TLS_SUITE_CIPHER_CBC
#include "securec.h"
#include "hitls_error.h"
#include "bsl_err_internal.h"
#include "bsl_log_internal.h"
#include "tls_binlog_id.h"
#include "bsl_bytes.h"
#include "crypt.h"
#include "rec_alert.h"
#include "rec_conn.h"
#include "record.h"
#include "rec_crypto_cbc.h"

#define CBC_PADDING_LEN_TAG_SIZE 1u

uint8_t RecConnGetCbcPaddingLen(uint8_t blockLen, uint32_t plaintextLen)
{
    if (blockLen == 0) {
        return 0;
    }
    uint8_t remainder = (plaintextLen + CBC_PADDING_LEN_TAG_SIZE) % blockLen;
    if (remainder == 0) {
        return 0;
    }
    return blockLen - remainder;
}

static uint32_t CbcCalCiphertextLen(const TLS_Ctx *ctx, RecConnSuitInfo *suiteInfo, uint32_t plantextLen, bool isRead)
{
    uint32_t ciphertextLen = plantextLen;
    ciphertextLen += suiteInfo->recordIvLength;
    bool isEncryptThenMac = isRead ?
        ctx->negotiatedInfo.isEncryptThenMacRead : ctx->negotiatedInfo.isEncryptThenMacWrite;
    if (isEncryptThenMac) {
        ciphertextLen += RecConnGetCbcPaddingLen(suiteInfo->blockLength, ciphertextLen) + CBC_PADDING_LEN_TAG_SIZE;
        ciphertextLen += suiteInfo->macLen;
    } else {
        ciphertextLen += suiteInfo->macLen;
        ciphertextLen += RecConnGetCbcPaddingLen(suiteInfo->blockLength, ciphertextLen) + CBC_PADDING_LEN_TAG_SIZE;
    }
    return ciphertextLen;
}

static int32_t CbcCalPlantextBufLen(TLS_Ctx *ctx, RecConnSuitInfo *suiteInfo,
    uint32_t ciphertextLen, uint32_t *offset, uint32_t *plainLen)
{
    uint32_t plantextLen = ciphertextLen;
    *offset = suiteInfo->recordIvLength;
    plantextLen -= *offset;
    if (ctx->negotiatedInfo.isEncryptThenMacRead) {
        plantextLen -= suiteInfo->macLen;
    }
    if (plantextLen > ciphertextLen) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17242, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "plantextLen err", 0, 0, 0, 0);
        return HITLS_INVALID_INPUT;
    }
    *plainLen = plantextLen;
    return HITLS_SUCCESS;
}

static void RecConnInitCipherParam(HITLS_CipherParameters *cipherParam, const RecConnState *state)
{
    cipherParam->ctx = &state->suiteInfo->ctx;
    cipherParam->type = state->suiteInfo->cipherType;
    cipherParam->algo = state->suiteInfo->cipherAlg;
    cipherParam->key = state->suiteInfo->key;
    cipherParam->keyLen = state->suiteInfo->encKeyLen;
    cipherParam->iv = state->suiteInfo->iv;
    cipherParam->ivLen = state->suiteInfo->fixedIvLength;
}


static int32_t RecConnCbcCheckCryptMsg(TLS_Ctx *ctx, const RecConnState *state, const REC_TextInput *cryptMsg,
    bool isEncryptThenMac)
{
    uint8_t offset = 0;
    if (isEncryptThenMac) {
        offset = state->suiteInfo->macLen;
    }
    if ((state->suiteInfo->blockLength == 0) || ((cryptMsg->textLen - offset) % state->suiteInfo->blockLength != 0)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15397, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "record cbc mode decrypt error: block length = %u, cipher text length = %u.",
            state->suiteInfo->blockLength, cryptMsg->textLen, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
    }
    return HITLS_SUCCESS;
}

static int32_t RecConnCbcCheckDecryptPadding(TLS_Ctx *ctx, const REC_TextInput *cryptMsg, uint8_t *data,
    uint32_t plaintextLen, uint32_t offset)
{
    const RecConnState *state = ctx->recCtx->readStates.currentState;
    uint8_t mac[MAX_DIGEST_SIZE] = {0};
    uint32_t macLen = MAX_DIGEST_SIZE;
    uint8_t paddingLen = data[plaintextLen - 1];

#ifdef HITLS_TLS_FEATURE_ETM
    if (cryptMsg->isEncryptThenMac && (plaintextLen < paddingLen + CBC_PADDING_LEN_TAG_SIZE)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15399, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "record cbc mode decrypt error: ciphertext len = %u, plaintext len = %u, mac len = %u, padding len = %u.",
            cryptMsg->textLen - offset - state->suiteInfo->macLen, plaintextLen, state->suiteInfo->macLen, paddingLen);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
    }
#endif
    if ((plaintextLen < state->suiteInfo->macLen + paddingLen + CBC_PADDING_LEN_TAG_SIZE)
#ifdef HITLS_TLS_FEATURE_ETM
        && !cryptMsg->isEncryptThenMac
#endif
        ) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15928, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "record cbc mode decrypt error: ciphertext len = %u, plaintext len = %u, mac len = %u, padding len = %u.",
            cryptMsg->textLen - offset, plaintextLen, state->suiteInfo->macLen, paddingLen);
        /* Anti-side channel attack: Calculate the MAC address even if the padding is incorrect */
        (void)RecConnGenerateMac(state->suiteInfo, cryptMsg, mac, &macLen);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
    }

    for (uint32_t i = 1; i <= paddingLen; i++) {
        if (data[plaintextLen - 1 - i] != paddingLen) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15400, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "record cbc mode decrypt error: padding len = %u, %u-to-last padding data = %u.",
                paddingLen, i, data[plaintextLen - 1 - i], 0);
            /* Anti-side channel attack: Calculate the MAC address even if the padding is incorrect */
#ifdef HITLS_TLS_FEATURE_ETM
            if (!cryptMsg->isEncryptThenMac)
#endif
            {
                (void)RecConnGenerateMac(state->suiteInfo, cryptMsg, mac, &macLen);
            }
            return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
        }
    }
    return HITLS_SUCCESS;
}

static int32_t RecConnCbcDecryptByMacThenEncrypt(TLS_Ctx *ctx, const RecConnState *state, const REC_TextInput *cryptMsg,
    uint8_t *data, uint32_t *dataLen)
{
    /* Check whether the ciphertext length is an integral multiple of the ciphertext block length */
    int32_t ret = RecConnCbcCheckCryptMsg(ctx, state, cryptMsg, false);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17243, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "RecConnCbcCheckCryptMsg fail", 0, 0, 0, 0);
        return ret;
    }

    /* Decryption start position */
    uint32_t offset = 0;
    /* plaintext length */
    uint32_t plaintextLen = *dataLen;
    HITLS_CipherParameters cipherParam = {0};
    RecConnInitCipherParam(&cipherParam, state);

    /* In TLS1.1 and later versions, explicit iv is used as the first ciphertext block. Therefore, the first
        * ciphertext block does not need to be decrypted */
    cipherParam.iv = cryptMsg->text;
    offset = state->suiteInfo->fixedIvLength;

    ret = SAL_CRYPT_Decrypt(&cipherParam, &cryptMsg->text[offset], cryptMsg->textLen - offset, data, &plaintextLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15398, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "record cbc mode decrypt error.", 0, 0, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
    }

    /* Check padding and padding length */
    ret = RecConnCbcCheckDecryptPadding(ctx, cryptMsg, data, plaintextLen, offset);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17244, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "RecConnCbcCheckDecryptPadding fail", 0, 0, 0, 0);
        return ret;
    }
    plaintextLen -= data[plaintextLen - 1] + CBC_PADDING_LEN_TAG_SIZE;

    /* Check MAC */
    ret = RecConnCheckMac(ctx, state->suiteInfo, cryptMsg, data, plaintextLen);
    plaintextLen -= state->suiteInfo->macLen;
    *dataLen = plaintextLen;
    return ret;
}


static int32_t RecConnCbcDecryptByEncryptThenMac(TLS_Ctx *ctx, const RecConnState *state, const REC_TextInput *cryptMsg,
    uint8_t *data, uint32_t *dataLen)
{
    /* Check MAC */
    int32_t ret = RecConnCheckMac(ctx, state->suiteInfo, cryptMsg, cryptMsg->text, cryptMsg->textLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17245, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "check mac fail", 0, 0, 0, 0);
        return ret;
    }

    /* Check whether the ciphertext length is an integral multiple of the ciphertext block length */
    ret = RecConnCbcCheckCryptMsg(ctx, state, cryptMsg, true);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17246, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "RecConnCbcCheckCryptMsg fail", 0, 0, 0, 0);
        return ret;
    }

    /* Decryption start position */
    uint32_t offset = 0;
    /* plaintext length */
    uint32_t plaintextLen = *dataLen;
    uint8_t macLen = state->suiteInfo->macLen;
    HITLS_CipherParameters cipherParam = {0};
    RecConnInitCipherParam(&cipherParam, state);

    /* In TLS1.1 and later versions, explicit iv is used as the first ciphertext block. Therefore, the first
        * ciphertext block does not need to be decrypted */
    cipherParam.iv = cryptMsg->text;
    offset = state->suiteInfo->fixedIvLength;

    ret = SAL_CRYPT_Decrypt(&cipherParam, &cryptMsg->text[offset],
        cryptMsg->textLen - offset - macLen, data, &plaintextLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15915, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "record cbc mode decrypt error.", 0, 0, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
    }

    /* Check padding and padding length */
    uint8_t paddingLen = data[plaintextLen - 1];
    ret = RecConnCbcCheckDecryptPadding(ctx, cryptMsg, data, plaintextLen, offset);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17247, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "RecConnCbcCheckDecryptPadding fail", 0, 0, 0, 0);
        return ret;
    }
    *dataLen = plaintextLen - paddingLen - CBC_PADDING_LEN_TAG_SIZE;

    return HITLS_SUCCESS;
}

static int32_t CbcDecrypt(TLS_Ctx *ctx, RecConnState *state, const REC_TextInput *cryptMsg,
    uint8_t *data, uint32_t *dataLen)
{
    uint8_t *decryptData = data;
    uint32_t decryptDataLen = *dataLen;

    int32_t ret;
    if (ctx->negotiatedInfo.isEncryptThenMacRead) {
        ret = RecConnCbcDecryptByEncryptThenMac(ctx, state, cryptMsg, decryptData, &decryptDataLen);
    } else {
        ret = RecConnCbcDecryptByMacThenEncrypt(ctx, state, cryptMsg, decryptData, &decryptDataLen);
    }
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    *dataLen = decryptDataLen;
    return HITLS_SUCCESS;
}

static int32_t RecConnCopyIV(const RecConnState *state, uint8_t *cipherText, uint32_t cipherTextLen)
{
    if (!state->suiteInfo->isExportIV) {
        SAL_CRYPT_Rand(state->suiteInfo->iv, state->suiteInfo->fixedIvLength);
    }
    /* The IV set by the user can only be used once */
    state->suiteInfo->isExportIV = 0;
    if (memcpy_s(cipherText, cipherTextLen, state->suiteInfo->iv, state->suiteInfo->fixedIvLength) != EOK) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15847, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record CBC encrypt error: copy iv fail.", 0, 0, 0, 0);
        return HITLS_MEMCPY_FAIL;
    }
    return HITLS_SUCCESS;
}

/*  Data that needs to be encrypted (do not fill MAC) */
static int32_t GenerateCbcPlainTextBeforeMac(const RecConnState *state, const REC_TextInput *plainMsg,
    uint32_t cipherTextLen, uint8_t *plainText, uint32_t *textLen)
{
    /* fill content */
    if (memcpy_s(plainText, cipherTextLen, plainMsg->text, plainMsg->textLen) != EOK) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15392, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record CBC encrypt error: memcpy plainMsg fail.", 0, 0, 0, 0);
        return HITLS_MEMCPY_FAIL;
    }
    uint32_t plainTextLen = plainMsg->textLen;

    /* fill padding and padding length */
    uint8_t paddingLen = RecConnGetCbcPaddingLen(state->suiteInfo->blockLength, plainTextLen);
    uint32_t count = paddingLen + CBC_PADDING_LEN_TAG_SIZE;
    if (memset_s(&plainText[plainTextLen], cipherTextLen - plainTextLen, paddingLen, count) != EOK) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_ENCRYPT);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15904, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record CBC encrypt error: memset padding fail.", 0, 0, 0, 0);
        return HITLS_REC_ERR_ENCRYPT;
    }
    plainTextLen += count;
    *textLen = plainTextLen;
    return HITLS_SUCCESS;
}

static int32_t PreparePlainText(const RecConnState *state, const REC_TextInput *plainMsg, uint32_t cipherTextLen,
    uint8_t **plainText, uint32_t *plainTextLen)
{
    *plainText = BSL_SAL_Calloc(1u, cipherTextLen);
    if (*plainText == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15927, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record CBC encrypt error: out of memory.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    int32_t ret = GenerateCbcPlainTextBeforeMac(state, plainMsg, cipherTextLen, *plainText, plainTextLen);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(*plainText);
    }
    return ret;
}

/* Data that needs to be encrypted (after filling the mac) */
static int32_t GenerateCbcPlainTextAfterMac(const RecConnState *state, const REC_TextInput *plainMsg,
    uint32_t cipherTextLen, uint8_t *plainText, uint32_t *textLen)
{
    /* Fill content */
    if (memcpy_s(plainText, cipherTextLen, plainMsg->text, plainMsg->textLen) != EOK) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15898, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record CBC encrypt error: memcpy plainMsg fail.", 0, 0, 0, 0);
        return HITLS_MEMCPY_FAIL;
    }
    uint32_t plainTextLen = plainMsg->textLen;

    /* Fill MAC */
    uint32_t macLen = state->suiteInfo->macLen;
    REC_TextInput input = {0};
    RecConnInitGenerateMacInput(plainMsg, plainMsg->text, plainMsg->textLen, &input);
    int32_t ret = RecConnGenerateMac(state->suiteInfo, &input, &plainText[plainTextLen], &macLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17248, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "RecConnGenerateMac fail.", 0, 0, 0, 0);
        return ret;
    }
    plainTextLen += macLen;

    /* Fill padding and padding length */
    uint8_t paddingLen = RecConnGetCbcPaddingLen(state->suiteInfo->blockLength, plainTextLen);
    uint32_t count = paddingLen + CBC_PADDING_LEN_TAG_SIZE;
    if (memset_s(&plainText[plainTextLen], cipherTextLen - plainTextLen, paddingLen, count) != EOK) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_ENCRYPT);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15393, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record CBC encrypt error: memset padding fail.", 0, 0, 0, 0);
        return HITLS_REC_ERR_ENCRYPT;
    }
    plainTextLen += count;
    *textLen = plainTextLen;
    return HITLS_SUCCESS;
}

static int32_t RecConnCbcEncryptThenMac(const RecConnState *state, const REC_TextInput *plainMsg, uint8_t *cipherText,
    uint32_t cipherTextLen)
{
    uint32_t offset = 0;
    uint8_t *plainText = NULL;
    uint32_t plainTextLen = 0;

    int32_t ret = PreparePlainText(state, plainMsg, cipherTextLen, &plainText, &plainTextLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = RecConnCopyIV(state, cipherText, cipherTextLen);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(plainText);
        return ret;
    }
    offset += state->suiteInfo->fixedIvLength;

    uint32_t macLen = state->suiteInfo->macLen;
    uint32_t encLen = cipherTextLen - offset - macLen;
    HITLS_CipherParameters cipherParam = {0};
    RecConnInitCipherParam(&cipherParam, state);
    ret = SAL_CRYPT_Encrypt(&cipherParam, plainText, plainTextLen, &cipherText[offset], &encLen);
    BSL_SAL_FREE(plainText);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15848, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "CBC encrypt record error.", 0, 0, 0, 0);
        return ret;
    }

    if (encLen != (cipherTextLen - offset - macLen)) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_ENCRYPT);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15903, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encrypt record (length) error.", 0, 0, 0, 0);
        return HITLS_REC_ERR_ENCRYPT;
    }

    /* fill MAC */
    REC_TextInput input = {0};
    RecConnInitGenerateMacInput(plainMsg, cipherText, cipherTextLen - macLen, &input);
    return RecConnGenerateMac(state->suiteInfo, &input, &cipherText[offset + encLen], &macLen);
}

int32_t RecConnCbcMacThenEncrypt(const RecConnState *state, const REC_TextInput *plainMsg, uint8_t *cipherText,
    uint32_t cipherTextLen)
{
    uint32_t plainTextLen = 0;
    uint8_t *plainText = BSL_SAL_Calloc(1u, cipherTextLen);
    if (plainText == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15390, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record CBC encrypt error: out of memory.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    int32_t ret = GenerateCbcPlainTextAfterMac(state, plainMsg, cipherTextLen, plainText, &plainTextLen);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(plainText);
        return ret;
    }
    uint32_t offset = 0;
    ret = RecConnCopyIV(state, cipherText, cipherTextLen);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(plainText);
        return ret;
    }
    offset += state->suiteInfo->fixedIvLength;

    uint32_t encLen = cipherTextLen - offset;
    HITLS_CipherParameters cipherParam = {0};
    RecConnInitCipherParam(&cipherParam, state);
    ret = SAL_CRYPT_Encrypt(&cipherParam, plainText, plainTextLen, &cipherText[offset], &encLen);
    BSL_SAL_FREE(plainText);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15391, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "CBC encrypt record error.", 0, 0, 0, 0);
        return ret;
    }

    if (encLen != (cipherTextLen - offset)) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_ENCRYPT);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15922, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encrypt record (length) error.", 0, 0, 0, 0);
        return HITLS_REC_ERR_ENCRYPT;
    }

    return HITLS_SUCCESS;
}

static int32_t CbcEncrypt(RecConnState *state, const REC_TextInput *plainMsg, uint8_t *cipherText,
    uint32_t cipherTextLen)
{
    if (plainMsg->isEncryptThenMac) {
        return RecConnCbcEncryptThenMac(state, plainMsg, cipherText, cipherTextLen);
    }
    return RecConnCbcMacThenEncrypt(state, plainMsg, cipherText, cipherTextLen);
}

const RecCryptoFunc *RecGetCbcCryptoFuncs(DecryptPostProcess decryptPostProcess, EncryptPreProcess encryptPreProcess)
{
    static RecCryptoFunc cryptoFuncCbc = {
        .calCiphertextLen = CbcCalCiphertextLen,
        .calPlantextBufLen = CbcCalPlantextBufLen,
        .decrypt = CbcDecrypt,
        .encryt = CbcEncrypt,
    };
    cryptoFuncCbc.decryptPostProcess = decryptPostProcess;
    cryptoFuncCbc.encryptPreProcess = encryptPreProcess;
    return &cryptoFuncCbc;
}
#endif