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
#define HMAC_MAX_BLEN 144

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

static int32_t RecConnCbcDecCheckPaddingEtM(TLS_Ctx *ctx, const REC_TextInput *cryptMsg, uint8_t *plain,
    uint32_t plainLen, uint32_t offset)
{
#ifdef HITLS_BSL_LOG
    const RecConnState *state = ctx->recCtx->readStates.currentState;
#else
    (void)offset;
#endif
    uint8_t padLen = plain[plainLen - 1];

    if (cryptMsg->isEncryptThenMac && (plainLen < padLen + CBC_PADDING_LEN_TAG_SIZE)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15399, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "record cbc mode decrypt error: ciphertext len = %u, plaintext len = %u, mac len = %u, padding len = %u.",
            cryptMsg->textLen - offset - state->suiteInfo->macLen, plainLen, state->suiteInfo->macLen, padLen);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
    }

    for (uint32_t i = 1; i <= padLen; i++) {
        if (plain[plainLen - 1 - i] != padLen) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15400, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "record cbc mode decrypt error: padding len = %u, %u-to-last padding data = %u.",
                padLen, i, plain[plainLen - 1 - i], 0);
            return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
        }
    }
    return HITLS_SUCCESS;
}

static uint32_t GetHmacBLen(HITLS_MacAlgo macAlgo)
{
    switch (macAlgo) {
        case HITLS_MAC_1:
        case HITLS_MAC_224:
        case HITLS_MAC_256:
        case HITLS_MAC_SM3:
            return 64; // Blen of upper hmac is 64.
        case HITLS_MAC_384:
        case HITLS_MAC_512:
            return 128; // Blen of upper hmac is 128.
        default:
            // should never be here.
            return 0;
    }
}

/**
 * a constant-time implemenation of HMAC to prevent side-channel attacks
 * reference: https://datatracker.ietf.org/doc/html/rfc2104#autoid-2
 */

static int32_t ConstTimeHmac(RecConnSuitInfo *suiteInfo, HITLS_HASH_Ctx **hashCtx, uint32_t good,
    const REC_TextInput *cryptMsg, uint8_t *data, uint32_t dataLen, uint8_t *mac, uint32_t *macLen)
{
    HITLS_HASH_Ctx *obCtx = hashCtx[2]; // the 2-th is the obscure hash context.
    uint32_t padLen = data[dataLen - 1];
    padLen = Uint32ConstTimeSelect(good, padLen, 0);
    uint32_t plainLen = dataLen - (suiteInfo->macLen + padLen + 1);
    plainLen = Uint32ConstTimeSelect(good, plainLen, 0);

    uint32_t blen = GetHmacBLen(suiteInfo->macAlg);
    uint8_t ipad[HMAC_MAX_BLEN] = {0};
    uint8_t opad[HMAC_MAX_BLEN * 2] = {0}; // opad need 2 Blen.
    uint8_t key[HMAC_MAX_BLEN] = {0};
    uint8_t ihash[MAX_DIGEST_SIZE] = {0};
    uint32_t ihashLen = sizeof(ihash);
    (void)memcpy_s(key, sizeof(key), suiteInfo->macKey, suiteInfo->macKeyLen);
    for (uint32_t i = 0; i < blen; i++) {
        ipad[i] = key[i] ^ 0x36;
        opad[i] = key[i] ^ 0x5c;
    }

    // update K xor ipad
    (void)SAL_CRYPT_DigestUpdate(hashCtx[0], ipad, blen);
    // update the obscureHashCtx simultaneously
    (void)SAL_CRYPT_DigestUpdate(obCtx, ipad, blen);

    /**
     * constant-time update plaintext to resist lucky13
     * ref: https://www.isg.rhul.ac.uk/tls/TLStiming.pdf
     */
    uint8_t header[13] = {0}; // seq + record type = 13 bytes
    uint32_t pos = 0;
    (void)memcpy_s(header, sizeof(header), cryptMsg->seq, REC_CONN_SEQ_SIZE);
    pos += REC_CONN_SEQ_SIZE;
    header[pos++] = cryptMsg->type;
    BSL_Uint16ToByte(cryptMsg->version, header + pos);
    pos += sizeof(uint16_t);
    BSL_Uint16ToByte((uint16_t)plainLen, header + pos);
    (void)SAL_CRYPT_DigestUpdate(hashCtx[0], header, sizeof(header));
    (void)SAL_CRYPT_DigestUpdate(obCtx, header, sizeof(header));

    uint32_t maxLen = dataLen - (suiteInfo->macLen + 1);
    maxLen = Uint32ConstTimeSelect(good, maxLen, dataLen);
    uint32_t flag = Uint32ConstTimeGt(maxLen, 256); // the value of 1 byte is up to 256.
    uint32_t minLen = Uint32ConstTimeSelect(flag, maxLen - 256, 0); // the value of 1 byte is up to 256.

    (void)SAL_CRYPT_DigestUpdate(hashCtx[0], data, minLen);
    (void)SAL_CRYPT_DigestUpdate(obCtx, data, minLen);

    for (uint32_t i = minLen; i < maxLen; i++) {
        if (i < plainLen) {
            SAL_CRYPT_DigestUpdate(hashCtx[0], data + i, 1);
        } else {
            SAL_CRYPT_DigestUpdate(obCtx, data + i, 1);
        }
    }
    (void)SAL_CRYPT_DigestFinal(hashCtx[0], ihash, &ihashLen);
    (void)memcpy_s(opad + blen, MAX_DIGEST_SIZE, ihash, ihashLen);

    // update (K xor opad) + ihash
    (void)SAL_CRYPT_DigestUpdate(hashCtx[1], opad, blen + ihashLen);
    (void)SAL_CRYPT_DigestFinal(hashCtx[1], mac, macLen);

    BSL_SAL_CleanseData(ipad, sizeof(ipad));
    BSL_SAL_CleanseData(opad, sizeof(opad));
    BSL_SAL_CleanseData(key, sizeof(key));

    return HITLS_SUCCESS;
}

static inline uint32_t ConstTimeSelectMemcmp(uint32_t good, uint8_t *a, uint8_t *b, uint32_t l)
{
    uint8_t *t = (good == 0) ? b : a;
    return ConstTimeMemcmp(t, b, l);
}

static int32_t RecConnCbcDecMtECheckMacTls(TLS_Ctx *ctx, const REC_TextInput *cryptMsg,
    uint8_t *plain, uint32_t plainLen)
{
    uint32_t tempPlainLen = plainLen;
    const RecConnState *state = ctx->recCtx->readStates.currentState;
    uint32_t hashAlg = RecGetHashAlgoFromMacAlgo(state->suiteInfo->macAlg);
    if (hashAlg == HITLS_HASH_BUTT) {
        return HITLS_CRYPT_ERR_HMAC;
    }
    
    HITLS_HASH_Ctx *ihashCtx = NULL;
    HITLS_HASH_Ctx *ohashCtx = NULL;
    HITLS_HASH_Ctx *obscureHashCtx = NULL;
    ihashCtx = SAL_CRYPT_DigestInit(LIBCTX_FROM_CTX(ctx), ATTRIBUTE_FROM_CTX(ctx), hashAlg);
    ohashCtx = SAL_CRYPT_DigestCopy(ihashCtx);
    obscureHashCtx = SAL_CRYPT_DigestCopy(ihashCtx);
    if (ihashCtx == NULL || ohashCtx == NULL || obscureHashCtx == NULL) {
        SAL_CRYPT_DigestFree(ihashCtx);
        SAL_CRYPT_DigestFree(ohashCtx);
        SAL_CRYPT_DigestFree(obscureHashCtx);
        return HITLS_REC_ERR_GENERATE_MAC;
    }

    uint8_t mac[MAX_DIGEST_SIZE] = {0};
    uint32_t macLen = sizeof(mac);
    uint8_t padLen = plain[tempPlainLen - 1];

    uint32_t good = Uint32ConstTimeGe(tempPlainLen, state->suiteInfo->macLen + padLen + 1);

    // constant-time check padding bytes
    for (uint32_t i = 1; i <= 255; i++) {
        uint32_t mask = good & Uint32ConstTimeLe(i, padLen);
        good &= Uint32ConstTimeEqual(plain[tempPlainLen - 1 - (i & mask)], padLen);
    }

    HITLS_HASH_Ctx *hashCtxs[3] = {ihashCtx, ohashCtx, obscureHashCtx};
    ConstTimeHmac(state->suiteInfo, hashCtxs, good, cryptMsg, plain, tempPlainLen, mac, &macLen);

    // check mac
    uint32_t retLen = Uint32ConstTimeSelect(good, padLen, 0);
    tempPlainLen -= state->suiteInfo->macLen + retLen + 1;
    good &= ConstTimeSelectMemcmp(good, &plain[tempPlainLen], mac, macLen);
    SAL_CRYPT_DigestFree(ihashCtx);
    SAL_CRYPT_DigestFree(ohashCtx);
    SAL_CRYPT_DigestFree(obscureHashCtx);
    return ~good;
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

    ret = SAL_CRYPT_Decrypt(LIBCTX_FROM_CTX(ctx), ATTRIBUTE_FROM_CTX(ctx),
        &cipherParam, &cryptMsg->text[offset], cryptMsg->textLen - offset, data, &plaintextLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15398, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "record cbc mode decrypt error.", 0, 0, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
    }

    /* Check padding and padding length */
    ret = RecConnCbcDecMtECheckMacTls(ctx, cryptMsg, data, plaintextLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17244, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "RecConnCbcDecMtECheckMacTls fail", 0, 0, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
    }
    *dataLen = plaintextLen - (state->suiteInfo->macLen + data[plaintextLen - 1] + CBC_PADDING_LEN_TAG_SIZE);
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

    ret = SAL_CRYPT_Decrypt(LIBCTX_FROM_CTX(ctx), ATTRIBUTE_FROM_CTX(ctx),
        &cipherParam, &cryptMsg->text[offset],
        cryptMsg->textLen - offset - macLen, data, &plaintextLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15915, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "record cbc mode decrypt error.", 0, 0, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
    }

    /* Check padding and padding length */
    uint8_t paddingLen = data[plaintextLen - 1];
    ret = RecConnCbcDecCheckPaddingEtM(ctx, cryptMsg, data, plaintextLen, offset);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17247, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "RecConnCbcDecCheckPaddingEtM fail", 0, 0, 0, 0);
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

static int32_t RecConnCopyIV(TLS_Ctx *ctx, const RecConnState *state, uint8_t *cipherText, uint32_t cipherTextLen)
{
    if (!state->suiteInfo->isExportIV) {
        SAL_CRYPT_Rand(LIBCTX_FROM_CTX(ctx), state->suiteInfo->iv, state->suiteInfo->fixedIvLength);
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
static int32_t GenerateCbcPlainTextAfterMac(HITLS_Lib_Ctx *libCtx, const char *attrName,
    const RecConnState *state, const REC_TextInput *plainMsg,
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
    int32_t ret = RecConnGenerateMac(libCtx, attrName, state->suiteInfo,
        &input, &plainText[plainTextLen], &macLen);
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

static int32_t RecConnCbcEncryptThenMac(
    TLS_Ctx *ctx, const RecConnState *state, const REC_TextInput *plainMsg, uint8_t *cipherText, uint32_t cipherTextLen)
{
    uint32_t offset = 0;
    uint8_t *plainText = NULL;
    uint32_t plainTextLen = 0;

    int32_t ret = PreparePlainText(state, plainMsg, cipherTextLen, &plainText, &plainTextLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = RecConnCopyIV(ctx, state, cipherText, cipherTextLen);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(plainText);
        return ret;
    }
    offset += state->suiteInfo->fixedIvLength;

    uint32_t macLen = state->suiteInfo->macLen;
    uint32_t encLen = cipherTextLen - offset - macLen;
    HITLS_CipherParameters cipherParam = {0};
    RecConnInitCipherParam(&cipherParam, state);
    ret = SAL_CRYPT_Encrypt(LIBCTX_FROM_CTX(ctx), ATTRIBUTE_FROM_CTX(ctx),
        &cipherParam, plainText, plainTextLen, &cipherText[offset], &encLen);
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
    return RecConnGenerateMac(LIBCTX_FROM_CTX(ctx), ATTRIBUTE_FROM_CTX(ctx),
        state->suiteInfo, &input, &cipherText[offset + encLen], &macLen);
}

int32_t RecConnCbcMacThenEncrypt(
    TLS_Ctx *ctx, const RecConnState *state, const REC_TextInput *plainMsg, uint8_t *cipherText, uint32_t cipherTextLen)
{
    uint32_t plainTextLen = 0;
    uint8_t *plainText = BSL_SAL_Calloc(1u, cipherTextLen);
    if (plainText == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15390, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record CBC encrypt error: out of memory.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    int32_t ret = GenerateCbcPlainTextAfterMac(LIBCTX_FROM_CTX(ctx), ATTRIBUTE_FROM_CTX(ctx),
        state, plainMsg, cipherTextLen, plainText, &plainTextLen);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(plainText);
        return ret;
    }
    uint32_t offset = 0;
    ret = RecConnCopyIV(ctx, state, cipherText, cipherTextLen);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(plainText);
        return ret;
    }
    offset += state->suiteInfo->fixedIvLength;

    uint32_t encLen = cipherTextLen - offset;
    HITLS_CipherParameters cipherParam = {0};
    RecConnInitCipherParam(&cipherParam, state);
    ret = SAL_CRYPT_Encrypt(LIBCTX_FROM_CTX(ctx), ATTRIBUTE_FROM_CTX(ctx),
        &cipherParam, plainText, plainTextLen, &cipherText[offset], &encLen);
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

static int32_t CbcEncrypt(TLS_Ctx *ctx, RecConnState *state, const REC_TextInput *plainMsg, uint8_t *cipherText,
    uint32_t cipherTextLen)
{
    if (plainMsg->isEncryptThenMac) {
        return RecConnCbcEncryptThenMac(ctx, state, plainMsg, cipherText, cipherTextLen);
    }
    return RecConnCbcMacThenEncrypt(ctx, state, plainMsg, cipherText, cipherTextLen);
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