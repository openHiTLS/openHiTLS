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
#include "rec_crypto_tls13_hmac.h"
#if defined(HITLS_TLS_SUITE_CIPHER_TLS13_INTEGRITY) && defined(HITLS_TLS_PROTO_TLS13)
#include <string.h>
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "crypt.h"
#include "hitls_error.h"
#include "record.h"
#include "rec_alert.h"
#include "rec_conn.h"

#define TLS13_INTEGRITY_AAD_MAX 13u
#define TLS13_INTEGRITY_NONCE_MAX 64u

static HITLS_HashAlgo Tls13IntegrityMacToHash(HITLS_MacAlgo macAlg)
{
    switch (macAlg) {
        case HITLS_MAC_256:
            return HITLS_HASH_SHA_256;
        case HITLS_MAC_384:
            return HITLS_HASH_SHA_384;
        default:
            return HITLS_HASH_BUTT;
    }
}

/* Reuse suiteInfo->macCtx across records (same pattern as RecConnGenerateMac for CBC). */
static int32_t Tls13IntegrityHmacPrepare(TLS_Ctx *ctx, RecConnSuitInfo *suiteInfo, HITLS_HashAlgo hashAlgo)
{
    if (suiteInfo->macCtx == NULL) {
        suiteInfo->macCtx = SAL_CRYPT_HmacInit(LIBCTX_FROM_CTX(ctx), ATTRIBUTE_FROM_CTX(ctx), hashAlgo,
            suiteInfo->key, suiteInfo->encKeyLen);
        if (suiteInfo->macCtx == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_CRYPT_ERR_HMAC);
            return HITLS_CRYPT_ERR_HMAC;
        }
        return HITLS_SUCCESS;
    }
    int32_t ret = SAL_CRYPT_HmacReInit(suiteInfo->macCtx);
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

/* RFC 8446 5.3 / RFC 9150: XOR padded 64-bit sequence number with static write_iv (variable length). */
static int32_t Tls13IntegrityBuildNonce(const RecConnSuitInfo *suiteInfo, uint8_t *nonce, uint32_t nonceLen,
    const uint8_t *seq, uint8_t seqLen)
{
    if (suiteInfo->recordIvLength != 0u) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_AEAD_NONCE_PARAM);
        return HITLS_REC_ERR_AEAD_NONCE_PARAM;
    }
    if (nonceLen != suiteInfo->fixedIvLength || nonceLen > TLS13_INTEGRITY_NONCE_MAX) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_AEAD_NONCE_PARAM);
        return HITLS_REC_ERR_AEAD_NONCE_PARAM;
    }
    if (seqLen != REC_CONN_SEQ_SIZE || nonceLen < seqLen) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_AEAD_NONCE_PARAM);
        return HITLS_REC_ERR_AEAD_NONCE_PARAM;
    }
    uint32_t padLen = nonceLen - seqLen;
    (void)memset(nonce, 0, padLen);
    (void)memcpy(nonce + padLen, seq, seqLen);
    for (uint32_t i = 0; i < nonceLen; i++) {
        nonce[i] ^= suiteInfo->iv[i];
    }
    return HITLS_SUCCESS;
}

/* TLS 1.3 additional_data = TLSCiphertext.opaque_type || legacy_record_version || TLSCiphertext.length */
static void Tls13IntegrityGetAad(uint8_t *aad, uint32_t *aadLen, const REC_TextInput *input, uint32_t cipherTextLen)
{
    aad[0] = input->type;
    BSL_Uint16ToByte(input->version, &aad[1]);
    BSL_Uint16ToByte((uint16_t)cipherTextLen, &aad[3]);
    *aadLen = 5u;
}

static uint32_t Tls13IntegrityCalCiphertextLen(const TLS_Ctx *ctx, RecConnSuitInfo *suiteInfo, uint32_t plantextLen,
    bool isRead)
{
    (void)ctx;
    (void)isRead;
    return plantextLen + suiteInfo->macLen + suiteInfo->recordIvLength;
}

static int32_t Tls13IntegrityCalPlantextBufLen(TLS_Ctx *ctx, RecConnSuitInfo *suiteInfo, uint32_t ciphertextLen,
    uint32_t *offset, uint32_t *plainLen)
{
    (void)ctx;
    *offset = suiteInfo->recordIvLength;
    uint32_t pLen = ciphertextLen - suiteInfo->macLen - suiteInfo->recordIvLength;
    if (pLen > ciphertextLen) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17241, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "plantextLen err", 0, 0, 0, 0);
        return HITLS_INVALID_INPUT;
    }
    *plainLen = pLen;
    return HITLS_SUCCESS;
}

static int32_t Tls13IntegrityEncrypt(TLS_Ctx *ctx, RecConnState *state, const REC_TextInput *plainMsg,
    uint8_t *cipherText, uint32_t cipherTextLen)
{
    RecConnSuitInfo *suiteInfo = state->suiteInfo;
    uint32_t plainLen = plainMsg->textLen;
    if (cipherTextLen != plainLen + suiteInfo->macLen) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_ENCRYPT);
        return HITLS_REC_ERR_ENCRYPT;
    }

    HITLS_HashAlgo hashAlgo = Tls13IntegrityMacToHash(suiteInfo->macAlg);
    if (hashAlgo == HITLS_HASH_BUTT) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_NOT_SUPPORT_CIPHER);
        return HITLS_REC_ERR_NOT_SUPPORT_CIPHER;
    }

    uint8_t nonce[TLS13_INTEGRITY_NONCE_MAX] = {0};
    uint32_t nonceLen = suiteInfo->fixedIvLength;
    int32_t ret = Tls13IntegrityBuildNonce(suiteInfo, nonce, nonceLen, plainMsg->seq, REC_CONN_SEQ_SIZE);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint8_t aad[TLS13_INTEGRITY_AAD_MAX] = {0};
    uint32_t aadLen = TLS13_INTEGRITY_AAD_MAX;
    Tls13IntegrityGetAad(aad, &aadLen, plainMsg, cipherTextLen);

    (void)memcpy(cipherText, plainMsg->text, plainLen);

    ret = Tls13IntegrityHmacPrepare(ctx, suiteInfo, hashAlgo);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_CleanseData(nonce, TLS13_INTEGRITY_NONCE_MAX);
        return ret;
    }
    HITLS_HMAC_Ctx *hmacCtx = suiteInfo->macCtx;
    ret = SAL_CRYPT_HmacUpdate(hmacCtx, nonce, nonceLen);
    if (ret == HITLS_SUCCESS) {
        ret = SAL_CRYPT_HmacUpdate(hmacCtx, aad, aadLen);
    }
    if (ret == HITLS_SUCCESS) {
        ret = SAL_CRYPT_HmacUpdate(hmacCtx, plainMsg->text, plainLen);
    }
    uint32_t macOutLen = suiteInfo->macLen;
    if (ret == HITLS_SUCCESS) {
        ret = SAL_CRYPT_HmacFinal(hmacCtx, cipherText + plainLen, &macOutLen);
    }
    BSL_SAL_CleanseData(nonce, TLS13_INTEGRITY_NONCE_MAX);
    BSL_SAL_CleanseData(aad, sizeof(aad));
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (macOutLen != suiteInfo->macLen) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_ENCRYPT);
        return HITLS_REC_ERR_ENCRYPT;
    }
    return HITLS_SUCCESS;
}

static int32_t Tls13IntegrityDecrypt(TLS_Ctx *ctx, RecConnState *state, const REC_TextInput *cryptMsg, uint8_t *data,
    uint32_t *dataLen)
{
    RecConnSuitInfo *suiteInfo = state->suiteInfo;
    if (cryptMsg->textLen < suiteInfo->macLen) {
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
    }
    uint32_t plainLen = cryptMsg->textLen - suiteInfo->macLen;
    const uint8_t *recvMac = cryptMsg->text + plainLen;

    HITLS_HashAlgo hashAlgo = Tls13IntegrityMacToHash(suiteInfo->macAlg);
    if (hashAlgo == HITLS_HASH_BUTT) {
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
    }

    uint8_t nonce[TLS13_INTEGRITY_NONCE_MAX] = {0};
    uint32_t nonceLen = suiteInfo->fixedIvLength;
    int32_t ret = Tls13IntegrityBuildNonce(suiteInfo, nonce, nonceLen, cryptMsg->seq, REC_CONN_SEQ_SIZE);
    if (ret != HITLS_SUCCESS) {
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
    }

    uint8_t aad[TLS13_INTEGRITY_AAD_MAX] = {0};
    uint32_t aadLen = TLS13_INTEGRITY_AAD_MAX;
    uint32_t plainDataLen = cryptMsg->textLen;
    Tls13IntegrityGetAad(aad, &aadLen, cryptMsg, plainDataLen);

    uint8_t calcMac[64] = {0};
    uint32_t calcLen = suiteInfo->macLen;
    ret = Tls13IntegrityHmacPrepare(ctx, suiteInfo, hashAlgo);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_CleanseData(nonce, TLS13_INTEGRITY_NONCE_MAX);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
    }
    HITLS_HMAC_Ctx *hmacCtx = suiteInfo->macCtx;
    ret = SAL_CRYPT_HmacUpdate(hmacCtx, nonce, nonceLen);
    if (ret == HITLS_SUCCESS) {
        ret = SAL_CRYPT_HmacUpdate(hmacCtx, aad, aadLen);
    }
    if (ret == HITLS_SUCCESS) {
        ret = SAL_CRYPT_HmacUpdate(hmacCtx, cryptMsg->text, plainLen);
    }
    if (ret == HITLS_SUCCESS) {
        ret = SAL_CRYPT_HmacFinal(hmacCtx, calcMac, &calcLen);
    }
    BSL_SAL_CleanseData(nonce, TLS13_INTEGRITY_NONCE_MAX);
    BSL_SAL_CleanseData(aad, sizeof(aad));
    if (ret != HITLS_SUCCESS) {
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
    }
    if (calcLen != suiteInfo->macLen) {
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
    }
    /* ConstTimeMemcmp returns 0xffffffff when equal, 0 when different. */
    if (ConstTimeMemcmp(recvMac, calcMac, calcLen) == 0) {
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
    }
    if (*dataLen < plainLen) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        return HITLS_MEMCPY_FAIL;
    }
    (void)memcpy(data, cryptMsg->text, plainLen);
    *dataLen = plainLen;
    return HITLS_SUCCESS;
}

const RecCryptoFunc *RecGetTls13IntegrityCryptoFuncs(DecryptPostProcess decryptPostProcess,
    EncryptPreProcess encryptPreProcess)
{
    static RecCryptoFunc cryptoFuncTls13Int = {
        Tls13IntegrityCalCiphertextLen,
        Tls13IntegrityCalPlantextBufLen,
        Tls13IntegrityDecrypt,
        NULL,
        Tls13IntegrityEncrypt,
        NULL,
    };
    cryptoFuncTls13Int.decryptPostProcess = decryptPostProcess;
    cryptoFuncTls13Int.encryptPreProcess = encryptPreProcess;
    return &cryptoFuncTls13Int;
}
#else
static uint32_t Tls13IntegrityStubCalCiphertextLen(const TLS_Ctx *ctx, RecConnSuitInfo *suiteInfo,
    uint32_t plantextLen, bool isRead)
{
    (void)ctx;
    (void)suiteInfo;
    (void)isRead;
    return plantextLen;
}

static int32_t Tls13IntegrityStubCalPlantextBufLen(TLS_Ctx *ctx, RecConnSuitInfo *suiteInfo,
    uint32_t ciphertextLen, uint32_t *offset, uint32_t *plainLen)
{
    (void)ctx;
    (void)suiteInfo;
    *offset = 0;
    *plainLen = ciphertextLen;
    return HITLS_SUCCESS;
}

static int32_t Tls13IntegrityStubDecrypt(TLS_Ctx *ctx, RecConnState *state, const REC_TextInput *cryptMsg,
    uint8_t *data, uint32_t *dataLen)
{
    (void)ctx;
    (void)state;
    (void)cryptMsg;
    (void)data;
    (void)dataLen;
    return HITLS_REC_ERR_NOT_SUPPORT_CIPHER;
}

static int32_t Tls13IntegrityStubEncrypt(TLS_Ctx *ctx, RecConnState *state, const REC_TextInput *plainMsg,
    uint8_t *cipherText, uint32_t cipherTextLen)
{
    (void)ctx;
    (void)state;
    (void)plainMsg;
    (void)cipherText;
    (void)cipherTextLen;
    return HITLS_REC_ERR_NOT_SUPPORT_CIPHER;
}

const RecCryptoFunc *RecGetTls13IntegrityCryptoFuncs(DecryptPostProcess decryptPostProcess,
    EncryptPreProcess encryptPreProcess)
{
    static RecCryptoFunc cryptoFuncTls13IntStub = {
        Tls13IntegrityStubCalCiphertextLen,
        Tls13IntegrityStubCalPlantextBufLen,
        Tls13IntegrityStubDecrypt,
        NULL,
        Tls13IntegrityStubEncrypt,
        NULL,
    };
    cryptoFuncTls13IntStub.decryptPostProcess = decryptPostProcess;
    cryptoFuncTls13IntStub.encryptPreProcess = encryptPreProcess;
    return &cryptoFuncTls13IntStub;
}
#endif /* HITLS_TLS_SUITE_CIPHER_TLS13_INTEGRITY && HITLS_TLS_PROTO_TLS13 */
