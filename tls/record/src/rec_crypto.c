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
#include <string.h>
#include "securec.h"
#include "hitls_build.h"
#include "bsl_log_internal.h"
#include "bsl_err_internal.h"
#ifdef HITLS_TLS_SUITE_CIPHER_AEAD
#include "rec_crypto_aead.h"
#endif
#ifdef HITLS_TLS_SUITE_CIPHER_CBC
#include "rec_crypto_cbc.h"
#endif
#include "tls_binlog_id.h"
#include "rec_conn.h"
#include "rec_alert.h"
#include "indicator.h"
#include "hs.h"
#include "hitls_error.h"

#ifdef HITLS_TLS_PROTO_TLS13
/* 16384 + 1: RFC8446 5.4. Record Padding the full encoded TLSInnerPlaintext MUST NOT exceed 2^14 + 1 octets. */
#define MAX_PADDING_LEN 16385


/* *
 * @brief   Obtain the content and record message types from the decrypted TLSInnerPlaintext.
 *          After TLS1.3 decryption, the TLSInnerPlaintext structure is used. The padding needs to be
            removed and the actual message type needs to be obtained.
 *
 *    struct {
 *            opaque content[TLSPlaintext.length];
 *            ContentType type;
 *            uint8 zeros[length_of_padding];
 *        } TLSInnerPlaintext;
 *
 * @param   text [IN] Decrypted content (TLSInnerPlaintext)
 * @param   textLen [OUT] Input (length of TLSInnerPlaintext)
 *                        Length of the output content
 * @param   recType [OUT] Message body length
 *
 * @return  HITLS_SUCCESS succeeded
 *          HITLS_ALERT_FATAL Unexpected Message
 */
int32_t RecParseInnerPlaintext(TLS_Ctx *ctx, const uint8_t *text, uint32_t *textLen, uint8_t *recType)
{
    /* The receiver decrypts and scans the field from the end to the beginning until it finds a non-zero octet. This
     * non-zero byte is the message type of record If no non-zero bytes are found, an unexpected alert needs to be sent
     * and the chain is terminated
     */
    uint32_t len = *textLen;
    for (uint32_t i = len; i > 0; i--) {
        if (text[i - 1] != 0) {
            *recType = text[i - 1];
            // When the value is the same as the rectype index, the value is the length of the content
            *textLen = i - 1;
            return HITLS_SUCCESS;
        }
    }

    BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_RECV_UNEXPECTED_MSG);
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15453, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "Recved  UNEXPECTED_MESSAGE.", 0, 0, 0, 0);
    return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
}
#endif /* HITLS_TLS_PROTO_TLS13 */

static int32_t DefaultDecryptPostProcess(TLS_Ctx *ctx, RecConnSuitInfo *suiteInfo, REC_TextInput *encryptedMsg,
    uint8_t *data, uint32_t *dataLen)
{
    (void)ctx;
    (void)suiteInfo;
    (void)encryptedMsg;
    (void)data;
    (void)dataLen;
#ifdef HITLS_TLS_PROTO_TLS13
    /* If the version is tls1.3 and encryption is required, you need to create a TLSInnerPlaintext message */
    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLS13 && suiteInfo != NULL) {
        return RecParseInnerPlaintext(ctx, data, dataLen, &encryptedMsg->type);
    }
#endif
    return HITLS_SUCCESS;
}
static int32_t DefaultEncryptPreProcess(TLS_Ctx *ctx, uint8_t recordType, const uint8_t *data, uint32_t plainLen,
    RecordPlaintext *recPlaintext)
{
#ifdef HITLS_TLS_PROTO_TLS
    (void)ctx, (void)data;
    recPlaintext->recordType = recordType;
    recPlaintext->plainLen = plainLen;
    recPlaintext->plainData = NULL;
#ifdef HITLS_TLS_PROTO_TLS13
    if (ctx->negotiatedInfo.version != HITLS_VERSION_TLS13 ||
        ctx->recCtx->writeStates.currentState->suiteInfo == NULL) {
        return HITLS_SUCCESS;
    }
    recPlaintext->isTlsInnerPlaintext = true;
    /* Currently, the padding length is set to 0. If required, the padding length can be customized */
    uint16_t recPaddingLength = 0;
    if (ctx->config.tlsConfig.recordPaddingCb != NULL) {
        recPaddingLength =
            (uint16_t)ctx->config.tlsConfig.recordPaddingCb(ctx, recordType, plainLen,
            ctx->config.tlsConfig.recordPaddingArg);
    }
#ifdef HITLS_TLS_FEATURE_INDICATOR
    INDICATOR_MessageIndicate(
        0, HS_GetVersion(ctx), RECORD_INNER_CONTENT_TYPE, &recordType, 1, ctx, ctx->config.tlsConfig.msgArg);
#endif

    /* TlsInnerPlaintext see rfc 8446 section 5.2 */

    /* tlsInnerPlaintext length = content length + record type length (1) + padding length */
    uint32_t tlsInnerPlaintextLen = plainLen + sizeof(uint8_t) + recPaddingLength;
    if (tlsInnerPlaintextLen > MAX_PADDING_LEN) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_RECORD_OVERFLOW);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15669, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Pack TlsInnerPlaintext length(%u) MUST NOT exceed 2^14 + 1 octets.", tlsInnerPlaintextLen, 0, 0, 0);
        return HITLS_REC_RECORD_OVERFLOW;
    }

    uint8_t *tlsInnerPlaintext = BSL_SAL_Calloc(1u, tlsInnerPlaintextLen);
    if (tlsInnerPlaintext == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_MEMALLOC_FAIL, BINLOG_ID17253, "Calloc fail");
    }

    if (memcpy_s(tlsInnerPlaintext, tlsInnerPlaintextLen, data, plainLen) != EOK) {
        BSL_SAL_FREE(tlsInnerPlaintext);
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_MEMCPY_FAIL, BINLOG_ID17254, "memcpy fail");
    }

    tlsInnerPlaintext[plainLen] = recordType;

    /* Padding is calloc when the memory is applied for. Therefore, the number of buffs to be supplemented is 0. You do
     * not need to perform any operation */
    recPlaintext->plainLen = tlsInnerPlaintextLen;
    recPlaintext->plainData = tlsInnerPlaintext;
    /* tls1.3 Hide the actual record type during encryption */
    recPlaintext->recordType = (uint8_t)REC_TYPE_APP;
#endif /* HITLS_TLS_PROTO_TLS13 */
    return HITLS_SUCCESS;
#else
    (void)ctx, (void)recordType, (void)data, (void)plainLen, (void)recPlaintext;
    return HITLS_REC_ERR_NOT_SUPPORT_CIPHER;
#endif /* HITLS_TLS_PROTO_TLS */
}

static uint32_t PlainCalCiphertextLen(const TLS_Ctx *ctx, RecConnSuitInfo *suiteInfo, uint32_t plantextLen, bool isRead)
{
    (void)ctx;
    (void)suiteInfo;
    (void)isRead;
    return plantextLen;
}
static int32_t PlainCalPlantextBufLen(TLS_Ctx *ctx, RecConnSuitInfo *suiteInfo,
    uint32_t ciphertextLen, uint32_t *offset, uint32_t *plainLen)
{
    (void)ctx;
    (void)suiteInfo;
    *offset = 0;
    *plainLen = ciphertextLen;
    return HITLS_SUCCESS;
}
static int32_t PlainDecrypt(TLS_Ctx *ctx, RecConnState *suiteInfo, const REC_TextInput *cryptMsg,
    uint8_t *data, uint32_t *dataLen)
{
    (void)ctx;
    (void)suiteInfo;
    if (memcpy_s(data, *dataLen, cryptMsg->text, cryptMsg->textLen) != EOK) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15404, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "RecConnDecrypt Failed: memcpy fail.", 0, 0, 0, 0);
        return HITLS_MEMCPY_FAIL;
    }
    // For empty ciphersuite case, the plaintext length is equal to ciphertext length
    *dataLen = cryptMsg->textLen;
    return HITLS_SUCCESS;
}

static int32_t PlainEncrypt(TLS_Ctx *ctx, RecConnState *state, const REC_TextInput *plainMsg,
    uint8_t *cipherText, uint32_t cipherTextLen)
{
    (void)ctx;
    (void)state;
    if (memcpy_s(cipherText, cipherTextLen, plainMsg->text, plainMsg->textLen) != EOK) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15926, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record:memcpy fail.", 0, 0, 0, 0);
        return HITLS_MEMCPY_FAIL;
    }
    return HITLS_SUCCESS;
}

static int32_t UnsupoortDecrypt(TLS_Ctx *ctx, RecConnState *suiteInfo, const REC_TextInput *cryptMsg,
    uint8_t *data, uint32_t *dataLen)
{
    (void)ctx;
    (void)suiteInfo;
    (void)cryptMsg;
    (void)data;
    (void)dataLen;
    return HITLS_REC_ERR_NOT_SUPPORT_CIPHER;
}

static int32_t UnsupoortEncrypt(TLS_Ctx *ctx, RecConnState *State, const REC_TextInput *plainMsg,
    uint8_t *cipherText, uint32_t cipherTextLen)
{
    (void)ctx;
    (void)State;
    (void)plainMsg;
    (void)cipherText;
    (void)cipherTextLen;
    return HITLS_REC_ERR_NOT_SUPPORT_CIPHER;
}


const RecCryptoFunc *RecGetCryptoFuncs(const RecConnSuitInfo *suiteInfo)
{
    static RecCryptoFunc cryptoFuncPlain = {
        PlainCalCiphertextLen,
        PlainCalPlantextBufLen,
        PlainDecrypt,
        DefaultDecryptPostProcess,
        PlainEncrypt,
        DefaultEncryptPreProcess
    };
    if (suiteInfo == NULL) {
        return &cryptoFuncPlain;
    }
    switch (suiteInfo->cipherType) {
#ifdef HITLS_TLS_SUITE_CIPHER_AEAD
        case HITLS_AEAD_CIPHER:
            return RecGetAeadCryptoFuncs(DefaultDecryptPostProcess, DefaultEncryptPreProcess);
#endif
#ifdef HITLS_TLS_SUITE_CIPHER_CBC
        case HITLS_CBC_CIPHER:
            return RecGetCbcCryptoFuncs(DefaultDecryptPostProcess, DefaultEncryptPreProcess);
#endif
        default:
            break;
    }
    BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_NOT_SUPPORT_CIPHER);
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16240, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "Internal error, unsupport cipher.", 0, 0, 0, 0);
    static RecCryptoFunc cryptoFuncUnsupport = {
        PlainCalCiphertextLen,
        PlainCalPlantextBufLen,
        UnsupoortDecrypt,
        DefaultDecryptPostProcess,
        UnsupoortEncrypt,
        DefaultEncryptPreProcess
    };
    return &cryptoFuncUnsupport;
}
