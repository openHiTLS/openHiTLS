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
#include "hitls_build.h"
#ifdef HITLS_TLS_SUITE_CIPHER_AEAD
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "crypt.h"
#include "hitls_error.h"
#include "record.h"
#include "rec_alert.h"
#include "rec_conn.h"
#include "rec_crypto_aead.h"

#define AEAD_AAD_TLS12_SIZE 13u            /* TLS1.2 AEAD additional_data length */
#define AEAD_AAD_MAX_SIZE   AEAD_AAD_TLS12_SIZE
#define AEAD_NONCE_SIZE 12u         /* The length of the AEAD nonce is fixed to 12 */
#define AEAD_NONCE_ZEROS_SIZE 4u            /* The length of the AEAD nonce First 4 bytes */
#ifdef HITLS_TLS_PROTO_TLS13
#define AEAD_AAD_TLS13_SIZE 5u            /* TLS1.3 AEAD additional_data length */
#endif

static int32_t CleanSensitiveData(int32_t ret, uint8_t *nonce, uint8_t *aad, uint32_t outLen, uint32_t cipherLen)
{
    BSL_SAL_CleanseData(nonce, AEAD_NONCE_SIZE);
    BSL_SAL_CleanseData(aad, AEAD_AAD_MAX_SIZE);
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15480, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record:encrypt record error.", NULL, NULL, NULL, NULL);
        return ret;
    }

    if (outLen != cipherLen) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_ENCRYPT);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15481, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record:encrypt error. outLen:%u cipherLen:%u", outLen, cipherLen, NULL, NULL);
        return HITLS_REC_ERR_ENCRYPT;
    }

    return HITLS_SUCCESS;
}

static int32_t AeadGetNonce(const RecConnSuitInfo *suiteInfo, uint8_t *nonce, uint8_t nonceLen,
    const uint8_t *seq, uint8_t seqLen)
{
    uint8_t fixedIvLength = suiteInfo->fixedIvLength;
    uint8_t recordIvLength = suiteInfo->recordIvLength;

    if ((fixedIvLength + recordIvLength) != nonceLen) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17239, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "nonceLen err", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_AEAD_NONCE_PARAM);
        return HITLS_REC_ERR_AEAD_NONCE_PARAM;  // The caller should ensure that the input is correct
    }

    if (recordIvLength == seqLen) {
        /*
         * According to the RFC5116 && RFC5288 AEAD_AES_128_GCM/AEAD_AES_256_GCM definition, the nonce length is fixed
         * to 12. 4 bytes + 8bytes(64 bits record sequence number, big endian) = 12 bytes 4 bytes the implicit part be
         * derived from iv. The first 4 bytes of the IV are obtained.
         */
        (void)memcpy_s(nonce, nonceLen, suiteInfo->iv, fixedIvLength);
        (void)memcpy_s(&nonce[fixedIvLength], recordIvLength, seq, seqLen);
        return HITLS_SUCCESS;
    } else if (recordIvLength == 0) {
        /*
         * (same as defined in RFC7905 AEAD_CHACHA20_POLY1305)
         * The per-record nonce for the AEAD defined in RFC8446 5.3
         * First 4 bytes (all 0s) + Last 8bytes(64 bits record sequence number, big endian) = 12 bytes
         * Perform XOR with the 12 bytes IV. The result is nonce.
         */
        // First four bytes (all 0s)
        (void)memset_s(&nonce[0], nonceLen, 0, AEAD_NONCE_ZEROS_SIZE);
        // First 4 bytes (all 0s) + Last 8 bytes (64-bit record sequence number, big endian)
        (void)memcpy_s(&nonce[AEAD_NONCE_ZEROS_SIZE], nonceLen - AEAD_NONCE_ZEROS_SIZE, seq, seqLen);
        for (uint32_t i = 0; i < nonceLen; i++) {
            nonce[i] = nonce[i] ^ suiteInfo->iv[i];
        }
        return HITLS_SUCCESS;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17240, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "get nonce fail", 0, 0, 0, 0);
    BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_AEAD_NONCE_PARAM);
    return HITLS_REC_ERR_AEAD_NONCE_PARAM;
}

static void AeadGetAad(uint8_t *aad, uint32_t *aadLen, const REC_TextInput *input, uint32_t plainDataLen)
{
#ifdef HITLS_TLS_PROTO_TLS13
    /*
    TLS1.3 generation
        additional_data = TLSCiphertext.opaque_type || TLSCiphertext.legacy_record_version || TLSCiphertext.length
    */
    if (input->negotiatedVersion == HITLS_VERSION_TLS13) {
        // The 0th byte is the record type
        aad[0] = input->type;
        uint32_t offset = 1;
        // The first and second bytes  of indicate the version number
        BSL_Uint16ToByte(input->version, &aad[offset]);
        offset += sizeof(uint16_t);
        // The third and fourth bytes  of indicate the data length
        BSL_Uint16ToByte((uint16_t)plainDataLen, &aad[offset]);
        *aadLen = AEAD_AAD_TLS13_SIZE;
        return;
    }
#endif /* HITLS_TLS_PROTO_TLS13 */
    /* non-TLS1.3 generation additional_data = seq_num + TLSCompressed.type + TLSCompressed.version +
     * TLSCompressed.length */
    (void)memcpy_s(aad, AEAD_AAD_MAX_SIZE, input->seq, REC_CONN_SEQ_SIZE);
    uint32_t offset = REC_CONN_SEQ_SIZE;
    aad[offset] = input->type;                                // The eighth byte indicates the record type
    offset++;
    BSL_Uint16ToByte(input->version, &aad[offset]);           // The ninth and tenth bytes indicate the version number.
    offset += sizeof(uint16_t);
    BSL_Uint16ToByte((uint16_t)plainDataLen, &aad[offset]);  // The 11th and 12th bytse indicate the data length.
    *aadLen = AEAD_AAD_TLS12_SIZE;
}

static uint32_t AeadCalCiphertextLen(const TLS_Ctx *ctx, RecConnSuitInfo *suiteInfo, uint32_t plantextLen, bool isRead)
{
    (void)ctx;
    (void)isRead;
    return plantextLen + suiteInfo->macLen + suiteInfo->recordIvLength;
}
static int32_t AeadCalPlantextBufLen(TLS_Ctx *ctx, RecConnSuitInfo *suiteInfo,
    uint32_t ciphertextLen, uint32_t *offset, uint32_t *plainLen)
{
    (void)ctx;
    *offset = suiteInfo->recordIvLength;
    uint32_t plantextLen = ciphertextLen - suiteInfo->macLen - suiteInfo->recordIvLength;
    if (plantextLen > ciphertextLen) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17241, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "plantextLen err", 0, 0, 0, 0);
        return HITLS_INVALID_INPUT;
    }
    *plainLen = plantextLen;
    return HITLS_SUCCESS;
}

static int32_t AeadDecrypt(TLS_Ctx *ctx, RecConnState *state, const REC_TextInput *cryptMsg,
    uint8_t *data, uint32_t *dataLen)
{
    RecConnSuitInfo *suiteInfo = state->suiteInfo;
    /** Initialize the encryption length offset */
    uint32_t cipherOffset = 0u;
    HITLS_CipherParameters cipherParam = {0};
    cipherParam.ctx = &suiteInfo->ctx;
    cipherParam.type = suiteInfo->cipherType;
    cipherParam.algo = suiteInfo->cipherAlg;
    cipherParam.key = (const uint8_t *)suiteInfo->key;
    cipherParam.keyLen = suiteInfo->encKeyLen;

    /** Read the explicit IV during AEAD decryption */
    const uint8_t *recordIv;
    if (suiteInfo->recordIvLength > 0u) {
        recordIv = &cryptMsg->text[cipherOffset];
        cipherOffset += REC_CONN_SEQ_SIZE;
    } else {
        // If no IV is displayed, use the serial number
        recordIv = cryptMsg->seq;
    }

    /** Calculate NONCE */
    uint8_t nonce[AEAD_NONCE_SIZE] = {0};
    int32_t ret = AeadGetNonce(suiteInfo, nonce, sizeof(nonce), recordIv, REC_CONN_SEQ_SIZE);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15395, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record decrypt:get nonce failed.", 0, 0, 0, 0);
        return ret;
    }
    cipherParam.iv = nonce;
    cipherParam.ivLen = AEAD_NONCE_SIZE;

    /* Calculate additional_data */
    uint8_t aad[AEAD_AAD_MAX_SIZE] = {0};
    uint32_t aadLen = AEAD_AAD_MAX_SIZE;
    /*
    Definition of additional_data
    tls1.2 additional_data = seq_num + TLSCompressed.type +
                TLSCompressed.version + TLSCompressed.length;
    tls1.3 additional_data = TLSCiphertext.opaque_type ||
                TLSCiphertext.legacy_record_version ||
                TLSCiphertext.length
    diff: length
    */
    uint32_t plainDataLen = cryptMsg->textLen;
    if (cryptMsg->negotiatedVersion != HITLS_VERSION_TLS13) {
        plainDataLen = cryptMsg->textLen - suiteInfo->recordIvLength - suiteInfo->macLen;
    }
    AeadGetAad(aad, &aadLen, cryptMsg, plainDataLen);
    cipherParam.aad = aad;
    cipherParam.aadLen = aadLen;

    /** Calculate the encryption length: GenericAEADCipher.content + aead tag */
    uint32_t cipherLen = cryptMsg->textLen - cipherOffset;
    /** Decryption */
    ret = SAL_CRYPT_Decrypt(LIBCTX_FROM_CTX(ctx), ATTRIBUTE_FROM_CTX(ctx),
        &cipherParam, &cryptMsg->text[cipherOffset], cipherLen, data, dataLen);
    /* Clear sensitive information */
    BSL_SAL_CleanseData(nonce, AEAD_NONCE_SIZE);
    BSL_SAL_CleanseData(aad, AEAD_AAD_MAX_SIZE);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15396, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "decrypt record error. ret:%d", ret, 0, 0, 0);
        if (BSL_UIO_GetUioChainTransportType(ctx->uio, BSL_UIO_SCTP)) {
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
            return HITLS_REC_BAD_RECORD_MAC;
        }
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
    }
    return HITLS_SUCCESS;
}

/**
 * @brief AEAD encryption
 *
 * @param state [IN] RecConnState Context
 * @param input [IN] Input data before encryption
 * @param cipherText [OUT] Encrypted content
 * @param cipherTextLen [IN] Length after encryption
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval HITLS_INTERNAL_EXCEPTION: null pointer
 * @retval HITLS_MEMCPY_FAIL The copy fails.
 * @retval For details, see SAL_CRYPT_Encrypt.
 */
static int32_t AeadEncrypt(TLS_Ctx *ctx, RecConnState *state, const REC_TextInput *plainMsg, uint8_t *cipherText,
    uint32_t cipherTextLen)
{
    /** Initialize the encryption length offset */
    uint32_t cipherOffset = 0u;
    HITLS_CipherParameters cipherParam = {0};
    cipherParam.ctx = &state->suiteInfo->ctx;
    cipherParam.type = state->suiteInfo->cipherType;
    cipherParam.algo = state->suiteInfo->cipherAlg;
    cipherParam.key = (const uint8_t *)state->suiteInfo->key;
    cipherParam.keyLen = state->suiteInfo->encKeyLen;

    /** During AEAD encryption, the sequence number is used as the explicit IV */
    if (state->suiteInfo->recordIvLength > 0u) {
        if (memcpy_s(&cipherText[cipherOffset], cipherTextLen, plainMsg->seq, REC_CONN_SEQ_SIZE) != EOK) {
            BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15384, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Record encrypt:memcpy fail.", 0, 0, 0, 0);
            return HITLS_MEMCPY_FAIL;
        }
        cipherOffset += REC_CONN_SEQ_SIZE;
    }

    /** Calculate NONCE */
    uint8_t nonce[AEAD_NONCE_SIZE] = {0};
    int32_t ret = AeadGetNonce(state->suiteInfo, nonce, sizeof(nonce), plainMsg->seq, REC_CONN_SEQ_SIZE);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15385, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record encrypt:get nonce failed.", 0, 0, 0, 0);
        return ret;
    }
    cipherParam.iv = nonce;
    cipherParam.ivLen = AEAD_NONCE_SIZE;

    /* Calculate additional_data */
    uint8_t aad[AEAD_AAD_MAX_SIZE];
    uint32_t aadLen = AEAD_AAD_MAX_SIZE;
    uint32_t textLen =
#ifdef HITLS_TLS_PROTO_TLS13
        (plainMsg->negotiatedVersion == HITLS_VERSION_TLS13) ? cipherTextLen :
#endif /* HITLS_TLS_PROTO_TLS13 */
        plainMsg->textLen;
    AeadGetAad(aad, &aadLen, plainMsg, textLen);
    cipherParam.aad = aad;
    cipherParam.aadLen = aadLen;

    /** Calculate the encryption length */
    uint32_t cipherLen = cipherTextLen - cipherOffset;
    uint32_t outLen = cipherLen;
    /** Encryption */
    ret = SAL_CRYPT_Encrypt(LIBCTX_FROM_CTX(ctx), ATTRIBUTE_FROM_CTX(ctx),
        &cipherParam, plainMsg->text, plainMsg->textLen, &cipherText[cipherOffset], &outLen);
    /* Clear sensitive information */
    return CleanSensitiveData(ret, nonce, aad, outLen, cipherLen);
}

const RecCryptoFunc *RecGetAeadCryptoFuncs(DecryptPostProcess decryptPostProcess, EncryptPreProcess encryptPreProcess)
{
    static RecCryptoFunc cryptoFuncAead = {
        .calCiphertextLen = AeadCalCiphertextLen,
        .calPlantextBufLen = AeadCalPlantextBufLen,
        .decrypt = AeadDecrypt,
        .encryt = AeadEncrypt,
    };
    cryptoFuncAead.decryptPostProcess = decryptPostProcess;
    cryptoFuncAead.encryptPreProcess = encryptPreProcess;
    return &cryptoFuncAead;
}
#endif