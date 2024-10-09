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
#include "bsl_sal.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "hitls_error.h"
#include "crypt.h"
#include "record.h"
#include "rec_alert.h"
#include "rec_conn.h"


#define KEY_EXPANSION_LABEL "key expansion"

#define AEAD_AAD_TLS12_SIZE 13u            /* TLS1.2 AEAD additional_data length */
#define AEAD_AAD_TLS13_SIZE 5u            /* TLS1.3 AEAD additional_data length */
#define AEAD_AAD_MAX_SIZE   AEAD_AAD_TLS12_SIZE
#define AEAD_NONCE_SIZE 12u         /* The length of the AEAD nonce is fixed to 12 */

#define CBC_PADDING_LEN_TAG_SIZE 1u
#define CBC_MAC_HEADER_LEN 13U

RecConnState *RecConnStateNew(void)
{
    RecConnState *state = (RecConnState *)BSL_SAL_Calloc(1, sizeof(RecConnState));
    if (state == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15382, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record conn:malloc fail.", 0, 0, 0, 0);
        return NULL;
    }
    return state;
}

void RecConnStateFree(RecConnState *state)
{
    if (state == NULL) {
        return;
    }
    /* Clear sensitive information */
    BSL_SAL_CleanseData(state->suiteInfo, sizeof(RecConnSuitInfo));
    BSL_SAL_FREE(state->suiteInfo);
    BSL_SAL_FREE(state);
    return;
}

uint64_t RecConnGetSeqNum(const RecConnState *state)
{
    return state->seq;
}

void RecConnSetSeqNum(RecConnState *state, uint64_t seq)
{
    state->seq = seq;
}

#ifndef HITLS_NO_DTLS12
uint16_t RecConnGetEpoch(const RecConnState *state)
{
    return state->epoch;
}

void RecConnSetEpoch(RecConnState *state, uint16_t epoch)
{
    state->epoch = epoch;
}
#endif

int32_t RecConnStateSetCipherInfo(RecConnState *state, RecConnSuitInfo *suitInfo)
{
    /* Clear sensitive information */
    BSL_SAL_CleanseData(state->suiteInfo, sizeof(RecConnSuitInfo));
    // Ensure that no memory leak occurs
    BSL_SAL_FREE(state->suiteInfo);

    state->suiteInfo = (RecConnSuitInfo *)BSL_SAL_Malloc(sizeof(RecConnSuitInfo));
    if (state->suiteInfo == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(
            BINLOG_ID15383, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Record conn: malloc fail.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }

    (void)memcpy_s(state->suiteInfo, sizeof(RecConnSuitInfo), suitInfo, sizeof(RecConnSuitInfo));
    return HITLS_SUCCESS;
}

// compute padding length form blockLen and plaintextLen
static uint8_t RecConnGetCbcPaddingLen(uint8_t blockLen, uint32_t plaintextLen)
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

uint32_t RecConnCalcCiphertextLen(const RecConnState *state, uint32_t plainLen, bool isEncThenMac)
{
    if (state == NULL || state->suiteInfo == NULL) {
        return plainLen;
    }

    uint32_t ciphertextLen = plainLen;
    /* TLS 12: GenericBlockCipher, IV[SecurityParameters.record_iv_length]
       TLS 13: nonce_explicit[SecurityParameters.record_iv_length] */
    uint32_t ivLen = state->suiteInfo->recordIvLength;
    // MAC[SecurityParameters.mac_length]
    uint32_t macLen = state->suiteInfo->macLen;

    if (state->suiteInfo->cipherType == HITLS_AEAD_CIPHER) {
        ciphertextLen += (ivLen + macLen);
    } else if (state->suiteInfo->cipherType == HITLS_CBC_CIPHER) {
        ciphertextLen += ivLen;
        // GenericBlockCipher.padding_length, used for CBC cipher
        uint8_t paddingLen = 0;
        if (isEncThenMac) {
            paddingLen = RecConnGetCbcPaddingLen(state->suiteInfo->blockLength, ciphertextLen);
            ciphertextLen += (paddingLen + CBC_PADDING_LEN_TAG_SIZE + macLen);
        } else {
            ciphertextLen += macLen;
            paddingLen = RecConnGetCbcPaddingLen(state->suiteInfo->blockLength, ciphertextLen);
            ciphertextLen += (paddingLen + CBC_PADDING_LEN_TAG_SIZE);
        }
    }

    return ciphertextLen;
}

/**
 * @brief   Calculate the plaintext length or its upperbound from the ciphertext length
 * @param   state [IN] RecState context, including cipher suite information
 * @param   ctLen [IN] ciphertext length
 * @return  Exact plaintext length for AEAD_CIPHER case, upper bound length for CBC_CIPHER
 */
static uint32_t CalcPlaintextLenUpperBound(const RecConnState *state, uint32_t ctLen)
{
    if (state == NULL || state->suiteInfo == NULL) {
        return ctLen;
    }
    uint32_t ptLenUpperBound = ctLen;
    uint32_t ivLen = state->suiteInfo->recordIvLength;
    // MAC[SecurityParameters.mac_length]
    uint32_t macLen = state->suiteInfo->macLen;
    if (state->suiteInfo->cipherType == HITLS_AEAD_CIPHER) {
        ptLenUpperBound -= (ivLen + macLen);
    } else if (state->suiteInfo->cipherType == HITLS_CBC_CIPHER) {
        ptLenUpperBound -= ivLen;
        /* paddingLen for CBC cipher  ranges from 0 to (blockSize - 1), let it be zero to compute
           the upper bound of plaintextLen when using CBC CIPHER */
        ptLenUpperBound -= (CBC_PADDING_LEN_TAG_SIZE + macLen);
    }
    return ptLenUpperBound > REC_MAX_PLAIN_TEXT_LENGTH ? REC_MAX_PLAIN_TEXT_LENGTH : ptLenUpperBound;
}

static int32_t AeadGetNonce(const RecConnState *state, uint8_t *nonce, uint8_t nonceLen,
    const uint8_t *seq, uint8_t seqLen)
{
    uint8_t fixedIvLength = state->suiteInfo->fixedIvLength;
    uint8_t recordIvLength = state->suiteInfo->recordIvLength;

    if ((fixedIvLength + recordIvLength) != nonceLen) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_AEAD_NONCE_PARAM);
        return HITLS_REC_ERR_AEAD_NONCE_PARAM;  // The caller should ensure that the input is correct
    }

    if (recordIvLength == seqLen) {
        /**
         * According to the RFC5116 && RFC5288 AEAD_AES_128_GCM/AEAD_AES_256_GCM definition, the nonce length is fixed
         * to 12. 4 bytes + 8bytes(64 bits record sequence number, big endian) = 12 bytes 4 bytes the implicit part be
         * derived from iv. The first 4 bytes of the IV are obtained.
         */
        (void)memcpy_s(nonce, nonceLen, state->suiteInfo->iv, fixedIvLength);
        (void)memcpy_s(&nonce[fixedIvLength], recordIvLength, seq, seqLen);
        return HITLS_SUCCESS;
    } else if (recordIvLength == 0) {
        /**
         * (same as defined in RFC7905 AEAD_CHACHA20_POLY1305)
         * The per-record nonce for the AEAD defined in RFC8446 5.3
         * First 4 bytes (all 0s) + Last 8bytes(64 bits record sequence number, big endian) = 12 bytes
         * Perform XOR with the 12 bytes IV. The result is nonce.
         */
        // First four bytes (all 0s)
        (void)memset_s(&nonce[0], nonceLen, 0, 4);
        // First 4 bytes (all 0s) + Last 8 bytes (64-bit record sequence number, big endian)
        (void)memcpy_s(&nonce[4], nonceLen - 4, seq, seqLen);
        for (uint32_t i = 0; i < nonceLen; i++) {
            nonce[i] = nonce[i] ^ state->suiteInfo->iv[i];
        }
        return HITLS_SUCCESS;
    }

    BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_AEAD_NONCE_PARAM);
    return HITLS_REC_ERR_AEAD_NONCE_PARAM;
}

static void AeadGetAad(uint8_t *aad, uint32_t *aadLen, const REC_TextInput *input, uint32_t plainDataLen)
{
    /**
    TLS1.3 generation
        additional_data = TLSCiphertext.opaque_type || TLSCiphertext.legacy_record_version || TLSCiphertext.length
    */
    if (input->negotiatedVersion == HITLS_VERSION_TLS13) {
        aad[0] = input->type;                               // The 0th byte is the record type
        BSL_Uint16ToByte(input->version, &aad[1]);       // The first and second bytes  of indicate the version number
        BSL_Uint16ToByte((uint16_t)plainDataLen, &aad[3]);  // The third and fourth bytes  of indicate the data length
        *aadLen = AEAD_AAD_TLS13_SIZE;
        return;
    }

    /* non-TLS1.3 generation additional_data = seq_num + TLSCompressed.type + TLSCompressed.version +
     * TLSCompressed.length */
    (void)memcpy_s(aad, AEAD_AAD_MAX_SIZE, input->seq, REC_CONN_SEQ_SIZE);
    aad[8] = input->type;                                // The eighth byte indicates the record type
    BSL_Uint16ToByte(input->version, &aad[9]);           // The ninth and tenth bytes indicate the version number.
    BSL_Uint16ToByte((uint16_t)plainDataLen, &aad[11]);  // The 11th and 12th bytse indicate the data length.
    *aadLen = AEAD_AAD_TLS12_SIZE;
    return;
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
static int32_t RecConnAeadEncrypt(const RecConnState *state, const REC_TextInput *plainMsg, uint8_t *cipherText,
    uint32_t cipherTextLen)
{
    /** Initialize the encryption length offset */
    uint32_t cipherOffset = 0u;
    HITLS_CipherParameters cipherParam = {0};
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
    int32_t ret = AeadGetNonce(state, nonce, sizeof(nonce), plainMsg->seq, REC_CONN_SEQ_SIZE);
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
    uint32_t textLen = (plainMsg->negotiatedVersion == HITLS_VERSION_TLS13) ? cipherTextLen : plainMsg->textLen;
    AeadGetAad(aad, &aadLen, plainMsg, textLen);
    cipherParam.aad = aad;
    cipherParam.aadLen = aadLen;

    /** Calculate the encryption length */
    uint32_t cipherLen = cipherTextLen - cipherOffset;
    uint32_t outLen = cipherLen;
    /** Encryption */
    ret = SAL_CRYPT_Encrypt(&cipherParam, plainMsg->text, plainMsg->textLen, &cipherText[cipherOffset], &outLen);
    /* Clear sensitive information */
    BSL_SAL_CleanseData(nonce, AEAD_NONCE_SIZE);
    BSL_SAL_CleanseData(aad, AEAD_AAD_MAX_SIZE);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15386, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record:encrypt record error.", 0, 0, 0, 0);
        return ret;
    }

    if (outLen != cipherLen) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_ENCRYPT);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15387, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record:encrypt error. outLen:%u cipherLen:%u", outLen, cipherLen, 0, 0);
        return HITLS_REC_ERR_ENCRYPT;
    }

    return HITLS_SUCCESS;
}

static uint32_t GetHashOfMACAlgorithm(HITLS_MacAlgo macAlgo)
{
    switch (macAlgo) {
        case HITLS_MAC_1:
            return HITLS_HASH_SHA1;
        case HITLS_MAC_256:
            return HITLS_HASH_SHA_256;
        case HITLS_MAC_224:
            return HITLS_HASH_SHA_224;
        case HITLS_MAC_384:
            return HITLS_HASH_SHA_384;
        case HITLS_MAC_512:
            return HITLS_HASH_SHA_512;
#ifndef HITLS_NO_TLCP11
        case HITLS_MAC_SM3:
            return HITLS_HASH_SM3;
#endif
        default:
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15388, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "CBC encrypt error: unsupport MAC algorithm = %u.", macAlgo, 0, 0, 0);
            break;
    }
    return HITLS_HASH_BUTT;
}

int32_t RecConnGenerateMac(const RecConnState *state, const REC_TextInput *plainMsg, uint8_t *mac, uint32_t *macLen)
{
    int32_t ret = HITLS_SUCCESS;
    uint8_t header[CBC_MAC_HEADER_LEN] = {0};
    uint32_t offset = 0;
    if (memcpy_s(header, CBC_MAC_HEADER_LEN, plainMsg->seq, REC_CONN_SEQ_SIZE) != EOK) {
        return HITLS_MEMCPY_FAIL;
    }
    offset += REC_CONN_SEQ_SIZE;

    header[offset] = plainMsg->type;                                      // The eighth byte is the record type
    offset++;
    BSL_Uint16ToByte(plainMsg->version, &header[offset]);                 // The 9th and 10th bytes are version numbers
    offset += sizeof(uint16_t);
    BSL_Uint16ToByte((uint16_t)plainMsg->textLen, &header[offset]);       // The 11th and 12th bytes are the data length

    HITLS_HashAlgo hashAlgo = GetHashOfMACAlgorithm(state->suiteInfo->macAlg);
    if (hashAlgo == HITLS_HASH_BUTT) {
        return HITLS_REC_ERR_GENERATE_MAC;
    }

    HITLS_HMAC_Ctx *hmacCtx = SAL_CRYPT_HmacInit(hashAlgo, state->suiteInfo->macKey, state->suiteInfo->macKeyLen);
    if (hmacCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_GENERATE_MAC);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15389, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "CBC encrypt error: HMAC init fail, hashAlgo = %u.", hashAlgo, 0, 0, 0);
        return HITLS_REC_ERR_GENERATE_MAC;
    }

    ret = SAL_CRYPT_HmacUpdate(hmacCtx, header, CBC_MAC_HEADER_LEN);
    if (ret != HITLS_SUCCESS) {
        SAL_CRYPT_HmacFree(hmacCtx);
        return ret;
    }

    ret = SAL_CRYPT_HmacUpdate(hmacCtx, plainMsg->text, plainMsg->textLen);
    if (ret != HITLS_SUCCESS) {
        SAL_CRYPT_HmacFree(hmacCtx);
        return ret;
    }

    ret = SAL_CRYPT_HmacFinal(hmacCtx, mac, macLen);
    if (ret != HITLS_SUCCESS) {
        SAL_CRYPT_HmacFree(hmacCtx);
        return ret;
    }

    SAL_CRYPT_HmacFree(hmacCtx);
    return HITLS_SUCCESS;
}

static void RecConnInitCipherParam(HITLS_CipherParameters *cipherParam, const RecConnState *state)
{
    cipherParam->type = state->suiteInfo->cipherType;
    cipherParam->algo = state->suiteInfo->cipherAlg;
    cipherParam->key = state->suiteInfo->key;
    cipherParam->keyLen = state->suiteInfo->encKeyLen;
    cipherParam->iv = state->suiteInfo->iv;
    cipherParam->ivLen = state->suiteInfo->fixedIvLength;
}

static void RecConnInitGenerateMacInput(const REC_TextInput *in, const uint8_t *text, uint32_t textLen,
    REC_TextInput *out)
{
    out->version = in->version;
    out->negotiatedVersion = in->negotiatedVersion;
    out->isEncryptThenMac = in->isEncryptThenMac;
    out->type = in->type;
    out->text = text;
    out->textLen = textLen;
    for (uint32_t i = 0u; i < REC_CONN_SEQ_SIZE; i++) {
        out->seq[i] = in->seq[i];
    }
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
    int32_t ret = RecConnGenerateMac(state, &input, &plainText[plainTextLen], &macLen);
    if (ret != HITLS_SUCCESS) {
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

int32_t RecConnCbcMacThenEncrypt(const RecConnState *state, const REC_TextInput *plainMsg, uint8_t *cipherText,
    uint32_t cipherTextLen)
{
    uint8_t *plainText = BSL_SAL_Calloc(1u, cipherTextLen);
    if (plainText == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15390, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record CBC encrypt error: out of memory.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }

    uint32_t plainTextLen = 0;
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
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15927, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record CBC encrypt error: out of memory.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    int32_t ret = GenerateCbcPlainTextBeforeMac(state, plainMsg, cipherTextLen, *plainText, plainTextLen);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(*plainText);
        return ret;
    }
    return HITLS_SUCCESS;
}

static int32_t RecConnCbcEncryptThenMac(const RecConnState *state, const REC_TextInput *plainMsg, uint8_t *cipherText,
    uint32_t cipherTextLen)
{
    uint8_t *plainText = NULL;
    uint32_t plainTextLen = 0;

    int32_t ret = PreparePlainText(state, plainMsg, cipherTextLen, &plainText, &plainTextLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint32_t offset = 0;
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
    ret = RecConnGenerateMac(state, &input, &cipherText[offset + encLen], &macLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    return HITLS_SUCCESS;
}

int32_t RecConnEncrypt(RecConnState *state, const REC_TextInput *plainMsg, uint8_t *cipherText, uint32_t cipherTextLen)
{
    if (state->suiteInfo == NULL) { // No cipher suite, plaintext
        if (memcpy_s(cipherText, cipherTextLen, plainMsg->text, plainMsg->textLen) != EOK) {
            BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15926, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Record:memcpy fail.", 0, 0, 0, 0);
            return HITLS_MEMCPY_FAIL;
        }
        return HITLS_SUCCESS;
    }
    if (state->suiteInfo->cipherType == HITLS_AEAD_CIPHER) {
        return RecConnAeadEncrypt(state, plainMsg, cipherText, cipherTextLen);
    } else if (state->suiteInfo->cipherType == HITLS_CBC_CIPHER) {
        if (plainMsg->isEncryptThenMac) {
            return RecConnCbcEncryptThenMac(state, plainMsg, cipherText, cipherTextLen);
        } else {
            return RecConnCbcMacThenEncrypt(state, plainMsg, cipherText, cipherTextLen);
        }
    }
    BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_NOT_SUPPORT_CIPHER);
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15394, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "Record:cipher is not supported.", 0, 0, 0, 0);
    return HITLS_REC_ERR_NOT_SUPPORT_CIPHER;
}

/**
 * @brief AEAD decryption
 *
 * @param ctx [IN] tls Context
 * @param state [IN] RecConnState Context
 * @param input [IN] Input data before decryption
 * @param data [OUT] Decrypted content
 * @param dataLen [OUT] IN: length of data OUT: length after decryption
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval HITLS_MEMCPY_FAIL The copy fails.
 * @retval HITLS_REC_BAD_RECORD_MAC Invalid MAC
 */
static int32_t RecConnAeadDecrypt(TLS_Ctx *ctx, const RecConnState *state, const REC_TextInput *cryptMsg,
    uint8_t *data, uint32_t *dataLen)
{
    /** Initialize the encryption length offset */
    uint32_t cipherOffset = 0u;
    HITLS_CipherParameters cipherParam = {0};
    cipherParam.type = state->suiteInfo->cipherType;
    cipherParam.algo = state->suiteInfo->cipherAlg;
    cipherParam.key = (const uint8_t *)state->suiteInfo->key;
    cipherParam.keyLen = state->suiteInfo->encKeyLen;

    /** Read the explicit IV during AEAD decryption */
    const uint8_t *recordIv;
    if (state->suiteInfo->recordIvLength > 0u) {
        recordIv = &cryptMsg->text[cipherOffset];
        cipherOffset += REC_CONN_SEQ_SIZE;
    } else {
        // If no IV is displayed, use the serial number
        recordIv = cryptMsg->seq;
    }

    /** Calculate NONCE */
    uint8_t nonce[AEAD_NONCE_SIZE] = {0};
    int32_t ret = AeadGetNonce(state, nonce, sizeof(nonce), recordIv, REC_CONN_SEQ_SIZE);
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
    /**
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
        plainDataLen = cryptMsg->textLen - state->suiteInfo->recordIvLength - state->suiteInfo->macLen;
    }
    AeadGetAad(aad, &aadLen, cryptMsg, plainDataLen);
    cipherParam.aad = aad;
    cipherParam.aadLen = aadLen;

    /** Calculate the encryption length: GenericAEADCipher.content + aead tag */
    uint32_t cipherLen = cryptMsg->textLen - cipherOffset;
    /** Decryption */
    ret = SAL_CRYPT_Decrypt(&cipherParam, &cryptMsg->text[cipherOffset], cipherLen, data, dataLen);
    /* Clear sensitive information */
    BSL_SAL_CleanseData(nonce, AEAD_NONCE_SIZE);
    BSL_SAL_CleanseData(aad, AEAD_AAD_MAX_SIZE);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15396, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "decrypt record error. ret:%d", ret, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
        return HITLS_REC_BAD_RECORD_MAC;
    }
    return HITLS_SUCCESS;
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

    if (cryptMsg->isEncryptThenMac && (plaintextLen < paddingLen + CBC_PADDING_LEN_TAG_SIZE)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15399, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "record cbc mode decrypt error: ciphertext len = %u, plaintext len = %u, mac len = %u, padding len = %u.",
            cryptMsg->textLen - offset - state->suiteInfo->macLen, plaintextLen, state->suiteInfo->macLen, paddingLen);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
    }

    if (!cryptMsg->isEncryptThenMac &&
        (plaintextLen < state->suiteInfo->macLen + paddingLen + CBC_PADDING_LEN_TAG_SIZE)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15928, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "record cbc mode decrypt error: ciphertext len = %u, plaintext len = %u, mac len = %u, padding len = %u.",
            cryptMsg->textLen - offset, plaintextLen, state->suiteInfo->macLen, paddingLen);
        /* Anti-side channel attack: Calculate the MAC address even if the padding is incorrect */
        (void)RecConnGenerateMac(state, cryptMsg, mac, &macLen);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
    }

    for (uint32_t i = 1; i <= paddingLen; i++) {
        if (data[plaintextLen - 1 - i] != paddingLen) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15400, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "record cbc mode decrypt error: padding len = %u, %u-to-last padding data = %u.",
                paddingLen, i, data[plaintextLen - 1 - i], 0);
            /* Anti-side channel attack: Calculate the MAC address even if the padding is incorrect */
            if (!cryptMsg->isEncryptThenMac) {
                (void)RecConnGenerateMac(state, cryptMsg, mac, &macLen);
            }
            return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
        }
    }
    return HITLS_SUCCESS;
}

static int32_t RecConnCbcCheckAfterDecryptMac(TLS_Ctx *ctx, const REC_TextInput *cryptMsg, uint32_t plaintextLen,
    uint8_t *data, uint32_t *dataLen)
{
    const RecConnState *state = ctx->recCtx->readStates.currentState;
    uint8_t paddingLen = data[plaintextLen - 1];
    uint8_t mac[MAX_DIGEST_SIZE] = {0};
    uint32_t macLen = MAX_DIGEST_SIZE;

    uint32_t contentLen = plaintextLen - (state->suiteInfo->macLen + paddingLen + CBC_PADDING_LEN_TAG_SIZE);
    REC_TextInput input = {0};
    RecConnInitGenerateMacInput(cryptMsg, data, contentLen, &input);
    int32_t ret = RecConnGenerateMac(state, &input, mac, &macLen);
    if (ret != HITLS_SUCCESS) {
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
    }

    if (macLen != state->suiteInfo->macLen) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15401, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "record cbc mode decrypt error: macLen = %u, required len = %u.", macLen, state->suiteInfo->macLen, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
    }

    if (memcmp(&data[contentLen], mac, macLen) != 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15402, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "record cbc mode decrypt error: MAC check failed.", 0, 0, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
    }

    *dataLen = contentLen;
    return HITLS_SUCCESS;
}

static int32_t RecConnCbcDecryptByMacThenEncrypt(TLS_Ctx *ctx, const RecConnState *state, const REC_TextInput *cryptMsg,
    uint8_t *data, uint32_t *dataLen)
{
    /* Check whether the ciphertext length is an integral multiple of the ciphertext block length */
    int32_t ret = RecConnCbcCheckCryptMsg(ctx, state, cryptMsg, false);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint32_t offset = 0; /* Decryption start position */
    uint32_t plaintextLen = *dataLen; /* plaintext length */
    HITLS_CipherParameters cipherParam = {0};
    RecConnInitCipherParam(&cipherParam, state);
    /* In TLS1.2 and later versions, explicit iv is used as the first ciphertext block. Therefore, the first
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
        return ret;
    }

    /* Check MAC */
    ret = RecConnCbcCheckAfterDecryptMac(ctx, cryptMsg, plaintextLen, data, dataLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    return HITLS_SUCCESS;
}

static int32_t RecConnCbcCheckBeforeDecryptMac(TLS_Ctx *ctx, const RecConnState *state, const REC_TextInput *cryptMsg)
{
    uint8_t mac[MAX_DIGEST_SIZE] = {0};
    uint32_t macLen = MAX_DIGEST_SIZE;
    uint32_t contentLen = cryptMsg->textLen - state->suiteInfo->macLen;
    REC_TextInput input = {0};
    RecConnInitGenerateMacInput(cryptMsg, cryptMsg->text, contentLen, &input);
    int32_t ret = RecConnGenerateMac(state, &input, mac, &macLen);
    if (ret != HITLS_SUCCESS) {
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
    }

    if (macLen != state->suiteInfo->macLen) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15929, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "record cbc mode decrypt error: macLen = %u, required len = %u.",
            macLen, state->suiteInfo->macLen, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
    }

    if (memcmp(&cryptMsg->text[contentLen], mac, macLen) != 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15942, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "record cbc mode decrypt error: MAC check failed.", 0, 0, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
    }
    return HITLS_SUCCESS;
}

static int32_t RecConnCbcDecryptByEncryptThenMac(TLS_Ctx *ctx, const RecConnState *state, const REC_TextInput *cryptMsg,
    uint8_t *data, uint32_t *dataLen)
{
    /* Check MAC */
    int32_t ret = RecConnCbcCheckBeforeDecryptMac(ctx, state, cryptMsg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Check whether the ciphertext length is an integral multiple of the ciphertext block length */
    ret = RecConnCbcCheckCryptMsg(ctx, state, cryptMsg, true);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint32_t offset = 0; /* Decryption start position */
    uint32_t plaintextLen = *dataLen; /* plaintext length */
    uint8_t macLen = state->suiteInfo->macLen;
    HITLS_CipherParameters cipherParam = {0};
    RecConnInitCipherParam(&cipherParam, state);
    /* In TLS1.2 and later versions, explicit iv is used as the first ciphertext block. Therefore, the first
        * ciphertext block does not need to be decrypted */
    cipherParam.iv = cryptMsg->text;
    offset = state->suiteInfo->fixedIvLength;

    ret = SAL_CRYPT_Decrypt(&cipherParam, &cryptMsg->text[offset],
        cryptMsg->textLen - offset - macLen, data, &plaintextLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15915, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "record cbc mode decrypt error.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
        return HITLS_REC_BAD_RECORD_MAC;
    }

    /* Check padding and padding length */
    uint8_t paddingLen = data[plaintextLen - 1];
    ret = RecConnCbcCheckDecryptPadding(ctx, cryptMsg, data, plaintextLen, offset);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    *dataLen = plaintextLen - paddingLen - CBC_PADDING_LEN_TAG_SIZE;

    return HITLS_SUCCESS;
}

static int32_t RecConnCbcDecrypt(TLS_Ctx *ctx, const RecConnState *state, const REC_TextInput *cryptMsg,
    uint8_t *data, uint32_t *dataLen)
{
    uint8_t *decryptData = BSL_SAL_Malloc(cryptMsg->textLen);
    if (decryptData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15973, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record CBC decrypt error: malloc decrypt data fail.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    uint32_t decryptDataLen = cryptMsg->textLen;

    int32_t ret;
    if (ctx->negotiatedInfo.isEncryptThenMacRead) {
        ret = RecConnCbcDecryptByEncryptThenMac(ctx, state, cryptMsg, decryptData, &decryptDataLen);
    } else {
        ret = RecConnCbcDecryptByMacThenEncrypt(ctx, state, cryptMsg, decryptData, &decryptDataLen);
    }

    if (ret != HITLS_SUCCESS) {
        BSL_SAL_Free(decryptData);
        return ret;
    }

    /* The user does not want the input data array to be overwritten by content other than the plaintext */
    if (memcpy_s(data, *dataLen, decryptData, decryptDataLen) != EOK) {
        BSL_SAL_Free(decryptData);
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15974, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record CBC decrypt error: memcpy decrypt data fail.", 0, 0, 0, 0);
        return HITLS_MEMCPY_FAIL;
    }
    *dataLen = decryptDataLen;

    BSL_SAL_Free(decryptData);
    return HITLS_SUCCESS;
}

int32_t RecConnDecrypt(TLS_Ctx *ctx, RecConnState *state, const REC_TextInput *cryptMsg,
    uint8_t *data, uint32_t *dataLen)
{
    uint32_t bufSize = *dataLen;
    uint32_t ciphertextLen = RecConnCalcCiphertextLen(state, 0, ctx->negotiatedInfo.isEncryptThenMacRead);
    // The length of the record body to be decrypted must be greater than or equal to ciphertextLen
    if (cryptMsg->textLen < ciphertextLen) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15403, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record decrypt: get a record with invalid length", 0, 0, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
    }
    if (state->suiteInfo == NULL) { // No ciphersuite
        if (bufSize < cryptMsg->textLen) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15950, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "get a record with invalid length", 0, 0, 0, 0);
            return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_RECORD_OVERFLOW);
        }
        if (memcpy_s(data, bufSize, cryptMsg->text, cryptMsg->textLen) != EOK) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15404, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Record decrypt:memcpy fail.", 0, 0, 0, 0);
            return HITLS_MEMCPY_FAIL;
        }
        // If no encryption is required, the decrypted length is the plaintext length
        *dataLen = cryptMsg->textLen;
        return HITLS_SUCCESS;
    }
    uint32_t expectedPlaintextLen = CalcPlaintextLenUpperBound(state, cryptMsg->textLen);
    if (expectedPlaintextLen > bufSize) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15346, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "expectedPlaintextLen(%u) > bufSize(%u)", expectedPlaintextLen, bufSize, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_RECORD_OVERFLOW);
    }
    if (state->suiteInfo->cipherType == HITLS_AEAD_CIPHER) {
        return RecConnAeadDecrypt(ctx, state, cryptMsg, data, dataLen);
    } else if (state->suiteInfo->cipherType == HITLS_CBC_CIPHER) {
        return RecConnCbcDecrypt(ctx, state, cryptMsg, data, dataLen);
    }
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15405, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "Record decrypt:cipher is not supported.", 0, 0, 0, 0);
    return HITLS_REC_ERR_NOT_SUPPORT_CIPHER;
}

static void PackSuitInfo(RecConnSuitInfo *suitInfo, const REC_SecParameters *param)
{
    suitInfo->macAlg = param->macAlg;
    suitInfo->cipherAlg = param->cipherAlg;
    suitInfo->cipherType = param->cipherType;
    suitInfo->fixedIvLength = param->fixedIvLength;
    suitInfo->encKeyLen = param->encKeyLen;
    suitInfo->macKeyLen = param->macKeyLen;
    suitInfo->blockLength = param->blockLength;
    suitInfo->recordIvLength = param->recordIvLength;
    suitInfo->macLen = param->macLen;
    return;
}

static void RecConnCalcWriteKey(const REC_SecParameters *param, uint8_t *keyBuf, uint32_t keyBufLen,
                                RecConnSuitInfo *client, RecConnSuitInfo *server)
{
    if (keyBufLen == 0) {
        return;
    }
    uint32_t offset = 0;
    uint32_t totalOffset = 2 * param->macKeyLen + 2 * param->encKeyLen + 2 * param->fixedIvLength;
    if (keyBufLen < totalOffset) {
        return;
    }

    if (param->macKeyLen > 0u) {
        if (memcpy_s(client->macKey, sizeof(client->macKey), keyBuf, param->macKeyLen) != EOK) {
            return;
        }
        offset += param->macKeyLen;
        if (memcpy_s(server->macKey, sizeof(server->macKey), keyBuf + offset, param->macKeyLen) != EOK) {
            return;
        }
        offset += param->macKeyLen;
    }
    if (param->encKeyLen > 0u) {
        if (memcpy_s(client->key, sizeof(client->key), keyBuf + offset, param->encKeyLen) != EOK) {
            return;
        }
        offset += param->encKeyLen;
        if (memcpy_s(server->key, sizeof(server->key), keyBuf + offset, param->encKeyLen) != EOK) {
            return;
        }
        offset += param->encKeyLen;
    }
    if (param->fixedIvLength > 0u) {
        if (memcpy_s(client->iv, sizeof(client->iv), keyBuf + offset, param->fixedIvLength) != EOK) {
            return;
        }
        offset += param->fixedIvLength;
        if (memcpy_s(server->iv, sizeof(server->iv), keyBuf + offset, param->fixedIvLength) != EOK) {
            return;
        }
    }
    PackSuitInfo(client, param);
    PackSuitInfo(server, param);
}

int32_t RecConnKeyBlockGen(const REC_SecParameters *param, RecConnSuitInfo *client, RecConnSuitInfo *server)
{
    /** Calculate the key length: 2MAC, 2key, 2IV  */
    uint32_t keyLen = ((uint32_t)param->macKeyLen * 2) + ((uint32_t)param->encKeyLen * 2) +
        ((uint32_t)param->fixedIvLength * 2);
    if (keyLen == 0u || param->macKeyLen > sizeof(client->macKey) ||
        param->encKeyLen > sizeof(client->key) || param->fixedIvLength > sizeof(client->iv)) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_NOT_SUPPORT_CIPHER);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15943, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record Key: not support--length is invalid.", 0, 0, 0, 0);
        return HITLS_REC_ERR_NOT_SUPPORT_CIPHER;
    }

    /*  Based on RFC5246 6.3
        key_block = PRF(SecurityParameters.master_secret, "key expansion", SecurityParameters.server_random +
                    SecurityParameters.client_random);
    */
    CRYPT_KeyDeriveParameters keyDeriveParam = {0};
    keyDeriveParam.hashAlgo = param->prfAlg;
    keyDeriveParam.secret = param->masterSecret;
    keyDeriveParam.secretLen = REC_MASTER_SECRET_LEN;
    keyDeriveParam.label = (const uint8_t *)KEY_EXPANSION_LABEL;
    keyDeriveParam.labelLen = strlen(KEY_EXPANSION_LABEL);

    uint8_t randomValue[REC_RANDOM_LEN * 2];
    /** Random value of the replication server */
    (void)memcpy_s(randomValue, sizeof(randomValue), param->serverRandom, REC_RANDOM_LEN);
    /** Random value of the replication client */
    (void)memcpy_s(&randomValue[REC_RANDOM_LEN], sizeof(randomValue) - REC_RANDOM_LEN,
        param->clientRandom, REC_RANDOM_LEN);

    keyDeriveParam.seed = randomValue;
    keyDeriveParam.seedLen = REC_RANDOM_LEN * 2; // Total length of 2 random numbers

    /** Maximum key length: 2MAC, 2key, 2IV */
    uint8_t keyBuf[REC_MAX_KEY_BLOCK_LEN];
    int32_t ret = SAL_CRYPT_PRF(&keyDeriveParam, keyBuf, keyLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15944, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Record Key:generate fail.", 0, 0, 0, 0);
        return ret;
    }

    RecConnCalcWriteKey(param, keyBuf, REC_MAX_KEY_BLOCK_LEN, client, server);
    BSL_SAL_CleanseData(keyBuf, sizeof(keyBuf));
    return HITLS_SUCCESS;
}

static int32_t RecTLS13CalcWriteKey(HITLS_HashAlgo hashAlgo, const uint8_t *baseKey, uint32_t baseKeyLen,
    uint8_t *key, uint32_t keyLen)
{
    uint8_t label[] = "key";
    CRYPT_KeyDeriveParameters deriveInfo = {0};
    deriveInfo.hashAlgo = hashAlgo;
    deriveInfo.secret = baseKey;
    deriveInfo.secretLen = baseKeyLen;
    deriveInfo.label = label;
    deriveInfo.labelLen = sizeof(label) - 1;
    deriveInfo.seed = NULL;
    deriveInfo.seedLen = 0;
    return SAL_CRYPT_HkdfExpandLabel(&deriveInfo, key, keyLen);
}

static int32_t RecTLS13CalcWriteIv(HITLS_HashAlgo hashAlgo, const uint8_t *baseKey, uint32_t baseKeyLen,
    uint8_t *iv, uint32_t ivLen)
{
    uint8_t label[] = "iv";
    CRYPT_KeyDeriveParameters deriveInfo = {0};
    deriveInfo.hashAlgo = hashAlgo;
    deriveInfo.secret = baseKey;
    deriveInfo.secretLen = baseKeyLen;
    deriveInfo.label = label;
    deriveInfo.labelLen = sizeof(label) - 1;
    deriveInfo.seed = NULL;
    deriveInfo.seedLen = 0;
    return SAL_CRYPT_HkdfExpandLabel(&deriveInfo, iv, ivLen);
}

int32_t RecTLS13ConnKeyBlockGen(const REC_SecParameters *param, RecConnSuitInfo *suitInfo)
{
    const uint8_t *secret = (const uint8_t *)param->masterSecret;
    uint32_t secretLen = SAL_CRYPT_DigestSize(param->prfAlg);
    if (secretLen == 0) {
        return HITLS_CRYPT_ERR_DIGEST;
    }
    uint32_t keyLen = param->encKeyLen;
    uint32_t ivLen = param->fixedIvLength;

    if (secretLen > sizeof(param->masterSecret) || keyLen > sizeof(suitInfo->key) || ivLen > sizeof(suitInfo->iv)) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_NOT_SUPPORT_CIPHER);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15408, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "length is invalid.", 0, 0, 0, 0);
        return HITLS_REC_ERR_NOT_SUPPORT_CIPHER;
    }

    int32_t ret = RecTLS13CalcWriteKey(param->prfAlg, secret, secretLen, suitInfo->key, keyLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = RecTLS13CalcWriteIv(param->prfAlg, secret, secretLen, suitInfo->iv, ivLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    PackSuitInfo(suitInfo, param);
    return HITLS_SUCCESS;
}
