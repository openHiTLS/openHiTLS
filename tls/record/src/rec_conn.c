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
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "hitls_error.h"
#include "crypt.h"
#include "rec_alert.h"
#include "rec_crypto.h"
#include "rec_conn.h"


#define KEY_EXPANSION_LABEL "key expansion"

#ifdef HITLS_TLS_SUITE_CIPHER_CBC
#define CBC_MAC_HEADER_LEN 13U
#endif

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
    if (state->suiteInfo != NULL) {
#ifdef HITLS_TLS_CALLBACK_CRYPT_HMAC_PRIMITIVES
        SAL_CRYPT_HmacFree(state->suiteInfo->macCtx);
        state->suiteInfo->macCtx = NULL;
#endif
        SAL_CRYPT_CipherFree(state->suiteInfo->ctx);
        state->suiteInfo->ctx = NULL;
    }
    /* Clear sensitive information */
    BSL_SAL_CleanseData(state->suiteInfo, sizeof(RecConnSuitInfo));
    BSL_SAL_FREE(state->suiteInfo);
    BSL_SAL_FREE(state);
}

uint64_t RecConnGetSeqNum(const RecConnState *state)
{
    return state->seq;
}

void RecConnSetSeqNum(RecConnState *state, uint64_t seq)
{
    state->seq = seq;
}

#ifdef HITLS_TLS_PROTO_DTLS12
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
    if (state->suiteInfo != NULL) {
        SAL_CRYPT_CipherFree(state->suiteInfo->ctx);
        state->suiteInfo->ctx = NULL;
#ifdef HITLS_TLS_CALLBACK_CRYPT_HMAC_PRIMITIVES
        SAL_CRYPT_HmacFree(state->suiteInfo->macCtx);
        state->suiteInfo->macCtx = NULL;
#endif
    }
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

#ifdef HITLS_TLS_SUITE_CIPHER_CBC
uint32_t RecGetHashAlgoFromMacAlgo(HITLS_MacAlgo macAlgo)
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
#ifdef HITLS_TLS_PROTO_TLCP11
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

int32_t RecConnGenerateMac(HITLS_Lib_Ctx *libCtx, const char *attrName,
    RecConnSuitInfo *suiteInfo, const REC_TextInput *plainMsg,
    uint8_t *mac, uint32_t *macLen)
{
    int32_t ret = HITLS_SUCCESS;
    uint8_t header[CBC_MAC_HEADER_LEN] = {0};
    uint32_t offset = 0;
    if (memcpy_s(header, CBC_MAC_HEADER_LEN, plainMsg->seq, REC_CONN_SEQ_SIZE) != EOK) {  //  sequence or epoch + seq
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_MEMCPY_FAIL, BINLOG_ID17228, "memcpy fail");
    }
    offset += REC_CONN_SEQ_SIZE;

    header[offset] = plainMsg->type;                                      // The eighth byte is the record type
    offset++;
    BSL_Uint16ToByte(plainMsg->version, &header[offset]);                 // The 9th and 10th bytes are version numbers
    offset += sizeof(uint16_t);
    BSL_Uint16ToByte((uint16_t)plainMsg->textLen, &header[offset]);       // The 11th and 12th bytes are the data length

    HITLS_HashAlgo hashAlgo = RecGetHashAlgoFromMacAlgo(suiteInfo->macAlg);
    if (hashAlgo == HITLS_HASH_BUTT) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_REC_ERR_GENERATE_MAC, BINLOG_ID17229,
            "RecGetHashAlgoFromMacAlgo fail");
    }

    if (suiteInfo->macCtx == NULL) {
        suiteInfo->macCtx = SAL_CRYPT_HmacInit(libCtx, attrName,
            hashAlgo, suiteInfo->macKey, suiteInfo->macKeyLen);
        ret = suiteInfo->macCtx == NULL ? HITLS_REC_ERR_GENERATE_MAC : HITLS_SUCCESS;
    } else {
        ret = SAL_CRYPT_HmacReInit(suiteInfo->macCtx);
    }
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_GENERATE_MAC);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_REC_ERR_GENERATE_MAC, BINLOG_ID15389, "SAL_CRYPT_HmacInit fail");
    }

    ret = SAL_CRYPT_HmacUpdate(suiteInfo->macCtx, header, CBC_MAC_HEADER_LEN);
    if (ret != HITLS_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID17230, "HmacUpdate fail");
    }

    ret = SAL_CRYPT_HmacUpdate(suiteInfo->macCtx, plainMsg->text, plainMsg->textLen);
    if (ret != HITLS_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID17231, "HmacUpdate fail");
    }

    ret = SAL_CRYPT_HmacFinal(suiteInfo->macCtx, mac, macLen);
    if (ret != HITLS_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID17232, "HmacFinal fail");
    }
    return HITLS_SUCCESS;
}

void RecConnInitGenerateMacInput(const REC_TextInput *in, const uint8_t *text, uint32_t textLen,
    REC_TextInput *out)
{
    out->version = in->version;
    out->negotiatedVersion = in->negotiatedVersion;
#ifdef HITLS_TLS_FEATURE_ETM
    out->isEncryptThenMac = in->isEncryptThenMac;
#endif
    out->type = in->type;
    out->text = text;
    out->textLen = textLen;
    for (uint32_t i = 0u; i < REC_CONN_SEQ_SIZE; i++) {
        out->seq[i] = in->seq[i];
    }
}

int32_t RecConnCheckMac(TLS_Ctx *ctx, RecConnSuitInfo *suiteInfo, const REC_TextInput *cryptMsg,
    const uint8_t *text, uint32_t textLen)
{
    REC_TextInput input = {0};
    uint8_t mac[MAX_DIGEST_SIZE] = {0};
    uint32_t macLen = MAX_DIGEST_SIZE;
    RecConnInitGenerateMacInput(cryptMsg, text, textLen - suiteInfo->macLen, &input);
    int32_t ret = RecConnGenerateMac(LIBCTX_FROM_CTX(ctx), ATTRIBUTE_FROM_CTX(ctx),
        suiteInfo, &input, mac, &macLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17233, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "RecConnGenerateMac fail.", 0, 0, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
    }
    if (macLen != suiteInfo->macLen) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15929, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "record cbc mode decrypt error: macLen = %u, required len = %u.",
            macLen, suiteInfo->macLen, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
    }

    if (ConstTimeMemcmp(&text[textLen - suiteInfo->macLen], mac, macLen) == 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15942, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "record cbc mode decrypt error: MAC check failed.", 0, 0, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
    }
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_SUITE_CIPHER_CBC */
int32_t RecConnEncrypt(
    TLS_Ctx *ctx, RecConnState *state, const REC_TextInput *plainMsg, uint8_t *cipherText, uint32_t cipherTextLen)
{
    return RecGetCryptoFuncs(state->suiteInfo)->encryt(ctx, state, plainMsg, cipherText, cipherTextLen);
}

int32_t RecConnDecrypt(TLS_Ctx *ctx, RecConnState *state, const REC_TextInput *cryptMsg, uint8_t *data,
    uint32_t *dataLen)
{
    const RecCryptoFunc *funcs = RecGetCryptoFuncs(state->suiteInfo);
    uint32_t ciphertextLen = funcs->calCiphertextLen(ctx, state->suiteInfo, 0, true);
    // The length of the record body to be decrypted must be greater than or equal to ciphertextLen
    if (cryptMsg->textLen < ciphertextLen) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15403, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "RecConnDecrypt Failed: record body length to be decrypted is %u, lower bound of ciphertext len is %u",
            cryptMsg->textLen, ciphertextLen, 0, 0);
        return RecordSendAlertMsg(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
    }
    return funcs->decrypt(ctx, state, cryptMsg, data, dataLen);
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

int32_t RecConnKeyBlockGen(HITLS_Lib_Ctx *libCtx, const char *attrName,
    const REC_SecParameters *param, RecConnSuitInfo *client, RecConnSuitInfo *server)
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
    keyDeriveParam.libCtx = libCtx;
    keyDeriveParam.attrName = attrName;

    uint8_t randomValue[REC_RANDOM_LEN * 2];
    /** Random value of the replication server */
    (void)memcpy_s(randomValue, sizeof(randomValue), param->serverRandom, REC_RANDOM_LEN);
    /** Random value of the replication client */
    (void)memcpy_s(&randomValue[REC_RANDOM_LEN], sizeof(randomValue) - REC_RANDOM_LEN,
        param->clientRandom, REC_RANDOM_LEN);

    keyDeriveParam.seed = randomValue;
    // Total length of 2 random numbers
    keyDeriveParam.seedLen = REC_RANDOM_LEN * 2;

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

#ifdef HITLS_TLS_PROTO_TLS13
static const uint8_t DEVICE_INFO_KEY[] = "key";
static const uint8_t DEVICE_INFO_IV[] = "iv";
int32_t RecTLS13CalcWriteKey(CRYPT_KeyDeriveParameters *deriveInfo, uint8_t *key, uint32_t keyLen)
{
    deriveInfo->label = DEVICE_INFO_KEY;
    deriveInfo->labelLen = sizeof(DEVICE_INFO_KEY) - 1;
    return SAL_CRYPT_HkdfExpandLabel(deriveInfo, key, keyLen);
}

int32_t RecTLS13CalcWriteIv(CRYPT_KeyDeriveParameters *deriveInfo, uint8_t *iv, uint32_t ivLen)
{
    deriveInfo->label = DEVICE_INFO_IV;
    deriveInfo->labelLen = sizeof(DEVICE_INFO_IV) - 1;
    return SAL_CRYPT_HkdfExpandLabel(deriveInfo, iv, ivLen);
}

int32_t RecTLS13ConnKeyBlockGen(HITLS_Lib_Ctx *libCtx, const char *attrName,
    const REC_SecParameters *param, RecConnSuitInfo *suitInfo)
{
    const uint8_t *secret = (const uint8_t *)param->masterSecret;
    uint32_t secretLen = SAL_CRYPT_DigestSize(param->prfAlg);
    if (secretLen == 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17234, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "DigestSize err", 0, 0, 0, 0);
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
    CRYPT_KeyDeriveParameters deriveInfo = {0};
    deriveInfo.hashAlgo = param->prfAlg;
    deriveInfo.secret = secret;
    deriveInfo.secretLen = secretLen;
    deriveInfo.libCtx = libCtx;
    deriveInfo.attrName = attrName;
    int32_t ret = RecTLS13CalcWriteKey(&deriveInfo, suitInfo->key, keyLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17235, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "CalcWriteKey fail", 0, 0, 0, 0);
        return ret;
    }

    ret = RecTLS13CalcWriteIv(&deriveInfo, suitInfo->iv, ivLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17236, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "CalcWriteIv fail", 0, 0, 0, 0);
        return ret;
    }

    PackSuitInfo(suitInfo, param);
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_TLS13 */