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
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "hitls_error.h"
#include "hs_kx.h"
#include "transcript_hash.h"
#include "hs_verify.h"

#define HS_VERIFY_DATA_LEN 12u

#define CLIENT_FINISHED_LABEL "client finished"
#define SERVER_FINISHED_LABEL "server finished"

#ifdef HITLS_TLS_PROTO_TLS13
#define MSG_HASH_HEADER_SIZE 4                                     /* message_hash message header length */
#define MAX_MSG_HASH_SIZE (MAX_DIGEST_SIZE + MSG_HASH_HEADER_SIZE) /* Maximum message_hash message length */
#endif /* HITLS_TLS_PROTO_TLS13 */
#ifdef HITLS_TLS_PROTO_TLS13
#define TLS13_CLIENT_CERT_VERIFY_LABEL "TLS 1.3, client CertificateVerify"
#define TLS13_SERVER_CERT_VERIFY_LABEL "TLS 1.3, server CertificateVerify"

#define TLS13_CERT_VERIFY_PREFIX 0x20 /* The signature data in TLS 1.3 is firstly filled with 64 0x20s */
#define TLS13_CERT_VERIFY_PREFIX_LEN 64
#endif /* #ifdef HITLS_TLS_PROTO_TLS13 */

int32_t VERIFY_Init(HS_Ctx *hsCtx)
{
    VERIFY_Deinit(hsCtx);
    VerifyCtx *verifyCtx = (VerifyCtx *)BSL_SAL_Calloc(1u, sizeof(VerifyCtx));
    if (verifyCtx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15475, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Verify init error: out of memory.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    verifyCtx->dataBuf = (HsMsgCache *)BSL_SAL_Calloc(1u, sizeof(HsMsgCache));
    if (verifyCtx->dataBuf == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15476, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Verify databuf malloc error: out of memory.", 0, 0, 0, 0);
        BSL_SAL_FREE(verifyCtx);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }
    hsCtx->verifyCtx = verifyCtx;
    return HITLS_SUCCESS;
}

void VERIFY_Deinit(HS_Ctx *hsCtx)
{
    if (hsCtx == NULL) {
        return;
    }
    VerifyCtx *verifyCtx = hsCtx->verifyCtx;
    if (verifyCtx == NULL) {
        return;
    }
    if (verifyCtx->hashCtx != NULL) {
        SAL_CRYPT_DigestFree(verifyCtx->hashCtx);
    }
    VERIFY_FreeMsgCache(verifyCtx);
    BSL_SAL_FREE(verifyCtx);
    hsCtx->verifyCtx = NULL;
    return;
}
#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
static int32_t SaveVerifyData(TLS_Ctx *ctx, bool isClient)
{
    VerifyCtx *verifyCtx = ctx->hsCtx->verifyCtx;
    uint8_t *verifyData = isClient ? ctx->negotiatedInfo.clientVerifyData : ctx->negotiatedInfo.serverVerifyData;
    if (memcpy_s(verifyData, MAX_DIGEST_SIZE, verifyCtx->verifyData, verifyCtx->verifyDataSize) != EOK) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15909, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "copy verifyData fail.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        return HITLS_MEMCPY_FAIL;
    }
    if (isClient) {
        ctx->negotiatedInfo.clientVerifyDataSize = verifyCtx->verifyDataSize;
    } else {
        ctx->negotiatedInfo.serverVerifyDataSize = verifyCtx->verifyDataSize;
    }
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_RENEGOTIATION */
int32_t VERIFY_CalcVerifyData(TLS_Ctx *ctx, bool isClient, const uint8_t *masterSecret, uint32_t masterSecretLen)
{
    int32_t ret = HITLS_SUCCESS;
    uint32_t digestLen = MAX_DIGEST_SIZE;
    uint8_t digest[MAX_DIGEST_SIZE] = {0};
    VerifyCtx *verifyCtx = ctx->hsCtx->verifyCtx;

    ret = VERIFY_CalcSessionHash(verifyCtx, digest, &digestLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15477, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Verify data calculate error: calc session hash fail.", 0, 0, 0, 0);
        return ret;
    }

    CRYPT_KeyDeriveParameters deriveInfo;
    deriveInfo.hashAlgo = verifyCtx->hashAlgo;
    deriveInfo.secret = masterSecret;
    deriveInfo.secretLen = masterSecretLen;
    deriveInfo.label = isClient ? ((const uint8_t *)CLIENT_FINISHED_LABEL) : ((const uint8_t *)SERVER_FINISHED_LABEL);
    deriveInfo.labelLen = isClient ? strlen(CLIENT_FINISHED_LABEL) : strlen(SERVER_FINISHED_LABEL);
    deriveInfo.seed = digest;
    deriveInfo.seedLen = digestLen;
    deriveInfo.libCtx = LIBCTX_FROM_CTX(ctx);
    deriveInfo.attrName = ATTRIBUTE_FROM_CTX(ctx);
    ret = SAL_CRYPT_PRF(&deriveInfo, verifyCtx->verifyData, HS_VERIFY_DATA_LEN);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15478, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Verify data calculate error: PRF fail.", 0, 0, 0, 0);
        return ret;
    }
    verifyCtx->verifyDataSize = HS_VERIFY_DATA_LEN;
#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
    ret = SaveVerifyData(ctx, isClient);
#endif /* HITLS_TLS_FEATURE_RENEGOTIATION */
    return ret;
}

static uint32_t GetHsDataLen(const VerifyCtx *ctx)
{
    uint32_t len = 0;
    const HsMsgCache *block = ctx->dataBuf;
    /* Calculate the signature data length */
    while (block != NULL) {
        len += block->dataSize;
        block = block->next;
    }
    return len;
}

static void LoopBlocks(const HsMsgCache *block, uint8_t *data, uint32_t len)
{
    uint32_t offset = 0;
    while ((block != NULL) && (block->dataSize > 0)) {
        (void) memcpy_s(data + offset, len - offset, block->data, block->dataSize);
        offset += block->dataSize;
        block = block->next;
    }
}

static int32_t GetHsData(VerifyCtx *ctx, uint8_t **data, uint32_t *dataLen)
{
    uint32_t hsDataLen = GetHsDataLen(ctx);
    if (hsDataLen == 0) {
        *dataLen = 0;
        *data = NULL;
        return HITLS_SUCCESS;
    }
    uint8_t *hsData = BSL_SAL_Malloc(hsDataLen);
    if (hsData == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16847, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Malloc fail", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }
    const HsMsgCache *block = ctx->dataBuf;
    LoopBlocks(block, hsData, hsDataLen);
    *dataLen = hsDataLen;
    *data = hsData;
    return HITLS_SUCCESS;
}

#ifdef HITLS_TLS_PROTO_TLS13
/* The sender packs the data, calculates the binder, and then appends verified data.
 *  The receiver parses the data, and then calculates the binder. */
static int32_t GetHsDataForBinder(VerifyCtx *ctx, uint32_t *dataLen, bool isClient, uint8_t **data)
{
    if (isClient) {
        return GetHsData(ctx, data, dataLen);
    }

    const HsMsgCache *block = ctx->dataBuf;
    if (block == NULL || block->next == NULL || block->next->data == 0) {
        return HITLS_SUCCESS;
    }
    uint32_t lenExcludeLastBlock = 0;
    /* Calculate the total length excluding the last block. */
    while (block->next != NULL && block->next->dataSize != 0) {
        lenExcludeLastBlock += block->dataSize;
        block = block->next;
    }
    uint32_t lastBlockLen = block->dataSize;
    if (lenExcludeLastBlock == 0) {
        *data = NULL;
        *dataLen = lenExcludeLastBlock;
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15479, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN, "In verify ctx, empty data.",
            0, 0, 0, 0);
        return HITLS_SUCCESS;
    }
    uint8_t *hsData = BSL_SAL_Malloc(lenExcludeLastBlock + lastBlockLen);
    if (hsData == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16869, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Malloc fail", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }
    (void)LoopBlocks(ctx->dataBuf, hsData, lenExcludeLastBlock + lastBlockLen);
    *dataLen = lenExcludeLastBlock;
    *data = hsData;
    return HITLS_SUCCESS;
}

static const char *GetCertVerifyLabel(bool isClient, uint32_t *len)
{
    if (isClient) {
        *len = strlen(TLS13_CLIENT_CERT_VERIFY_LABEL);
        return TLS13_CLIENT_CERT_VERIFY_LABEL;
    }
    *len = strlen(TLS13_SERVER_CERT_VERIFY_LABEL);
    return TLS13_SERVER_CERT_VERIFY_LABEL;
}

static uint8_t *Tls13GetUnsignData(TLS_Ctx *ctx, uint32_t *dataLen, bool isClient)
{
    VerifyCtx *verifyCtx = ctx->hsCtx->verifyCtx;
    uint32_t digestLen = MAX_DIGEST_SIZE;
    uint8_t digest[MAX_DIGEST_SIZE] = {0};
    int32_t ret = VERIFY_CalcSessionHash(verifyCtx, digest, &digestLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15480, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "calc session hash fail when get unsign data.", 0, 0, 0, 0);
        return NULL;
    }

    uint32_t labelLen = 0;
    const char *label = GetCertVerifyLabel(isClient, &labelLen);

    /* sixty-four 0x20 s + label + 0x00 + SessionHash */
    uint32_t unsignDataLen = TLS13_CERT_VERIFY_PREFIX_LEN + labelLen + 1 + digestLen;
    uint8_t *unsignData = BSL_SAL_Malloc(unsignDataLen);
    if (unsignData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15481, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "malloc unsignData fail when get unsign data.", 0, 0, 0, 0);
        return NULL;
    }

    uint32_t offset = 0;
    /* Filled prefix: sixty-four 0x20 s */
    (void)memset_s(unsignData, unsignDataLen, TLS13_CERT_VERIFY_PREFIX, TLS13_CERT_VERIFY_PREFIX_LEN);
    offset += TLS13_CERT_VERIFY_PREFIX_LEN;

    /* Filled labels */
    if (memcpy_s(&unsignData[offset], unsignDataLen - offset, label, labelLen) != EOK) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16870, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "memcpy fail", 0, 0, 0, 0);
        BSL_SAL_FREE(unsignData);
        return NULL;
    }
    offset += labelLen;

    /* Filled with one 0 */
    unsignData[offset] = 0;
    offset++;

    /*  Filled SessionHash */
    if (memcpy_s(&unsignData[offset], unsignDataLen - offset, digest, digestLen) != EOK) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16871, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "memcpy fail", 0, 0, 0, 0);
        BSL_SAL_FREE(unsignData);
        return NULL;
    }

    *dataLen = unsignDataLen;
    return unsignData;
}
#endif /* HITLS_TLS_PROTO_TLS13 */
#ifdef HITLS_TLS_PROTO_TLCP11
static uint8_t *TlcpGetUnsignData(TLS_Ctx *ctx, uint32_t *dataLen)
{
    int32_t ret = HITLS_SUCCESS;
    uint32_t unsignDataLen = MAX_DIGEST_SIZE;
    uint8_t *unsignData = BSL_SAL_Malloc(unsignDataLen);
    if (unsignData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16214, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "malloc unsignData fail when get unsign data", 0, 0, 0, 0);
        return NULL;
    }
    VerifyCtx *verifyCtx = ctx->hsCtx->verifyCtx;
    ret = VERIFY_CalcSessionHash(verifyCtx, unsignData, &unsignDataLen);
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        BSL_SAL_Free(unsignData);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16215, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "calc session hash fail when get unsign data", 0, 0, 0, 0);
        return NULL;
    }

    *dataLen = unsignDataLen;
    return unsignData;
}
#endif

static uint8_t *GetUnsignData(TLS_Ctx *ctx, uint32_t *dataLen, bool isClient, HITLS_HashAlgo hashAlgo)
{
    (void)isClient;
    (void)hashAlgo;
#ifdef HITLS_TLS_PROTO_TLS13
    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLS13) {
        return Tls13GetUnsignData(ctx, dataLen, isClient);
    }
#endif /* HITLS_TLS_PROTO_TLS13 */
#ifdef HITLS_TLS_PROTO_TLCP11
    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLCP_DTLCP11) {
        return TlcpGetUnsignData(ctx, dataLen);
    }
#endif
    uint8_t *data = NULL;
    (void)GetHsData(ctx->hsCtx->verifyCtx, &data, dataLen);
    return data;
}

int32_t VERIFY_CalcSignData(TLS_Ctx *ctx, HITLS_CERT_Key *privateKey, HITLS_SignHashAlgo signScheme)
{
    int32_t ret = HITLS_SUCCESS;
    HITLS_SignAlgo signAlgo = 0;
    HITLS_HashAlgo hashAlgo = 0;
    VerifyCtx *verifyCtx = ctx->hsCtx->verifyCtx;

    if (CFG_GetSignParamBySchemes(ctx, signScheme, &signAlgo, &hashAlgo) != true) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15482, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get sign parm fail.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_PACK_SIGNATURE_ERR);
        return HITLS_PACK_SIGNATURE_ERR;
    }
    /* Obtaining the data to be signed */
    uint32_t dataLen = 0u;
    uint8_t *data = GetUnsignData(ctx, &dataLen, ctx->isClient, hashAlgo); // 签名的时候使用的是本端的isClient
    if (data == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16872, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "GetUnsignData fail", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_GET_UNSIGN_DATA_FAIL);
        return HITLS_MSG_HANDLE_GET_UNSIGN_DATA_FAIL;
    }

    CERT_SignParam signParam = {0};
    signParam.signAlgo = signAlgo;
    signParam.hashAlgo = hashAlgo;
    signParam.data = data;
    signParam.dataLen = dataLen;
    signParam.sign = verifyCtx->verifyData;
    signParam.signLen = MAX_SIGN_SIZE;

    ret = SAL_CERT_CreateSign(ctx, privateKey, &signParam);
    if ((ret != HITLS_SUCCESS) || (signParam.signLen > MAX_SIGN_SIZE)) {
        BSL_SAL_FREE(data);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15483, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "create signature fail.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_PACK_SIGNATURE_ERR);
        return HITLS_PACK_SIGNATURE_ERR;
    }
    verifyCtx->verifyDataSize = signParam.signLen;

    BSL_SAL_FREE(data);
    return HITLS_SUCCESS;
}

int32_t VERIFY_VerifySignData(TLS_Ctx *ctx, HITLS_CERT_Key *pubkey, HITLS_SignHashAlgo signScheme,
                              const uint8_t *signData, uint16_t signDataLen)
{
    int32_t ret = HITLS_SUCCESS;
    HITLS_SignAlgo signAlgo = 0;
    HITLS_HashAlgo hashAlgo = 0;

    if (CFG_GetSignParamBySchemes(ctx, signScheme, &signAlgo, &hashAlgo) != true) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15484, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get sign parm fail.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        BSL_ERR_PUSH_ERROR(HITLS_PACK_SIGNATURE_ERR);
        return HITLS_PACK_SIGNATURE_ERR;
    }
    /* Obtain the data to be signed */
    uint32_t dataLen = 0;
    uint8_t *data = GetUnsignData(ctx, &dataLen, !ctx->isClient, hashAlgo);
    if (data == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16873, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "get data fail", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_GET_UNSIGN_DATA_FAIL);
        return HITLS_MSG_HANDLE_GET_UNSIGN_DATA_FAIL;
    }

    CERT_SignParam signParam = {.signAlgo = signAlgo, .hashAlgo = hashAlgo, .data = data, .dataLen = dataLen};
    signParam.sign = BSL_SAL_Dump(signData, signDataLen);
    if (signParam.sign == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16874, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "dump fail", 0, 0, 0, 0);
        BSL_SAL_FREE(data);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }
    signParam.signLen = signDataLen;

    ret = SAL_CERT_VerifySign(ctx, pubkey, &signParam);
    BSL_SAL_FREE(signParam.sign);
    BSL_SAL_FREE(data);
    if (ret != HITLS_SUCCESS) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECRYPT_ERROR);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15485, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "verify signature fail.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_VERIFY_SIGN_FAIL);
        return HITLS_MSG_HANDLE_VERIFY_SIGN_FAIL;
    }
    return HITLS_SUCCESS;
}

int32_t VERIFY_GetVerifyData(const VerifyCtx *ctx, uint8_t *verifyData, uint32_t *verifyDataLen)
{
    if (ctx->verifyDataSize > MAX_DIGEST_SIZE) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15488, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Get verify data error: incorrect digest size.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_INCORRECT_DIGEST_LEN);
        return HITLS_MSG_HANDLE_INCORRECT_DIGEST_LEN;
    }

    if (memcpy_s(verifyData, *verifyDataLen, ctx->verifyData, ctx->verifyDataSize) != EOK) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15489, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Get verify data error: memcpy fail.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        return HITLS_MEMCPY_FAIL;
    }
    *verifyDataLen = ctx->verifyDataSize;
    return HITLS_SUCCESS;
}
#ifdef HITLS_TLS_PROTO_TLS13
static uint8_t *GetBaseKey(TLS_Ctx *ctx, bool isClient)
{
    uint8_t *baseKey = NULL;
#ifdef HITLS_TLS_FEATURE_PHA
    if (ctx->phaState == PHA_REQUESTED) {
        baseKey = isClient ? ctx->clientAppTrafficSecret : ctx->serverAppTrafficSecret;
    } else
#endif /* HITLS_TLS_FEATURE_PHA */
    {
        baseKey = isClient ? ctx->hsCtx->clientHsTrafficSecret : ctx->hsCtx->serverHsTrafficSecret;
    }
    return baseKey;
}

int32_t VERIFY_Tls13CalcVerifyData(TLS_Ctx *ctx, bool isClient)
{
    int32_t ret = HITLS_SUCCESS;
    HITLS_HashAlgo hashAlg = ctx->negotiatedInfo.cipherSuiteInfo.hashAlg;
    uint32_t hashLen = SAL_CRYPT_DigestSize(hashAlg);
    if (hashLen == 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16875, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "DigestSize err", 0, 0, 0, 0);
        return HITLS_CRYPT_ERR_DIGEST;
    }
    uint8_t finishedKey[MAX_DIGEST_SIZE] = {0};
    uint8_t *baseKey = NULL;

    baseKey = GetBaseKey(ctx, isClient);

    /* finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length) */
    ret = HS_TLS13DeriveFinishedKey(LIBCTX_FROM_CTX(ctx), ATTRIBUTE_FROM_CTX(ctx),
        hashAlg, baseKey, hashLen, finishedKey, hashLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16876, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "DeriveFinishedKey fail", 0, 0, 0, 0);
        return ret;
    }

    VerifyCtx *verifyCtx = ctx->hsCtx->verifyCtx;
    uint32_t digestLen = MAX_DIGEST_SIZE;
    uint8_t digest[MAX_DIGEST_SIZE] = {0};
    ret = VERIFY_CalcSessionHash(verifyCtx, digest, &digestLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15490, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "calc session hash fail when calc tls13 verify data.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }

    /* verify_data = HMAC(finished_key, Transcript-Hash(Handshake Context, Certificate*, CertificateVerify*)) */
    verifyCtx->verifyDataSize = hashLen;
    ret = SAL_CRYPT_Hmac(LIBCTX_FROM_CTX(ctx), ATTRIBUTE_FROM_CTX(ctx),
        hashAlg, finishedKey, hashLen, digest, digestLen, verifyCtx->verifyData, &verifyCtx->verifyDataSize);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15910, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "SAL_CRYPT_Hmac fail when calc tls13 verify data.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
    }
    return ret;
}

static int32_t ConstructMsgHash(HITLS_Lib_Ctx *libCtx, const char *attrName, HITLS_HashAlgo hashAlgo,
    HsMsgCache *dataBuf, uint8_t *out, uint32_t *outLen)
{
    int32_t ret = HITLS_SUCCESS;
    uint32_t digestLen = *outLen - MSG_HASH_HEADER_SIZE;
    uint32_t inLen = dataBuf->dataSize;
    uint8_t *in = BSL_SAL_Dump(dataBuf->data, dataBuf->dataSize);
    if (in == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16877, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Dump fail", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(BSL_UIO_MEM_ALLOC_FAIL);
        return BSL_UIO_MEM_ALLOC_FAIL;
    }
    ret = SAL_CRYPT_Digest(libCtx, attrName, hashAlgo, in, inLen, &out[MSG_HASH_HEADER_SIZE], &digestLen);
    BSL_SAL_FREE(in);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16878, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Digest fail", 0, 0, 0, 0);
        return ret;
    }

    uint32_t offset = 0;
    out[offset++] = MESSAGE_HASH;
    out[offset++] = 0;
    out[offset++] = 0;
    out[offset] = (uint8_t)digestLen;
    *outLen = digestLen + MSG_HASH_HEADER_SIZE;

    return HITLS_SUCCESS;
}

static int32_t ReinitVerify(TLS_Ctx *ctx, uint8_t *msgHash, uint32_t msgHashLen, uint8_t *hrr, uint32_t hrrLen)
{
    int32_t ret = HITLS_SUCCESS;

    VERIFY_Deinit(ctx->hsCtx);

    ret = VERIFY_Init(ctx->hsCtx);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16879, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "VERIFY_Init fail", 0, 0, 0, 0);
        return ret;
    }
    VerifyCtx *verifyCtx = ctx->hsCtx->verifyCtx;

    ret = VERIFY_Append(verifyCtx, msgHash, msgHashLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16880, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "VERIFY_Append fail", 0, 0, 0, 0);
        return ret;
    }

    return VERIFY_Append(verifyCtx, hrr, hrrLen);
}

int32_t VERIFY_HelloRetryRequestVerifyProcess(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    uint32_t msgHashLen = MAX_MSG_HASH_SIZE;
    uint8_t msgHash[MAX_MSG_HASH_SIZE] = {0};
    VerifyCtx *verifyCtx = ctx->hsCtx->verifyCtx;
    HsMsgCache *dataBuf = verifyCtx->dataBuf;

    /** Set the verify information. */
    ret = VERIFY_SetHash(LIBCTX_FROM_CTX(ctx), ATTRIBUTE_FROM_CTX(ctx),
        ctx->hsCtx->verifyCtx, ctx->negotiatedInfo.cipherSuiteInfo.hashAlg);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15491, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "set verify info fail.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return ret;
    }

    ret = ConstructMsgHash(LIBCTX_FROM_CTX(ctx), ATTRIBUTE_FROM_CTX(ctx),
        verifyCtx->hashAlgo, dataBuf, msgHash, &msgHashLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15493, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "construct msg hash fail.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return ret;
    }

    dataBuf = dataBuf->next;
    uint32_t helloRetryRequestLen = dataBuf->dataSize;
    uint8_t *helloRetryRequest = BSL_SAL_Dump(dataBuf->data, dataBuf->dataSize);
    if (helloRetryRequest == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15494, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "malloc helloRetryRequest fail when process hrr verify.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    ret = ReinitVerify(ctx, msgHash, msgHashLen, helloRetryRequest, helloRetryRequestLen);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(helloRetryRequest);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return ret;
    }
    BSL_SAL_FREE(helloRetryRequest);

    return HITLS_SUCCESS;
}

/*
    Transcript-Hash(Truncate(ClientHello1))
    Where Truncate() removes the binders list from the ClientHello
    If the server responds with a HelloRetryRequest and the client then sends ClientHello2,
    its binder will be computed over:
    Transcript-Hash(ClientHello1, HelloRetryRequest, Truncate(ClientHello2))
*/
int32_t VERIFY_CalcPskBinder(const TLS_Ctx *ctx, HITLS_HashAlgo hashAlgo, bool isExternalPsk, uint8_t *psk,
    uint32_t pskLen, const uint8_t *msg, uint32_t msgLen, uint8_t *binder, uint32_t binderLen)
{
    int32_t ret = HITLS_SUCCESS;
    HITLS_HASH_Ctx *hashCtx = NULL;
    uint8_t *hsData = NULL;
    uint8_t earlySecret[MAX_DIGEST_SIZE] = {0};
    uint8_t binderKey[MAX_DIGEST_SIZE] = {0};
    uint8_t finishedKey[MAX_DIGEST_SIZE] = {0};
    uint8_t transcriptHash[MAX_DIGEST_SIZE] = {0};
    uint32_t hashLen = SAL_CRYPT_DigestSize(hashAlgo);
    uint32_t hsDataLen = 0u;
    uint32_t calcBinderLen = binderLen;
    if (hashLen == 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16881, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "DigestSize err", 0, 0, 0, 0);
        return HITLS_CRYPT_ERR_DIGEST;
    }
    // HKDF.Extract PSK to compute EarlySecret
    ret = HS_TLS13DeriveEarlySecret(LIBCTX_FROM_CTX(ctx), ATTRIBUTE_FROM_CTX(ctx),
        hashAlgo, psk, pskLen, earlySecret, &hashLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16882, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "DeriveEarlySecret fail", 0, 0, 0, 0);
        goto EXIT;
    }
    // HKDF.Expand EarlySecret to compute BinderKey
    ret = HS_TLS13DeriveBinderKey(LIBCTX_FROM_CTX(ctx), ATTRIBUTE_FROM_CTX(ctx),
        hashAlgo, isExternalPsk, earlySecret, hashLen, binderKey, hashLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16883, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "DeriveBinderKey fail", 0, 0, 0, 0);
        goto EXIT;
    }
    // HKDF.Expand BinderKey to compute Binder Finished Key
    ret = HS_TLS13DeriveFinishedKey(LIBCTX_FROM_CTX(ctx), ATTRIBUTE_FROM_CTX(ctx),
        hashAlgo, binderKey, hashLen, finishedKey, hashLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16884, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "DeriveFinishedKey fail", 0, 0, 0, 0);
        goto EXIT;
    }

    hashCtx = SAL_CRYPT_DigestInit(LIBCTX_FROM_CTX(ctx), ATTRIBUTE_FROM_CTX(ctx), hashAlgo);
    if (hashCtx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16885, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "DigestInit fail", 0, 0, 0, 0);
        ret = HITLS_CRYPT_ERR_DIGEST;
        goto EXIT;
    }

    ret = GetHsDataForBinder(ctx->hsCtx->verifyCtx, &hsDataLen, ctx->isClient, &hsData);
    if (ret != HITLS_SUCCESS) {
        goto EXIT;
    }
    if (hsData != NULL) {
        ret = SAL_CRYPT_DigestUpdate(hashCtx, hsData, hsDataLen);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16886, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "DigestUpdate fail", 0, 0, 0, 0);
            goto EXIT;
        }
    }

    if (SAL_CRYPT_DigestUpdate(hashCtx, msg, msgLen) != HITLS_SUCCESS ||
        SAL_CRYPT_DigestFinal(hashCtx, transcriptHash, &hashLen) != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16887, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "DigestUpdate or DigestFinal fail", 0, 0, 0, 0);
        ret = HITLS_CRYPT_ERR_DIGEST;
        goto EXIT;
    }

    ret = SAL_CRYPT_Hmac(LIBCTX_FROM_CTX(ctx), ATTRIBUTE_FROM_CTX(ctx),
        hashAlgo, finishedKey, hashLen, transcriptHash, hashLen, binder, &calcBinderLen);

EXIT:
    BSL_SAL_CleanseData(earlySecret, MAX_DIGEST_SIZE);
    BSL_SAL_CleanseData(binderKey, MAX_DIGEST_SIZE);
    BSL_SAL_CleanseData(finishedKey, MAX_DIGEST_SIZE);
    BSL_SAL_FREE(hsData);
    SAL_CRYPT_DigestFree(hashCtx);
    return ret;
}

#endif /* HITLS_TLS_PROTO_TLS13 */