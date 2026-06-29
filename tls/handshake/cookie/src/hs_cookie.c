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
#if (defined(HITLS_TLS_PROTO_DTLS12) || defined(HITLS_TLS_PROTO_DTLS13)) && defined(HITLS_BSL_UIO_UDP)
#include <string.h>
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "bsl_bytes.h"
#include "bsl_errno.h"
#include "sal_net.h"
#include "hitls.h"
#include "hitls_error.h"
#include "hitls_cookie.h"
#include "hitls_crypt_type.h"
#include "tls.h"
#include "tls_config.h"
#include "cipher_suite.h"
#include "hs_ctx.h"
#include "hs.h"
#include "hs_common.h"
#include "hs_cookie.h"
#include "hs_verify.h"
#include "transcript_hash.h"
#include "pack.h"

#ifdef HITLS_TLS_FEATURE_DEFAULT_COOKIE
#define MAX_IP_ADDR_SIZE 256u

static int32_t UpdateMacKey(TLS_Ctx *ctx, CookieInfo *cookieInfo)
{
    memcpy(cookieInfo->preMacKey, cookieInfo->macKey, MAC_KEY_LEN); /* Save the old key */
    int32_t ret = SAL_CRYPT_Rand(LIBCTX_FROM_CTX(ctx), cookieInfo->macKey, MAC_KEY_LEN); /* Create a new key */
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15691, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "generate macKey fail when calc cookie.", 0, 0, 0, 0);
        return ret;
    }
    cookieInfo->algRemainTime = COOKIE_SECRET_LIFETIME; /* Updated the current HMAC algorithm usage times */
    return HITLS_SUCCESS;
}

static void FillCipherSuite(const ClientHelloMsg *clientHello, uint8_t *material,
    uint32_t *offset)
{
    for (uint32_t i = 0; i < clientHello->cipherSuitesSize; i++) {
        BSL_Uint16ToByte(clientHello->cipherSuites[i], &material[*offset]);
        *offset += sizeof(uint16_t);
    }
}

static int32_t GenerateCookiePeerAddrMaterial(const TLS_Ctx *ctx, uint8_t *material, uint32_t materialSize,
    uint32_t *usedLen)
{
    *usedLen = 0;
    BSL_SAL_SockAddr peerAddr = NULL;
    int32_t ret = SAL_SockAddrNew(&peerAddr);
    if (ret != BSL_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16916, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "addr New fail", 0, 0, 0, 0);
        return HITLS_MEMCPY_FAIL;
    }

    int32_t peerAddrLen = (int32_t)SAL_SockAddrSize(peerAddr);
    ret = BSL_UIO_Ctrl(ctx->uio, BSL_UIO_GET_PEER_IP_ADDR, peerAddrLen, peerAddr);
    if (ret == BSL_SUCCESS) {
        if ((size_t)peerAddrLen > MAX_IP_ADDR_SIZE || (uint32_t)peerAddrLen > materialSize) {
            BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15692, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "copy ipAddr fail when calc cookie.", 0, 0, 0, 0);
            SAL_SockAddrFree(peerAddr);
            return HITLS_MEMCPY_FAIL;
        }
        memcpy(material, peerAddr, (size_t)peerAddrLen);
        *usedLen = (uint32_t)peerAddrLen;
    }

    SAL_SockAddrFree(peerAddr);
    return HITLS_SUCCESS;
}

/**
 * @brief   Generate cookie calculation materials
 * @attention The maximum memory required is already applied, so the function does not
 * need to check whether the memory is out of bounds
 *
 * @param ctx [IN] Hitls context
 * @param clientHello [IN] ClientHello message
 * @param material [OUT] Returned material
 * @param materialSize [IN] Maximum length of the material
 * @param usedLen [OUT] Returned actual material length
 *
 * @retval HITLS_SUCCESS
 * @retval HITLS_MEMCPY_FAIL
 */
static int32_t GenerateCookieCalcMaterial(const TLS_Ctx *ctx, const ClientHelloMsg *clientHello,
    uint8_t *material, uint32_t materialSize, uint32_t *usedLen)
{
    uint32_t offset = 0;
    /* Add the peer IP address */
    int32_t ret = GenerateCookiePeerAddrMaterial(ctx, material, materialSize, &offset);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    /* fill the version */
    BSL_Uint16ToByte(clientHello->version, &material[offset]);
    offset += sizeof(uint16_t);

    /* fill client's random value */
    if (HS_RANDOM_SIZE > materialSize - offset) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15693, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "copy random fail when calc cookie.", 0, 0, 0, 0);
        return HITLS_MEMCPY_FAIL;
    }
    memcpy(&material[offset], clientHello->randomValue, HS_RANDOM_SIZE);
    offset += HS_RANDOM_SIZE;

    /* fill session_id */
    if (clientHello->sessionIdSize != 0 && clientHello->sessionId != NULL) {
        if (clientHello->sessionIdSize > materialSize - offset) {
            BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15694, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "copy sessionId fail when calc cookie.", 0, 0, 0, 0);
            return HITLS_MEMCPY_FAIL;
        }
        memcpy(&material[offset], clientHello->sessionId, clientHello->sessionIdSize);
        offset += clientHello->sessionIdSize;
    }

    /* fill the cipher suite */
    FillCipherSuite(clientHello, material, &offset);

    *usedLen = offset;
    return HITLS_SUCCESS;
}

/**
 * @brief Add cookie calculation materials to the HMAC.
 *
 * @param ctx [IN] Hitls context
 * @param clientHello [IN] ClientHello message
 * @param cookieInfo [IN] cookie info
 * @param cookie [IN] cookie
 * @param cookieLen [IN] cookie len
 *
 * @retval HITLS_SUCCESS
 * @retval For other error codes, see hitls_error.h.
 */
static int32_t AddCookieCalcMaterial(
    const TLS_Ctx *ctx, const ClientHelloMsg *clientHello, CookieInfo *cookieInfo, uint8_t *cookie, uint32_t *cookieLen)
{
    /* Add the cookie calculation material, that is, the peer IP address + version + random + sessionID + cipherSuites
     */
    uint32_t materialSize = MAX_IP_ADDR_SIZE + sizeof(uint16_t) + HS_RANDOM_SIZE + clientHello->sessionIdSize +
                            clientHello->cipherSuitesSize * sizeof(uint16_t);
    uint8_t *material = BSL_SAL_Calloc(1u, materialSize);
    if (material == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15695, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "material malloc fail when calc cookie.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }

    int32_t ret;
    uint32_t usedLen = 0;
    ret = GenerateCookieCalcMaterial(ctx, clientHello, material, materialSize, &usedLen);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_ClearFree(material, materialSize);
        return ret;
    }

    ret = SAL_CRYPT_Hmac(LIBCTX_FROM_CTX(ctx), ATTRIBUTE_FROM_CTX(ctx),
        HITLS_HASH_SHA_256, cookieInfo->macKey, MAC_KEY_LEN, material, usedLen, cookie, cookieLen);
    BSL_SAL_ClearFree(material, materialSize);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15696, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "SAL_CRYPT_Hmac fail when calc cookie.", 0, 0, 0, 0);
    }
    return ret;
}
#endif /* HITLS_TLS_FEATURE_DEFAULT_COOKIE */

#if defined(HITLS_TLS_PROTO_DTLS13) && defined(HITLS_TLS_FEATURE_DEFAULT_COOKIE)
#define DTLS13_COOKIE_VERSION 1u
#define DTLS13_COOKIE_FLAG_KEY_SHARE_HRR 0x01u
#define DTLS13_COOKIE_HEADER_LEN 11u
#define DTLS13_COOKIE_MAC_LEN MAC_KEY_LEN
#define DTLS13_COOKIE_MAX_LEN (DTLS13_COOKIE_HEADER_LEN + MAX_DIGEST_SIZE + DTLS13_COOKIE_MAC_LEN)

typedef struct {
    uint8_t flags;
    uint16_t cipherSuite;
    uint16_t selectedGroup;
    uint8_t hashLen;
    uint8_t clientHelloHash[MAX_DIGEST_SIZE];
} Dtls13CookiePayload;

static const uint8_t g_dtls13CookieMagic[] = {'D', '1', '3', 'C'};

static int32_t CalcDtls13CookieMac(const TLS_Ctx *ctx, const uint8_t *macKey, const uint8_t *payload,
    uint32_t payloadLen, uint8_t *mac, uint32_t *macLen)
{
    uint32_t materialSize = MAX_IP_ADDR_SIZE + payloadLen;
    uint8_t *material = BSL_SAL_Calloc(1u, materialSize);
    if (material == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    uint32_t usedLen = 0;
    int32_t ret = GenerateCookiePeerAddrMaterial(ctx, material, materialSize, &usedLen);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_ClearFree(material, materialSize);
        return ret;
    }
    if (payloadLen > materialSize - usedLen) {
        BSL_SAL_ClearFree(material, materialSize);
        return HITLS_MEMCPY_FAIL;
    }
    memcpy(&material[usedLen], payload, payloadLen);
    usedLen += payloadLen;

    ret = SAL_CRYPT_Hmac(LIBCTX_FROM_CTX(ctx), ATTRIBUTE_FROM_CTX(ctx), HITLS_HASH_SHA_256,
        macKey, MAC_KEY_LEN, material, usedLen, mac, macLen);
    BSL_SAL_ClearFree(material, materialSize);
    return ret;
}

static int32_t BuildDtls13CookiePayload(TLS_Ctx *ctx, uint8_t *payload, uint32_t *payloadLen)
{
    bool isKeyShareHrr = ctx->hsCtx->isHrrKeyShare;
    int32_t ret = VERIFY_SetHash(LIBCTX_FROM_CTX(ctx), ATTRIBUTE_FROM_CTX(ctx),
        ctx->hsCtx->verifyCtx, ctx->negotiatedInfo.cipherSuiteInfo.hashAlg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint8_t digest[MAX_DIGEST_SIZE] = {0};
    uint32_t digestLen = sizeof(digest);
    ret = VERIFY_CalcSessionHash(ctx->hsCtx->verifyCtx, digest, &digestLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    if (digestLen > MAX_DIGEST_SIZE) {
        return HITLS_MSG_HANDLE_INCORRECT_DIGEST_LEN;
    }

    uint32_t offset = 0;
    memcpy(&payload[offset], g_dtls13CookieMagic, sizeof(g_dtls13CookieMagic));
    offset += sizeof(g_dtls13CookieMagic);
    payload[offset++] = DTLS13_COOKIE_VERSION;
    payload[offset++] = isKeyShareHrr ? DTLS13_COOKIE_FLAG_KEY_SHARE_HRR : 0u;
    BSL_Uint16ToByte(ctx->negotiatedInfo.cipherSuiteInfo.cipherSuite, &payload[offset]);
    offset += sizeof(uint16_t);
    BSL_Uint16ToByte(isKeyShareHrr ? ctx->negotiatedInfo.negotiatedGroup : 0u, &payload[offset]);
    offset += sizeof(uint16_t);
    payload[offset++] = (uint8_t)digestLen;
    memcpy(&payload[offset], digest, digestLen);
    offset += digestLen;

    *payloadLen = offset;
    return HITLS_SUCCESS;
}

static int32_t GenerateDtls13AppCookie(TLS_Ctx *ctx)
{
    uint8_t cookie[TLS_HS_MAX_COOKIE_SIZE] = {0};
    uint32_t cookieLen = sizeof(cookie);
    int32_t returnVal = ctx->globalConfig->appGenCookieCb(ctx, cookie, &cookieLen);
    if (returnVal == HITLS_COOKIE_GENERATE_ERROR) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_COOKIE_ERR);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15697, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "appGenCookieCb return error 0x%x.", returnVal, 0, 0, 0);
        return HITLS_MSG_HANDLE_COOKIE_ERR;
    }
    if (cookieLen > TLS_HS_MAX_COOKIE_SIZE) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_COOKIE_ERR);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17353, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "cookie len is too long.", 0, 0, 0, 0);
        return HITLS_MSG_HANDLE_COOKIE_ERR;
    }

    BSL_SAL_FREE(ctx->negotiatedInfo.cookie);
    ctx->negotiatedInfo.cookie = BSL_SAL_Dump(cookie, cookieLen);
    if (ctx->negotiatedInfo.cookie == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }
    ctx->negotiatedInfo.cookieSize = cookieLen;
    return HITLS_SUCCESS;
}

int32_t HS_Dtls13GenerateCookie(TLS_Ctx *ctx)
{
    if (ctx == NULL || ctx->hsCtx == NULL) {
        return HITLS_NULL_INPUT;
    }
    if (ctx->globalConfig != NULL && ctx->globalConfig->appGenCookieCb != NULL) {
        return GenerateDtls13AppCookie(ctx);
    }

    CookieInfo *cookieInfo = &ctx->negotiatedInfo.cookieInfo;
    if (cookieInfo->algRemainTime == 0) {
        int32_t ret = UpdateMacKey(ctx, cookieInfo);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

    uint8_t payload[DTLS13_COOKIE_HEADER_LEN + MAX_DIGEST_SIZE] = {0};
    uint32_t payloadLen = 0;
    int32_t ret = BuildDtls13CookiePayload(ctx, payload, &payloadLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint8_t cookie[DTLS13_COOKIE_MAX_LEN] = {0};
    if (payloadLen > sizeof(cookie) - DTLS13_COOKIE_MAC_LEN) {
        return HITLS_MSG_HANDLE_COOKIE_ERR;
    }
    memcpy(cookie, payload, payloadLen);
    uint32_t macLen = DTLS13_COOKIE_MAC_LEN;
    ret = CalcDtls13CookieMac(ctx, cookieInfo->macKey, payload, payloadLen, &cookie[payloadLen], &macLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    if (macLen != DTLS13_COOKIE_MAC_LEN) {
        return HITLS_MSG_HANDLE_COOKIE_ERR;
    }

    BSL_SAL_FREE(ctx->negotiatedInfo.cookie);
    ctx->negotiatedInfo.cookie = BSL_SAL_Dump(cookie, payloadLen + macLen);
    if (ctx->negotiatedInfo.cookie == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }
    ctx->negotiatedInfo.cookieSize = payloadLen + macLen;
    cookieInfo->algRemainTime--;
    return HITLS_SUCCESS;
}

static bool ParseDtls13CookiePayload(const uint8_t *cookie, uint32_t cookieLen, Dtls13CookiePayload *payload)
{
    if (cookieLen < DTLS13_COOKIE_HEADER_LEN + DTLS13_COOKIE_MAC_LEN ||
        memcmp(cookie, g_dtls13CookieMagic, sizeof(g_dtls13CookieMagic)) != 0) {
        return false;
    }

    uint32_t payloadLen = cookieLen - DTLS13_COOKIE_MAC_LEN;
    uint32_t offset = sizeof(g_dtls13CookieMagic);
    if (cookie[offset++] != DTLS13_COOKIE_VERSION) {
        return false;
    }
    payload->flags = cookie[offset++];
    payload->cipherSuite = BSL_ByteToUint16(&cookie[offset]);
    offset += sizeof(uint16_t);
    payload->selectedGroup = BSL_ByteToUint16(&cookie[offset]);
    offset += sizeof(uint16_t);
    payload->hashLen = cookie[offset++];
    if (payload->hashLen == 0 || payload->hashLen > MAX_DIGEST_SIZE || payload->hashLen != payloadLen - offset) {
        return false;
    }
    memcpy(payload->clientHelloHash, &cookie[offset], payload->hashLen);
    return true;
}

static int32_t CheckDtls13CookieMacWithKey(TLS_Ctx *ctx, const uint8_t *macKey, const uint8_t *cookie,
    uint32_t cookieLen, bool *isCookieValid)
{
    uint32_t payloadLen = cookieLen - DTLS13_COOKIE_MAC_LEN;
    uint8_t mac[DTLS13_COOKIE_MAC_LEN] = {0};
    uint32_t macLen = sizeof(mac);
    int32_t ret = CalcDtls13CookieMac(ctx, macKey, cookie, payloadLen, mac, &macLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    if (macLen == DTLS13_COOKIE_MAC_LEN &&
        ConstTimeMemcmp(mac, &cookie[payloadLen], DTLS13_COOKIE_MAC_LEN) != 0) {
        *isCookieValid = true;
    }
    BSL_SAL_CleanseData(mac, sizeof(mac));
    return HITLS_SUCCESS;
}

static int32_t CheckDtls13CookieMac(TLS_Ctx *ctx, const uint8_t *cookie, uint32_t cookieLen, bool *isCookieValid)
{
    CookieInfo *cookieInfo = &ctx->negotiatedInfo.cookieInfo;
    *isCookieValid = false;

    int32_t ret = CheckDtls13CookieMacWithKey(ctx, cookieInfo->macKey, cookie, cookieLen, isCookieValid);
    if (ret != HITLS_SUCCESS || *isCookieValid) {
        return ret;
    }

    uint8_t emptyKey[MAC_KEY_LEN] = {0};
    if (ConstTimeMemcmp(cookieInfo->preMacKey, emptyKey, sizeof(emptyKey)) == 0) {
        return HITLS_SUCCESS;
    }
    return CheckDtls13CookieMacWithKey(ctx, cookieInfo->preMacKey, cookie, cookieLen, isCookieValid);
}

static int32_t PackDtls13HrrTranscript(TLS_Ctx *ctx, const Dtls13CookiePayload *payload,
    const uint8_t *cookie, uint32_t cookieLen, uint8_t **hrrTranscript, uint32_t *hrrTranscriptLen)
{
    ExtensionFlag oldExtFlag = ctx->hsCtx->extFlag;

    BSL_SAL_FREE(ctx->negotiatedInfo.cookie);
    ctx->negotiatedInfo.cookie = BSL_SAL_Dump(cookie, cookieLen);
    if (ctx->negotiatedInfo.cookie == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
    ctx->negotiatedInfo.cookieSize = cookieLen;
    ctx->negotiatedInfo.version = HITLS_VERSION_DTLS13;
    ctx->negotiatedInfo.negotiatedGroup = payload->selectedGroup;
    ctx->hsCtx->isHrrKeyShare = (payload->flags & DTLS13_COOKIE_FLAG_KEY_SHARE_HRR) != 0;
    ctx->hsCtx->haveHrr = true;
    ctx->hsCtx->kxCtx->keyExchParam.share.count = 0;
    if (ctx->hsCtx->isHrrKeyShare) {
        ctx->hsCtx->kxCtx->keyExchParam.share.groups[0] = payload->selectedGroup;
        ctx->hsCtx->kxCtx->keyExchParam.share.count = 1;
    }

    uint8_t *hrrMsg = NULL;
    uint32_t hrrMsgLen = 0;
    uint32_t hrrMsgBufLen = 0;
    PackPacket pkt = {.buf = &hrrMsg, .bufLen = &hrrMsgBufLen, .bufOffset = &hrrMsgLen};
    uint32_t headerPosition = 0;
    int32_t ret = PackStartLengthField(&pkt, DTLS_HS_MSG_HEADER_SIZE, &headerPosition);
    if (ret != HITLS_SUCCESS) {
        goto EXIT;
    }

    memset(&ctx->hsCtx->extFlag, 0, sizeof(ctx->hsCtx->extFlag));
    ret = PackTls13HelloRetryRequest(ctx, &pkt);
    if (ret != HITLS_SUCCESS) {
        goto EXIT;
    }

    uint8_t *dtlsHeaderBuf = NULL;
    uint32_t totalLen = 0;
    ret = PackGetSubBuffer(&pkt, headerPosition, &totalLen, &dtlsHeaderBuf);
    if (ret != HITLS_SUCCESS) {
        goto EXIT;
    }
    PackDtlsMsgHeader(SERVER_HELLO, ctx->hsCtx->nextSendSeq, totalLen - DTLS_HS_MSG_HEADER_SIZE, dtlsHeaderBuf);

    ret = VERIFY_Dtls13BuildTranscriptMsg(hrrMsg, hrrMsgLen, hrrTranscript, hrrTranscriptLen);

EXIT:
    ctx->hsCtx->extFlag = oldExtFlag;
    BSL_SAL_FREE(hrrMsg);
    return ret;
}

static int32_t ProcessDtls13AppCookie(TLS_Ctx *ctx, const uint8_t *cookie, uint32_t cookieLen, bool *isCookieValid)
{
    int32_t isValid = ctx->globalConfig->appVerifyCookieCb(ctx, cookie, cookieLen);
    if (isValid == HITLS_COOKIE_VERIFY_ERROR) {
        return HITLS_SUCCESS;
    }

    *isCookieValid = true;
    return HITLS_SUCCESS;
}

static int32_t Dtls13CookieVerifyFail(TLS_Ctx *ctx)
{
    BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_COOKIE_ERR);
    ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
    return HITLS_MSG_HANDLE_COOKIE_ERR;
}

int32_t HS_Dtls13ProcessCookie(TLS_Ctx *ctx, const ClientHelloMsg *clientHello, bool *isCookieValid)
{
    if (ctx == NULL || ctx->hsCtx == NULL || clientHello == NULL || isCookieValid == NULL) {
        return HITLS_NULL_INPUT;
    }
    *isCookieValid = false;
    if (!clientHello->extension.flag.haveCookie || clientHello->extension.content.cookie == NULL) {
        return HITLS_SUCCESS;
    }

    const uint8_t *cookie = clientHello->extension.content.cookie;
    uint32_t cookieLen = clientHello->extension.content.cookieLen;
    if (ctx->globalConfig != NULL && ctx->globalConfig->appVerifyCookieCb != NULL) {
        int32_t ret = ProcessDtls13AppCookie(ctx, cookie, cookieLen, isCookieValid);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        return *isCookieValid ? HITLS_SUCCESS : Dtls13CookieVerifyFail(ctx);
    }

    Dtls13CookiePayload payload = {0};
    if (!ParseDtls13CookiePayload(cookie, cookieLen, &payload)) {
        return Dtls13CookieVerifyFail(ctx);
    }

    int32_t ret = CheckDtls13CookieMac(ctx, cookie, cookieLen, isCookieValid);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    if (!*isCookieValid) {
        return Dtls13CookieVerifyFail(ctx);
    }

    ret = CFG_GetCipherSuiteInfo(payload.cipherSuite, &ctx->negotiatedInfo.cipherSuiteInfo);
    if (ret != HITLS_SUCCESS) {
        *isCookieValid = false;
        return Dtls13CookieVerifyFail(ctx);
    }

    uint8_t *hrrTranscript = NULL;
    uint32_t hrrTranscriptLen = 0;
    ret = PackDtls13HrrTranscript(ctx, &payload, cookie, cookieLen, &hrrTranscript, &hrrTranscriptLen);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(hrrTranscript);
        return ret;
    }
    ret = VERIFY_RestoreHelloRetryRequestTranscript(ctx, payload.clientHelloHash, payload.hashLen,
        hrrTranscript, hrrTranscriptLen);
    BSL_SAL_FREE(hrrTranscript);
    return ret;
}
#endif /* HITLS_TLS_PROTO_DTLS13 && HITLS_TLS_FEATURE_DEFAULT_COOKIE */

int32_t HS_CalcCookie(TLS_Ctx *ctx, const ClientHelloMsg *clientHello, uint8_t *cookie, uint32_t *cookieLen,
    bool isCheck)
{
    (void)clientHello;
    /* If the user's cookie calculation callback is registered, use the user's callback interface */
    if (ctx->globalConfig != NULL && ctx->globalConfig->appGenCookieCb != NULL) {
        int32_t returnVal = ctx->globalConfig->appGenCookieCb(ctx, cookie, cookieLen);
        /* A return value of zero indicates that the cookie generation failed, and a return value of other values is a
         * success, so the judgment here is a failure rather than a non-success */
        if (returnVal == HITLS_COOKIE_GENERATE_ERROR) {
            BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_COOKIE_ERR);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15697, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "appGenCookieCb return error 0x%x.", returnVal, 0, 0, 0);
            return HITLS_MSG_HANDLE_COOKIE_ERR;
        }
        if (*cookieLen > TLS_HS_MAX_COOKIE_SIZE) {
            BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_COOKIE_ERR);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17353, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "cookie len is too long.", 0, 0, 0, 0);
            return HITLS_MSG_HANDLE_COOKIE_ERR;
        }
        return HITLS_SUCCESS;
    }
#ifdef HITLS_TLS_FEATURE_DEFAULT_COOKIE
    /* If the cookie calculation callback is not registered, the default calculation is used */
    int32_t ret = HITLS_SUCCESS;
    CookieInfo *cookieInfo = &ctx->negotiatedInfo.cookieInfo;

    /* If the number of remaining usage times of the current algorithm is 0, update the algorithm */
    if (cookieInfo->algRemainTime == 0) {
        ret = UpdateMacKey(ctx, cookieInfo);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

    /* Add cookie calculation materials */
    ret = AddCookieCalcMaterial(ctx, clientHello, cookieInfo, cookie, cookieLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Updated the current HMAC algorithm usage times */
    if (!isCheck) {
        cookieInfo->algRemainTime--;
    }

    return HITLS_SUCCESS;
#else
    return HITLS_MSG_HANDLE_COOKIE_ERR;
#endif /* HITLS_TLS_FEATURE_DEFAULT_COOKIE */
}

#ifdef HITLS_TLS_FEATURE_DEFAULT_COOKIE
static int32_t CheckCookie(TLS_Ctx *ctx, const ClientHelloMsg *clientHello, bool *isCookieValid)
{
    uint8_t cookie[TLS_HS_MAX_COOKIE_SIZE] = {0};
    uint32_t cookieLen = sizeof(cookie);

    *isCookieValid = false;

    int32_t ret = HS_CalcCookie(ctx, clientHello, cookie, &cookieLen, true);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16917, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "CalcCookie fail", 0, 0, 0, 0);
        return ret;
    }

    if ((cookieLen == clientHello->cookieLen) &&
        (ConstTimeMemcmp(cookie, clientHello->cookie, cookieLen) != 0)) {
        *isCookieValid = true;
    }
    BSL_SAL_CleanseData(cookie, TLS_HS_MAX_COOKIE_SIZE);
    return HITLS_SUCCESS;
}

static int32_t CheckCookieWithPreMacKey(TLS_Ctx *ctx, const ClientHelloMsg *clientHello, bool *isCookieValid)
{
    uint8_t macKeyStore[MAC_KEY_LEN] = {0};
    CookieInfo *cookieInfo = &ctx->negotiatedInfo.cookieInfo;

    /* If the previous key does not exist, the system will not verify */
    if (memcmp(cookieInfo->preMacKey, macKeyStore, MAC_KEY_LEN) == 0) {
        return HITLS_SUCCESS;
    }

    /* Save the current mackey */
    memcpy(macKeyStore, cookieInfo->macKey, MAC_KEY_LEN);
    /* Use the previous mackey */
    memcpy(cookieInfo->macKey, cookieInfo->preMacKey, MAC_KEY_LEN);

    int32_t ret = CheckCookie(ctx, clientHello, isCookieValid);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16918, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "CheckCookie fail", 0, 0, 0, 0);
        BSL_SAL_CleanseData(macKeyStore, MAC_KEY_LEN);
        return ret;
    }

    /* Restore the current mackey */
    memcpy(cookieInfo->macKey, macKeyStore, MAC_KEY_LEN);
    BSL_SAL_CleanseData(macKeyStore, MAC_KEY_LEN);
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_DEFAULT_COOKIE */

#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
static int32_t CheckCookieDuringRenegotiation(TLS_Ctx *ctx, const ClientHelloMsg *clientHello, bool *isCookieValid)
{
    uint8_t *cookie = ctx->negotiatedInfo.cookie;
    uint16_t cookieLen = (uint16_t)ctx->negotiatedInfo.cookieSize;

    if ((cookieLen == clientHello->cookieLen) &&
        (ConstTimeMemcmp(cookie, clientHello->cookie, cookieLen) != 0)) {
        *isCookieValid = true;
    }
    return HITLS_SUCCESS;
}
#endif

int32_t HS_CheckCookie(TLS_Ctx *ctx, const ClientHelloMsg *clientHello, bool *isCookieValid)
{
    /* The DTLS protocol determines whether cookie verification is required based on user setting */
    if (IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask) &&
        !ctx->config.tlsConfig.isSupportDtlsCookieExchange && !ctx->isDtlsListen) {
        *isCookieValid = true;
        return HITLS_SUCCESS;
    }

    *isCookieValid = false;

    /* If the client does not send the cookie, the verification is not required */
    if (clientHello->cookie == NULL) {
        return HITLS_SUCCESS;
    }

#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
    /* In the renegotiation scenario, the cookie stored in the negotiatedInfo is used for verification */
    if (ctx->negotiatedInfo.isRenegotiation) {
        return CheckCookieDuringRenegotiation(ctx, clientHello, isCookieValid);
    }
#endif

    /* If the user's cookie validation callback is registered, use the user's callback interface */
    HITLS_AppVerifyCookieCb cookieCb = ctx->globalConfig->appVerifyCookieCb;
    if (cookieCb != NULL) {
        int32_t isValid = cookieCb(ctx, clientHello->cookie, clientHello->cookieLen);
        /* If the return value is not zero, the cookie is valid, so the judgment here does not equal failure rather than
         * success */
        if (isValid != HITLS_COOKIE_VERIFY_ERROR) {
            *isCookieValid = true;
        }
        return HITLS_SUCCESS;
    }
#ifdef HITLS_TLS_FEATURE_DEFAULT_COOKIE
    /* If the cookie validation callback function of the user is not registered, use the default validation function */
    int32_t ret = CheckCookie(ctx, clientHello, isCookieValid);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16919, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "CheckCookie fail", 0, 0, 0, 0);
        return ret;
    }

    /* If the cookie is successfully verified for the first time, it is returned. Otherwise, the previous MacKey is used
     * to verify the cookie again */
    if (*isCookieValid) {
        return HITLS_SUCCESS;
    }

    return CheckCookieWithPreMacKey(ctx, clientHello, isCookieValid);
#else
    return HITLS_MSG_HANDLE_COOKIE_ERR;
#endif /* HITLS_TLS_FEATURE_DEFAULT_COOKIE */
}
#endif /* (HITLS_TLS_PROTO_DTLS12 || HITLS_TLS_PROTO_DTLS13) && HITLS_BSL_UIO_UDP */
