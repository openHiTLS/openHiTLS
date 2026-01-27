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
#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
#include "securec.h"
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
#include "hs_ctx.h"
#include "hs.h"

#define MAX_IP_ADDR_SIZE 256u

static int32_t UpdateMacKey(TLS_Ctx *ctx, CookieInfo *cookieInfo)
{
    (void)memcpy_s(cookieInfo->preMacKey, MAC_KEY_LEN, cookieInfo->macKey, MAC_KEY_LEN); /* Save the old key */
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
    uint8_t ipAddr[MAX_IP_ADDR_SIZE] = {0};
    BSL_UIO_CtrlGetPeerIpAddrParam param = {ipAddr, sizeof(ipAddr)};
    uint32_t offset = 0;
    BSL_SAL_SockAddr peerAddr = NULL;
    int32_t ret = SAL_SockAddrNew(&peerAddr);
    if (ret != BSL_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16916, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "addr New fail", 0, 0, 0, 0);
        return HITLS_MEMCPY_FAIL;
    }
    int32_t peerAddrLen = (int32_t)SAL_SockAddrSize(peerAddr);
    /* Add the peer IP address */
    ret = BSL_UIO_Ctrl(ctx->uio, BSL_UIO_GET_PEER_IP_ADDR, peerAddrLen, peerAddr);
    if (ret == BSL_SUCCESS) {
        if (memcpy_s(ipAddr, MAX_IP_ADDR_SIZE, peerAddr, (size_t)peerAddrLen) != EOK) {
            SAL_SockAddrFree(peerAddr);
            return BSL_MEMCPY_FAIL;
        }
        param.size = (uint32_t)peerAddrLen;
        if (memcpy_s(material, materialSize, ipAddr, param.size) != EOK) {
            BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15692, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "copy ipAddr fail when calc cookie.", 0, 0, 0, 0);
            SAL_SockAddrFree(peerAddr);
            return HITLS_MEMCPY_FAIL;
        }
        offset += param.size;
    }
    SAL_SockAddrFree(peerAddr);
    /* fill the version */
    BSL_Uint16ToByte(clientHello->version, &material[offset]);
    offset += sizeof(uint16_t);

    /* fill client's random value */
    if (memcpy_s(&material[offset], materialSize - offset, clientHello->randomValue, HS_RANDOM_SIZE) != EOK) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15693, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "copy random fail when calc cookie.", 0, 0, 0, 0);
        return HITLS_MEMCPY_FAIL;
    }
    offset += HS_RANDOM_SIZE;

    /* fill session_id */
    if (clientHello->sessionIdSize != 0 && clientHello->sessionId != NULL) {
        if (memcpy_s(&material[offset], materialSize - offset,
            clientHello->sessionId, clientHello->sessionIdSize) != EOK) {
            BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15694, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "copy sessionId fail when calc cookie.", 0, 0, 0, 0);
            return HITLS_MEMCPY_FAIL;
        }
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
        (void)memset_s(material, materialSize, 0, materialSize);
        BSL_SAL_FREE(material);
        return ret;
    }

    ret = SAL_CRYPT_Hmac(LIBCTX_FROM_CTX(ctx), ATTRIBUTE_FROM_CTX(ctx),
        HITLS_HASH_SHA_256, cookieInfo->macKey, MAC_KEY_LEN, material, usedLen, cookie, cookieLen);
    (void)memset_s(material, materialSize, 0, materialSize);
    BSL_SAL_FREE(material);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15696, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "SAL_CRYPT_Hmac fail when calc cookie.", 0, 0, 0, 0);
    }
    return ret;
}

int32_t HS_CalcCookie(TLS_Ctx *ctx, const ClientHelloMsg *clientHello, uint8_t *cookie, uint32_t *cookieLen)
{
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
    cookieInfo->algRemainTime--;

    return HITLS_SUCCESS;
}

static int32_t CheckCookie(TLS_Ctx *ctx, const ClientHelloMsg *clientHello, bool *isCookieValid)
{
    uint8_t cookie[TLS_HS_MAX_COOKIE_SIZE] = {0};
    uint32_t cookieLen = sizeof(cookie);

    *isCookieValid = false;

    /* Calculating cookies will reduce the number of times the algorithm is used. In order to prevent algorithm
     * switching after calculation, it is increased by itself and then calculated */
    ctx->negotiatedInfo.cookieInfo.algRemainTime++;
    int32_t ret = HS_CalcCookie(ctx, clientHello, cookie, &cookieLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16917, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "CalcCookie fail", 0, 0, 0, 0);
        return ret;
    }

    if ((cookieLen == clientHello->cookieLen) &&
        (memcmp((char *)cookie, (char *)clientHello->cookie, cookieLen) == 0)) {
        *isCookieValid = true;
    }
    (void)memset_s(cookie, TLS_HS_MAX_COOKIE_SIZE, 0, TLS_HS_MAX_COOKIE_SIZE);
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
    (void)memcpy_s(macKeyStore, MAC_KEY_LEN, cookieInfo->macKey, MAC_KEY_LEN);
    /* Use the previous mackey */
    (void)memcpy_s(cookieInfo->macKey, MAC_KEY_LEN, cookieInfo->preMacKey, MAC_KEY_LEN);

    int32_t ret = CheckCookie(ctx, clientHello, isCookieValid);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16918, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "CheckCookie fail", 0, 0, 0, 0);
        (void)memset_s(macKeyStore, MAC_KEY_LEN, 0, MAC_KEY_LEN);
        return ret;
    }

    /* Restore the current mackey */
    (void)memcpy_s(cookieInfo->macKey, MAC_KEY_LEN, macKeyStore, MAC_KEY_LEN);
    (void)memset_s(macKeyStore, MAC_KEY_LEN, 0, MAC_KEY_LEN);
    return HITLS_SUCCESS;
}

#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
static int32_t CheckCookieDuringRenegotiation(TLS_Ctx *ctx, const ClientHelloMsg *clientHello, bool *isCookieValid)
{
    uint8_t *cookie = ctx->negotiatedInfo.cookie;
    uint16_t cookieLen = (uint16_t)ctx->negotiatedInfo.cookieSize;

    if ((cookieLen == clientHello->cookieLen) &&
        (memcmp((char *)cookie, (char *)clientHello->cookie, cookieLen) == 0)) {
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
}
#endif /* HITLS_TLS_PROTO_DTLS12 && HITLS_BSL_UIO_UDP */