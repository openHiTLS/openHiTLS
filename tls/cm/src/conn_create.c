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

#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "tls_binlog_id.h"
#include "bsl_sal.h"
#include "bsl_errno.h"
#include "bsl_list.h"
#include "hitls_error.h"
#include "hitls_type.h"
#include "hitls_config.h"
#include "hitls_cert_type.h"
#include "hitls.h"
#include "tls.h"
#include "tls_config.h"
#include "cert.h"
#include "session.h"
#include "session_mgr.h"
#include "bsl_uio.h"
#include "config.h"
#include "config_check.h"
#include "conn_common.h"
#include "conn_init.h"
#include "crypt.h"
#include "cipher_suite.h"

static int32_t PeerInfoInit(HITLS_Ctx *ctx)
{
    /* The peerInfo.caList is used to adapt to the OpenSSL behavior. When creating the SSL_CTX object, OpenSSL
     * initializes the member so that the member is not null */
    ctx->peerInfo.caList = BSL_LIST_New(sizeof(HITLS_TrustedCANode *));
    if (ctx->peerInfo.caList == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    return HITLS_SUCCESS;
}

/**
 * @ingroup    hitls
 * @brief      Create a TLS object and deep Copy the HITLS_Config to the HITLS_Ctx.
 * @attention  After the creation is successful, the HITLS_Config can be released.
 * @param      config [IN] config Context
 * @return     HITLS_Ctx Pointer. If the operation fails, null is returned.
 */
HITLS_Ctx *HITLS_New(HITLS_Config *config)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return NULL;
    }

    int32_t ret;

    HITLS_Ctx *newCtx = (HITLS_Ctx *)BSL_SAL_Calloc(1u, sizeof(HITLS_Ctx));
    if (newCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return NULL;
    }

    ret = CFG_CheckConfig(config);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(newCtx);
        return NULL;
    }

    ret = CFG_DumpConfig(newCtx, config);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(newCtx);
        return NULL;
    }
    HITLS_CFG_UpRef(config);
    newCtx->globalConfig = config;

    ret = PeerInfoInit(newCtx);
    if (ret != HITLS_SUCCESS) {
        HITLS_Free(newCtx);
        return NULL;
    }

    ChangeConnState(newCtx, CM_STATE_IDLE);
    return newCtx;
}

static void CaListNodeDestroy(void *data)
{
    HITLS_TrustedCANode *tmpData = (HITLS_TrustedCANode *)data;
    BSL_SAL_FREE(tmpData->data);
    BSL_SAL_FREE(tmpData);
    return;
}

static void CleanPeerInfo(PeerInfo *peerInfo)
{
    BSL_SAL_FREE(peerInfo->groups);
    BSL_LIST_FREE(peerInfo->caList, CaListNodeDestroy);
}

static void CleanNegotiatedInfo(TLS_NegotiatedInfo *negotiatedInfo)
{
    BSL_SAL_FREE(negotiatedInfo->cookie);
    BSL_SAL_FREE(negotiatedInfo->alpnSelected);
    return;
}

/**
 * @ingroup hitls
 * @brief   Release the TLS connection.
 * @param   ctx [IN] TLS connection handle.
 * @return  void
 */
void HITLS_Free(HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    ctx->rwstate = HITLS_NOTHING;
    CONN_Deinit(ctx);
    BSL_UIO_Free(ctx->uio);
    BSL_UIO_Free(ctx->rUio);
    ctx->rUio = NULL;
    ctx->uio = NULL;

    /* Release certificate resources before releasing the config file. Otherwise, memory leakage occurs */
    HITLS_SESS_Free(ctx->session);
    CFG_CleanConfig(&ctx->config.tlsConfig);
    HITLS_CFG_FreeConfig(ctx->globalConfig);
    CleanPeerInfo(&(ctx->peerInfo));
    CleanNegotiatedInfo(&ctx->negotiatedInfo);
    SAL_CRYPT_DigestFree(ctx->phaHash);
    ctx->phaHash = NULL;
    SAL_CRYPT_DigestFree(ctx->phaCurHash);
    ctx->phaCurHash = NULL;
    ctx->phaState = PHA_NONE;
    BSL_SAL_FREE(ctx->certificateReqCtx);
    ctx->certificateReqCtxSize = 0;
    BSL_SAL_FREE(ctx);
    return;
}

int32_t HITLS_SetReadUio(HITLS_Ctx *ctx, BSL_UIO *uio)
{
    if ((ctx == NULL) || (uio == NULL)) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    int32_t ret = BSL_UIO_UpRef(uio);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_UIO_FAIL);
        return HITLS_UIO_FAIL;
    }

    if (ctx->rUio != NULL) {
        /* A message is displayed, warning the user that the UIO is set repeatedly */
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15662, BSL_LOG_LEVEL_WARN, BSL_LOG_BINLOG_TYPE_RUN,
            "Warning: Repeated uio setting.", 0, 0, 0, 0);
        /* Release the original UIO */
        BSL_UIO_Free(ctx->rUio);
    }

    ctx->rUio = uio;

    return HITLS_SUCCESS;
}

/**
 * @ingroup hitls
 * @brief   Set the UIO for the HiTLS context.
 * @attention This function must be called before HITLS_Connect and HITLS_Accept and released after HITLS_Free. If this
 *          function has been called, you must call BSL_UIO_Free to release the UIO.
 * @param   ctx [OUT] TLS connection handle.
 * @param   uio [IN] UIO object
 * @return  HITLS_SUCCESS succeeded
 *          Other Error Codes, see hitls_error.h
 */
int32_t HITLS_SetUio(HITLS_Ctx *ctx, BSL_UIO *uio)
{
    int32_t ret;
    if ((ctx == NULL) || (uio == NULL)) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    /* The UIO count increases by 1, and the reference counting is performed for the write UIO */
    ret = BSL_UIO_UpRef(uio);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_UIO_FAIL);
        return HITLS_UIO_FAIL;
    }

    /* The UIO count increases by 1, and the reference counting is performed for reading the UIO */
    ret = BSL_UIO_UpRef(uio);
    if (ret != BSL_SUCCESS) {
        BSL_UIO_Free(uio); // free Drop the one on the top.
        BSL_ERR_PUSH_ERROR(HITLS_UIO_FAIL);
        return HITLS_UIO_FAIL;
    }

    /* The original write uio is not empty */
    if (ctx->uio != NULL) {
        /* A message is displayed, warning the user that the UIO is set repeatedly. */
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15960, BSL_LOG_LEVEL_WARN, BSL_LOG_BINLOG_TYPE_RUN,
            "Warning: Repeated uio setting.", 0, 0, 0, 0);
        /* Release the original write UIO */
        if (ctx->bUio != NULL) {
            ctx->uio = BSL_UIO_PopCurrent(ctx->uio);
        }
        BSL_UIO_FreeChain(ctx->uio);
    }
    ctx->uio = uio;
    if (ctx->bUio != NULL) {
        ret = BSL_UIO_Append(ctx->bUio, ctx->uio);
        if (ret != BSL_SUCCESS) {
            BSL_UIO_Free(uio); // free Drop the one on the top.
            BSL_ERR_PUSH_ERROR(HITLS_UIO_FAIL);
            return HITLS_UIO_FAIL;
        }
        ctx->uio = ctx->bUio;
    }
    /* The original read UIO is not empty */
    if (ctx->rUio != NULL) {
        /* A message is displayed, warning the user that the UIO is set repeatedly */
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15253, BSL_LOG_LEVEL_WARN, BSL_LOG_BINLOG_TYPE_RUN,
            "Warning: Repeated uio setting.", 0, 0, 0, 0);
        /* Release the original read UIO */
        BSL_UIO_Free(ctx->rUio);
    }
    ctx->rUio = uio;

    /* The PMTU needs to be set for DTLS. If the PMTU is not set, use the default value */
    if ((ctx->config.pmtu == 0) && IS_DTLS_VERSION(ctx->config.tlsConfig.maxVersion)) {
        ctx->config.pmtu = DTLS_SCTP_PMTU;
    }

    return HITLS_SUCCESS;
}

BSL_UIO *HITLS_GetUio(const HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }
    /* If |bUio| is active, the true caller-configured uio is its |next_uio|. */
    if (ctx->config.tlsConfig.isFlightTransmitEnable == true && ctx->bUio != NULL) {
        return BSL_UIO_Next(ctx->bUio);
    }
    return ctx->uio;
}

BSL_UIO *HITLS_GetReadUio(const HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }
    return ctx->rUio;
}

/**
 * @ingroup hitls
 * @brief   Obtain user data from the HiTLS context. Generally, this interface is invoked during the callback registered
 *          with the HiTLS.
 * @attention must be invoked before HITLS_Connect and HITLS_Accept. The life cycle of the user identifier must be
 *           longer than the life cycle of the TLS object.
 * @param  ctx [OUT] TLS connection handle.
 * @param  userData [IN] User identifier.
 * @retval HITLS_SUCCESS succeeded.
 * @retval HITLS_NULL_INPUT The input parameter TLS object is a null pointer.
 */
void *HITLS_GetUserData(const HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    return ctx->config.userData;
}

/**
 * @ingroup hitls
 * @brief User data is stored in the HiTLS context and can be obtained from the callback registered with the HiTLS.
 * @attention must be invoked before HITLS_Connect and HITLS_Accept. The life cycle of the user identifier must be
 *            longer than the life cycle of the TLS object. If the user data needs to be cleared, the
 * HITLS_SetUserData(ctx, NULL) interface can be invoked directly. The Clean interface is not provided separately.
 * @param  ctx [OUT] TLS connection handle.
 * @param  userData [IN] User identifier.
 * @retval HITLS_SUCCESS succeeded.
 * @retval HITLS_NULL_INPUT The input parameter TLS object is a null pointer.
 */
int32_t HITLS_SetUserData(HITLS_Ctx *ctx, void *userData)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    ctx->config.userData = userData;
    return HITLS_SUCCESS;
}

int32_t HITLS_SetErrorCode(HITLS_Ctx *ctx, int32_t errorCode)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    ctx->errorCode = errorCode;
    return HITLS_SUCCESS;
}

int32_t HITLS_GetErrorCode(const HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return ctx->errorCode;
}

int32_t HITLS_GetSelectedAlpnProto(HITLS_Ctx *ctx, uint8_t **proto, uint32_t *protoLen)
{
    if (ctx == NULL || proto == NULL || protoLen == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    if (ctx->negotiatedInfo.alpnSelected == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *proto = ctx->negotiatedInfo.alpnSelected;
    *protoLen = ctx->negotiatedInfo.alpnSelectedSize;

    return HITLS_SUCCESS;
}

int32_t HITLS_IsServer(const HITLS_Ctx *ctx, uint8_t *isServer)
{
    if (ctx == NULL || isServer == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *isServer = 0;
    if (ctx->isClient == false) {
        *isServer = 1;
    }

    return HITLS_SUCCESS;
}

/* Configure the handle for the session information about the HITLS link */
int32_t HITLS_SetSession(HITLS_Ctx *ctx, HITLS_Session *session)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    /* The client and server are specified only in hitls connect/accept. Therefore, the client cannot be specified here
     */
    HITLS_SESS_Free(ctx->session);

    /* Ignore whether the HITLS_SESS_Dup return is NULL or non-NULL */
    ctx->session = HITLS_SESS_Dup(session);
    return HITLS_SUCCESS;
}

/* Obtain the session information handle and directly obtain the pointer */
HITLS_Session *HITLS_GetSession(const HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }
    return ctx->session;
}

/* Obtain the handle of the copied session information */
HITLS_Session *HITLS_GetDupSession(HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }
    return HITLS_SESS_Dup(ctx->session);
}

int32_t HITLS_GetPeerSignatureType(const HITLS_Ctx *ctx, HITLS_SignAlgo *sigType)
{
    HITLS_SignAlgo signAlg = HITLS_SIGN_BUTT;
    HITLS_HashAlgo hashAlg = HITLS_HASH_BUTT;

    if (ctx == NULL || sigType == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    if (CFG_GetSignParamBySchemes(ctx->negotiatedInfo.version, ctx->peerInfo.peerSignHashAlg,
        &signAlg, &hashAlg) == false) {
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_NO_SUITABLE_CIPHER_SUITE);
        return HITLS_CONFIG_NO_SUITABLE_CIPHER_SUITE;
    }

    *sigType = signAlg;

    return HITLS_SUCCESS;
}

int32_t HITLS_GetLocalSignScheme(const HITLS_Ctx *ctx, HITLS_SignHashAlgo *localSignScheme)
{
    if (ctx == NULL || localSignScheme == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *localSignScheme = ctx->negotiatedInfo.signScheme;
    return HITLS_SUCCESS;
}

int32_t HITLS_GetPeerSignScheme(const HITLS_Ctx *ctx, HITLS_SignHashAlgo *peerSignScheme)
{
    if (ctx == NULL || peerSignScheme == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *peerSignScheme = ctx->peerInfo.peerSignHashAlg;
    return HITLS_SUCCESS;
}

int32_t HITLS_SetEcGroups(HITLS_Ctx *ctx, uint16_t *lst, uint32_t groupSize)
{
    if (ctx == NULL || lst == NULL || groupSize == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetGroups(&(ctx->config.tlsConfig), lst, groupSize);
}

int32_t HITLS_SetSigalgsList(HITLS_Ctx *ctx, const uint16_t *signAlgs, uint16_t signAlgsSize)
{
    if (ctx == NULL || signAlgs == NULL || signAlgsSize == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetSignature(&(ctx->config.tlsConfig), signAlgs, signAlgsSize);
}

int32_t HITLS_GetRenegotiationSupport(const HITLS_Ctx *ctx, uint8_t *isSupportRenegotiation)
{
    if (ctx == NULL || isSupportRenegotiation == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_GetRenegotiationSupport(&(ctx->config.tlsConfig), isSupportRenegotiation);
}

int32_t HITLS_SetEcPointFormats(HITLS_Ctx *ctx, const uint8_t *pointFormats, uint32_t pointFormatsSize)
{
    if (ctx == NULL || pointFormats == NULL || pointFormatsSize == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    return HITLS_CFG_SetEcPointFormats(&(ctx->config.tlsConfig), pointFormats, pointFormatsSize);
}

int32_t HITLS_ClearChainCerts(HITLS_Ctx *ctx)
{
    if (ctx == NULL || ctx->config.tlsConfig.certMgrCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    int32_t ret = HITLS_CFG_ClearChainCerts(&(ctx->config.tlsConfig));
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    return HITLS_SUCCESS;
}

int32_t HITLS_SetClientVerifySupport(HITLS_Ctx *ctx, bool support)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    return HITLS_CFG_SetClientVerifySupport(&(ctx->config.tlsConfig), support);
}

int32_t HITLS_SetNoClientCertSupport(HITLS_Ctx *ctx, bool support)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetNoClientCertSupport(&(ctx->config.tlsConfig), support);
}

int32_t HITLS_SetPostHandshakeAuthSupport(HITLS_Ctx *ctx, bool support)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetPostHandshakeAuthSupport(&(ctx->config.tlsConfig), support);
}

int32_t HITLS_SetVerifyNoneSupport(HITLS_Ctx *ctx, bool support)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetVerifyNoneSupport(&(ctx->config.tlsConfig), support);
}

int32_t HITLS_SetClientOnceVerifySupport(HITLS_Ctx *ctx, bool support)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetClientOnceVerifySupport(&(ctx->config.tlsConfig), support);
}

int32_t HITLS_SetDhAutoSupport(HITLS_Ctx *ctx, bool support)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetDhAutoSupport(&(ctx->config.tlsConfig), support);
}

int32_t HITLS_SetTmpDh(HITLS_Ctx *ctx, HITLS_CRYPT_Key *dhPkey)
{
    if (ctx == NULL || dhPkey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetTmpDh(&(ctx->config.tlsConfig), dhPkey);
}

HITLS_CERT_Chain *HITLS_GetPeerCertChain(const HITLS_Ctx *ctx)
{
    int32_t ret;
    CERT_Pair *certPair = NULL;

    if (ctx == NULL || ctx->session == NULL) {
        return NULL;
    }

    ret = SESS_GetPeerCert(ctx->session, &certPair);
    if (ret != HITLS_SUCCESS || certPair == NULL) {
        return NULL;
    }

    HITLS_CERT_Chain *certChain = SAL_CERT_PairGetChain(certPair);
    return certChain;
}

HITLS_TrustedCAList *HITLS_GetClientCAList(const HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    return ctx->peerInfo.caList;
}

int32_t HITLS_GetSecureRenegotiationSupport(const HITLS_Ctx *ctx, uint8_t *isSecureRenegotiation)
{
    if (ctx == NULL || isSecureRenegotiation == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *isSecureRenegotiation = (uint8_t)ctx->negotiatedInfo.isSecureRenegotiation;
    return HITLS_SUCCESS;
}