/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "tlv.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "tls_binlog_id.h"
#include "bsl_bytes.h"
#include "bsl_list.h"
#include "bsl_sal.h"
#include "hitls_error.h"
#include "session_type.h"
#include "cert_mgr_ctx.h"
#include "session_enc.h"

typedef int32_t (*PfuncEncSessionObjFunc)(const HITLS_Session *sess, SessionObjType type, uint8_t *data,
    uint32_t length, uint32_t *encLen);

typedef struct {
    SessionObjType type;
    PfuncEncSessionObjFunc func;
} SessObjEncFunc;

static int32_t EncSessObjVersion(const HITLS_Session *sess, SessionObjType type, uint8_t *data, uint32_t length,
    uint32_t *encLen)
{
    int ret;
    uint16_t version = sess->version;
    BSL_Tlv tlv = {0};
    tlv.type = type;
    tlv.length = sizeof(version);
    tlv.value = (uint8_t *)&version;

    if (data == NULL) {
        /* If the input parameter is NULL, return the length after encoding. */
        *encLen = sizeof(tlv.type) + sizeof(tlv.length) + tlv.length;
        return HITLS_SUCCESS;
    }

    ret = BSL_TLV_Pack(&tlv, data, length, encLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_ENC_VERSION_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15992, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode session obj version fail.", 0, 0, 0, 0);
        return HITLS_SESS_ERR_ENC_VERSION_FAIL;
    }

    return HITLS_SUCCESS;
}

static int32_t EncSessObjCipherSuite(const HITLS_Session *sess, SessionObjType type, uint8_t *data, uint32_t length,
    uint32_t *encLen)
{
    int ret;
    uint16_t cipherSuite = sess->cipherSuite;
    BSL_Tlv tlv = {0};
    tlv.type = type;
    tlv.length = sizeof(cipherSuite);
    tlv.value = (uint8_t *)&cipherSuite;

    if (data == NULL) {
        /* If the input parameter is NULL, return the length after encoding. */
        *encLen = sizeof(tlv.type) + sizeof(tlv.length) + tlv.length;
        return HITLS_SUCCESS;
    }

    ret = BSL_TLV_Pack(&tlv, data, length, encLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_ENC_CIPHER_SUITE_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15982, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode session obj cipher suite fail.", 0, 0, 0, 0);
        return HITLS_SESS_ERR_ENC_CIPHER_SUITE_FAIL;
    }

    return HITLS_SUCCESS;
}

static int32_t EncSessObjMasterSecret(const HITLS_Session *sess, SessionObjType type, uint8_t *data, uint32_t length,
    uint32_t *encLen)
{
    int ret;
    BSL_Tlv tlv = {0};
    tlv.type = type;
    tlv.length = sess->masterKeySize;
    tlv.value = (uint8_t *)sess->masterKey;

    if (data == NULL) {
        /* If the input parameter is NULL, return the length after encoding. */
        *encLen = sizeof(tlv.type) + sizeof(tlv.length) + tlv.length;
        return HITLS_SUCCESS;
    }

    ret = BSL_TLV_Pack(&tlv, data, length, encLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_ENC_MASTER_SECRET_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15983, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode session obj master secret fail.", 0, 0, 0, 0);
        return HITLS_SESS_ERR_ENC_MASTER_SECRET_FAIL;
    }

    return HITLS_SUCCESS;
}

static int32_t EncSessObjPskIdentity(const HITLS_Session *sess, SessionObjType type, uint8_t *data, uint32_t length,
    uint32_t *encLen)
{
    if (sess->pskIdentitySize == 0) {
        return HITLS_SUCCESS;
    }

    int ret;
    BSL_Tlv tlv = {0};
    tlv.type = type;
    tlv.length = sess->pskIdentitySize;
    tlv.value = (uint8_t *)sess->pskIdentity;

    if (data == NULL) {
        /* If the input parameter is NULL, return the length after encoding. */
        *encLen = sizeof(tlv.type) + sizeof(tlv.length) + tlv.length;
        return HITLS_SUCCESS;
    }

    ret = BSL_TLV_Pack(&tlv, data, length, encLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_ENC_PSK_IDENTITY_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15984, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode session obj psk identity fail.", 0, 0, 0, 0);
        return HITLS_SESS_ERR_ENC_PSK_IDENTITY_FAIL;
    }

    return HITLS_SUCCESS;
}

static int32_t EncSessObjStartTime(const HITLS_Session *sess, SessionObjType type, uint8_t *data, uint32_t length,
    uint32_t *encLen)
{
    int ret;
    uint64_t startTime = sess->startTime;
    BSL_Tlv tlv = {0};
    tlv.type = type;
    tlv.length = sizeof(startTime);
    tlv.value = (uint8_t *)&startTime;

    if (data == NULL) {
        /* If the input parameter is NULL, return the length after encoding. */
        *encLen = sizeof(tlv.type) + sizeof(tlv.length) + tlv.length;
        return HITLS_SUCCESS;
    }

    ret = BSL_TLV_Pack(&tlv, data, length, encLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_ENC_START_TIME_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15985, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode session obj start time fail.", 0, 0, 0, 0);
        return HITLS_SESS_ERR_ENC_START_TIME_FAIL;
    }

    return HITLS_SUCCESS;
}

static int32_t EncSessObjTimeout(const HITLS_Session *sess, SessionObjType type, uint8_t *data, uint32_t length,
    uint32_t *encLen)
{
    int ret;
    uint64_t timeout = sess->timeout;
    BSL_Tlv tlv = {0};
    tlv.type = type;
    tlv.length = sizeof(timeout);
    tlv.value = (uint8_t *)&timeout;

    if (data == NULL) {
        /* If the input parameter is NULL, return the length after encoding. */
        *encLen = sizeof(tlv.type) + sizeof(tlv.length) + tlv.length;
        return HITLS_SUCCESS;
    }

    ret = BSL_TLV_Pack(&tlv, data, length, encLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_ENC_TIME_OUT_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15986, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode session obj timeout fail.", 0, 0, 0, 0);
        return HITLS_SESS_ERR_ENC_TIME_OUT_FAIL;
    }

    return HITLS_SUCCESS;
}

static int32_t EncSessObjHostName(const HITLS_Session *sess, SessionObjType type, uint8_t *data, uint32_t length,
    uint32_t *encLen)
{
    if (sess->hostNameSize == 0) {
        return HITLS_SUCCESS;
    }

    int ret;
    BSL_Tlv tlv = {0};
    tlv.type = type;
    tlv.length = sess->hostNameSize;
    tlv.value = (uint8_t *)sess->hostName;

    if (data == NULL) {
        /* If the input parameter is NULL, return the length after encoding. */
        *encLen = sizeof(tlv.type) + sizeof(tlv.length) + tlv.length;
        return HITLS_SUCCESS;
    }

    ret = BSL_TLV_Pack(&tlv, data, length, encLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_ENC_HOST_NAME_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15987, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode session obj host name fail.", 0, 0, 0, 0);
        return HITLS_SESS_ERR_ENC_HOST_NAME_FAIL;
    }

    return HITLS_SUCCESS;
}

static int32_t EncSessObjSessionIdCtx(const HITLS_Session *sess, SessionObjType type, uint8_t *data, uint32_t length,
    uint32_t *encLen)
{
    if (sess->sessionIdCtxSize == 0) {
        return HITLS_SUCCESS;
    }

    int ret;
    BSL_Tlv tlv = {0};
    tlv.type = type;
    tlv.length = sess->sessionIdCtxSize;
    tlv.value = (uint8_t *)sess->sessionIdCtx;

    if (data == NULL) {
        /* If the input parameter is NULL, return the length after encoding. */
        *encLen = sizeof(tlv.type) + sizeof(tlv.length) + tlv.length;
        return HITLS_SUCCESS;
    }

    ret = BSL_TLV_Pack(&tlv, data, length, encLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_ENC_SESSION_ID_CTX_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15988, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode session obj session id ctx fail.", 0, 0, 0, 0);
        return HITLS_SESS_ERR_ENC_SESSION_ID_CTX_FAIL;
    }

    return HITLS_SUCCESS;
}

static int32_t EncSessObjSessionId(const HITLS_Session *sess, SessionObjType type, uint8_t *data, uint32_t length,
    uint32_t *encLen)
{
    if (sess->sessionIdSize == 0) {
        return HITLS_SUCCESS;
    }

    int ret;
    BSL_Tlv tlv = {0};
    tlv.type = type;
    tlv.length = sess->sessionIdSize;
    tlv.value = (uint8_t *)sess->sessionId;

    if (data == NULL) {
        /* If the input parameter is NULL, return the length after encoding. */
        *encLen = sizeof(tlv.type) + sizeof(tlv.length) + tlv.length;
        return HITLS_SUCCESS;
    }

    ret = BSL_TLV_Pack(&tlv, data, length, encLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_ENC_SESSION_ID_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15989, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode session obj session id fail.", 0, 0, 0, 0);
        return HITLS_SESS_ERR_ENC_SESSION_ID_FAIL;
    }

    return HITLS_SUCCESS;
}

static int32_t EncSessObjExtendMasterSecret(const HITLS_Session *sess, SessionObjType type, uint8_t *data,
    uint32_t length, uint32_t *encLen)
{
    int ret;
    uint8_t haveExtMasterSecret = (uint8_t)sess->haveExtMasterSecret;
    BSL_Tlv tlv = {0};
    tlv.type = type;
    tlv.length = sizeof(haveExtMasterSecret);
    tlv.value = (uint8_t *)&haveExtMasterSecret;

    if (data == NULL) {
        /* If the input parameter is NULL, return the length after encoding. */
        *encLen = sizeof(tlv.type) + sizeof(tlv.length) + tlv.length;
        return HITLS_SUCCESS;
    }

    ret = BSL_TLV_Pack(&tlv, data, length, encLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_ENC_EXT_MASTER_SECRET_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15990, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode session obj extend master secret fail.", 0, 0, 0, 0);
        return HITLS_SESS_ERR_ENC_EXT_MASTER_SECRET_FAIL;
    }

    return HITLS_SUCCESS;
}

static int32_t EncSessObjVerifyResult(const HITLS_Session *sess, SessionObjType type, uint8_t *data, uint32_t length,
    uint32_t *encLen)
{
    int ret;
    int32_t verifyResult = sess->verifyResult;
    BSL_Tlv tlv = {0};
    tlv.type = type;
    tlv.length = sizeof(verifyResult);
    tlv.value = (uint8_t *)&verifyResult;

    if (data == NULL) {
        /* If the input parameter is NULL, return the length after encoding. */
        *encLen = sizeof(tlv.type) + sizeof(tlv.length) + tlv.length;
        return HITLS_SUCCESS;
    }

    ret = BSL_TLV_Pack(&tlv, data, length, encLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_ENC_VERIFY_RESULT_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15991, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode session obj verify result fail.", 0, 0, 0, 0);
        return HITLS_SESS_ERR_ENC_VERIFY_RESULT_FAIL;
    }

    return HITLS_SUCCESS;
}

static int32_t PackCertToBuf(const HITLS_Session *sess, uint8_t *buf, uint32_t bufLen)
{
    CERT_Pair *peerCert = sess->peerCert;
    HITLS_CERT_X509 *cert = peerCert->cert;
    CERT_MgrCtx *mgrCtx = sess->certMgrCtx;
    if (mgrCtx->method.certEncode == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16063, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "mgrCtx->method.certEncode is null.", 0, 0, 0, 0);
        return HITLS_NULL_INPUT;
    }
    uint32_t encodeLen = 0;
    /* Write the certificate data. */
    int32_t ret = mgrCtx->method.certEncode(NULL, cert, &buf[CERT_LEN_TAG_SIZE],
        bufLen - CERT_LEN_TAG_SIZE, &encodeLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16064, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "certEncode error.", 0, 0, 0, 0);
        return HITLS_CERT_ERR_ENCODE_CERT;
    }
    if (bufLen - CERT_LEN_TAG_SIZE != encodeLen) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16065, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encodeLen error.", 0, 0, 0, 0);
        return HITLS_CERT_ERR_ENCODE_CERT;
    }
    BSL_Uint24ToByte(encodeLen, buf);

    return HITLS_SUCCESS;
}

static int32_t GetPeertCertSize(const HITLS_Session *sess)
{
    uint32_t certLen = 0;
    CERT_Pair *peerCert = sess->peerCert;
    CERT_MgrCtx *mgrCtx = sess->certMgrCtx;
    if (mgrCtx == NULL || mgrCtx->method.certCtrl == NULL || peerCert->cert == NULL) {
        return 0;
    }
    int32_t ret = mgrCtx->method.certCtrl(NULL, peerCert->cert, CERT_CTRL_GET_ENCODE_LEN, NULL, (void *)&certLen);
    if (ret != HITLS_SUCCESS || certLen == 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16066, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "CERT_CTRL_GET_ENCODE_LEN error.", 0, 0, 0, 0);
        return 0;
    }
    return certLen + CERT_LEN_TAG_SIZE;
}

static int32_t EncSessObjPeerCert(const HITLS_Session *sess, SessionObjType type, uint8_t *data, uint32_t length,
    uint32_t *encLen)
{
    CERT_Pair *peerCert = sess->peerCert;
    if (peerCert == NULL) {
        return HITLS_SUCCESS;
    }
    uint32_t bufLen = GetPeertCertSize(sess);
    if (bufLen == 0) {
        return HITLS_SUCCESS;
    }
    BSL_Tlv tlv = {0};
    tlv.type = type;
    tlv.length = bufLen;

    if (data == NULL) {
        /* If the input parameter is NULL, return the length after encoding. */
        *encLen = sizeof(tlv.type) + sizeof(tlv.length) + tlv.length;
        return HITLS_SUCCESS;
    }

    uint8_t *buf = BSL_SAL_Calloc(1u, bufLen);
    if (buf == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16067, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "buf malloc fail.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    int32_t ret = PackCertToBuf(sess, buf, bufLen);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(buf);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16068, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "PackCertToBuf fail.", 0, 0, 0, 0);
        return HITLS_SESS_ERR_ENC_PEER_CERT_FAIL;
    }
    tlv.value = buf;

    ret = BSL_TLV_Pack(&tlv, data, length, encLen);
    BSL_SAL_FREE(buf);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_ENC_PEER_CERT_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16069, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode session obj peer cert fail.", 0, 0, 0, 0);
        return HITLS_SESS_ERR_ENC_PEER_CERT_FAIL;
    }

    return HITLS_SUCCESS;
}

static int32_t EncSessObjTicketAgeAdd(const HITLS_Session *sess, SessionObjType type, uint8_t *data, uint32_t length,
    uint32_t *encLen)
{
    int ret;
    uint32_t ticketAgeAdd = sess->ticketAgeAdd;
    BSL_Tlv tlv = {0};
    tlv.type = type;
    tlv.length = sizeof(ticketAgeAdd);
    tlv.value = (uint8_t *)&ticketAgeAdd;

    if (data == NULL) {
        /* If the input parameter is NULL, the length after encoding is returned. */
        *encLen = sizeof(tlv.type) + sizeof(tlv.length) + tlv.length;
        return HITLS_SUCCESS;
    }

    ret = BSL_TLV_Pack(&tlv, data, length, encLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_ENC_VERIFY_RESULT_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15562, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode session obj TicketAgeAdd fail.", 0, 0, 0, 0);
        return HITLS_SESS_ERR_ENC_VERIFY_RESULT_FAIL;
    }

    return HITLS_SUCCESS;
}

/**
 * Encoding function list.
 * Ensure that the sequence of decode and encode types is the same.
 */
static const SessObjEncFunc OBJ_LIST[] = {
    {SESS_OBJ_VERSION, EncSessObjVersion},
    {SESS_OBJ_CIPHER_SUITE, EncSessObjCipherSuite},
    {SESS_OBJ_MASTER_SECRET, EncSessObjMasterSecret},
    {SESS_OBJ_PEER_CERT, EncSessObjPeerCert},
    {SESS_OBJ_PSK_IDENTITY, EncSessObjPskIdentity},
    {SESS_OBJ_START_TIME, EncSessObjStartTime},
    {SESS_OBJ_TIMEOUT, EncSessObjTimeout},
    {SESS_OBJ_HOST_NAME, EncSessObjHostName},
    {SESS_OBJ_SESSION_ID_CTX, EncSessObjSessionIdCtx},
    {SESS_OBJ_SESSION_ID, EncSessObjSessionId},
    {SESS_OBJ_SUPPORT_EXTEND_MASTER_SECRET, EncSessObjExtendMasterSecret},
    {SESS_OBJ_VERIFY_RESULT, EncSessObjVerifyResult},
    {SESS_OBJ_AGE_ADD, EncSessObjTicketAgeAdd},
};

uint32_t SESS_GetTotalEncodeSize(const HITLS_Session *sess)
{
    if (sess == NULL) {
        return 0;
    }

    uint32_t index;
    uint32_t offset = 0;
    uint32_t encLen = 0;

    for (index = 0; index < sizeof(OBJ_LIST) / sizeof(SessObjEncFunc); index++) {
        encLen = 0;
        /* This parameter is used only to obtain the encoded length and will not verified the returned value. */
        (void)OBJ_LIST[index].func(sess, OBJ_LIST[index].type, NULL, 0, &encLen);
        offset += encLen;
    }

    return offset;
}

int32_t SESS_Encode(const HITLS_Session *sess, uint8_t *data, uint32_t length, uint32_t *usedLen)
{
    if (sess == NULL || data == NULL || usedLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16008, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "SESS_Encode input parameter is NULL.", 0, 0, 0, 0);
        return HITLS_INTERNAL_EXCEPTION;
    }

    int32_t ret;
    uint32_t index;
    uint8_t *curPos = data;
    uint32_t offset = 0;
    uint32_t encLen = 0;

    for (index = 0; index < sizeof(OBJ_LIST) / sizeof(SessObjEncFunc); index++) {
        encLen = 0;
        ret = OBJ_LIST[index].func(sess, OBJ_LIST[index].type, curPos, length - offset, &encLen);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        offset += encLen;
        curPos += encLen;
    }

    *usedLen = offset;
    return HITLS_SUCCESS;
}
