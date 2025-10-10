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
#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
#include "tlv.h"
#include "bsl_log_internal.h"
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
#include "cert_method.h"

typedef int32_t (*PfuncEncSessionObjFunc)(const HITLS_Session *sess, SessionObjType type, uint8_t *data,
    uint32_t length, uint32_t *encLen);

typedef struct {
    SessionObjType type;
    PfuncEncSessionObjFunc func;
} SessObjEncFunc;

static int32_t EncSessObjVersion(const HITLS_Session *sess, SessionObjType type, uint8_t *data, uint32_t length,
    uint32_t *encLen)
{
    uint16_t version = sess->version;
    BSL_Tlv tlv = {type, (uint32_t)sizeof(version), (uint8_t *)&version};

    if (data == NULL) {
        /* If the input parameter is NULL, return the length after encoding. */
        *encLen = sizeof(tlv.type) + sizeof(tlv.length) + tlv.length;
        return HITLS_SUCCESS;
    }

    int32_t ret = BSL_TLV_Pack(&tlv, data, length, encLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_ENC_VERSION_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15992, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode session version fail. ret %d", ret, 0, 0, 0);
        return HITLS_SESS_ERR_ENC_VERSION_FAIL;
    }

    return HITLS_SUCCESS;
}

static int32_t EncSessObjCipherSuite(const HITLS_Session *sess, SessionObjType type, uint8_t *data, uint32_t length,
    uint32_t *encLen)
{
    uint16_t cipherSuite = sess->cipherSuite;
    BSL_Tlv tlv = {type, (uint32_t)sizeof(cipherSuite), (uint8_t *)&cipherSuite};

    if (data == NULL) {
        /* If the input parameter is NULL, return the length after encoding. */
        *encLen = sizeof(tlv.type) + sizeof(tlv.length) + tlv.length;
        return HITLS_SUCCESS;
    }

    int32_t ret = BSL_TLV_Pack(&tlv, data, length, encLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_ENC_CIPHER_SUITE_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15982, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode session cipher suite fail. ret %d", ret, 0, 0, 0);
        return HITLS_SESS_ERR_ENC_CIPHER_SUITE_FAIL;
    }

    return HITLS_SUCCESS;
}

static int32_t EncSessObjMasterSecret(const HITLS_Session *sess, SessionObjType type, uint8_t *data, uint32_t length,
    uint32_t *encLen)
{
    BSL_Tlv tlv = {type, sess->masterKeySize, (uint8_t *)(uintptr_t)(sess->masterKey)};

    if (data == NULL) {
        /* If the input parameter is NULL, return the length after encoding. */
        *encLen = sizeof(tlv.type) + sizeof(tlv.length) + tlv.length;
        return HITLS_SUCCESS;
    }

    int32_t ret = BSL_TLV_Pack(&tlv, data, length, encLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_ENC_MASTER_SECRET_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15983, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode session master secret fail. ret %d", ret, 0, 0, 0);
        return HITLS_SESS_ERR_ENC_MASTER_SECRET_FAIL;
    }

    return HITLS_SUCCESS;
}

static int32_t EncSessObjStartTime(const HITLS_Session *sess, SessionObjType type, uint8_t *data, uint32_t length,
    uint32_t *encLen)
{
    uint64_t startTime = sess->startTime;
    BSL_Tlv tlv = {type, (uint32_t)sizeof(startTime), (uint8_t *)&startTime};

    if (data == NULL) {
        /* If the input parameter is NULL, return the length after encoding. */
        *encLen = sizeof(tlv.type) + sizeof(tlv.length) + tlv.length;
        return HITLS_SUCCESS;
    }

    int32_t ret = BSL_TLV_Pack(&tlv, data, length, encLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_ENC_START_TIME_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15985, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode session start time fail. ret %d", ret, 0, 0, 0);
        return HITLS_SESS_ERR_ENC_START_TIME_FAIL;
    }

    return HITLS_SUCCESS;
}

static int32_t EncSessObjTimeout(const HITLS_Session *sess, SessionObjType type, uint8_t *data, uint32_t length,
    uint32_t *encLen)
{
    uint64_t timeout = sess->timeout;
    BSL_Tlv tlv = {type, (uint32_t)sizeof(timeout), (uint8_t *)&timeout};

    if (data == NULL) {
        /* If the input parameter is NULL, return the length after encoding. */
        *encLen = sizeof(tlv.type) + sizeof(tlv.length) + tlv.length;
        return HITLS_SUCCESS;
    }

    int32_t ret = BSL_TLV_Pack(&tlv, data, length, encLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_ENC_TIME_OUT_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15986, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode session timeout fail. ret %d", ret, 0, 0, 0);
        return HITLS_SESS_ERR_ENC_TIME_OUT_FAIL;
    }

    return HITLS_SUCCESS;
}

#ifdef HITLS_TLS_FEATURE_SNI
static int32_t EncSessObjHostName(const HITLS_Session *sess, SessionObjType type, uint8_t *data, uint32_t length,
    uint32_t *encLen)
{
    if (sess->hostNameSize == 0) {
        return HITLS_SUCCESS;
    }

    BSL_Tlv tlv = {type, sess->hostNameSize, (uint8_t *)sess->hostName};

    if (data == NULL) {
        /* If the input parameter is NULL, return the length after encoding. */
        *encLen = sizeof(tlv.type) + sizeof(tlv.length) + tlv.length;
        return HITLS_SUCCESS;
    }

    int32_t ret = BSL_TLV_Pack(&tlv, data, length, encLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_ENC_HOST_NAME_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15987, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode session host name fail. ret %d", ret, 0, 0, 0);
        return HITLS_SESS_ERR_ENC_HOST_NAME_FAIL;
    }

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_SNI */

static int32_t EncSessObjSessionIdCtx(const HITLS_Session *sess, SessionObjType type, uint8_t *data, uint32_t length,
    uint32_t *encLen)
{
    if (sess->sessionIdCtxSize == 0) {
        return HITLS_SUCCESS;
    }

    BSL_Tlv tlv = {type, sess->sessionIdCtxSize, (uint8_t *)(uintptr_t)(sess->sessionIdCtx)};

    if (data == NULL) {
        /* If the input parameter is NULL, return the length after encoding. */
        *encLen = sizeof(tlv.type) + sizeof(tlv.length) + tlv.length;
        return HITLS_SUCCESS;
    }

    int32_t ret = BSL_TLV_Pack(&tlv, data, length, encLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_ENC_SESSION_ID_CTX_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15988, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode session session id ctx fail. ret %d", ret, 0, 0, 0);
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

    BSL_Tlv tlv = {type, sess->sessionIdSize, (uint8_t *)(uintptr_t)(sess->sessionId)};

    if (data == NULL) {
        /* If the input parameter is NULL, return the length after encoding. */
        *encLen = sizeof(tlv.type) + sizeof(tlv.length) + tlv.length;
        return HITLS_SUCCESS;
    }

    int32_t ret = BSL_TLV_Pack(&tlv, data, length, encLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_ENC_SESSION_ID_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15989, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode session session id fail. ret %d", ret, 0, 0, 0);
        return HITLS_SESS_ERR_ENC_SESSION_ID_FAIL;
    }

    return HITLS_SUCCESS;
}

static int32_t EncSessObjExtendMasterSecret(const HITLS_Session *sess, SessionObjType type, uint8_t *data,
    uint32_t length, uint32_t *encLen)
{
    uint8_t haveExtMasterSecret = (uint8_t)sess->haveExtMasterSecret;
    BSL_Tlv tlv = {type, (uint32_t)sizeof(haveExtMasterSecret), (uint8_t *)&haveExtMasterSecret};

    if (data == NULL) {
        /* If the input parameter is NULL, return the length after encoding. */
        *encLen = sizeof(tlv.type) + sizeof(tlv.length) + tlv.length;
        return HITLS_SUCCESS;
    }

    int32_t ret = BSL_TLV_Pack(&tlv, data, length, encLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_ENC_EXT_MASTER_SECRET_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15990, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode session extend master secret fail. ret %d", ret, 0, 0, 0);
        return HITLS_SESS_ERR_ENC_EXT_MASTER_SECRET_FAIL;
    }

    return HITLS_SUCCESS;
}

static int32_t EncSessObjVerifyResult(const HITLS_Session *sess, SessionObjType type, uint8_t *data, uint32_t length,
    uint32_t *encLen)
{
    int32_t verifyResult = sess->verifyResult;
    BSL_Tlv tlv = {type, (uint32_t)sizeof(verifyResult), (uint8_t *)&verifyResult};

    if (data == NULL) {
        /* If the input parameter is NULL, return the length after encoding. */
        *encLen = sizeof(tlv.type) + sizeof(tlv.length) + tlv.length;
        return HITLS_SUCCESS;
    }

    int32_t ret = BSL_TLV_Pack(&tlv, data, length, encLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_ENC_VERIFY_RESULT_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15991, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode session verify result fail. ret %d", ret, 0, 0, 0);
        return HITLS_SESS_ERR_ENC_VERIFY_RESULT_FAIL;
    }

    return HITLS_SUCCESS;
}

static int32_t PackCertToBuf(const HITLS_Session *sess, uint8_t *buf, uint32_t bufLen)
{
    CERT_Pair *peerCert = sess->peerCert;
    HITLS_CERT_X509 *cert = peerCert->cert;
    uint32_t encodeLen = 0;
#ifndef HITLS_TLS_FEATURE_PROVIDER
    CERT_MgrCtx *mgrCtx = sess->certMgrCtx;
    if (mgrCtx->method.certEncode == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16254, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "mgrCtx->method.certEncode is null.", 0, 0, 0, 0);
        return HITLS_NULL_INPUT;
    }
    /* Write the certificate data. */
    int32_t ret = mgrCtx->method.certEncode(NULL, cert, &buf[CERT_LEN_TAG_SIZE],
        bufLen - CERT_LEN_TAG_SIZE, &encodeLen);
#else
    int32_t ret = SAL_CERT_X509Encode(NULL, cert, &buf[CERT_LEN_TAG_SIZE],
        bufLen - CERT_LEN_TAG_SIZE, &encodeLen);
#endif
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16255, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "certEncode error.", 0, 0, 0, 0);
        return HITLS_CERT_ERR_ENCODE_CERT;
    }
    if (bufLen - CERT_LEN_TAG_SIZE != encodeLen) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16256, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encodeLen error.", 0, 0, 0, 0);
        return HITLS_CERT_ERR_ENCODE_CERT;
    }
    BSL_Uint24ToByte(encodeLen, buf);

    return HITLS_SUCCESS;
}

static uint32_t GetPeertCertSize(const HITLS_Session *sess)
{
    uint32_t certLen = 0;
    CERT_Pair *peerCert = sess->peerCert;
#ifndef HITLS_TLS_FEATURE_PROVIDER
    CERT_MgrCtx *mgrCtx = sess->certMgrCtx;
    if (mgrCtx == NULL || mgrCtx->method.certCtrl == NULL || peerCert->cert == NULL) {
        return 0;
    }
    int32_t ret = mgrCtx->method.certCtrl(NULL, peerCert->cert, CERT_CTRL_GET_ENCODE_LEN, NULL, (void *)&certLen);
#else
    int32_t ret = SAL_CERT_X509Ctrl(NULL, peerCert->cert, CERT_CTRL_GET_ENCODE_LEN, NULL, (void *)&certLen);
#endif
    if (ret != HITLS_SUCCESS || certLen == 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16257, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
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
    BSL_Tlv tlv = {type, bufLen, NULL};

    if (data == NULL) {
        /* If the input parameter is NULL, return the length after encoding. */
        *encLen = sizeof(tlv.type) + sizeof(tlv.length) + tlv.length;
        return HITLS_SUCCESS;
    }
    uint8_t *curPos = data;
    if ((length < TLV_HEADER_LENGTH) || (tlv.length > length - TLV_HEADER_LENGTH)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16258, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "TLV build error: length = %u is not enough for tlv length = %u, tlv type = 0x%x.",
            length, tlv.length, tlv.type, 0);
        BSL_ERR_PUSH_ERROR(BSL_TLV_ERR_BAD_PARAM);
        return BSL_TLV_ERR_BAD_PARAM;
    }

    /* Write the TLV type */
    BSL_Uint32ToByte(tlv.type, curPos);
    curPos += sizeof(uint32_t);
    /* Write the TLV length */
    BSL_Uint32ToByte(tlv.length, curPos);
    curPos += sizeof(uint32_t);
    int32_t ret = PackCertToBuf(sess, curPos, tlv.length);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16265, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "PackCertToBuf fail. ret %d", ret, 0, 0, 0);
        return HITLS_SESS_ERR_ENC_PEER_CERT_FAIL;
    }

    *encLen = TLV_HEADER_LENGTH + tlv.length;

    return HITLS_SUCCESS;
}

static int32_t EncSessObjTicketAgeAdd(const HITLS_Session *sess, SessionObjType type, uint8_t *data, uint32_t length,
    uint32_t *encLen)
{
    uint32_t ticketAgeAdd = sess->ticketAgeAdd;
    BSL_Tlv tlv = {type, (uint32_t)sizeof(ticketAgeAdd), (uint8_t *)&ticketAgeAdd};

    if (data == NULL) {
        /* If the input parameter is NULL, the length after encoding is returned. */
        *encLen = sizeof(tlv.type) + sizeof(tlv.length) + tlv.length;
        return HITLS_SUCCESS;
    }

    int32_t ret = BSL_TLV_Pack(&tlv, data, length, encLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_ENC_VERIFY_RESULT_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16183, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode session TicketAgeAdd fail. ret %d", ret, 0, 0, 0);
        return HITLS_SESS_ERR_ENC_VERIFY_RESULT_FAIL;
    }

    return HITLS_SUCCESS;
}

/*
 * Encoding function list.
 * Ensure that the sequence of decode and encode types is the same.
 */
static const SessObjEncFunc OBJ_LIST[] = {
    {SESS_OBJ_VERSION, EncSessObjVersion},
    {SESS_OBJ_CIPHER_SUITE, EncSessObjCipherSuite},
    {SESS_OBJ_MASTER_SECRET, EncSessObjMasterSecret},
    {SESS_OBJ_PEER_CERT, EncSessObjPeerCert},
    {SESS_OBJ_START_TIME, EncSessObjStartTime},
    {SESS_OBJ_TIMEOUT, EncSessObjTimeout},
#ifdef HITLS_TLS_FEATURE_SNI
    {SESS_OBJ_HOST_NAME, EncSessObjHostName},
#endif
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
#endif /* HITLS_TLS_FEATURE_SESSION_TICKET */