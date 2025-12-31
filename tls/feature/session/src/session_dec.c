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
#include <stdbool.h>
#include "securec.h"
#include "tlv.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "tls_binlog_id.h"
#include "bsl_bytes.h"
#include "bsl_sal.h"
#include "hitls_error.h"
#include "session_enc.h"
#include "session_type.h"
#include "cert_method.h"
#include "parse_common.h"

#define MAX_PSK_IDENTITY_LEN 0xffff
#ifdef HITLS_TLS_FEATURE_SNI
#define MAX_HOST_NAME_LEN 0xff
#endif
typedef int32_t (*PfuncDecSessionObjFunc)(HITLS_Session *sess, SessionObjType type, const uint8_t *data,
    uint32_t length, uint32_t *readLen);

typedef struct {
    SessionObjType type;
    PfuncDecSessionObjFunc func;
} SessObjDecFunc;

static int32_t DecSessObjVersion(HITLS_Session *sess, SessionObjType type, const uint8_t *data, uint32_t length,
    uint32_t *readLen)
{
    uint16_t version = 0;
    BSL_Tlv tlv = {0, (uint32_t)sizeof(version), (uint8_t *)&version};

    int32_t ret = BSL_TLV_Parse(type, data, length, &tlv, readLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_DEC_VERSION_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15993, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "decode session version fail. ret %d", ret, 0, 0, 0);
        return HITLS_SESS_ERR_DEC_VERSION_FAIL;
    }

    sess->version = version;
    return HITLS_SUCCESS;
}

static int32_t DecSessObjCipherSuite(HITLS_Session *sess, SessionObjType type, const uint8_t *data, uint32_t length,
    uint32_t *readLen)
{
    uint16_t cipherSuite = 0;
    BSL_Tlv tlv = {0, (uint32_t)sizeof(cipherSuite), (uint8_t *)&cipherSuite};

    int32_t ret = BSL_TLV_Parse(type, data, length, &tlv, readLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_DEC_CIPHER_SUITE_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15994, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "decode session cipher suite fail. ret %d", ret, 0, 0, 0);
        return HITLS_SESS_ERR_DEC_CIPHER_SUITE_FAIL;
    }

    sess->cipherSuite = cipherSuite;
    return HITLS_SUCCESS;
}

static int32_t DecSessObjMasterSecret(HITLS_Session *sess, SessionObjType type, const uint8_t *data, uint32_t length,
    uint32_t *readLen)
{
    BSL_Tlv tlv = {0, MAX_MASTER_KEY_SIZE, sess->masterKey};

    int32_t ret = BSL_TLV_Parse(type, data, length, &tlv, readLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_DEC_MASTER_SECRET_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15995, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "decode session master secret fail. ret %d", ret, 0, 0, 0);
        return HITLS_SESS_ERR_DEC_MASTER_SECRET_FAIL;
    }

    sess->masterKeySize = tlv.length;
    return HITLS_SUCCESS;
}

static int32_t DecSessObjStartTime(HITLS_Session *sess, SessionObjType type, const uint8_t *data, uint32_t length,
    uint32_t *readLen)
{
    uint64_t startTime = 0;
    BSL_Tlv tlv = {0, (uint32_t)sizeof(startTime), (uint8_t *)&startTime};

    int32_t ret = BSL_TLV_Parse(type, data, length, &tlv, readLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_DEC_START_TIME_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15998, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "decode session start time fail. ret %d", ret, 0, 0, 0);
        return HITLS_SESS_ERR_DEC_START_TIME_FAIL;
    }

    sess->startTime = startTime;
    return HITLS_SUCCESS;
}

static int32_t DecSessObjTimeout(HITLS_Session *sess, SessionObjType type, const uint8_t *data, uint32_t length,
    uint32_t *readLen)
{
    uint64_t timeout = 0;
    BSL_Tlv tlv = {0, (uint32_t)sizeof(timeout), (uint8_t *)&timeout};

    int32_t ret = BSL_TLV_Parse(type, data, length, &tlv, readLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_DEC_TIME_OUT_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15999, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "decode session timeout fail. ret %d", ret, 0, 0, 0);
        return HITLS_SESS_ERR_DEC_TIME_OUT_FAIL;
    }

    sess->timeout = timeout;
    return HITLS_SUCCESS;
}

#ifdef HITLS_TLS_FEATURE_SNI
static int32_t DecSessObjHostName(HITLS_Session *sess, SessionObjType type, const uint8_t *data, uint32_t length,
    uint32_t *readLen)
{
    uint32_t offset = sizeof(uint32_t);
    // The length has been verified at the upper layer and must be greater than 8 bytes.
    uint32_t tlvLen = BSL_ByteToUint32(&data[offset]);
    if (tlvLen > MAX_HOST_NAME_LEN || tlvLen == 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16701, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "tlvLen error", 0, 0, 0, 0);
        return HITLS_SESS_ERR_DEC_HOST_NAME_FAIL;
    }
    uint8_t *hostName = BSL_SAL_Calloc(1u, tlvLen);
    if (hostName == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16000, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "malloc hostName fail when decode session obj host name.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }

    BSL_Tlv tlv = {0, tlvLen, hostName};

    int32_t ret = BSL_TLV_Parse(type, data, length, &tlv, readLen);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_FREE(hostName);
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_DEC_HOST_NAME_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16001, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "decode session host name fail. ret %d", ret, 0, 0, 0);
        return HITLS_SESS_ERR_DEC_HOST_NAME_FAIL;
    }

    sess->hostName = tlv.value;
    sess->hostNameSize = tlv.length;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_SNI */

static int32_t DecSessObjSessionIdCtx(HITLS_Session *sess, SessionObjType type, const uint8_t *data, uint32_t length,
    uint32_t *readLen)
{
    BSL_Tlv tlv = {0, HITLS_SESSION_ID_MAX_SIZE, sess->sessionIdCtx};

    int32_t ret = BSL_TLV_Parse(type, data, length, &tlv, readLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_DEC_SESSION_ID_CTX_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16002, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "decode session session id ctx fail. ret %d", ret, 0, 0, 0);
        return HITLS_SESS_ERR_DEC_SESSION_ID_CTX_FAIL;
    }

    sess->sessionIdCtxSize = tlv.length;
    return HITLS_SUCCESS;
}

static int32_t DecSessObjSessionId(HITLS_Session *sess, SessionObjType type, const uint8_t *data, uint32_t length,
    uint32_t *readLen)
{
    BSL_Tlv tlv = {0, HITLS_SESSION_ID_MAX_SIZE, sess->sessionId};

    int32_t ret = BSL_TLV_Parse(type, data, length, &tlv, readLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_DEC_SESSION_ID_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16003, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "decode session session id fail. ret %d", ret, 0, 0, 0);
        return HITLS_SESS_ERR_DEC_SESSION_ID_FAIL;
    }

    sess->sessionIdSize = tlv.length;
    return HITLS_SUCCESS;
}

static int32_t DecSessObjExtendMasterSecret(HITLS_Session *sess, SessionObjType type, const uint8_t *data,
    uint32_t length, uint32_t *readLen)
{
    uint8_t haveExtMasterSecret = 0;
    BSL_Tlv tlv = {0, (uint32_t)sizeof(haveExtMasterSecret), &haveExtMasterSecret};

    int32_t ret = BSL_TLV_Parse(type, data, length, &tlv, readLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_DEC_EXT_MASTER_SECRET_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16004, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "decode session extend master secret fail. ret %d", ret, 0, 0, 0);
        return HITLS_SESS_ERR_DEC_EXT_MASTER_SECRET_FAIL;
    }

    sess->haveExtMasterSecret = (bool)haveExtMasterSecret;
    return HITLS_SUCCESS;
}

static int32_t DecSessObjVerifyResult(HITLS_Session *sess, SessionObjType type, const uint8_t *data, uint32_t length,
    uint32_t *readLen)
{
    uint32_t verifyResult = 0;
    BSL_Tlv tlv = {0, (uint32_t)sizeof(verifyResult), (uint8_t *)&verifyResult};

    int32_t ret = BSL_TLV_Parse(type, data, length, &tlv, readLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_DEC_VERIFY_RESULT_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16005, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "decode session verify result fail. ret %d", ret, 0, 0, 0);
        return HITLS_SESS_ERR_DEC_VERIFY_RESULT_FAIL;
    }

    sess->verifyResult = (int32_t)verifyResult;
    return HITLS_SUCCESS;
}

static int32_t ParseBufToCert(HITLS_Session *sess, const uint8_t *buf, uint32_t bufLen)
{
    uint32_t offset = 0;
    ParsePacket pkt = {.ctx = NULL, .buf = buf, .bufLen = bufLen, .bufOffset = &offset};
    /* Obtain the certificate length */
    uint32_t certLen = 0;
    int32_t ret = ParseBytesToUint24(&pkt, &certLen);
    if (ret != HITLS_SUCCESS || (certLen != (pkt.bufLen - CERT_LEN_TAG_SIZE))) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16260, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "decode certLen fail.", 0, 0, 0, 0);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }
#ifndef HITLS_TLS_FEATURE_PROVIDER
    CERT_MgrCtx *certMgrCtx = sess->certMgrCtx;
    if (certMgrCtx == NULL || certMgrCtx->method.certParse == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16261, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "certMgrCtx or certMgrCtx->method.certParse is null.", 0, 0, 0, 0);
        return HITLS_NULL_INPUT;
    }

    /* Parse the first device certificate. */
    HITLS_CERT_X509 *cert = certMgrCtx->method.certParse(NULL, &pkt.buf[*pkt.bufOffset], certLen,
        TLS_PARSE_TYPE_BUFF, TLS_PARSE_FORMAT_ASN1);
#else
    HITLS_CERT_X509 *cert = SAL_CERT_X509Parse(LIBCTX_FROM_SESSION_CTX(sess),
        ATTRIBUTE_FROM_SESSION_CTX(sess), NULL, &pkt.buf[*pkt.bufOffset], certLen,
        TLS_PARSE_TYPE_BUFF, TLS_PARSE_FORMAT_ASN1);
#endif
    if (cert == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16262, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "parse peer eecert error", 0, 0, 0, 0);
        return HITLS_CERT_ERR_PARSE_MSG;
    }

    CERT_Pair *newCertPair = BSL_SAL_Calloc(1u, sizeof(CERT_Pair));
    if (newCertPair == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16263, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "peer cert malloc fail.", 0, 0, 0, 0);
        SAL_CERT_X509Free(cert);
        return HITLS_MEMALLOC_FAIL;
    }
    newCertPair->cert = cert;
    sess->peerCert = newCertPair;
    return HITLS_SUCCESS;
}

static int32_t DecSessObjPeerCert(HITLS_Session *sess, SessionObjType type, const uint8_t *data, uint32_t length,
    uint32_t *readLen)
{
    (void)type;
    uint32_t offset = sizeof(uint32_t);
    // The length has been verified at the upper layer and must be greater than 8 bytes.
    uint32_t tlvLen = BSL_ByteToUint32(&data[offset]);
    offset += sizeof(uint32_t);
    if ((tlvLen == 0) || (tlvLen > length - offset)) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_DEC_PEER_CERT_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16264, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "decode peercert fail.", 0, 0, 0, 0);
        return HITLS_SESS_ERR_DEC_PEER_CERT_FAIL;
    }

    *readLen = tlvLen + offset;
    return ParseBufToCert(sess, &data[offset], tlvLen);
}

static int32_t DecSessObjTicketAgeAdd(HITLS_Session *sess, SessionObjType type, const uint8_t *data, uint32_t length,
    uint32_t *readLen)
{
    uint32_t ticketAgeAdd = 0;
    BSL_Tlv tlv = {0, (uint32_t)sizeof(ticketAgeAdd), (uint8_t *)&ticketAgeAdd};

    int32_t ret = BSL_TLV_Parse(type, data, length, &tlv, readLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_DEC_START_TIME_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15998, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "decode session TicketAgeAdd fail. ret %d", ret, 0, 0, 0);
        return HITLS_SESS_ERR_DEC_START_TIME_FAIL;
    }

    sess->ticketAgeAdd = ticketAgeAdd;
    return HITLS_SUCCESS;
}

/*
 * Decoding function list.
 * Ensure that the sequence of decode and encode types is the same.
 */
static const SessObjDecFunc OBJ_LIST[] = {
    {SESS_OBJ_VERSION, DecSessObjVersion},
    {SESS_OBJ_CIPHER_SUITE, DecSessObjCipherSuite},
    {SESS_OBJ_MASTER_SECRET, DecSessObjMasterSecret},
    {SESS_OBJ_PEER_CERT, DecSessObjPeerCert},
    {SESS_OBJ_START_TIME, DecSessObjStartTime},
    {SESS_OBJ_TIMEOUT, DecSessObjTimeout},
#ifdef HITLS_TLS_FEATURE_SNI
    {SESS_OBJ_HOST_NAME, DecSessObjHostName},
#endif
    {SESS_OBJ_SESSION_ID_CTX, DecSessObjSessionIdCtx},
    {SESS_OBJ_SESSION_ID, DecSessObjSessionId},
    {SESS_OBJ_SUPPORT_EXTEND_MASTER_SECRET, DecSessObjExtendMasterSecret},
    {SESS_OBJ_VERIFY_RESULT, DecSessObjVerifyResult},
    {SESS_OBJ_AGE_ADD, DecSessObjTicketAgeAdd},
};

int32_t SESS_Decode(HITLS_Session *sess, const uint8_t *data, uint32_t length)
{
    if (sess == NULL || data == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16006, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "SESS_Decode input parameter is NULL.", 0, 0, 0, 0);
        return HITLS_INTERNAL_EXCEPTION;
    }

    int32_t ret;
    uint32_t index;
    const uint8_t *curPos = data;
    uint32_t offset = 0;
    uint32_t readLen = 0;

    for (index = 0; index < sizeof(OBJ_LIST) / sizeof(SessObjDecFunc); index++) {
        if (length - offset < TLV_HEADER_LENGTH) {
            BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_DECODE_TICKET);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16009, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "SESS_Decode length error, offset is %u, length is %u.", offset, length, 0, 0);
            return HITLS_SESS_ERR_DECODE_TICKET;
        }

        uint32_t type = BSL_ByteToUint32(curPos);
        if (OBJ_LIST[index].type != type) {
            continue;
        }
        readLen = 0;
        ret = OBJ_LIST[index].func(sess, OBJ_LIST[index].type, curPos, length - offset, &readLen);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        offset += readLen;
        curPos += readLen;
    }
    if (offset != length) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_DECODE_TICKET);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16007, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "SESS_Decode fail, offset is %u, length is %u.", offset, length, 0, 0);
        return HITLS_SESS_ERR_DECODE_TICKET;
    }

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_SESSION_TICKET */