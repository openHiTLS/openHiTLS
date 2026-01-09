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
#include "securec.h"
#include "bsl_sal.h"
#include "tls_binlog_id.h"
#include "hitls_type.h"
#include "hitls_crypt_type.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "tls_config.h"
#include "config.h"
#include "cipher_suite.h"
#include "cert_mgr.h"
#ifdef HITLS_TLS_FEATURE_SESSION
#include "session_mgr.h"
#endif
#ifdef HITLS_TLS_FEATURE_SECURITY
#include "security.h"
#endif
#include "config_type.h"
#include "config_check.h"

#ifdef HITLS_TLS_PROTO_TLCP11
uint16_t g_tlcpCipherSuites[] = {
    HITLS_ECDHE_SM4_CBC_SM3,
    HITLS_ECC_SM4_CBC_SM3,
    HITLS_ECDHE_SM4_GCM_SM3,
    HITLS_ECC_SM4_GCM_SM3,
};
#endif

uint16_t g_tls12CipherSuites[] = {
#ifdef HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    HITLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
#endif
#ifdef HITLS_TLS_SUITE_DHE_DSS_WITH_AES_256_GCM_SHA384
    HITLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
#endif
#ifdef HITLS_TLS_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384
    HITLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    HITLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    HITLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
#endif
#ifdef HITLS_TLS_SUITE_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    HITLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    HITLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
#endif
#ifdef HITLS_TLS_SUITE_DHE_DSS_WITH_AES_128_GCM_SHA256
    HITLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
#endif
#ifdef HITLS_TLS_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256
    HITLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM
    HITLS_ECDHE_ECDSA_WITH_AES_128_CCM,
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM
    HITLS_ECDHE_ECDSA_WITH_AES_256_CCM,
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
    HITLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384
    HITLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
#endif
#ifdef HITLS_TLS_SUITE_DHE_RSA_WITH_AES_128_CCM
    HITLS_DHE_RSA_WITH_AES_128_CCM,
#endif
#ifdef HITLS_TLS_SUITE_DHE_RSA_WITH_AES_256_CCM
    HITLS_DHE_RSA_WITH_AES_256_CCM,
#endif
#ifdef HITLS_TLS_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256
    HITLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
#endif
#ifdef HITLS_TLS_SUITE_DHE_DSS_WITH_AES_256_CBC_SHA256
    HITLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
    HITLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    HITLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
#endif
#ifdef HITLS_TLS_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256
    HITLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
#endif
#ifdef HITLS_TLS_SUITE_DHE_DSS_WITH_AES_128_CBC_SHA256
    HITLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
    HITLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA
    HITLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
#endif
#ifdef HITLS_TLS_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA
    HITLS_DHE_RSA_WITH_AES_256_CBC_SHA,
#endif
#ifdef HITLS_TLS_SUITE_DHE_DSS_WITH_AES_256_CBC_SHA
    HITLS_DHE_DSS_WITH_AES_256_CBC_SHA,
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
    HITLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA
    HITLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
#endif
#ifdef HITLS_TLS_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA
    HITLS_DHE_RSA_WITH_AES_128_CBC_SHA,
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_256_GCM_SHA384
    HITLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384,
#endif
#ifdef HITLS_TLS_SUITE_RSA_PSK_WITH_AES_256_GCM_SHA384
    HITLS_RSA_PSK_WITH_AES_256_GCM_SHA384,
#endif
#ifdef HITLS_TLS_SUITE_DHE_PSK_WITH_AES_256_GCM_SHA384
    HITLS_DHE_PSK_WITH_AES_256_GCM_SHA384,
#endif
#ifdef HITLS_TLS_SUITE_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256
    HITLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256,
#endif
#ifdef HITLS_TLS_SUITE_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256
    HITLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256
    HITLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
#endif
#ifdef HITLS_TLS_SUITE_DHE_DSS_WITH_AES_128_CBC_SHA
    HITLS_DHE_DSS_WITH_AES_128_CBC_SHA,
#endif
#ifdef HITLS_TLS_SUITE_RSA_WITH_AES_256_GCM_SHA384
    HITLS_RSA_WITH_AES_256_GCM_SHA384,
#endif
#ifdef HITLS_TLS_SUITE_PSK_WITH_AES_256_GCM_SHA384
    HITLS_PSK_WITH_AES_256_GCM_SHA384,
#endif
#ifdef HITLS_TLS_SUITE_PSK_WITH_CHACHA20_POLY1305_SHA256
    HITLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_128_GCM_SHA256
    HITLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256,
#endif
#ifdef HITLS_TLS_SUITE_RSA_PSK_WITH_AES_128_GCM_SHA256
    HITLS_RSA_PSK_WITH_AES_128_GCM_SHA256,
#endif
#ifdef HITLS_TLS_SUITE_DHE_PSK_WITH_AES_128_GCM_SHA256
    HITLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
#endif
#ifdef HITLS_TLS_SUITE_RSA_WITH_AES_128_GCM_SHA256
    HITLS_RSA_WITH_AES_128_GCM_SHA256,
#endif
#ifdef HITLS_TLS_SUITE_PSK_WITH_AES_128_GCM_SHA256
    HITLS_PSK_WITH_AES_128_GCM_SHA256,
#endif
#ifdef HITLS_TLS_SUITE_PSK_WITH_AES_256_CCM
    HITLS_PSK_WITH_AES_256_CCM,
#endif
#ifdef HITLS_TLS_SUITE_RSA_WITH_AES_256_CBC_SHA256
    HITLS_RSA_WITH_AES_256_CBC_SHA256,
#endif
#ifdef HITLS_TLS_SUITE_RSA_WITH_AES_128_CBC_SHA256
    HITLS_RSA_WITH_AES_128_CBC_SHA256,
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_128_CCM_SHA256
    HITLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256,
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_256_CBC_SHA384
    HITLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_256_CBC_SHA
    HITLS_ECDHE_PSK_WITH_AES_256_CBC_SHA,
#endif
#ifdef HITLS_TLS_SUITE_RSA_PSK_WITH_AES_256_CBC_SHA384
    HITLS_RSA_PSK_WITH_AES_256_CBC_SHA384,
#endif
#ifdef HITLS_TLS_SUITE_DHE_PSK_WITH_AES_128_CCM
    HITLS_DHE_PSK_WITH_AES_128_CCM,
#endif
#ifdef HITLS_TLS_SUITE_DHE_PSK_WITH_AES_256_CCM
    HITLS_DHE_PSK_WITH_AES_256_CCM,
#endif
#ifdef HITLS_TLS_SUITE_DHE_PSK_WITH_AES_256_CBC_SHA384
    HITLS_DHE_PSK_WITH_AES_256_CBC_SHA384,
#endif
#ifdef HITLS_TLS_SUITE_RSA_PSK_WITH_AES_256_CBC_SHA
    HITLS_RSA_PSK_WITH_AES_256_CBC_SHA,
#endif
#ifdef HITLS_TLS_SUITE_DHE_PSK_WITH_AES_256_CBC_SHA
    HITLS_DHE_PSK_WITH_AES_256_CBC_SHA,
#endif
#ifdef HITLS_TLS_SUITE_RSA_WITH_AES_256_CBC_SHA
    HITLS_RSA_WITH_AES_256_CBC_SHA,
#endif
#ifdef HITLS_TLS_SUITE_PSK_WITH_AES_256_CBC_SHA384
    HITLS_PSK_WITH_AES_256_CBC_SHA384,
#endif
#ifdef HITLS_TLS_SUITE_PSK_WITH_AES_256_CBC_SHA
    HITLS_PSK_WITH_AES_256_CBC_SHA,
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_128_CBC_SHA256
    HITLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
#endif
#ifdef HITLS_TLS_SUITE_ECDHE_PSK_WITH_AES_128_CBC_SHA
    HITLS_ECDHE_PSK_WITH_AES_128_CBC_SHA,
#endif
#ifdef HITLS_TLS_SUITE_RSA_PSK_WITH_AES_128_CBC_SHA256
    HITLS_RSA_PSK_WITH_AES_128_CBC_SHA256,
#endif
#ifdef HITLS_TLS_SUITE_DHE_PSK_WITH_AES_128_CBC_SHA256
    HITLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
#endif
#ifdef HITLS_TLS_SUITE_RSA_PSK_WITH_AES_128_CBC_SHA
    HITLS_RSA_PSK_WITH_AES_128_CBC_SHA,
#endif
#ifdef HITLS_TLS_SUITE_DHE_PSK_WITH_AES_128_CBC_SHA
    HITLS_DHE_PSK_WITH_AES_128_CBC_SHA,
#endif
#ifdef HITLS_TLS_SUITE_RSA_WITH_AES_128_CBC_SHA
    HITLS_RSA_WITH_AES_128_CBC_SHA,
#endif
#ifdef HITLS_TLS_SUITE_PSK_WITH_AES_128_CBC_SHA256
    HITLS_PSK_WITH_AES_128_CBC_SHA256,
#endif
#ifdef HITLS_TLS_SUITE_PSK_WITH_AES_128_CBC_SHA
    HITLS_PSK_WITH_AES_128_CBC_SHA,
#endif
};

int32_t SetDefaultCipherSuite(HITLS_Config *config, const uint16_t *cipherSuites, uint32_t cipherSuiteSize)
{
    BSL_SAL_FREE(config->cipherSuites);
    config->cipherSuites = BSL_SAL_Dump(cipherSuites, cipherSuiteSize);
    if (config->cipherSuites == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16563, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Dump fail", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }

    config->cipherSuitesSize = cipherSuiteSize / sizeof(uint16_t);
    return HITLS_SUCCESS;
}

#ifdef HITLS_TLS_PROTO_TLS13
static int32_t SetTLS13DefaultCipherSuites(HITLS_Config *config)
{
    const uint16_t ciphersuites13[] = {
        HITLS_AES_256_GCM_SHA384,
        HITLS_CHACHA20_POLY1305_SHA256,
        HITLS_AES_128_GCM_SHA256,
    };

    BSL_SAL_FREE(config->tls13CipherSuites);
    config->tls13CipherSuites = BSL_SAL_Dump(ciphersuites13, sizeof(ciphersuites13));
    if (config->tls13CipherSuites == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16564, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Dump fail", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }

    config->tls13cipherSuitesSize = sizeof(ciphersuites13) / sizeof(uint16_t);
    return HITLS_SUCCESS;
}
#endif
static int32_t SetDefaultPointFormats(HITLS_Config *config)
{
    const uint8_t pointFormats[] = {HITLS_POINT_FORMAT_UNCOMPRESSED};
    uint32_t size = sizeof(pointFormats);

    BSL_SAL_FREE(config->pointFormats);
    config->pointFormats = BSL_SAL_Dump(pointFormats, size);
    if (config->pointFormats == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16565, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Dump fail", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    config->pointFormatsSize = size / sizeof(uint8_t);

    return HITLS_SUCCESS;
}

static void BasicInitConfig(HITLS_Config *config)
{
    config->isSupportExtendedMasterSecret = false;
    config->emptyRecordsNum = HITLS_MAX_EMPTY_RECORDS;
#ifdef HITLS_TLS_PROTO_TLS13
    config->isMiddleBoxCompat = true;
#endif
#ifdef HITLS_TLS_FEATURE_MODE
    config->modeSupport = HITLS_MODE_AUTO_RETRY;
#endif
#ifdef HITLS_TLS_FEATURE_MAX_SEND_FRAGMENT
    config->maxSendFragment = HITLS_MAX_SEND_FRAGMENT_DEFAULT;
#endif
#ifdef HITLS_TLS_FEATURE_REC_INBUFFER_SIZE
    config->recInbufferSize = 0;
#endif
#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
    config->allowLegacyRenegotiate = false;
#endif
#ifdef HITLS_TLS_FEATURE_ETM
    config->isEncryptThenMac = true;
#endif
}
static void InitConfig(HITLS_Config *config)
{
    BasicInitConfig(config);
#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
    config->allowClientRenegotiate = false;
    config->isSupportRenegotiation = false;
#endif
#if defined(HITLS_TLS_FEATURE_RENEGOTIATION) && defined(HITLS_TLS_FEATURE_SESSION)
    config->isResumptionOnRenego = false;
#endif
#ifdef HITLS_TLS_SUITE_KX_RSA
    config->needCheckPmsVersion = false;
#endif
    config->readAhead = 0;
#ifdef HITLS_TLS_CONFIG_KEY_USAGE
    config->needCheckKeyUsage = true;
#endif
#ifdef HITLS_TLS_CONFIG_MANUAL_DH
    config->isSupportDhAuto = false;
#endif
#ifdef HITLS_TLS_FEATURE_FLIGHT
    config->isFlightTransmitEnable = true;
#endif
#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
    config->isSupportDtlsCookieExchange = false;
#endif
#ifdef HITLS_TLS_FEATURE_CERT_MODE_VERIFY_PEER
    config->isSupportVerifyNone = false;
#endif
#ifdef HITLS_TLS_FEATURE_CERT_MODE_CLIENT_VERIFY
    config->isSupportClientVerify = false;
    config->isSupportNoClientCert = true;
    config->isSupportClientOnceVerify = false;
#endif
#ifdef HITLS_TLS_FEATURE_PHA
    config->isSupportPostHandshakeAuth = false;
#endif
#ifdef HITLS_TLS_PROTO_CLOSE_STATE
    config->isQuietShutdown = false;
#endif
    config->maxCertList = HITLS_MAX_CERT_LIST_DEFAULT;
    config->isKeepPeerCert = true;
#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
    config->isSupportSessionTicket = true;
    config->ticketNums = HITLS_TLS13_TICKET_NUM_DEFAULT;
#endif
#ifdef HITLS_TLS_FEATURE_SECURITY
    // Default security settings
    SECURITY_SetDefault(config);
#endif
}

static int32_t DefaultCipherSuitesByVersion(uint16_t version, HITLS_Config *config)
{
    const uint16_t *groups = g_tls12CipherSuites;
    uint32_t size = sizeof(g_tls12CipherSuites);
    switch (version) {
#ifdef HITLS_TLS_PROTO_TLCP11
        case HITLS_VERSION_TLCP_DTLCP11:
            groups = g_tlcpCipherSuites;
            size = sizeof(g_tlcpCipherSuites);
            break;
#endif
        default:
            break;
    }
    return SetDefaultCipherSuite(config, groups, size);
}

int32_t DefaultConfig(HITLS_Lib_Ctx *libCtx, const char *attrName, uint16_t version, HITLS_Config *config)
{
    // Static settings
    config->minVersion = version;
    config->maxVersion = version;
    config->libCtx = libCtx;
    config->attrName = attrName;

    InitConfig(config);

    int32_t ret = DefaultCipherSuitesByVersion(version, config);
    if (ret != HITLS_SUCCESS) {
        CFG_CleanConfig(config);
        return HITLS_MEMALLOC_FAIL;
    }
#ifdef HITLS_TLS_PROTO_TLS13
    /* Configure the TLS1.3 cipher suite for all TLS versions */
    ret = SetTLS13DefaultCipherSuites(config);
    if (ret != HITLS_SUCCESS) {
        CFG_CleanConfig(config);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_MEMALLOC_FAIL, BINLOG_ID16570, "SetCipherSuites fail");
    }
#endif
    if (ConfigLoadSignatureSchemeInfo(config) != HITLS_SUCCESS) {
        CFG_CleanConfig(config);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_MEMALLOC_FAIL, BINLOG_ID16571, "SetSignHashAlg fail");
    }

    if ((SetDefaultPointFormats(config) != HITLS_SUCCESS) ||
        (ConfigLoadGroupInfo(config) != HITLS_SUCCESS)) {
        CFG_CleanConfig(config);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_MEMALLOC_FAIL, BINLOG_ID16572, "SetPointFormat or LoadGroup fail");
    }

    if (SAL_CERT_MgrIsEnable()) {
        config->certMgrCtx = SAL_CERT_MgrCtxProviderNew(libCtx, attrName);
        if (config->certMgrCtx == NULL) {
            CFG_CleanConfig(config);
            return RETURN_ERROR_NUMBER_PROCESS(HITLS_MEMALLOC_FAIL, BINLOG_ID16573, "certMgrCtx new fail");
        }
    }
#ifdef HITLS_TLS_FEATURE_SESSION
    config->sessMgr = SESSMGR_New(config->libCtx);
    if (config->sessMgr == NULL) {
        CFG_CleanConfig(config);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_MEMALLOC_FAIL, BINLOG_ID16574, "sessMgr new fail");
    }
#endif
    return HITLS_SUCCESS;
}
#ifdef HITLS_TLS_PROTO_TLS13
int32_t DefaultTLS13Config(HITLS_Config *config)
{
    // Static settings
    config->minVersion = HITLS_VERSION_TLS13;
    config->maxVersion = HITLS_VERSION_TLS13;
    InitConfig(config);

    // Dynamic setting. By default, only the cipher suite and point format are set. For details, see the comments in
    // HITLS_CFG_NewDTLS12Config.
    if ((SetTLS13DefaultCipherSuites(config) != HITLS_SUCCESS) ||
        (SetDefaultPointFormats(config) != HITLS_SUCCESS) ||
        (ConfigLoadGroupInfo(config) != HITLS_SUCCESS) ||
        (ConfigLoadSignatureSchemeInfo(config) != HITLS_SUCCESS)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16575, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Failed to set the default configuration of tls13", 0, 0, 0, 0);
        CFG_CleanConfig(config);
        return HITLS_MEMALLOC_FAIL;
    }

    config->keyExchMode = TLS13_KE_MODE_PSK_WITH_DHE;

    if (SAL_CERT_MgrIsEnable()) {
        config->certMgrCtx = SAL_CERT_MgrCtxProviderNew(LIBCTX_FROM_CONFIG(config), ATTRIBUTE_FROM_CONFIG(config));
        if (config->certMgrCtx == NULL) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16576, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "certMgrCtx new fail", 0, 0, 0, 0);
            CFG_CleanConfig(config);
            return HITLS_MEMALLOC_FAIL;
        }
    }
#ifdef HITLS_TLS_FEATURE_SESSION
    config->sessMgr = SESSMGR_New(config->libCtx);
    if (config->sessMgr == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16577, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "sessMgr new fail", 0, 0, 0, 0);
        CFG_CleanConfig(config);
        return HITLS_MEMALLOC_FAIL;
    }
#endif
    return HITLS_SUCCESS;
}
#endif
#ifdef HITLS_TLS_CONFIG_VERSION
static int32_t SetDefaultTlsAllCipherSuites(HITLS_Config *config)
{
    int32_t ret = HITLS_SUCCESS;
#ifdef HITLS_TLS_PROTO_TLS13
    ret = SetTLS13DefaultCipherSuites(config);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#endif

    uint32_t tls12CipherSuitesLen = sizeof(g_tls12CipherSuites) / sizeof(uint16_t);
    uint32_t tlcpCipherSuitesLen = 0;
#ifdef HITLS_TLS_PROTO_TLCP11
    tlcpCipherSuitesLen = sizeof(g_tlcpCipherSuites) / sizeof(uint16_t);
#endif
    uint32_t cipherSuitesLen = tls12CipherSuitesLen + tlcpCipherSuitesLen;
    uint16_t *cipherSuites = BSL_SAL_Calloc(1u, cipherSuitesLen * sizeof(uint16_t));
    if (cipherSuites == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
#ifdef HITLS_TLS_PROTO_TLCP11
    (void)memcpy_s(cipherSuites, cipherSuitesLen * sizeof(uint16_t), g_tlcpCipherSuites, sizeof(g_tlcpCipherSuites));
#endif
    (void)memcpy_s(cipherSuites + tlcpCipherSuitesLen, (cipherSuitesLen - tlcpCipherSuitesLen) * sizeof(uint16_t),
                   g_tls12CipherSuites, sizeof(g_tls12CipherSuites));
    ret = SetDefaultCipherSuite(config, cipherSuites, cipherSuitesLen * sizeof(uint16_t));
    BSL_SAL_FREE(cipherSuites);
    return ret;
}
#endif
#ifdef HITLS_TLS_CONFIG_VERSION
int32_t DefaultTlsAllConfig(HITLS_Config *config)
{
    ChangeMinMaxVersion(config->version, config->originVersionMask, &config->minVersion, &config->maxVersion);

    InitConfig(config);

    // Dynamic setting
    if ((SetDefaultTlsAllCipherSuites(config) != HITLS_SUCCESS) ||
        (SetDefaultPointFormats(config) != HITLS_SUCCESS) ||
        (ConfigLoadGroupInfo(config) != HITLS_SUCCESS) ||
        (ConfigLoadSignatureSchemeInfo(config) != HITLS_SUCCESS)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16578, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Failed to set the default configuration of tls_all", 0, 0, 0, 0);
        CFG_CleanConfig(config);
        return HITLS_MEMALLOC_FAIL;
    }

    config->keyExchMode = TLS13_KE_MODE_PSK_WITH_DHE;

    if (SAL_CERT_MgrIsEnable()) {
        config->certMgrCtx = SAL_CERT_MgrCtxProviderNew(LIBCTX_FROM_CONFIG(config), ATTRIBUTE_FROM_CONFIG(config));
        if (config->certMgrCtx == NULL) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16579, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "MgrCtx new fail", 0, 0, 0, 0);
            CFG_CleanConfig(config);
            return HITLS_MEMALLOC_FAIL;
        }
    }
#ifdef HITLS_TLS_FEATURE_SESSION
    config->sessMgr = SESSMGR_New(config->libCtx);
    if (config->sessMgr == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16580, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "sessMgr new fail", 0, 0, 0, 0);
        CFG_CleanConfig(config);
        return HITLS_MEMALLOC_FAIL;
    }
#endif
    return HITLS_SUCCESS;
}
#endif
#ifdef HITLS_TLS_PROTO_DTLS
static int32_t SetDefaultDtlsAllCipherSuites(HITLS_Config *config)
{
    const uint16_t cipherSuites[] = {
        /* DTLS1.2 */
        HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, HITLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        HITLS_DHE_DSS_WITH_AES_256_GCM_SHA384, HITLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
        HITLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, HITLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        HITLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256, HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        HITLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, HITLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
        HITLS_DHE_RSA_WITH_AES_128_GCM_SHA256,

        /* The DTLS1.0 cipher suite is not supported */
    };

    return SetDefaultCipherSuite(config, cipherSuites, sizeof(cipherSuites));
}

int32_t DefaultDtlsAllConfig(HITLS_Config *config)
{
    // Static settings
    config->minVersion =
        HITLS_VERSION_DTLS12;  // does not support DTLS 1.0. Therefore, the minimum version number is set to DTLS 1.2.
    config->maxVersion = HITLS_VERSION_DTLS12;
    InitConfig(config);

    // Dynamic setting
    if ((SetDefaultDtlsAllCipherSuites(config) != HITLS_SUCCESS) ||
        (SetDefaultPointFormats(config) != HITLS_SUCCESS) ||
        (ConfigLoadGroupInfo(config) != HITLS_SUCCESS) ||
        (ConfigLoadSignatureSchemeInfo(config) != HITLS_SUCCESS)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16581, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "set default config fail", 0, 0, 0, 0);
        CFG_CleanConfig(config);
        return HITLS_MEMALLOC_FAIL;
    }

    if (SAL_CERT_MgrIsEnable()) {
        config->certMgrCtx = SAL_CERT_MgrCtxProviderNew(LIBCTX_FROM_CONFIG(config), ATTRIBUTE_FROM_CONFIG(config));
        if (config->certMgrCtx == NULL) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16582, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "MgrCtxNew fail", 0, 0, 0, 0);
            CFG_CleanConfig(config);
            return HITLS_MEMALLOC_FAIL;
        }
    }
#ifdef HITLS_TLS_FEATURE_SESSION
    config->sessMgr = SESSMGR_New(config->libCtx);
    if (config->sessMgr == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16583, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "SESSMGR_New fail", 0, 0, 0, 0);
        CFG_CleanConfig(config);
        return HITLS_MEMALLOC_FAIL;
    }
#endif
    return HITLS_SUCCESS;
}
#endif
