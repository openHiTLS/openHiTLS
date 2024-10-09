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

#include "bsl_sal.h"
#include "hitls_type.h"
#include "hitls_crypt_type.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "tls_config.h"
#include "config.h"
#include "cipher_suite.h"
#include "session_mgr.h"
#include "security.h"

#ifndef HITLS_NO_TLCP11
static int32_t SetTLCPDefaultCipherSuites(HITLS_Config *config)
{
    const uint16_t cipherSuites[] = {
        HITLS_ECDHE_SM4_CBC_SM3,
        HITLS_ECC_SM4_CBC_SM3,
    };
    uint32_t size = sizeof(cipherSuites);

    config->cipherSuites = BSL_SAL_Dump(cipherSuites, size);
    if (config->cipherSuites == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }

    config->cipherSuitesSize = size / sizeof(uint16_t);
    return HITLS_SUCCESS;
}
#endif

static int32_t SetTls12DefaultCipherSuites(HITLS_Config *config)
{
    const uint16_t ciphersuites12[] = {
        HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        HITLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        HITLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
        HITLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
        HITLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        HITLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        HITLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        HITLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        HITLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
        HITLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
        HITLS_ECDHE_ECDSA_WITH_AES_128_CCM,
        HITLS_ECDHE_ECDSA_WITH_AES_256_CCM,
        HITLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
        HITLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
        HITLS_DHE_RSA_WITH_AES_128_CCM,
        HITLS_DHE_RSA_WITH_AES_256_CCM,
        HITLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
        HITLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
        HITLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        HITLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        HITLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
        HITLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
        HITLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        HITLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        HITLS_DHE_RSA_WITH_AES_256_CBC_SHA,
        HITLS_DHE_DSS_WITH_AES_256_CBC_SHA,
        HITLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        HITLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        HITLS_DHE_RSA_WITH_AES_128_CBC_SHA,
        HITLS_DHE_DSS_WITH_AES_128_CBC_SHA,
        HITLS_RSA_WITH_AES_256_GCM_SHA384,
        HITLS_RSA_WITH_AES_128_GCM_SHA256,
        HITLS_RSA_WITH_AES_256_CBC_SHA256,
        HITLS_RSA_WITH_AES_128_CBC_SHA256,
        HITLS_RSA_WITH_AES_256_CBC_SHA,
        HITLS_RSA_WITH_AES_128_CBC_SHA,
    };
    uint32_t size = sizeof(ciphersuites12);

    config->cipherSuites = BSL_SAL_Dump(ciphersuites12, size);
    if (config->cipherSuites == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }

    config->cipherSuitesSize = size / sizeof(uint16_t);
    return HITLS_SUCCESS;
}

static int32_t SetTLS13DefaultCipherSuites(HITLS_Config *config)
{
    const uint16_t ciphersuites13[] = {
        HITLS_AES_256_GCM_SHA384,
        HITLS_CHACHA20_POLY1305_SHA256,
        HITLS_AES_128_GCM_SHA256,
    };

    config->tls13CipherSuites = BSL_SAL_Dump(ciphersuites13, sizeof(ciphersuites13));
    if (config->tls13CipherSuites == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }

    config->tls13cipherSuitesSize = sizeof(ciphersuites13) / sizeof(uint16_t);
    return HITLS_SUCCESS;
}

static int32_t SetDefaultPointFormats(HITLS_Config *config)
{
    const uint8_t pointFormats[] = {HITLS_POINT_FORMAT_UNCOMPRESSED};
    uint32_t size = sizeof(pointFormats);

    config->pointFormats = BSL_SAL_Dump(pointFormats, size);
    if (config->pointFormats == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
    config->pointFormatsSize = size / sizeof(uint8_t);

    return HITLS_SUCCESS;
}

static int32_t SetDefaultGroups(HITLS_Config *config)
{
    const uint16_t groupsTls[] = {
        HITLS_EC_GROUP_CURVE25519,
        HITLS_EC_GROUP_SECP521R1,
        HITLS_EC_GROUP_SECP384R1,
        HITLS_EC_GROUP_SECP256R1,
        HITLS_EC_GROUP_BRAINPOOLP512R1,
        HITLS_EC_GROUP_BRAINPOOLP384R1,
        HITLS_EC_GROUP_BRAINPOOLP256R1,
    };
    const uint16_t groupsTlcp[] = {
        HITLS_EC_GROUP_SM2,
    };

    uint32_t size = (config->maxVersion == HITLS_VERSION_TLCP11) ? sizeof(groupsTlcp) : sizeof(groupsTls);

    config->groups = BSL_SAL_Dump((config->maxVersion == HITLS_VERSION_TLCP11) ? groupsTlcp : groupsTls, size);
    if (config->groups == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
    config->groupsSize = size / sizeof(uint16_t);

    return HITLS_SUCCESS;
}

static int32_t SetDefaultTLS13Groups(HITLS_Config *config)
{
    /* rfc8446 4.2.7 Supported Groups */
    const uint16_t groupsTls[] = {
        HITLS_EC_GROUP_CURVE25519,
        HITLS_EC_GROUP_SECP521R1,
        HITLS_EC_GROUP_SECP384R1,
        HITLS_EC_GROUP_SECP256R1,
        HITLS_FF_DHE_2048,
        HITLS_FF_DHE_3072,
        HITLS_FF_DHE_4096,
        HITLS_FF_DHE_6144,
        HITLS_FF_DHE_8192,
    };

    config->groups = BSL_SAL_Dump(groupsTls, sizeof(groupsTls));
    if (config->groups == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
    config->groupsSize = sizeof(groupsTls) / sizeof(uint16_t);

    return HITLS_SUCCESS;
}

static int32_t SetDefaultSignHashAlg(HITLS_Config *config)
{
    uint32_t listLen = 0;
#ifndef HITLS_NO_TLCP11
    const SignSchemeInfo *signHashAlgList = (config->maxVersion != HITLS_VERSION_TLCP11) ?
        CFG_GetSignSchemeList(&listLen) :
        CFG_GetSignSchemeListTlcp(&listLen);
#else
    const SignSchemeInfo *signHashAlgList = CFG_GetSignSchemeList(&listLen);
#endif
    config->signAlgorithms = BSL_SAL_Calloc(1u, listLen * sizeof(uint16_t));
    if (config->signAlgorithms == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
    for (uint32_t i = 0; i < listLen; i++) {
        config->signAlgorithms[i] = signHashAlgList[i].scheme;
    }
    config->signAlgorithmsSize = listLen;

    return HITLS_SUCCESS;
}

static int32_t SetTLS13DefaultSignScheme(HITLS_Config *config)
{
    uint32_t listSize = 0;
    uint32_t validNum = 0;
    const SignSchemeInfo *signHashAlgList = CFG_GetSignSchemeList(&listSize);

    config->signAlgorithms = BSL_SAL_Calloc(listSize, sizeof(uint16_t));
    if (config->signAlgorithms == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
    for (uint32_t i = 0; i < listSize; i++) {
        /* rfc8446 4.2.3 These algorithms are deprecated as of
        TLS 1.3.  They MUST NOT be offered or negotiated by any
        implementation.  In particular, MD5 [SLOTH], SHA-224, and DSA
        MUST NOT be used. */
        if ((signHashAlgList[i].signAlg == HITLS_SIGN_DSA) || (signHashAlgList[i].hashAlg == HITLS_HASH_SHA1) ||
            (signHashAlgList[i].hashAlg == HITLS_HASH_SHA_224)) {
            continue;
        }
        config->signAlgorithms[validNum] = signHashAlgList[i].scheme;
        validNum++;
    }
    config->signAlgorithmsSize = validNum;

    return HITLS_SUCCESS;
}

static void InitConfig(HITLS_Config *config)
{
    config->isSupportRenegotiation = false;
    config->isResumptionOnRenego = false;
    if (config->maxVersion == HITLS_VERSION_TLCP11) {
        config->isSupportExtendMasterSecret = false;
        config->isSupportDhAuto = false;
    } else {
        config->isSupportExtendMasterSecret = true;
        config->isSupportDhAuto = true;
    }
    config->isSupportSessionTicket = true;
    config->isFlightTransmitEnable = false;
    config->needCheckKeyUsage = true;
    config->needCheckPmsVersion = false;

    /** Set the certificate verification mode */
    config->isSupportClientVerify = false;
    config->isSupportNoClientCert = false;
    config->isSupportPostHandshakeAuth = false;
    config->isSupportVerifyNone = false;
    config->isSupportClientOnceVerify = false;

    config->isQuietShutdown = false;

    config->ticketNums = HITLS_TLS13_TICKET_NUM_DEFAULT;

    config->maxCertList = HITLS_MAX_CERT_LIST_DEFAULT;

    // Default security settings
    SECURITY_SetDefault(config);
}

static int32_t DefaultCipherSuitesByVersion(uint16_t version, HITLS_Config *config)
{
    switch (version) {
#ifndef HITLS_NO_TLCP11
        case HITLS_VERSION_TLCP11:
            return SetTLCPDefaultCipherSuites(config);
#endif
        default:
            break;
    }
    return SetTls12DefaultCipherSuites(config);
}

int32_t DefaultConfig(uint16_t version, HITLS_Config *config)
{
    // Static settings
    config->minVersion = version;
    config->maxVersion = version;

    InitConfig(config);

    int32_t ret = DefaultCipherSuitesByVersion(version, config);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Configure the TLS1.3 cipher suite for all TLS versions */
    ret = SetTLS13DefaultCipherSuites(config);
    if (ret != HITLS_SUCCESS) {
        goto ERR;
    }

    if (SetDefaultSignHashAlg(config) != HITLS_SUCCESS) {
        goto ERR;
    }

    if ((SetDefaultPointFormats(config) != HITLS_SUCCESS) ||
        (SetDefaultGroups(config) != HITLS_SUCCESS)) {
        goto ERR;
    }

    if (SAL_CERT_MgrIsEnable()) {
        config->certMgrCtx = SAL_CERT_MgrCtxNew();
        if (config->certMgrCtx == NULL) {
            goto ERR;
        }
    }

    config->sessMgr = SESSMGR_New();
    if (config->sessMgr == NULL) {
        goto ERR;
    }
    return HITLS_SUCCESS;
ERR:
    CFG_CleanConfig(config);
    return HITLS_MEMALLOC_FAIL;
}

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
        (SetDefaultTLS13Groups(config) != HITLS_SUCCESS) ||
        (SetTLS13DefaultSignScheme(config) != HITLS_SUCCESS)) {
        CFG_CleanConfig(config);
        return HITLS_MEMALLOC_FAIL;
    }

    config->keyExchMode = TLS13_KE_MODE_PSK_WITH_DHE;

    if (SAL_CERT_MgrIsEnable()) {
        config->certMgrCtx = SAL_CERT_MgrCtxNew();
        if (config->certMgrCtx == NULL) {
            CFG_CleanConfig(config);
            return HITLS_MEMALLOC_FAIL;
        }
    }

    config->sessMgr = SESSMGR_New();
    if (config->sessMgr == NULL) {
        CFG_CleanConfig(config);
        return HITLS_MEMALLOC_FAIL;
    }

    return HITLS_SUCCESS;
}

static int32_t SetDefaultTlsAllCipherSuites(HITLS_Config *config)
{
    int32_t ret;
    ret = SetTLS13DefaultCipherSuites(config);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = SetTls12DefaultCipherSuites(config);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    return HITLS_SUCCESS;
}

int32_t DefaultTlsAllConfig(HITLS_Config *config)
{
    // Support full version
    config->minVersion = HITLS_VERSION_TLS12;
    config->maxVersion = HITLS_VERSION_TLS13;

    InitConfig(config);

    // Dynamic setting
    if ((SetDefaultTlsAllCipherSuites(config) != HITLS_SUCCESS) ||
        (SetDefaultPointFormats(config) != HITLS_SUCCESS) ||
        (SetDefaultGroups(config) != HITLS_SUCCESS) ||
        (SetDefaultSignHashAlg(config) != HITLS_SUCCESS)) {
        CFG_CleanConfig(config);
        return HITLS_MEMALLOC_FAIL;
    }

    config->keyExchMode = TLS13_KE_MODE_PSK_WITH_DHE;

    if (SAL_CERT_MgrIsEnable()) {
        config->certMgrCtx = SAL_CERT_MgrCtxNew();
        if (config->certMgrCtx == NULL) {
            CFG_CleanConfig(config);
            return HITLS_MEMALLOC_FAIL;
        }
    }

    config->sessMgr = SESSMGR_New();
    if (config->sessMgr == NULL) {
        CFG_CleanConfig(config);
        return HITLS_MEMALLOC_FAIL;
    }

    return HITLS_SUCCESS;
}

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
    uint32_t size = sizeof(cipherSuites);

    config->cipherSuites = BSL_SAL_Dump(cipherSuites, size);
    if (config->cipherSuites == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }

    config->cipherSuitesSize = size / sizeof(uint16_t);
    return HITLS_SUCCESS;
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
        (SetDefaultGroups(config) != HITLS_SUCCESS) ||
        (SetDefaultSignHashAlg(config) != HITLS_SUCCESS)) {
        CFG_CleanConfig(config);
        return HITLS_MEMALLOC_FAIL;
    }

    if (SAL_CERT_MgrIsEnable()) {
        config->certMgrCtx = SAL_CERT_MgrCtxNew();
        if (config->certMgrCtx == NULL) {
            CFG_CleanConfig(config);
            return HITLS_MEMALLOC_FAIL;
        }
    }

    config->sessMgr = SESSMGR_New();
    if (config->sessMgr == NULL) {
        CFG_CleanConfig(config);
        return HITLS_MEMALLOC_FAIL;
    }
    return HITLS_SUCCESS;
}