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

#include <stdbool.h>
#include <stdint.h>
#include "bsl_err_internal.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "hitls_crypt_type.h"
#include "hitls_cert_type.h"
#include "hitls_error.h"
#include "hitls_config.h"
#include "tls.h"
#include "tls_config.h"
#include "cipher_suite.h"

static bool IsSignAlgValid(uint16_t signAlg, uint16_t version)
{
    uint32_t listLen = 0;
#ifndef HITLS_NO_TLCP11
    const SignSchemeInfo *signSchemeList = (version != HITLS_VERSION_TLCP11) ?
        CFG_GetSignSchemeList(&listLen) :
        CFG_GetSignSchemeListTlcp(&listLen);
#else
    (void)version;
    const SignSchemeInfo *signSchemeList = CFG_GetSignSchemeList(&listLen);
#endif

    for (uint32_t i = 0; i < listLen; i++) {
        if (signSchemeList[i].scheme == signAlg) {
            return true;
        }
    }

    return false;
}

static bool CFG_IsValidVersion(uint16_t version)
{
    switch (version) {
        case HITLS_VERSION_TLS12:
        case HITLS_VERSION_TLS13:
        case HITLS_VERSION_DTLS12:
        case HITLS_VERSION_TLCP11:
            return true;
        default:
            break;
    }
    return false;
}

static bool  HaveMatchSignAlg(HITLS_AuthAlgo authAlg, const uint16_t *signatureAlgorithms,
    uint32_t signatureAlgorithmsSize, uint16_t version)
{
    HITLS_SignAlgo signAlg = HITLS_SIGN_BUTT;
    HITLS_HashAlgo hashAlg = HITLS_HASH_BUTT;

    /** Traverse the signature algorithms. If the matching is successful, return true */
    for (uint32_t i = 0u; i < signatureAlgorithmsSize; i++) {
        if (CFG_GetSignParamBySchemes(version, signatureAlgorithms[i], &signAlg, &hashAlg)) {
            if (((signAlg == HITLS_SIGN_RSA_PKCS1_V15) || (signAlg == HITLS_SIGN_RSA_PSS_RSAE)) &&
                (authAlg == HITLS_AUTH_RSA)) {
                return true;
            }

            if (((signAlg == HITLS_SIGN_ECDSA) || (signAlg == HITLS_SIGN_ED25519)) &&
                (authAlg == HITLS_AUTH_ECDSA)) {
                return true;
            }

            if (signAlg == HITLS_SIGN_DSA && authAlg == HITLS_AUTH_DSS) {
                return true;
            }

            if (signAlg == HITLS_SIGN_SM2 && authAlg == HITLS_AUTH_SM2) {
                return true;
            }
        }
    }

    return false;
}

static int32_t CheckPointFormats(const TLS_Config *config)
{
    if ((config->pointFormats == NULL) || (config->pointFormatsSize == 0)) {
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_SET);
        return HITLS_CONFIG_INVALID_SET;
    }

    /** Currently, only one point format is supported */
    if ((config->pointFormatsSize != 1) || (config->pointFormats[0] != HITLS_POINT_FORMAT_UNCOMPRESSED)) {
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_UNSUPPORT_POINT_FORMATS);
        return HITLS_CONFIG_UNSUPPORT_POINT_FORMATS;
    }

    return HITLS_SUCCESS;
}

static bool IsCipherSuiteValid(const TLS_Config *config, uint16_t cipherSuite)
{
    if ((CFG_CheckCipherSuiteSupported(cipherSuite) != true) ||
        (CFG_CheckCipherSuiteVersion(cipherSuite, config->minVersion, config->maxVersion) != true)) {
        /* The cipher suite must match the configured version */
        return false;
    }
    return true;
}

static int32_t CheckSign(const TLS_Config *config)
{
    uint16_t *signAlgorithms = config->signAlgorithms;
    uint32_t signAlgorithmsSize = config->signAlgorithmsSize;
    /** If the signature algorithm is empty, the default signature algorithm in the cipher suite is used and no further
     * check is required */
    if ((signAlgorithms == NULL) || (signAlgorithmsSize == 0)) {
        return HITLS_SUCCESS;
    }

    /** Check the validity of the signature algorithms one by one */
    for (uint32_t i = 0; i < signAlgorithmsSize; i++) {
        if (IsSignAlgValid(signAlgorithms[i], config->maxVersion) == false) {
            BSL_ERR_PUSH_ERROR(HITLS_CONFIG_UNSUPPORT_SIGNATURE_ALGORITHM);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15779, BSL_LOG_LEVEL_FATAL, BSL_LOG_BINLOG_TYPE_RUN,
                "Unsupported signature algorithms: 0x%04x.", signAlgorithms[i], 0, 0, 0);
            return HITLS_CONFIG_UNSUPPORT_SIGNATURE_ALGORITHM;
        }
    }

    /**
        In this case, only the 1.3 cipher suite is configured, or only TLS1.3 is supported.
        The authentication algorithm is not specified in the TLS 1.3 cipher suite and therefore does not need to be
       checked.
    */
    if (config->cipherSuitesSize == 0 || ((config->minVersion == HITLS_VERSION_TLS13) &&
        (config->maxVersion == HITLS_VERSION_TLS13))) {
        return HITLS_SUCCESS;
    }

    /** Check the compatibility between the signature algorithm and the cipher suite */
    for (uint32_t i = 0; i < config->cipherSuitesSize; i++) {
        CipherSuiteInfo info = {0};
        if (IsCipherSuiteValid(config, config->cipherSuites[i]) == false) {
            continue;
        }

        (void)CFG_GetCipherSuiteInfo(config->cipherSuites[i], &info);

        /** PSK does not require the signature algorithm */
        if ((info.kxAlg == HITLS_KEY_EXCH_PSK) || (info.kxAlg == HITLS_KEY_EXCH_DHE_PSK) ||
            (info.kxAlg == HITLS_KEY_EXCH_ECDHE_PSK)) {
            return HITLS_SUCCESS;
        }

        /* Anon does not require the signature algorithm */
        if (info.authAlg == HITLS_AUTH_NULL) {
            return HITLS_SUCCESS;
        }

        /** Check whether a signature algorithm matching the cipher suite exists */
        if (HaveMatchSignAlg(info.authAlg, signAlgorithms, signAlgorithmsSize, config->maxVersion)) {
            return HITLS_SUCCESS;
        }
    }
    BSL_ERR_PUSH_ERROR(HITLS_CONFIG_NO_SUITABLE_SIGNATURE_ALGORITHM);
    return HITLS_CONFIG_NO_SUITABLE_SIGNATURE_ALGORITHM;
}

static bool IsHaveEccCipherSuite(const TLS_Config *config)
{
    for (uint32_t i = 0u; i < config->cipherSuitesSize; i++) {
        CipherSuiteInfo info = {0};
        if (IsCipherSuiteValid(config, config->cipherSuites[i]) == false) {
            continue;
        }
        (void)CFG_GetCipherSuiteInfo(config->cipherSuites[i], &info);

        /* The ECC cipher suite exists */
        if ((info.authAlg == HITLS_AUTH_ECDSA) ||
            (info.kxAlg == HITLS_KEY_EXCH_ECDHE) ||
            (info.kxAlg == HITLS_KEY_EXCH_ECDH) ||
            (info.kxAlg == HITLS_KEY_EXCH_ECDHE_PSK)) {
            return true;
        }
    }

    return false;
}

static int32_t CheckGroup(const TLS_Config *config)
{
    if (config->groupsSize == 0u) {
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_NO_GROUPS);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15780, BSL_LOG_LEVEL_WARN, BSL_LOG_BINLOG_TYPE_RUN,
            "Set ecdhe cipher with no group id", 0, 0, 0, 0);
        return HITLS_CONFIG_NO_GROUPS;
    }

    return HITLS_SUCCESS;
}

int32_t CFG_CheckVersion(uint16_t minVersion, uint16_t maxVersion)
{
    if ((CFG_IsValidVersion(minVersion) == false) || (CFG_IsValidVersion(maxVersion) == false) ||
        (IS_DTLS_VERSION(minVersion) != IS_DTLS_VERSION(maxVersion))) {
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_VERSION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15781, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Config max version [0x%x] or min version [0x%x] is invalid.", maxVersion, minVersion, 0, 0);
        return HITLS_CONFIG_INVALID_VERSION;
    }

    if ((IS_DTLS_VERSION(maxVersion) && (maxVersion > minVersion))) {
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_VERSION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15782, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Config max version [0x%x] or min version [0x%x] is invalid.", maxVersion, minVersion, 0, 0);
        return HITLS_CONFIG_INVALID_VERSION;
    }

    if ((IS_DTLS_VERSION(maxVersion) == false) && (maxVersion < minVersion)) {
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_VERSION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15783, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Config max version [0x%x] or min version [0x%x] is invalid.", maxVersion, minVersion, 0, 0);
        return HITLS_CONFIG_INVALID_VERSION;
    }
#ifndef HITLS_NO_TLCP11
    if (minVersion == HITLS_VERSION_TLCP11 || maxVersion == HITLS_VERSION_TLCP11) {
        if (minVersion != maxVersion) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15331, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Config max version [0x%x] or min version [0x%x] is invalid.", maxVersion,
                minVersion, 0, 0);
            return HITLS_CONFIG_INVALID_VERSION;
        }
    }
#endif
    return HITLS_SUCCESS;
}

int32_t CFG_CheckConfig(const TLS_Config *config)
{
    int32_t ret;

    /** The check of the cipher suite is checked during setting. The algorithm suite needs to be sorted and the memory
     * overhead increases. Therefore, the algorithm suite is still placed in the Set interface */
    if (config->cipherSuitesSize == 0 && config->tls13cipherSuitesSize == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_SET);
        return HITLS_CONFIG_INVALID_SET;
    }

    /* The checkpoint format and group are required only when the ecdhe cipher suite is available */
    if (IsHaveEccCipherSuite(config)) {
        ret = CheckPointFormats(config);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }

        ret = CheckGroup(config);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

    ret = CheckSign(config);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    return HITLS_SUCCESS;
}
