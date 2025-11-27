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
#ifdef HITLS_TLS_FEATURE_SECURITY
#include <stdint.h>
#include "securec.h"
#include "bsl_err_internal.h"
#include "tls_binlog_id.h"
#include "hitls_error.h"
#include "hitls_security.h"
#include "tls.h"
#include "security.h"
#include "config_type.h"
/* Number of security bits corresponding to the security level */
static const int32_t g_minBits[] = {HITLS_SECURITY_LEVEL_ONE_SECBITS,
    HITLS_SECURITY_LEVEL_TWO_SECBITS,
    HITLS_SECURITY_LEVEL_THREE_SECBITS,
    HITLS_SECURITY_LEVEL_FOUR_SECBITS,
    HITLS_SECURITY_LEVEL_FIVE_SECBITS};
int32_t SECURITY_GetSecbits(int32_t level)
{
    if (level <= HITLS_SECURITY_LEVEL_MIN) {
        return 0;
    } else {
        level = (level > HITLS_SECURITY_LEVEL_MAX) ? HITLS_SECURITY_LEVEL_MAX : level;
    }
    return g_minBits[level - 1];
}

static int32_t CheckCipherSuite(void *other, int32_t level)
{
    if (other == NULL) {
        return SECURITY_ERR;
    }

    CipherSuiteInfo *info = (CipherSuiteInfo *)other;
    int32_t minBits = SECURITY_GetSecbits(level);
    if (info->strengthBits < minBits) {
        return SECURITY_ERR;
    }
    /* The anonymous cipher suite is insecure. */
    if (info->minVersion != HITLS_VERSION_TLS13 && info->authAlg == HITLS_AUTH_NULL) {
        return SECURITY_ERR;
    }
    /* The level is greater than or equal to 1, and the export cipher suite and the MD5 algorithm for calculating MAC
     * addresses are prohibited. Currently, the export cipher suite and the MD5 algorithm for calculating MAC addresses
     * are not supported. Therefore, the check is not required. */
    /* The RC4 stream encryption algorithm is not supported because the RC4 stream encryption algorithm is not
     * supported. */
    /* Forbidding non-forward security cipher suites when Level is greater than or equal to 3. */
    if ((level >= HITLS_SECURITY_LEVEL_THREE) &&
        (info->kxAlg != HITLS_KEY_EXCH_DHE && info->kxAlg != HITLS_KEY_EXCH_ECDHE &&
            info->kxAlg != HITLS_KEY_EXCH_DHE_PSK && info->kxAlg != HITLS_KEY_EXCH_ECDHE_PSK &&
            info->minVersion != HITLS_VERSION_TLS13)) {
        return SECURITY_ERR;
    }
    /* If the level is greater than or equal to 4, disable the SHA1 algorithm. */

    if ((level >= HITLS_SECURITY_LEVEL_FOUR) && (info->macAlg == HITLS_MAC_1)) {
        return SECURITY_ERR;
    }

    return SECURITY_SUCCESS;
}

static int32_t CheckVersion(int32_t id, int32_t level)
{
    /* Check the DTLS version. */
    if (IS_DTLS_VERSION((uint32_t)id)) {
        /* The level is greater than or equal to 1, and DTLS1.0 cannot be used. */
        if ((level >= HITLS_SECURITY_LEVEL_ONE) && ((uint32_t)id > HITLS_VERSION_DTLS12)) {
            return SECURITY_ERR;
        }
        return SECURITY_SUCCESS;
    }
#ifdef HITLS_TLS_PROTO_TLCP11
    /* If the level is greater than or equal to 1, SSL2.0, SSL3.0, TLS1.0, and TLS1.1 cannot be used. */
    if ((level >= HITLS_SECURITY_LEVEL_ONE) && ((uint32_t)id < HITLS_VERSION_TLS12) &&
        ((uint32_t)id != HITLS_VERSION_TLCP_DTLCP11)) {
        return SECURITY_ERR;
    }
    /* Level is greater than or equal to 4 and TLCP1.1 is prohibited because the security strength of the signature
     * algorithm CERT_SIG_SCHEME_SM2_SM3 is 128 bits. */
    if ((level >= HITLS_SECURITY_LEVEL_FOUR) && ((uint32_t)id == HITLS_VERSION_TLCP_DTLCP11)) {
        return SECURITY_ERR;
    }
#else
    /* If the level is greater than or equal to 1, SSL2.0, SSL3.0, TLS1.0, and TLS1.1 cannot be used. */
    if ((level >= HITLS_SECURITY_LEVEL_ONE) && ((uint32_t)id < HITLS_VERSION_TLS12)) {
        return SECURITY_ERR;
    }
#endif
    return SECURITY_SUCCESS;
}

static int32_t CheckSessionTicket(int32_t level)
{
    /* If the level is greater than or equal to 3, the session ticket is prohibited. */
    if (level >= HITLS_SECURITY_LEVEL_THREE) {
        return SECURITY_ERR;
    }
    return SECURITY_SUCCESS;
}

/* Default callback function */
int32_t SECURITY_DefaultCb(const HITLS_Ctx *ctx, const HITLS_Config *config, int32_t option, int32_t bits, int32_t id,
    void *other, void *exData)
{
    (void)exData;
    int32_t level = HITLS_DEFAULT_SECURITY_LEVEL;

    if (config != NULL) {
        (void)HITLS_CFG_GetSecurityLevel(config, &level);
    } else if (ctx != NULL) {
        (void)HITLS_GetSecurityLevel(ctx, &level);
    } else {
        return SECURITY_ERR;
    }
    /* No restrictions are imposed when Level is 0. */
    if (level <= HITLS_SECURITY_LEVEL_MIN) {
        return SECURITY_SUCCESS;
    }

    if (level > HITLS_SECURITY_LEVEL_MAX) {
        level = HITLS_SECURITY_LEVEL_MAX;
    }

    /* Check the number of security bits. */
    int32_t minBits = SECURITY_GetSecbits(level);
    switch (option) {
        case HITLS_SECURITY_SECOP_VERSION:
            /* Check the version. */
            return CheckVersion(id, level);
        case HITLS_SECURITY_SECOP_CIPHER_SUPPORTED:
        case HITLS_SECURITY_SECOP_CIPHER_SHARED:
        case HITLS_SECURITY_SECOP_CIPHER_CHECK:
            /* Check the algorithm suite. */
            return CheckCipherSuite(other, level);
        case HITLS_SECURITY_SECOP_TICKET:
            /* Check the session ticket. */
            return CheckSessionTicket(level);
        default:
            return (bits < minBits) ? SECURITY_ERR : SECURITY_SUCCESS;
    }
}

void SECURITY_SetDefault(HITLS_Config *config)
{
    if (config == NULL) {
        return;
    }
    /*  Default security settings. Set the default security level and default security callback function. */
    config->securityLevel = HITLS_DEFAULT_SECURITY_LEVEL;
    config->securityCb = SECURITY_DefaultCb;
    return;
}

int32_t SECURITY_CfgCheck(const HITLS_Config *config, int32_t option, int32_t bits, int32_t id, void *other)
{
    if (config == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16698, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "config null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    if (config->securityCb == NULL) {
        /* The security callback function is empty and does not need to be checked. */
        return SECURITY_SUCCESS;
    }
    const TLS_SigSchemeInfo *schemeInfo = NULL;
    const TLS_GroupInfo *groupInfo = NULL;
    uint16_t ianaId;
    switch (option) {
        case HITLS_SECURITY_SECOP_SIGALG_SUPPORTED:
        case HITLS_SECURITY_SECOP_SIGALG_SHARED:
        case HITLS_SECURITY_SECOP_SIGALG_CHECK:
            schemeInfo = ConfigGetSignatureSchemeInfo(config, (uint16_t)id);
            if (schemeInfo != NULL) {
                ianaId = schemeInfo->signatureScheme;
                return config->securityCb(NULL, config, option, schemeInfo->secBits, schemeInfo->hashAlgId,
                    &ianaId, config->securityExData);
            }
            ianaId = (uint16_t)id;
            return config->securityCb(NULL, config, option, 0, 0, &ianaId, config->securityExData);
        case HITLS_SECURITY_SECOP_CURVE_SUPPORTED:
        case HITLS_SECURITY_SECOP_CURVE_SHARED:
        case HITLS_SECURITY_SECOP_CURVE_CHECK:
            groupInfo = ConfigGetGroupInfo(config, (uint16_t)id);
            if (groupInfo != NULL) {
                ianaId = groupInfo->groupId;
                return config->securityCb(NULL, config, option, groupInfo->secBits, groupInfo->paraId,
                    &ianaId, config->securityExData);
            }
            ianaId = (uint16_t)id;
            return config->securityCb(NULL, config, option, 0, 0, &ianaId, config->securityExData);
        default:
            break;
    }
    return config->securityCb(NULL, config, option, bits, id, other, config->securityExData);
}
int32_t SECURITY_SslCheck(const HITLS_Ctx *ctx, int32_t option, int32_t bits, int32_t id, void *other)
{
    if (ctx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16699, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "ctx null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return SECURITY_CfgCheck(&(ctx->config.tlsConfig), option, bits, id, other);
}
#endif /* HITLS_TLS_FEATURE_SECURITY */