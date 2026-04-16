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

/* BEGIN_HEADER */

#include <string.h>
#include "hitls_config.h"
#include "hitls_error.h"
#include "hitls_crypt_type.h"
#include "cipher_suite.h"
#include "frame_tls.h"
#include "helper.h"

/* END_HEADER */

/** @
* @test SDV_TLS_RFC9150_CIPHER_INFO_TC001
* @title RFC 9150: query CipherSuiteInfo for TLS_SHA256_SHA256
* @precon nan
* @brief
* 1. When the suite is supported, call CFG_GetCipherSuiteInfo(HITLS_TLS_SHA256_SHA256).
* @expect
* 1. cipherType is HITLS_TLS13_INTEGRITY_CIPHER; key/IV/MAC lengths match RFC 9150 registration.
@ */
/* BEGIN_CASE */
void SDV_TLS_RFC9150_CIPHER_INFO_TC001(void)
{
    FRAME_Init();
    CipherSuiteInfo info = {0};

    if (!CFG_CheckCipherSuiteSupported(HITLS_TLS_SHA256_SHA256)) {
        goto EXIT;
    }

    ASSERT_EQ(CFG_GetCipherSuiteInfo(HITLS_TLS_SHA256_SHA256, &info), HITLS_SUCCESS);
    ASSERT_EQ(info.cipherSuite, HITLS_TLS_SHA256_SHA256);
    ASSERT_EQ(info.cipherType, HITLS_TLS13_INTEGRITY_CIPHER);
    ASSERT_EQ(info.cipherAlg, HITLS_CIPHER_NULL);
    ASSERT_EQ(info.macAlg, HITLS_MAC_256);
    ASSERT_EQ(info.hashAlg, HITLS_HASH_SHA_256);
    ASSERT_EQ(info.fixedIvLength, 32u);
    ASSERT_EQ(info.encKeyLen, 32u);
    ASSERT_EQ(info.macLen, 32u);
    ASSERT_EQ(info.minVersion, HITLS_VERSION_TLS13);
    ASSERT_EQ(info.maxVersion, HITLS_VERSION_TLS13);
    ASSERT_TRUE(strcmp(info.stdName, "TLS_SHA256_SHA256") == 0);

EXIT:
    return;
}
/* END_CASE */

/** @
* @test SDV_TLS_RFC9150_CIPHER_INFO_TC002
* @title RFC 9150: query CipherSuiteInfo for TLS_SHA384_SHA384
* @precon nan
* @brief
* 1. When the suite is supported, call CFG_GetCipherSuiteInfo(HITLS_TLS_SHA384_SHA384).
* @expect
* 1. cipherType is HITLS_TLS13_INTEGRITY_CIPHER; key/IV/MAC lengths match RFC 9150 registration.
@ */
/* BEGIN_CASE */
void SDV_TLS_RFC9150_CIPHER_INFO_TC002(void)
{
    FRAME_Init();
    CipherSuiteInfo info = {0};

    if (!CFG_CheckCipherSuiteSupported(HITLS_TLS_SHA384_SHA384)) {
        goto EXIT;
    }

    ASSERT_EQ(CFG_GetCipherSuiteInfo(HITLS_TLS_SHA384_SHA384, &info), HITLS_SUCCESS);
    ASSERT_EQ(info.cipherSuite, HITLS_TLS_SHA384_SHA384);
    ASSERT_EQ(info.cipherType, HITLS_TLS13_INTEGRITY_CIPHER);
    ASSERT_EQ(info.cipherAlg, HITLS_CIPHER_NULL);
    ASSERT_EQ(info.macAlg, HITLS_MAC_384);
    ASSERT_EQ(info.hashAlg, HITLS_HASH_SHA_384);
    ASSERT_EQ(info.fixedIvLength, 48u);
    ASSERT_EQ(info.encKeyLen, 48u);
    ASSERT_EQ(info.macLen, 48u);
    ASSERT_EQ(info.minVersion, HITLS_VERSION_TLS13);
    ASSERT_EQ(info.maxVersion, HITLS_VERSION_TLS13);
    ASSERT_TRUE(strcmp(info.stdName, "TLS_SHA384_SHA384") == 0);

EXIT:
    return;
}
/* END_CASE */

/** @
* @test SDV_TLS_RFC9150_CFG_SET_CIPHER_TC001
* @title RFC 9150: HITLS_CFG_SetCipherSuites with integrity-only TLS 1.3 suites
* @precon nan
* @brief
* 1. For each supported RFC 9150 suite, add it to a TLS 1.3 config and call HITLS_CFG_SetCipherSuites.
* @expect
* 1. HITLS_SUCCESS is returned.
@ */
/* BEGIN_CASE */
void SDV_TLS_RFC9150_CFG_SET_CIPHER_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    uint16_t suites[2];
    uint32_t n = 0;

    if (CFG_CheckCipherSuiteSupported(HITLS_TLS_SHA256_SHA256)) {
        suites[n++] = HITLS_TLS_SHA256_SHA256;
    }
    if (CFG_CheckCipherSuiteSupported(HITLS_TLS_SHA384_SHA384)) {
        suites[n++] = HITLS_TLS_SHA384_SHA384;
    }
    if (n == 0) {
        goto EXIT;
    }

    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetCipherSuites(config, suites, n), HITLS_SUCCESS);

EXIT:
    if (config != NULL) {
        HITLS_CFG_FreeConfig(config);
    }
}
/* END_CASE */
