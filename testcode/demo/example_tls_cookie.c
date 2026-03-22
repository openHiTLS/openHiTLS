/*
 * DTLS cookie configuration demo.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "crypt_eal_init.h"
#include "crypt_errno.h"
#include "hitls.h"
#include "hitls_cert_init.h"
#include "hitls_config.h"
#include "hitls_cookie.h"
#include "hitls_crypt_init.h"
#include "hitls_error.h"

#define DTLS_COOKIE_VALUE "openhitls-dtls-cookie"

static int32_t TlsCookieInitLibrary(void)
{
    int32_t ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);

    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    HITLS_CertMethodInit();
    HITLS_CryptMethodInit();
    return HITLS_SUCCESS;
}

static int32_t TlsCookieGenerateCallback(HITLS_Ctx *ctx, uint8_t *cookie, uint32_t *cookieLen)
{
    const uint32_t expectedLen = (uint32_t)(sizeof(DTLS_COOKIE_VALUE) - 1);

    /* The demo uses a fixed cookie so the callback contract stays easy to inspect. */
    (void)ctx;
    if (cookie == NULL || cookieLen == NULL || *cookieLen < expectedLen) {
        return HITLS_COOKIE_GENERATE_ERROR;
    }
    (void)memcpy(cookie, DTLS_COOKIE_VALUE, expectedLen);
    *cookieLen = expectedLen;
    return HITLS_COOKIE_GENERATE_SUCCESS;
}

static int32_t TlsCookieVerifyCallback(HITLS_Ctx *ctx, const uint8_t *cookie, uint32_t cookieLen)
{
    const uint32_t expectedLen = (uint32_t)(sizeof(DTLS_COOKIE_VALUE) - 1);

    (void)ctx;
    if (cookie == NULL || cookieLen != expectedLen) {
        return HITLS_COOKIE_VERIFY_ERROR;
    }
    if (memcmp(cookie, DTLS_COOKIE_VALUE, expectedLen) != 0) {
        return HITLS_COOKIE_VERIFY_ERROR;
    }
    return HITLS_COOKIE_VERIFY_SUCCESS;
}

static int32_t TlsCookieCreateServerConfig(HITLS_Config **configOut)
{
    HITLS_Config *config = NULL;
    bool isDtls = false;
    bool cookieEnabled = false;
    int32_t ret;

    config = HITLS_CFG_NewDTLS12Config();
    if (config == NULL) {
        printf("HITLS_CFG_NewDTLS12Config failed\n");
        return -1;
    }
    /* Verify that the chosen config object is really a DTLS-family config before adding DTLS-only options. */
    ret = HITLS_CFG_IsDtls(config, &isDtls);
    if (ret != HITLS_SUCCESS || !isDtls) {
        printf("HITLS_CFG_IsDtls failed: ret=0x%x isDtls=%d\n", ret, isDtls);
        goto cleanup;
    }
    /* Cookie exchange is a DTLS server-side anti-spoofing feature, so enable it before registering callbacks. */
    ret = HITLS_CFG_SetDtlsCookieExchangeSupport(config, true);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_CFG_SetCookieGenCb(config, TlsCookieGenerateCallback);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_CFG_SetCookieVerifyCb(config, TlsCookieVerifyCallback);
    if (ret != HITLS_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_CFG_GetDtlsCookieExchangeSupport(config, &cookieEnabled);
    if (ret != HITLS_SUCCESS || !cookieEnabled) {
        printf("DTLS cookie exchange is not enabled on config\n");
        ret = -1;
        goto cleanup;
    }
    *configOut = config;
    return HITLS_SUCCESS;

cleanup:
    HITLS_CFG_FreeConfig(config);
    return ret;
}

static int32_t TlsCookieRunConfigExample(HITLS_Config *config)
{
    uint8_t cookie[64] = {0};
    uint32_t cookieLen = sizeof(cookie);
    HITLS_Ctx *ctx = NULL;
    bool isDtls = false;
    bool cookieEnabled = false;
    int32_t ret;

    ctx = HITLS_New(config);
    if (ctx == NULL) {
        printf("HITLS_New failed\n");
        return -1;
    }
    /* Re-check DTLS state on the runtime context to confirm the config propagated into the live connection object. */
    ret = HITLS_IsDtls(ctx, &isDtls);
    if (ret != HITLS_SUCCESS || !isDtls) {
        printf("HITLS_IsDtls failed: ret=0x%x isDtls=%d\n", ret, isDtls);
        goto cleanup;
    }
    ret = HITLS_GetDtlsCookieExangeSupport(ctx, &cookieEnabled);
    if (ret != HITLS_SUCCESS || !cookieEnabled) {
        printf("DTLS cookie exchange is not enabled on context\n");
        ret = -1;
        goto cleanup;
    }
    /* Validate that cookie generation and verification callbacks are both ready before wiring them into DTLS. */
    if (TlsCookieGenerateCallback(ctx, cookie, &cookieLen) != HITLS_COOKIE_GENERATE_SUCCESS) {
        printf("cookie generation callback failed\n");
        ret = -1;
        goto cleanup;
    }
    if (TlsCookieVerifyCallback(ctx, cookie, cookieLen) != HITLS_COOKIE_VERIFY_SUCCESS) {
        printf("cookie verification callback failed\n");
        ret = -1;
        goto cleanup;
    }

    printf("configured DTLS cookie exchange and verified callback contract successfully\n");
    ret = HITLS_SUCCESS;

cleanup:
    HITLS_Free(ctx);
    return ret;
}

int main(void)
{
    HITLS_Config *config = NULL;
    int32_t ret;

    printf("=== example_tls_cookie ===\n");

    ret = TlsCookieInitLibrary();
    if (ret != HITLS_SUCCESS) {
        printf("library init failed: 0x%x\n", ret);
        return -1;
    }
    ret = TlsCookieCreateServerConfig(&config);
    if (ret != HITLS_SUCCESS) {
        HITLS_CFG_FreeConfig(config);
        CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
        return -1;
    }
    ret = TlsCookieRunConfigExample(config);
    HITLS_CFG_FreeConfig(config);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    if (ret != HITLS_SUCCESS) {
        printf("example_tls_cookie failed\n");
        return -1;
    }

    printf("example_tls_cookie succeeded\n");
    return 0;
}
