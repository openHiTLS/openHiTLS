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
#if defined(HITLS_CRYPTO_CMVP_ISO19790) || defined(HITLS_CRYPTO_CMVP_SM) || defined(HITLS_CRYPTO_CMVP_FIPS)

#include <string.h>
#include "cmvp_common.h"
#include "crypt_eal_mac.h"
#include "crypt_errno.h"
#include "bsl_err.h"
#include "securec.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "bsl_sal.h"
#include "cmvp_integrity_hmac.h"

#ifndef CMVP_INTEGRITYKEY
#define CMVP_INTEGRITYKEY ""
#endif

const char *GetIntegrityKey(void)
{
    return CMVP_INTEGRITYKEY;
}

static uint8_t *GetLibHmac(void *libCtx, const char *attrName, CRYPT_MAC_AlgId id, const char *libPath,
    uint32_t *hmacLen)
{
    char *buf = NULL;
    uint8_t *hmac = NULL;
    uint32_t bufLen;
    CRYPT_EAL_MacCtx *ctx = NULL;

    buf = CMVP_ReadFile(libPath, "rb", &bufLen);
    GOTO_ERR_IF_TRUE(buf == NULL, CRYPT_CMVP_COMMON_ERR);
    ctx = CRYPT_EAL_ProviderMacNewCtx(libCtx, id, attrName);
    GOTO_ERR_IF_TRUE(ctx == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    *hmacLen = CRYPT_EAL_GetMacLen(ctx);
    hmac = BSL_SAL_Malloc(*hmacLen);
    GOTO_ERR_IF_TRUE(hmac == NULL, CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_MacInit(ctx, (const uint8_t *)GetIntegrityKey(), (uint32_t)strlen(GetIntegrityKey())) !=
        CRYPT_SUCCESS, CRYPT_CMVP_ERR_INTEGRITY);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_MacUpdate(ctx, (uint8_t *)buf, bufLen) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_INTEGRITY);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_MacFinal(ctx, hmac, hmacLen) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_INTEGRITY);

    BSL_SAL_Free(buf);
    CRYPT_EAL_MacFreeCtx(ctx);
    return hmac;
ERR:
    BSL_SAL_Free(buf);
    BSL_SAL_Free(hmac);
    CRYPT_EAL_MacFreeCtx(ctx);
    return NULL;
}

static uint8_t *GetExpectHmac(const char *hmacPath, uint32_t *hmacLen)
{
    uint8_t *hmac = NULL;
    char *buf = NULL;
    uint32_t bufLen;
    char seps[] = " \n";
    char *tmp = NULL;
    char *nextTmp = NULL;

    buf = CMVP_ReadFile(hmacPath, "r", &bufLen);
    GOTO_ERR_IF_TRUE(buf == NULL, CRYPT_CMVP_COMMON_ERR);
    // HMAC-SHA256(libhitls_crypto.so)= 76a90d73cb68585837a2ebdf009e9e485acba4fd718bae898bdc354537f8a72a\n
    // The format of the generated .hmac file is as shown in the preceding figure.
    // The content between spaces and newline characters is truncated.
    tmp = strtok_s(buf, seps, &nextTmp);
    GOTO_ERR_IF_TRUE(tmp == NULL, CRYPT_CMVP_COMMON_ERR);
    tmp = strtok_s(NULL, seps, &nextTmp);
    GOTO_ERR_IF_TRUE(tmp == NULL, CRYPT_CMVP_COMMON_ERR);
    hmac = CMVP_StringsToBins(tmp, hmacLen);
    GOTO_ERR_IF_TRUE(hmac == NULL, CRYPT_CMVP_COMMON_ERR);

    BSL_SAL_Free(buf);
    return hmac;
ERR:
    BSL_SAL_Free(buf);
    BSL_SAL_Free(hmac);
    return NULL;
}

bool CMVP_IntegrityHmac(void *libCtx, const char *attrName, const char *libPath, CRYPT_MAC_AlgId id)
{
    bool ret = false;
    char *hmacPath = NULL;
    uint8_t *hmac = NULL;
    uint8_t *expectHmac = NULL;
    uint32_t hmacLen, expectHmacLen;

    hmacPath = BSL_SAL_Malloc((uint32_t)strlen(libPath) + (uint32_t)strlen(".hmac") + 1);
    GOTO_ERR_IF_TRUE(hmacPath == NULL, CRYPT_MEM_ALLOC_FAIL);
    (void)sprintf_s(hmacPath, strlen(libPath) + strlen(".hmac") + 1, "%s%s", libPath, ".hmac");
    hmacPath[strlen(libPath) + strlen(".hmac")] = '\0';

    hmac = GetLibHmac(libCtx, attrName, id, libPath, &hmacLen);
    GOTO_ERR_IF_TRUE(hmac == NULL, CRYPT_CMVP_ERR_INTEGRITY);
    expectHmac = GetExpectHmac(hmacPath, &expectHmacLen);
    GOTO_ERR_IF_TRUE(expectHmac == NULL, CRYPT_CMVP_ERR_INTEGRITY);
    GOTO_ERR_IF_TRUE(hmacLen != expectHmacLen, CRYPT_CMVP_ERR_INTEGRITY);
    GOTO_ERR_IF_TRUE(memcmp(expectHmac, hmac, hmacLen) != 0, CRYPT_CMVP_ERR_INTEGRITY);

    ret = true;
ERR:
    BSL_SAL_Free(hmac);
    BSL_SAL_Free(expectHmac);
    BSL_SAL_Free(hmacPath);
    return ret;
}

#endif /* HITLS_CRYPTO_CMVP_ISO19790 || HITLS_CRYPTO_CMVP_SM || HITLS_CRYPTO_CMVP_FIPS */
