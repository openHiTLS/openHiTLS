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
#if defined(HITLS_CRYPTO_CMVP_ISO19790) || defined(HITLS_CRYPTO_CMVP_FIPS)

#include <string.h>
#include "crypt_cmvp_selftest.h"
#include "cmvp_common.h"
#include "err.h"
#include "crypt_errno.h"
#include "crypt_eal_kdf.h"
#include "crypt_params_key.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "bsl_sal.h"

typedef struct {
    const char *pw;
    const char *salt;
    uint32_t n;
    uint32_t r;
    uint32_t p;
    const char *key;
} CMVP_SCRYPT_VECTOR;

// https://datatracker.ietf.org/doc/html/rfc7914#page-13
static const CMVP_SCRYPT_VECTOR SCRYPT_VECTOR = {
    .pw = "70617373776f7264",
    .salt = "4e61436c",
    .n = 1024,
    .r = 8,
    .p = 16,
    .key = "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a388"
        "6ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"
};

static bool CRYPT_CMVP_SelftestScryptInternal(void *libCtx, const char *attrName)
{
    bool ret = false;
    uint8_t *pw = NULL;
    uint8_t *salt = NULL;
    uint8_t *key = NULL;
    uint8_t *expkey = NULL;
    uint32_t pwLen, saltLen, expkeyLen;
    uint32_t n = SCRYPT_VECTOR.n;
    uint32_t r = SCRYPT_VECTOR.r;
    uint32_t p = SCRYPT_VECTOR.p;
    CRYPT_EAL_KdfCTX *ctx = NULL;
    pw = CMVP_StringsToBins(SCRYPT_VECTOR.pw, &pwLen);
    GOTO_ERR_IF_TRUE(pw == NULL, CRYPT_CMVP_COMMON_ERR);
    salt = CMVP_StringsToBins(SCRYPT_VECTOR.salt, &saltLen);
    GOTO_ERR_IF_TRUE(salt == NULL, CRYPT_CMVP_COMMON_ERR);
    expkey = CMVP_StringsToBins(SCRYPT_VECTOR.key, &expkeyLen);
    GOTO_ERR_IF_TRUE(expkey == NULL, CRYPT_CMVP_COMMON_ERR);
    key = BSL_SAL_Malloc(expkeyLen);
    GOTO_ERR_IF_TRUE(key == NULL, CRYPT_MEM_ALLOC_FAIL);

    ctx = CRYPT_EAL_ProviderKdfNewCtx(libCtx, CRYPT_KDF_SCRYPT, attrName);
    GOTO_ERR_IF_TRUE(ctx == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    BSL_Param param[6] = {
        {CRYPT_PARAM_KDF_PASSWORD, BSL_PARAM_TYPE_OCTETS, pw, pwLen, 0},
        {CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS, salt, saltLen, 0},
        {CRYPT_PARAM_KDF_N, BSL_PARAM_TYPE_UINT32, &n, sizeof(uint32_t), 0},
        {CRYPT_PARAM_KDF_R, BSL_PARAM_TYPE_UINT32, &r, sizeof(uint32_t), 0},
        {CRYPT_PARAM_KDF_P, BSL_PARAM_TYPE_UINT32, &p, sizeof(uint32_t), 0},
        BSL_PARAM_END
    };
    GOTO_ERR_IF_TRUE(CRYPT_EAL_KdfSetParam(ctx, param) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_KdfDerive(ctx, key, expkeyLen) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(memcmp(key, expkey, expkeyLen) != 0, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    ret = true;
ERR:
    BSL_SAL_Free(pw);
    BSL_SAL_Free(salt);
    BSL_SAL_Free(expkey);
    BSL_SAL_Free(key);
    CRYPT_EAL_KdfFreeCtx(ctx);
    return ret;
}

bool CRYPT_CMVP_SelftestScrypt(void)
{
    return CRYPT_CMVP_SelftestScryptInternal(NULL, NULL);
}

bool CRYPT_CMVP_SelftestProviderScrypt(void *libCtx, const char *attrName)
{
    return CRYPT_CMVP_SelftestScryptInternal(libCtx, attrName);
}

#endif /* HITLS_CRYPTO_CMVP_ISO19790 || HITLS_CRYPTO_CMVP_FIPS */
