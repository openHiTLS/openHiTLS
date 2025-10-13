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
#include "crypt_params_key.h"
#include "crypt_errno.h"
#include "crypt_eal_kdf.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "bsl_sal.h"

typedef struct {
    const char *ikm;
    const char *salt;
    const char *info;
    const char *okm;
    CRYPT_MAC_AlgId id;
} CMVP_HKDF_VECTOR;

// https://datatracker.ietf.org/doc/html/rfc5869.html#appendix-A
static const CMVP_HKDF_VECTOR HKDF_VECTOR = {
    .ikm = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    .salt = "000102030405060708090a0b0c",
    .info = "f0f1f2f3f4f5f6f7f8f9",
    .okm = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    .id = CRYPT_MAC_HMAC_SHA256
};

static bool CRYPT_CMVP_SelftestHkdfInternal(void *libCtx, const char *attrName)
{
    bool ret = false;
    uint8_t *key = NULL;
    uint8_t *salt = NULL;
    uint8_t *info = NULL;
    uint8_t *expOut = NULL;
    uint8_t *out = NULL;
    uint32_t keyLen, saltLen, infoLen, expOutLen;
    CRYPT_EAL_KdfCTX *ctx = NULL;
    CRYPT_HKDF_MODE mode = CRYPT_KDF_HKDF_MODE_FULL;
    CRYPT_MAC_AlgId id = CRYPT_MAC_HMAC_SHA256;

    key = CMVP_StringsToBins(HKDF_VECTOR.ikm, &keyLen);
    GOTO_ERR_IF_TRUE(key == NULL, CRYPT_CMVP_COMMON_ERR);
    salt = CMVP_StringsToBins(HKDF_VECTOR.salt, &saltLen);
    GOTO_ERR_IF_TRUE(salt == NULL, CRYPT_CMVP_COMMON_ERR);
    info = CMVP_StringsToBins(HKDF_VECTOR.info, &infoLen);
    GOTO_ERR_IF_TRUE(info == NULL, CRYPT_CMVP_COMMON_ERR);
    expOut = CMVP_StringsToBins(HKDF_VECTOR.okm, &expOutLen);
    GOTO_ERR_IF_TRUE(expOut == NULL, CRYPT_CMVP_COMMON_ERR);
    GOTO_ERR_IF_TRUE(expOut == NULL, CRYPT_CMVP_COMMON_ERR);
    out = BSL_SAL_Malloc(expOutLen);
    GOTO_ERR_IF_TRUE(out == NULL, CRYPT_MEM_ALLOC_FAIL);

    ctx = CRYPT_EAL_ProviderKdfNewCtx(libCtx, CRYPT_KDF_HKDF, attrName);
    GOTO_ERR_IF_TRUE(ctx == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    BSL_Param param[6] = {
        {CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, &id, sizeof(id), 0},
        {CRYPT_PARAM_KDF_MODE, BSL_PARAM_TYPE_UINT32, &mode, sizeof(mode), 0},
        {CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS, key, keyLen, 0},
        {CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS, salt, saltLen, 0},
        {CRYPT_PARAM_KDF_INFO, BSL_PARAM_TYPE_OCTETS, info, infoLen, 0},
        BSL_PARAM_END
    };
    GOTO_ERR_IF_TRUE(CRYPT_EAL_KdfSetParam(ctx, param) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_KdfDerive(ctx, out, expOutLen) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(memcmp(out, expOut, expOutLen) != 0, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    ret = true;
ERR:
    BSL_SAL_Free(key);
    BSL_SAL_Free(salt);
    BSL_SAL_Free(info);
    BSL_SAL_Free(expOut);
    BSL_SAL_Free(out);
    CRYPT_EAL_KdfFreeCtx(ctx);
    return ret;
}

bool CRYPT_CMVP_SelftestHkdf(void)
{
    return CRYPT_CMVP_SelftestHkdfInternal(NULL, NULL);
}

bool CRYPT_CMVP_SelftestProviderHkdf(void *libCtx, const char *attrName)
{
    return CRYPT_CMVP_SelftestHkdfInternal(libCtx, attrName);
}

#endif /* HITLS_CRYPTO_CMVP_ISO19790 || HITLS_CRYPTO_CMVP_FIPS */
