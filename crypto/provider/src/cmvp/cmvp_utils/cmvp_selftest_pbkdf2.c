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
#include "crypt_cmvp_selftest.h"
#include "cmvp_common.h"
#include "err.h"
#include "crypt_errno.h"
#include "crypt_eal_kdf.h"
#include "bsl_err_internal.h"
#include "crypt_params_key.h"
#include "crypt_utils.h"
#include "bsl_sal.h"

typedef struct {
    const char *pw;
    const char *salt;
    uint32_t iter;
    const char *key;
    CRYPT_MAC_AlgId id;
} CMVP_PBKDF2_VECTOR;

// https://www.ietf.org/rfc/rfc6070.txt
static const CMVP_PBKDF2_VECTOR PBKDF2_VECTOR[] = {
    {
        .pw = "passwordPASSWORDpassword",
        .salt = "saltSALTsaltSALTsaltSALTsaltSALTsalt",
        .iter = 4096,
        .key = "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038",
        .id = CRYPT_MAC_HMAC_SHA1
    },
    {
        .pw = "passwordPASSWORDpassword",
        .salt = "saltSALTsaltSALTsaltSALTsaltSALTsalt",
        .iter = 1024,
        .key = "1e0d8ab1b32bb96dff58ff89ab171e643a425fd87f26261b56f9d38c992f2593a713f9c1772f8bf2",
        .id = CRYPT_MAC_HMAC_SM3
    },
};

static const CMVP_PBKDF2_VECTOR *FindVectorById(CRYPT_MAC_AlgId id)
{
    const CMVP_PBKDF2_VECTOR *pPbkdf2Vec = NULL;
    uint32_t num = sizeof(PBKDF2_VECTOR) / sizeof(PBKDF2_VECTOR[0]);

    for (uint32_t i = 0; i < num; i++) {
        if (PBKDF2_VECTOR[i].id == id) {
            pPbkdf2Vec = &PBKDF2_VECTOR[i];
            return pPbkdf2Vec;
        }
    }

    return NULL;
}

static bool CRYPT_CMVP_SelftestPbkdf2Internal(void *libCtx, const char *attrName, CRYPT_MAC_AlgId id)
{
    (void)id;
    bool ret = false;
    const char *pw = NULL;
    const char *salt = NULL;
    uint8_t *expOut = NULL;
    uint8_t *out = NULL;
    uint32_t expOutLen, pwLen, saltLen, iter;
    CRYPT_EAL_KdfCTX *ctx = NULL;
    const CMVP_PBKDF2_VECTOR *pbkdf2Vec = FindVectorById(id);
    if (pbkdf2Vec == NULL || pbkdf2Vec->pw == NULL) {
        return false;
    }
    iter = pbkdf2Vec->iter;
    pw = pbkdf2Vec->pw;
    pwLen = (uint32_t)strlen(pbkdf2Vec->pw);
    salt = pbkdf2Vec->salt;
    saltLen = (uint32_t)strlen(pbkdf2Vec->salt);
    expOut = CMVP_StringsToBins(pbkdf2Vec->key, &expOutLen);
    GOTO_ERR_IF_TRUE(expOut == NULL, CRYPT_CMVP_COMMON_ERR);
    out = BSL_SAL_Malloc(expOutLen);
    GOTO_ERR_IF_TRUE(out == NULL, CRYPT_MEM_ALLOC_FAIL);
    ctx = CRYPT_EAL_ProviderKdfNewCtx(libCtx, CRYPT_KDF_PBKDF2, attrName);
    GOTO_ERR_IF_TRUE(ctx == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    BSL_Param param[5] = {
        {CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, &id, sizeof(id), 0},
        {CRYPT_PARAM_KDF_PASSWORD, BSL_PARAM_TYPE_OCTETS, (void *)(uintptr_t)pw, pwLen, 0},
        {CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS, (void *)(uintptr_t)salt, saltLen, 0},
        {CRYPT_PARAM_KDF_ITER, BSL_PARAM_TYPE_UINT32, &iter, sizeof(uint32_t), 0},
        BSL_PARAM_END
    };
    GOTO_ERR_IF_TRUE(CRYPT_EAL_KdfSetParam(ctx, param) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_KdfDerive(ctx, out, expOutLen) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(memcmp(out, expOut, expOutLen) != 0, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    ret = true;
ERR:
    BSL_SAL_Free(expOut);
    BSL_SAL_Free(out);
    CRYPT_EAL_KdfFreeCtx(ctx);
    return ret;
}

bool CRYPT_CMVP_SelftestPbkdf2(CRYPT_MAC_AlgId id)
{
    return CRYPT_CMVP_SelftestPbkdf2Internal(NULL, NULL, id);
}

bool CRYPT_CMVP_SelftestProviderPbkdf2(void *libCtx, const char *attrName, CRYPT_MAC_AlgId id)
{
    return CRYPT_CMVP_SelftestPbkdf2Internal(libCtx, attrName, id);
}

#endif /* HITLS_CRYPTO_CMVP_ISO19790 || HITLS_CRYPTO_CMVP_SM || HITLS_CRYPTO_CMVP_FIPS */
