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
    const char *key;
    const char *label;
    const char *seed;
    const char *dk;
    CRYPT_MAC_AlgId id;
} CMVP_KDFTLS12_VECTOR;

// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/800-135testvectors/tls.zip
static const CMVP_KDFTLS12_VECTOR KDF_TLS12_VECTOR = {
    .key = "202c88c00f84a17a20027079604787461176455539e705be730890602c289a5001e34eeb3a043e5d52a65e66125188bf",
    .label = "6b657920657870616e73696f6eae6c806f8ad4d80784549dff28a4b58fd837681a51d928c3e30ee5ff14f3986862e1fd91",
    .seed = "f23f558a605f28478c58cf72637b89784d959df7e946d3f07bd1b616",
    .dk = "d06139889fffac1e3a71865f504aa5d0d2a2e89506c6f2279b670c3e1b74f531016a25"
        "30c51a3a0f7e1d6590d0f0566b2f387f8d11fd4f731cdd572d2eae927f6f2f81410b25"
        "e6960be68985add6c38445ad9f8c64bf8068bf9a6679485d966f1ad6f68b43495b10a6"
        "83755ea2b858d70ccac7ec8b053c6bd41ca299d4e51928",
    .id = CRYPT_MAC_HMAC_SHA256
};

static bool CRYPT_CMVP_SelftestKdfTls12Internal(void *libCtx, const char *attrName)
{
    bool ret = false;
    uint8_t *key = NULL;
    uint8_t *label = NULL;
    uint8_t *seed = NULL;
    uint8_t *expDk = NULL;
    uint8_t *dk = NULL;
    uint32_t keyLen, labelLen, seedLen, expDkLen;
    CRYPT_EAL_KdfCTX *ctx = NULL;
    CRYPT_MAC_AlgId id = CRYPT_MAC_HMAC_SHA256;
    key = CMVP_StringsToBins(KDF_TLS12_VECTOR.key, &keyLen);
    GOTO_ERR_IF_TRUE(key == NULL, CRYPT_CMVP_COMMON_ERR);
    label = CMVP_StringsToBins(KDF_TLS12_VECTOR.label, &labelLen);
    GOTO_ERR_IF_TRUE(label == NULL, CRYPT_CMVP_COMMON_ERR);
    seed = CMVP_StringsToBins(KDF_TLS12_VECTOR.seed, &seedLen);
    GOTO_ERR_IF_TRUE(seed == NULL, CRYPT_CMVP_COMMON_ERR);
    expDk = CMVP_StringsToBins(KDF_TLS12_VECTOR.dk, &expDkLen);
    GOTO_ERR_IF_TRUE(expDk == NULL, CRYPT_CMVP_COMMON_ERR);
    dk = BSL_SAL_Malloc(expDkLen);
    GOTO_ERR_IF_TRUE(dk == NULL, CRYPT_MEM_ALLOC_FAIL);

    ctx = CRYPT_EAL_ProviderKdfNewCtx(libCtx, CRYPT_KDF_KDFTLS12, attrName);
    GOTO_ERR_IF_TRUE(ctx == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    BSL_Param param[5] = {
        {CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, &id, sizeof(id), 0},
        {CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS, key, keyLen, 0},
        {CRYPT_PARAM_KDF_LABEL, BSL_PARAM_TYPE_OCTETS, label, labelLen, 0},
        {CRYPT_PARAM_KDF_SEED, BSL_PARAM_TYPE_OCTETS, seed, seedLen, 0},
        BSL_PARAM_END
    };
    GOTO_ERR_IF_TRUE(CRYPT_EAL_KdfSetParam(ctx, param) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_KdfDerive(ctx, dk, expDkLen) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(memcmp(dk, expDk, expDkLen) != 0, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    ret = true;
ERR:
    BSL_SAL_Free(key);
    BSL_SAL_Free(label);
    BSL_SAL_Free(seed);
    BSL_SAL_Free(expDk);
    BSL_SAL_Free(dk);
    CRYPT_EAL_KdfFreeCtx(ctx);
    return ret;
}

bool CRYPT_CMVP_SelftestKdfTls12(void)
{
    return CRYPT_CMVP_SelftestKdfTls12Internal(NULL, NULL);
}

bool CRYPT_CMVP_SelftestProviderKdfTls12(void *libCtx, const char *attrName)
{
    return CRYPT_CMVP_SelftestKdfTls12Internal(libCtx, attrName);
}

#endif /* HITLS_CRYPTO_CMVP_ISO19790 || HITLS_CRYPTO_CMVP_FIPS */
