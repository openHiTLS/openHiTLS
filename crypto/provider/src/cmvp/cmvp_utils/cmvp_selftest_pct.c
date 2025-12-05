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
#include "crypt_utils.h"
#include "crypt_dsa.h"
#include "crypt_ecdsa.h"
#include "crypt_curve25519.h"
#include "crypt_rsa.h"
#include "crypt_sm2.h"
#include "crypt_eal_implprovider.h"

typedef struct {
    int32_t id;
    CRYPT_EAL_ImplPkeySign sign;
    CRYPT_EAL_ImplPkeyVerify verify;
    CRYPT_EAL_ImplPkeyMgmtCtrl ctrl;
} PkeyMethodMap;

static const PkeyMethodMap pkey_map[] = {
#ifdef HITLS_CRYPTO_DSA
    {CRYPT_PKEY_DSA,     (CRYPT_EAL_ImplPkeySign)CRYPT_DSA_Sign,
        (CRYPT_EAL_ImplPkeyVerify)CRYPT_DSA_Verify,        (CRYPT_EAL_ImplPkeyMgmtCtrl)CRYPT_DSA_Ctrl},
#endif
#ifdef HITLS_CRYPTO_ED25519
    {CRYPT_PKEY_ED25519, (CRYPT_EAL_ImplPkeySign)CRYPT_CURVE25519_Sign,
        (CRYPT_EAL_ImplPkeyVerify)CRYPT_CURVE25519_Verify, (CRYPT_EAL_ImplPkeyMgmtCtrl)CRYPT_CURVE25519_Ctrl},
#endif
#ifdef HITLS_CRYPTO_RSA
    {CRYPT_PKEY_RSA,     (CRYPT_EAL_ImplPkeySign)CRYPT_RSA_Sign,
        (CRYPT_EAL_ImplPkeyVerify)CRYPT_RSA_Verify,        (CRYPT_EAL_ImplPkeyMgmtCtrl)CRYPT_RSA_Ctrl},
#endif
#ifdef HITLS_CRYPTO_ECDSA
    {CRYPT_PKEY_ECDSA,   (CRYPT_EAL_ImplPkeySign)CRYPT_ECDSA_Sign,
        (CRYPT_EAL_ImplPkeyVerify)CRYPT_ECDSA_Verify,      (CRYPT_EAL_ImplPkeyMgmtCtrl)CRYPT_ECDSA_Ctrl},
#endif
#ifdef HITLS_CRYPTO_SM2
    {CRYPT_PKEY_SM2,     (CRYPT_EAL_ImplPkeySign)CRYPT_SM2_Sign,
        (CRYPT_EAL_ImplPkeyVerify)CRYPT_SM2_Verify,        (CRYPT_EAL_ImplPkeyMgmtCtrl)CRYPT_SM2_Ctrl},
#endif
    {CRYPT_PKEY_MAX, NULL, NULL, NULL}
};

static bool CMVP_SignVerifyPct(void *ctx, int32_t algId)
{
    bool ret = false;
    uint8_t *sign = NULL;
    uint32_t signLen = 0;
    const uint8_t msg[] = {0x01, 0x02, 0x03, 0x04};
    uint32_t mdId = CRYPT_MD_SHA512;

    const PkeyMethodMap *map = NULL;
    for (uint32_t i = 0; i < sizeof(pkey_map) / sizeof(pkey_map[0]); i++) {
        if (algId == pkey_map[i].id) {
            map = &pkey_map[i];
            break;
        }
    }
    GOTO_ERR_IF_TRUE(map == NULL, CRYPT_EAL_ERR_ALGID);

    GOTO_ERR_IF_TRUE(map->ctrl(ctx, CRYPT_CTRL_GET_SIGNLEN, &signLen, sizeof(signLen)) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);

    sign = BSL_SAL_Malloc(signLen);
    GOTO_ERR_IF_TRUE(sign == NULL, CRYPT_MEM_ALLOC_FAIL);

    if (algId == CRYPT_PKEY_RSA) {
        GOTO_ERR_IF_TRUE(map->ctrl(ctx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &mdId, sizeof(mdId)) != CRYPT_SUCCESS,
            CRYPT_CMVP_ERR_ALGO_SELFTEST);
    }

    GOTO_ERR_IF_TRUE(map->sign(ctx, algId == CRYPT_PKEY_SM2 ? CRYPT_MD_SM3 : CRYPT_MD_SHA512, msg, sizeof(msg),
        sign, &signLen) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    GOTO_ERR_IF_TRUE(map->verify(ctx, algId == CRYPT_PKEY_SM2 ? CRYPT_MD_SM3 : CRYPT_MD_SHA512, msg, sizeof(msg),
        sign, signLen) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    ret = true;
ERR:
    BSL_SAL_Free(sign);
    return ret;
}

bool CRYPT_CMVP_SelftestPkeyPct(void *ctx, int32_t algId)
{
    if (algId == CRYPT_PKEY_DH || algId == CRYPT_PKEY_ECDH || algId == CRYPT_PKEY_X25519) {
        return true;
    }
    return CMVP_SignVerifyPct(ctx, algId);
}

#endif /* HITLS_CRYPTO_CMVP_ISO19790 || HITLS_CRYPTO_CMVP_SM || HITLS_CRYPTO_CMVP_FIPS */
