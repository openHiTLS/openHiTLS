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
#ifdef HITLS_CRYPTO_CMVP_SM

#include "crypt_eal_implprovider.h"
#include "crypt_sm2.h"
#include "crypt_errno.h"
#include "cmvp_sm.h"
#include "crypt_cmvp.h"

static int32_t CRYPT_SM2_SignWrapper(const CRYPT_SM2_Ctx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
    uint8_t *sign, uint32_t *signLen)
{
    if (!CMVP_SmPkeyC2(algId)) {
        return CRYPT_CMVP_ERR_PARAM_CHECK;
    }
    return CRYPT_SM2_Sign(ctx, algId, data, dataLen, sign, signLen);
}

static int32_t CRYPT_SM2_VerifyWrapper(const CRYPT_SM2_Ctx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
    const uint8_t *sign, uint32_t signLen)
{
    if (!CMVP_SmPkeyC2(algId)) {
        return CRYPT_CMVP_ERR_PARAM_CHECK;
    }
    return CRYPT_SM2_Verify(ctx, algId, data, dataLen, sign, signLen);
}

const CRYPT_EAL_Func g_smSignSm2[] = {
#ifdef HITLS_CRYPTO_SM2_SIGN
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, (CRYPT_EAL_ImplPkeySign)CRYPT_SM2_SignWrapper},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, (CRYPT_EAL_ImplPkeyVerify)CRYPT_SM2_VerifyWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

#endif /* HITLS_CRYPTO_CMVP_SM */