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
#ifdef HITLS_CRYPTO_CMVP_ISO19790

#include "crypt_eal_implprovider.h"
#ifdef HITLS_CRYPTO_MLKEM
#include "crypt_mlkem.h"
#endif
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_iso_selftest.h"
#include "crypt_iso_provderimpl.h"

#ifdef HITLS_CRYPTO_MLKEM
static int32_t CRYPT_ML_KEM_EncapsWrapper(const CRYPT_Iso_Pkey_Ctx *ctx, uint8_t *cipher, uint32_t *cipherLen,
    uint8_t *share, uint32_t *shareLen)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_ENCAPS, CRYPT_ALGO_PKEY, ctx->algId);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return CRYPT_ML_KEM_Encaps(ctx->ctx, cipher, cipherLen, share, shareLen);
}

static int32_t CRYPT_ML_KEM_DecapsWrapper(const CRYPT_Iso_Pkey_Ctx *ctx, uint8_t *cipher, uint32_t cipherLen,
    uint8_t *share, uint32_t *shareLen)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_DECAPS, CRYPT_ALGO_PKEY, ctx->algId);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return CRYPT_ML_KEM_Decaps(ctx->ctx, cipher, cipherLen, share, shareLen);
}
#endif

const CRYPT_EAL_Func g_isoMlKem[] = {
#ifdef HITLS_CRYPTO_MLKEM
    {CRYPT_EAL_IMPLPKEYKEM_ENCAPSULATE, (CRYPT_EAL_ImplPkeyKemEncapsulate)CRYPT_ML_KEM_EncapsWrapper},
    {CRYPT_EAL_IMPLPKEYKEM_DECAPSULATE, (CRYPT_EAL_ImplPkeyKemDecapsulate)CRYPT_ML_KEM_DecapsWrapper},
#endif
    CRYPT_EAL_FUNC_END
};

#endif // HITLS_CRYPTO_CMVP_ISO19790
