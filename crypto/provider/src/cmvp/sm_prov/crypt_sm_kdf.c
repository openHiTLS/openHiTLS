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
#include "crypt_pbkdf2.h"
#include "crypt_kdf_tls12.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_cmvp.h"
#include "cmvp_sm.h"
#include "bsl_log_internal.h"
#include "bsl_err_internal.h"
#include "bsl_params.h"
#include "crypt_params_key.h"

/* Constants for parameter validation */
#define KDF_DEF_MAC_ALGID   CRYPT_MAC_HMAC_SM3
#define KDF_DEF_SALT_LEN    16
#define KDF_DEF_PBKDF2_ITER 1024

void *CRYPT_EAL_SmKdfNewCtxEx(CRYPT_EAL_SmProvCtx *provCtx, int32_t algId)
{
    if (provCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    switch (algId) {
#ifdef HITLS_CRYPTO_PBKDF2
        case CRYPT_KDF_PBKDF2:
            return CRYPT_PBKDF2_NewCtxEx(provCtx->libCtx, algId);
#endif
#ifdef HITLS_CRYPTO_KDFTLS12
        case CRYPT_KDF_KDFTLS12:
            return CRYPT_KDFTLS12_NewCtxEx(provCtx->libCtx, algId);
#endif
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_NOT_SUPPORT);
            return NULL;
    }
}

static int32_t GetPbkdf2Params(const BSL_Param *param, CRYPT_EAL_Pbkdf2Param *pbkdf2Param)
{
    int32_t id;
    uint32_t iter;
    uint32_t len;
    const BSL_Param *temp = NULL;

    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_KDF_SALT)) != NULL) {
        pbkdf2Param->saltLen = temp->valueLen;
    }

    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_KDF_ITER)) != NULL) {
        len = sizeof(iter);
        int32_t ret = BSL_PARAM_GetValue(temp, CRYPT_PARAM_KDF_ITER, BSL_PARAM_TYPE_UINT32, &iter, &len);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        pbkdf2Param->iter = iter;
    }

    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_KDF_MAC_ID)) != NULL) {
        len = sizeof(id);
        int32_t ret = BSL_PARAM_GetValue(temp, CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, &id, &len);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        pbkdf2Param->macId = (CRYPT_MAC_AlgId)id;
    }
    return CRYPT_SUCCESS;
}

static int32_t CheckKdfParam(const BSL_Param *param)
{
    int32_t ret = CRYPT_SUCCESS;
    CRYPT_EAL_Pbkdf2Param pbkdf2 = {KDF_DEF_MAC_ALGID, KDF_DEF_SALT_LEN, KDF_DEF_PBKDF2_ITER, 0};
    CRYPT_EAL_KdfC2Data data = {&pbkdf2, NULL};
    ret = GetPbkdf2Params(param, &pbkdf2);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (!CMVP_SmKdfC2(&data)) {
        BSL_ERR_PUSH_ERROR(CRYPT_CMVP_ERR_PARAM_CHECK);
        return CRYPT_CMVP_ERR_PARAM_CHECK;
    }
    return ret;
}

static int32_t CRYPT_PBKDF2_SetParamWrapper(CRYPT_PBKDF2_Ctx *ctx, const BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CheckKdfParam(param);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return CRYPT_PBKDF2_SetParam(ctx, param);
}

const CRYPT_EAL_Func g_smKdfPBKdf2[] = {
#ifdef HITLS_CRYPTO_PBKDF2
    {CRYPT_EAL_IMPLKDF_NEWCTX, (CRYPT_EAL_ImplKdfNewCtx)CRYPT_EAL_SmKdfNewCtxEx},
    {CRYPT_EAL_IMPLKDF_SETPARAM, (CRYPT_EAL_ImplKdfSetParam)CRYPT_PBKDF2_SetParamWrapper},
    {CRYPT_EAL_IMPLKDF_DERIVE, (CRYPT_EAL_ImplKdfDerive)CRYPT_PBKDF2_Derive},
    {CRYPT_EAL_IMPLKDF_DEINITCTX, (CRYPT_EAL_ImplKdfDeInitCtx)CRYPT_PBKDF2_Deinit},
    {CRYPT_EAL_IMPLKDF_FREECTX, (CRYPT_EAL_ImplKdfFreeCtx)CRYPT_PBKDF2_FreeCtx},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_smKdfKdfTLS12[] = {
#ifdef HITLS_CRYPTO_KDFTLS12
    {CRYPT_EAL_IMPLKDF_NEWCTX, (CRYPT_EAL_ImplKdfNewCtx)CRYPT_EAL_SmKdfNewCtxEx},
    {CRYPT_EAL_IMPLKDF_SETPARAM, (CRYPT_EAL_ImplKdfSetParam)CRYPT_KDFTLS12_SetParam},
    {CRYPT_EAL_IMPLKDF_DERIVE, (CRYPT_EAL_ImplKdfDerive)CRYPT_KDFTLS12_Derive},
    {CRYPT_EAL_IMPLKDF_DEINITCTX, (CRYPT_EAL_ImplKdfDeInitCtx)CRYPT_KDFTLS12_Deinit},
    {CRYPT_EAL_IMPLKDF_FREECTX, (CRYPT_EAL_ImplKdfFreeCtx)CRYPT_KDFTLS12_FreeCtx},
#endif
    CRYPT_EAL_FUNC_END,
};

#endif /* HITLS_CRYPTO_CMVP_SM */
