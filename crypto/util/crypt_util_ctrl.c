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

#include <stddef.h>
#include "hitls_build.h"

#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#if defined(HITLS_CRYPTO_HKDF) || defined(HITLS_CRYPTO_KDFTLS12) || defined(HITLS_CRYPTO_PBKDF2) || \
    defined(HITLS_CRYPTO_SCRYPT)
#include "eal_mac_local.h"
#endif
#include "crypt_params_key.h"
#include "crypt_util_ctrl.h"

int32_t CRYPT_CTRL_GetNum32(uint32_t num, void *val, uint32_t valLen)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (valLen != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    *(uint32_t *)val = num;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_CTRL_GetNum32Ex(GetNumCallBack getNumCb, void *cbArg, void *val, uint32_t valLen)
{
    if (val == NULL || getNumCb == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (valLen != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    *(int32_t *)val = getNumCb(cbArg);
    return CRYPT_SUCCESS;
}

#if defined(HITLS_CRYPTO_HKDF) || defined(HITLS_CRYPTO_KDFTLS12) || defined(HITLS_CRYPTO_PBKDF2) || \
    defined(HITLS_CRYPTO_SCRYPT)
int32_t CRYPT_CTRL_SetData(const uint8_t *src, uint32_t srcLen, uint8_t **dst, uint32_t *dstLen)
{
    // In case of hkdf/kdftls12/pbkdf2/scrypt, if src is NULL, allow srcLen is 0
    if (src == NULL  && srcLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    BSL_SAL_ClearFree((void *)*dst, *dstLen);
    *dst = BSL_SAL_Dump(src, srcLen);
    if (*dst == NULL && srcLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    *dstLen = srcLen;
    return CRYPT_SUCCESS;
}
#endif

#if defined(HITLS_CRYPTO_HKDF) || defined(HITLS_CRYPTO_KDFTLS12) || defined(HITLS_CRYPTO_PBKDF2)
int32_t CRYPT_CTRL_SetMdAttrToHmac(const char *mdAttr, uint32_t mdAttrLen, MacSetParam setParamCb, void *hmacCtx)
{
    if (mdAttr == NULL || mdAttrLen == 0 || hmacCtx == NULL || setParamCb == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    BSL_Param param[] = {
        {.key = CRYPT_PARAM_MD_ATTR, .valueType = BSL_PARAM_TYPE_UTF8_STR,
            .value = (void *)(uintptr_t)mdAttr, .valueLen = mdAttrLen, .useLen = 0},
        BSL_PARAM_END};
    return setParamCb(hmacCtx, param);
}

int32_t CRYPT_CTRL_SetMacMethod(void *libCtx, CRYPT_MAC_AlgId inId, int32_t ret, void **macCtx, EAL_MacMethod *macMeth,
    CRYPT_MAC_AlgId *id)
{
    if (macCtx == NULL || macMeth == NULL || id == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    // free the old macCtx
    if (*macCtx != NULL) {
        if ((macMeth)->freeCtx == NULL) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        (macMeth)->freeCtx(*macCtx);
        *macCtx = NULL;
        (void)memset_s(macMeth, sizeof(EAL_MacMethod), 0, sizeof(EAL_MacMethod));
    }
    EAL_MacMethod *findMeth = EAL_MacFindMethod(inId, macMeth);
    if (findMeth == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_METH_NULL_MEMBER);
        return CRYPT_EAL_ERR_METH_NULL_MEMBER;
    }
    if (findMeth->newCtx == NULL) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *macCtx = findMeth->newCtx(libCtx, inId);
    if (*macCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    *id = inId;
    return CRYPT_SUCCESS;
}
#endif
