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
#if defined(HITLS_CRYPTO_PROVIDER) && defined(HITLS_CRYPTO_MD)
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_types.h"
#include "crypt_utils.h"
#include "bsl_params.h"

int32_t CRYPT_MdCommonGetParam(uint16_t mdSize, uint16_t mdBlockSize, BSL_Param *param)
{
    if (param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    int32_t ret = CRYPT_INVALID_ARG;
    BSL_Param *paramPtr = param;
    while (paramPtr->key != 0) {
        if (paramPtr->key == CRYPT_PARAM_MD_DIGEST_SIZE) {
            ret = BSL_PARAM_SetValue(paramPtr, CRYPT_PARAM_MD_DIGEST_SIZE, BSL_PARAM_TYPE_UINT16, &mdSize,
                sizeof(mdSize));
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
        } else if (paramPtr->key == CRYPT_PARAM_MD_BLOCK_SIZE) {
            ret = BSL_PARAM_SetValue(paramPtr, CRYPT_PARAM_MD_BLOCK_SIZE, BSL_PARAM_TYPE_UINT16, &mdBlockSize,
                sizeof(mdBlockSize));
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
        }
        paramPtr++;
    }
    return ret;
}
#endif
