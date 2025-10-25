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
#include "bsl_params.h"
#include "crypt_params_key.h"
#include "crypt_local_types.h"
#include "crypt_utils.h"

#if defined(HITLS_CRYPTO_RSA_VERIFY) || defined(HITLS_CRYPTO_RSA_SIGN) || defined(HITLS_CRYPTO_DSA) || \
    defined(HITLS_CRYPTO_ECDSA) || defined(HITLS_CRYPTO_SM2_SIGN)

typedef struct {
    CRYPT_MD_AlgId id;
    uint32_t mdSize;
} CRYPT_MdInfo;

uint32_t CRYPT_GetMdSizeById(CRYPT_MD_AlgId id)
{
    // need synchronize with enum CRYPT_MD_AlgId
    static CRYPT_MdInfo mdInfo[] = {
        {.id = CRYPT_MD_MD5,  .mdSize = 16},       // mdSize 16
        {.id = CRYPT_MD_SHA1, .mdSize = 20},      // mdSize 20
        {.id = CRYPT_MD_SHA224, .mdSize = 28},    // mdSize 28
        {.id = CRYPT_MD_SHA256, .mdSize = 32},    // mdSize 32
        {.id = CRYPT_MD_SHA384, .mdSize = 48},    // mdSize 48
        {.id = CRYPT_MD_SHA512, .mdSize = 64},    // mdSize 64
        {.id = CRYPT_MD_SHA3_224, .mdSize = 28},  // mdSize 28
        {.id = CRYPT_MD_SHA3_256, .mdSize = 32},  // mdSize 32
        {.id = CRYPT_MD_SHA3_384, .mdSize = 48},  // mdSize 48
        {.id = CRYPT_MD_SHA3_512, .mdSize = 64},  // mdSize 64
        {.id = CRYPT_MD_SHAKE128, .mdSize = 0},   // mdSize 0
        {.id = CRYPT_MD_SHAKE256, .mdSize = 0},   // mdSize 0
        {.id = CRYPT_MD_SM3,      .mdSize = 32},  // mdSize 32
        {.id = CRYPT_MD_MAX,      .mdSize = 0},   // mdSize 36
    };

    for (uint32_t i = 0; i < sizeof(mdInfo) / sizeof(mdInfo[0]); i++) {
        if (mdInfo[i].id == id) {
            return mdInfo[i].mdSize;
        }
    }
    return 0;
}
#endif

#if defined(HITLS_CRYPTO_DSA) || defined(HITLS_CRYPTO_ECDSA) || defined(HITLS_CRYPTO_SM2_SIGN)
int32_t CRYPT_SetSignMdCtrl(CRYPT_MD_AlgId *signMdId, void *val, uint32_t len, CheckSignMdCallBack checkSignMdIdCb)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != sizeof(CRYPT_MD_AlgId)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    if (checkSignMdIdCb != NULL) {
        int32_t ret = checkSignMdIdCb(val);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
    *signMdId = *(CRYPT_MD_AlgId *)val;
    return CRYPT_SUCCESS;
}

#endif

#define PARAM_MAX_NUMBER 1000

const BSL_Param *EAL_FindConstParam(const BSL_Param *param, int32_t key)
{
    if (key == 0) {
        BSL_ERR_PUSH_ERROR(BSL_PARAMS_INVALID_KEY);
        return NULL;
    }
    if (param == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return NULL;
    }
    int32_t index = 0;
    while (param[index].key != 0 && index < PARAM_MAX_NUMBER) {
        if (param[index].key == key) {
            return &param[index];
        }
        index++;
    }
    BSL_ERR_PUSH_ERROR(BSL_PARAMS_MISMATCH);
    return NULL;
}

BSL_Param *EAL_FindParam(BSL_Param *param, int32_t key)
{
    if (key == 0) {
        BSL_ERR_PUSH_ERROR(BSL_PARAMS_INVALID_KEY);
        return NULL;
    }
    if (param == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return NULL;
    }
    int32_t index = 0;
    while (param[index].key != 0 && index < PARAM_MAX_NUMBER) {
        if (param[index].key == key) {
            return &param[index];
        }
        index++;
    }
    BSL_ERR_PUSH_ERROR(BSL_PARAMS_MISMATCH);
    return NULL;
}
