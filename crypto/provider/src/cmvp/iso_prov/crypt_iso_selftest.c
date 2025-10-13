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

#include "securec.h"
#include "crypt_types.h"
#include "crypt_errno.h"
#include "crypt_iso_provider.h"
#include "bsl_params.h"
#include "bsl_err_internal.h"
#include "cmvp_iso19790.h"
#include "crypt_cmvp_selftest.h"
#include "crypt_params_key.h"
#include "cmvp_common.h"
#include "crypt_iso_selftest.h"

#define BSL_PARAM_COUNT 4

int32_t CRYPT_Iso_Log(void *provCtx, CRYPT_EVENT_TYPE event, CRYPT_ALGO_TYPE type, int32_t id)
{
    int32_t algId = id;
    int32_t algType = type;
    int index = 0;
    BSL_Param param[BSL_PARAM_COUNT] = {{0}, {0}, {0}, BSL_PARAM_END};
    (void)BSL_PARAM_InitValue(&param[index++], CRYPT_PARAM_EVENT, BSL_PARAM_TYPE_INT32, &event, sizeof(event));
    (void)BSL_PARAM_InitValue(&param[index++], CRYPT_PARAM_ALGID, BSL_PARAM_TYPE_INT32, &algId, sizeof(algId));
    (void)BSL_PARAM_InitValue(&param[index++], CRYPT_PARAM_ALGO_TYPE, BSL_PARAM_TYPE_INT32, &algType, sizeof(algType));
    return CRYPT_Iso_EventOperation(provCtx, param);
}

static void IsoRunLog(void *provCtx, CRYPT_EVENT_TYPE oper, CRYPT_ALGO_TYPE type, int32_t id, int32_t err)
{
    if (provCtx == NULL || ((CRYPT_EAL_IsoProvCtx *)provCtx)->runLog == NULL) {
        return;
    }
    ((CRYPT_EAL_IsoProvCtx *)provCtx)->runLog(oper, type, id, err);
}

static int32_t IsoLogEvent(CRYPT_EVENT_TYPE event, void *provCtx, BSL_Param *param, int32_t ret)
{
    BSL_Param *temp = BSL_PARAM_FindParam(param, CRYPT_PARAM_ALGID);
    if (temp == NULL || temp->valueType != BSL_PARAM_TYPE_INT32) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t id = *(int32_t *)(uintptr_t)temp->value;
    
    temp = BSL_PARAM_FindParam(param, CRYPT_PARAM_ALGO_TYPE);
    if (temp == NULL || temp->valueType != BSL_PARAM_TYPE_INT32) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t type = *(int32_t *)(uintptr_t)temp->value;
    IsoRunLog(provCtx, event, type, id, ret);
    return CRYPT_SUCCESS;
}

static int32_t IsoIntegrityTest(void *provCtx, BSL_Param *param)
{
    void *libCtx = NULL;
    BSL_Param *temp = BSL_PARAM_FindParam(param, CRYPT_PARAM_LIB_CTX);
    int32_t ret = BSL_PARAM_GetPtrValue(temp, CRYPT_PARAM_LIB_CTX, BSL_PARAM_TYPE_CTX_PTR, &libCtx, NULL);
    if (ret != BSL_SUCCESS || libCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    IsoRunLog(provCtx, CRYPT_EVENT_INTEGRITY_TEST, 0, 0, CRYPT_SUCCESS);
    ret = CMVP_Iso19790CheckIntegrity(libCtx, CRYPT_EAL_ISO_ATTR);
    if (ret != CRYPT_SUCCESS) {
        IsoRunLog(provCtx, CRYPT_EVENT_INTEGRITY_TEST, 0, 0, ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

static int32_t IsoKatTest(void *provCtx, BSL_Param *param)
{
    void *libCtx = NULL;
    BSL_Param *temp = BSL_PARAM_FindParam(param, CRYPT_PARAM_LIB_CTX);
    int32_t ret = BSL_PARAM_GetPtrValue(temp, CRYPT_PARAM_LIB_CTX, BSL_PARAM_TYPE_CTX_PTR, &libCtx, NULL);
    if (ret != BSL_SUCCESS || libCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    IsoRunLog(provCtx, CRYPT_EVENT_KAT_TEST, 0, 0, CRYPT_SUCCESS);
    ret = CMVP_Iso19790Kat(libCtx, CRYPT_EAL_ISO_ATTR);
    if (ret != CRYPT_SUCCESS) {
        IsoRunLog(provCtx, CRYPT_EVENT_KAT_TEST, 0, 0, ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_Iso_EventOperation(void *provCtx, BSL_Param *param)
{
    BSL_Param *temp = BSL_PARAM_FindParam(param, CRYPT_PARAM_EVENT);
    if (temp == NULL || temp->valueType != BSL_PARAM_TYPE_INT32) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t event = *(int32_t *)(uintptr_t)temp->value;
    switch (event) {
        case CRYPT_EVENT_KAT_TEST:
            return IsoKatTest(provCtx, param);
        case CRYPT_EVENT_INTEGRITY_TEST:
            return IsoIntegrityTest(provCtx, param);
        case CRYPT_EVENT_PARAM_CHECK:
            return IsoLogEvent(event, provCtx, param, CRYPT_CMVP_ERR_PARAM_CHECK);
        case CRYPT_EVENT_ENC:
        case CRYPT_EVENT_DEC:
        case CRYPT_EVENT_GEN:
        case CRYPT_EVENT_SIGN:
        case CRYPT_EVENT_VERIFY:
        case CRYPT_EVENT_MD:
        case CRYPT_EVENT_MAC:
        case CRYPT_EVENT_KDF:
        case CRYPT_EVENT_KEYAGGREMENT:
        case CRYPT_EVENT_RANDGEN:
        case CRYPT_EVENT_ZERO:
        case CRYPT_EVENT_SETSSP:
        case CRYPT_EVENT_GETSSP:
        case CRYPT_EVENT_ENCAPS:
        case CRYPT_EVENT_DECAPS:
        case CRYPT_EVENT_BLIND:
        case CRYPT_EVENT_UNBLIND:
        case CRYPT_EVENT_PCT_TEST:
        case CRYPT_EVENT_GET_VERSION:
            return IsoLogEvent(event, provCtx, param, CRYPT_SUCCESS);
        default:
            break;
    }
    return CRYPT_NOT_SUPPORT;
}

int32_t CRYPT_Iso_GetLogFunc(BSL_Param *param, CRYPT_EAL_CMVP_LogFunc *logFunc)
{
    int32_t ret = CRYPT_SUCCESS;
    BSL_Param *temp = BSL_PARAM_FindParam(param, CRYPT_PARAM_CMVP_LOG_FUNC);
    if (temp == NULL) {
        *logFunc = CMVP_Iso19790EventProcess;
        return CRYPT_SUCCESS;
    }
    ret = BSL_PARAM_GetPtrValue(temp, CRYPT_PARAM_CMVP_LOG_FUNC, BSL_PARAM_TYPE_FUNC_PTR, (void **)logFunc, NULL);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (*logFunc == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_Iso_Selftest(BSL_Param *param)
{
    CRYPT_EAL_LibCtx *libCtx = NULL;
    if (CMVP_CheckIsInternalLibCtx(param)) {
        return CRYPT_SUCCESS;
    }
    int32_t ret = CMVP_CreateInternalLibCtx(param, &libCtx, CRYPT_Iso_Selftest);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    CRYPT_EAL_CMVP_LogFunc runLog = NULL;
    ret = CRYPT_Iso_GetLogFunc(param, &runLog);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_LibCtxFree(libCtx);
        return ret;
    }
    runLog(CRYPT_EVENT_INTEGRITY_TEST, 0, 0, CRYPT_SUCCESS);
    ret = CMVP_Iso19790CheckIntegrity(libCtx, CRYPT_EAL_ISO_ATTR);
    if (ret != CRYPT_SUCCESS) {
        runLog(CRYPT_EVENT_INTEGRITY_TEST, 0, 0, ret);
        CRYPT_EAL_LibCtxFree(libCtx);
        return ret;
    }

    runLog(CRYPT_EVENT_KAT_TEST, 0, 0, CRYPT_SUCCESS);
    ret = CMVP_Iso19790Kat(libCtx, CRYPT_EAL_ISO_ATTR);
    CRYPT_EAL_LibCtxFree(libCtx);
    if (ret != CRYPT_SUCCESS) {
        runLog(CRYPT_EVENT_KAT_TEST, 0, 0, ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

#endif /* HITLS_CRYPTO_CMVP_ISO19790 */