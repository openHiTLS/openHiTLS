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
#if defined(HITLS_CRYPTO_ENTROPY) && defined(HITLS_CRYPTO_ENTROPY_SYS)

#include <stdint.h>
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_list.h"
#include "crypt_errno.h"
#include "crypt_entropy.h"
#include "crypt_eal_entropy.h"
#include "es_entropy_pool.h"
#include "es_cf.h"
#include "es_noise_source.h"

struct ES_Entropy {
    bool isWork; // Whether in working state
    bool enableTest; // Whether to enable the health test
    uint32_t poolSize; // Entropy pool size
    ES_EntropyPool *pool; // Entropy pool
    ES_CfMethod *cfMeth; // compression function handle
    BslList *nsList;
    CRYPT_EAL_EsLogFunc runLog;
};

#define ENTROPY_POOL_SIZE_DEFAULT 4096
#define ENTROPY_POOL_SIZE_MIN 512
#define ENTROPY_POOL_SIZE_MAX 4096

ENTROPY_EntropySource *ENTROPY_EsNew(void)
{
    ENTROPY_EntropySource *es = BSL_SAL_Malloc(sizeof(ENTROPY_EntropySource));
    if (es == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    (void)memset_s(es, sizeof(ENTROPY_EntropySource), 0, sizeof(ENTROPY_EntropySource));
    es->nsList = ES_NsListCreat();
    if (es->nsList == NULL) {
        BSL_SAL_Free(es);
        return NULL;
    }
    es->poolSize = ENTROPY_POOL_SIZE_DEFAULT;
    es->enableTest = false;
    return es;
}

void ENTROPY_EsFree(ENTROPY_EntropySource *es)
{
    if (es == NULL) {
        return;
    }
    if (es->isWork == true) {
        ENTROPY_EsDeinit(es);
    }
    BSL_SAL_FREE(es->cfMeth);
    ES_NsListFree(es->nsList);
    es->nsList = NULL;
    BSL_SAL_Free(es);
    return;
}

int32_t ENTROPY_EsInit(ENTROPY_EntropySource *es)
{
    if (es == NULL || es->cfMeth == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (es->isWork) {
        return CRYPT_SUCCESS;
    }
    ES_CfMethod *meth = es->cfMeth;
    if (meth->init != NULL) {
        meth->ctx = meth->init(&meth->meth);
        if (meth->ctx == NULL) {
            ENTROPY_EsDeinit(es);
            return CRYPT_ENTROPY_ES_CF_ERROR;
        }
    }
    int32_t ret = ES_NsListInit(es->nsList, es->enableTest);
    if (ret != CRYPT_SUCCESS) {
        ENTROPY_EsDeinit(es);
        return ret;
    }
    ES_EntropyPool *pool = ES_EntropyPoolInit(es->poolSize);
    if (pool == NULL) {
        ENTROPY_EsDeinit(es);
        return CRYPT_ENTROPY_ES_POOL_ERROR;
    }
    es->pool = pool;
    es->isWork = true;
    return CRYPT_SUCCESS;
}

void ENTROPY_EsDeinit(ENTROPY_EntropySource *es)
{
    if (es == NULL) {
        return;
    }
    es->isWork = false;
    ES_EntropyPoolDeInit(es->pool);
    es->pool = NULL;
    if (es->cfMeth != NULL && es->cfMeth->deinit != NULL) {
        es->cfMeth->deinit(es->cfMeth->ctx);
        es->cfMeth->ctx = NULL;
    }
    ES_NsListDeinit(es->nsList);
    return;
}
static int32_t EsPoolSizeSet(ENTROPY_EntropySource *es, void *data, uint32_t len)
{
    if (es->isWork) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ES_STATE_ERROR);
        return CRYPT_ENTROPY_ES_STATE_ERROR;
    }
    if (len != sizeof(uint32_t) || *(uint32_t *)data < ENTROPY_POOL_SIZE_MIN ||
        *(uint32_t *)data > ENTROPY_POOL_SIZE_MAX) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_CTRL_INVALID_PARAM);
        return CRYPT_ENTROPY_CTRL_INVALID_PARAM;
    }
    es->poolSize = *(uint32_t *)data;
    return CRYPT_SUCCESS;
}

static int32_t EsNsAdd(ENTROPY_EntropySource *es, void *data, uint32_t len)
{
    if (es->isWork) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ES_STATE_ERROR);
        return CRYPT_ENTROPY_ES_STATE_ERROR;
    }
    if (data == NULL || len != sizeof(CRYPT_EAL_NsPara)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_EAL_NsPara *para = (CRYPT_EAL_NsPara *)data;
    return ES_NsAdd(es->nsList, para->name, para->autoTest, para->minEntropy, &para->nsMeth,
        (const CRYPT_EAL_NsTestPara *)&(para->nsPara));
}

static int32_t EsEnableTest(ENTROPY_EntropySource *es, void *data, uint32_t len)
{
    if (es->isWork) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ES_STATE_ERROR);
        return CRYPT_ENTROPY_ES_STATE_ERROR;
    }
    if (data == NULL || len != sizeof(bool)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    es->enableTest = *(bool *)data;
    return CRYPT_SUCCESS;
}

static int32_t EsNsRemove(ENTROPY_EntropySource *es, void *data, uint32_t len)
{
    if (es->isWork) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ES_STATE_ERROR);
        return CRYPT_ENTROPY_ES_STATE_ERROR;
    }
    if (data == NULL || len == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return ES_NsRemove(es->nsList, (const char *)data);
}

static int32_t EsSetCF(ENTROPY_EntropySource *es, ENTROPY_CFPara *data)
{
    if (es->isWork) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ES_STATE_ERROR);
        return CRYPT_ENTROPY_ES_STATE_ERROR;
    }
    if (es->cfMeth != NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ES_CF_ERROR);
        return CRYPT_ENTROPY_ES_CF_ERROR;
    }
    es->cfMeth = ES_CFGetMethod(data->algId, data->md);
    if (es->cfMeth == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ES_CF_NOT_SUPPORT);
        return CRYPT_ENTROPY_ES_CF_NOT_SUPPORT;
    }
    return CRYPT_SUCCESS;
}

static int32_t EsGetSize(ENTROPY_EntropySource *es, int32_t cmd, void *data, uint32_t len)
{
    if (data == NULL || len != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (!es->isWork) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ES_STATE_ERROR);
        return CRYPT_ENTROPY_ES_STATE_ERROR;
    }
    switch (cmd) {
        case CRYPT_ENTROPY_GET_POOL_SIZE:
            *(uint32_t *)data = es->poolSize;
            return CRYPT_SUCCESS;
        case CRYPT_ENTROPY_POOL_GET_CURRSIZE:
            *(uint32_t *)data = ES_EntropyPoolGetCurSize(es->pool);
            return CRYPT_SUCCESS;
        case CRYPT_ENTROPY_GET_CF_SIZE:
            *(uint32_t *)data = es->cfMeth->getCfOutLen(es->cfMeth->ctx);
            return CRYPT_SUCCESS;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ES_CTRL_ERROR);
            return CRYPT_ENTROPY_ES_CTRL_ERROR;
    }
}
static int32_t EsGetState(ENTROPY_EntropySource *es, void *data, uint32_t len)
{
    if (data == NULL || len != sizeof(bool)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    *(bool *)data = es->isWork;
    return CRYPT_SUCCESS;
}

static int32_t EsSetLogCallback(ENTROPY_EntropySource *es, void *data, uint32_t len)
{
    (void)len;
    if (es == NULL || data == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    es->runLog = (CRYPT_EAL_EsLogFunc)data;
    return CRYPT_SUCCESS;
}

int32_t ENTROPY_EsCtrl(ENTROPY_EntropySource *es, int32_t cmd, void *data, uint32_t len)
{
    if (es == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (cmd) {
        case CRYPT_ENTROPY_SET_POOL_SIZE:
            return EsPoolSizeSet(es, data, len);
        case CRYPT_ENTROPY_ADD_NS:
            return EsNsAdd(es, data, len);
        case CRYPT_ENTROPY_REMOVE_NS:
            return EsNsRemove(es, data, len);
        case CRYPT_ENTROPY_ENABLE_TEST:
            return EsEnableTest(es, data, len);
        case CRYPT_ENTROPY_SET_CF:
            return EsSetCF(es, data);
        case CRYPT_ENTROPY_GET_STATE:
            return EsGetState(es, data, len);
        case CRYPT_ENTROPY_SET_LOG_CALLBACK:
            return EsSetLogCallback(es, data, len);
        default:
            return EsGetSize(es, cmd, data, len);
    }
}

uint32_t ENTROPY_EsEntropyGet(ENTROPY_EntropySource *es, uint8_t *data, uint32_t len)
{
    if (es == NULL || !es->isWork || data == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return 0;
    }
    if (ES_EntropyPoolGetCurSize(es->pool) <= 0) {
        int32_t ret = ENTROPY_EsEntropyGather(es);
        if (ret != CRYPT_SUCCESS) {
            return 0;
        }
    }
    return ES_EntropyPoolPopBytes(es->pool, data, len);
}

static uint32_t EsGetEntropy(ENTROPY_EntropySource *es, uint8_t *buf, uint32_t bufLen, uint32_t entropy)
{
    ES_NoiseSource *ns = NULL;
    uint32_t needLen = 0;
    uint32_t curEntropy = 0;
    uint8_t *data = buf;
    while (curEntropy < entropy) {
        uint32_t tmpEntropy = curEntropy;
        for (ns = BSL_LIST_GET_FIRST(es->nsList); ns != NULL && needLen < bufLen; ns = BSL_LIST_GET_NEXT(es->nsList)) {
            int32_t ret = ES_NsRead(ns, data, 1);
            if (ret == CRYPT_SUCCESS) {
                data++;
                needLen++;
                curEntropy += ns->minEntropy;
            }
            if (es->runLog != NULL) {
                es->runLog(ret);
            }
            if (curEntropy >= entropy) {
                break;
            }
        }
        if (curEntropy == tmpEntropy) {
            BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ES_NS_NOT_AVA);
            needLen = 0;
            break;
        }
    }
    return needLen;
}

static uint32_t GetMinLen(uint32_t entropy, uint32_t minEntropy)
{
    return (uint32_t)(((uint64_t)entropy + (uint64_t)minEntropy - 1) / (uint64_t)minEntropy);
}

int32_t ENTROPY_EsEntropyGather(ENTROPY_EntropySource *es)
{
    if (es == NULL || es->isWork == false || es->cfMeth == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    ES_CfMethod *meth = es->cfMeth;
    if ((meth->getCfOutLen(meth->ctx) > (uint32_t)ES_EntropyPoolGetMaxSize(es->pool) -
        ES_EntropyPoolGetCurSize(es->pool))) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ES_POOL_INSUFFICIENT);
        return CRYPT_ENTROPY_ES_POOL_INSUFFICIENT;
    }
    uint32_t minEntropy = ES_NsListGetMinEntropy(es->nsList);
    uint32_t needEntropy = meth->getNeedEntropy(meth->ctx);
    uint32_t bufLen = GetMinLen(needEntropy, minEntropy);
    uint8_t *buf = BSL_SAL_Malloc(bufLen);
    if (buf == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    uint32_t needLen = EsGetEntropy(es, buf, bufLen, needEntropy);
    if (needLen == 0) {
        BSL_SAL_Free(buf);
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ES_ENTROPY_NOT_ENOUGH);
        return CRYPT_ENTROPY_ES_ENTROPY_NOT_ENOUGH;
    }
    int32_t ret = meth->update(meth->ctx, buf, needLen);
    BSL_SAL_Free(buf);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint32_t len;
    uint8_t *data = meth->getEntropyData(meth->ctx, &len);
    if (data == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = ES_EntropyPoolPushBytes(es->pool, data, len);
    (void)memset_s(data, len, 0, len);
    BSL_SAL_Free(data);
    return ret;
}
#endif