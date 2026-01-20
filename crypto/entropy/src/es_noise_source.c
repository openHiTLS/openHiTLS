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
#include "crypt_errno.h"
#include "bsl_list_internal.h"
#include "bsl_err_internal.h"
#include "es_noise_source.h"

#define ES_NS_MAX_SIZE 16
#define ES_MIN_ENTROPY_MAX 8
/* Noise source non-blocking reading. Set the maximum reading time to 10s. */
#define ES_MAX_TIMEOUT_MAX 10

static int32_t NsRead(ES_NoiseSource *ns, uint8_t *buf, uint32_t bufLen);
/*
 * GM/T 0105-2021 Section 5.5
 * The Power-Up Health Test requires a continuous health test of at least 1024 consecutive samples.
 */
#define ENTROPY_START_UP_TEST_SIZE 1024
int32_t ES_NoiseSourceStartupTest(ES_NoiseSource *ns)
{
    uint8_t buf[ENTROPY_START_UP_TEST_SIZE] = {0};
    return NsRead(ns, buf, ENTROPY_START_UP_TEST_SIZE);
}

static ES_NoiseSource *ES_NsCreate(const char *name, bool autoTest, uint32_t minEntropy,
    const CRYPT_EAL_NsMethod *method, const CRYPT_EAL_NsTestPara *para)
{
    ES_NoiseSource *ctx = BSL_SAL_Malloc(sizeof(ES_NoiseSource));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    (void)memset_s(ctx, sizeof(ES_NoiseSource), 0, sizeof(ES_NoiseSource));
    uint32_t len = strlen(name) + 1;
    ctx->name = BSL_SAL_Malloc(len);
    if (ctx->name == NULL) {
        BSL_SAL_FREE(ctx);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    (void)strncpy_s(ctx->name, len, name, len - 1);
    // Initializing
    ctx->autoTest = autoTest;
    ctx->para = method->para;
    ctx->init = method->init;
    ctx->read = method->read;
    ctx->deinit = method->deinit;
    ctx->minEntropy = minEntropy;
    ctx->state.rctCutoff = para->rctCutoff;
    ctx->state.aptCutOff = para->aptCutoff;
    ctx->state.aptWindowSize = para->aptWinSize;
    return ctx;
}

static void ES_NsFree(ES_NoiseSource *ns)
{
    if (ns->usrdata != NULL && ns->deinit != NULL) {
        ns->deinit(ns->usrdata);
    }
    BSL_SAL_FREE(ns->name);
    BSL_SAL_Free(ns);
    return;
}

BslList *ES_NsListCreat(void)
{
    BslList *ns = BSL_LIST_New(sizeof(BslListNode));
    if (ns == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_LIST_MALLOC_FAIL);
        return NULL;
    }
    int32_t ret;

#ifndef HITLS_BSL_SAL_DARWIN
    /* TODO: Enable CPU Jitter on Darwin after Currently not supported
     * 1. Disabled on macOS because health test thresholds (RCT/APT) need adjustment
     * 2. Jitter is platform-independent in theory but requires per-platform validation
     */
    ES_NoiseSource *jitterCtx = ES_CpuJitterGetCtx();
    if (jitterCtx == NULL) {
        goto ERR;
    }
    ret = BSL_LIST_AddElement(ns, jitterCtx, BSL_LIST_POS_AFTER);
    if (ret != CRYPT_SUCCESS) {
        ES_NsFree(jitterCtx);
        goto ERR;
    }
#endif

    ES_NoiseSource *stampCtx = ES_TimeStampGetCtx();
    if (stampCtx == NULL) {
        goto ERR;
    }
    ret = BSL_LIST_AddElement(ns, stampCtx, BSL_LIST_POS_AFTER);
    if (ret != CRYPT_SUCCESS) {
        ES_NsFree(stampCtx);
        goto ERR;
    }
    return ns;
ERR:
    BSL_LIST_FREE(ns, (BSL_LIST_PFUNC_FREE)ES_NsFree);
    return NULL;
}

int32_t ES_NsListInit(BslList *nsList, bool enableTest)
{
    if (BSL_LIST_COUNT(nsList) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ES_NO_NS);
        return CRYPT_ENTROPY_ES_NO_NS;
    }
    bool nsUsed = false;
    ES_NoiseSource *ns = NULL;
    BSL_ERR_SET_MARK();
    for (ns = BSL_LIST_GET_FIRST(nsList); ns != NULL; ns = BSL_LIST_GET_NEXT(nsList)) {
        /*
         * If the health check is automatically performed when the noise source is generated, no additional health
         * check is required. Otherwise, determine whether to perform the health check based on the configuration.
         */
        ns->enableTest = (ns->autoTest) ? false : enableTest;
        if (ns->init != NULL) {
            ns->usrdata = ns->init(ns->para);
            if (ns->usrdata == NULL) {
                ns->isEnable = false;
                continue;
            }
        }
        ns->isInit = true;
        if (enableTest) {
            int32_t ret = ES_NoiseSourceStartupTest(ns);
            if (ret != CRYPT_SUCCESS) {
                ns->isEnable = false;
                BSL_ERR_PUSH_ERROR(ret);
                continue;
            }
        }
        ns->isEnable = true;
        nsUsed = true;
    }
    if (!nsUsed) {
        ES_NsListDeinit(nsList);
        return CRYPT_ENTROPY_ES_NO_NS;
    }
    BSL_ERR_POP_TO_MARK();
    return CRYPT_SUCCESS;
}

void ES_NsListDeinit(BslList *nsList)
{
    if (BSL_LIST_COUNT(nsList) == 0) {
        return;
    }
    ES_NoiseSource *ns = NULL;
    for (ns = BSL_LIST_GET_FIRST(nsList); ns != NULL; ns = BSL_LIST_GET_NEXT(nsList)) {
        ns->isInit = false;
        ns->isEnable = false;
        if (ns->deinit != NULL) {
            ns->deinit(ns->usrdata);
            ns->usrdata = NULL;
        }
    }
    return;
}

void ES_NsListFree(BslList *nsList)
{
    BSL_LIST_FREE(nsList, (BSL_LIST_PFUNC_FREE)ES_NsFree);
}

static int32_t ES_NsComp(const ES_NoiseSource *ns, const char *name)
{
    return strcmp(ns->name, name);
}

int32_t ES_NsAdd(BslList *nsList, const char *name, bool autoTest, uint32_t minEntropy,
    const CRYPT_EAL_NsMethod *method, const CRYPT_EAL_NsTestPara *para)
{
    if (name == NULL || minEntropy > ES_MIN_ENTROPY_MAX) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (method->read == NULL || (method->init == NULL && method->deinit != NULL) ||
        (method->init != NULL && method->deinit == NULL)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (BSL_LIST_COUNT(nsList) >= ES_NS_MAX_SIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ES_NS_FULL);
        return CRYPT_ENTROPY_ES_NS_FULL;
    }
    if (BSL_LIST_SearchEx(nsList, name, (BSL_LIST_PFUNC_CMP)ES_NsComp) != NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ES_DUP_NS);
        return CRYPT_ENTROPY_ES_DUP_NS;
    }
    ES_NoiseSource *ns = ES_NsCreate(name, autoTest, minEntropy, method, para);
    if (ns == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ES_CREATE_ERROR);
        return CRYPT_ENTROPY_ES_CREATE_ERROR;
    }
    int32_t ret = BSL_LIST_AddElement(nsList, ns, BSL_LIST_POS_AFTER);
    if (ret != CRYPT_SUCCESS) {
        ES_NsFree(ns);
    }
    return ret;
}

int32_t ES_NsRemove(BslList *nsList, const char *name)
{
    BslListNode *tmpNode = NULL;
    for (BslListNode *node = BSL_LIST_FirstNode(nsList); node != NULL;) {
        tmpNode = node;
        ES_NoiseSource *ns = BSL_LIST_GetData(tmpNode);
        if (ns == NULL) {
            continue;
        }
        if (strcmp(ns->name, name) == 0) {
            BSL_LIST_DeleteNode(nsList, (const BslListNode *)tmpNode, (BSL_LIST_PFUNC_FREE)ES_NsFree);
            return CRYPT_SUCCESS;
        }
        node = BSL_LIST_GetNextNode(nsList, tmpNode);
    }
    BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ES_NS_NOT_FOUND);
    return CRYPT_ENTROPY_ES_NS_NOT_FOUND;
}

static int32_t NsRead(ES_NoiseSource *ns, uint8_t *buf, uint32_t bufLen)
{
    int32_t ret = ns->read(ns->usrdata, ES_MAX_TIMEOUT_MAX, buf, bufLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (!ns->enableTest) {
        return CRYPT_SUCCESS;
    }
    for (uint32_t iter = 0; iter < bufLen; iter++) {
        ret = ES_HealthTestRct(&(ns->state), buf[iter]);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        ret = ES_HealthTestApt(&(ns->state), buf[iter]);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
    return ret;
}

int32_t ES_NsRead(ES_NoiseSource *ns, uint8_t *buf, uint32_t bufLen)
{
    if (ns->isInit != true || ns->isEnable != true) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ES_NS_NOT_AVA);
        return CRYPT_ENTROPY_ES_NS_NOT_AVA;
    }

    return NsRead(ns, buf, bufLen);
}

uint32_t ES_NsListGetMinEntropy(BslList *nsList)
{
    if (BSL_LIST_COUNT(nsList) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ES_NO_NS);
        return 0;
    }
    uint32_t minEntropy = 8;
    ES_NoiseSource *ns = NULL;
    for (ns = BSL_LIST_GET_FIRST(nsList); ns != NULL; ns = BSL_LIST_GET_NEXT(nsList)) {
        minEntropy = (ns->minEntropy < minEntropy) ? ns->minEntropy : minEntropy;
    }
    return minEntropy;
}
#endif
