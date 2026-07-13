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
#include <string.h>
#include "crypt_errno.h"
#include "bsl_list.h"
#include "bsl_err_internal.h"
#include "es_noise_source.h"

#define ES_MIN_ENTROPY_MAX 8

/* Noise source non-blocking reading. Set the maximum reading time to 10s. */
#define ES_MAX_TIMEOUT_MAX 10

static int32_t NsRead(ES_NoiseSource *ns, uint8_t *buf, uint32_t bufLen);
int32_t ES_NoiseSourceStartupTest(ES_NoiseSource *ns)
{
    uint8_t buf[ES_STARTUP_TEST_SAMPLES] = {0};
    /* The window is ES_STARTUP_TEST_SAMPLES sample records; record widths
       divide the buffer, so every chunk stays record-aligned. */
    uint32_t recordBytes = ns->sampleBytes;
    uint64_t remaining = (uint64_t)ES_STARTUP_TEST_SAMPLES * recordBytes;
    int32_t ret = CRYPT_SUCCESS;
    while (remaining > 0 && ret == CRYPT_SUCCESS) {
        uint32_t chunk = remaining > sizeof(buf) ? (uint32_t)sizeof(buf) : (uint32_t)remaining;
        ret = NsRead(ns, buf, chunk);
        remaining -= chunk;
    }
    BSL_SAL_CleanseData(buf, sizeof(buf));
    return ret;
}

static ES_NoiseSource *ES_NsCreate(const char *name, bool autoTest, uint32_t claimBitsPerOsr,
                                   const CRYPT_EAL_NsMethod *method, const CRYPT_EAL_NsTestPara *para)
{
    ES_NoiseSource *ctx = BSL_SAL_Malloc(sizeof(ES_NoiseSource));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    memset(ctx, 0, sizeof(ES_NoiseSource));
    uint32_t len = strlen(name) + 1;
    ctx->name = BSL_SAL_Malloc(len);
    if (ctx->name == NULL) {
        BSL_SAL_FREE(ctx);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    strcpy(ctx->name, name);
    ctx->autoTest = autoTest;
    ctx->para = method->para;
    ctx->init = method->init;
    ctx->read = method->read;
    ctx->deinit = method->deinit;
    ctx->sampleBytes = 1;
    ctx->claimBitsPerOsr = claimBitsPerOsr;
    /* Externally registered sources are credited when they declare a positive entropy rate. */
    ctx->credited = (claimBitsPerOsr > 0);
    ctx->state.rct.cutoff = para->rctCutoff;
    ctx->state.apt.cutoff = para->aptCutoff;
    ctx->state.apt.windowSize = para->aptWinSize;
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
#ifdef HITLS_CRYPTO_ENTROPY_NS_CPUJITTER
    ES_NoiseSource *jitterCtx = ES_CpuJitterGetCtx();
    if (jitterCtx == NULL) {
        goto ERR;
    }
    if (BSL_LIST_AddElement(ns, jitterCtx, BSL_LIST_POS_END) != CRYPT_SUCCESS) {
        ES_NsFree(jitterCtx);
        goto ERR;
    }
#endif

#ifdef HITLS_CRYPTO_ENTROPY_NS_HASHLOOP
    ES_NoiseSource *hashLoopCtx = ES_HashLoopGetCtx();
    if (hashLoopCtx == NULL) {
        goto ERR;
    }
    if (BSL_LIST_AddElement(ns, hashLoopCtx, BSL_LIST_POS_END) != CRYPT_SUCCESS) {
        ES_NsFree(hashLoopCtx);
        goto ERR;
    }
#endif
    return ns;
#if defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) || defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP)
ERR:
    BSL_LIST_FREE(ns, (BSL_LIST_PFUNC_FREE)ES_NsFree);
    return NULL;
#endif
}

static void NsOsrReadback(ES_NoiseSource *ns)
{
    if (ns->osrGet != NULL) {
        uint32_t osr = ns->osrGet(ns->usrdata);
        /* The instance ladder ceiling bounds the readback. */
        if (osr >= 1 && osr <= ns->osrMax && ns->initAt != NULL && osr > ns->osr) {
            ns->osr = osr;
        }
    }
}

bool ES_NsOsrDemote(ES_NoiseSource *ns)
{
    if (ns->initAt == NULL || ns->osr >= ns->osrMax) {
        return false;
    }
    ns->osr++;
    return true;
}

/* Initialize one source. With initAt, the source walks the osr ladder upward
   from the instance rate internally on one calibrated state and the settled
   rate comes back through NsOsrReadback. */
static int32_t NsSourceInit(ES_NoiseSource *ns)
{
    if (ns->initAt != NULL) {
        return ns->initAt(ns->para, ns->osr, &ns->usrdata);
    }
    ns->usrdata = ns->init(ns->para);
    if (ns->usrdata == NULL) {
        return CRYPT_ENTROPY_ES_NS_NOT_AVA;
    }
    return CRYPT_SUCCESS;
}

/* One full init cycle for one source: instance init (adaptive sources walk
   the claim ladder internally) plus the authoritative startup window,
   re-initialized from a lowered ceiling until the window passes or the
   ladder is exhausted. */
static int32_t NsCycleInit(ES_NoiseSource *ns, bool enableTest)
{
    /* Record geometry is a construction-time contract: a nonzero width
       that divides the startup window keeps every chunk record-aligned. */
    if (ns->sampleBytes == 0 || (ES_STARTUP_TEST_SAMPLES % ns->sampleBytes) != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ES_NS_NOT_AVA);
        return CRYPT_ENTROPY_ES_NS_NOT_AVA;
    }
    /* And a fresh RCT/APT window: no run or proportion state may leak in
       from a previous instance of this record. */
    ES_HealthTestReset(&ns->state);
    /*
     * If the health check is automatically performed when the noise source is generated, no additional health
     * check is required. Otherwise, determine whether to perform the health check based on the configuration.
     */
    ns->enableTest = (ns->autoTest) ? false : enableTest;
    if (ns->init != NULL || ns->initAt != NULL) {
        int32_t initRet = NsSourceInit(ns);
        if (initRet != CRYPT_SUCCESS) {
            return initRet;
        }
    }
    ns->isInit = true;
    NsOsrReadback(ns);
    if (!enableTest) {
        return CRYPT_SUCCESS;
    }
    int32_t ret = ES_NoiseSourceStartupTest(ns);
    /* The 1024-byte startup test is the authoritative verification
       window: an adaptive source that settled on a marginal rate is
       re-initialized at a raised osr until the window passes or the
       ladder is exhausted. */
    while (ES_NsVerdictDemotes(ret) && ES_NsOsrDemote(ns)) {
        if (ns->deinit != NULL) {
            ns->deinit(ns->usrdata);
            ns->usrdata = NULL;
        }
        ES_HealthTestReset(&ns->state);
        int32_t initRet = NsSourceInit(ns);
        if (initRet != CRYPT_SUCCESS) {
            return initRet;
        }
        NsOsrReadback(ns);
        ret = ES_NoiseSourceStartupTest(ns);
    }
    return ret;
}

int32_t ES_NsListInit(BslList *nsList, bool enableTest)
{
    if (BSL_LIST_COUNT(nsList) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ES_NO_NS);
        return CRYPT_ENTROPY_ES_NO_NS;
    }
    bool nsUsed = false;
    bool allPermanent = true;
    int32_t structuralRet = CRYPT_SUCCESS;
    int32_t cycleRet = CRYPT_SUCCESS;
    /* Credited verdict: a permanent retirement is terminal and overrides any
       earlier transient credited error, independent of registration order;
       among non-permanent errors the first one wins. */
    int32_t creditedRet = CRYPT_SUCCESS;
    for (BslListNode *node = BSL_LIST_FirstNode(nsList); node != NULL; node = BSL_LIST_GetNextNode(nsList, node)) {
        ES_NoiseSource *ns = BSL_LIST_GetData(node);
        if (ns->permanentFailure) {
            if (ns->credited) {
                creditedRet = CRYPT_ENTROPY_ES_PERMANENT_FAILURE;
            }
            continue;
        }
        int32_t ret = NsCycleInit(ns, enableTest);
        if (ret == CRYPT_SUCCESS) {
            ns->floorFailStreak = 0;
            /* A fresh startup timer check supersedes any pending recovery:
               drop the suspension, probation and streak so a
               reinitialized source starts clean. */
            ns->needRecovery = false;
            ns->onProbation = false;
            ns->recoveryFailStreak = 0;
            ns->isEnable = true;
            nsUsed = true;
            allPermanent = false;
            continue;
        }
        ns->isEnable = false;
        if (ret < 0) {
            /* Private negative encodings from init paths stop here; the list
               boundary speaks CRYPT_* verdicts only. */
            ret = CRYPT_ENTROPY_ES_NS_NOT_AVA;
        }
        bool recordsCreditedRet = ns->credited && creditedRet == CRYPT_SUCCESS;
        if (recordsCreditedRet) {
            creditedRet = ret;
        }
        if (ES_NsVerdictRetires(ret)) {
            ES_NsRetire(ns);
            if (ns->credited) {
                creditedRet = CRYPT_ENTROPY_ES_PERMANENT_FAILURE;
            }
            if (structuralRet == CRYPT_SUCCESS) {
                structuralRet = ret;
            }
            continue;
        }
        if (ns->initAt != NULL && ES_NsVerdictDemotes(ret)) {
            /* Walk exhaustion or an authoritative window failure after the
               ladder topped out: floor-level health evidence. */
            ns->osr = ns->osrMax;
            if (++ns->floorFailStreak >= NS_PERMANENT_FAIL_STREAK) {
                ES_NsRetire(ns);
                if (ns->credited) {
                    creditedRet = CRYPT_ENTROPY_ES_PERMANENT_FAILURE;
                }
                continue;
            }
        }
        allPermanent = false;
        if (cycleRet == CRYPT_SUCCESS) {
            cycleRet = ret;
        }
    }
    if (nsUsed && creditedRet == CRYPT_SUCCESS) {
        return CRYPT_SUCCESS;
    }

    int32_t ret;
    if (nsUsed) {
        ret = creditedRet;
    } else if (structuralRet != CRYPT_SUCCESS) {
        ret = structuralRet;
    } else if (allPermanent) {
        ret = CRYPT_ENTROPY_ES_PERMANENT_FAILURE;
    } else if (creditedRet != CRYPT_SUCCESS) {
        ret = creditedRet;
    } else if (cycleRet != CRYPT_SUCCESS) {
        ret = cycleRet;
    } else {
        ret = CRYPT_ENTROPY_ES_NO_NS;
    }
    ES_NsListDeinit(nsList);
    BSL_ERR_PUSH_ERROR(ret);
    return ret;
}

void ES_NsListDeinit(BslList *nsList)
{
    if (BSL_LIST_COUNT(nsList) == 0) {
        return;
    }
    for (BslListNode *node = BSL_LIST_FirstNode(nsList); node != NULL; node = BSL_LIST_GetNextNode(nsList, node)) {
        ES_NoiseSource *ns = BSL_LIST_GetData(node);
        ns->isInit = false;
        ns->isEnable = false;
        if (ns->usrdata != NULL && ns->deinit != NULL) {
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

int32_t ES_NsAdd(BslList *nsList, const char *name, bool autoTest, uint32_t claimBitsPerOsr,
                 const CRYPT_EAL_NsMethod *method, const CRYPT_EAL_NsTestPara *para)
{
    if (name == NULL || claimBitsPerOsr > ES_MIN_ENTROPY_MAX) {
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
    if (BSL_LIST_SearchDataConst(nsList, name, (BSL_LIST_PFUNC_CMP)ES_NsComp, NULL) != NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ES_DUP_NS);
        return CRYPT_ENTROPY_ES_DUP_NS;
    }
    ES_NoiseSource *ns = ES_NsCreate(name, autoTest, claimBitsPerOsr, method, para);
    if (ns == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ES_CREATE_ERROR);
        return CRYPT_ENTROPY_ES_CREATE_ERROR;
    }
    int32_t ret = BSL_LIST_AddElement(nsList, ns, BSL_LIST_POS_END);
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
            node = BSL_LIST_GetNextNode(nsList, tmpNode);
            continue;
        }
        if (strcmp(ns->name, name) == 0) {
            BSL_LIST_DeleteNode(nsList, (const BslListNode *)tmpNode, (BSL_LIST_PFUNC_FREE)ES_NsFree);
            return CRYPT_SUCCESS;
        }
        /* Advance from the saved node so later delete/free never invalidates the iterator step. */
        node = BSL_LIST_GetNextNode(nsList, tmpNode);
    }
    BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ES_NS_NOT_FOUND);
    return CRYPT_ENTROPY_ES_NS_NOT_FOUND;
}

static int32_t NsRead(ES_NoiseSource *ns, uint8_t *buf, uint32_t bufLen)
{
    int32_t ret = ns->read(ns->usrdata, ES_MAX_TIMEOUT_MAX, buf, bufLen);
    if (ret != CRYPT_SUCCESS) {
        /* Internal negative encodings collapse to the public availability
           verdict at this boundary. */
        return ret < 0 ? CRYPT_ENTROPY_ES_NS_NOT_AVA : ret;
    }
    if (!ns->enableTest) {
        return CRYPT_SUCCESS;
    }
    for (uint32_t iter = 0; iter < bufLen; iter++) {
        ret = ES_HealthTestRct(&ns->state.rct, buf[iter]);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        ret = ES_HealthTestApt(&ns->state.apt, buf[iter]);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
    return ret;
}

int32_t ES_NsRead(ES_NoiseSource *ns, uint8_t *buf, uint32_t bufLen)
{
    if (ns->isInit != true || ns->isEnable != true) {
        return CRYPT_ENTROPY_ES_NS_NOT_AVA;
    }

    return NsRead(ns, buf, bufLen);
}

#endif
