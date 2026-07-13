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
#include "bsl_err_internal.h"
#include "bsl_list.h"
#include "crypt_errno.h"
#include "crypt_entropy.h"
#include "crypt_eal_entropy.h"
#include "es_entropy_pool.h"
#include "es_cf.h"
#include "es_noise_source.h"
#include "es_entropy_local.h"

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
    memset(es, 0, sizeof(ENTROPY_EntropySource));
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

#define ENTROPY_COLLECTION_CHUNK_SIZE 4096

/* Outcome of one entropy collection transaction. */
typedef struct {
    uint32_t dataLen;
    int32_t rootErr;
    int32_t conditionerErr;
} ES_CollectionResult;

/* Mutable state for bounded collection and conditioner streaming. */
typedef struct {
    ES_CfMethod *conditioner;
    void *conditionerCtx;
    uint8_t *buffer;
    uint32_t bufferSize;
    uint32_t bufferLen;
    uint32_t remaining[ES_NS_MAX_SIZE];
    bool startup;
} ES_CollectionState;

static void EsDisableFailedNs(ES_NoiseSource *ns, int32_t ret)
{
    if (ES_NsVerdictRetires(ret)) {
        ES_NsRetire(ns);
    } else if (ES_NsVerdictDemotes(ret)) {
        /* An alarm on probation charges the failed recovery to the streak
           here; window and probation paths are mutually exclusive per
           suspension, so no double counting. */
        if (ns->onProbation) {
            ns->onProbation = false;
            if (++ns->recoveryFailStreak >= NS_PERMANENT_FAIL_STREAK) {
                ns->permanentFailure = true;
            }
        }
        /* Statistical alarm: suspend pending recovery. A permanent verdict
           retires the source below. */
        if (!ns->permanentFailure) {
            ns->needRecovery = true;
        }
    }
    if (ns->permanentFailure) {
        ES_NsRetire(ns);
    } else if (ns->credited || ns->needRecovery) {
        ns->isEnable = false;
    }
}

/* Recovery of one suspended source at its unchanged settled rate:
   a pass re-arms it, a repeated alarm counts toward retirement, and a
   permanent-tier or structural verdict retires it immediately. */
static int32_t EsRecoverNs(ENTROPY_EntropySource *es, ES_NoiseSource *ns)
{
    /* Only sources providing a recovery callback may re-arm; the rest
       stay suspended fail-closed for the record's lifetime. */
    if (ns->recover == NULL) {
        return CRYPT_ENTROPY_ES_NS_NOT_AVA;
    }
    int32_t ret = ns->recover(ns->usrdata);
    if (es->runLog != NULL) {
        es->runLog(ret);
    }
    if (ret == CRYPT_SUCCESS) {
        /* A passing recovery window only re-arms the source; the failure streak
           is held until a full credited gather vindicates it (see
           EsClearProbation), so a source that re-alarms every transaction
           cannot recover forever without ever retiring. */
        ns->needRecovery = false;
        ns->onProbation = true;
        ns->isEnable = true;
        return CRYPT_SUCCESS;
    }
    if (ES_NsVerdictRetires(ret)) {
        ES_NsRetire(ns);
        return ret;
    }
    /* Only genuine health alarms accrue retirement evidence; operational
       callback errors leave the source suspended and retryable without
       counting toward the permanent latch. */
    if (ES_NsVerdictDemotes(ret) && ++ns->recoveryFailStreak >= NS_PERMANENT_FAIL_STREAK) {
        ES_NsRetire(ns);
        return CRYPT_ENTROPY_ES_PERMANENT_FAILURE;
    }
    return ret;
}

/* One full credited gather vindicates every source still on probation: only a
   real transaction that met its quota clears the retained failure streak. */
static void EsClearProbation(ENTROPY_EntropySource *es)
{
    for (BslListNode *node = BSL_LIST_FirstNode(es->nsList); node != NULL;
        node = BSL_LIST_GetNextNode(es->nsList, node)) {
        ES_NoiseSource *ns = BSL_LIST_GetData(node);
        if (ns->onProbation) {
            ns->onProbation = false;
            ns->recoveryFailStreak = 0;
        }
    }
}

/* Gather-entry gate: run every pending recovery, then require each credited
   source to be armed. Auxiliary recovery failures remain local to that source. */
static int32_t EsEnsureSourcesReady(ENTROPY_EntropySource *es)
{
    for (BslListNode *node = BSL_LIST_FirstNode(es->nsList); node != NULL;
        node = BSL_LIST_GetNextNode(es->nsList, node)) {
        ES_NoiseSource *ns = BSL_LIST_GetData(node);
        if (ns->permanentFailure) {
            if (ns->credited) {
                return CRYPT_ENTROPY_ES_PERMANENT_FAILURE;
            }
            continue;
        }
        if (ns->needRecovery) {
            int32_t ret = EsRecoverNs(es, ns);
            if (ret != CRYPT_SUCCESS && ns->credited) {
                return ret;
            }
        }
        if (ns->credited && !ns->isEnable) {
            return CRYPT_ENTROPY_ES_NS_NOT_AVA;
        }
    }
    return CRYPT_SUCCESS;
}

static bool EsCreditedSourcesReady(ENTROPY_EntropySource *es)
{
    for (BslListNode *node = BSL_LIST_FirstNode(es->nsList); node != NULL;
        node = BSL_LIST_GetNextNode(es->nsList, node)) {
        ES_NoiseSource *ns = BSL_LIST_GetData(node);
        if (ns->credited && !ns->isEnable) {
            return false;
        }
    }
    return true;
}

static bool EsHasCreditedSource(ENTROPY_EntropySource *es)
{
    for (BslListNode *node = BSL_LIST_FirstNode(es->nsList); node != NULL;
        node = BSL_LIST_GetNextNode(es->nsList, node)) {
        ES_NoiseSource *ns = BSL_LIST_GetData(node);
        if (ns->isEnable && ns->credited) {
            return true;
        }
    }
    return false;
}

static bool EsPrepareCollection(ENTROPY_EntropySource *es, uint32_t needBits,
    ES_CollectionState *state)
{
    memset(state->remaining, 0, sizeof(state->remaining));
    uint32_t nsIndex = 0;
    for (BslListNode *node = BSL_LIST_FirstNode(es->nsList); node != NULL;
        node = BSL_LIST_GetNextNode(es->nsList, node), nsIndex++) {
        ES_NoiseSource *ns = BSL_LIST_GetData(node);
        if (!ns->isEnable) {
            continue;
        }
        /* Every credited source carries the whole needBits claim on its own,
           so a source claiming claimBitsPerOsr / osr bit per sample needs
           needBits * osr / claim samples, rounded up. Fixed-claim sources
           carry osr 0 and uncredited ones claim 0; both normalize to 1 so the
           quota stays bounded. */
        uint32_t divisor = ns->osr == 0 ? 1 : ns->osr;
        uint32_t claim = ns->claimBitsPerOsr == 0 ? 1 : ns->claimBitsPerOsr;
        uint64_t samples = ((uint64_t)needBits * divisor + claim - 1) / claim;
        if (samples > UINT32_MAX) {
            return false;
        }
        state->remaining[nsIndex] = (uint32_t)samples;
    }
    return true;
}

static bool EsCollectionComplete(const uint32_t remaining[ES_NS_MAX_SIZE])
{
    for (uint32_t i = 0; i < ES_NS_MAX_SIZE; i++) {
        if (remaining[i] != 0) {
            return false;
        }
    }
    return true;
}

static bool EsFlushCollection(ES_CollectionState *state, ES_CollectionResult *result)
{
    if (state->bufferLen == 0) {
        return true;
    }
    int32_t ret = state->conditioner->update(state->conditionerCtx, state->buffer, state->bufferLen);
    if (ret != CRYPT_SUCCESS) {
        result->conditionerErr = ret;
        return false;
    }
    state->bufferLen = 0;
    return true;
}

/* One source's contiguous block, never interleaved: the transaction feeds
   Hash_df(block_0 || block_1 || ...) in registration order. The quota counts
   every measurement, so the credited n_in stays fixed (SP800-90B 3.1.5) and
   the credited population matches the assessed one. A degrading source aborts
   through the stuck-run cutoff. */
static bool EsCollectBlock(ENTROPY_EntropySource *es, ES_NoiseSource *ns, uint32_t nsIndex,
    ES_CollectionState *state, ES_CollectionResult *result)
{
    uint32_t recordBytes = ns->sampleBytes;
    while (state->remaining[nsIndex] > 0) {
        /* Flush ahead of the read so one record never straddles the buffer. */
        if (state->bufferLen + recordBytes > state->bufferSize && !EsFlushCollection(state, result)) {
            return false;
        }
        int32_t ret = ES_NsRead(ns, state->buffer + state->bufferLen, recordBytes);
        if (ret == CRYPT_SUCCESS) {
            state->bufferLen += recordBytes;
            result->dataLen++;
            state->remaining[nsIndex]--;
        } else {
            if (state->startup && ES_NsVerdictDemotes(ret)) {
                (void)ES_NsOsrDemote(ns);
            }
            EsDisableFailedNs(ns, ret);
        }
        if (es->runLog != NULL) {
            es->runLog(ret);
        }
        if (ret != CRYPT_SUCCESS) {
            if (ns->credited) {
                /* If this alarm retired the source, surface the permanent
                   verdict on this same transaction rather than the raw
                   RCT/APT code, so the caller learns retirement immediately. */
                result->rootErr = ns->permanentFailure ? CRYPT_ENTROPY_ES_PERMANENT_FAILURE : ret;
                return false;
            }
            /* An uncredited source that fails carries no claim: drop its
               remaining mix and continue with the credited blocks. */
            state->remaining[nsIndex] = 0;
            return true;
        }
    }
    return true;
}

static ES_CollectionResult EsCollect(ENTROPY_EntropySource *es, ES_CollectionState *state)
{
    ES_CollectionResult result = {0, CRYPT_SUCCESS, CRYPT_SUCCESS};
    uint32_t nsIndex = 0;
    for (BslListNode *node = BSL_LIST_FirstNode(es->nsList); node != NULL;
        node = BSL_LIST_GetNextNode(es->nsList, node), nsIndex++) {
        ES_NoiseSource *ns = BSL_LIST_GetData(node);
        if (!ns->isEnable) {
            continue;
        }
        if (!EsCollectBlock(es, ns, nsIndex, state, &result)) {
            return result;
        }
    }
    (void)EsFlushCollection(state, &result);
    return result;
}

/* Shared plumbing of one collection transaction: pool-capacity check,
   per-source quotas, conditioner init, buffered collect, buffer teardown.
   On success the caller owns state->conditionerCtx and judges completeness;
   on failure the context is already released. */
static int32_t EsCollectTransaction(ENTROPY_EntropySource *es, bool startup,
    ES_CollectionState *state, ES_CollectionResult *result)
{
    ES_CfMethod *meth = es->cfMeth;
    if (meth->getCfOutLen(meth->ctx) >
        (uint32_t)ES_EntropyPoolGetMaxSize(es->pool) - ES_EntropyPoolGetCurSize(es->pool)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ES_POOL_INSUFFICIENT);
        return CRYPT_ENTROPY_ES_POOL_INSUFFICIENT;
    }
    state->conditioner = meth;
    state->startup = startup;
    if (!EsPrepareCollection(es, meth->getNeedEntropy(meth->ctx), state)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ES_NS_NOT_AVA);
        return CRYPT_ENTROPY_ES_NS_NOT_AVA;
    }
    state->conditionerCtx = meth->init(&meth->meth);
    if (state->conditionerCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ES_CF_ERROR);
        return CRYPT_ENTROPY_ES_CF_ERROR;
    }
    state->bufferSize = ENTROPY_COLLECTION_CHUNK_SIZE;
    state->buffer = BSL_SAL_Malloc(state->bufferSize);
    if (state->buffer == NULL) {
        meth->deinit(state->conditionerCtx);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    *result = EsCollect(es, state);
    BSL_SAL_ClearFree(state->buffer, state->bufferSize);
    if (result->conditionerErr != CRYPT_SUCCESS) {
        meth->deinit(state->conditionerCtx);
        BSL_ERR_PUSH_ERROR(result->conditionerErr);
        return result->conditionerErr;
    }
    return CRYPT_SUCCESS;
}

/* Collect each credited source's full share of the conditioner input into
   the retained first seed block. */
static int32_t EsStartupSeed(ENTROPY_EntropySource *es)
{
    if (!EsHasCreditedSource(es)) {
        return CRYPT_SUCCESS;
    }
    ES_CfMethod *meth = es->cfMeth;
    ES_CollectionState state = {0};
    ES_CollectionResult result;
    int32_t ret = EsCollectTransaction(es, true, &state, &result);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (!EsCreditedSourcesReady(es) || !EsCollectionComplete(state.remaining) || result.dataLen == 0) {
        meth->deinit(state.conditionerCtx);
        if (result.rootErr != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(result.rootErr);
        }
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ES_NS_NOT_AVA);
        return CRYPT_ENTROPY_ES_NS_NOT_AVA;
    }
    uint32_t len;
    uint8_t *data = meth->getEntropyData(state.conditionerCtx, &len);
    meth->deinit(state.conditionerCtx);
    if (data == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = ES_EntropyPoolPushBytes(es->pool, data, len);
    BSL_SAL_ClearFree(data, len);
    return ret;
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
    /* A successful list init arms every credited source, so no separate
       readiness check is needed here. */
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
    ret = EsStartupSeed(es);
    if (ret != CRYPT_SUCCESS) {
        ENTROPY_EsDeinit(es);
        return ret;
    }
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

static int32_t EsSetCF(ENTROPY_EntropySource *es, ENTROPY_CFPara *data, uint32_t len)
{
    if (es->isWork) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ES_STATE_ERROR);
        return CRYPT_ENTROPY_ES_STATE_ERROR;
    }
    if (data == NULL || len != sizeof(ENTROPY_CFPara)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
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
            return EsSetCF(es, data, len);
        case CRYPT_ENTROPY_GET_STATE:
            return EsGetState(es, data, len);
        case CRYPT_ENTROPY_SET_LOG_CALLBACK:
            return EsSetLogCallback(es, data, len);
        default:
            return EsGetSize(es, cmd, data, len);
    }
}

/* One collection transaction. The caller owns the readiness gate, and a
   working entropy source always carries a conditioner. */
static int32_t EsGatherCollected(ENTROPY_EntropySource *es)
{
    ES_CfMethod *meth = es->cfMeth;
    if (!EsHasCreditedSource(es)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ES_NS_NOT_AVA);
        return CRYPT_ENTROPY_ES_NS_NOT_AVA;
    }
    ES_CollectionState state = {0};
    ES_CollectionResult result;
    int32_t ret = EsCollectTransaction(es, false, &state, &result);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (!EsCollectionComplete(state.remaining) || result.dataLen == 0) {
        meth->deinit(state.conditionerCtx);
        if (result.rootErr == CRYPT_ENTROPY_ES_PERMANENT_FAILURE) {
            /* A source retired mid-transaction: report retirement now. */
            BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ES_PERMANENT_FAILURE);
            return CRYPT_ENTROPY_ES_PERMANENT_FAILURE;
        }
        if (result.rootErr != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(result.rootErr);
        }
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ES_NS_NOT_AVA);
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ES_ENTROPY_NOT_ENOUGH);
        return CRYPT_ENTROPY_ES_ENTROPY_NOT_ENOUGH;
    }
    uint32_t len;
    uint8_t *data = meth->getEntropyData(state.conditionerCtx, &len);
    meth->deinit(state.conditionerCtx);
    if (data == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    /* Gather fed needEntropy = out*8 + CF_FE_EXLEN claimed bits, so this block
       enters the pool as full entropy: 8 claimed bits per byte, tracked by
       byte count. */
    ret = ES_EntropyPoolPushBytes(es->pool, data, len);
    BSL_SAL_ClearFree(data, len);
    if (ret == CRYPT_SUCCESS) {
        /* A full runtime transaction vindicates any source still on probation:
           clear its retained failure streak so intermittent alarms separated
           by real successes do not accumulate toward retirement. */
        EsClearProbation(es);
    }
    return ret;
}

uint32_t ENTROPY_EsEntropyGet(ENTROPY_EntropySource *es, uint8_t *data, uint32_t len)
{
    if (es == NULL || !es->isWork || data == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return 0;
    }
    /* Run the recovery gate here too: a source suspended by a prior alarm must
       get its recovery run on the consumption path, not only on an
       explicit gather. A pass re-arms it before the pool is drained. */
    int32_t readyRet = EsEnsureSourcesReady(es);
    if (readyRet != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(readyRet);
        return 0;
    }
    if (ES_EntropyPoolGetCurSize(es->pool) <= 0) {
        if (EsGatherCollected(es) != CRYPT_SUCCESS) {
            return 0;
        }
    }
    return ES_EntropyPoolPopBytes(es->pool, data, len);
}

int32_t ENTROPY_EsEntropyGather(ENTROPY_EntropySource *es)
{
    if (es == NULL || es->isWork == false || es->cfMeth == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t readyRet = EsEnsureSourcesReady(es);
    if (readyRet != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(readyRet);
        return readyRet;
    }
    return EsGatherCollected(es);
}
#endif
