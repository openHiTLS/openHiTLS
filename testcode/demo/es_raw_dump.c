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

/*
 * Raw noise-sample collection for SP800-90B / AIS 31 evidence. The entropy
 * source implementation files are #included so the tool reaches the internal
 * measurement paths; the production library carries no collection code.
 *
 * Raw symbol: D_i = tick2_i - tick1_i, the raw 64-bit delta the conditioner
 * absorbs (little-endian, 8 bytes). Assessment runs on b_i = D_i mod 256.
 *
 * Output is headerless:
 *   u64  - little-endian uint64 raw deltas (archive)
 *   lsb8 - one 8-bit assessment symbol per byte; also writes <outfile>.u64
 *          and reports u64-domain health maxima on stderr
 *
 * Usage: es_raw_dump <jitter|hashloop|blocks> <seq|restart> <outfile> [count] [u64|lsb8]
 *   seq:      count = samples, default 2000000
 *   restart:  count = rows, default 1000; fresh source state per row,
 *             1000 samples per row (ea_restart matrix layout)
 *   blocks:   production-path capture of the conditioner input through the
 *             linked library (seq, lsb8 only; count = runtime bytes; writes
 *             .startup / .journal.csv / .blocks.csv)
 * Timing uses the production ES_NsTickGet path.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include "hitls_build.h"

#ifndef __FILENAME__
#define __FILENAME__ "es_raw_dump.c"
#endif

#if !defined(HITLS_CRYPTO_ENTROPY) || !defined(HITLS_CRYPTO_ENTROPY_SYS) || \
    (!defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) && !defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP))
int main(void)
{
    fprintf(stderr, "es_raw_dump: build with the entropy feature macros of the target library "
        "(HITLS_CRYPTO_ENTROPY, HITLS_CRYPTO_ENTROPY_SYS, HITLS_CRYPTO_ENTROPY_NS_*)\n");
    return 1;
}
#else

/* The production .c files are compiled in-TU: the sampling internals are
   static, and the #define blocks pin OSR/OSR_MAX to the evaluated profile
   independent of the library build flags. */
#include "../../crypto/entropy/src/es_health_test.c"
#include "../../crypto/entropy/src/es_ns_delta_common.c"
/* The list engine (ES_NsListInit and the health lifecycle) must come from the
   same source revision as the ES_NoiseSource layout compiled above; linking it
   from a stale libhitls_crypto build reads shifted struct fields. */
#include "../../crypto/entropy/src/es_noise_source.c"
/* Oversampling rate of the evaluated evidence profile; pins the in-TU source
   builds and gates the library-side blocks capture. */
#define RAW_EVIDENCE_OSR 3U
#ifdef HITLS_CRYPTO_ENTROPY_NS_CPUJITTER
#undef HITLS_JITTER_OSR
#undef HITLS_JITTER_OSR_MAX
#define HITLS_JITTER_OSR RAW_EVIDENCE_OSR
#define HITLS_JITTER_OSR_MAX RAW_EVIDENCE_OSR
#include "../../crypto/entropy/src/es_ns_jitter.c"
#undef HITLS_JITTER_OSR_MAX
#undef HITLS_JITTER_OSR
#endif
#ifdef HITLS_CRYPTO_ENTROPY_NS_HASHLOOP
#undef HITLS_HASHLOOP_OSR
#undef HITLS_HASHLOOP_OSR_MAX
#define HITLS_HASHLOOP_OSR RAW_EVIDENCE_OSR
#define HITLS_HASHLOOP_OSR_MAX RAW_EVIDENCE_OSR
#include "../../crypto/entropy/src/es_ns_hashloop.c"
#undef HITLS_HASHLOOP_OSR_MAX
#undef HITLS_HASHLOOP_OSR
#endif
/* Library-side capture for blocks mode, which needs the dual-source profile. */
#ifdef HITLS_CRYPTO_ENTROPY_NS_HASHLOOP
#include "crypt_eal_entropy.h"
#include "crypt_types.h"
#include "es_cf.h"
#include "es_entropy_local.h"
#include "../../crypto/eal/src/eal_entropy.h"
#endif

#define RAW_RESTART_ROW_SAMPLES 1000
#define RAW_SEQ_DEFAULT_SAMPLES 2000000ULL
#define RAW_RESTART_DEFAULT_ROWS 1000ULL
#define RAW_IO_CHUNK 4096
#define RAW_INIT_MAX_ATTEMPTS 50

typedef struct {
    int32_t (*newState)(void **state);
    void (*freeState)(void *state);
    uint64_t (*sample)(void *state);
    ES_NoiseSource *(*newNs)(void);
    int32_t (*verdict)(void *state);
} RawSource;

#ifdef HITLS_CRYPTO_ENTROPY_NS_CPUJITTER
/* Shipped JitterStateNew + JitterMeasure: raw pre-conditioning deltas.
   Intermittent verdicts leave the stream untouched (no osr walk, no startup
   test), so recording every measurement matches the credited population; a
   permanent latch zeroizes further deltas, so the dump aborts instead of
   archiving zeros. */
static int32_t RawJitterNew(void **state)
{
    ES_JitterState *e = NULL;
    int32_t ret = JitterStateNew(&e);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    fprintf(stderr, "jitter memSize=%u (l1d probe=%u)\n", e->memSize,
        ES_CpuJitterL1dCacheSize());
    *state = e;
    return CRYPT_SUCCESS;
}

static uint64_t RawJitterSample(void *state)
{
    ES_JitterState *e = (ES_JitterState *)state;
    JitterMeasure(e);
    return e->ns.lastDelta;
}

static int32_t RawJitterVerdict(void *state)
{
    return ((ES_JitterState *)state)->ns.testFailure;
}

static const RawSource g_rawJitter = {
    RawJitterNew, ES_CpuJitterFree, RawJitterSample, ES_CpuJitterGetCtx, RawJitterVerdict
};
#endif

#ifdef HITLS_CRYPTO_ENTROPY_NS_HASHLOOP
/* Shipped HashLoopStateNew + HashLoopMeasure: raw pre-conditioning deltas,
   same verdict handling as the jitter source above.
   Iteration count is HITLS_HASHLOOP_ITERATIONS. */
static int32_t RawHashLoopNew(void **state)
{
    ES_HashLoopState *e = NULL;
    int32_t ret = HashLoopStateNew(&e);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    *state = e;
    return CRYPT_SUCCESS;
}

static uint64_t RawHashLoopSample(void *state)
{
    ES_HashLoopState *e = (ES_HashLoopState *)state;
    HashLoopMeasure(e);
    return e->ns.lastDelta;
}

static int32_t RawHashLoopVerdict(void *state)
{
    return ((ES_HashLoopState *)state)->ns.testFailure;
}

static const RawSource g_rawHashLoop = {
    RawHashLoopNew, ES_HashLoopFree, RawHashLoopSample, ES_HashLoopGetCtx, RawHashLoopVerdict
};
#endif

/* Capture-side health telemetry over the raw u64 deltas: a scratch
   production engine with every cutoff widened past reach, so the archived
   maxima come from the shipped predicates themselves rather than a mirror. */
typedef struct {
    ES_DeltaNs eng;
    uint32_t eqRunMax;
    uint32_t stuckRunMax;
    uint32_t aptMax;
} RawHealthStat;

/* Row boundary: a run cannot span a source re-init. Maxima persist. */
static void RawHealthReset(RawHealthStat *hs)
{
    ES_DeltaNsStartupReset(&hs->eng);
    ES_DeltaNsOsrApply(&hs->eng, RAW_EVIDENCE_OSR);
    hs->eng.stuckCutoff = UINT32_MAX;
    hs->eng.rct.cutoff = UINT32_MAX;
    hs->eng.apt.cutoff = UINT32_MAX;
    hs->eng.rctPermCutoff = UINT32_MAX;
    hs->eng.aptPermCutoff = UINT32_MAX;
}

static void RawHealthUpdate(RawHealthStat *hs, uint64_t d)
{
    ES_DeltaNsProcessRawDelta(&hs->eng, d);
    if (hs->eng.rct.count > hs->eqRunMax) {
        hs->eqRunMax = hs->eng.rct.count;
    }
    if (hs->eng.stuckCount > hs->stuckRunMax) {
        hs->stuckRunMax = hs->eng.stuckCount;
    }
    if (hs->eng.apt.count > hs->aptMax) {
        hs->aptMax = hs->eng.apt.count;
    }
}

static void RawHealthPrint(const RawHealthStat *hs)
{
    /* eq-run and apt512 come from the production RCT/APT, so they are in the
       assessed 8-bit symbol domain; the stuck run stays on the full delta. */
    fprintf(stderr, "health: eq-run max=%u (lsb8), stuck-run max=%u (u64), apt512 max=%u (lsb8)\n",
        hs->eqRunMax, hs->stuckRunMax, hs->aptMax);
}

static int WriteSamples(const RawSource *src, void *state, FILE *fp, FILE *fu, RawHealthStat *hs,
    uint64_t n, int u64Out)
{
    uint8_t u64Buf[RAW_IO_CHUNK * sizeof(uint64_t)];
    uint8_t byteBuf[RAW_IO_CHUNK];
    uint64_t done = 0;
    while (done < n) {
        uint32_t chunk = (uint32_t)((n - done > RAW_IO_CHUNK) ? RAW_IO_CHUNK : (n - done));
        for (uint32_t i = 0; i < chunk; i++) {
            uint64_t delta = src->sample(state);
            /* The latching call already zeroized its own delta; abort before
               this chunk is written so no zeroized record reaches the
               archive. */
            if (src->verdict(state) == NS_ENTROPY_PERMANENT_FAILURE) {
                fprintf(stderr, "permanent health verdict after %llu samples: "
                    "the engine zeroizes further deltas, aborting the dump\n",
                    (unsigned long long)(done + i));
                return 1;
            }
            RawHealthUpdate(hs, delta);
            /* Same little-endian record the production conditioner
               absorbs, so archives stay comparable across platforms. */
            PUT_UINT64_LE(delta, u64Buf, i * sizeof(uint64_t));
            if (!u64Out) {
                byteBuf[i] = (uint8_t)(delta & 0xff);
            }
        }
        size_t written = u64Out ? fwrite(u64Buf, sizeof(uint64_t), chunk, fp)
                                : fwrite(byteBuf, 1, chunk, fp);
        if (written != chunk) {
            perror("fwrite");
            return 1;
        }
        if (fu != NULL && fwrite(u64Buf, sizeof(uint64_t), chunk, fu) != chunk) {
            perror("fwrite");
            return 1;
        }
        done += chunk;
    }
    return 0;
}

static int DumpSequential(const RawSource *src, FILE *fp, FILE *fu, uint64_t samples, int u64Out)
{
    void *state = NULL;
    int32_t initRet = src->newState(&state);
    if (initRet != CRYPT_SUCCESS) {
        fprintf(stderr, "state initialization failed: 0x%x\n", (unsigned)initRet);
        return 1;
    }
    RawHealthStat hs = {0};
    RawHealthReset(&hs);
    int ret = WriteSamples(src, state, fp, fu, &hs, samples, u64Out);
    src->freeState(state);
    if (ret == 0) {
        fprintf(stderr, "seq done: %llu samples\n", (unsigned long long)samples);
        RawHealthPrint(&hs);
    }
    return ret;
}

#ifdef HITLS_CRYPTO_ENTROPY_NS_HASHLOOP
/* Conditioner input captured on the production path: per-source blocks in
   registration order, via a wrapper around this instance's conditioner
   update, so the recorded bytes are exactly what EsCollect hands Hash_df.
   EsInit leaves one block in the pool, so the first Get may drain it without
   a gather (journal row got=32, len=0). Build library and tool from one
   revision and keep hidden visibility on, or ELF binding lets the in-TU
   copies preempt the library's entropy symbols (osrMax 3 = tool copy). */
#define BLOCKS_GET_LEN 32U /* sha3_256_df output block, checked against GET_CF_SIZE */
#define BLOCKS_MAX_TXN 262144U
#define BLOCKS_INIT_ATTEMPTS 3U
#define BLOCKS_ERR_CODES 4U

typedef struct {
    char kind; /* 'I' init/seed transaction, 'G' runtime get */
    uint64_t start;
    uint64_t end;
    int64_t got;
} BlkTxn;

static uint8_t *g_blkBuf;
static uint64_t g_blkLen;
static uint64_t g_blkSize;
static uint64_t g_blkDropped;
static int32_t (*g_blkOrigUpdate)(void *ctx, uint8_t *data, uint32_t dataLen);
static uint64_t g_blkLogFails;
static int32_t g_blkErrCodes[BLOCKS_ERR_CODES];
static uint32_t g_blkErrCount;

static int32_t BlkCaptureUpdate(void *ctx, uint8_t *data, uint32_t dataLen)
{
    if (g_blkLen + dataLen <= g_blkSize) {
        (void)memcpy(g_blkBuf + g_blkLen, data, dataLen);
        g_blkLen += dataLen;
    } else {
        g_blkDropped += dataLen;
    }
    return g_blkOrigUpdate(ctx, data, dataLen);
}

/* Block attribution: sources are serial, so per-source byte counts in read
   order reconstruct the block boundaries. Each read method is wrapped per
   instance; the wrapper dispatches on usrdata. */
#define BLOCKS_MAX_BLOCKS 65536U

typedef struct {
    void *usrdata;
    const char *name;
    int32_t (*orig)(void *usrdata, uint32_t timeout, uint8_t *buf, uint32_t bufLen);
} BlkSourceHook;

typedef struct {
    const char *name;
    uint64_t bytes;
} BlkBlock;

static BlkSourceHook g_blkHooks[ES_NS_MAX_SIZE];
static uint32_t g_blkHookCount;
static BlkBlock g_blkBlocks[BLOCKS_MAX_BLOCKS];
static uint32_t g_blkBlockCount;
static const char *g_blkActive;
static int g_blkBlockOverflow;

static int32_t BlkCaptureRead(void *usrdata, uint32_t timeout, uint8_t *buf, uint32_t bufLen)
{
    BlkSourceHook *hook = NULL;
    for (uint32_t i = 0; i < g_blkHookCount; i++) {
        if (g_blkHooks[i].usrdata == usrdata) {
            hook = &g_blkHooks[i];
            break;
        }
    }
    if (hook == NULL) {
        return CRYPT_ENTROPY_ES_NS_NOT_AVA;
    }
    int32_t ret = hook->orig(usrdata, timeout, buf, bufLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (g_blkBlockOverflow) {
        return ret;
    }
    if (g_blkActive != hook->name) {
        if (g_blkBlockCount >= BLOCKS_MAX_BLOCKS) {
            g_blkBlockOverflow = 1;
            return ret;
        }
        g_blkActive = hook->name;
        g_blkBlocks[g_blkBlockCount++] = (BlkBlock){hook->name, 0};
    }
    if (g_blkBlockCount > 0) {
        g_blkBlocks[g_blkBlockCount - 1].bytes += bufLen;
    }
    return ret;
}

/* Collection-result hook: keeps the library-reported failure codes that a
   short Get alone cannot convey. Success returns immediately so the per-byte
   cost inside EsCollect stays one compare. */
static void BlkRunLog(int32_t ret)
{
    if (ret == CRYPT_SUCCESS) {
        return;
    }
    g_blkLogFails++;
    for (uint32_t i = 0; i < g_blkErrCount; i++) {
        if (g_blkErrCodes[i] == ret) {
            return;
        }
    }
    if (g_blkErrCount < BLOCKS_ERR_CODES) {
        g_blkErrCodes[g_blkErrCount++] = ret;
    }
}

static int BlkWriteRange(FILE *fp, uint64_t start, uint64_t end)
{
    return fwrite(g_blkBuf + start, 1, end - start, fp) == (end - start) ? 0 : 1;
}

static int DumpBlocks(const char *outfile, uint64_t targetBytes)
{
    int rc = 1;
    BlkTxn *journal = NULL;
    CRYPT_EAL_Es *es = NULL;
    FILE *fs = NULL;
    FILE *fr = NULL;
    FILE *fj = NULL;
    uint32_t txnCount = 0;

    /* runtimeBytes counts captured bytes directly, so the buffer only needs
       the target plus startup/overshoot slack. */
    g_blkSize = targetBytes + (1U << 20);
    /* malloc takes size_t: on a 32-bit build a uint64 target would truncate
       and undersize the buffer the 64-bit bound check then overruns. */
    if (g_blkSize > SIZE_MAX / 2) {
        fprintf(stderr, "capture size %llu exceeds the addressable buffer\n",
            (unsigned long long)g_blkSize);
        goto done;
    }
    g_blkBuf = malloc((size_t)g_blkSize);
    journal = malloc(sizeof(BlkTxn) * BLOCKS_MAX_TXN);
    if (g_blkBuf == NULL || journal == NULL) {
        fprintf(stderr, "allocation failed\n");
        goto done;
    }
    /* Pre-fault the capture buffer so first-touch page faults do not land
       inside EsCollect between noise samples. */
    (void)memset(g_blkBuf, 0, g_blkSize);

    es = CRYPT_EAL_EsNew();
    if (es == NULL) {
        fprintf(stderr, "CRYPT_EAL_EsNew failed\n");
        goto done;
    }
    int32_t ret = CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, "sha3_256_df", strlen("sha3_256_df"));
    fprintf(stderr, "set cf sha3_256_df: 0x%x\n", (unsigned)ret);
    if (ret != CRYPT_SUCCESS || es->es == NULL || es->es->cfMeth == NULL ||
        es->es->cfMeth->update == NULL) {
        fprintf(stderr, "conditioner method not ready\n");
        goto done;
    }
    ret = CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_LOG_CALLBACK, (void *)BlkRunLog, 0);
    if (ret != CRYPT_SUCCESS) {
        fprintf(stderr, "set log callback: 0x%x (continuing without it)\n", (unsigned)ret);
    }
    g_blkOrigUpdate = es->es->cfMeth->update;
    es->es->cfMeth->update = BlkCaptureUpdate;

    /* A failed init leaves nothing seeded, so its captured bytes are not part
       of any seed that fed production; discard and retry on a clean offset. */
    for (uint32_t attempt = 1; attempt <= BLOCKS_INIT_ATTEMPTS; attempt++) {
        g_blkLen = 0;
        ret = CRYPT_EAL_EsInit(es);
        if (ret == CRYPT_SUCCESS) {
            break;
        }
        fprintf(stderr, "init attempt %u failed: 0x%x\n", attempt, (unsigned)ret);
    }
    if (ret != CRYPT_SUCCESS) {
        goto done;
    }
    journal[0] = (BlkTxn){'I', 0, g_blkLen, -1};
    txnCount = 1;
    fprintf(stderr, "init ok, startup capture %llu bytes\n", (unsigned long long)g_blkLen);
    /* Discarded init attempts must not colour the runtime collection report;
       their codes were printed per attempt above. */
    g_blkLogFails = 0;
    g_blkErrCount = 0;
    if (es->es->cfMeth->update != BlkCaptureUpdate) {
        fprintf(stderr, "wrapper displaced by init, aborting\n");
        goto done;
    }
    /* The one-Get-one-gather attribution requires the request length to equal
       the conditioner output block; verify instead of assuming. */
    uint32_t cfLen = 0;
    if (CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_GET_CF_SIZE, &cfLen, sizeof(cfLen)) != CRYPT_SUCCESS ||
        cfLen != BLOCKS_GET_LEN) {
        fprintf(stderr, "cf output length %u mismatches BLOCKS_GET_LEN %u\n", cfLen, BLOCKS_GET_LEN);
        goto done;
    }
    /* osrMax is reported because it identifies which build of the source
       constructor produced the record: the library's own ladder bound versus
       the OSR-pinned in-TU copy this file also compiles for the per-source
       modes. The evidence log therefore states the profile it measured. */
    uint32_t creditedCount = 0;
    for (BslListNode *node = BSL_LIST_FirstNode(es->es->nsList); node != NULL;
        node = BSL_LIST_GetNextNode(es->es->nsList, node)) {
        ES_NoiseSource *ns = BSL_LIST_GetData(node);
        fprintf(stderr, "source: %s credited=%d enabled=%d osr=%u osrMax=%u\n",
            ns->name, (int)ns->credited, (int)ns->isEnable, ns->osr, ns->osrMax);
        /* usrdata exists only after init, so the read hooks go on here rather
           than before CRYPT_EAL_EsInit; startup blocks are consequently not
           attributed, which the .startup file already separates out. */
        if (ns->usrdata != NULL && ns->read != NULL && g_blkHookCount < ES_NS_MAX_SIZE) {
            g_blkHooks[g_blkHookCount] = (BlkSourceHook){ns->usrdata, ns->name, ns->read};
            g_blkHookCount++;
            ns->read = BlkCaptureRead;
        }
        if (ns->credited && ns->isEnable) {
            creditedCount++;
        }
        if (ns->credited && ns->osr != RAW_EVIDENCE_OSR) {
            fprintf(stderr, "credited source settled at osr %u; the evidence profile requires %u\n",
                ns->osr, RAW_EVIDENCE_OSR);
            goto done;
        }
    }
    /* The joint-entropy evidence this mode produces is a dual-source claim, so
       a library carrying only one credited source must not silently yield a
       single-source stream under the same file name. */
    if (creditedCount != 2U) {
        fprintf(stderr, "%u credited sources active; the dual-source evidence profile requires 2\n",
            creditedCount);
        goto done;
    }

    uint64_t runtimeBytes = 0;
    uint32_t voided = 0;
    while (runtimeBytes < targetBytes && txnCount < BLOCKS_MAX_TXN) {
        uint8_t out[BLOCKS_GET_LEN];
        BlkTxn *txn = &journal[txnCount];
        *txn = (BlkTxn){'G', g_blkLen, 0, 0};
        uint32_t got = CRYPT_EAL_EsEntropyGet(es, out, BLOCKS_GET_LEN);
        txn->end = g_blkLen;
        txn->got = (int64_t)got;
        txnCount++;
        if (got == BLOCKS_GET_LEN) {
            runtimeBytes += txn->end - txn->start;
        } else {
            voided++;
            break;
        }
    }

    /* A voided transaction or a library-reported collection failure leaves
       the captured stream and the block journal describing different byte
       ranges; discard the run instead of writing misaligned evidence. */
    if (voided != 0 || g_blkLogFails != 0 || g_blkBlockOverflow) {
        fprintf(stderr, "blocks: evidence discarded, %u voided transactions, %llu library failures, "
            "block table overflow=%d", voided, (unsigned long long)g_blkLogFails, g_blkBlockOverflow);
        for (uint32_t i = 0; i < g_blkErrCount; i++) {
            fprintf(stderr, "%s0x%x", i == 0 ? ", codes: " : " ", (unsigned)g_blkErrCodes[i]);
        }
        fprintf(stderr, "\n");
        goto done;
    }

    char path[4096];
    if (strlen(outfile) + sizeof(".journal.csv") > sizeof(path)) {
        fprintf(stderr, "outfile path too long\n");
        goto done;
    }
    (void)snprintf(path, sizeof(path), "%s.startup", outfile);
    fs = fopen(path, "wb");
    fr = fopen(outfile, "wb");
    (void)snprintf(path, sizeof(path), "%s.journal.csv", outfile);
    fj = fopen(path, "w");
    if (fs == NULL || fr == NULL || fj == NULL) {
        fprintf(stderr, "output open failed\n");
        goto done;
    }
    fprintf(fj, "idx,kind,start,end,len,got\n");
    int werr = 0;
    uint64_t txnMin = UINT64_MAX;
    uint64_t txnMax = 0;
    uint64_t txnSum = 0;
    uint32_t txnOk = 0;
    for (uint32_t i = 0; i < txnCount; i++) {
        const BlkTxn *t = &journal[i];
        uint64_t len = t->end - t->start;
        fprintf(fj, "%u,%c,%llu,%llu,%llu,%lld\n", i, t->kind, (unsigned long long)t->start,
            (unsigned long long)t->end, (unsigned long long)len, (long long)t->got);
        if (t->kind == 'I') {
            werr |= BlkWriteRange(fs, t->start, t->end);
        } else {
            werr |= BlkWriteRange(fr, t->start, t->end);
            if (len > 0) {
                txnOk++;
                txnSum += len;
                txnMin = len < txnMin ? len : txnMin;
                txnMax = len > txnMax ? len : txnMax;
            }
        }
    }
    /* Block journal: per-source byte runs of the captured stream, in read
       order. Offsets are absolute in <outfile>.startup + <outfile> as
       captured; startup blocks are unattributed (hooks install after init). */
    (void)snprintf(path, sizeof(path), "%s.blocks.csv", outfile);
    FILE *fb = fopen(path, "w");
    if (fb == NULL) {
        fprintf(stderr, "block journal open failed\n");
        werr |= 1;
    } else {
        fprintf(fb, "idx,source,start,len\n");
        uint64_t off = journal[0].end; /* runtime blocks start after the seed */
        for (uint32_t i = 0; i < g_blkBlockCount; i++) {
            fprintf(fb, "%u,%s,%llu,%llu\n", i, g_blkBlocks[i].name,
                (unsigned long long)off, (unsigned long long)g_blkBlocks[i].bytes);
            off += g_blkBlocks[i].bytes;
        }
        werr |= fclose(fb) != 0;
    }

    werr |= fclose(fs) != 0;
    werr |= fclose(fr) != 0;
    werr |= fclose(fj) != 0;
    fs = NULL;
    fr = NULL;
    fj = NULL;

    fprintf(stderr, "transactions: %u total, %u gather-backed ok, dropped=%llu\n",
        txnCount, txnOk, (unsigned long long)g_blkDropped);
    if (txnOk > 0) {
        fprintf(stderr, "gather size bytes: min=%llu avg=%llu max=%llu\n",
            (unsigned long long)txnMin, (unsigned long long)(txnSum / txnOk),
            (unsigned long long)txnMax);
    }
    /* Evidence files must not silently truncate: dropped capture bytes or a
       short run fail the exit code just like a failed write. */
    rc = (werr != 0 || g_blkDropped != 0 || runtimeBytes < targetBytes) ? 1 : 0;
    fprintf(stderr, "blocks: %u recorded", g_blkBlockCount);
    if (g_blkBlockCount > 0) {
        uint64_t bmin = UINT64_MAX, bmax = 0, bsum = 0;
        for (uint32_t i = 0; i < g_blkBlockCount; i++) {
            uint64_t v = g_blkBlocks[i].bytes;
            bsum += v;
            bmin = v < bmin ? v : bmin;
            bmax = v > bmax ? v : bmax;
        }
        fprintf(stderr, ", bytes min=%llu avg=%llu max=%llu",
            (unsigned long long)bmin, (unsigned long long)(bsum / g_blkBlockCount),
            (unsigned long long)bmax);
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "blocks production done: startup=%llu runtime=%llu bytes, %s\n",
        (unsigned long long)journal[0].end, (unsigned long long)runtimeBytes,
        rc == 0 ? "ok" : "FAILED");

done:
    if (fs != NULL) {
        (void)fclose(fs);
    }
    if (fr != NULL) {
        (void)fclose(fr);
    }
    if (fj != NULL) {
        (void)fclose(fj);
    }
    if (es != NULL) {
        CRYPT_EAL_EsFree(es);
    }
    free(g_blkBuf);
    g_blkBuf = NULL;
    free(journal);
    return rc;
}
#endif

static void FreeDetachedNs(ES_NoiseSource *ns)
{
    if (ns == NULL) {
        return;
    }
    if (ns->usrdata != NULL && ns->deinit != NULL) {
        ns->deinit(ns->usrdata);
    }
    BSL_SAL_Free(ns->name);
    BSL_SAL_Free(ns);
}

static BslList *InitProductionSource(const RawSource *src, ES_NoiseSource **outNs, uint32_t *attempts,
    int32_t *lastRet)
{
    *lastRet = CRYPT_SUCCESS;
    for (uint32_t attempt = 0; attempt < RAW_INIT_MAX_ATTEMPTS; attempt++) {
        BslList *list = BSL_LIST_New(sizeof(BslListNode));
        ES_NoiseSource *ns = src->newNs();
        (*attempts)++;
        if (list == NULL) {
            *lastRet = CRYPT_MEM_ALLOC_FAIL;
            FreeDetachedNs(ns);
            continue;
        }
        if (ns == NULL) {
            *lastRet = CRYPT_MEM_ALLOC_FAIL;
            ES_NsListFree(list);
            continue;
        }
        int32_t ret = BSL_LIST_AddElement(list, ns, BSL_LIST_POS_END);
        if (ret != CRYPT_SUCCESS) {
            *lastRet = ret;
            FreeDetachedNs(ns);
            ES_NsListFree(list);
            continue;
        }
        ret = ES_NsListInit(list, true);
        if (ret == CRYPT_SUCCESS) {
            *outNs = ns;
            return list;
        }
        *lastRet = ret;
        ES_NsListFree(list);
    }
    return NULL;
}

static int DumpRestart(const RawSource *src, FILE *fp, FILE *fu, uint64_t rows, int u64Out)
{
    RawHealthStat hs = {0};
    RawHealthReset(&hs);
    uint64_t totalAttempts = 0;
    uint64_t osrCounts[NS_DELTA_OSR_MAX + 1] = {0};
    for (uint64_t row = 0; row < rows; row++) {
        ES_NoiseSource *ns = NULL;
        uint32_t attempts = 0;
        int32_t lastRet = CRYPT_SUCCESS;
        BslList *list = InitProductionSource(src, &ns, &attempts, &lastRet);
        totalAttempts += attempts;
        if (list == NULL) {
            fprintf(stderr, "row %llu: production source initialization failed after %u attempts, last ret=0x%x\n",
                (unsigned long long)row, attempts, (unsigned)lastRet);
            return 1;
        }
        uint32_t osr = ns->osr;
        if (osr <= NS_DELTA_OSR_MAX) {
            osrCounts[osr]++;
        }
        RawHealthReset(&hs);
        int ret = WriteSamples(src, ns->usrdata, fp, fu, &hs, RAW_RESTART_ROW_SAMPLES, u64Out);
        ES_NsListFree(list);
        if (ret != 0) {
            return ret;
        }
        if ((row + 1) % 100 == 0) {
            fprintf(stderr, "\r%llu / %llu rows", (unsigned long long)(row + 1),
                (unsigned long long)rows);
        }
    }
    fprintf(stderr, "\nproduction init: %llu successful restarts, %llu total attempts; effective osr",
        (unsigned long long)rows, (unsigned long long)totalAttempts);
    for (uint32_t osr = NS_DELTA_OSR_MIN; osr <= NS_DELTA_OSR_MAX; osr++) {
        if (osrCounts[osr] != 0) {
            fprintf(stderr, " %u=%llu", osr, (unsigned long long)osrCounts[osr]);
        }
    }
    fprintf(stderr, "\nrestart done: %llu rows x %d samples\n",
        (unsigned long long)rows, RAW_RESTART_ROW_SAMPLES);
    RawHealthPrint(&hs);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr,
            "usage: %s <jitter|hashloop|blocks> <seq|restart> <outfile> [count] [u64|lsb8]\n"
            "       jitter, hashloop : production noise-source raw symbols for assessment\n"
            "       blocks           : production-path capture of the conditioner input via the\n"
            "                          linked library (seq only, lsb8 only; count = runtime bytes;\n"
            "                          writes <outfile>, <outfile>.startup, <outfile>.journal.csv)\n",
            argv[0]);
        return 1;
    }
    const RawSource *src = NULL;
    int blocksMode = 0;
    if (strcmp(argv[1], "jitter") == 0) {
#ifdef HITLS_CRYPTO_ENTROPY_NS_CPUJITTER
        src = &g_rawJitter;
#else
        fprintf(stderr, "jitter source not compiled in (HITLS_CRYPTO_ENTROPY_NS_CPUJITTER)\n");
        return 1;
#endif
    } else if (strcmp(argv[1], "hashloop") == 0) {
#ifdef HITLS_CRYPTO_ENTROPY_NS_HASHLOOP
        src = &g_rawHashLoop;
        fprintf(stderr, "hashloop: production es_ns_hashloop.c path, HITLS_HASHLOOP_ITERATIONS=%d\n",
            HITLS_HASHLOOP_ITERATIONS);
#else
        fprintf(stderr, "hashloop source not compiled in (HITLS_CRYPTO_ENTROPY_NS_HASHLOOP)\n");
        return 1;
#endif
    } else if (strcmp(argv[1], "blocks") == 0) {
#ifdef HITLS_CRYPTO_ENTROPY_NS_HASHLOOP
        blocksMode = 1;
        fprintf(stderr, "blocks: production-path capture through the linked library\n");
#else
        fprintf(stderr, "blocks source needs HITLS_CRYPTO_ENTROPY_NS_HASHLOOP\n");
        return 1;
#endif
    } else {
        fprintf(stderr, "unknown source: %s\n", argv[1]);
        return 1;
    }

    int restartMode = (strcmp(argv[2], "restart") == 0);
    if (!restartMode && strcmp(argv[2], "seq") != 0) {
        fprintf(stderr, "unknown mode: %s\n", argv[2]);
        return 1;
    }
    if (blocksMode && restartMode) {
        fprintf(stderr, "blocks supports seq only\n");
        return 1;
    }
    uint64_t count = restartMode ? RAW_RESTART_DEFAULT_ROWS : RAW_SEQ_DEFAULT_SAMPLES;
    if (argc > 4) {
        char *end = NULL;
        errno = 0;
        unsigned long long v = strtoull(argv[4], &end, 10);
        /* strtoull wraps a leading minus into the unsigned range; reject it. */
        if (argv[4][0] == '-' || errno != 0 || end == argv[4] || *end != '\0' || v == 0) {
            fprintf(stderr, "invalid count: %s\n", argv[4]);
            return 1;
        }
        count = v;
    }
    int u64Out = 1;
    if (argc > 5) {
        if (strcmp(argv[5], "lsb8") == 0) {
            u64Out = 0;
        } else if (strcmp(argv[5], "u64") != 0) {
            fprintf(stderr, "unknown format: %s\n", argv[5]);
            return 1;
        }
    }
#ifdef HITLS_CRYPTO_ENTROPY_NS_HASHLOOP
    if (blocksMode) {
        if (argc > 5 && strcmp(argv[5], "u64") == 0) {
            fprintf(stderr, "blocks captures the conditioner input byte stream; u64 is unavailable\n");
            return 1;
        }
        return DumpBlocks(argv[3], count);
    }
#endif
    FILE *fp = fopen(argv[3], "wb");
    if (fp == NULL) {
        perror("fopen");
        return 1;
    }
    FILE *fu = NULL;
    if (!u64Out) {
        char upath[4096];
        int m = snprintf(upath, sizeof(upath), "%s.u64", argv[3]);
        if (m < 0 || (size_t)m >= sizeof(upath)) {
            fprintf(stderr, "outfile path too long\n");
            (void)fclose(fp);
            return 1;
        }
        fu = fopen(upath, "wb");
        if (fu == NULL) {
            perror("fopen");
            (void)fclose(fp);
            return 1;
        }
    }
    int ret = restartMode ? DumpRestart(src, fp, fu, count, u64Out)
                          : DumpSequential(src, fp, fu, count, u64Out);
    /* Evidence files must not silently truncate on the final buffer flush. */
    if (fclose(fp) != 0) {
        perror("fclose");
        ret = 1;
    }
    if (fu != NULL && fclose(fu) != 0) {
        perror("fclose");
        ret = 1;
    }
    return ret;
}
#endif
