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
#ifdef HITLS_CRYPTO_BN

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "bn_bincal.h"
#include "bn_optimizer.h"
#include "crypt_utils.h"
#include "bn_montbin.h"

// The mont contains 4 BN_UINT* fields and 2 common fields.
#define MAX_MONT_SIZE ((BITS_TO_BN_UNIT(BN_MAX_BITS) * 4 + 2) * sizeof(BN_UINT))

static void CopyConsttime(BN_UINT *dst, const BN_UINT *a, const BN_UINT *b, uint32_t len, BN_UINT mask)
{
    BN_UINT rmask = ~mask;
    for (uint32_t i = 0; i < len; i++) {
        dst[i] = (a[i] & mask) ^ (b[i] & rmask);
    }
}

/* reduce(r) */
static void MontDecBin(BN_UINT *r, BN_Mont *mont)
{
    uint32_t mSize = mont->mSize;
    BN_UINT *x = mont->t;
    BN_COPY_BYTES(x, mSize << 1, r, mSize);
    Reduce(r, x, mont->one, mont->mod, mSize, mont->k0);
}

/* Return value is (r - m0)' mod r */
static BN_UINT Inverse(BN_UINT m0)
{
    BN_UINT x = 2; /* 2^1 */
    BN_UINT y = 1;
    BN_UINT mask = 1; /* Mask */
    for (uint32_t i = 1; i < BN_UINT_BITS; i++, x <<= 1) {
        BN_UINT rH, rL;
        mask = (mask << 1) | 1;
        MUL_AB(rH, rL, m0, y);
        if (x < (rL & mask)) {
            y += x;
        }
        (void)rH;
    }
    return (BN_UINT)(0 - y);
}

/* Pre-computation */
static int32_t MontExpReady(BN_BigNum *table[], uint32_t num, BN_Mont *mont, BN_Optimizer *opt)
{
    BN_UINT *b = mont->b;
    uint32_t i;
    for (i = 1; i < num; i++) { /* Request num - 1 data blocks */
        table[i] = OptimizerGetBn(opt, mont->mSize);
        if (table[i] == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
            return CRYPT_BN_OPTIMIZER_GET_FAIL;
        }
    }
    table[0] = table[1];
    memcpy(table[1]->data, b, mont->mSize * sizeof(BN_UINT));

    for (i = 2; i < num; i++) { /* precompute num - 2 data blocks */
        int32_t ret = MontMulBin(table[i]->data, table[0]->data, table[i - 1]->data, mont, opt, false);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
    return CRYPT_SUCCESS;
}

static uint32_t GetELimb(const BN_UINT *e, BN_UINT *eLimb, uint32_t base, uint32_t bits)
{
    if (bits > base) { /* Required data */
        (*eLimb) = e[0] & (((1u) << base) - 1);
        return base;
    }
    (*eLimb) = 0;
    for (uint32_t i = 0; i < bits; i++) {
        uint32_t bit = base - i - 1;
        uint32_t nw = bit / BN_UINT_BITS; /* shift words */
        uint32_t nb = bit % BN_UINT_BITS; /* shift bits */
        (*eLimb) <<= 1;
        (*eLimb) |= ((e[nw] >> nb) & 1);
    }
    return bits;
}

static uint32_t GetReadySize(uint32_t bits)
{
    if (bits > 512) { /* If bits are greater than 512 */
        return 6;     /* The size is 6. */
    }
    if (bits > 256) { /* If bits are greater than 256 */
        return 5;     /* The size is 5. */
    }
    if (bits > 128) { /* If bits are greater than 128 */
        return 4;     /* The size is 4. */
    }
    if (bits > 64) {  /* If bits are greater than 64 */
        return 3;     /* The size is 3. */
    }
    if (bits > 32) {  /* If bits are greater than 32 */
        return 2;     /* The size is 2. */
    }
    return 1;
}

/* r = r ^ e mod mont */
static int32_t MontExpBin(BN_UINT *r, const BN_UINT *e, uint32_t eSize, BN_Mont *mont, BN_Optimizer *opt)
{
    BN_BigNum *table[64] = { 0 }; /* 0 -- 2^6 that is 0 -- 64 */
    int32_t ret = OptimizerStart(opt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    memcpy(mont->b, r, mont->mSize * sizeof(BN_UINT));
    uint32_t base = BinBits(e, eSize) - 1;
    uint32_t perSize = GetReadySize(base);
    const uint32_t readySize = 1 << perSize;
    ret = MontExpReady(table, readySize, mont, opt);
    if (ret != CRYPT_SUCCESS) {
        OptimizerEnd(opt);
        return ret;
    }
    do {
        BN_UINT eLimb;
        uint32_t bit = GetELimb(e, &eLimb, base, perSize);
        for (uint32_t i = 0; i < bit; i++) {
            ret = MontSqrBin(r, mont, opt, false);
            if (ret != CRYPT_SUCCESS) {
                OptimizerEnd(opt);
                return ret;
            }
        }
        if (eLimb != 0) {
            ret = MontMulBin(r, r, table[eLimb]->data, mont, opt, false);
            if (ret != CRYPT_SUCCESS) {
                OptimizerEnd(opt);
                return ret;
            }
        }
        base -= bit;
    } while (base != 0);
    OptimizerEnd(opt);
    return CRYPT_SUCCESS;
}

/*
 * Window size (in bits) for the constant-time exponentiation, chosen from the
 * public exponent bit bound. The thresholds account for the cost of the
 * constant-time table scan, which grows with 2^w: they minimize
 * bits/w multiplications + (2^w - 2) precomputations + (bits/w) table scans.
 */
static uint32_t ConsttimeWinSize(uint32_t bits)
{
    if (bits > 2560) { /* If bits are greater than 2560 */
        return 6;      /* The window size is 6. */
    }
    if (bits > 320) {  /* If bits are greater than 320 */
        return 5;      /* The window size is 5. */
    }
    if (bits > 80) {   /* If bits are greater than 80 */
        return 4;      /* The window size is 4. */
    }
    if (bits > 20) {   /* If bits are greater than 20 */
        return 3;      /* The window size is 3. */
    }
    return 2;
}

/*
 * The constant-time precomputation table keeps b^0 .. b^(2^w - 1) in one
 * contiguous buffer in limb-interleaved order: limb j of entry i is stored at
 * tbl[(j << w) + i]. Secret-dependent entries are read by scanning the entire
 * table with masks (MontExpGather), so the memory access pattern is
 * independent of the exponent and reveals nothing through the data cache.
 */

/* Store entry idx into the interleaved table. Only used with public idx values
   (the fixed 0..2^w-1 order of the precomputation). */
static void MontExpScatter(BN_UINT *tbl, const BN_UINT *src, uint32_t mSize, uint32_t winBits, uint32_t idx)
{
    for (uint32_t j = 0; j < mSize; j++) {
        tbl[(j << winBits) + idx] = src[j];
    }
}

/* Read entry idx from the interleaved table. Only used with public idx values
   (the fixed order of the precomputation). */
static void MontExpReadEntry(BN_UINT *dst, const BN_UINT *tbl, uint32_t mSize, uint32_t winBits, uint32_t idx)
{
    for (uint32_t j = 0; j < mSize; j++) {
        dst[j] = tbl[(j << winBits) + idx];
    }
}

#if defined(HITLS_CRYPTO_BN_X8664) && defined(__x86_64__) && defined(HITLS_SIXTY_FOUR_BITS) && \
    (defined(__GNUC__) || defined(__clang__))
#define HITLS_BN_MONT_GATHER_SIMD
#endif

#ifndef HITLS_BN_MONT_GATHER_SIMD
/* Load entry idx from the interleaved table. idx is secret: every table word
   is read and selected with masks, never addressed by idx. Splitting
   idx = hi * stride + lo lets the 4 hi masks and the stride lo masks be
   computed once, so the scan needs ~1 logic operation per word read.
   Requires winBits >= 2. */
static void MontExpGather(BN_UINT *dst, const BN_UINT *tbl, uint32_t mSize, uint32_t winBits, BN_UINT idx)
{
    const uint32_t stride = (1u << winBits) >> 2;
    const BN_UINT hi = idx >> (winBits - 2);
    const BN_UINT y0 = BN_IsZeroUintConsttime(hi ^ 0);
    const BN_UINT y1 = BN_IsZeroUintConsttime(hi ^ 1);
    const BN_UINT y2 = BN_IsZeroUintConsttime(hi ^ 2);
    const BN_UINT y3 = BN_IsZeroUintConsttime(hi ^ 3);
    const BN_UINT lo = idx & (BN_UINT)(stride - 1);
    BN_UINT loMask[16]; /* stride = 2^(winBits - 2) <= 16 */
    for (uint32_t i = 0; i < stride; i++) {
        loMask[i] = BN_IsZeroUintConsttime((BN_UINT)i ^ lo);
    }
    for (uint32_t j = 0; j < mSize; j++) {
        const BN_UINT *row = tbl + ((uintptr_t)j << winBits);
        BN_UINT acc = 0;
        for (uint32_t i = 0; i < stride; i++) {
            acc |= (((row[i] & y0) | (row[i + stride] & y1)) |
                    ((row[i + 2 * stride] & y2) | (row[i + 3 * stride] & y3))) & loMask[i];
        }
        dst[j] = acc;
    }
}
#endif /* !HITLS_BN_MONT_GATHER_SIMD */

#ifdef HITLS_BN_MONT_GATHER_SIMD
#include <immintrin.h>

/* The SIMD gathers below share the scalar gather's security contract: every
   table word is read with plain full-width loads at public addresses, and the
   secret idx only reaches the equality masks. The table scan is bound by load
   width, so each wider variant roughly halves its cost. */

/* 128-bit loads, baseline on x86_64 (no runtime dispatch needed). */
static void MontExpGatherSse2(BN_UINT *dst, const BN_UINT *tbl, uint32_t mSize, uint32_t winBits, BN_UINT idx)
{
    const uint32_t nvec = (1u << winBits) >> 1;
    __m128i vm[32]; /* tabSize / 2 <= 32 selection mask vectors */
    __m128i vi = _mm_set_epi64x(1, 0);
    const __m128i vidx = _mm_set1_epi64x((long long)idx);
    const __m128i vstep = _mm_set1_epi64x(2);
    for (uint32_t i = 0; i < nvec; i++) {
        /* 64-bit lane equality from two 32-bit compares (SSE2 has no pcmpeqq):
           both halves of a lane match only when the whole lane matches, since
           idx < 2^6 keeps the high halves zero. */
        const __m128i eq = _mm_cmpeq_epi32(vi, vidx);
        vm[i] = _mm_and_si128(eq, _mm_shuffle_epi32(eq, 0xB1)); /* 0xB1 swaps 32-bit pairs */
        vi = _mm_add_epi64(vi, vstep);
    }
    for (uint32_t j = 0; j < mSize; j++) {
        const BN_UINT *row = tbl + ((uintptr_t)j << winBits);
        __m128i acc = _mm_setzero_si128();
        for (uint32_t i = 0; i < nvec; i++) {
            acc = _mm_or_si128(acc,
                _mm_and_si128(_mm_loadu_si128((const __m128i *)(row + 2 * i)), vm[i]));
        }
        acc = _mm_or_si128(acc, _mm_unpackhi_epi64(acc, acc));
        dst[j] = (BN_UINT)_mm_cvtsi128_si64(acc);
    }
}

/* 256-bit loads, dispatched at run time. */
__attribute__((target("avx2")))
static void MontExpGatherAvx2(BN_UINT *dst, const BN_UINT *tbl, uint32_t mSize, uint32_t winBits, BN_UINT idx)
{
    const uint32_t nvec = (1u << winBits) >> 2;
    __m256i vm[16]; /* tabSize / 4 <= 16 selection mask vectors */
    __m256i vi = _mm256_set_epi64x(3, 2, 1, 0);
    const __m256i vidx = _mm256_set1_epi64x((long long)idx);
    const __m256i vstep = _mm256_set1_epi64x(4);
    for (uint32_t i = 0; i < nvec; i++) {
        vm[i] = _mm256_cmpeq_epi64(vi, vidx);
        vi = _mm256_add_epi64(vi, vstep);
    }
    for (uint32_t j = 0; j < mSize; j++) {
        const BN_UINT *row = tbl + ((uintptr_t)j << winBits);
        __m256i acc = _mm256_setzero_si256();
        for (uint32_t i = 0; i < nvec; i++) {
            acc = _mm256_or_si256(acc,
                _mm256_and_si256(_mm256_loadu_si256((const __m256i *)(row + 4 * i)), vm[i]));
        }
        __m128i fold = _mm_or_si128(_mm256_castsi256_si128(acc), _mm256_extracti128_si256(acc, 1));
        fold = _mm_or_si128(fold, _mm_unpackhi_epi64(fold, fold));
        dst[j] = (BN_UINT)_mm_cvtsi128_si64(fold);
    }
}

#endif

typedef void (*MontExpGatherFunc)(BN_UINT *dst, const BN_UINT *tbl, uint32_t mSize, uint32_t winBits, BN_UINT idx);

/* A 512-bit gather tier was measured and rejected: the scan is a small share
   of the runtime, and the AVX-512 frequency licensing it triggers slows the
   surrounding scalar multiplication kernels by far more than it saves. */
static MontExpGatherFunc MontExpSelectGather(void)
{
#ifdef HITLS_BN_MONT_GATHER_SIMD
    if (IsSupportAVX2() && IsOSSupportAVX()) {
        return MontExpGatherAvx2;
    }
    return MontExpGatherSse2;
#else
    return MontExpGather;
#endif
}

/* BinFixSize equivalent without value-dependent branches: the scan always
   reads every word and selects the highest nonzero index with masks. */
static uint32_t ConsttimeFixSize(const BN_UINT *data, uint32_t size)
{
    uint32_t cnt = 0;
    for (uint32_t i = 0; i < size; i++) {
        const BN_UINT mask = ~BN_IsZeroUintConsttime(data[i]);
        cnt = (uint32_t)((mask & (i + 1)) | (~mask & cnt));
    }
    return cnt;
}

/* One window: winBits squarings followed by the multiplication with the
   gathered table entry. */
static int32_t MontExpWinStep(BN_UINT *r, const BN_UINT *tblEntry, uint32_t winBits, BN_Mont *mont, BN_Optimizer *opt)
{
    for (uint32_t i = 0; i < winBits; i++) {
        int32_t ret = MontSqrBin(r, mont, opt, true);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
    return MontMulBin(r, r, tblEntry, mont, opt, true);
}

/*
 * r = r ^ (e mod 2^eBits) mod mont, r holds the Montgomery form of the base
 * on entry. eBits is a public upper bound of the exponent bit length: 0 (or
 * anything above the word width of e) selects the full eSize * BN_UINT_BITS.
 * Fixed-window exponentiation whose control flow, operation count, and memory
 * access pattern depend only on the public quantities (eBits, eSize, mSize),
 * never on the value of e:
 *  - a fixed number of exponent bits is processed, so the timing does not
 *    reveal the bit length of e (the classic leading-zero-bits leak on
 *    DSA/DH secrets), and an all-zero e correctly yields R = mont(1);
 *  - the table holds b^0, so every window performs exactly winBits squarings
 *    and one multiplication, with no zero-window special case;
 *  - window values only select table entries through the gather scan.
 * The first window needs no squaring and no multiplication (its table entry is
 * the result so far), which also saves rounds compared to consuming the top
 * window bit by bit. Even table entries are filled by squaring the half-index
 * entry (public indexes), which is cheaper than the multiplication chain.
 */
static int32_t MontExpConsttimeBin(BN_UINT *r, const BN_UINT *e, uint32_t eSize, uint32_t eBits,
    BN_Mont *mont, BN_Optimizer *opt)
{
    const uint32_t mSize = mont->mSize;
    uint32_t bits = eSize * BN_UINT_BITS;
    if (eBits != 0 && eBits < bits) {
        bits = eBits;
    }
    uint32_t winBits = ConsttimeWinSize(bits);
    /* Keep the table inside the BigNum size limit; the mask split needs
       winBits >= 2 (a modulus large enough to still overflow the table at
       winBits == 2 is far beyond any computable exponentiation and fails
       cleanly at the allocation below). */
    while (winBits > 2 && (mSize << winBits) > BITS_TO_BN_UNIT(BN_MAX_BITS)) {
        winBits--;
    }
    const MontExpGatherFunc gather = MontExpSelectGather();
    int32_t ret = OptimizerStart(opt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    BN_BigNum *tblBn = OptimizerGetBn(opt, mSize << winBits);
    BN_BigNum *cur = OptimizerGetBn(opt, mSize);
    if (tblBn == NULL || cur == NULL) {
        OptimizerEnd(opt);
        BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
        return CRYPT_BN_OPTIMIZER_GET_FAIL;
    }
    BN_UINT *tbl = tblBn->data;
    /* entry 0 is b^0 = R mod N = reduce(montRR) */
    BN_COPY_BYTES(mont->t, mSize << 1, mont->montRR, mSize);
    Reduce(cur->data, mont->t, mont->one, mont->mod, mSize, mont->k0);
    MontExpScatter(tbl, cur->data, mSize, winBits, 0);
    MontExpScatter(tbl, r, mSize, winBits, 1);
    memcpy(mont->b, r, mSize * sizeof(BN_UINT));
    memcpy(cur->data, r, mSize * sizeof(BN_UINT));
    for (uint32_t i = 2; i < (1u << winBits); i++) {
        if ((i & 1) == 0) { /* b^i = (b^(i/2))^2, squaring is cheaper than multiplying */
            MontExpReadEntry(cur->data, tbl, mSize, winBits, i >> 1);
            ret = MontSqrBin(cur->data, mont, opt, true);
        } else { /* b^i = b^(i-1) * b, cur still holds b^(i-1) */
            ret = MontMulBin(cur->data, cur->data, mont->b, mont, opt, true);
        }
        if (ret != CRYPT_SUCCESS) {
            OptimizerEnd(opt);
            return ret;
        }
        MontExpScatter(tbl, cur->data, mSize, winBits, i);
    }
    BN_UINT eLimb = 0;
    uint32_t cnt = bits % winBits;
    cnt = (cnt == 0) ? winBits : cnt;
    (void)GetELimb(e, &eLimb, bits, cnt);
    gather(r, tbl, mSize, winBits, eLimb);
    for (uint32_t remain = bits - cnt; remain != 0; remain -= winBits) {
        (void)GetELimb(e, &eLimb, remain, winBits);
        gather(cur->data, tbl, mSize, winBits, eLimb);
        ret = MontExpWinStep(r, cur->data, winBits, mont, opt);
        if (ret != CRYPT_SUCCESS) {
            OptimizerEnd(opt);
            return ret;
        }
    }
    OptimizerEnd(opt);
    return CRYPT_SUCCESS;
}

static int32_t MontParaCheck(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *e, const BN_Mont *mont,
    const BN_Optimizer *opt)
{
    if (r == NULL || a == NULL || e == NULL || mont == NULL || opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (e->sign) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_EXP_NO_NEGATIVE);
        return CRYPT_BN_ERR_EXP_NO_NEGATIVE;
    }
    return BnExtend(r, mont->mSize);
}

static const BN_BigNum *DealBaseNum(const BN_BigNum *a, BN_Mont *mont, BN_Optimizer *opt, int32_t *ret)
{
    const BN_BigNum *aTmp = a;
    if (BinCmp(a->data, a->size, mont->mod, mont->mSize) >= 0) {
        BN_BigNum *tmpval = OptimizerGetBn(opt, a->size + 2); // BinDiv need a->room >= a->size + 2
        BN_BigNum *tmpMod = OptimizerGetBn(opt, mont->mSize); // BinDiv need a->room >= a->size + 2
        if (tmpval == NULL || tmpMod == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
            *ret = CRYPT_BN_OPTIMIZER_GET_FAIL;
            return NULL;
        }
        *ret = BN_Copy(tmpval, a);
        if (*ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(*ret);
            return NULL;
        }
        memcpy(tmpMod->data, mont->mod, mont->mSize * sizeof(BN_UINT));
        tmpval->size = BinDiv(NULL, NULL, tmpval->data, tmpval->size, tmpMod->data, mont->mSize);
        aTmp = tmpval;
    }
    return aTmp;
}

static const BN_UINT *TmpValueHandle(BN_BigNum *r, const BN_BigNum *e, const BN_BigNum *a, BN_Optimizer *opt)
{
    const BN_UINT *te = e->data;
    uint32_t esize = e->size;
    if (e == r) {
        BN_BigNum *ee = OptimizerGetBn(opt, esize);
        if (ee == NULL) {
            return NULL;
        }
        memcpy(ee->data, e->data, esize * sizeof(BN_UINT));
        te = ee->data;
    }
    BN_COPY_BYTES(r->data, r->room, a->data, a->size);
    return te;
}

/* whether e == 0, reading every word without value-dependent branches
   (BinBits' bit scan would leak the leading-zero count of a secret exponent) */
static bool MontExpIsZero(const BN_BigNum *e)
{
    BN_UINT acc = 0;
    for (uint32_t i = 0; i < e->size; i++) {
        acc |= e->data[i];
    }
    return acc == 0;
}

/*
 * Constant-time variant of MontExpCore: after the public-metadata checks, no
 * branch, loop bound, or memory index depends on the values of a, e, or the
 * result — only on their public word counts.
 */
static int32_t MontExpConsttimeCore(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *e, uint32_t eBits,
    BN_Mont *mont, BN_Optimizer *opt)
{
    const uint32_t mSize = mont->mSize;
    if (e->size == 0) { /* a normalized zero exponent, known from public metadata */
        if (mSize != 1) {
            return BN_SetLimb(r, 1);
        }
        return (mont->mod[0] == 1) ? BN_Zeroize(r) : BN_SetLimb(r, 1);
    }
    int32_t ret = OptimizerStart(opt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    const BN_BigNum *aTmp = a;
    if (a->size > mSize) {
        /* More words than the modulus (outside the documented |a| < mod
           contract): fall back to the division-based reduction on this public
           size condition. Values within mSize words need no pre-reduction:
           the Montgomery encoding below reduces any r < 2^(mSize * 64). */
        aTmp = DealBaseNum(a, mont, opt, &ret);
        if (aTmp == NULL) {
            OptimizerEnd(opt);
            return ret;
        }
    }
    const BN_UINT *te = TmpValueHandle(r, e, aTmp, opt);
    if (te == NULL) {
        OptimizerEnd(opt);
        BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
        return CRYPT_BN_OPTIMIZER_GET_FAIL;
    }
    /* field conversion */
    ret = MontEncBin(r->data, mont, opt, true);
    if (ret != CRYPT_SUCCESS) {
        OptimizerEnd(opt);
        return ret;
    }
    /* modular exponentiation */
    ret = MontExpConsttimeBin(r->data, te, e->size, eBits, mont, opt);
    if (ret != CRYPT_SUCCESS) {
        OptimizerEnd(opt);
        return ret;
    }
    /* field conversion */
    MontDecBin(r->data, mont);

    if (aTmp->sign) { /* the sign is public metadata */
        /* When the exponent is odd and the result nonzero, the result is
           mod - r; compute it unconditionally and select with masks. */
        BN_UINT nz = 0;
        for (uint32_t i = 0; i < mSize; i++) {
            nz |= r->data[i];
        }
        const BN_UINT mask = ((BN_UINT)0 - (te[0] & 1)) & ~BN_IsZeroUintConsttime(nz);
        BinSub(mont->t, mont->mod, r->data, mSize);
        CopyConsttime(r->data, mont->t, r->data, mSize, mask);
    }
    r->size = ConsttimeFixSize(r->data, mSize);
    r->sign = false;
    OptimizerEnd(opt);
    return CRYPT_SUCCESS;
}

/* must satisfy the absolute value x < mod */
static int32_t MontExpCore(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *e,
    BN_Mont *mont, BN_Optimizer *opt, bool consttime)
{
    if (consttime) {
        return MontExpConsttimeCore(r, a, e, 0, mont, opt);
    }
    if (MontExpIsZero(e)) {
        if (mont->mSize != 1) {
            return BN_SetLimb(r, 1);
        }
        return (mont->mod[0] == 1) ? BN_Zeroize(r) : BN_SetLimb(r, 1);
    }
    if (a->size == 0) {
        return BN_Zeroize(r);
    }
    int32_t ret = OptimizerStart(opt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    /* if a >= mod */
    const BN_BigNum *aTmp = DealBaseNum(a, mont, opt, &ret);
    if (aTmp == NULL) {
        OptimizerEnd(opt);
        return ret;
    }
    const BN_UINT *te = TmpValueHandle(r, e, aTmp, opt);
    if (te == NULL) {
        OptimizerEnd(opt);
        BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
        return CRYPT_BN_OPTIMIZER_GET_FAIL;
    }
    /* field conversion */
    ret = MontEncBin(r->data, mont, opt, false);
    if (ret != CRYPT_SUCCESS) {
        OptimizerEnd(opt);
        return ret;
    }
    /* modular exponentiation */
    ret = MontExpBin(r->data, te, e->size, mont, opt);
    if (ret != CRYPT_SUCCESS) {
        OptimizerEnd(opt);
        return ret;
    }
    /* field conversion */
    MontDecBin(r->data, mont);

    /* negative number processing */
    r->size = BinFixSize(r->data, mont->mSize);
    if (aTmp->sign && ((te[0] & 0x1) == 1) && r->size != 0) {
        BinSub(r->data, mont->mod, r->data, mont->mSize);
        r->size = BinFixSize(r->data, mont->mSize);
    }
    r->sign = false;
    OptimizerEnd(opt);
    return CRYPT_SUCCESS;
}

static int32_t MontExp(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *e, BN_Mont *mont,
    BN_Optimizer *opt, bool consttime)
{
    int32_t ret = MontParaCheck(r, a, e, mont, opt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    return MontExpCore(r, a, e, mont, opt, consttime);
}

int32_t BN_MontExp(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *e, BN_Mont *mont, BN_Optimizer *opt)
{
    bool consttime = (BN_IsFlag(a, CRYPT_BN_FLAG_CONSTTIME) || BN_IsFlag(e, CRYPT_BN_FLAG_CONSTTIME));
    return MontExp(r, a, e, mont, opt, consttime);
}

/* must satisfy the absolute value x < mod */
int32_t BN_MontExpConsttime(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *e, BN_Mont *mont, BN_Optimizer *opt)
{
    return MontExp(r, a, e, mont, opt, true);
}

/* must satisfy the absolute value x < mod */
int32_t BN_MontExpConsttimeBits(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *e, uint32_t eBits,
    BN_Mont *mont, BN_Optimizer *opt)
{
    int32_t ret = MontParaCheck(r, a, e, mont, opt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return MontExpConsttimeCore(r, a, e, eBits, mont, opt);
}

static uint32_t MontSize(uint32_t room)
{
    uint32_t size = (uint32_t)(sizeof(BN_Mont) + sizeof(BN_UINT));
    /* Requires 6 * room + 1 space. mod(1) + montRR(1) + b(1) + t(2) + one = 6.
       In addition, one more room is required when the modulus is set later. */
    size += (room * 6 + 1) * ((uint32_t)sizeof(BN_UINT));
    return size;
}

void BN_MontDestroy(BN_Mont *mont)
{
    if (mont == NULL) {
        return;
    }
    memset(mont, 0, MontSize(mont->mSize));
    BSL_SAL_FREE(mont);
}

/* set the modulus */
static void SetMod(BN_Mont *mont, const BN_BigNum *mod)
{
    uint32_t mSize = mod->size;
    memcpy(mont->mod, mod->data, mSize * sizeof(BN_UINT));
    memset(mont->one, 0, mSize * 3 * sizeof(BN_UINT)); /* clear one and RR */
    mont->one[0] = 1;    /* set one */
    mont->k0 = Inverse(mod->data[0]);
    mont->montRR[mSize * 2] = 1; /* 2^2n */
    mont->montRR[mSize * 2 + 1] = 0; /* 2 more rooms are provided to ensure the division does not exceed the limit */
    mont->montRR[mSize * 2 + 2] = 0; /* 2 more rooms are provided to ensure the division does not exceed the limit */

    // The size of the space required for calculating the montRR is 2 * mSize + 1
    (void)BinDiv(NULL, NULL, mont->montRR, 2 * mSize + 1, mont->mod, mSize);
    memcpy(mont->mod, mod->data, mSize * sizeof(BN_UINT));
}

/* create a Montgomery structure, where m is a modulo */
BN_Mont *BN_MontCreate(const BN_BigNum *m)
{
    if (m == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    if (!BN_GetBit(m, 0) || m->sign) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return NULL;
    }
    uint32_t mSize = m->size;
    uint32_t montSize = MontSize(mSize);
    if (montSize > MAX_MONT_SIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_BITS_TOO_MAX);
        return NULL;
    }
    BN_Mont *mont = BSL_SAL_Malloc(montSize);
    if (mont == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    BN_UINT *base = AlignedPointer((uint8_t *)mont + sizeof(BN_Mont), sizeof(BN_UINT));
    mont->mSize = mSize;
    mont->mod = base;               /* mSize */
    mont->one = (base += mSize);    /* mSize */
    mont->montRR = (base += mSize); /* mSize */
    mont->b = (base += mSize);      /* mSize */
    mont->t = base + mSize;         /* 2 * mSize */
    SetMod(mont, m);
    return mont;
}

int32_t MontSqrBinCore(BN_UINT *r, BN_Mont *mont, BN_Optimizer *opt, bool consttime)
{
    int32_t ret = OptimizerStart(opt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    uint32_t mSize = mont->mSize;
    BN_UINT *x = mont->t;
#ifdef HITLS_CRYPTO_BN_COMBA
    BN_BigNum *bnSpace = OptimizerGetBn(opt, SpaceSize(mSize));
    if (bnSpace == NULL) {
        OptimizerEnd(opt);
        BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
        return CRYPT_BN_OPTIMIZER_GET_FAIL;
    }
    SqrConquer(x, r, mSize, bnSpace->data, consttime);
#else
    (void)consttime;
    BinSqr(x, mSize << 1, r, mSize);
#endif
    Reduce(r, x, mont->one, mont->mod, mSize, mont->k0);

    OptimizerEnd(opt);
    return CRYPT_SUCCESS;
}

/* reduce（a）= (a * R') mod N) */
void ReduceCore(BN_UINT *r, BN_UINT *x, const BN_UINT *m, uint32_t mSize, BN_UINT m0)
{
    BN_UINT carry = 0;
    uint32_t n = 0;
    /* Cyclic shift, obtain r = (x / R) mod N  */
    do {
        BN_UINT q = x[n] * m0; /* q = (s[0] + x[i]) * m0 */
        BN_UINT tmp = BinMulAcc(x + n, m, mSize, q); /* (s + qm) mod m == s. Refresh s[0] to x[0] */
        /* Add carry to tmp and update carry flag. */
        tmp = tmp + carry;
        carry = (tmp < carry) ? 1 : 0;
        /* Add tmp to x[mSize + n] and update the carry flag. */
        x[mSize + n] += tmp;
        carry = (x[mSize + n] < tmp) ? 1 : carry;
        if (n + 1 == mSize) {
            break;
        }
        n++;
    } while (true);
    /* If x < 2m, the carry value is 0 or -1. */
    carry -= BinSub(r, x + mSize, m, mSize);
    CopyConsttime(r, x + mSize, r, mSize, carry);
}

/* reduce(r * RR) */
int32_t MontEncBinCore(BN_UINT *r, BN_Mont *mont, BN_Optimizer *opt, bool consttime)
{
    int32_t ret = OptimizerStart(opt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    uint32_t mSize = mont->mSize;
    BN_UINT *x = mont->t;
#ifdef HITLS_CRYPTO_BN_COMBA
    BN_BigNum *bnSpace = OptimizerGetBn(opt, SpaceSize(mSize));
    if (bnSpace == NULL) {
        OptimizerEnd(opt);
        BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
        return CRYPT_BN_OPTIMIZER_GET_FAIL;
    }

    MulConquer(x, r, mont->montRR, mSize, bnSpace->data, consttime);
#else
    (void)consttime;
    BinMul(x, mSize << 1, r, mSize, mont->montRR, mSize);
#endif

    Reduce(r, x, mont->one, mont->mod, mSize, mont->k0);

    OptimizerEnd(opt);
    return CRYPT_SUCCESS;
}

/* reduce(r * b) */
int32_t MontMulBinCore(BN_UINT *r, const BN_UINT *a, const BN_UINT *b, BN_Mont *mont, BN_Optimizer *opt, bool consttime)
{
    int32_t ret = OptimizerStart(opt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    uint32_t mSize = mont->mSize;
    BN_UINT *x = mont->t;
#ifdef HITLS_CRYPTO_BN_COMBA
    uint32_t size = SpaceSize(mSize);
    BN_BigNum *bnSpace = OptimizerGetBn(opt, size);
    if (bnSpace == NULL) {
        OptimizerEnd(opt);
        BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
        return CRYPT_BN_OPTIMIZER_GET_FAIL;
    }
    MulConquer(x, a, b, mSize, bnSpace->data, consttime);
#else
    (void)consttime;
    BinMul(x, mSize << 1, a, mSize, b, mSize);
#endif
    Reduce(r, x, mont->one, mont->mod, mSize, mont->k0);

    OptimizerEnd(opt);
    return CRYPT_SUCCESS;
}

#ifdef HITLS_CRYPTO_DSA
static int32_t GetFirstData(BN_UINT *r, uint32_t base1, uint32_t base2,
    BN_BigNum *table1[], BN_BigNum *table2[], BN_Mont *mont,
    BN_Optimizer *opt)
{
    bool consttime = false;
    if (base1 == base2) {
        return MontMulBin(r, table1[0]->data, table2[0]->data, mont, opt, consttime);
    } else if (base1 > base2) {
        memcpy(r, table1[0]->data, mont->mSize * sizeof(BN_UINT));
    } else {
        memcpy(r, table2[0]->data, mont->mSize * sizeof(BN_UINT));
    }
    return CRYPT_SUCCESS;
}

/* Precalculate odd multiples of data. The data in the table is b^1, b^3, b^5...b^(2*num - 1) */
static int32_t MontExpOddReady(BN_BigNum *table[], uint32_t num, BN_Mont *mont, BN_Optimizer *opt, bool consttime)
{
    BN_UINT *b = mont->b;
    uint32_t i;
    for (i = 0; i < num; i++) { /* Request num - 1 data blocks */
        table[i] = OptimizerGetBn(opt, mont->mSize);
        if (table[i] == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
            return CRYPT_BN_OPTIMIZER_GET_FAIL;
        }
    }
    memcpy(table[0]->data, b, mont->mSize * sizeof(BN_UINT));
    if (num == 1) {
        // When num is 1, pre-computation is not need.
        return CRYPT_SUCCESS;
    }
    int32_t ret = MontSqrBin(table[0]->data, // b^2
        mont, opt, consttime);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = MontMulBin(table[1]->data, table[0]->data, mont->b, // b^3
        mont, opt, consttime);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    for (i = 2; i < num; i++) { /* precompute num - 2 data blocks */
        // b^(2*i + 1)
        ret = MontMulBin(table[i]->data, table[0]->data, table[i - 1]->data, mont, opt, consttime);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
    memcpy(table[0]->data, b, mont->mSize * sizeof(BN_UINT));
    return CRYPT_SUCCESS;
}

// Obtain the data with the length of bits from the start position of the base to the eLimb,
// ignore the high-order 0 data, and obtain an odd number or 0.
uint32_t GetOddLimbBin(const BN_UINT *e, BN_UINT *eLimb, uint32_t base, uint32_t bits, uint32_t size)
{
    (*eLimb) = 0;
    if (base == 0) {
        return 0;
    }
    uint32_t loc = base;
    uint32_t retBits = 0;
    // Offset from current. Check whether non-zero data exists.
    while (true) {
        loc--;
        uint32_t nw = loc / BN_UINT_BITS; /* shift words */
        uint32_t nb = loc % BN_UINT_BITS; /* shift retBits */
        if (nw < size && ((e[nw] >> nb) & 1) != 0) {
            // Exit the loop when the bit is 1.
            break;
        }
        retBits++;
        if (loc == 0) {
            // If no valid bit is encountered until the end, the subsequent bits are returned.
            return retBits;
        }
    }
    // Obtain valid data from the loc location.
    for (uint32_t i = 0; i < bits; i++) {
        uint32_t nw = loc / BN_UINT_BITS; /* shift words */
        uint32_t nb = loc % BN_UINT_BITS; /* shift retBits */
        (*eLimb) <<= 1;
        (*eLimb) |= ((e[nw] >> nb) & 1);
        retBits++;
        if (loc == 0) {
            // The remaining data is insufficient and the system exits early.
            break;
        }
        loc--;
    }
    // The data must be 0 or an odd number.
    while ((*eLimb) != 0 && ((*eLimb) & 1) == 0) {
        // If eLimb is not 0 and is an even number, shift the eLimb to right.
        (*eLimb) >>= 1;
        retBits--;
    }
    return retBits;
}

/* r = (a1 ^ e1) * (a2 ^ e2) mod mont */
static int32_t MontExpMul(BN_UINT *r, const BN_BigNum *a1, const BN_BigNum *e1,
    const BN_BigNum *a2, const BN_BigNum *e2, BN_Mont *mont, BN_Optimizer *opt)
{
    bool consttime = false;
    BN_UINT eLimb1, eLimb2;
    uint32_t bit1 = 0;
    uint32_t bit2 = 0;
    // The window retains only the values whose exponent is an odd number, reduce storage in half.
    BN_BigNum *table1[32] = { 0 }; /* 0 -- (2^6 >> 1), that is 0 -- 32 */
    BN_BigNum *table2[32] = { 0 }; /* 0 -- (2^6 >> 1), that is 0 -- 32 */
    int32_t ret = OptimizerStart(opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint32_t base1 = BinBits(e1->data, e1->size);
    uint32_t base2 = BinBits(e2->data, e2->size);
    uint32_t base = (base1 > base2) ? base1 : base2;

    uint32_t perSize1 = GetReadySize(base1);
    uint32_t perSize2 = GetReadySize(base2);
    const uint32_t readySize1 = 1 << (perSize1 - 1);
    const uint32_t readySize2 = 1 << (perSize2 - 1);

    // Generate the pre-computation table.
    memcpy(mont->b, a1->data, mont->mSize * sizeof(BN_UINT));
    GOTO_ERR_IF(MontExpOddReady(table1, readySize1, mont, opt, consttime), ret);
    memcpy(mont->b, a2->data, mont->mSize * sizeof(BN_UINT));
    GOTO_ERR_IF(MontExpOddReady(table2, readySize2, mont, opt, consttime), ret);
    // Obtain the first data.
    GOTO_ERR_IF(GetFirstData(r, base1, base2, table1, table2, mont, opt), ret);
    base--;

    while (base != 0) {
        bit1 = (bit1 == 0) ? GetOddLimbBin(e1->data, &eLimb1, base, perSize1, e1->size) : bit1;
        bit2 = (bit2 == 0) ? GetOddLimbBin(e2->data, &eLimb2, base, perSize2, e2->size) : bit2;
        uint32_t bit = (bit1 < bit2) ? bit1 : bit2;
        for (uint32_t i = 0; i < bit; i++) {
            GOTO_ERR_IF(MontSqrBin(r, mont, opt, consttime), ret);
        }
        if (bit == bit1 && eLimb1 != 0) {
            GOTO_ERR_IF(MontMulBin(r, r, table1[(eLimb1 - 1) >> 1]->data, mont, opt, consttime), ret);
        }
        if (bit == bit2 && eLimb2 != 0) {
            GOTO_ERR_IF(MontMulBin(r, r, table2[(eLimb2 - 1) >> 1]->data, mont, opt, consttime), ret);
        }
        bit1 -= bit;
        bit2 -= bit;
        base -= bit;
    };
ERR:
    OptimizerEnd(opt);
    return ret;
}

static int32_t MontExpMulParaCheck(BN_BigNum *r, const BN_BigNum *a1,
    const BN_BigNum *e1, const BN_BigNum *a2, const BN_BigNum *e2, const BN_Mont *mont,
    const BN_Optimizer *opt)
{
    if (r == NULL || a1 == NULL || e1 == NULL || a2 == NULL || e2 == NULL || mont == NULL || opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (e1->sign || e2->sign) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_EXP_NO_NEGATIVE);
        return CRYPT_BN_ERR_EXP_NO_NEGATIVE;
    }
    return BnExtend(r, mont->mSize);
}

typedef struct {
    BN_BigNum *a1;
    BN_BigNum *a2;
    BN_BigNum *e1;
    BN_BigNum *e2;
} MontsMulFactor;

static int32_t MontsFactorGetByOptThenCopy(MontsMulFactor *dst, const MontsMulFactor *src,
    uint32_t mSize, BN_Optimizer *opt)
{
    dst->a1 = OptimizerGetBn(opt, mSize);
    dst->a2 = OptimizerGetBn(opt, mSize);
    dst->e1 = OptimizerGetBn(opt, mSize);
    dst->e2 = OptimizerGetBn(opt, mSize);
    if (dst->a1 == NULL || dst->a2 == NULL || dst->e1 == NULL || dst->e2 == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
        return CRYPT_BN_OPTIMIZER_GET_FAIL;
    }
    int32_t ret = BN_Copy(dst->a1, src->a1);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = BN_Copy(dst->a2, src->a2);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = BN_Copy(dst->e1, src->e1);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return BN_Copy(dst->e2, src->e2);
}

/* r = (a1 ^ e1) * (a2 ^ e2) mod mont */
int32_t BN_MontExpMul(BN_BigNum *r, const BN_BigNum *a1, const BN_BigNum *e1,
    const BN_BigNum *a2, const BN_BigNum *e2, BN_Mont *mont, BN_Optimizer *opt)
{
    int32_t ret = MontExpMulParaCheck(r, a1, e1, a2, e2, mont, opt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (BinCmp(a2->data, a2->size, mont->mod, mont->mSize) >= 0 ||
        BinCmp(a1->data, a1->size, mont->mod, mont->mSize) >= 0) {
        /* a1 >= mod || a2 >= mod */
        BSL_ERR_PUSH_ERROR(CRYPT_BN_MONT_BASE_TOO_MAX);
        return CRYPT_BN_MONT_BASE_TOO_MAX;
    }
    if (BN_IsZero(a1) || BN_IsZero(a2)) {
        return BN_Zeroize(r);
    }
    if (BN_IsZero(e1)) {
        return MontExpCore(r, a2, e2, mont, opt, false);
    }
    if (BN_IsZero(e2)) {
        return MontExpCore(r, a1, e1, mont, opt, false);
    }
    ret = OptimizerStart(opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    MontsMulFactor factor;
    const MontsMulFactor srcFactor = {(BN_BigNum *)(uintptr_t)a1, (BN_BigNum *)(uintptr_t)a2,
        (BN_BigNum *)(uintptr_t)e1, (BN_BigNum *)(uintptr_t)e2};
    GOTO_ERR_IF_EX(MontsFactorGetByOptThenCopy(&factor, &srcFactor, mont->mSize, opt), ret);
    /* field conversion */
    GOTO_ERR_IF(MontEncBin(factor.a1->data, mont, opt, false), ret);
    GOTO_ERR_IF(MontEncBin(factor.a2->data, mont, opt, false), ret);
    /* modular exponentiation */
    GOTO_ERR_IF_EX(MontExpMul(r->data, factor.a1, factor.e1, factor.a2, factor.e2, mont, opt), ret);
    /* field conversion */
    MontDecBin(r->data, mont);
    r->size = BinFixSize(r->data, mont->mSize);
    r->sign = false;
ERR:
    OptimizerEnd(opt);
    return ret;
}
#endif

#if defined(HITLS_CRYPTO_RSA)

int32_t MontMulCore(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b, BN_Mont *mont, BN_Optimizer *opt)
{
    int32_t ret;
    BN_BigNum *t1 = OptimizerGetBn(opt, mont->mSize);
    if (t1 == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
        return CRYPT_BN_OPTIMIZER_GET_FAIL;
    }
    BN_COPY_BYTES(t1->data, mont->mSize, a->data, a->size);
    BN_COPY_BYTES(r->data, mont->mSize, b->data, b->size);
    GOTO_ERR_IF(MontEncBin(t1->data, mont, opt, false), ret);
    GOTO_ERR_IF(MontEncBin(r->data, mont, opt, false), ret);
    GOTO_ERR_IF(MontMulBin(r->data, t1->data, r->data, mont, opt, false), ret);
    MontDecBin(r->data, mont);
    r->size = BinFixSize(r->data, mont->mSize);
ERR:
    return ret;
}

#endif // HITLS_CRYPTO_RSA

#if defined(HITLS_CRYPTO_BN_PRIME)

int32_t MontSqrCore(BN_BigNum *r, const BN_BigNum *a, BN_Mont *mont, BN_Optimizer *opt)
{
    int32_t ret;
    BN_COPY_BYTES(r->data, mont->mSize, a->data, a->size);
    GOTO_ERR_IF(MontEncBin(r->data, mont, opt, false), ret);
    GOTO_ERR_IF(MontSqrBin(r->data, mont, opt, false), ret);
    MontDecBin(r->data, mont);
    r->size = BinFixSize(r->data, mont->mSize);
ERR:
    return ret;
}

#endif // HITLS_CRYPTO_BN_PRIME

#ifdef HITLS_CRYPTO_CURVE_MONT

int32_t BnMontEnc(BN_BigNum *r, BN_Mont *mont, BN_Optimizer *opt, bool consttime)
{
    int32_t ret;
    GOTO_ERR_IF(MontEncBin(r->data, mont, opt, consttime), ret);
    r->size = BinFixSize(r->data, mont->mSize);
ERR:
    return ret;
}

void BnMontDec(BN_BigNum *r, BN_Mont *mont)
{
    MontDecBin(r->data, mont);
    r->size = BinFixSize(r->data, mont->mSize);
}

int32_t BN_EcPrimeMontSqr(BN_BigNum *r, const BN_BigNum *a, void *data, BN_Optimizer *opt)
{
    int32_t ret;
    BN_Mont *mont = (BN_Mont *)data;
    BN_COPY_BYTES(r->data, mont->mSize, a->data, a->size);
    GOTO_ERR_IF(MontSqrBin(r->data, mont, opt, false), ret);
    r->size = BinFixSize(r->data, mont->mSize);
ERR:
    return ret;
}

int32_t BN_EcPrimeMontMul(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b, void *data, BN_Optimizer *opt)
{
    int32_t ret;
    BN_Mont *mont = (BN_Mont *)data;
    GOTO_ERR_IF(MontMulBin(r->data, a->data, b->data, mont, opt, false), ret);
    r->size = BinFixSize(r->data, mont->mSize);
ERR:
    return ret;
}
#endif /* HITLS_CRYPTO_CURVE_MONT */

#endif /* HITLS_CRYPTO_BN */
