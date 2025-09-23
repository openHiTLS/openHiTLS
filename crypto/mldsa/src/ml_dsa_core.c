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
#ifdef HITLS_CRYPTO_MLDSA
#include "securec.h"
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "crypt_utils.h"
#include "crypt_sha3.h"
#include "crypt_errno.h"
#include "crypt_util_rand.h"
#include "bsl_err_internal.h"
#include "ml_dsa_local.h"
#include "eal_md_local.h"

#define BITS_OF_BYTE 8
#define MLDSA_SET_VECTOR_MEM(ptr, buf) {ptr = buf; buf += MLDSA_N;}

static int32_t HashFuncH(const uint8_t *inPutA, uint32_t lenA, const uint8_t *inPutB, uint32_t lenB,
    uint8_t *out, uint32_t outLen)
{
    uint32_t len = outLen;
    int32_t ret = 0;
    const EAL_MdMethod *hashMethod = EAL_MdFindDefaultMethod(CRYPT_MD_SHAKE256);
    if (hashMethod == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    void *mdCtx = hashMethod->newCtx(NULL, hashMethod->id);
    if (mdCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    GOTO_ERR_IF(hashMethod->init(mdCtx, NULL), ret);
    GOTO_ERR_IF(hashMethod->update(mdCtx, inPutA, lenA), ret);
    if (inPutB != NULL) {
        GOTO_ERR_IF(hashMethod->update(mdCtx, inPutB, lenB), ret);
    }
    GOTO_ERR_IF(hashMethod->final(mdCtx, out, &len), ret);
ERR:
    hashMethod->freeCtx(mdCtx);
    return ret;
}

typedef struct {
    int32_t *bufAddr;
    uint32_t bufSize;
    int32_t *matrix[MLDSA_K_MAX][MLDSA_L_MAX];
    int32_t *s2[MLDSA_K_MAX];
    int32_t *t0[MLDSA_K_MAX];
    int32_t *t1[MLDSA_K_MAX];
    int32_t *s1[MLDSA_L_MAX];
    int32_t *s1Ntt[MLDSA_L_MAX];
} MLDSA_KeyGenMatrixSt;

static void MLDSASetMatrixMem(uint8_t k, uint8_t l, int32_t *matrix[MLDSA_K_MAX][MLDSA_L_MAX], int32_t *buf)
{
    for (uint8_t i = 0; i < k; i++) {
        for (uint8_t j = 0; j < l; j++) {
            matrix[i][j] = buf;
            buf += MLDSA_N;
        }
    }
}

static int32_t MLDSAKeyGenCreateMatrix(uint8_t k, uint8_t l, MLDSA_KeyGenMatrixSt *st)
{
    // Key generation requires 3 two-dimensional arrays of length k and 2 of length l.
    st->bufSize = (k * l + 3 * k + 2 * l) * MLDSA_N * sizeof(int32_t);
    int32_t *buf = BSL_SAL_Malloc(st->bufSize);
    if (buf == NULL) {
        return BSL_MALLOC_FAIL;
    }
    st->bufAddr = buf;  // Used to free memory.
    MLDSASetMatrixMem(k, l, st->matrix, buf);
    buf += k * l * MLDSA_N;
    for (uint8_t i = 0; i < k; i++) {
        MLDSA_SET_VECTOR_MEM(st->t0[i], buf);
        MLDSA_SET_VECTOR_MEM(st->t1[i], buf);
        MLDSA_SET_VECTOR_MEM(st->s2[i], buf);
    }
    for (uint8_t i = 0; i < l; i++) {
        MLDSA_SET_VECTOR_MEM(st->s1[i], buf);
        MLDSA_SET_VECTOR_MEM(st->s1Ntt[i], buf);
    }
    return CRYPT_SUCCESS;
}

typedef struct {
    int32_t *bufAddr;
    uint32_t bufSize;
    int32_t *matrix[MLDSA_K_MAX][MLDSA_L_MAX];
    int32_t *t0[MLDSA_K_MAX];
    int32_t *r0[MLDSA_K_MAX];
    int32_t *s2[MLDSA_K_MAX];
    int32_t *cs2[MLDSA_K_MAX];
    int32_t *ct0[MLDSA_K_MAX];
    int32_t *h[MLDSA_K_MAX];
    int32_t *w[MLDSA_K_MAX];
    int32_t *w1[MLDSA_K_MAX];
    int32_t *s1[MLDSA_L_MAX];
    int32_t *y[MLDSA_L_MAX];
    int32_t *z[MLDSA_L_MAX];
} MLDSA_SignMatrixSt;

static int32_t MLDSASignCreateMatrix(uint8_t k, uint8_t l, MLDSA_SignMatrixSt *st)
{
    // The signature requires 8 two-dimensional arrays of length k and 3 of length l.
    st->bufSize = (k * l + 8 * k + 3 * l) * MLDSA_N * sizeof(int32_t);
    int32_t *buf = BSL_SAL_Malloc(st->bufSize);
    if (buf == NULL) {
        return BSL_MALLOC_FAIL;
    }
    st->bufAddr = buf;  // Used to free memory.
    MLDSASetMatrixMem(k, l, st->matrix, buf);
    buf += k * l * MLDSA_N;
    for (uint8_t i = 0; i < k; i++) {
        MLDSA_SET_VECTOR_MEM(st->r0[i], buf);
        MLDSA_SET_VECTOR_MEM(st->t0[i], buf);
        MLDSA_SET_VECTOR_MEM(st->s2[i], buf);
        MLDSA_SET_VECTOR_MEM(st->cs2[i], buf);
        MLDSA_SET_VECTOR_MEM(st->ct0[i], buf);
        MLDSA_SET_VECTOR_MEM(st->h[i], buf);
        MLDSA_SET_VECTOR_MEM(st->w[i], buf);
        MLDSA_SET_VECTOR_MEM(st->w1[i], buf);
    }
    for (uint8_t i = 0; i < l; i++) {
        MLDSA_SET_VECTOR_MEM(st->s1[i], buf);
        MLDSA_SET_VECTOR_MEM(st->y[i], buf);
        MLDSA_SET_VECTOR_MEM(st->z[i], buf);
    }
    return CRYPT_SUCCESS;
}

typedef struct {
    int32_t *bufAddr;
    uint32_t bufSize;
    int32_t *matrix[MLDSA_K_MAX][MLDSA_L_MAX];
    int32_t *t1[MLDSA_K_MAX];
    int32_t *h[MLDSA_K_MAX];
    int32_t *w[MLDSA_K_MAX];
    int32_t *z[MLDSA_L_MAX];
} MLDSA_VerifyMatrixSt;

static int32_t MLDSAVerifyCreateMatrix(uint8_t k, uint8_t l, MLDSA_VerifyMatrixSt *st)
{
    // Signature verification requires 3 two-dimensional arrays of length k and 1 of length l.
    st->bufSize = (k * l + 3 * k + l) * MLDSA_N * sizeof(int32_t);
    int32_t *buf = BSL_SAL_Malloc(st->bufSize);
    if (buf == NULL) {
        return BSL_MALLOC_FAIL;
    }
    st->bufAddr = buf;  // Used to free memory.
    MLDSASetMatrixMem(k, l, st->matrix, buf);
    buf += k * l * MLDSA_N;

    for (uint8_t i = 0; i < k; i++) {
        MLDSA_SET_VECTOR_MEM(st->t1[i], buf);
        MLDSA_SET_VECTOR_MEM(st->h[i], buf);
        MLDSA_SET_VECTOR_MEM(st->w[i], buf);
    }
    for (uint8_t i = 0; i < l; i++) {
        MLDSA_SET_VECTOR_MEM(st->z[i], buf);
    }
    return CRYPT_SUCCESS;
}

// NIST.FIPS.204 Algorithm 14 CoeffFromThreeBytes(b0, b1, b2)
static int32_t CoeffFromThreeBytes(uint8_t b0, uint8_t b1, uint8_t b2)
{
    uint8_t b = b2;
    if (b > 0x7f) {
        b = b - 0x80;
    }
    // 𝑧 ← 2^16 ⋅ b2′ + 2^8 ⋅ b1 + b0
    return (((int32_t)b << 16) | ((int32_t)b1 << 8)) | b0;
}

// NIST.FIPS.204 Algorithm 30 RejNTTPoly(ρ)
static int32_t RejNTTPoly(int32_t a[MLDSA_N], uint8_t seed[MLDSA_SEED_EXTEND_BYTES_LEN])
{
    int32_t ret;
    unsigned int buflen = CRYPT_SHAKE128_BLOCKSIZE;
    uint8_t buf[CRYPT_SHAKE128_BLOCKSIZE];

    const EAL_MdMethod *hashMethod = EAL_MdFindDefaultMethod(CRYPT_MD_SHAKE128);
    if (hashMethod == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    void *mdCtx = hashMethod->newCtx(NULL, hashMethod->id);
    if (mdCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    GOTO_ERR_IF(hashMethod->init(mdCtx, NULL), ret);
    GOTO_ERR_IF(hashMethod->update(mdCtx, seed, MLDSA_SEED_EXTEND_BYTES_LEN), ret);
    GOTO_ERR_IF(hashMethod->squeeze(mdCtx, buf, buflen), ret);
    uint32_t j = 0;
    for (uint32_t i = 0; i < MLDSA_N;) {
        a[i] = CoeffFromThreeBytes(buf[j], buf[j + 1], buf[j + 2]); // Data from 3 uint8_t to int32_t.
        j += 3;
        if (a[i] < MLDSA_Q) {  // a[i] is less than MLDSA_Q is an invalid value.
            i++;
        }
        if (j >= CRYPT_SHAKE128_BLOCKSIZE) {
            GOTO_ERR_IF(hashMethod->squeeze(mdCtx, buf, buflen), ret);
            j = 0;
        }
    }
ERR:
    hashMethod->freeCtx(mdCtx);
    return ret;
}

// NIST.FIPS.204 Algorithm 32 ExpandA(ρ)
static int32_t ExpandA(const CRYPT_ML_DSA_Ctx *ctx, const uint8_t *pubSeed, int32_t *matrix[MLDSA_K_MAX][MLDSA_L_MAX])
{
    uint8_t k = ctx->info->k;
    uint8_t l = ctx->info->l;
    uint8_t seed[MLDSA_SEED_EXTEND_BYTES_LEN];
    (void)memcpy_s(seed, sizeof(seed), pubSeed, MLDSA_PUBLIC_SEED_LEN);
    for (uint8_t i = 0; i < k; i++) {
        for (uint8_t j = 0; j < l; j++) {
            seed[MLDSA_PUBLIC_SEED_LEN] = j;
            seed[MLDSA_PUBLIC_SEED_LEN + 1] = i;
            int32_t ret = RejNTTPoly(matrix[i][j], seed);
            RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);
        }
    }
    return CRYPT_SUCCESS;
}

// NIST.FIPS.204 Algorithm 31 RejBoundedPoly(ρ)
static int32_t RejBoundedPoly(const CRYPT_ML_DSA_Ctx *ctx, int32_t *a, uint8_t *s)
{
    uint8_t buf[CRYPT_SHAKE256_BLOCKSIZE];
    uint32_t bufLen = CRYPT_SHAKE256_BLOCKSIZE;
    int32_t ret = CRYPT_SUCCESS;
    const EAL_MdMethod *hashMethod = EAL_MdFindDefaultMethod(CRYPT_MD_SHAKE256);
    if (hashMethod == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    void *mdCtx = hashMethod->newCtx(NULL, hashMethod->id);
    if (mdCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    GOTO_ERR_IF(hashMethod->init(mdCtx, NULL), ret);
    GOTO_ERR_IF(hashMethod->update(mdCtx, s, MLDSA_PRIVATE_SEED_LEN + 2), ret);  // k and l used 2 bytes.
    GOTO_ERR_IF(hashMethod->squeeze(mdCtx, buf, bufLen), ret);
    for (uint32_t i = 0, j = 0; i < MLDSA_N; j++) {
        if (j == CRYPT_SHAKE256_BLOCKSIZE) {
            GOTO_ERR_IF(hashMethod->squeeze(mdCtx, buf, CRYPT_SHAKE256_BLOCKSIZE), ret);
            j = 0;
        }
        int32_t z0 = (int32_t)(buf[j] & 0x0F);
        int32_t z1 = (int32_t)(buf[j] >> 4u);
        // Algorithm 15 CoeffFromHalfByte(b)
        // if 𝜂 = 2 and b < 15 then return 2 − (b mod 5)
        if (ctx->info->eta == 2) {
            if (z0 < 0x0F) {
                // This is Barrett Modular Multiplication, 205 == 2^10 / 5
                z0 = z0 - ((205 * z0) >> 10) * 5;  // 2 − (b mod 5)
                a[i] = 2 - z0;
                i++;
            }
            if (z1 < 0x0F && i < MLDSA_N) {
                // Barrett Modular Multiplication, 205 == 2^10 / 5
                z1 = z1 - ((205 * z1) >> 10) * 5;
                a[i] = 2 - z1;  // 2 − (b mod 5)
                i++;
            }
        } else {
            if (z0 < 9) { // if 𝜂 = 4 and b < 9 then a[i] = 4 − b
                a[i] = 4 - z0;
                i++;
            }
            if (z1 < 9 && i < MLDSA_N) { // if 𝜂 = 4 and b < 9 then a[i + 1] = 4 − b
                a[i] = 4 - z1;
                i++;
            }
        }
    }
ERR:
    hashMethod->freeCtx(mdCtx);
    return ret;
}

// Algorithm 33 ExpandS(ρ)
static int32_t ExpandS(const CRYPT_ML_DSA_Ctx *ctx, const uint8_t *prvSeed,
    int32_t *s1[MLDSA_L_MAX], int32_t *s2[MLDSA_K_MAX])
{
    int32_t ret;
    uint8_t k = ctx->info->k;
    uint8_t l = ctx->info->l;
    uint8_t seed[MLDSA_PRIVATE_SEED_LEN + 2]; // 2 bytes are reserved.
    (void)memcpy_s(seed, sizeof(seed), prvSeed, MLDSA_PRIVATE_SEED_LEN);
    seed[MLDSA_PRIVATE_SEED_LEN + 1] = 0;
    for (uint8_t i = 0; i < l; i++) {
        seed[MLDSA_PRIVATE_SEED_LEN] = i;
        ret = RejBoundedPoly(ctx, s1[i], seed);
        RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);
    }
    for (uint8_t i = 0; i < k; i++) {
        seed[MLDSA_PRIVATE_SEED_LEN] = l + i;
        ret = RejBoundedPoly(ctx, s2[i], seed);
        RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);
    }
    return CRYPT_SUCCESS;
}

static void ComputesNTT(const CRYPT_ML_DSA_Ctx *ctx, int32_t *s[MLDSA_L_MAX], int32_t *sOut[MLDSA_L_MAX])
{
    for (uint8_t i = 0; i < ctx->info->l; i++) {
        (void)memcpy_s(sOut[i], sizeof(int32_t) * MLDSA_N, s[i], sizeof(int32_t) * MLDSA_N);
        MLDSA_ComputesNTT(sOut[i]);
    }
    return;
}

static void VectorsMul(int32_t *t, int32_t *matrix, int32_t *s)
{
    for (uint32_t i = 0; i < MLDSA_N; i++) {
        t[i] = MLDSA_MontgomeryReduce((int64_t)matrix[i] * s[i]);
    }
}

static void MatrixMul(const CRYPT_ML_DSA_Ctx *ctx, int32_t *t, int32_t *matrix[MLDSA_L_MAX], int32_t *s[MLDSA_L_MAX])
{
    int32_t tmp[MLDSA_N] = { 0 };
    VectorsMul(t, matrix[0], s[0]);
    for (uint32_t i = 1; i < ctx->info->l; i++) {
        VectorsMul(tmp, matrix[i], s[i]);
        for (uint32_t j = 0; j < MLDSA_N; j++) {
            t[j] = t[j] + tmp[j];
        }
    }
    for (uint32_t j = 0; j < MLDSA_N; j++) {
        MLDSA_MOD_Q(t[j]);
    }
}

static void ComputesT(const CRYPT_ML_DSA_Ctx *ctx, int32_t *t[MLDSA_K_MAX], int32_t *matrix[MLDSA_K_MAX][MLDSA_L_MAX],
    int32_t *s1[MLDSA_L_MAX], int32_t *s2[MLDSA_K_MAX])
{
    for (uint8_t i = 0; i < ctx->info->k; i++) {
        MatrixMul(ctx, t[i], matrix[i], s1);
        MLDSA_ComputesINVNTT(t[i]);
        for (int32_t j = 0; j < MLDSA_N; j++) {
            t[i][j] = t[i][j] + s2[i][j];
            t[i][j] = t[i][j] < 0 ? (t[i][j] + MLDSA_Q) : t[i][j];
        }
    }
}

static void ComputesPower2Round(const CRYPT_ML_DSA_Ctx *ctx, int32_t *t0[MLDSA_K_MAX], int32_t *t1[MLDSA_K_MAX])
{
    for (uint32_t i = 0; i < ctx->info->k; i++) {
        for (int32_t j = 0; j < MLDSA_N; j++) {
            int32_t t = (t1[i][j] + (1 << (MLDSA_D - 1)) - 1) >> MLDSA_D;
            t0[i][j] = t1[i][j] - (t << MLDSA_D);
            t1[i][j] = t;
        }
    }
}

// The following encoding function encodes MLDSA_N int32_t data into the uint8_t array.
static void ByteEncode(uint8_t *buf, uint32_t *t, uint32_t bits)
{
    if (bits == 10u) {
        for (uint32_t i = 0; i < MLDSA_N / 4; i++) {
            buf[5 * i + 0] = (uint8_t)(t[4 * i + 0] >> 0);
            buf[5 * i + 1u] = (uint8_t)((t[4 * i + 0] >> 8u) | (t[4 * i + 1u] << 2u));
            buf[5 * i + 2u] = (uint8_t)((t[4 * i + 1u] >> 6u) | (t[4 * i + 2u] << 4u));
            buf[5 * i + 3u] = (uint8_t)((t[4 * i + 2u] >> 4u) | (t[4 * i + 3u] << 6u));
            buf[5 * i + 4u] = (uint8_t)(t[4 * i + 3u] >> 2u);
        }
    } else if (bits == 6u) {
        for (uint32_t i = 0; i < MLDSA_N / 4; i++) {
            buf[3 * i + 0] = (uint8_t)(t[4 * i] | (t[4 * i + 1] << 6u));
            buf[3 * i + 1u] = (uint8_t)(t[4 * i + 1u] >> 2 | (t[4 * i + 2u] << 4u));
            buf[3 * i + 2u] = (uint8_t)(t[4 * i + 2u] >> 4 | (t[4 * i + 3u] << 2u));
        }
    } else if (bits == 4u) {
        for (uint32_t i = 0; i < MLDSA_N / 2; i++) {
            buf[i] = (uint8_t)(t[2 * i] | (t[2 * i + 1] << 4u));
        }
    }
}

static void ByteDecode(uint8_t *buf, uint32_t *t, uint32_t bits)
{
    if (bits == 10u) {
        for (uint32_t i = 0; i < MLDSA_N / 4; i++) {
            t[4 * i + 0] = (buf[5 * i + 0] | ((uint32_t)buf[5 * i + 1] << 8)) & 0x03ff;
            t[4 * i + 1u] = ((buf[5 * i + 1u] >> 2u) | ((uint32_t)buf[5 * i + 2u] << 6u)) & 0x03ff;
            t[4 * i + 2u] = ((buf[5 * i + 2u] >> 4u) | ((uint32_t)buf[5 * i + 3u] << 4u)) & 0x03ff;
            t[4 * i + 3u] = ((buf[5 * i + 3u] >> 6u) | ((uint32_t)buf[5 * i + 4u] << 2u)) & 0x03ff;
        }
    }
}

static void BitPack(uint8_t *buf, uint32_t w[MLDSA_N], uint32_t bits, uint32_t b)
{
    uint32_t t[8] = {0};
    uint32_t i;
    uint32_t n;
    if (bits == 3u) {
        for (i = 0; i < MLDSA_N / 8; i++) {
            for (uint32_t j = 0; j < 8; j++) {
                t[j] = b - (uint32_t)w[i * 8 + j];
            }
            n = bits * i;
            buf[n + 0] = (uint8_t)((t[0]) | (t[1] << 3u) | (t[2] << 6u));
            buf[n + 1u] = (uint8_t)((t[2] >> 2u) | (t[3] << 1u) | (t[4] << 4u) | (t[5] << 7u));
            buf[n + 2u] = (uint8_t)((t[5] >> 1u) | (t[6] << 2u) | (t[7] << 5u));
        }
    } else if (bits == 4u) {
        for (i = 0; i < MLDSA_N / 2; i++) {
            t[0] = (int32_t)b - w[i * 2];
            t[1] = (int32_t)b - w[i * 2 + 1];
            buf[i] = (uint8_t)(t[0] | (t[1] << 4u));
        }
    } else if (bits == MLDSA_D) {
        for (i = 0; i < MLDSA_N / 8; i++) {
            for (uint32_t j = 0; j < 8; j++) {
                t[j] = b - w[i * 8 + j];
            }
            n = bits * i;
            buf[n + 0] = (uint8_t)t[0];
            buf[n + 1] = (uint8_t)(t[0] >> 8u);
            buf[n + 1] |= (uint8_t)(t[1] << 5u);
            buf[n + 2] = (uint8_t)(t[1] >> 3u);
            buf[n + 3] = (uint8_t)(t[1] >> 11u);
            buf[n + 3] |= (uint8_t)(t[2] << 2u);
            buf[n + 4] = (uint8_t)(t[2] >> 6u);
            buf[n + 4] |= (uint8_t)(t[3] << 7u);
            buf[n + 5] = (uint8_t)(t[3] >> 1u);
            buf[n + 6] = (uint8_t)(t[3] >> 9u);
            buf[n + 6] |= (uint8_t)(t[4] << 4u);
            buf[n + 7] = (uint8_t)(t[4] >> 4u);
            buf[n + 8] = (uint8_t)(t[4] >> 12u);
            buf[n + 8] |= (uint8_t)(t[5] << 1u);
            buf[n + 9] = (uint8_t)(t[5] >> 7u);
            buf[n + 9] |= (uint8_t)(t[6] << 6u);
            buf[n + 10] = (uint8_t)(t[6] >> 2u);
            buf[n + 11] = (uint8_t)(t[6] >> 10u);
            buf[n + 11] |= (uint8_t)(t[7] << 3u);
            buf[n + 12] = (uint8_t)(t[7] >> 5u);
        }
    }
    // bits has only this three values.
    return;
}

static void BitUnPake(const uint8_t *v, uint32_t w[MLDSA_N], uint32_t bits, uint32_t b)
{
    uint32_t t[8] = {0};
    uint32_t i;
    uint32_t n;
    if (bits == 3u) {
        for (i = 0; i < MLDSA_N / 8; i++) {
            n = bits * i;
            t[0] = (v[n + 0]) & 0x07;
            t[1] = (v[n + 0] >> 3u) & 0x07;
            t[2] = ((v[n + 0] >> 6u) | (v[n + 1] << 2u)) & 0x07;
            t[3] = (v[n + 1u] >> 1u) & 0x07;
            t[4] = (v[n + 1u] >> 4u) & 0x07;
            t[5] = ((v[n + 1u] >> 7u) | (v[n + 2] << 1u)) & 0x07;
            t[6] = (v[n + 2u] >> 2u) & 0x07;
            t[7] = (v[n + 2u] >> 5u) & 0x07;

            for (uint32_t j = 0; j < 8; j++) {
                w[i * 8 + j] = b - t[j];
            }
        }
    } else if (bits == 4u) {
        for (i = 0; i < MLDSA_N / 2; i++) {
            t[0] = v[i] & 0x0f;
            t[1] = (v[i] >> 4u) & 0x0f;
            w[i * 2] = b - t[0];
            w[i * 2 + 1] = b - t[1];
        }
    } else if (bits == MLDSA_D) {
        for (i = 0; i < MLDSA_N / 8; i++) {
            n = bits * i;
            t[0] = (v[n + 0] | ((uint32_t)v[n + 1] << 8u)) & 0x1fff;
            t[1] = (v[n + 1] >> 5u | ((uint32_t)v[n + 2u] << 3u) |
                ((uint32_t)v[n + 3u] << 11u)) & 0x1fff;
            t[2] = (v[n + 3u] >> 2u | ((uint32_t)v[n + 4u] << 6u)) & 0x1fff;
            t[3] = (v[n + 4u] >> 7u | ((uint32_t)v[n + 5u] << 1u) |
                ((uint32_t)v[n + 6u] << 9u)) & 0x1fff;

            t[4] = (v[n + 6u] >> 4u | ((uint32_t)v[n + 7u] << 4u) |
                ((uint32_t)v[n + 8u] << 12u)) & 0x1fff;
            t[5] = (v[n + 8u] >> 1u | ((uint32_t)v[n + 9u] << 7u)) & 0x1fff;
            t[6] = (v[n + 9u] >> 6u | ((uint32_t)v[n + 10u] << 2u) |
                ((uint32_t)v[n + 11u] << 10u)) & 0x1fff;
            t[7] = (v[n + 11u] >> 3u | ((uint32_t)v[n + 12u] << 5u)) & 0x1fff;

            for (uint32_t j = 0; j < 8; j++) {
                w[i * 8 + j] = b - t[j];
            }
        }
    }
    // bits has only this three values.
    return;
}

static void SignBitPack(uint8_t *buf, uint32_t w[MLDSA_N], uint32_t bits, uint32_t b)
{
    uint32_t t[4] = {0};
    uint32_t i;
    uint32_t n;
    if (bits == GAMMA_BITS_OF_MLDSA_44) {
        for (i = 0; i < MLDSA_N / 4; i++) {
            for (uint32_t j = 0; j < 4; j++) {
                t[j] = b - w[i * 4 + j];
            }
            n = 9 * i;
            buf[n + 0] = (uint8_t)t[0];
            buf[n + 1u] = (uint8_t)(t[0] >> 8u);
            buf[n + 2u] = (uint8_t)(t[0] >> 16u | t[1] << 2u);
            buf[n + 3u] = (uint8_t)(t[1] >> 6u);
            buf[n + 4u] = (uint8_t)(t[1] >> 14u | t[2] << 4u);
            buf[n + 5u] = (uint8_t)(t[2] >> 4u);
            buf[n + 6u] = (uint8_t)(t[2] >> 12u | t[3] << 6u);
            buf[n + 7u] = (uint8_t)(t[3] >> 2u);
            buf[n + 8u] = (uint8_t)(t[3] >> 10u);
        }
    } else if (bits == GAMMA_BITS_OF_MLDSA_65_87) {
        for (i = 0; i < MLDSA_N / 2; i++) {
            t[0] = b - w[i * 2];
            t[1] = b - w[i * 2 + 1u];
            n = 5 * i;
            buf[n + 0] = (uint8_t)t[0];
            buf[n + 1u] = (uint8_t)(t[0] >> 8u);
            buf[n + 2u] = (uint8_t)(t[0] >> 16u | t[1] << 4u);
            buf[n + 3u] = (uint8_t)(t[1] >> 4u);
            buf[n + 4u] = (uint8_t)(t[1] >> 12u);
        }
    }
    // bits has only this two values.
    return;
}

static void SignBitUnPake(const uint8_t *v, uint32_t w[MLDSA_N], uint32_t bits, uint32_t b)
{
    uint32_t t[4] = {0};
    uint32_t i;
    uint32_t n;
    if (bits == GAMMA_BITS_OF_MLDSA_44) {
        for (i = 0; i < MLDSA_N / 4; i++) {
            n = 9 * i;
            t[0] = (v[n + 0] | ((uint32_t)v[n + 1] << 8) | ((uint32_t)v[n + 2] << 16)) & 0x3ffff;
            t[1] = (v[n + 2u] >> 2u | ((uint32_t)v[n + 3u] << 6u) | ((uint32_t)v[n + 4u] << 14u)) & 0x3ffff;
            t[2] = (v[n + 4u] >> 4u | ((uint32_t)v[n + 5u] << 4u) | ((uint32_t)v[n + 6u] << 12u)) & 0x3ffff;
            t[3] = (v[n + 6u] >> 6u | ((uint32_t)v[n + 7u] << 2u) | ((uint32_t)v[n + 8u] << 10u)) & 0x3ffff;

            n = 4 * i;
            w[n] = b - t[0];
            w[n + 1u] = b - t[1];
            w[n + 2u] = b - t[2];
            w[n + 3u] = b - t[3];
        }
    } else if (bits == GAMMA_BITS_OF_MLDSA_65_87) {
        for (i = 0; i < MLDSA_N / 2; i++) {
            n = 5 * i;
            t[0] = (v[n + 0] | ((uint32_t)v[n + 1] << 8u) | ((uint32_t)v[n + 2u] << 16u)) & 0xfffff;
            t[1] = (v[n + 2u] >> 4u | ((uint32_t)v[n + 3u] << 4u) | ((uint32_t)v[n + 4u] << 12u)) & 0xfffff;

            w[i * 2] = b - t[0];
            w[i * 2 + 1u] = b - t[1];
        }
    }
    // bits has only this two values.
    return;
}

// Algorithm 22 pkEncode(ρ, t1)
static void PkEncode(const CRYPT_ML_DSA_Ctx *ctx, uint8_t *seed, int32_t *t[MLDSA_K_MAX])
{
    (void)memcpy_s(ctx->pubKey, ctx->pubLen, seed, MLDSA_PUBLIC_SEED_LEN);
    for (int32_t i = 0; i < ctx->info->k; i++) {
        // 10 is bitlen(𝑞−1) − d
        ByteEncode(ctx->pubKey + MLDSA_PUBLIC_SEED_LEN + i * MLDSA_PUBKEY_POLYT_PACKEDBYTES, (uint32_t *)t[i], 10);
    }
}

// Algorithm 23 pkDecode(pk)
static void PkDecode(const CRYPT_ML_DSA_Ctx *ctx, uint8_t *seed, int32_t *t[MLDSA_K_MAX])
{
    (void)memcpy_s(seed, MLDSA_PUBLIC_SEED_LEN, ctx->pubKey, MLDSA_PUBLIC_SEED_LEN);
    for (int32_t i = 0; i < ctx->info->k; i++) {
        // 10 is bitlen(𝑞−1) − d
        ByteDecode(ctx->pubKey + MLDSA_PUBLIC_SEED_LEN + i * MLDSA_PUBKEY_POLYT_PACKEDBYTES, (uint32_t *)t[i], 10);
    }
}

// Algorithm 24 skEncode(ρ, K,tr, 𝐬1, 𝐬2, t0)
static void SkEncode(const CRYPT_ML_DSA_Ctx *ctx, uint8_t *pubSeed, uint8_t *signSeed, uint8_t *tr,
    MLDSA_KeyGenMatrixSt *st)
{
    uint32_t i;
    uint32_t bitLen = ctx->info->eta == 2 ? 3 : 4;  // 3 and 4 is bitlen(2𝜂)
    uint32_t index = MLDSA_PUBLIC_SEED_LEN;
    (void)memcpy_s(ctx->prvKey, ctx->prvLen, pubSeed, MLDSA_PUBLIC_SEED_LEN);
    (void)memcpy_s(ctx->prvKey + index, ctx->prvLen - index, signSeed, MLDSA_SIGNING_SEED_LEN);
    index += MLDSA_SIGNING_SEED_LEN;
    (void)memcpy_s(ctx->prvKey + index, ctx->prvLen - index, tr, MLDSA_PRIVATE_SEED_LEN);
    index += MLDSA_PRIVATE_SEED_LEN;
    for (i = 0; i < ctx->info->l; i++) {
        BitPack(ctx->prvKey + index, (uint32_t *)st->s1[i], bitLen, ctx->info->eta);
        index += MLDSA_N_BYTE * bitLen;
    }
    for (i = 0; i < ctx->info->k; i++) {
        BitPack(ctx->prvKey + index, (uint32_t *)st->s2[i], bitLen, ctx->info->eta);
        index += MLDSA_N_BYTE * bitLen;
    }
    for (i = 0; i < ctx->info->k; i++) {
        BitPack(ctx->prvKey + index, (uint32_t *)st->t0[i], MLDSA_D, 4096);  // 2^(𝑑−1) == 4096
        index += MLDSA_N_BYTE * MLDSA_D;
    }
}

// Algorithm 25 skDecode(sk)
static void SkDecode(const CRYPT_ML_DSA_Ctx *ctx, uint8_t *pubSeed, uint8_t *signSeed, uint8_t *tr,
    MLDSA_SignMatrixSt *st)
{
    uint32_t i;
    uint32_t bitLen = ctx->info->eta == 2 ? 3 : 4;  // 3 and 4 is bitlen(2𝜂)
    uint32_t index = MLDSA_PUBLIC_SEED_LEN;
    (void)memcpy_s(pubSeed, MLDSA_PUBLIC_SEED_LEN, ctx->prvKey, MLDSA_PUBLIC_SEED_LEN);
    (void)memcpy_s(signSeed, MLDSA_SIGNING_SEED_LEN, ctx->prvKey + index, MLDSA_SIGNING_SEED_LEN);

    index += MLDSA_SIGNING_SEED_LEN;
    (void)memcpy_s(tr, MLDSA_PRIVATE_SEED_LEN, ctx->prvKey + index, MLDSA_PRIVATE_SEED_LEN);
    index += MLDSA_PRIVATE_SEED_LEN;

    for (i = 0; i < ctx->info->l; i++) {
        BitUnPake(ctx->prvKey + index, (uint32_t *)st->s1[i], bitLen, ctx->info->eta);
        index += MLDSA_N_BYTE * bitLen;
    }
    for (i = 0; i < ctx->info->k; i++) {
        BitUnPake(ctx->prvKey + index, (uint32_t *)st->s2[i], bitLen, ctx->info->eta);
        index += MLDSA_N_BYTE * bitLen;
    }
    for (i = 0; i < ctx->info->k; i++) {
        BitUnPake(ctx->prvKey + index, (uint32_t *)st->t0[i], MLDSA_D, 4096);  // 2^(𝑑−1) == 4096
        index += MLDSA_N_BYTE * MLDSA_D;
    }
}

static void SignCalNtt(const CRYPT_ML_DSA_Ctx *ctx, MLDSA_SignMatrixSt *st)
{
    uint32_t i;
    for (i = 0; i < ctx->info->l; i++) {
        MLDSA_ComputesNTT(st->s1[i]);
    }
    for (i = 0; i < ctx->info->k; i++) {
        MLDSA_ComputesNTT(st->s2[i]);
    }
    for (i = 0; i < ctx->info->k; i++) {
        MLDSA_ComputesNTT(st->t0[i]);
    }
}

// Algorithm 34 ExpandMask(ρ, μ)
static int32_t ExpandMask(const CRYPT_ML_DSA_Ctx *ctx, int32_t *y[MLDSA_L_MAX], uint8_t *p, uint16_t u)
{
    uint16_t n = 0;
    uint8_t v[640];  // The maximum length is 20 * 32 == 640 byte.
    uint32_t bits = (ctx->info->k == K_VALUE_OF_MLDSA_44) ? GAMMA_BITS_OF_MLDSA_44 : GAMMA_BITS_OF_MLDSA_65_87;
    for (uint16_t i = 0; i < ctx->info->l; i++) {
        n = u + i;
        p[MLDSA_PRIVATE_SEED_LEN] = (uint8_t)n;
        p[MLDSA_PRIVATE_SEED_LEN + 1] = (uint8_t)(n >> BITS_OF_BYTE);
        // 𝑣 ← H(ρ′, 32𝑐)
        int32_t ret = HashFuncH(p, MLDSA_PRIVATE_SEED_LEN + 2, NULL, 0, v, 32 * bits);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        SignBitUnPake(v, (uint32_t *)y[i], bits, ctx->info->gamma1);
    }
    return CRYPT_SUCCESS;
}

// Algorithm 36 Decompose(r)
static void Decompose(const CRYPT_ML_DSA_Ctx *ctx, int32_t r, int32_t *r1, int32_t *r0)
{
    int32_t t = (int32_t)(((uint32_t)r + 0x7f) >> 7u);
    if (ctx->info->k == K_VALUE_OF_MLDSA_44) {  // If is MLDSA44
        // This is Barrett Modular Multiplication, mod is 2𝛾2.
        t = (t * 11275u + (1 << 23u)) >> 24u;
        t ^= ((43 - t) >> 31u) & t;
    } else {
        t = (t * 1025u + (1 << 21u)) >> 22u;
        t &= 0x0f;
    }

    *r0 = r - t * 2 * ctx->info->gamma2;  // r1 ← (r+ − r0)/(2𝛾2)
    *r0 -= (((MLDSA_Q - 1) / 2 - *r0) >> 31u) & MLDSA_Q;
    *r1 = t;  // high bits.
    return;
}

static void ComputesW(const CRYPT_ML_DSA_Ctx *ctx, int32_t *w[MLDSA_L_MAX], int32_t *w1[MLDSA_L_MAX],
    int32_t *matrix[MLDSA_K_MAX][MLDSA_L_MAX], int32_t *y[MLDSA_L_MAX])
{
    for (uint8_t i = 0; i < ctx->info->k; i++) {
        MatrixMul(ctx, w[i], matrix[i], y);
        MLDSA_ComputesINVNTT(w[i]);
        for (int32_t j = 0; j < MLDSA_N; j++) {
            w[i][j] = w[i][j] < 0 ? (w[i][j] + MLDSA_Q) : w[i][j];
            Decompose(ctx, w[i][j], &w1[i][j], &w[i][j]);
        }
    }
}

// Algorithm 28 w1Encode(w1)
static void W1Encode(const CRYPT_ML_DSA_Ctx *ctx, uint8_t *buf, int32_t *w[MLDSA_K_MAX])
{
    uint32_t bitLen = ctx->info->k == K_VALUE_OF_MLDSA_44 ? 6 : 4;  // Only the bitLen value of MLDSA44 is 6.
    uint32_t blockSize = ctx->info->k == K_VALUE_OF_MLDSA_44 ? 192 : 128;  // MLDSA44 blockSize is 192, other is 128.
    for (uint32_t i = 0; i < ctx->info->k; i++) {
        ByteEncode(buf + i * blockSize, (uint32_t *)w[i], bitLen);
    }
}

// Algorithm 29 SampleInBall(ρ)
static int32_t SampleInBall(const CRYPT_ML_DSA_Ctx *ctx, const uint8_t *p, uint32_t pLen, int32_t c[MLDSA_N])
{
    uint8_t s[CRYPT_SHAKE256_BLOCKSIZE] = {0};
    uint32_t sLen = CRYPT_SHAKE256_BLOCKSIZE;
    uint64_t h = 0;
    uint32_t index = 0;
    uint8_t j = 0;
    int32_t ret;
    const EAL_MdMethod *hashMethod = EAL_MdFindDefaultMethod(CRYPT_MD_SHAKE256);
    if (hashMethod == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    void *mdCtx = hashMethod->newCtx(NULL, hashMethod->id);
    if (mdCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    GOTO_ERR_IF(hashMethod->init(mdCtx, NULL), ret);
    GOTO_ERR_IF(hashMethod->update(mdCtx, p, pLen), ret);
    GOTO_ERR_IF(hashMethod->squeeze(mdCtx, s, sLen), ret);
    for (index = 0; index < 8; index++) {    //  𝑠 ← H.Squeeze(ctx, 8)
        h = h | ((uint64_t)s[index] << (8 * index));
    }
    for (uint32_t i = MLDSA_N - ctx->info->tau; i < MLDSA_N; i++) {
        do {
            if (index == CRYPT_SHAKE256_BLOCKSIZE) {
                GOTO_ERR_IF(hashMethod->squeeze(mdCtx, s, sLen), ret);
                index = 0;
            }
            j = s[index];
            index++;
        } while (j > i);

        c[i] = c[j];
        c[j] = 1 - ((h & 1) << 1);
        h >>= 1;
    }
ERR:
    hashMethod->freeCtx(mdCtx);
    return ret;
}

static void MLDSA_VectorsAdd(int32_t *t, int32_t *a, int32_t *b)
{
    for (uint32_t i = 0; i < MLDSA_N; i++) {
        t[i] = a[i] + b[i];
        MLDSA_MOD_Q(t[i]);
    }
}

static void MLDSA_VectorsSub(int32_t *t, int32_t *a, int32_t *b)
{
    for (uint32_t i = 0; i < MLDSA_N; i++) {
        t[i] = a[i] - b[i];
        MLDSA_MOD_Q(t[i]);
    }
}

static void ComputesZ(const CRYPT_ML_DSA_Ctx *ctx, int32_t *y[MLDSA_L_MAX], int32_t *c, int32_t *s[MLDSA_L_MAX],
    int32_t *z[MLDSA_L_MAX])
{
    for (uint8_t i = 0; i < ctx->info->l; i++) {
        VectorsMul(z[i], c, s[i]);
        MLDSA_ComputesINVNTT(z[i]);
        MLDSA_VectorsAdd(z[i], y[i], z[i]);
    }
}

static bool ValidityChecks(int32_t *z, uint32_t t)
{
    uint32_t n;
    for (uint32_t j = 0; j < MLDSA_N; j++) {
        n = z[j] >> 31;    // Shift rightwards by 31 bits.
        n = z[j] - (n & ((uint32_t)z[j] << 1));
        if (n >= t) {
            return false;
        }
    }
    return true;
}

static bool ValidityChecksL(const CRYPT_ML_DSA_Ctx *ctx, int32_t *z[MLDSA_L_MAX], uint32_t t)
{
    for (uint8_t i = 0; i < ctx->info->l; i++) {
        if (ValidityChecks(z[i], t) == false) {
            return false;
        }
    }
    return true;
}

static bool ValidityChecksK(const CRYPT_ML_DSA_Ctx *ctx, int32_t *z[MLDSA_K_MAX], uint32_t t)
{
    for (uint8_t i = 0; i < ctx->info->k; i++) {
        if (ValidityChecks(z[i], t) == false) {
            return false;
        }
    }
    return true;
}

static void ComputesR(const CRYPT_ML_DSA_Ctx *ctx, int32_t *c, MLDSA_SignMatrixSt *st)
{
    for (uint8_t i = 0; i < ctx->info->k; i++) {
        VectorsMul(st->cs2[i], c, st->s2[i]);
        MLDSA_ComputesINVNTT(st->cs2[i]);
        MLDSA_VectorsSub(st->r0[i], st->w[i], st->cs2[i]);
    }
}

static void ComputesCT(const CRYPT_ML_DSA_Ctx *ctx, int32_t *c, int32_t *t[MLDSA_K_MAX], int32_t *ct[MLDSA_K_MAX])
{
    for (uint8_t i = 0; i < ctx->info->k; i++) {
        VectorsMul(ct[i], c, t[i]);
        MLDSA_ComputesINVNTT(ct[i]);
        for (uint32_t j = 0; j < MLDSA_N; j++) {
            int32_t m = (int32_t)(((uint32_t)ct[i][j] + (1 << 22)) >> 23);  // m = (ct + 2^22) / 2^23
            ct[i][j] = ct[i][j] - m * MLDSA_Q;
        }
    }
}

static uint32_t MakeHint(const CRYPT_ML_DSA_Ctx *ctx, MLDSA_SignMatrixSt *st)
{
    uint32_t num = 0;
    for (uint32_t i = 0; i < ctx->info->k; i++) {
        MLDSA_VectorsAdd(st->w[i], st->w[i], st->ct0[i]);
        MLDSA_VectorsSub(st->w[i], st->w[i], st->cs2[i]);
        for (uint32_t j = 0; j < MLDSA_N; j++) {
            if (st->w[i][j] > (int32_t)ctx->info->gamma2 || st->w[i][j] < (0 - (int32_t)ctx->info->gamma2) ||
                (st->w[i][j] == (0 - (int32_t)ctx->info->gamma2) && st->w1[i][j] != 0)) {
                st->h[i][j] = 1;
                num++;
            } else {
                st->h[i][j] = 0;
            }
        }
    }
    return num;
}

static void SigEncode(const CRYPT_ML_DSA_Ctx *ctx, uint8_t *out, uint32_t outLen, int32_t *z[MLDSA_L_MAX],
    int32_t *h[MLDSA_K_MAX])
{
    // // 𝛾1 bits of MLDSA44 is 18，𝛾1 bits of MLDSA65 and MLDSA87 is 20.
    uint32_t bits = (ctx->info->k == K_VALUE_OF_MLDSA_44) ? GAMMA_BITS_OF_MLDSA_44 : GAMMA_BITS_OF_MLDSA_65_87;
    uint32_t blockSize = MLDSA_N / BITS_OF_BYTE * bits;
    uint8_t *ptr = out;
    uint32_t index = 0;
    for (uint32_t i = 0; i < ctx->info->l; i++) {
        SignBitPack(ptr, (uint32_t *)z[i], bits, ctx->info->gamma1);
        ptr += blockSize;
    }

    (void)memset_s(ptr, outLen - blockSize * ctx->info->l, 0, outLen - blockSize * ctx->info->l);
    for (uint32_t i = 0; i < ctx->info->k; i++) {
        for (uint32_t j = 0; j < MLDSA_N; j++) {
            if (h[i][j] != 0) {
                ptr[index] = j;
                index++;
            }
        }
        ptr[ctx->info->omega + i] = index;
    }
}

static int32_t SigDecode(const CRYPT_ML_DSA_Ctx *ctx, const uint8_t *in, int32_t *z[MLDSA_L_MAX],
    int32_t *h[MLDSA_K_MAX])
{
    uint32_t bits = (ctx->info->k == K_VALUE_OF_MLDSA_44) ? GAMMA_BITS_OF_MLDSA_44 : GAMMA_BITS_OF_MLDSA_65_87;
    uint32_t blockSize = MLDSA_N / BITS_OF_BYTE * bits;
    const uint8_t *ptr = in;
    uint32_t index = 0;

    for (int32_t i = 0; i < ctx->info->l; i++) {
        SignBitUnPake(ptr, (uint32_t *)z[i], bits, ctx->info->gamma1);
        ptr += blockSize;
    }

    for (int32_t i = 0; i < ctx->info->k; i++) {
        if (ptr[ctx->info->omega + i] < index || ptr[ctx->info->omega + i] > ctx->info->omega) {
            BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_SIGN_DATA_ERROR);
            return CRYPT_MLDSA_SIGN_DATA_ERROR;
        }
        uint32_t first = index;
        (void)memset_s(h[i], sizeof(int32_t) * MLDSA_N, 0, sizeof(int32_t) * MLDSA_N);
        while (index < ptr[ctx->info->omega + i]) {
            if (index > first && (ptr[index - 1] >= ptr[index])) {
                BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_SIGN_DATA_ERROR);
                return CRYPT_MLDSA_SIGN_DATA_ERROR;
            }
            h[i][ptr[index]] = 1;
            index++;
        }
    }
    for (int32_t i = index; i < (ctx->info->omega - 1); i++) {
        RETURN_RET_IF(ptr[i] != 0, CRYPT_MLDSA_SIGN_DATA_ERROR);
    }
    return CRYPT_SUCCESS;
}

static void ComputesApproxW(const CRYPT_ML_DSA_Ctx *ctx, MLDSA_VerifyMatrixSt *st, int32_t *c, int32_t *w[MLDSA_K_MAX])
{
    MLDSA_ComputesNTT(c);
    for (uint8_t i = 0; i < ctx->info->l; i++) {
        MLDSA_ComputesNTT(st->z[i]);
    }
    for (uint8_t i = 0; i < ctx->info->k; i++) {
        for (int32_t j = 0; j < MLDSA_N; j++) {
            // t1 ⋅ 2^𝑑
            st->t1[i][j] = (int32_t)((uint32_t)st->t1[i][j] << MLDSA_D);
        }
        // NTT(t1 ⋅ 2^𝑑)
        MLDSA_ComputesNTT(st->t1[i]);
        // NTT(𝑐) ∘ NTT(t1 ⋅ 2^𝑑)
        VectorsMul(st->t1[i], st->t1[i], c);
        // A ∘ NTT(z)
        MatrixMul(ctx, w[i], st->matrix[i], st->z);

        MLDSA_VectorsSub(w[i], w[i], st->t1[i]);
        MLDSA_ComputesINVNTT(w[i]);
    }
}

static void UseHint(const CRYPT_ML_DSA_Ctx *ctx, int32_t *h[MLDSA_K_MAX], int32_t *w[MLDSA_K_MAX])
{
    int32_t r1;
    int32_t r0;
    for (uint8_t i = 0; i < ctx->info->k; i++) {
        for (uint32_t j = 0; j < MLDSA_N; j++) {
            if (w[i][j] < 0) {
                w[i][j] += MLDSA_Q;
            }
            Decompose(ctx, w[i][j], &r1, &r0);
            if (h[i][j] == 0) {
                w[i][j] = r1;
                continue;
            }
            if (ctx->info->gamma2 == 95232) {  // 95232 is (MLDSA_Q-1) / 88;
                // 𝑚 ← (𝑞 − 1)/(2𝛾2) = 44
                // If r0 > 0 return (r1 + 1) mod m else return (r1 − 1) mod m
                w[i][j] = (r0 > 0) ? ((r1 == 43) ? 0 : (r1 + 1)) : ((r1 == 0) ? 43 : (r1 - 1)); // 43 is (m - 1)
                continue;
            }
            w[i][j] = ((r0 > 0) ? (r1 + 1) : (r1 - 1)) & 0x0f;
        }
    }
}

// Referenced from NIST.FIPS.204 Algorithm 6 ML-DSA.KeyGen_internal(𝑑)
int32_t MLDSA_KeyGenInternal(CRYPT_ML_DSA_Ctx *ctx, uint8_t *d)
{
    uint8_t k = ctx->info->k;
    uint8_t l = ctx->info->l;
    uint8_t seed[MLDSA_SEED_EXTEND_BYTES_LEN] = { 0 };
    uint8_t digest[MLDSA_EXPANDED_SEED_BYTES_LEN] = { 0 };
    uint8_t tr[MLDSA_TR_MSG_LEN] = { 0 };
    MLDSA_KeyGenMatrixSt st = { 0 };
    int32_t ret;

    GOTO_ERR_IF(MLDSAKeyGenCreateMatrix(k, l, &st), ret);
    // 32-byte random seed + 1 byte 'k' + 1 byte 'l'
    (void)memcpy_s(seed, sizeof(seed), d, MLDSA_SEED_BYTES_LEN);
    seed[MLDSA_SEED_BYTES_LEN] = k;
    seed[MLDSA_SEED_BYTES_LEN + 1] = l;
    // (ρ, ρ′, K) ∈ B32 × B64 × B32 ← H(𝜉||IntegerToBytes(k, 1)||IntegerToBytes(ℓ, 1), 128)
    GOTO_ERR_IF(HashFuncH(seed, sizeof(seed), NULL, 0, digest, MLDSA_EXPANDED_SEED_BYTES_LEN), ret);
    uint8_t *pubSeed = digest;
    uint8_t *prvSeed = digest + MLDSA_PUBLIC_SEED_LEN;
    uint8_t *signSeed = digest + MLDSA_PUBLIC_SEED_LEN + MLDSA_PRIVATE_SEED_LEN;

    // A ← ExpandA(ρ)
    GOTO_ERR_IF(ExpandA(ctx, pubSeed, st.matrix), ret);
    // (𝐬1, 𝐬2) ← ExpandS(ρ′)
    GOTO_ERR_IF(ExpandS(ctx, prvSeed, st.s1, st.s2), ret);

    // t ← NTT^−1(A ∘ NTT(𝐬1)) + 𝐬2
    ComputesNTT(ctx, st.s1, st.s1Ntt);
    ComputesT(ctx, st.t1, st.matrix, st.s1Ntt, st.s2);  // t = As1 + s2

    // (t1, t0) ← Power2Round(t)
    ComputesPower2Round(ctx, st.t0, st.t1);
    // pk ← pkEncode(ρ, t1)
    PkEncode(ctx, pubSeed, st.t1);

    // tr ← H(pk, 64)
    GOTO_ERR_IF(HashFuncH(ctx->pubKey, ctx->pubLen, NULL, 0, tr, MLDSA_TR_MSG_LEN), ret);  // Step 9

    // sk ← skEncode(ρ, K, tr, 𝐬1, 𝐬2, t0)
    SkEncode(ctx, pubSeed, signSeed, tr, &st); // Step 10
    
    ctx->hasSeed = true;
    (void)memcpy_s(ctx->seed, MLDSA_SEED_BYTES_LEN, d, MLDSA_SEED_BYTES_LEN);
ERR:
    BSL_SAL_ClearFree(st.bufAddr, st.bufSize);
    BSL_SAL_CleanseData(seed, sizeof(seed));
    BSL_SAL_CleanseData(digest, sizeof(digest));
    return ret;
}

// Referenced from NIST.FIPS.204 Algorithm 7 ML-DSA.Sign_internal(sk, 𝑀′, r𝑛𝑑)
int32_t MLDSA_SignInternal(const CRYPT_ML_DSA_Ctx *ctx, CRYPT_Data *msg, uint8_t *out, uint32_t *outLen, uint8_t *rand)
{
    int32_t ret = CRYPT_SUCCESS;
    uint8_t pubSeed[MLDSA_PUBLIC_SEED_LEN];
    uint8_t uBuf[MLDSA_XOF_MSG_LEN];
    uint8_t tr[MLDSA_TR_MSG_LEN];
    uint8_t signSeed[MLDSA_SIGNING_SEED_LEN + MLDSA_SEED_BYTES_LEN];
    (void)memcpy_s(signSeed + MLDSA_SIGNING_SEED_LEN, MLDSA_SEED_BYTES_LEN, rand, MLDSA_SEED_BYTES_LEN);

    // The w1Len length of MLDSA44 and MLDSA65 is 768, and the w1Len length of MLDSA87 is 1024.
    uint32_t w1Len = (ctx->info->k == 4 || ctx->info->k == 6) ? 768 : 1024;
    uint8_t *w1Buf = BSL_SAL_Malloc(w1Len);
    RETURN_RET_IF(w1Buf == NULL, CRYPT_MEM_ALLOC_FAIL);

    MLDSA_SignMatrixSt st = { 0 };
    GOTO_ERR_IF(MLDSASignCreateMatrix(ctx->info->k, ctx->info->l, &st), ret);

    // (ρ, K, tr, 𝐬1, 𝐬2, t0) ← skDecode(sk)
    SkDecode(ctx, pubSeed, signSeed, tr, &st);
    // NTT(s1), NTT(s2), NTT(t0)
    SignCalNtt(ctx, &st);
    // A ← ExpandA(ρ)
    GOTO_ERR_IF(ExpandA(ctx, pubSeed, st.matrix), ret);
    if (ctx->isMuMsg) {
        (void)memcpy_s(uBuf, MLDSA_XOF_MSG_LEN, msg->data, msg->len);
    } else {
        // μ ← H(BytesToBits(tr)||𝑀′, 64)
        GOTO_ERR_IF(HashFuncH(tr, MLDSA_TR_MSG_LEN, msg->data, msg->len, uBuf, MLDSA_XOF_MSG_LEN), ret);
    }
    // ρ″ ← H(K||r𝑛𝑑||μ, 64)
    uint8_t p[MLDSA_XOF_MSG_LEN + 2]; // The counter used 2 bytes.
    GOTO_ERR_IF(HashFuncH(signSeed, sizeof(signSeed), uBuf, MLDSA_XOF_MSG_LEN, p, MLDSA_XOF_MSG_LEN), ret);

    uint16_t u = 0;
    // The length of c is λ/4.
    uint32_t cBufLen = ctx->info->secBits / 4;
    int32_t c[MLDSA_N];
    do {
        // y ← ExpandMask(ρ″, 𝜅)
        GOTO_ERR_IF(ExpandMask(ctx, st.y, p, u), ret);
        u = u + ctx->info->l;
        ComputesNTT(ctx, st.y, st.z);
        // w ← NTT−1(A ∘ NTT(y)); w1 ← HighBits(w)
        ComputesW(ctx, st.w, st.w1, st.matrix, st.z);

        // 𝑐 ← H(μ||w1Encode(w1), 𝜆/4)
        W1Encode(ctx, w1Buf, st.w1);
        GOTO_ERR_IF(HashFuncH(uBuf, MLDSA_XOF_MSG_LEN, w1Buf, w1Len, out, cBufLen), ret);
        (void)memset_s(c, sizeof(c), 0, sizeof(c));
        // 𝑐 ∈ 𝑅𝑞 ← SampleInBall(c)
        SampleInBall(ctx, out, cBufLen, c);
        // 𝑐 ← NTT(𝑐)
        MLDSA_ComputesNTT(c);

        // ⟨⟨𝑐𝐬1⟩⟩ ← NTT^−1(𝑐 ∘ 𝐬1); z ← y + ⟨⟨𝑐𝐬1⟩⟩
        ComputesZ(ctx, st.y, c, st.s1, st.z);
        // if ||z||∞ ≥ 𝛾1 − β
        if (ValidityChecksL(ctx, st.z, ctx->info->gamma1 - ctx->info->beta) == false) {
            continue;
        }
        // ⟨⟨𝑐𝐬2⟩⟩ ← NTT^−1(𝑐 ∘ 𝐬2); 𝐫0 ← LowBits(w − ⟨⟨𝑐𝐬2⟩⟩)
        ComputesR(ctx, c, &st);
        // if ||𝐫0||∞ ≥ 𝛾2 − β
        if (ValidityChecksK(ctx, st.r0, ctx->info->gamma2 - ctx->info->beta) == false) {
            continue;
        }
        // ⟨⟨𝑐t0⟩⟩ ← NTT^−1(𝑐 ∘ t0)
        ComputesCT(ctx, c, st.t0, st.ct0);
        // if ||⟨⟨𝑐t0⟩⟩||∞ ≥ 𝛾2
        if (ValidityChecksK(ctx, st.ct0, ctx->info->gamma2) == false) {
            continue;
        }
        // h ← MakeHint(−⟨⟨𝑐t0⟩⟩, w − ⟨⟨𝑐𝐬2⟩⟩ + ⟨⟨𝑐t0⟩⟩)
        if (MakeHint(ctx, &st) > ctx->info->omega) {
            continue;
        }
        break;
    } while (true);

    *outLen = ctx->info->signatureLen;
    // σ ← sigEncode(𝑐, z̃ mod±𝑞, h)
    SigEncode(ctx, out + cBufLen, *outLen - cBufLen, st.z, st.h);
ERR:
    BSL_SAL_ClearFree(st.bufAddr, st.bufSize);
    BSL_SAL_ClearFree(w1Buf, w1Len);
    BSL_SAL_CleanseData(signSeed, sizeof(signSeed));
    return ret;
}

// Referenced from NIST.FIPS.204 Algorithm 8 ML-DSA.Verify_internal(pk, 𝑀′, σ)
int32_t MLDSA_VerifyInternal(const CRYPT_ML_DSA_Ctx *ctx, CRYPT_Data *msg, const uint8_t *sign, uint32_t signLen)
{
    (void)signLen;
    uint8_t k = ctx->info->k;
    uint8_t l = ctx->info->l;
    uint8_t pubSeed[MLDSA_PUBLIC_SEED_LEN];
    uint8_t uBuf[MLDSA_XOF_MSG_LEN];
    uint8_t cBuf[MLDSA_XOF_MSG_LEN];
    uint8_t tr[MLDSA_TR_MSG_LEN];
    uint32_t cBufLen = ctx->info->secBits / 4;
    MLDSA_VerifyMatrixSt st = { 0 };
    int32_t c[MLDSA_N] = { 0 };
    int32_t ret;

    // The w1Len length of MLDSA44 and MLDSA65 is 768, and the w1Len length of MLDSA87 is 1024.
    uint32_t w1Len = (k == 4 || k == 6) ? 768 : 1024;
    uint8_t *w1Buf = BSL_SAL_Malloc(w1Len);
    RETURN_RET_IF(w1Buf == NULL, CRYPT_MEM_ALLOC_FAIL);

    GOTO_ERR_IF(MLDSAVerifyCreateMatrix(k, l, &st), ret);

    // (ρ, t1) ← pkDecode(pk)
    PkDecode(ctx, pubSeed, st.t1);
    // (c,z,h) ← sigDecode(σ)
    GOTO_ERR_IF(SigDecode(ctx, sign + cBufLen, st.z, st.h), ret);

    // if ||z||∞ < 𝛾1 − β
    if (ValidityChecksL(ctx, st.z, ctx->info->gamma1 - ctx->info->beta) == false) {
        ret = CRYPT_MLDSA_SIGN_DATA_ERROR;
        goto ERR;
    }

    // A ← ExpandA(ρ)
    GOTO_ERR_IF(ExpandA(ctx, pubSeed, st.matrix), ret);
    if (ctx->isMuMsg) {
        (void)memcpy_s(uBuf, MLDSA_XOF_MSG_LEN, msg->data, msg->len);
    } else {
        // tr ← H(pk, 64)
        GOTO_ERR_IF(HashFuncH(ctx->pubKey, ctx->pubLen, NULL, 0, tr, MLDSA_TR_MSG_LEN), ret);
        // μ ← (H(BytesToBits(tr)||𝑀′, 64))
        GOTO_ERR_IF(HashFuncH(tr, MLDSA_TR_MSG_LEN, msg->data, msg->len, uBuf, MLDSA_XOF_MSG_LEN), ret);
    }

    // 𝑐 ∈ 𝑅𝑞 ← SampleInBall(𝑐)
    SampleInBall(ctx, sign, cBufLen, c);
    // w′ ← NTT−1(A ∘ NTT(z) − NTT(𝑐) ∘ NTT(t1 ⋅ 2𝑑))
    ComputesApproxW(ctx, &st, c, st.w);
    // w1′ ← UseHint(h, w′)
    UseHint(ctx, st.h, st.w);
    // c′← H(μ||w1Encode(w1′), 𝜆/4)
    W1Encode(ctx, w1Buf, st.w);
    GOTO_ERR_IF(HashFuncH(uBuf, MLDSA_XOF_MSG_LEN, w1Buf, w1Len, cBuf, cBufLen), ret);

    // If c and c' are not equal, verify failed.
    if (memcmp(sign, cBuf, cBufLen) != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_VERIFY_FAIL);
        ret = CRYPT_MLDSA_VERIFY_FAIL;
        goto ERR;
    }
ERR:
    BSL_SAL_Free(st.bufAddr);
    BSL_SAL_Free(w1Buf);
    return ret;
}

#ifdef HITLS_CRYPTO_MLDSA_CHECK

// calculate public key from private key
int32_t MLDSA_CalPub(const CRYPT_ML_DSA_Ctx *ctx, uint8_t *pub, uint32_t pubLen)
{
    int32_t ret;
    MLDSA_SignMatrixSt st = { 0 };
    uint8_t pubSeed[MLDSA_PUBLIC_SEED_LEN];
    uint8_t kValue[MLDSA_SIGNING_SEED_LEN + MLDSA_SEED_BYTES_LEN];
    int32_t tmp0[MLDSA_K_MAX][MLDSA_N];
    int32_t tmp1[MLDSA_K_MAX][MLDSA_N];
    int32_t tmp2[MLDSA_L_MAX][MLDSA_N];
    uint8_t tr[MLDSA_TR_MSG_LEN];

    int32_t *s1Ntt[MLDSA_L_MAX];
    int32_t *t0[MLDSA_K_MAX];
    int32_t *t1[MLDSA_K_MAX];

    for (int32_t i = 0; i < ctx->info->k; i++) {
        t0[i] = tmp0[i];
        t1[i] = tmp1[i];
    }
    for (int32_t i = 0; i < ctx->info->l; i++) {
        s1Ntt[i] = tmp2[i];
    }

    GOTO_ERR_IF(MLDSASignCreateMatrix(ctx->info->k, ctx->info->l, &st), ret);
    SkDecode(ctx, pubSeed, kValue, tr, &st); // get ρ, K, tr, s1, s2, t0
    // A <- ExpandA(ρ)
    GOTO_ERR_IF(ExpandA(ctx, pubSeed, st.matrix), ret);
    // t <- NTT^−1(A ∘ NTT(s1)) + s2
    ComputesNTT(ctx, st.s1, s1Ntt);
    ComputesT(ctx, t1, st.matrix, s1Ntt, st.s2);  // t = As1 + s2
    // (t1, t0) <- Power2Round(t)
    ComputesPower2Round(ctx, t0, t1);
    for (int32_t i = 0; i < ctx->info->k; i++) {
        if (memcmp(t0[i], st.t0[i], MLDSA_N) != 0) {
            BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_PAIRWISE_CHECK_FAIL);
            ret = CRYPT_MLDSA_PAIRWISE_CHECK_FAIL;
            goto ERR;
        }
    }
    // pk <- pkEncode(ρ, t1)
    if (memcpy_s(pub, pubLen, pubSeed, MLDSA_PUBLIC_SEED_LEN) != EOK) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLDSA_LEN_NOT_ENOUGH);
        ret = CRYPT_MLDSA_LEN_NOT_ENOUGH;
        goto ERR;
    }
    for (int32_t i = 0; i < ctx->info->k; i++) {
        // 10 is bitlen(q − 1) − d
        ByteEncode(pub + MLDSA_PUBLIC_SEED_LEN + i * MLDSA_PUBKEY_POLYT_PACKEDBYTES, (uint32_t *)t1[i], 10);
    }
ERR:
    BSL_SAL_ClearFree(st.bufAddr, st.bufSize);
    BSL_SAL_CleanseData(kValue, sizeof(kValue));
    BSL_SAL_CleanseData(pubSeed, sizeof(pubSeed));
    return ret;
}

#endif // HITLS_CRYPTO_MLDSA_CHECK

#endif