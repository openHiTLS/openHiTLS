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
#include <stdio.h>
#include <stdint.h>
#include "crypt_errno.h"
#include "crypt_sha3.h"
#include "eal_md_local.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "ml_dsa_local.h"


void MLDSA_VectorsMul(int32_t *t, const int32_t *matrix, const int32_t *s)
{
    for (uint32_t i = 0; i < MLDSA_N; i++) {
        t[i] = MLDSA_PlantardMulReduce((uint64_t)matrix[i] * (uint64_t)s[i] * (uint64_t)MLDSA_PLANTARD_INV);
    }
}

void MLDSA_MatrixMul(const CRYPT_ML_DSA_Ctx *ctx, int32_t *t, int32_t *const matrix[MLDSA_L_MAX],
    int32_t *const s[MLDSA_L_MAX])
{
    int64_t tmp[MLDSA_N] = { 0 };
    for (uint32_t i = 0; i < ctx->info->l; i++) {
        for (uint32_t j = 0; j < MLDSA_N; j++) {
            tmp[j] += (int64_t)matrix[i][j] * s[i][j];
        }
    }
    for (uint32_t j = 0; j < MLDSA_N; j++) {
        t[j] = MLDSA_PlantardMulReduce((uint64_t)tmp[j] * (uint64_t)MLDSA_PLANTARD_INV);
    }
}


/**
 * MLDSA_UseHint - Apply hint bits to correct rounding in signature verification
 * 
 * This function implements the UseHint algorithm from ML-DSA specification.
 * During signature verification, hint bits help recover the correct high-order bits
 * of the challenge-dependent value w from a potentially rounded version.
 * 
 * @ctx: ML-DSA context containing algorithm parameters (k, gamma2)
 * @h: Array of hint polynomials (binary values indicating where rounding occurred)
 * @w: Array of polynomials to be corrected using hints (modified in-place)
 * 
 * Algorithm overview:
 * For each coefficient w[i][j], decompose it into high (r1) and low (r0) parts.
 * If hint bit h[i][j] is set, adjust r1 by ±1 based on the sign of r0,
 * ensuring recovery of the original high-order bits before rounding.
 */
void MLDSA_UseHint(const CRYPT_ML_DSA_Ctx *ctx, int32_t *const h[MLDSA_K_MAX], int32_t *w[MLDSA_K_MAX])
{
    int32_t r1;
    int32_t r0;
    for (uint8_t i = 0; i < ctx->info->k; i++) {
        for (uint32_t j = 0; j < MLDSA_N; j++) {
            // Normalize w[i][j] to positive range [0, q) by adding q if negative
            // if w[i][j] < 0 then w[i][j] >> 31 is 0xFFFFFFFF else w[i][j] >> 31 is 0.
            w[i][j] = w[i][j] + (MLDSA_Q & (w[i][j] >> 31));
            
            // Decompose w[i][j] into high and low parts using Power2Round
            MLDSA_Decompose(ctx, w[i][j], &r1, &r0);
            
            // If hint bit is 0, no correction needed
            if (h[i][j] == 0) {
                w[i][j] = r1;
                continue;
            }
            
            // Apply hint correction based on gamma2 parameter
            if (ctx->info->gamma2 == 95232) {  // 95232 is (MLDSA_Q-1) / 88; for ML-DSA-44/65
                // m = (q - 1) / (2*gamma2) = 44
                // Adjust r1 by ±1 (mod m) based on sign of r0
                // If r0 > 0: increment r1 (mod m)
                // If r0 <= 0: decrement r1 (mod m)
                w[i][j] = (r0 > 0) ? ((r1 == 43) ? 0 : (r1 + 1)) : ((r1 == 0) ? 43 : (r1 - 1)); // 43 is (m - 1)
                continue;
            }
            
            // For ML-DSA-87 with gamma2 = 261888
            // m = (q - 1) / (2*gamma2) = 16, result masked to 4 bits
            w[i][j] = ((r0 > 0) ? (r1 + 1) : (r1 - 1)) & 0x0f;
        }
    }
}

void MLDSA_Decompose(const CRYPT_ML_DSA_Ctx *ctx, int32_t r, int32_t *r1, int32_t *r0)
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
}

void MLDSA_Batch_Decompose(const CRYPT_ML_DSA_Ctx *ctx, int32_t a[MLDSA_N], int32_t r1[MLDSA_N])
{
    for (uint32_t i = 0; i < MLDSA_N; i++) {
        int32_t r0;
        a[i] = a[i] + (MLDSA_Q & (a[i] >> 31));
        MLDSA_Decompose(ctx, a[i], &r1[i], &r0);
        a[i] = r0;
    }
}

int32_t MLDSA_RejNTTPoly(int32_t a[MLDSA_N], const uint8_t seed[MLDSA_SEED_EXTEND_BYTES_LEN])
{
    int32_t ret;
    unsigned int outlen = CRYPT_SHAKE128_BLOCKSIZE;
    const uint32_t buflen = CRYPT_SHAKE128_BLOCKSIZE / 4;
    uint32_t buf[CRYPT_SHAKE128_BLOCKSIZE / 4];

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
    GOTO_ERR_IF(hashMethod->squeeze(mdCtx, (uint8_t *)buf, outlen), ret);
    uint32_t j = 0;
    for (uint32_t i = 0; i < MLDSA_N;) {
        const uint32_t w0 = CRYPT_HTOLE32(buf[j]);
        const uint32_t w1 = CRYPT_HTOLE32(buf[j + 1]);
        const uint32_t w2 = CRYPT_HTOLE32(buf[j + 2]);

        int32_t t0 = w0;
        int32_t t1 = (w0 >> 24) | (w1 << 8);
        int32_t t2 = (w1 >> 16) | (w2 << 16);
        int32_t t3 = (w2 >> 8);

        t0 &= 0x7FFFFFU;
        t1 &= 0x7FFFFFU;
        t2 &= 0x7FFFFFU;
        t3 &= 0x7FFFFFU;

        const int32_t m0 = (MLDSA_Q - 1 - t0) >> 31;
        const int32_t m1 = (MLDSA_Q - 1 - t1) >> 31;
        const int32_t m2 = (MLDSA_Q - 1 - t2) >> 31;
        const int32_t m3 = (MLDSA_Q - 1 - t3) >> 31;

        a[i] = t0 & ~m0;
        i += 1 + m0; // a[i] is less than MLDSA_Q is a valid value.
        if (i < MLDSA_N) {
            a[i] = t1 & ~m1;
            i += 1 + m1;
        }

        if (i < MLDSA_N) {
            a[i] = t2 & ~m2;
            i += 1 + m2;
        }

        if (i < MLDSA_N) {
            a[i] = t3 & ~m3;
            i += 1 + m3;
        }

        j += 3;
        if (j >= buflen && i < MLDSA_N) {
            GOTO_ERR_IF(hashMethod->squeeze(mdCtx, (uint8_t *)buf, outlen), ret);
            j = 0;
        }
    }
ERR:
    hashMethod->freeCtx(mdCtx);
    return ret;
}

int32_t MLDSA_RejBoundedPolyEta2(int32_t *a, const uint8_t *s)
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

        // This is Barrett Modular Multiplication, 205 == 2^10 / 5
        int32_t mask = (0xE - z0) >> 31; // 0 or -1
        z0 = z0 - ((205 * z0) >> 10) * 5; // 205 == 2^10 / 5
        a[i] = (2 - z0) & ~mask; // 2 − (b mod 5)
        i += 1 + mask;

        if (i < MLDSA_N) {
            // Barrett Modular Multiplication, 205 == 2^10 / 5
            mask = (0xE - z1) >> 31; // 0 or -1
            z1 = z1 - ((205 * z1) >> 10) * 5; // 205 == 2^10 / 5
            a[i] = (2 - z1) & ~mask; // 2 − (b mod 5)
            i += 1 + mask;
        }
    }
ERR:
    hashMethod->freeCtx(mdCtx);
    return ret;
}

int32_t MLDSA_RejBoundedPolyEta4(int32_t *a, const uint8_t *s)
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
        int32_t mask = (0x8 - z0) >> 31;
        a[i] = (4 - z0) & ~mask; // if 𝜂 = 4 and b < 9 then a[i] = 4 − b
        i += 1 + mask;

        if (i < MLDSA_N) {
            mask = (0x8 - z1) >> 31;
            a[i] = (4 - z1) & ~mask; // if 𝜂 = 4 and b < 9 then a[i] = 4 − b
            i += 1 + mask;
        }
    }
ERR:
    hashMethod->freeCtx(mdCtx);
    return ret;
}

bool MLDSA_ValidityChecks(const int32_t *z, uint32_t t)
{
    uint32_t n;
    uint32_t result = 0;
    for (uint32_t j = 0; j < MLDSA_N; j++) {
        n = z[j] >> 31; // Shift rightwards by 31 bits.
        n = z[j] - (n & ((uint32_t)z[j] << 1));
        // If |z[j]| >= t, (t - 1 - n) is negative and its highest bit (sign bit) is 1.
        result |= ((t - 1 - n) >> 31) & 1;
    }
    return (result == 0);
}

void MLDSA_VectorsAdd(int32_t *t, int32_t *a, int32_t *b)
{
    for (uint32_t i = 0; i < MLDSA_N; i++) {
        t[i] = a[i] + b[i];
        MLDSA_MOD_Q(t[i]);
    }
}

void MLDSA_VectorsAddQ(int32_t *t, int32_t *a, int32_t *b)
{
    for (uint32_t i = 0; i < MLDSA_N; i++) {
        t[i] = a[i] + b[i];
        t[i] = t[i] + (MLDSA_Q & (t[i] >> 31));
    }
}

void MLDSA_VectorsSub(int32_t *t, int32_t *a, int32_t *b)
{
    for (uint32_t i = 0; i < MLDSA_N; i++) {
        t[i] = a[i] - b[i];
        MLDSA_MOD_Q(t[i]);
    }
}

void MLDSA_ComputesPower2Round(const CRYPT_ML_DSA_Ctx *ctx, int32_t *t0[MLDSA_K_MAX], int32_t *t1[MLDSA_K_MAX])
{
    for (uint32_t i = 0; i < ctx->info->k; i++) {
        for (int32_t j = 0; j < MLDSA_N; j++) {
            int32_t t = (t1[i][j] + (1 << (MLDSA_D - 1)) - 1) >> MLDSA_D;
            t0[i][j] = t1[i][j] - (t << MLDSA_D);
            t1[i][j] = t;
        }
    }
}

void MLDSA_SignBitUnPack(const uint8_t *v, uint32_t w[MLDSA_N], uint32_t bits, uint32_t b)
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
}

#endif // HITLS_CRYPTO_MLDSA
