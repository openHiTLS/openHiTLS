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
#ifdef HITLS_CRYPTO_MLKEM
#include <string.h>
#include "securec.h"
#include "crypt_utils.h"
#include "crypt_sha3.h"
#include "crypt_errno.h"
#include "asm_sha3.h"
#include "ml_kem_local.h"

#define GEN_MATRIX_NBLOCKS \
    ((12 * MLKEM_N / 8 * (1 << 12) / MLKEM_Q + CRYPT_SHAKE128_BLOCKSIZE) / CRYPT_SHAKE128_BLOCKSIZE)

void MLKEMPointMulExtended(int16_t *, int16_t *, const int16_t *);
void MLKEMAsymMulMont(uint32_t k, int16_t *r, int16_t *a, int16_t *b, int16_t *c);
void MLKEMAsymMul(uint32_t k, int16_t *r, int16_t **a, int16_t *b, int16_t *c);
void MLKEMPolyAddReduce(uint32_t k, int16_t **r, int16_t **e);
void MLKEMAdd2Reduce(int16_t *, int16_t *, const int16_t *);
void MLKEMSubReduce(int16_t *, int16_t *);
void MLKEMPolyVecReduce(uint32_t k, int16_t **r);
void PolyVectoBytes(uint32_t k, uint8_t *r, int16_t **a);
void MLKEMPolyINTTtoMont(uint32_t k, int16_t **r);
void MLKEMPolyCBDEta(uint32_t eta, int16_t *r, const uint8_t *buf);
void PolyVecCompress(uint32_t k, uint8_t *r, int16_t **a);
void PolyCompress(uint32_t k, uint8_t *r, int16_t *a);
void PackCipherText(uint32_t k, uint32_t c1len, uint8_t *ct, int16_t **t, int16_t *c2);
void MLKEMPolyCompress4(uint8_t *, int16_t *);
void MLKEMPolyCompress5(uint8_t *, int16_t *);
void MLKEMPolyCompress1(uint8_t *, int16_t *);
unsigned int MLKEMRejUniform(int16_t *, const uint8_t *);
void MLKEM_ComputeNTTAsm(int16_t *a);
void MLKEM_ComputeINTTAsm(int16_t *a);

/*
 * Base multiplication (basemul) twiddle factor table.
 *
 * X^256 + 1 decomposes into 64 degree-4 factors, each splitting into two
 * degree-2 factors:
 *   (X^2 - zeta_j) * (X^2 + zeta_j),  zeta_j = omega^(2*bitrev(j,6)+1) mod^{+-} Q
 * for j = 0..63. The basemul needs both zeta_j and its Barrett companion zeta_hi_j.
 *
 * Generation script (verified against this table):
 *
 *   # Uses Q, omega, bitrev, mod_pm, barrett_hi defined above.
 *   def gen_basemul_table():  # -> 256 entries (MLKEM_N)
 *       T = []
 *       for row in range(16):  # 16 rows of 16 entries
 *           roots = []
 *           for m in range(4):  # 4 twiddles per row
 *               j = 4 * row + m
 *               k = 2 * bitrev(j, 6) + 1
 *               z = mod_pm(pow(omega, k, Q))
 *               roots.append((z, barrett_hi(z)))
 *           for z, _ in roots: T += [z, -z]     # root part
 *           for _, h in roots: T += [h, -h]     # root_hi part
 *       return T
 */
const __attribute__((aligned(16))) int16_t MLKEM_BASEMUL_TWIDDLE_TABLE[MLKEM_N] = {
    17,     -17,    -568,   568,    583,    -583,   -680,  680,    167,    -167,   -5591,  5591,   5739,   -5739,
    -6693,  6693,   1637,   -1637,  723,    -723,   -1041, 1041,   1100,   -1100,  16113,  -16113, 7117,   -7117,
    -10247, 10247,  10828,  -10828, 1409,   -1409,  -667,  667,    -48,    48,     233,    -233,   13869,  -13869,
    -6565,  6565,   -472,   472,    2293,   -2293,  756,   -756,   -1173,  1173,   -314,   314,    -279,   279,
    7441,   -7441,  -11546, 11546,  -3091,  3091,   -2746, 2746,   -1626,  1626,   1651,   -1651,  -540,   540,
    -1540,  1540,   -16005, 16005,  16251,  -16251, -5315, 5315,   -15159, 15159,  -1482,  1482,   952,    -952,
    1461,   -1461,  -642,   642,    -14588, 14588,  9371,  -9371,  14381,  -14381, -6319,  6319,   939,    -939,
    -1021,  1021,   -892,   892,    -941,   941,    9243,  -9243,  -10050, 10050,  -8780,  8780,   -9262,  9262,
    733,    -733,   -992,   992,    268,    -268,   641,   -641,   7215,   -7215,  -9764,  9764,   2638,   -2638,
    6309,   -6309,  1584,   -1584,  -1031,  1031,   -1292, 1292,   -109,   109,    15592,  -15592, -10148, 10148,
    -12717, 12717,  -1073,  1073,   375,    -375,   -780,  780,    -1239,  1239,   1645,   -1645,  3691,   -3691,
    -7678,  7678,   -12196, 12196,  16192,  -16192, 1063,  -1063,  319,    -319,   -556,   556,    757,    -757,
    10463,  -10463, 3140,   -3140,  -5473,  5473,   7451,  -7451,  -1230,  1230,   561,    -561,   -863,   863,
    -735,   735,    -12107, 12107,  5522,   -5522,  -8495, 8495,   -7235,  7235,   -525,   525,    1092,   -1092,
    403,    -403,   1026,   -1026,  -5168,  5168,   10749, -10749, 3967,   -3967,  10099,  -10099, 1143,   -1143,
    -1179,  1179,   -554,   554,    886,    -886,   11251, -11251, -11605, 11605,  -5453,  5453,   8721,   -8721,
    -1607,  1607,   1212,   -1212,  -1455,  1455,   1029,  -1029,  -15818, 15818,  11930,  -11930, -14322, 14322,
    10129,  -10129, -1219,  1219,   -394,   394,    885,   -885,   -1175,  1175,   -11999, 11999,  -3878,  3878,
    8711,   -8711,  -11566, 11566};

void KyberShake256x2Prf(uint8_t *out1, uint8_t *out2, size_t outlen, const uint8_t key[MLKEM_SEED_LEN], uint8_t nonce1,
                        uint8_t nonce2)
{
    uint8_t extkey1[MLKEM_SEED_LEN + 1];
    uint8_t extkey2[MLKEM_SEED_LEN + 1];

    memcpy(extkey1, key, MLKEM_SEED_LEN);
    memcpy(extkey2, key, MLKEM_SEED_LEN);
    extkey1[MLKEM_SEED_LEN] = nonce1;
    extkey2[MLKEM_SEED_LEN] = nonce2;
    Shake256x2(out1, out2, outlen, extkey1, extkey2, sizeof(extkey1));
}

void KyberShake128x2Absorb(Keccakx2State state, const uint8_t seed[MLKEM_SEED_LEN], uint8_t x1, uint8_t x2, uint8_t y1,
                           uint8_t y2)
{
    uint8_t extseed1[MLKEM_SEED_LEN + 2 + 6];
    uint8_t extseed2[MLKEM_SEED_LEN + 2 + 6];

    memcpy(extseed1, seed, MLKEM_SEED_LEN);
    memcpy(extseed2, seed, MLKEM_SEED_LEN);
    extseed1[MLKEM_SEED_LEN] = x1;
    extseed1[MLKEM_SEED_LEN + 1] = y1;

    extseed2[MLKEM_SEED_LEN] = x2;
    extseed2[MLKEM_SEED_LEN + 1] = y2;

    Keccakx2Absorb(state, CRYPT_SHAKE128_BLOCKSIZE, extseed1, extseed2, MLKEM_SEED_LEN + 2, 0x1F);
}

void KyberShakeAbsorb(ShakeState *state, const uint8_t seed[MLKEM_SEED_LEN], uint8_t x, uint8_t y)
{
    uint8_t extseed[MLKEM_SEED_LEN + 2];

    memcpy(extseed, seed, MLKEM_SEED_LEN);
    extseed[MLKEM_SEED_LEN] = x;
    extseed[MLKEM_SEED_LEN + 1] = y;
    KeccakAbsorb(state->s, CRYPT_SHAKE128_BLOCKSIZE, extseed, sizeof(extseed), 0x1F);
    state->pos = CRYPT_SHAKE128_BLOCKSIZE;
}

void PolyGetNoiseEtaX2(uint32_t eta, int16_t vec1[MLKEM_N], int16_t vec2[MLKEM_N], const uint8_t seed[MLKEM_SEED_LEN],
                       uint8_t nonce1, uint8_t nonce2)
{
    uint8_t buf1[eta * MLKEM_N / 4], buf2[eta * MLKEM_N / 4];
    KyberShake256x2Prf(buf1, buf2, sizeof(buf1), seed, nonce1, nonce2);
    MLKEMPolyCBDEta(eta, vec1, buf1);
    MLKEMPolyCBDEta(eta, vec2, buf2);
}

int32_t SampleEta1(const CRYPT_ML_KEM_Ctx *ctx, uint8_t *seed, int16_t *s[], int16_t *e[])
{
    uint32_t k = ctx->info->k;
    uint32_t eta1 = ctx->info->eta1;
    if (k == 2) {
        PolyGetNoiseEtaX2(eta1, s[0], s[1], seed, 0, 1);
        PolyGetNoiseEtaX2(eta1, e[0], e[1], seed, 2, 3);
    } else if (k == 3) {
        PolyGetNoiseEtaX2(eta1, s[0], s[1], seed, 0, 1);
        PolyGetNoiseEtaX2(eta1, s[2], e[0], seed, 2, 3);
        PolyGetNoiseEtaX2(eta1, e[1], e[2], seed, 4, 5);
    } else if (k == 4) {
        PolyGetNoiseEtaX2(eta1, s[0], s[1], seed, 0, 1);
        PolyGetNoiseEtaX2(eta1, s[2], s[3], seed, 2, 3);
        PolyGetNoiseEtaX2(eta1, e[0], e[1], seed, 4, 5);
        PolyGetNoiseEtaX2(eta1, e[2], e[3], seed, 6, 7);
    }
    for (uint32_t i = 0; i < k; i++) {
        MLKEM_ComputeNTTAsm(s[i]);
        MLKEM_ComputeNTTAsm(e[i]);
    }
    return CRYPT_SUCCESS;
}

// Sample noise for encryption: s[] (ephemeral secret y) is sampled with eta1 and NTT-transformed,
// e[] (error vector) is sampled with eta2 and left in normal domain.
int32_t SampleEta2(const CRYPT_ML_KEM_Ctx *ctx, uint8_t *seed, int16_t *s[], int16_t *e[])
{
    uint32_t k = ctx->info->k;
    uint32_t eta1 = ctx->info->eta1;
    uint32_t eta2 = ctx->info->eta2;
    if (k == 2) {
        PolyGetNoiseEtaX2(eta1, s[0], s[1], seed, 0, 1);
        PolyGetNoiseEtaX2(eta2, e[0], e[1], seed, 2, 3);
        seed[MLKEM_SEED_LEN] = 4;
    } else if (k == 3) {
        PolyGetNoiseEtaX2(eta1, s[0], s[1], seed, 0, 1);
        PolyGetNoiseEtaX2(eta1, s[2], e[0], seed, 2, 3);
        PolyGetNoiseEtaX2(eta1, e[1], e[2], seed, 4, 5);
        seed[MLKEM_SEED_LEN] = 6;
    } else if (k == 4) {
        PolyGetNoiseEtaX2(eta1, s[0], s[1], seed, 0, 1);
        PolyGetNoiseEtaX2(eta1, s[2], s[3], seed, 2, 3);
        PolyGetNoiseEtaX2(eta1, e[0], e[1], seed, 4, 5);
        PolyGetNoiseEtaX2(eta1, e[2], e[3], seed, 6, 7);
        seed[MLKEM_SEED_LEN] = 8;
    }
    for (uint32_t i = 0; i < k; i++) {
        MLKEM_ComputeNTTAsm(s[i]);
    }
    return CRYPT_SUCCESS;
}

// Parse polynomial from XOF output with rejection sampling
// Converts 12-bit values from byte array to int16_t polynomial with rejection
// Returns number of coefficients accepted
static unsigned int Parse(int16_t *poly, uint8_t *arrayB, uint32_t arrayLen, uint32_t n)
{
    uint32_t i = 0;
    uint32_t j = 0;

    while (j < n) {
        if (i + 3 > arrayLen) {
            return j;
        }
        // The 4 bits of each byte are combined with the 8 bits of another byte into 12 bits.
        uint16_t d1 = ((uint16_t)arrayB[i]) + (((uint16_t)(arrayB[i + 1] & 0x0F)) << 8);
        uint16_t d2 = (((uint16_t)arrayB[i + 1]) >> 4) + (((uint16_t)arrayB[i + 2]) << 4);

        i += 3;

        if (d1 < MLKEM_Q) {
            poly[j++] = (int16_t)d1;
        }
        if (j < n && d2 < MLKEM_Q) {
            poly[j++] = (int16_t)d2;
        }
    }
    return j;
}

// Generate a pair of matrix polynomials using x2 (dual-lane) SHAKE128
static void GenMatrixX2Pair(const uint8_t *seed, int16_t *poly0, int16_t *poly1,
                            uint8_t x1, uint8_t x2, uint8_t y1, uint8_t y2)
{
    uint8_t buf0[GEN_MATRIX_NBLOCKS * CRYPT_SHAKE128_BLOCKSIZE + 2];
    uint8_t buf1[GEN_MATRIX_NBLOCKS * CRYPT_SHAKE128_BLOCKSIZE + 2];
    Keccakx2State state;

    KyberShake128x2Absorb(state, seed, x1, x2, y1, y2);
    Keccakx2Squeeze(buf0, buf1, GEN_MATRIX_NBLOCKS, CRYPT_SHAKE128_BLOCKSIZE, state);
    uint32_t buflen = GEN_MATRIX_NBLOCKS * CRYPT_SHAKE128_BLOCKSIZE;

    uint32_t ctr0 = MLKEMRejUniform(poly0, buf0);
    uint32_t ctr1 = MLKEMRejUniform(poly1, buf1);

    while (ctr0 < MLKEM_N || ctr1 < MLKEM_N) {
        uint32_t off = buflen % 3;
        for (uint32_t m = 0; m < off; m++) {
            buf0[m] = buf0[buflen - off + m];
            buf1[m] = buf1[buflen - off + m];
        }
        Keccakx2Squeeze(buf0 + off, buf1 + off, 1, CRYPT_SHAKE128_BLOCKSIZE, state);
        buflen = off + CRYPT_SHAKE128_BLOCKSIZE;
        ctr0 += Parse(poly0 + ctr0, buf0, buflen, MLKEM_N - ctr0);
        ctr1 += Parse(poly1 + ctr1, buf1, buflen, MLKEM_N - ctr1);
    }
}

// Generate a single matrix polynomial using scalar SHAKE128
static void GenMatrixSingle(const uint8_t *seed, int16_t *poly, uint8_t x, uint8_t y)
{
    uint8_t buf[GEN_MATRIX_NBLOCKS * CRYPT_SHAKE128_BLOCKSIZE + 2];
    ShakeState state;

    KyberShakeAbsorb(&state, seed, x, y);
    KeccakSqueeze(buf, GEN_MATRIX_NBLOCKS, state.s, CRYPT_SHAKE128_BLOCKSIZE);
    uint32_t buflen = GEN_MATRIX_NBLOCKS * CRYPT_SHAKE128_BLOCKSIZE;

    uint32_t ctr = MLKEMRejUniform(poly, buf);

    while (ctr < MLKEM_N) {
        uint32_t off = buflen % 3;
        for (uint32_t m = 0; m < off; m++) {
            buf[m] = buf[buflen - off + m];
        }
        KeccakSqueeze(buf + off, 1, state.s, CRYPT_SHAKE128_BLOCKSIZE);
        buflen = off + CRYPT_SHAKE128_BLOCKSIZE;
        ctr += Parse(poly + ctr, buf, buflen, MLKEM_N - ctr);
    }
}

int32_t GenMatrix(const CRYPT_ML_KEM_Ctx *ctx, const uint8_t *seed, int16_t *polyMatrix[MLKEM_K_MAX][MLKEM_K_MAX],
                  bool isEnc)
{
    uint8_t k = ctx->info->k;

    if (k == 2 || k == 4) {
        for (uint32_t i = 0; i < k; i++) {
            for (uint32_t j = 0; j < k; j += 2) {
                uint8_t x1 = isEnc ? i : j;
                uint8_t x2 = isEnc ? i : j + 1;
                uint8_t y1 = isEnc ? j : i;
                uint8_t y2 = isEnc ? j + 1 : i;
                GenMatrixX2Pair(seed, polyMatrix[i][j], polyMatrix[i][j + 1], x1, x2, y1, y2);
            }
        }
    } else if (k == 3) {
        // k=3: 8 entries use x2 mode (4 pairs), 1 entry [2][2] uses singleton mode
        for (uint32_t idx = 0; idx < 8; idx += 2) {
            uint32_t i1 = idx / 3, j1 = idx % 3;
            uint32_t i2 = (idx + 1) / 3, j2 = (idx + 1) % 3;
            uint8_t x1 = isEnc ? i1 : j1;
            uint8_t x2 = isEnc ? i2 : j2;
            uint8_t y1 = isEnc ? j1 : i1;
            uint8_t y2 = isEnc ? j2 : i2;
            GenMatrixX2Pair(seed, polyMatrix[i1][j1], polyMatrix[i2][j2], x1, x2, y1, y2);
        }
        // Last coefficient [2][2]: isEnc swap is a no-op since i == j == 2
        GenMatrixSingle(seed, polyMatrix[2][2], 2, 2);
    }
    return CRYPT_SUCCESS;
}

int32_t MLKEM_PKEGen(CRYPT_ML_KEM_Ctx *ctx, uint8_t *digest, uint8_t *pk, uint8_t *dk)
{
    int32_t ret = CRYPT_SUCCESS;
    uint8_t k = ctx->info->k;
    // expand 32+1 bytes to two pseudorandom 32-byte seeds
    uint8_t *p = digest;
    uint8_t *q = digest + CRYPT_SHA3_512_DIGESTSIZE / 2;
    GOTO_ERR_IF(GenMatrix(ctx, p, ctx->keyData.matrix, false), ret); // Step 3 - 7
    GOTO_ERR_IF(SampleEta1(ctx, q, ctx->keyData.vectorS, ctx->keyData.vectorT), ret); // Step 8 - 15

    int16_t s_asym[MLKEM_K_MAX][MLKEM_N >> 1];
    int16_t e[MLKEM_K_MAX][MLKEM_N];
    int16_t *ae[MLKEM_K_MAX] = {e[0], e[1], e[2], e[3]};
    for (uint32_t i = 0; i < k; i++) {
        MLKEMPointMulExtended(s_asym[i], ctx->keyData.vectorS[i], MLKEM_BASEMUL_TWIDDLE_TABLE);
    }
    for (uint32_t i = 0; i < k; i++) {
        MLKEMAsymMulMont(k, ae[i], ctx->keyData.matrix[i][0], &(ctx->keyData.vectorS[0][0]), &(s_asym[0][0]));
    }
    MLKEMPolyAddReduce(k, ctx->keyData.vectorT, ae);
    MLKEMPolyVecReduce(k, ctx->keyData.vectorS);
    MLKEMPolyVecReduce(k, ctx->keyData.vectorT);
    PolyVectoBytes(k, pk, ctx->keyData.vectorT);
    PolyVectoBytes(k, dk, ctx->keyData.vectorS);
    memcpy(pk + k * MLKEM_CIPHER_LEN, p, MLKEM_SEED_LEN);
ERR:
    return ret;
}

// For K-PKE.Encrypt: (Compress(mu), Compress(v))
int32_t MLKEM_PKEEnc(uint32_t k, MLKEM_MatrixSt *mat, uint8_t du, uint8_t dv, uint8_t *ct, int16_t *y[], int16_t *e1[],
                     int16_t *u[], int16_t *e2, int16_t *mu, int16_t *c2)
{
    (void)dv;
    (void)u;
    // PKE-Enc Using Transpose Matrix in Step 19: mu = INTT(AT * y) + e1,
    // and the default generated matrix is A.
    int16_t *transMatrix[MLKEM_K_MAX][MLKEM_K_MAX] = {0};
    for (uint32_t i = 0; i < k; i++) {
        for (uint32_t j = 0; j < k; j++) {
            transMatrix[j][i] = mat->matrix[i][j];
        }
    }
    int16_t s_asym[MLKEM_K_MAX][MLKEM_N >> 1];
    int16_t t[MLKEM_K_MAX][MLKEM_N];
    int16_t *at[MLKEM_K_MAX] = {t[0], t[1], t[2], t[3]};
    for (uint32_t i = 0; i < k; i++) {
        MLKEMPointMulExtended(&(s_asym[i][0]), &(y[i][0]), MLKEM_BASEMUL_TWIDDLE_TABLE);
    }
    for (uint32_t i = 0; i < k; i++) {
        MLKEMAsymMul(k, at[i], transMatrix[i], &(y[0][0]), &(s_asym[0][0]));
    }
    MLKEMAsymMul(k, c2, mat->vectorT, &(y[0][0]), &(s_asym[0][0]));

    MLKEMPolyINTTtoMont(k, at);
    MLKEM_ComputeINTTAsm(c2);
    MLKEMPolyAddReduce(k, at, e1);
    MLKEMAdd2Reduce(c2, e2, mu);
    PackCipherText(k, MLKEM_ENCODE_BLOCKSIZE * k * du, ct, at, c2);

    return CRYPT_SUCCESS;
}

// For K-PKE.Decrypt: Compress(v' - INTT(s*NTT(V)))
int32_t MLKEM_PKEDec(uint32_t k, MLKEM_MatrixSt *mat, int16_t *m, int16_t *c1[], int16_t *c2, uint8_t *result)
{
    int16_t b_asym[MLKEM_K_MAX][MLKEM_N >> 1];
    for (uint32_t i = 0; i < k; i++) {
        MLKEM_ComputeNTTAsm(c1[i]);
        MLKEMPointMulExtended(&(b_asym[i][0]), &(c1[i][0]), MLKEM_BASEMUL_TWIDDLE_TABLE);
    }
    MLKEMAsymMul(k, m, mat->vectorS, &(c1[0][0]), &(b_asym[0][0]));
    MLKEM_ComputeINTTAsm(m);
    MLKEMSubReduce(c2, m);
    MLKEMPolyCompress1(result, c2);

    return CRYPT_SUCCESS;
}

void MLKEM_SamplePolyCBD(int16_t *polyF, uint8_t *buf, uint8_t eta)
{
    MLKEMPolyCBDEta(eta, polyF, buf);
}

#endif