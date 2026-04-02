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
#include "securec.h"
#include "crypt_sha3.h"
#include "crypt_utils.h"
#include "bsl_err_internal.h"
#include "eal_md_local.h"
#include "ml_kem_local.h"

typedef void (*CompressFunc)(int16_t *x);

/*
 * zeta converted to Plantard domin
 * x = (zeta * (-2^(2l)) mod q) * (q^-1 mod 2^(2l))
 * quotient = round(x / 2^(2l))
 * x -= quotient * 2^(2l)
 */
const int32_t CONST_ZETA_POWER_1[MLKEM_N_HALF] = {
    1290168, -2064267850, -966335387, -51606696, -886345008, 812805467, -1847519726, 1094061961,
    1370157786, -1819136043, 249002310, 1028263423, -700560901, -89021551, 734105255, -2042335004,
    381889553, -1137927652, 1727534158, 1904287092, -365117376, 72249375, -1404992305, 1719793153,
    1839778722, -1593356746, 690239563, -576704830, -1207596692, -580575332, -1748176835, 1059227441,
    372858381, 427045412, -98052722, -2029433330, 1544330386, -1322421591, -1357256111, -1643673275,
    838608815, -1744306333, -1052776603, 815385801, -598637676, 42575525, 1703020977, -1824296712,
    -1303069080, 1851390229, 1041165097, 583155668, 1855260731, -594767174, 1979116802, -1195985185,
    -879894171, -918599193, 1910737929, 836028480, -1103093132, -282546662, 1583035408, 1174052340,
    21932846, -732815086, 752167598, -877313836, 2112004045, 932791035, -1343064270, 1419184148,
    1817845876, -860541660, -61928035, 300609006, 975366560, -1513366367, -405112565, -359956706,
    -2097812202, 2130066389, -696690399, -1986857805, -1912028096, 1228239371, 1884934581, -828287474,
    1211467195, -1317260921, -1150829326, -1214047529, 945692709, -1279846067, 345764865, 826997308,
    2043625172, -1330162596, -1666896289, -140628247, 483812778, -1006330577, -1598517416, 2122325384,
    1371447954, 411563403, -717333077, 976656727, -1586905909, 723783916, -1113414471, -948273043,
    -677337888, 1408862808, 519937465, 1323711759, 1474661346, -1521107372, -714752743, 1143088323,
    -2073299022, 1563682897, -1877193576, 1327582262, -1572714068, -508325958, 1141798155, -1515946702,
};

const int32_t CONST_ZETA_POWER_2[MLKEM_N_HALF] = {
    21932846, -21932845, -732815086, 732815087, 752167598, -752167597, -877313836, 877313837,
    2112004045, -2112004044, 932791035, -932791034, -1343064270, 1343064271, 1419184148, -1419184147,
    1817845876, -1817845875, -860541660, 860541661, -61928035, 61928036, 300609006, -300609005,
    975366560, -975366559, -1513366367, 1513366368, -405112565, 405112566, -359956706, 359956707,
    -2097812202, 2097812203, 2130066389, -2130066388, -696690399, 696690400, -1986857805, 1986857806,
    -1912028096, 1912028097, 1228239371, -1228239370, 1884934581, -1884934580, -828287474, 828287475,
    1211467195, -1211467194, -1317260921, 1317260922, -1150829326, 1150829327, -1214047529, 1214047530,
    945692709, -945692708, -1279846067, 1279846068, 345764865, -345764864, 826997308, -826997307,
    2043625172, -2043625171, -1330162596, 1330162597, -1666896289, 1666896290, -140628247, 140628248,
    483812778, -483812777, -1006330577, 1006330578, -1598517416, 1598517417, 2122325384, -2122325383,
    1371447954, -1371447953, 411563403, -411563402, -717333077, 717333078, 976656727, -976656726,
    -1586905909, 1586905910, 723783916, -723783915, -1113414471, 1113414472, -948273043, 948273044,
    -677337888, 677337889, 1408862808, -1408862807, 519937465, -519937464, 1323711759, -1323711758,
    1474661346, -1474661345, -1521107372, 1521107373, -714752743, 714752744, 1143088323, -1143088322,
    -2073299022, 2073299023, 1563682897, -1563682896, -1877193576, 1877193577, 1327582262, -1327582261,
    -1572714068, 1572714069, -508325958, 508325959, 1141798155, -1141798154, -1515946702, 1515946703,
};


// Compress
// The values of du and dv are from NIST.FIPS.203 Table 2.
static void DivMlKemQBit4(int16_t *x)
{
    for (int32_t i = 0; i < MLKEM_N; ++i) {
        uint64_t tmp = x[i] + ((x[i] >> 15) & MLKEM_Q);
        tmp = tmp * 41285360; // 2^4 * round(2^33 / q) = 41285360
        x[i] = (int16_t)(((tmp + (1ULL << 32)) >> 33) & 0xF);
    }
}

static void DivMlKemQBit5(int16_t *x)
{
    for (int32_t i = 0; i < MLKEM_N; ++i) {
        uint64_t tmp = x[i] + ((x[i] >> 15) & MLKEM_Q);
        tmp = tmp * 82570720; // 2^5 * round(2^33 / q) = 82570720
        x[i] = (int16_t)(((tmp + (1ULL << 32)) >> 33) & 0x1F);
    }
}

static void DivMlKemQBit10(int16_t *x)
{
    for (int32_t i = 0; i < MLKEM_N; ++i) {
        uint64_t tmp = x[i] + ((x[i] >> 15) & MLKEM_Q);
        tmp = tmp * 2642263040; // 2^10 * round(2^33 / q) = 2642263040
        x[i] = (int16_t)(((tmp + (1ULL << 32)) >> 33) & 0x3FF);
    }
}

static void DivMlKemQBit11(int16_t *x)
{
    for (int32_t i = 0; i < MLKEM_N; ++i) {
        uint64_t tmp = x[i] + ((x[i] >> 15) & MLKEM_Q);
        tmp = tmp * 5284526080; // 2^11 * round(2^33 / q) = 5284526080
        x[i] = (int16_t)(((tmp + (1ULL << 32)) >> 33) & 0x7FF);
    }
}

static void DivMlKemQBit1(int16_t *x)
{
    for (int32_t i = 0; i < MLKEM_N; ++i) {
        uint32_t tmp = x[i] + ((x[i] >> 15) & MLKEM_Q);
        tmp = tmp * 1290168; // 2^1 * round(2^31 / q) = 1290168
        x[i] = (int16_t)(((tmp + (1U << 30)) >> 31) & 0x1);
    }
}

static CompressFunc g_compressFuncsTable[] = {
    NULL, DivMlKemQBit1, NULL, NULL, DivMlKemQBit4, DivMlKemQBit5, NULL,
    NULL, NULL, NULL, DivMlKemQBit10, DivMlKemQBit11
};

static void PolyCompress(int16_t *x, uint8_t d)
{
    g_compressFuncsTable[d](x);
}

static void MlkemAddPoly(const int16_t *a, int16_t *b)
{
    for (int32_t i = 0; i < MLKEM_N; ++i) {
        b[i] += a[i];
    }
}

static void MlkemSubPoly(const int16_t *a, int16_t *b)
{
    for (int32_t i = 0; i < MLKEM_N; ++i) {
        b[i] = a[i] - b[i];
    }
}

// basecase multiplication: add to polyH but not override it
static void BaseMulAdd(int32_t polyH[2], const int16_t f0, const int16_t f1, const int16_t g0, const int16_t g1,
                       const int32_t factor)
{
    polyH[0] += f0 * g0 + f1 * PlantardReduction((uint32_t)g1 * (uint32_t)factor);
    polyH[1] += f0 * g1 + f1 * g0;
}

static void BaseMulAddCache(int32_t polyH[2], const int16_t f0, const int16_t f1, const int16_t g0, const int16_t g1,
                       const int16_t cache)
{
    polyH[0] += f0 * g0 + f1 * cache;
    polyH[1] += f0 * g1 + f1 * g0;
}

static void CircMulAdd(int32_t dest[MLKEM_N], const int16_t src1[MLKEM_N], const int16_t src2[MLKEM_N],
                       const int32_t *factor)
{
    for (uint32_t i = 0; i < MLKEM_N / 4; i++) {
        // 4-byte data is calculated in each round.
        BaseMulAdd(&dest[4 * i], src1[4 * i], src1[4 * i + 1], src2[4 * i], src2[4 * i + 1], factor[2 * i]);
        BaseMulAdd(&dest[4 * i + 2], src1[4 * i + 2], src1[4 * i + 3], src2[4 * i + 2], src2[4 * i + 3],
                   factor[2 * i + 1]);
    }
}

static void CircMulAddUseCache(int32_t dest[MLKEM_N], const int16_t src1[MLKEM_N], const int16_t src2[MLKEM_N],
                       const int16_t *mulCache)
{
    for (uint32_t i = 0; i < MLKEM_N / 4; i++) {
        // 4-byte data is calculated in each round.
        BaseMulAddCache(&dest[4 * i], src1[4 * i], src1[4 * i + 1], src2[4 * i], src2[4 * i + 1], mulCache[2 * i]);
        BaseMulAddCache(&dest[4 * i + 2], src1[4 * i + 2], src1[4 * i + 3], src2[4 * i + 2], src2[4 * i + 3],
                        mulCache[2 * i + 1]);
    }
}

static void PolyReduce(int16_t *poly, int32_t *src)
{
    for (int32_t i = 0; i < MLKEM_N; ++i) {
        poly[i] = BarrettReduction(src[i]);
    }
}

void MLKEM_ComputeMulCache(uint8_t k, int16_t **input, int16_t output[MLKEM_K_MAX][MLKEM_N_HALF], const int32_t *factor)
{
    for (int32_t i = 0; i < k; ++i) {
        for (int32_t j = 0; j < MLKEM_N_HALF; ++j) {
            output[i][j] = PlantardReduction((uint32_t)input[i][2 * j + 1] * (uint32_t)factor[j]);
        }
    }
}

// polyVecOut += (matrix * polyVec): add to polyVecOut but not override it
void MLKEM_MatrixMulAdd(uint8_t k, int16_t **matrix, int16_t **polyVec, int16_t **polyVecOut,
                        const int16_t mulCache[MLKEM_K_MAX][MLKEM_N_HALF])
{
    int16_t **currOutPoly = polyVecOut;
    int32_t tmps[MLKEM_N];
    for (int32_t i = 0; i < k; ++i) {
        int16_t **currMatrixPoly = matrix + i * MLKEM_K_MAX;
        int16_t **currVecPoly = polyVec;
        for (int32_t j= 0; j < MLKEM_N; ++j) {
            tmps[j] = (*currOutPoly)[j];
        }
        for (int32_t j = 0; j < k; ++j) {
            CircMulAddUseCache(tmps, *currMatrixPoly, *currVecPoly, mulCache[j]);
            ++currMatrixPoly;
            ++currVecPoly;
        }
        PolyReduce(*currOutPoly, tmps);
        ++currOutPoly;
    }
}

// polyVecOut += (matrix^T * polyVec): add to polyVecOut but not override it
void MLKEM_TransposeMatrixMulAdd(uint8_t k, int16_t **matrix, int16_t **polyVec, int16_t **polyVecOut,
                                 const int16_t mulCache[MLKEM_K_MAX][MLKEM_N_HALF])
{
    int16_t **currOutPoly = polyVecOut;
    for (int32_t i = 0; i < k; ++i) {
        int16_t **currMatrixPoly = matrix + i;
        int16_t **currVecPoly = polyVec;
        int32_t tmps[MLKEM_N] = {0};
        for (int32_t j = 0; j < k; ++j) {
            CircMulAddUseCache(tmps, *currMatrixPoly, *currVecPoly, mulCache[j]);
            currMatrixPoly += MLKEM_K_MAX;
            ++currVecPoly;
        }
        PolyReduce(*currOutPoly, tmps);
        ++currOutPoly;
    }
}

void MLKEM_VectorInnerProductAddUseCache(uint8_t k, int16_t **polyVec1, int16_t **polyVec2, int16_t *polyOut,
                                 const int16_t mulCache[MLKEM_K_MAX][MLKEM_N_HALF])
{
    int32_t tmps[MLKEM_N] = {0};
    for (int32_t i = 0; i < k; ++i) {
        CircMulAddUseCache(tmps, polyVec1[i], polyVec2[i], mulCache[i]);
    }
    PolyReduce(polyOut, tmps);
}

void MLKEM_VectorInnerProductAdd(uint8_t k, int16_t **polyVec1, int16_t **polyVec2, int16_t *polyOut,
                                 const int32_t *factor)
{
    int32_t tmps[MLKEM_N] = {0};
    for (int32_t i = 0; i < k; ++i) {
        CircMulAdd(tmps, polyVec1[i], polyVec2[i], factor);
    }
    PolyReduce(polyOut, tmps);
}


int32_t SampleEta1(const CRYPT_ML_KEM_Ctx *ctx, uint8_t *seed, int16_t *s[], int16_t *e[])
{
    uint8_t q[MLKEM_SEED_LEN + 1] = { 0 };  // Reserved lengths of nonce is 1 byte.
    uint8_t prfOut[MLKEM_PRF_BLOCKSIZE * MLKEM_ETA1_MAX] = { 0 };
    (void)memcpy_s(q, MLKEM_SEED_LEN, seed, MLKEM_SEED_LEN);
    uint8_t nonce = 0;
    for (uint8_t i = 0; i < ctx->info->k; i++) {
        q[MLKEM_SEED_LEN] = nonce++;
        CRYPT_SHAKE256(prfOut, MLKEM_PRF_BLOCKSIZE * MLKEM_ETA1_MAX, q, MLKEM_SEED_LEN + 1);
        MLKEM_SamplePolyCBD(s[i], prfOut, ctx->info->eta1);
        MLKEM_ComputNTT(s[i], CONST_ZETA_POWER_1);
    }
    for (uint8_t i = 0; i < ctx->info->k; i++) {
        q[MLKEM_SEED_LEN] = nonce++;
        CRYPT_SHAKE256(prfOut, MLKEM_PRF_BLOCKSIZE * MLKEM_ETA1_MAX, q, MLKEM_SEED_LEN + 1);
        MLKEM_SamplePolyCBD(e[i], prfOut, ctx->info->eta1);
        MLKEM_ComputNTT(e[i], CONST_ZETA_POWER_1);
    }
    return CRYPT_SUCCESS;
}

// Sample noise for encryption: s[] (ephemeral secret y) is sampled with eta1 and NTT-transformed,
// e[] (error vector) is sampled with eta2 and left in normal domain.
int32_t SampleEta2(const CRYPT_ML_KEM_Ctx *ctx, uint8_t *seed, int16_t *s[], int16_t *e[])
{
    uint8_t q[MLKEM_SEED_LEN + 1] = { 0 };  // Reserved lengths of nonce is 1 byte.
    uint8_t prfOut[MLKEM_PRF_BLOCKSIZE * MLKEM_ETA1_MAX] = { 0 };
    (void)memcpy_s(q, MLKEM_SEED_LEN, seed, MLKEM_SEED_LEN);
    uint8_t nonce = 0;
    for (uint8_t i = 0; i < ctx->info->k; i++) {
        q[MLKEM_SEED_LEN] = nonce++;
        CRYPT_SHAKE256(prfOut, MLKEM_PRF_BLOCKSIZE * MLKEM_ETA1_MAX, q, MLKEM_SEED_LEN + 1);
        MLKEM_SamplePolyCBD(s[i], prfOut, ctx->info->eta1);
        MLKEM_ComputNTT(s[i], CONST_ZETA_POWER_1);
    }
    for (uint8_t i = 0; i < ctx->info->k; i++) {
        q[MLKEM_SEED_LEN] = nonce++;
        CRYPT_SHAKE256(prfOut, MLKEM_PRF_BLOCKSIZE * MLKEM_ETA2_MAX, q, MLKEM_SEED_LEN + 1);
        MLKEM_SamplePolyCBD(e[i], prfOut, ctx->info->eta2);
    }
    seed[MLKEM_SEED_LEN] = nonce;
    return CRYPT_SUCCESS;
}

static int32_t Parse(uint16_t *polyNtt, uint8_t *arrayB, uint32_t *curLen)
{
    uint32_t i = 0;
    while (*curLen < MLKEM_N && i < CRYPT_SHAKE128_BLOCKSIZE) {
        // The 4 bits of each byte are combined with the 8 bits of another byte into 12 bits.
        uint16_t d1 = ((uint16_t)arrayB[i]) + (((uint16_t)arrayB[i + 1] & 0x0f) << 8);  // 4 bits.
        uint16_t d2 = (((uint16_t)arrayB[i + 1]) >> 4) + (((uint16_t)arrayB[i + 2]) << 4);

        int32_t mask = (MLKEM_Q - 1 - d1) >> 31;
        polyNtt[*curLen] = (int16_t)(d1 & ~mask);
        *curLen += 1 + mask;

        if (*curLen < MLKEM_N) {
            mask = (MLKEM_Q - 1 - d2) >> 31;
            polyNtt[*curLen] = (int16_t)(d2 & ~mask);
            *curLen += 1 + mask;
        }
        i += 3;  // 3 bytes are processed in each round.
    }
    return CRYPT_SUCCESS;
}

int32_t GenMatrix(const CRYPT_ML_KEM_Ctx *ctx, const uint8_t *seed,
    int16_t *polyMatrix[MLKEM_K_MAX][MLKEM_K_MAX], bool isEnc)
{
    uint8_t k = ctx->info->k;
    uint8_t p[MLKEM_SEED_LEN + 2];  // Reserved lengths of i and j is 2 byte.
    uint8_t xofOut[CRYPT_SHAKE128_BLOCKSIZE];

    EAL_MdMethod method = {0, 0, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};
    void *provCtx = NULL;
    if (EAL_MdFindMethodEx(CRYPT_MD_SHAKE128, ctx->libCtx, NULL, &method, &provCtx, ctx->libCtx != NULL) == NULL) {
        return CRYPT_EAL_ERR_ALGID;
    }

    void *hashCtx = method.newCtx(provCtx, CRYPT_MD_SHAKE128);
    if (hashCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    (void)memcpy_s(p, MLKEM_SEED_LEN, seed, MLKEM_SEED_LEN);
    int32_t ret = CRYPT_SUCCESS;
    uint32_t curLen;
    for (uint8_t i = 0; i < k; i++) {
        for (uint8_t j = 0; j < k; j++) {
            if (isEnc) {
                p[MLKEM_SEED_LEN] = i;
                p[MLKEM_SEED_LEN + 1] = j;
            } else {
                p[MLKEM_SEED_LEN] = j;
                p[MLKEM_SEED_LEN + 1] = i;
            }
            curLen = 0;
            GOTO_ERR_IF(method.init(hashCtx, NULL), ret);
            GOTO_ERR_IF(method.update(hashCtx, p, MLKEM_SEED_LEN + 2), ret);
            while (curLen < MLKEM_N) {
                GOTO_ERR_IF(method.squeeze(hashCtx, xofOut, CRYPT_SHAKE128_BLOCKSIZE), ret);
                GOTO_ERR_IF(Parse((uint16_t *)polyMatrix[i][j], xofOut, &curLen), ret);
            }
        }
    }
ERR:
    method.freeCtx(hashCtx);
    return ret;
}

int32_t MLKEM_PKEGen(CRYPT_ML_KEM_Ctx *ctx, uint8_t *digest, uint8_t *pk, uint8_t *dk)
{
    int32_t ret = CRYPT_SUCCESS;
    uint8_t k = ctx->info->k;
    // expand 32+1 bytes to two pseudorandom 32-byte seeds
    uint8_t *p = digest;
    uint8_t *q = digest + CRYPT_SHA3_512_DIGESTSIZE / 2;
    GOTO_ERR_IF(GenMatrix(ctx, p, ctx->keyData.matrix, false), ret);  // Step 3 - 7
    GOTO_ERR_IF(SampleEta1(ctx, q, ctx->keyData.vectorS, ctx->keyData.vectorT), ret);  // Step 8 - 15
    for (int32_t i = 0; i < k; ++i) {
        for (int32_t j = 0; j < MLKEM_N; ++j) {
            ctx->keyData.vectorS[i][j] = BarrettReduction(ctx->keyData.vectorS[i][j]);
        }
    }
    int16_t mulCache[MLKEM_K_MAX][MLKEM_N_HALF];
    MLKEM_ComputeMulCache(k, ctx->keyData.vectorS, mulCache, CONST_ZETA_POWER_2);
    MLKEM_MatrixMulAdd(k, (int16_t **)ctx->keyData.matrix, ctx->keyData.vectorS, ctx->keyData.vectorT, mulCache);
    // output: pk, dk,  ekPKE ← ByteEncode12(𝐭)‖p.
    for (uint8_t i = 0; i < k; i++) {
        // Step 19
        ByteEncode(pk + MLKEM_SEED_LEN * MLKEM_BITS_OF_Q * i, ctx->keyData.vectorT[i], MLKEM_BITS_OF_Q);
        // Step 20
        ByteEncode(dk + MLKEM_SEED_LEN * MLKEM_BITS_OF_Q * i, ctx->keyData.vectorS[i], MLKEM_BITS_OF_Q);
    }
    // The buffer of pk is sufficient, check it before calling this function.
    (void)memcpy_s(pk + MLKEM_SEED_LEN * MLKEM_BITS_OF_Q * k, MLKEM_SEED_LEN, p, MLKEM_SEED_LEN);
ERR:
    return ret;
}

// For K-PKE.Encrypt: (Compress(mu), Compress(v))
int32_t MLKEM_PKEEnc(uint32_t k, MLKEM_MatrixSt *mat, uint8_t du, uint8_t dv, uint8_t *ct,
    int16_t *y[], int16_t *e1[], int16_t *u[],
    int16_t *e2, int16_t *mu, int16_t *c2)
{
    // Step 18
    int16_t mulCache[MLKEM_K_MAX][MLKEM_N_HALF];
    MLKEM_ComputeMulCache(k, y, mulCache, CONST_ZETA_POWER_2);
    MLKEM_TransposeMatrixMulAdd(k, (int16_t **)mat->matrix, y, u, mulCache);
    // Step 19
    for (uint32_t i = 0; i < k; i++) {
        MLKEM_ComputINTT(u[i], CONST_ZETA_POWER_1);
        MlkemAddPoly(e1[i], u[i]);
        PolyCompress(u[i], du);
    }
    // Step 21
    MLKEM_VectorInnerProductAdd(k, mat->vectorT, y, c2, CONST_ZETA_POWER_2);
    MLKEM_ComputINTT(c2, CONST_ZETA_POWER_1);
    MlkemAddPoly(e2, c2);
    MlkemAddPoly(mu, c2);
    PolyCompress(c2, dv);

    // Step 22
    for (uint32_t i = 0; i < k; i++) {
        ByteEncode(ct + MLKEM_ENCODE_BLOCKSIZE * du * i, u[i], du);
    }
    // Step 23
    ByteEncode(ct + MLKEM_ENCODE_BLOCKSIZE * du * k, c2, dv);
    return CRYPT_SUCCESS;
}

// For K-PKE.Decrypt: Compress(v' - INTT(s*NTT(V)))
int32_t MLKEM_PKEDec(uint32_t k, MLKEM_MatrixSt *mat, int16_t *m, int16_t *c1[], int16_t *c2, uint8_t *result)
{
    for (uint32_t i = 0; i < k; i++) {
        MLKEM_ComputNTT(c1[i], CONST_ZETA_POWER_1);
    }
    MLKEM_VectorInnerProductAdd(k, mat->vectorS, c1, m, CONST_ZETA_POWER_2);
    MLKEM_ComputINTT(m, CONST_ZETA_POWER_1);
    // c2 - m
    MlkemSubPoly(c2, m);
    PolyCompress(m, 1);

    ByteEncode(result, m, 1);  // Step 7
    return CRYPT_SUCCESS;
}

void MLKEM_SamplePolyCBD(int16_t *polyF, uint8_t *buf, uint8_t eta)
{
    uint32_t i;
    uint32_t j;
    uint8_t a;
    uint8_t b;
    uint32_t t1;
    if (eta == 3) {  // The value of eta can only be 2 or 3.
        for (i = 0; i < MLKEM_N / 4; i++) {
            uint32_t temp = (uint32_t)buf[eta * i];
            temp |= (uint32_t)buf[eta * i + 1] << 8;
            temp |= (uint32_t)buf[eta * i + 2] << 16;
            t1 = temp & 0x00249249;  // temp & 0x00249249 is used to obtain a specific bit in temp.
            t1 += (temp >> 1) & 0x00249249;
            t1 += (temp >> 2) & 0x00249249;

            for (j = 0; j < 4; j++) {
                a = (t1 >> (6 * j)) & 0x3;
                b = (t1 >> (6 * j + eta)) & 0x3;
                polyF[4 * i + j] = a - b;
            }
        }
    } else if (eta == 2) {
        for (i = 0; i < MLKEM_N / 4; i++) {
            uint16_t temp = (uint16_t)buf[eta * i];
            temp |= (uint16_t)buf[eta * i + 1] << 0x8;
            t1 = temp & 0x5555;  // temp & 0x5555 is used to obtain a specific bit in temp.
            t1 += (temp >> 1) & 0x5555;

            for (j = 0; j < 4; j++) {
                a = (t1 >> (4 * j)) & 0x3;
                b = (t1 >> (4 * j + eta)) & 0x3;
                polyF[4 * i + j] = a - b;
            }
        }
    }
}
#endif