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
#ifdef HITLS_CRYPTO_SCRYPT

#include <stdint.h>
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_local_types.h"
#include "crypt_errno.h"
#include "crypt_util_ctrl.h"
#include "crypt_utils.h"
#include "crypt_types.h"
#include "crypt_scrypt.h"
#include "eal_mac_local.h"
#include "eal_md_local.h"
#include "pbkdf2_local.h"
#include "bsl_params.h"
#include "crypt_params_key.h"

#define SCRYPT_PR_MAX   ((1 << 30) - 1)

// Convert the little-endian array to the host order.
#define SALSA_INPUT_TO_HOST(T, x) \
do { \
    (x)[0] = CRYPT_LE32TOH((T)[0]);    \
    (x)[1] = CRYPT_LE32TOH((T)[1]);    \
    (x)[2] = CRYPT_LE32TOH((T)[2]);    \
    (x)[3] = CRYPT_LE32TOH((T)[3]);    \
    (x)[4] = CRYPT_LE32TOH((T)[4]);    \
    (x)[5] = CRYPT_LE32TOH((T)[5]);    \
    (x)[6] = CRYPT_LE32TOH((T)[6]);    \
    (x)[7] = CRYPT_LE32TOH((T)[7]);    \
    (x)[8] = CRYPT_LE32TOH((T)[8]);    \
    (x)[9] = CRYPT_LE32TOH((T)[9]);    \
    (x)[10] = CRYPT_LE32TOH((T)[10]);    \
    (x)[11] = CRYPT_LE32TOH((T)[11]);    \
    (x)[12] = CRYPT_LE32TOH((T)[12]);    \
    (x)[13] = CRYPT_LE32TOH((T)[13]);    \
    (x)[14] = CRYPT_LE32TOH((T)[14]);    \
    (x)[15] = CRYPT_LE32TOH((T)[15]);    \
} while (0)

// Convert the host order to little endian order.
#define SALSA_OUTPUT_TO_LE32(T, x) \
do { \
    (T)[0] = CRYPT_HTOLE32((x)[0] + CRYPT_LE32TOH((T)[0]));    \
    (T)[1] = CRYPT_HTOLE32((x)[1] + CRYPT_LE32TOH((T)[1]));    \
    (T)[2] = CRYPT_HTOLE32((x)[2] + CRYPT_LE32TOH((T)[2]));    \
    (T)[3] = CRYPT_HTOLE32((x)[3] + CRYPT_LE32TOH((T)[3]));    \
    (T)[4] = CRYPT_HTOLE32((x)[4] + CRYPT_LE32TOH((T)[4]));    \
    (T)[5] = CRYPT_HTOLE32((x)[5] + CRYPT_LE32TOH((T)[5]));    \
    (T)[6] = CRYPT_HTOLE32((x)[6] + CRYPT_LE32TOH((T)[6]));    \
    (T)[7] = CRYPT_HTOLE32((x)[7] + CRYPT_LE32TOH((T)[7]));    \
    (T)[8] = CRYPT_HTOLE32((x)[8] + CRYPT_LE32TOH((T)[8]));    \
    (T)[9] = CRYPT_HTOLE32((x)[9] + CRYPT_LE32TOH((T)[9]));    \
    (T)[10] = CRYPT_HTOLE32((x)[10] + CRYPT_LE32TOH((T)[10]));   \
    (T)[11] = CRYPT_HTOLE32((x)[11] + CRYPT_LE32TOH((T)[11]));   \
    (T)[12] = CRYPT_HTOLE32((x)[12] + CRYPT_LE32TOH((T)[12]));   \
    (T)[13] = CRYPT_HTOLE32((x)[13] + CRYPT_LE32TOH((T)[13]));   \
    (T)[14] = CRYPT_HTOLE32((x)[14] + CRYPT_LE32TOH((T)[14]));   \
    (T)[15] = CRYPT_HTOLE32((x)[15] + CRYPT_LE32TOH((T)[15]));   \
} while (0)

#define SCRYPT_ELEMENTSIZE 64

struct CryptScryptCtx {
    const EAL_MacMethod *macMeth;
    const EAL_MdMethod *mdMeth;
    PBKDF2_PRF pbkdf2Prf;
    uint8_t *password;
    uint32_t passLen;
    uint8_t *salt;
    uint32_t saltLen;
    uint32_t n;
    uint32_t r;
    uint32_t p;
    void *libCtx; // For provider usage, can be NULL if not used.
};

/* This function is implemented by referring to the RFC standard.
   For details, see section 3 in https://www.rfc-editor.org/rfc/rfc7914.txt */
static void SCRYPT_Salsa20WordSpecification(uint32_t t[16])
{
    uint32_t x[16];

    SALSA_INPUT_TO_HOST(t, x);

    // Starting from 8, the index is decreased by 2 for each calculation, which is equivalent to 4 calculations.
    for (int i = 8; i > 0; i -= 2) {
        x[4] ^= ROTL32(x[0] + x[12], 7);
        x[8] ^= ROTL32(x[4] + x[0], 9);
        x[12] ^= ROTL32(x[8] + x[4], 13);
        x[0] ^= ROTL32(x[12] + x[8], 18);
        x[9] ^= ROTL32(x[5] + x[1], 7);
        x[13] ^= ROTL32(x[9] + x[5], 9);
        x[1] ^= ROTL32(x[13] + x[9], 13);
        x[5] ^= ROTL32(x[1] + x[13], 18);
        x[14] ^= ROTL32(x[10] + x[6], 7);
        x[2] ^= ROTL32(x[14] + x[10], 9);
        x[6] ^= ROTL32(x[2] + x[14], 13);
        x[10] ^= ROTL32(x[6] + x[2], 18);
        x[3] ^= ROTL32(x[15] + x[11], 7);
        x[7] ^= ROTL32(x[3] + x[15], 9);
        x[11] ^= ROTL32(x[7] + x[3], 13);
        x[15] ^= ROTL32(x[11] + x[7], 18);
        x[1] ^= ROTL32(x[0] + x[3], 7);
        x[2] ^= ROTL32(x[1] + x[0], 9);
        x[3] ^= ROTL32(x[2] + x[1], 13);
        x[0] ^= ROTL32(x[3] + x[2], 18);
        x[6] ^= ROTL32(x[5] + x[4], 7);
        x[7] ^= ROTL32(x[6] + x[5], 9);
        x[4] ^= ROTL32(x[7] + x[6], 13);
        x[5] ^= ROTL32(x[4] + x[7], 18);
        x[11] ^= ROTL32(x[10] + x[9], 7);
        x[8] ^= ROTL32(x[11] + x[10], 9);
        x[9] ^= ROTL32(x[8] + x[11], 13);
        x[10] ^= ROTL32(x[9] + x[8], 18);
        x[12] ^= ROTL32(x[15] + x[14], 7);
        x[13] ^= ROTL32(x[12] + x[15], 9);
        x[14] ^= ROTL32(x[13] + x[12], 13);
        x[15] ^= ROTL32(x[14] + x[13], 18);
    }
    SALSA_OUTPUT_TO_LE32(t, x);
}

static void SCRYPT_BlockMix(uint8_t *b, uint8_t *y, uint32_t r)
{
    uint8_t *bTmp = b;
    uint8_t *y0 = y;
    uint8_t *y1 = y + (r << 6);

    /* RFC7914 section 4
    In this implementation, the output Y is split and processed separately based on the description in section 4.
    The performance is slightly improved.
    1. B' = Y, Y0 = Y, Y1 = Y[r], b=B,
       The block size of each Y is 64 bytes. The processing unit in this function is 64 bytes.
    2. Y0 = B[2 * r - 1] ^ B[0]
       Salsa(Y0)
       Y1 = Y0 ^ B[1]
       Salsa(Y1)
    3. for i = 1 to r -1 do
        b += 2      // Two blocks have been processed in step 2.
        Y0 += 1     // Process the next block of Y0.
        Y0 = b[0] ^ Y1
        Salsa(Y0)
        Y1 += 1
        Y1 = b[1] ^ Y0
        Salsa(Y1)
    4. B = Y  // Copy Y to B.
    */

    // r << 7 is equal to r * 128, where r * 128 is the block size of the algorithm.
    DATA32_XOR(b + (r << 7) - SCRYPT_ELEMENTSIZE, bTmp, y0, SCRYPT_ELEMENTSIZE);
    SCRYPT_Salsa20WordSpecification((uint32_t*)(uintptr_t)y0);
    DATA32_XOR(y0, bTmp + SCRYPT_ELEMENTSIZE, y1, SCRYPT_ELEMENTSIZE);
    SCRYPT_Salsa20WordSpecification((uint32_t*)(uintptr_t)y1);

    for (uint32_t i = 1; i < r; i++) {
        bTmp += 128; // Process two pieces of 64-bit(SCRYPT_ELEMENTSIZE) data in one cycle. 64 * 2 = 128

        y0 += SCRYPT_ELEMENTSIZE;
        DATA32_XOR(y1, bTmp, y0, SCRYPT_ELEMENTSIZE);
        SCRYPT_Salsa20WordSpecification((uint32_t*)(uintptr_t)y0);

        y1 += SCRYPT_ELEMENTSIZE;
        DATA32_XOR(y0, bTmp + SCRYPT_ELEMENTSIZE, y1, SCRYPT_ELEMENTSIZE);
        SCRYPT_Salsa20WordSpecification((uint32_t*)(uintptr_t)y1);
    }

    (void)memcpy_s(b, r << 7, y, r << 7); // Length bit r of B and y: r << 7
}

/* For details about this function, see section 5 in RFC7914 */
static void SCRYPT_ROMix(uint8_t *b, uint32_t n, uint32_t r, uint8_t *v, uint8_t *y)
{
    uint32_t i;
    uint8_t *tmp = NULL;
    uint32_t blockSize = r << 7;

    for (i = 0, tmp = v; i < n; i++, tmp += blockSize) {
        (void)memcpy_s(tmp, blockSize, b, blockSize);
        SCRYPT_BlockMix(b, y, r);
    }

    for (i = 0; i < n; i++) {
        uint32_t j = GET_UINT32_LE(b, blockSize - 64) & (n - 1);

        // X= B, X = X ^ Vj
        DATA32_XOR(b, &v[j * blockSize], b, blockSize);
        SCRYPT_BlockMix(b, y, r);
    }
}

static int32_t SCRYPT_CheckParam(uint32_t n, uint32_t r, uint32_t p, const uint8_t *out, uint32_t len)
{
    if (r == 0 || p == 0 || n <= 1 || ((n & (n - 1)) != 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_SCRYPT_PARAM_ERROR);
        return CRYPT_SCRYPT_PARAM_ERROR;
    }
    if (p > SCRYPT_PR_MAX / r) {
        BSL_ERR_PUSH_ERROR(CRYPT_SCRYPT_PARAM_ERROR);
        return CRYPT_SCRYPT_PARAM_ERROR;
    }
    /* r <= 3 indicates 16 * r < (sizeof(uint64_t) * 8 - 1) */
    if ((r <= 3) && (n >= (((uint64_t)1) << (16 * r)))) {
        BSL_ERR_PUSH_ERROR(CRYPT_SCRYPT_PARAM_ERROR);
        return CRYPT_SCRYPT_PARAM_ERROR;
    }
    /* (p * 128 * r < UINT32_MAX) && (32 * r * n * sizeof(uint32_t)) */
    if ((r > ((UINT32_MAX / 128) / p)) || (n > ((UINT32_MAX / 128) / r))) {
        BSL_ERR_PUSH_ERROR(CRYPT_SCRYPT_PARAM_ERROR);
        return CRYPT_SCRYPT_PARAM_ERROR;
    }
    /* malloc size:p * 128 * r + n * 128 * r + 128 *r */
    if ((uint64_t)p * 128 * r + n * 128 * r + 128 * r > UINT32_MAX) {
        BSL_ERR_PUSH_ERROR(CRYPT_SCRYPT_PARAM_ERROR);
        return CRYPT_SCRYPT_PARAM_ERROR;
    }

    if (out == NULL || len == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_SCRYPT_PARAM_ERROR);
        return CRYPT_SCRYPT_PARAM_ERROR;
    }

    return CRYPT_SUCCESS;
}

static int32_t SCRYPT_CheckPointer(PBKDF2_PRF pbkdf2Prf, const uint8_t *key, uint32_t keyLen,
    const uint8_t *salt, uint32_t saltLen)
{
    if (pbkdf2Prf == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (key == NULL && keyLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (salt == NULL && saltLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return CRYPT_SUCCESS;
}

/* For details about this function, see section 6 in RFC7914. */
int32_t CRYPT_SCRYPT(PBKDF2_PRF pbkdf2Prf, const EAL_MacMethod *macMeth, CRYPT_MAC_AlgId macId,
    const EAL_MdMethod *mdMeth, const uint8_t *key, uint32_t keyLen, const uint8_t *salt,
    uint32_t saltLen, uint32_t n, uint32_t r, uint32_t p, uint8_t *out, uint32_t len)
{
    int32_t ret;
    // V in ROMix and BlockMix is allocated here, reducing memory application and release costs
    uint8_t *b = NULL, *v = NULL, *bi = NULL, *y = NULL;
    uint32_t bLen, blockSize, sumLen;

    if ((ret = SCRYPT_CheckParam(n, r, p, out, len)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if ((ret = SCRYPT_CheckPointer(pbkdf2Prf, key, keyLen, salt, saltLen)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    blockSize = r << 7; // block length: r << 7 (r * 128)
    bLen = blockSize * p;

    sumLen = bLen + blockSize * n + blockSize;
    b = BSL_SAL_Malloc(sumLen);
    if (b == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    v = b + bLen;
    y = v + blockSize * n;

    GOTO_ERR_IF(pbkdf2Prf(NULL, macMeth, macId, mdMeth, key, keyLen, salt, saltLen, 1, b, bLen), ret);

    bi = b;
    for (uint32_t i = 0; i < p; i++, bi += blockSize) {
        SCRYPT_ROMix(bi, n, r, v, y);
    }

    GOTO_ERR_IF(pbkdf2Prf(NULL, macMeth, macId, mdMeth, key, keyLen, b, bLen, 1, out, len), ret);

ERR:
    BSL_SAL_FREE(b);

    return ret;
}

int32_t CRYPT_SCRYPT_SetMacMethod(CRYPT_SCRYPT_Ctx *ctx)
{
    ctx->macMeth = EAL_MacFindDefaultMethod(CRYPT_MAC_HMAC_SHA256);
    if (ctx->macMeth == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_METH_NULL_MEMBER);
        return CRYPT_EAL_ERR_METH_NULL_MEMBER;
    }
    ctx->mdMeth = EAL_MdFindDefaultMethod(CRYPT_MD_SHA256);
    if (ctx->mdMeth == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_METH_NULL_MEMBER);
        return CRYPT_EAL_ERR_METH_NULL_MEMBER;
    }

    return CRYPT_SUCCESS;
}

int32_t CRYPT_SCRYPT_InitCtx(CRYPT_SCRYPT_Ctx *ctx)
{
    int32_t ret = CRYPT_SCRYPT_SetMacMethod(ctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ctx->pbkdf2Prf = CRYPT_PBKDF2_HMAC;
    return CRYPT_SUCCESS;
}

CRYPT_SCRYPT_Ctx *CRYPT_SCRYPT_NewCtx(void)
{
    CRYPT_SCRYPT_Ctx *ctx = BSL_SAL_Calloc(1, sizeof(CRYPT_SCRYPT_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    int32_t ret = CRYPT_SCRYPT_InitCtx(ctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_FREE(ctx);
        return NULL;
    }
    return ctx;
}

CRYPT_SCRYPT_Ctx *CRYPT_SCRYPT_NewCtxEx(void *libCtx, int32_t algId)
{
    (void)algId;
    CRYPT_SCRYPT_Ctx *ctx = CRYPT_SCRYPT_NewCtx();
    if (ctx == NULL) {
        return NULL;
    }
    ctx->libCtx = libCtx;
    return ctx;
}

int32_t CRYPT_SCRYPT_SetN(CRYPT_SCRYPT_Ctx *ctx, const uint32_t n)
{
    if (n <= 1 || (n & (n - 1)) != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_SCRYPT_PARAM_ERROR);
        return CRYPT_SCRYPT_PARAM_ERROR;
    }
    ctx->n = n;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SCRYPT_SetR(CRYPT_SCRYPT_Ctx *ctx, const uint32_t r)
{
    if (r == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_SCRYPT_PARAM_ERROR);
        return CRYPT_SCRYPT_PARAM_ERROR;
    }
    ctx->r = r;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SCRYPT_SetP(CRYPT_SCRYPT_Ctx *ctx, const uint32_t p)
{
    if (p == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_SCRYPT_PARAM_ERROR);
        return CRYPT_SCRYPT_PARAM_ERROR;
    }
    ctx->p = p;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SCRYPT_SetParam(CRYPT_SCRYPT_Ctx *ctx, const BSL_Param *param)
{
    uint32_t val = 0;
    uint32_t len = 0;
    const BSL_Param *temp = NULL;
    int32_t ret = CRYPT_SCRYPT_PARAM_ERROR;
    if (ctx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_KDF_PASSWORD)) != NULL) {
        GOTO_ERR_IF(CRYPT_CTRL_SetData(temp->value, temp->valueLen, &ctx->password, &ctx->passLen), ret);
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_KDF_SALT)) != NULL) {
        GOTO_ERR_IF(CRYPT_CTRL_SetData(temp->value, temp->valueLen, &ctx->salt, &ctx->saltLen), ret);
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_KDF_N)) != NULL) {
        len = sizeof(val);
        GOTO_ERR_IF(BSL_PARAM_GetValue(temp, CRYPT_PARAM_KDF_N,
            BSL_PARAM_TYPE_UINT32, &val, &len), ret);
        GOTO_ERR_IF(CRYPT_SCRYPT_SetN(ctx, val), ret);
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_KDF_R)) != NULL) {
        len = sizeof(val);
        GOTO_ERR_IF(BSL_PARAM_GetValue(temp, CRYPT_PARAM_KDF_R,
            BSL_PARAM_TYPE_UINT32, &val, &len), ret);
        GOTO_ERR_IF(CRYPT_SCRYPT_SetR(ctx, val), ret);
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_KDF_P)) != NULL) {
        len = sizeof(val);
        GOTO_ERR_IF(BSL_PARAM_GetValue(temp, CRYPT_PARAM_KDF_P,
            BSL_PARAM_TYPE_UINT32, &val, &len), ret);
        GOTO_ERR_IF(CRYPT_SCRYPT_SetP(ctx, val), ret);
    }
ERR:
    return ret;
}

int32_t CRYPT_SCRYPT_Derive(CRYPT_SCRYPT_Ctx *ctx, uint8_t *out, uint32_t len)
{
    int32_t ret;

    uint8_t *b = NULL, *v = NULL, *bi = NULL, *y = NULL;
    uint32_t bLen, blockSize, sumLen;

    const EAL_MacMethod *macMeth = ctx->macMeth;
    const EAL_MdMethod *mdMeth = ctx->mdMeth;
    PBKDF2_PRF pbkdf2Prf = ctx->pbkdf2Prf;
    const uint8_t *password = ctx->password;
    uint32_t passLen = ctx->passLen;
    const uint8_t *salt = ctx->salt;
    uint32_t saltLen = ctx->saltLen;
    uint32_t n = ctx->n;
    uint32_t r = ctx->r;
    uint32_t p = ctx->p;

    if ((ret = SCRYPT_CheckParam(n, r, p, out, len)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if ((ret = SCRYPT_CheckPointer(pbkdf2Prf, password, passLen, salt, saltLen)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    blockSize = r << 7;
    bLen = blockSize * p;

    sumLen = bLen + blockSize * n + blockSize;
    if (sumLen < bLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_SCRYPT_DATA_TOO_MAX);
        return CRYPT_SCRYPT_DATA_TOO_MAX;
    }
    b = BSL_SAL_Malloc(sumLen);
    if (b == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    v = b + bLen;
    y = v + blockSize * ctx->n;

    GOTO_ERR_IF(pbkdf2Prf(ctx->libCtx, macMeth, CRYPT_MAC_HMAC_SHA256, mdMeth, password, passLen, salt, saltLen, 1,
        b, bLen), ret);

    bi = b;
    for (uint32_t i = 0; i < p; i++, bi += blockSize) {
        SCRYPT_ROMix(bi, n, r, v, y);
    }

    GOTO_ERR_IF(pbkdf2Prf(ctx->libCtx, macMeth, CRYPT_MAC_HMAC_SHA256, mdMeth, password, passLen, b, bLen, 1,
        out, len), ret);

ERR:
    BSL_SAL_FREE(b);

    return ret;
}

int32_t CRYPT_SCRYPT_Deinit(CRYPT_SCRYPT_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    BSL_SAL_ClearFree(ctx->password, ctx->passLen);
    BSL_SAL_FREE(ctx->salt);
    (void)memset_s(ctx, sizeof(CRYPT_SCRYPT_Ctx), 0, sizeof(CRYPT_SCRYPT_Ctx));

    int32_t ret = CRYPT_SCRYPT_InitCtx(ctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

void CRYPT_SCRYPT_FreeCtx(CRYPT_SCRYPT_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    BSL_SAL_ClearFree(ctx->password, ctx->passLen);
    BSL_SAL_FREE(ctx->salt);
    BSL_SAL_Free(ctx);
}

CRYPT_SCRYPT_Ctx *CRYPT_SCRYPT_DupCtx(const CRYPT_SCRYPT_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }
    uint8_t *password = NULL;
    uint8_t *salt = NULL;
    CRYPT_SCRYPT_Ctx *newCtx = BSL_SAL_Dump(ctx, sizeof(CRYPT_SCRYPT_Ctx));
    if (newCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    if (ctx->password != NULL) {
        password = BSL_SAL_Dump(ctx->password, ctx->passLen);
        GOTO_ERR_IF_TRUE((password == NULL), CRYPT_MEM_ALLOC_FAIL);
    }
    if (ctx->salt != NULL) {
        salt = BSL_SAL_Dump(ctx->salt, ctx->saltLen);
        GOTO_ERR_IF_TRUE((salt == NULL), CRYPT_MEM_ALLOC_FAIL);
    }

    newCtx->password = password;
    newCtx->salt = salt;
    return newCtx;
ERR:
    BSL_SAL_ClearFree(password, ctx->passLen);
    BSL_SAL_Free(salt);
    BSL_SAL_Free(newCtx);
    return NULL;
}


#endif /* HITLS_CRYPTO_SCRYPT */
