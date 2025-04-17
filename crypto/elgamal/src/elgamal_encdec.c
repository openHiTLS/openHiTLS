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
#ifdef HITLS_CRYPTO_ELGAMAL

#include "crypt_utils.h"
#include "crypt_elgamal.h"
#include "elgamal_local.h"
#include "crypt_errno.h"
#include "bsl_sal.h"
#include "securec.h"
#include "bsl_err_internal.h"

static int32_t AddZero(uint32_t bits, uint8_t *out, uint32_t *outLen)
{
    int32_t ret;
    uint32_t i;
    uint32_t zeros = 0;
    /* Divide bits by 8 to obtain the byte length. If it is smaller than the key length, pad it with 0. */
    if ((*outLen) < BN_BITS_TO_BYTES(bits)) {
        /* Divide bits by 8 to obtain the byte length. If it is smaller than the key length, pad it with 0. */
        zeros = BN_BITS_TO_BYTES(bits) - (*outLen);
        ret = memmove_s(out + zeros, BN_BITS_TO_BYTES(bits) - zeros, out, (*outLen));
        if (ret != EOK) {
            BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
            return CRYPT_SECUREC_FAIL;
        }
        for (i = 0; i < zeros; i++) {
            out[i] = 0x0;
        }
    }
    *outLen = BN_BITS_TO_BYTES(bits);
    return CRYPT_SUCCESS;
}

static int32_t ResultToOut(uint32_t bits, const BN_BigNum *result, uint8_t *out, uint32_t *outLen)
{
    int32_t ret = BN_Bn2Bin(result, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return AddZero(bits, out, outLen);
}

int32_t CRYPT_ELGAMAL_PubEnc(const CRYPT_ELGAMAL_Ctx *ctx, const uint8_t *input, uint32_t inputLen, uint8_t *out1,
                             uint32_t *out1Len, uint8_t *out2, uint32_t *out2Len)
{
    int32_t ret;
    CRYPT_ELGAMAL_PubKey *pubKey = ctx->pubKey;
    if (pubKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    BN_Mont *mont = NULL;
    mont = BN_MontCreate(pubKey->p);

    uint32_t bits = CRYPT_ELGAMAL_GetBits(ctx);
    uint32_t k_bits = CRYPT_ELGAMAL_GetKBits(ctx);
    BN_Optimizer *optimizer = BN_OptimizerCreate();
    if (optimizer == NULL || mont == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        BN_MontDestroy(mont);
        BN_OptimizerDestroy(optimizer);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    BN_BigNum *m = BN_Create(bits);
    BN_BigNum *r = BN_Create(k_bits);
    BN_BigNum *yr = BN_Create(bits);
    BN_BigNum *c1 = BN_Create(bits);
    BN_BigNum *c2 = BN_Create(bits);
    BN_BigNum *gcd_result = BN_Create(bits);
    BN_BigNum *top = BN_Create(k_bits);

    bool createFailed =
        (m == NULL || r == NULL || yr == NULL || c1 == NULL || c2 == NULL || gcd_result == NULL || top == NULL);
    if (createFailed) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto EXIT;
    }

    ret = BN_Bin2Bn(m, input, inputLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    if (BN_IsNegative(m)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ELGAMAL_ERR_INPUT_VALUE);
        ret = CRYPT_ELGAMAL_ERR_INPUT_VALUE;
        goto EXIT;
    }

    ret = BN_SubLimb(top, pubKey->q, 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    while (true) {
        ret = BN_RandRangeEx(ctx->libCtx, r, top);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }
        // Check whether r is relatively prime to p-1, if not, regenerate r
        ret = BN_Gcd(gcd_result, r, top, optimizer);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }
        if (BN_IsOne(gcd_result)) {
            break;
        }
    }

    ret = BN_MontExp(c1, pubKey->g, r, mont, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ret = BN_MontExp(yr, pubKey->y, r, mont, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ret = BN_ModMul(c2, m, yr, pubKey->p, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ret = BN_Bn2Bin(c1, out1, out1Len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ret = BN_Bn2Bin(c2, out2, out2Len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
EXIT:
    BN_Destroy(m);
    BN_Destroy(r);
    BN_Destroy(yr);
    BN_Destroy(c1);
    BN_Destroy(c2);
    BN_Destroy(gcd_result);
    BN_Destroy(top);
    BN_OptimizerDestroy(optimizer);
    BN_MontDestroy(mont);
    return ret;
}

int32_t CRYPT_ELGAMAL_PrvDec(const CRYPT_ELGAMAL_Ctx *ctx, const BN_BigNum *c1, const BN_BigNum *c2, uint32_t bits,
                             uint8_t *out, uint32_t *outLen)
{
    int32_t ret;
    CRYPT_ELGAMAL_PrvKey *prvKey = ctx->prvKey;
    if (prvKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    BN_Optimizer *optimizer = BN_OptimizerCreate();
    if (optimizer == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    bits = CRYPT_ELGAMAL_GetBits(ctx);
    BN_BigNum *m = BN_Create(bits);
    BN_BigNum *c1_x = BN_Create(bits);
    BN_BigNum *c1_x_inv = BN_Create(bits);
    BN_BigNum *result = BN_Create(bits);

    bool createFailed = (m == NULL || c1_x == NULL || c1_x_inv == NULL || result == NULL);

    if (createFailed) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto EXIT;
    }

    ret = BN_ModExp(c1_x, c1, prvKey->x, prvKey->p, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ret = BN_ModInv(c1_x_inv, c1_x, prvKey->p, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ret = BN_ModMul(m, c2, c1_x_inv, prvKey->p, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ret = ResultToOut(bits, result, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
EXIT:
    BN_Destroy(m);
    BN_Destroy(c1_x);
    BN_Destroy(c1_x_inv);
    BN_Destroy(result);
    BN_OptimizerDestroy(optimizer);
    return ret;
}

static int32_t EncryptInputCheck(const CRYPT_ELGAMAL_Ctx *ctx, const uint8_t *input, uint32_t inputLen, uint8_t *out,
                                 uint32_t *outLen)
{
    if (ctx == NULL || (input == NULL && inputLen != 0) || out == NULL || outLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->pubKey == NULL) {
        // Check whether the public key information exists.
        BSL_ERR_PUSH_ERROR(CRYPT_ELGAMAL_NO_KEY_INFO);
        return CRYPT_ELGAMAL_NO_KEY_INFO;
    }
    // Check whether the length of the out is sufficient to place the encryption information.
    uint32_t bits = CRYPT_ELGAMAL_GetBits(ctx);
    if ((*outLen) < BN_BITS_TO_BYTES(bits)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ELGAMAL_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_ELGAMAL_BUFF_LEN_NOT_ENOUGH;
    }
    if (inputLen > BN_BITS_TO_BYTES(bits)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ELGAMAL_ERR_ENC_BITS);
        return CRYPT_ELGAMAL_ERR_ENC_BITS;
    }

    return CRYPT_SUCCESS;
}

int32_t CRYPT_ELGAMAL_Encrypt(CRYPT_ELGAMAL_Ctx *ctx, const uint8_t *data, uint32_t dataLen, uint8_t *out,
                              uint32_t *outLen)
{
    int32_t ret = EncryptInputCheck(ctx, data, dataLen, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint32_t bits = CRYPT_ELGAMAL_GetBits(ctx);
    uint32_t out1Len = bits;
    uint32_t out2Len = (*outLen) - bits;
    uint32_t out3Len = 2 * bits ;
    uint8_t *out1 = BSL_SAL_Calloc(1u, out1Len);
    uint8_t *out2 = BSL_SAL_Calloc(1u, out2Len);
    uint8_t *out3 = BSL_SAL_Calloc(1u, out3Len);
    BN_BigNum *result = BN_Create(*outLen);
    BN_BigNum *c = BN_Create(*outLen);
    if (out1 == NULL || out2 == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto EXIT;
    }

    ret = CRYPT_ELGAMAL_PubEnc(ctx, data, dataLen, out1, &out1Len, out2, &out2Len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    (void)memcpy_s(out3, out3Len, out1, out1Len); // c1
    (void)memcpy_s(out3 + out1Len, out3Len - out1Len, out2, out2Len); // c2

    ret = BN_Bin2Bn(c,out3,out3Len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ret = ResultToOut(2 * bits, result, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

EXIT:
    BSL_SAL_FREE(out1);
    BSL_SAL_FREE(out2);
    BSL_SAL_FREE(out3);
    BN_Destroy(result);
    BN_Destroy(c);
    return ret;
}

static int32_t DecryptInputCheck(const CRYPT_ELGAMAL_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
                                 const uint8_t *out, const uint32_t *outLen)
{
    if (ctx == NULL || data == NULL || out == NULL || outLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->prvKey == NULL) {
        // Check whether the private key information exists.
        BSL_ERR_PUSH_ERROR(CRYPT_ELGAMAL_NO_KEY_INFO);
        return CRYPT_ELGAMAL_NO_KEY_INFO;
    }
    // Check whether the length of the out is sufficient to place the decryption information.
    uint32_t bits = CRYPT_ELGAMAL_GetBits(ctx);
    if ((*outLen) < BN_BITS_TO_BYTES(bits)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ELGAMAL_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_ELGAMAL_BUFF_LEN_NOT_ENOUGH;
    }
    if (dataLen != 2 * BN_BITS_TO_BYTES(bits)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ELGAMAL_ERR_DEC_BITS);
        return CRYPT_ELGAMAL_ERR_DEC_BITS;
    }

    return CRYPT_SUCCESS;
}

static int32_t CheckCiphertext(const BN_BigNum *c1, const BN_BigNum *c2, const CRYPT_ELGAMAL_PrvKey *prvKey)
{
    if (BN_Cmp(c1, prvKey->p) >= 0 || BN_IsNegative(c1)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ELGAMAL_ERR_INPUT_VALUE);
        return CRYPT_ELGAMAL_ERR_INPUT_VALUE;
    }
    if (BN_Cmp(c2, prvKey->p) >= 0 || BN_IsNegative(c2)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ELGAMAL_ERR_INPUT_VALUE);
        return CRYPT_ELGAMAL_ERR_INPUT_VALUE;
    }
    int32_t ret = CRYPT_SUCCESS;
    BN_BigNum *gcd_result = BN_Create(BN_Bits(c1));
    BN_Optimizer *optimizer = BN_OptimizerCreate();
    if (gcd_result == NULL || optimizer == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto EXIT;
    }
    ret = BN_Gcd(gcd_result, c1, prvKey->p, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    if (BN_IsOne(gcd_result) == false) {
        BSL_ERR_PUSH_ERROR(CRYPT_ELGAMAL_ERR_INPUT_VALUE);
        ret = CRYPT_ELGAMAL_ERR_INPUT_VALUE;
        goto EXIT;
    }
    ret = BN_Gcd(gcd_result, c2, prvKey->p, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    if (BN_IsOne(gcd_result) == false) {
        BSL_ERR_PUSH_ERROR(CRYPT_ELGAMAL_ERR_INPUT_VALUE);
        ret = CRYPT_ELGAMAL_ERR_INPUT_VALUE;
        goto EXIT;
    }
EXIT:
    BN_Destroy(gcd_result);
    BN_OptimizerDestroy(optimizer);
    return ret;
}

int32_t CRYPT_ELGAMAL_Decrypt(CRYPT_ELGAMAL_Ctx *ctx, const uint8_t *data, uint32_t dataLen, uint8_t *out,
                              uint32_t *outLen)
{
    int32_t ret = DecryptInputCheck(ctx, data, dataLen, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint32_t bits = CRYPT_ELGAMAL_GetBits(ctx);
    uint32_t data1Len = BN_BITS_TO_BYTES(bits);
    uint32_t data2Len = dataLen - BN_BITS_TO_BYTES(bits);
    uint8_t *data1 = BSL_SAL_Calloc(1u, data1Len);
    uint8_t *data2 = BSL_SAL_Calloc(1u, data2Len);
    BN_BigNum *c1 = BN_Create(bits);
    BN_BigNum *c2 = BN_Create(bits);

    if (data1 == NULL || data2 == NULL || c1 == NULL || c2 == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto EXIT;
    }

    (void)memcpy_s(data1, data1Len, data, data1Len); // c1
    (void)memcpy_s(data2, data2Len, data + data1Len, data2Len); // c2

    ret = BN_Bin2Bn(c1, data1, data1Len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ret = BN_Bin2Bn(c2, data2, data2Len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ret = CheckCiphertext(c1, c2, ctx->prvKey);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ret = CRYPT_ELGAMAL_PrvDec(ctx, c1, c2, bits, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
EXIT:
    BSL_SAL_FREE(data1);
    BSL_SAL_FREE(data2);
    BN_Destroy(c1);
    BN_Destroy(c2);
    return ret;
}

static uint32_t CRYPT_ELGAMAL_GetLen(const CRYPT_ELGAMAL_Ctx *ctx, GetLenFunc func, void *val, uint32_t len)
{
    if (val == NULL || len != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    *(int32_t *)val = func(ctx);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_ELGAMAL_Ctrl(CRYPT_ELGAMAL_Ctx *ctx, int32_t opt, void *val, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (opt) {
        case CRYPT_CTRL_GET_BITS:
            return CRYPT_ELGAMAL_GetLen(ctx, (GetLenFunc)CRYPT_ELGAMAL_GetBits, val, len);
        case CRYPT_CTRL_GET_SECBITS:
            return CRYPT_ELGAMAL_GetLen(ctx, (GetLenFunc)CRYPT_ELGAMAL_GetSecBits, val, len);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_ELGAMAL_CTRL_NOT_SUPPORT_ERROR);
            return CRYPT_ELGAMAL_CTRL_NOT_SUPPORT_ERROR;
    }
}

#endif // HITLS_CRYPTO_ELGAMAL