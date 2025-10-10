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
#ifdef HITLS_CRYPTO_BN_RAND

#include <stdint.h>
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "bn_basic.h"
#include "bn_bincal.h"
#include "crypt_util_rand.h"

static int32_t RandGenerate(void *libCtx, BN_BigNum *r, uint32_t bits)
{
    uint32_t room = BITS_TO_BN_UNIT(bits);
    BN_UINT mask;
    // Maxbits = (1 << 29) --> MaxBytes = (1 << 26), hence BN_BITS_TO_BYTES(bits) will not exceed the upper limit.
    uint32_t byteSize = BN_BITS_TO_BYTES(bits);
    uint8_t *buf = BSL_SAL_Malloc(byteSize);
    if (buf == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = CRYPT_RandEx(libCtx, buf, byteSize);
    if (ret == CRYPT_NO_REGIST_RAND) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_RAND_GEN_FAIL);
        ret = CRYPT_BN_RAND_GEN_FAIL;
        goto ERR;
    }
    ret = BN_Bin2Bn(r, buf, byteSize);
    BSL_SAL_CleanseData(buf, byteSize);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    mask = (BN_UINT)(-1) >> ((BN_UINT_BITS - bits % BN_UINT_BITS) % BN_UINT_BITS);
    r->data[room - 1] &= mask;
    r->size = BinFixSize(r->data, room);
ERR:
    BSL_SAL_FREE(buf);
    return ret;
}

static int32_t CheckTopAndBottom(uint32_t bits, uint32_t top, uint32_t bottom)
{
    if (top > BN_RAND_TOP_TWOBIT) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_RAND_TOP_BOTTOM);
        return CRYPT_BN_ERR_RAND_TOP_BOTTOM;
    }
    if (bottom > BN_RAND_BOTTOM_TWOBIT) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_RAND_TOP_BOTTOM);
        return CRYPT_BN_ERR_RAND_TOP_BOTTOM;
    }
    if (top > bits || bottom > bits) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_RAND_BITS_NOT_ENOUGH);
        return CRYPT_BN_ERR_RAND_BITS_NOT_ENOUGH;
    }
    return CRYPT_SUCCESS;
}

int32_t BN_Rand(BN_BigNum *r, uint32_t bits, uint32_t top, uint32_t bottom)
{
    return BN_RandEx(NULL, r, bits, top, bottom);
}

int32_t BN_RandEx(void *libCtx, BN_BigNum *r, uint32_t bits, uint32_t top, uint32_t bottom)
{
    if (r == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CheckTopAndBottom(bits, top, bottom);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (bits == 0) {
        return BN_Zeroize(r);
    }

    if (bits > BN_MAX_BITS) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_BITS_TOO_MAX);
        return CRYPT_BN_BITS_TOO_MAX;
    }
    ret = BnExtend(r, BITS_TO_BN_UNIT(bits));
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = RandGenerate(libCtx, r, bits);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    r->data[0] |= (bottom == BN_RAND_BOTTOM_TWOBIT) ? 0x3 : (BN_UINT)bottom;  // CheckTopAndBottom ensure that bottom>0
    if (top == BN_RAND_TOP_ONEBIT) {
        (void)BN_SetBit(r, bits - 1);
    } else if (top == BN_RAND_TOP_TWOBIT) {
        (void)BN_SetBit(r, bits - 1);
        (void)BN_SetBit(r, bits - 2); /* the most significant 2 bits are 1 */
    }
    r->size = BinFixSize(r->data, r->room);
    return ret;
}

static int32_t InputCheck(BN_BigNum *r, const BN_BigNum *p)
{
    if (r == NULL || p == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (BN_IsZero(p)) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_RAND_ZERO);
        return CRYPT_BN_ERR_RAND_ZERO;
    }
    if (p->sign == true) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_RAND_NEGATIVE);
        return CRYPT_BN_ERR_RAND_NEGATIVE;
    }
    return BnExtend(r, p->size);
}

int32_t BN_RandRange(BN_BigNum *r, const BN_BigNum *p)
{
    return BN_RandRangeEx(NULL, r, p);
}

int32_t BN_RandRangeEx(void *libCtx, BN_BigNum *r, const BN_BigNum *p)
{
    const int32_t maxCnt = 100; /* try 100 times */
    int32_t tryCnt = 0;

    int32_t ret = InputCheck(r, p);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BN_Zeroize(r);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (BN_IsOne(p)) {
        return CRYPT_SUCCESS;
    }
    uint32_t bits = BN_Bits(p);
    do {
        tryCnt++;
        if (tryCnt > maxCnt) {
            /* The success rate is more than 50%. */
            /* Return a failure if failed to generated after try 100 times */
            BSL_ERR_PUSH_ERROR(CRYPT_BN_RAND_GEN_FAIL);
            return CRYPT_BN_RAND_GEN_FAIL;
        }
        ret = RandGenerate(libCtx, r, bits);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    } while (BinCmp(r->data, r->size, p->data, p->size) >= 0);

    return ret;
}
#endif /* HITLS_CRYPTO_BN_RAND */
