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
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "bn_basic.h"
#include "bn_bincal.h"
#include "crypt_util_rand.h"

static int32_t RandGenerate(BN_BigNum *r, uint32_t bits)
{
    int32_t ret;
    uint32_t room = BITS_TO_BN_UNIT(bits);
    BN_UINT mask;
    uint32_t bufSize = BITS_TO_BYTES(bits); // bits < (1u << 29), hence bits + 7 will not exceed the upper limit.
    uint8_t *buf = BSL_SAL_Malloc(bufSize);
    if (buf == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = CRYPT_Rand(buf, bufSize);
    if (ret == CRYPT_NO_REGIST_RAND) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    if (ret != CRYPT_SUCCESS) {
        ret = CRYPT_BN_RAND_GEN_FAIL;
        BSL_ERR_PUSH_ERROR(CRYPT_BN_RAND_GEN_FAIL);
        goto EXIT;
    }
    ret = BN_Bin2Bn(r, buf, bufSize);
    BSL_SAL_CleanseData((void *)buf, bufSize);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    mask = (BN_UINT)(-1) >> ((BN_UINT_BITS - bits % BN_UINT_BITS) % BN_UINT_BITS);
    r->data[room - 1] &= mask;
    r->size = BinFixSize(r->data, room);
EXIT:
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
    if (BnExtend(r, BITS_TO_BN_UNIT(bits)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = RandGenerate(r, bits);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    r->data[0] |= (bottom == BN_RAND_BOTTOM_TWOBIT) ? 0x3 : (BN_UINT)bottom;  // CheckTopAndBottom ensure that bottom>0
    if (top == BN_RAND_TOP_ONEBIT) {
        BN_SetBit(r, bits - 1);
    } else if (top == BN_RAND_TOP_TWOBIT) {
        BN_SetBit(r, bits - 1);
        BN_SetBit(r, bits - 2); /* the most significant 2 bits are 1 */
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
    if (BN_ISNEG(p->flag)) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_RAND_NEGATIVE);
        return CRYPT_BN_ERR_RAND_NEGATIVE;
    }
    if (BnExtend(r, p->size) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    return CRYPT_SUCCESS;
}

int32_t BN_RandRange(BN_BigNum *r, const BN_BigNum *p)
{
    const int32_t maxCnt = 100; /* try 100 times */
    int32_t tryCnt = 0;
    int32_t ret;

    ret = InputCheck(r, p);
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
        ret = RandGenerate(r, bits);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    } while (BinCmp(r->data, r->size, p->data, p->size) >= 0);

    return ret;
}

#endif /* HITLS_CRYPTO_BN */
