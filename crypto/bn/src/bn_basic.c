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

#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "bn_bincal.h"
#include "bn_basic.h"

BN_BigNum *BN_Create(uint32_t bits)
{
    if (bits > BN_MAX_BITS) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_BITS_INVALID);
        return NULL;
    }
    uint32_t room = BITS_TO_BN_UNIT(bits);
    BN_BigNum *r = (BN_BigNum *)BSL_SAL_Calloc(1u, sizeof(BN_BigNum));
    if (r == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    if (room != 0) {
        r->room = room;
        r->data = (BN_UINT *)BSL_SAL_Calloc(1u, room * sizeof(BN_UINT));
        if (r->data == NULL) {
            BSL_SAL_FREE(r);
            return NULL;
        }
    }

    return r;
}

void BN_Destroy(BN_BigNum *a)
{
    if (a == NULL) {
        return;
    }
    // clear sensitive information
    BSL_SAL_CleanseData((void *)(a->data), a->size * sizeof(BN_UINT));
    if (a->flag == CRYPT_BN_FLAG_STATIC) {
        return;
    }
    BSL_SAL_FREE(a->data);
    if (!BN_IsFlag(a, CRYPT_BN_FLAG_OPTIMIZER)) {
        BSL_SAL_FREE(a);
    }
}

inline void BN_Init(BN_BigNum *bn, BN_UINT *data, uint32_t room, int32_t number)
{
    for (uint32_t i = 0; i < (uint32_t)number; i++) {
        bn[i].data = &data[room * i];
        bn[i].room = room;
        bn[i].flag = CRYPT_BN_FLAG_STATIC;
    }
}
#ifdef HITLS_CRYPTO_EAL_BN
bool BnVaild(const BN_BigNum *a)
{
    if (a == NULL) {
        return false;
    }
    if (a->size == 0) {
        return !a->sign;
    }
    if (a->data == NULL || a->size > a->room) {
        return false;
    }
    if ((a->size <= a->room) && (a->data[a->size - 1] != 0)) {
        return true;
    }
    return false;
}
#endif

#ifdef HITLS_CRYPTO_BN_CB
BN_CbCtx *BN_CbCtxCreate(void)
{
    BN_CbCtx *r = (BN_CbCtx *)BSL_SAL_Calloc(1u, sizeof(BN_CbCtx));
    if (r == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    return r;
}

void BN_CbCtxSet(BN_CbCtx *gencb, BN_CallBack callBack, void *arg)
{
    if (gencb == NULL) {
        return;
    }
    BN_CbCtx *tmpCb = gencb;
    tmpCb->arg = arg;
    tmpCb->cb = callBack;
}

void *BN_CbCtxGetArg(BN_CbCtx *callBack)
{
    if (callBack == NULL) {
        return NULL;
    }
    return callBack->arg;
}

int32_t BN_CbCtxCall(BN_CbCtx *callBack, int32_t process, int32_t target)
{
    if (callBack == NULL || callBack->cb == NULL) {
        return CRYPT_SUCCESS;
    }
    int32_t ret = callBack->cb(callBack, process, target);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

void BN_CbCtxDestroy(BN_CbCtx *cb)
{
    if (cb == NULL) {
        return;
    }
    BSL_SAL_FREE(cb);
}
#endif

int32_t BN_SetSign(BN_BigNum *a, bool sign)
{
    if (a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    /* 0 must be a positive number symbol */
    if (BN_IsZero(a) == true && sign == true) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_NO_NEGATIVE_ZERO);
        return CRYPT_BN_NO_NEGATIVE_ZERO;
    }
    a->sign = sign;
    return CRYPT_SUCCESS;
}

static bool IsLegalFlag(uint32_t flag)
{
    switch (flag) {
        case CRYPT_BN_FLAG_CONSTTIME:
        case CRYPT_BN_FLAG_OPTIMIZER:
        case CRYPT_BN_FLAG_STATIC:
            return true;
        default:
            return false;
    }
}

int32_t BN_SetFlag(BN_BigNum *a, uint32_t flag)
{
    if (a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (!IsLegalFlag(flag)) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_FLAG_INVALID);
        return CRYPT_BN_FLAG_INVALID;
    }
    a->flag |= flag;
    return CRYPT_SUCCESS;
}

int32_t BN_Copy(BN_BigNum *r, const BN_BigNum *a)
{
    if (r == NULL || a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (r != a) {
        int32_t ret = BnExtend(r, a->size);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        r->sign = a->sign;
        BN_COPY_BYTES(r->data, r->size, a->data, a->size);
        r->size = a->size;
    }
    return CRYPT_SUCCESS;
}

BN_BigNum *BN_Dup(const BN_BigNum *a)
{
    if (a == NULL) {
        return NULL;
    }
    BN_BigNum *r = BN_Create(a->room * BN_UINT_BITS);
    if (r != NULL) {
        r->sign = a->sign;
        (void)memcpy_s(r->data, a->size * sizeof(BN_UINT), a->data, a->size * sizeof(BN_UINT));
        r->size = a->size;
    }
    return r;
}

bool BN_IsZero(const BN_BigNum *a)
{
    if (a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return true;
    }
    return (a->size == 0);
}

bool BN_IsOne(const BN_BigNum *a)
{
    if (a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return false;
    }
    return (a->size == 1 && a->data[0] == 1 && a->sign == false);
}

bool BN_IsNegative(const BN_BigNum *a)
{
    if (a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return false;
    }
    return a->sign;
}

bool BN_IsOdd(const BN_BigNum *a)
{
    if (a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return false;
    }
    return (a->size > 0) && (a->data[0] & 1) != 0;
}

bool BN_IsFlag(const BN_BigNum *a, uint32_t flag)
{
    if (a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return false;
    }
    return a->flag & flag;
}

int32_t BN_Zeroize(BN_BigNum *a)
{
    if (a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    // clear sensitive information
    BSL_SAL_CleanseData(a->data, a->size * sizeof(BN_UINT));
    a->sign = false;
    a->size = 0;
    return CRYPT_SUCCESS;
}

bool BN_IsLimb(const BN_BigNum *a, const BN_UINT w)
{
    if (a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return (w == 0);
    }
    return !a->sign && (((a->size == 1) && (a->data[0] == w)) || ((w == 0) && (a->size == 0)));
}

int32_t BN_SetLimb(BN_BigNum *r, BN_UINT w)
{
    if (r == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = BnExtend(r, 1);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    BN_Zeroize(r);
    if (w != 0) {
        r->data[r->size] = w;
        r->size++;
    }
    return CRYPT_SUCCESS;
}

BN_UINT BN_GetLimb(const BN_BigNum *a)
{
    if (a == NULL) {
        return 0;
    }
    if (a->size > 1) {
        return BN_MASK;
    } else if (a->size == 1) {
        return a->data[0];
    }
    return 0;
}

bool BN_GetBit(const BN_BigNum *a, uint32_t n)
{
    if (a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return false;
    }
    uint32_t nw = n / BN_UINT_BITS;
    uint32_t nb = n % BN_UINT_BITS;
    if (nw >= a->size) {
        return false;
    }
    return (uint32_t)(((a->data[nw]) >> nb) & ((BN_UINT)1));
}

int32_t BN_SetBit(BN_BigNum *a, uint32_t n)
{
    if (a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    uint32_t nw = n / BN_UINT_BITS;
    uint32_t nb = n % BN_UINT_BITS;
    if (nw >= a->room) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_SPACE_NOT_ENOUGH);
        return CRYPT_BN_SPACE_NOT_ENOUGH;
    }
    a->data[nw] |= (((BN_UINT)1) << nb);
    if (a->size < nw + 1) {
        a->size = nw + 1;
    }
    return CRYPT_SUCCESS;
}

int32_t BN_ClrBit(BN_BigNum *a, uint32_t n)
{
    if (a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    uint32_t nw = n / BN_UINT_BITS;
    uint32_t nb = n % BN_UINT_BITS;
    if (nw >= a->size) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_SPACE_NOT_ENOUGH);
        return CRYPT_BN_SPACE_NOT_ENOUGH;
    }
    a->data[nw] &= (~(((BN_UINT)1) << nb));
    // check whether the size changes
    a->size = BinFixSize(a->data, a->size);
    if (a->size == 0) {
        a->sign = false;
    }
    return CRYPT_SUCCESS;
}

int32_t BN_MaskBit(BN_BigNum *a, uint32_t n)
{
    if (a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    uint32_t nw = n / BN_UINT_BITS;
    uint32_t nb = n % BN_UINT_BITS;
    if (a->size <= nw) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_SPACE_NOT_ENOUGH);
        return CRYPT_BN_SPACE_NOT_ENOUGH;
    }
    if (nb == 0) {
        a->size = nw;
    } else {
        a->size = nw + 1;
        a->data[nw] &= ~(BN_MASK << nb);
    }
    a->size = BinFixSize(a->data, a->size);
    if (a->size == 0) {
        a->sign = false;
    }
    return CRYPT_SUCCESS;
}

uint32_t BN_Bits(const BN_BigNum *a)
{
    if (a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return 0;
    }
    return BinBits(a->data, a->size);
}

uint32_t BN_Bytes(const BN_BigNum *a)
{
    return BN_BITS_TO_BYTES(BN_Bits(a));
}

int32_t BnExtend(BN_BigNum *a, uint32_t words)
{
    if (a->room >= words) {
        return CRYPT_SUCCESS;
    }
    if (a->flag == CRYPT_BN_FLAG_STATIC) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_NOT_SUPPORT_EXTENSION);
        return CRYPT_BN_NOT_SUPPORT_EXTENSION;
    }
    if (words > BITS_TO_BN_UNIT(BN_MAX_BITS)) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_BITS_TOO_MAX);
        return CRYPT_BN_BITS_TOO_MAX;
    }

    BN_UINT *tmp = (BN_UINT *)BSL_SAL_Calloc(1u, words * sizeof(BN_UINT));
    if (tmp == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (a->size > 0) {
        (void)memcpy_s(tmp, a->size * sizeof(BN_UINT), a->data, a->size * sizeof(BN_UINT));
        BSL_SAL_CleanseData(a->data, a->size * sizeof(BN_UINT));
    }
    BSL_SAL_FREE(a->data);
    a->data = tmp;
    a->room = words;
    return CRYPT_SUCCESS;
}

// ref. NIST.SP.800-57 Section 5.6.1.1
int32_t BN_SecBits(int32_t pubLen, int32_t prvLen)
{
    int32_t bits = 256; // the secure length is initialized to a maximum of 256
    int32_t level[] = {1024, 2048, 3072, 7680, 15360, INT32_MAX};
    int32_t secbits[] = {0, 80, 112, 128, 192, 256};
    for (int32_t loc = 0; loc < (int32_t)(sizeof(level) / sizeof(level[0])); loc++) {
        if (pubLen < level[loc]) {
            bits = secbits[loc];
            break;
        }
    }

    if (prvLen == -1) { // In IFC algorithm, the security length only needs to consider the modulus number.
        return bits;
    }
    bits = ((prvLen / 2) >= bits) ? bits : (prvLen / 2); // The security length of FFC algorithm is considering prvLen/2
    // Encryption does not use the algorithm/key combination which security strength is less than 112 bits
    // such as less than 80 bits
    return (bits < 80) ? 0 : bits;
}
#endif /* HITLS_CRYPTO_BN */
