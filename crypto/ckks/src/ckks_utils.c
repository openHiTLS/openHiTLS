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
#ifdef HITLS_CRYPTO_CKKS

#include "crypt_types.h"
#include "crypt_ckks.h"
#include "crypt_utils.h"
#include "crypt_bn.h"
#include "ckks_local.h"
#include "ckks_utils.h"
#include "crypt_errno.h"
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_params_key.h"

#ifndef DISABLE_CKKS_SIMD
#ifdef __x86_64__ // The 256-bit AVX register can store 4 doubles

#ifdef __AVX__
#define AVX_ABLE
#endif

#ifdef AVX_ABLE
#define PD4_START
#define CKKS_FFT_ALIGN 64

#endif //AVX_ABLE
#endif //__x86_64__
#endif //DISABLE_CKKS_SIMD

/****************** Generic Mathematical Functions ******************/
/********************************************************************/

uint32_t Gcd(uint32_t a, uint32_t b)
{
    while (b != 0) {
        uint32_t temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

uint32_t Get_ZMStar_Gens(uint32_t *gens, uint32_t m)
{
    int32_t flag = 0;
    uint32_t j = 0;
    for (uint32_t g = 2; g < m; g++) {
        uint32_t res = 1;
        for (uint32_t i = 0; i < m - 1; i++) {
            res = (res * g) % m;
            if (res == 1) {
                flag = 1;
            }
            break;
        }
        if (flag == 0) {
            gens[j++] = g;
        }
    }
    return j;
}

uint32_t PowerMod(uint32_t base, uint32_t exp, uint32_t mod)
{
    uint32_t res = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 0) {
            res = (res * base) % mod;
        }
        exp >>= 1;
        base = (base * base) % mod;
    }
    return res;
}

uint32_t *Get_ZMStar(uint32_t m)
{
    uint32_t *ZMStar = (uint32_t *)BSL_SAL_Malloc((m / 2) * sizeof(uint32_t));
    uint32_t cnt = 0;
    for (uint32_t i = 1; i < m; i++) {
        if (Gcd(i, m) == 1) {
            ZMStar[cnt++] = i;
        }
    }
    return ZMStar;
}

bool Lexico_Order(uint32_t *buffer, const uint32_t *ZMStar, uint32_t buffer_sz, uint32_t ZMStar_sz)
{
    if (ZMStar_sz == 0) {
        return false;
    }
    int32_t i = (int32_t)(ZMStar_sz - 1);
    for (; i >= 0; i--) {
        if (i >= (int32_t)buffer_sz) {
            continue;
        }
        if (buffer[i] < ZMStar[i] - 1) {
            buffer[i]++;
            for (int32_t j = i + 1; j < (int32_t)buffer_sz; j++) {
                buffer[j] = 0;
            }
            return true;
        }
    }
    return false;
}

uint32_t Get_T_Ele(const uint32_t *exps, uint32_t exps_sz, const uint32_t *gens, uint32_t gens_sz, uint32_t m)
{
    uint32_t t = 1;
    uint32_t n = (exps_sz < gens_sz) ? exps_sz : gens_sz;
    for (uint32_t i = 0; i < n; i++) {
        long g = PowerMod(gens[i], exps[i], m);
        t = (t * g) % m;
    }
    return t;
}

bool Check_I_In_ZMStar(const int32_t *Tidx, uint32_t t, uint32_t m)
{
    return (t > 0 && t < m && Tidx[t] > -1);
}

double Coordinate_Wise_Random_Rounding(double coord)
{
    double fl = (int32_t)(coord >= 0 ? coord : coord - 1);
    double frac = coord - fl;
    double r = (double)rand() / (RAND_MAX + 1.0);
    if (r < frac) {
        return (fl + 1);
    } else {
        return fl;
    }
}

uint64_t htonll(uint64_t host)
{
    // Detect host byte order (small end returns converted value, big end returns directly)
    union {
        uint32_t i;
        uint8_t c[4];
    } test = {0x01020304};
    if (test.c[0] == 0x01) {
        return host; // big end
    }

    return ((host & 0xFF00000000000000ULL) >> 56) | ((host & 0x00FF000000000000ULL) >> 40) |
           ((host & 0x0000FF0000000000ULL) >> 24) | ((host & 0x000000FF00000000ULL) >> 8) |
           ((host & 0x00000000FF000000ULL) << 8) | ((host & 0x0000000000FF0000ULL) << 24) |
           ((host & 0x000000000000FF00ULL) << 40) | ((host & 0x00000000000000FFULL) << 56);
}

uint64_t ntohll(uint64_t net)
{
    return htonll(net); // Same as htonll
}

/************************* Complex Operation ************************/
/********************************************************************/

CKKS_Complex CKKS_Complex_Conj(CKKS_Complex c)
{
    CKKS_Complex complex_conj;
    complex_conj.real = c.real;
    complex_conj.imag = -c.imag;
    return complex_conj;
}

CKKS_Complex CKKS_Complex_Add(CKKS_Complex c1, CKKS_Complex c2)
{
    CKKS_Complex sum;
    sum.real = c1.real + c2.real;
    sum.imag = c1.imag + c2.imag;
    return sum;
}

CKKS_Complex CKKS_Complex_Int_Add(CKKS_Complex c, uint32_t w)
{
    CKKS_Complex sum;
    sum.real = c.real + (double)w;
    sum.imag = c.imag;
    return sum;
}

CKKS_Complex CKKS_Complex_Sub(CKKS_Complex c1, CKKS_Complex c2)
{
    CKKS_Complex differ;
    differ.real = c1.real - c2.real;
    differ.imag = c1.imag - c2.imag;
    return differ;
}

CKKS_Complex CKKS_Complex_Int_Sub(CKKS_Complex c, uint32_t w)
{
    CKKS_Complex differ;
    differ.real = c.real - (double)w;
    differ.imag = c.imag;
    return differ;
}

CKKS_Complex CKKS_Complex_Mul(CKKS_Complex c1, CKKS_Complex c2)
{
    CKKS_Complex product;
    product.real = c1.real * c2.real - c1.imag * c2.imag;
    product.imag = c1.real * c2.imag + c1.imag * c2.real;
    return product;
}

CKKS_Complex CKKS_Complex_Conj_Mul(CKKS_Complex c1, CKKS_Complex c2)
{
    CKKS_Complex product;
    product.real = c1.real * c2.real + c1.imag * c2.imag;
    product.imag = c1.real * c2.imag - c1.imag * c2.real;
    return product;
}

CKKS_Complex CKKS_Complex_ADouble_Mul(CKKS_Complex c, double w)
{
    CKKS_Complex product;
    product.real = c.real * w;
    product.imag = c.imag * w;
    return product;
}

CKKS_Complex CKKS_Complex_Int_Div(CKKS_Complex c, uint32_t w)
{
    CKKS_Complex product;
    product.real = c.real / (double)w;
    product.imag = c.imag / (double)w;
    return product;
}

double CKKS_Complex_Cabs(CKKS_Complex c)
{
    return sqrt(c.real * c.real + c.imag * c.imag);
}

void CKKS_Complex_Copy(CKKS_Complex *new_c, const CKKS_Complex c)
{
    new_c->real = c.real;
    new_c->imag = c.imag;
}

CKKS_Complex CKKS_ADouble2Complex(double d1)
{
    CKKS_Complex complex;
    complex.real = d1;
    complex.imag = 0;
    return complex;
}

CKKS_Complex CKKS_U32t2Complex(uint32_t u1)
{
    CKKS_Complex complex;
    complex.real = (double)u1;
    complex.imag = 0;
    return complex;
}

int32_t CKKS_BN2Double(const BN_BigNum *a, double *val)
{
    if (a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (BN_IsZero(a)) {
        return 0.0;
    }
    bool is_neg = BN_IsNegative(a);
    uint32_t bytes_len = BN_Bytes(a);
    uint8_t *bytes = (uint8_t *)BSL_SAL_Malloc(bytes_len);
    uint32_t bin_len = bytes_len;
    int32_t ret = BN_Bn2Bin(a, bytes, &bin_len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // Convert big-endian sequential byte stream to an integer (processing up to the first 53 bits)
    double res = 0.0;
    uint32_t max_bits = 53;
    uint32_t max_bytes = BN_BITS_TO_BYTES(max_bits);
    for (uint32_t i = 0; i < max_bytes && i < bin_len; i++) {
        res = res * 256.0 + (double)bytes[i];
    }
    BSL_SAL_Free(bytes);
    *val = is_neg ? -res : res;
    return CRYPT_SUCCESS;
}

int32_t CKKS_Complex_Array_Init(CKKS_Complex_Array *mem, size_t initial_size)
{
    if (mem == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    mem->size = initial_size;
    mem->elem_size = sizeof(CKKS_Complex);
    mem->data = (CKKS_Complex *)CKKS_Aligned_Allocate(initial_size, mem->elem_size);
    if (mem->data == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    (void)memset_s(mem->data, initial_size * sizeof(CKKS_Complex), 0, initial_size * sizeof(CKKS_Complex));
    return CRYPT_SUCCESS;
}

int32_t Set_Complex_Array_Data(CKKS_Complex_Array *mem, CKKS_Complex *complex_arr)
{
    if (mem == NULL || complex_arr == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    size_t i = 0;
    while (i < sizeof(complex_arr)) {
        mem->data[i] = complex_arr[i];
    }
    return CRYPT_SUCCESS;
}

int32_t Push_Complex_Array_Ele(CKKS_Complex_Array *mem, void *ele)
{
    size_t new_size = mem->size + 1;
    void *new_data = CKKS_Aligned_Allocate(new_size, mem->elem_size);
    if (new_data == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        BSL_SAL_Free(mem);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    memcpy_s(new_data, new_size * mem->elem_size, mem->data, mem->size * mem->elem_size);
    CKKS_Aligned_Deallocate(mem->data);
    mem->data = new_data;
    memcpy_s((char *)mem->data + mem->size * mem->elem_size, mem->elem_size, ele, mem->elem_size);
    mem->size++;
    return CRYPT_SUCCESS;
}

int32_t CKKS_Complex_Array_Copy(CKKS_Complex_Array *dst, const CKKS_Complex_Array *src)
{
    if (dst == NULL || src == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    dst->size = src->size;
    dst->elem_size = src->elem_size;
    for (size_t i = 0; i < dst->size; i++) {
        CKKS_Complex_Copy(&dst->data[i], src->data[i]);
    }
    return CRYPT_SUCCESS;
}

void CKKS_Complex_Array_Destroy(CKKS_Complex_Array *mem)
{
    if (mem->data) {
        CKKS_Aligned_Deallocate(mem->data);
    }
    if (mem) {
        BSL_SAL_Free(mem);
    }
}

int32_t CKKS_Doubles2Complex(CKKS_Complex_Array *complex_arr, double *doublearr, uint32_t doublearr_sz)
{
    if (doublearr_sz % 2 != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    complex_arr->size = doublearr_sz / 2;
    complex_arr->elem_size = sizeof(CKKS_Complex);
    for (size_t i = 0; i < complex_arr->size; i++) {
        complex_arr->data[i].real = doublearr[2 * i];
        complex_arr->data[i].imag = doublearr[2 * i + 1];
    }
    return CRYPT_SUCCESS;
}

int32_t CKKS_Complex2Doubles(double *doublearr, const CKKS_Complex_Array *complex_arr)
{
    if (doublearr == NULL || complex_arr == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    for (size_t i = 0; i < complex_arr->size; i++) {
        doublearr[2 * i] = complex_arr->data[i].real;
        doublearr[2 * i + 1] = complex_arr->data[i].imag;
    }
    return CRYPT_SUCCESS;
}

int32_t CKKS_ComplexArray2Bin(const CKKS_Complex_Array *arr, uint8_t *bin, uint32_t *binLen)
{
    if (arr == NULL || bin == NULL || binLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    uint64_t doublearr_sz = 2 * arr->size;
    double *double_arr = (double *)BSL_SAL_Malloc(doublearr_sz * sizeof(double));
    int32_t ret = CKKS_Complex2Doubles(double_arr, arr);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_ERR_CAL_VALUE);
        return CRYPT_CKKS_ERR_CAL_VALUE;
    }
    const uint32_t totalSize = doublearr_sz * sizeof(double) + sizeof(uint64_t);

    if (*binLen < totalSize) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_CKKS_BUFF_LEN_NOT_ENOUGH;
    }

    uint64_t be_length = htonll(doublearr_sz);
    memcpy_s(bin, sizeof(uint64_t), &be_length, sizeof(uint64_t));

    uint8_t *ptr = bin + sizeof(uint64_t);
    for (uint64_t i = 0; i < doublearr_sz; i++) {
        uint64_t u64;
        memcpy_s(&u64, sizeof(uint64_t), &double_arr[i], sizeof(uint64_t));
        u64 = htonll(u64);
        memcpy_s(ptr, sizeof(uint64_t), &u64, sizeof(uint64_t));
        ptr += sizeof(uint64_t);
    }

    *binLen = totalSize;
    return CRYPT_SUCCESS;
}

int32_t CKKS_Bin2ComplexArray(CKKS_Complex_Array *arr, const uint8_t *bin, uint32_t binLen)
{
    if (arr == NULL || bin == NULL || binLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (binLen < sizeof(uint64_t)) {
        return CRYPT_CKKS_BUFF_LEN_NOT_ENOUGH;
    }

    uint64_t be_length;
    memcpy_s(&be_length, sizeof(uint64_t), bin, sizeof(uint64_t));
    uint64_t double_arrsz = ntohll(be_length);

    uint32_t expected = sizeof(uint64_t) + double_arrsz * sizeof(double);
    if (binLen < expected) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_CKKS_BUFF_LEN_NOT_ENOUGH;
    }

    double *double_arr = (double *)BSL_SAL_Malloc(double_arrsz * sizeof(double));
    if (double_arr == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    const uint8_t *ptr = bin + sizeof(uint64_t);
    for (uint64_t i = 0; i < double_arrsz; i++) {
        uint64_t u64;
        memcpy_s(&u64, sizeof(uint64_t), ptr, sizeof(uint64_t));
        u64 = ntohll(u64); // 转回主机字节序
        memcpy_s(&double_arr[i], sizeof(double), &u64, sizeof(double));
        ptr += sizeof(uint64_t);
    }

    int32_t ret = CKKS_Doubles2Complex(arr, double_arr, (uint32_t)double_arrsz);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_ERR_CAL_VALUE);
        return CRYPT_CKKS_ERR_CAL_VALUE;
    }

    return CRYPT_SUCCESS;
}

/*********************** Polynomial Operation ***********************/
/********************************************************************/

int32_t CKKS_Poly_Init(CKKS_Poly *poly, uint32_t bits, uint32_t m)
{
    if (poly == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (m == 0 || (m != 0 && (m & (m - 1)) == 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    poly->degree = m / 2 - 1;
    poly->coeffs = (BN_BigNum **)BSL_SAL_Malloc((m / 2) * sizeof(BN_BigNum *));
    if (poly->coeffs == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        BSL_SAL_Free(poly);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    (void)memset_s(poly->coeffs, (m / 2) * sizeof(BN_BigNum *), 0, (m / 2) * sizeof(BN_BigNum *));

    poly->polyctx = (CKKS_PolyCtx *)BSL_SAL_Malloc(sizeof(CKKS_PolyCtx));
    if (poly->polyctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        CKKS_Poly_Destroy(poly);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (CKKS_PolyCtx_Set(poly->polyctx, bits, m) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        CKKS_Poly_Destroy(poly);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    return CRYPT_SUCCESS;
}

void CKKS_Poly_Destroy(CKKS_Poly *poly)
{
    if (poly != NULL && poly->coeffs != NULL) {
        for (uint32_t i = 0; i < poly->degree + 1; i++) {
            BN_Destroy(poly->coeffs[i]);
        }
    }
    if (poly->polyctx) {
        BSL_SAL_Free(poly->polyctx);
    }
    BSL_SAL_Free(poly);
}

int32_t CKKS_Poly_Copy(CKKS_Poly *dst, const CKKS_Poly *src)
{
    if (dst == NULL || src == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    uint32_t m = src->polyctx->m;
    int32_t ret = CKKS_PolyCtx_Set(dst->polyctx, src->polyctx->bits, src->polyctx->m);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        CKKS_Poly_Destroy(dst);
        return ret;
    }
    dst->degree = src->degree;
    if (dst->coeffs == NULL) {
        dst->coeffs = (BN_BigNum **)BSL_SAL_Malloc((m / 2) * sizeof(BN_BigNum *));
        if (dst->coeffs == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
    }
    for (uint32_t i = 0; i <= src->degree; i++) {
        dst->coeffs[i] = BN_Dup(src->coeffs[i]);
        if (dst->coeffs[i] == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            CKKS_Poly_Destroy(dst);
            return CRYPT_MEM_ALLOC_FAIL;
        }
    }
    return CRYPT_SUCCESS;
}

CKKS_Poly *CKKS_Poly_Dup(const CKKS_Poly *src)
{
    if (src == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    uint32_t m = src->polyctx->m;
    CKKS_Poly *dst = (CKKS_Poly *)BSL_SAL_Malloc(sizeof(CKKS_Poly));
    int32_t ret = CKKS_PolyCtx_Set(dst->polyctx, src->polyctx->bits, src->polyctx->m);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        CKKS_Poly_Destroy(dst);
        return NULL;
    }
    dst->degree = src->degree;
    dst->coeffs = (BN_BigNum **)BSL_SAL_Malloc((m / 2) * sizeof(BN_BigNum *));
    if (dst->coeffs == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        BSL_SAL_Free(dst);
        return NULL;
    }
    for (uint32_t i = 0; i <= src->degree; i++) {
        dst->coeffs[i] = BN_Dup(src->coeffs[i]);
        if (dst->coeffs[i] == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            CKKS_Poly_Destroy(dst);
            return NULL;
        }
    }
    return dst;
}

int32_t CKKS_Poly_Set_Coeff(CKKS_Poly *poly, uint32_t index, BN_BigNum *coeff)
{
    if (poly == NULL || index > poly->degree) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = BN_Copy(poly->coeffs[index], coeff);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

int32_t CKKS_Poly_Get_Coeff(BN_BigNum *coeff, const CKKS_Poly *poly, uint32_t index)
{
    if (poly == NULL || poly->coeffs == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    BN_BigNum *bn_0 = BN_Create(poly->polyctx->bits);
    int32_t ret = BN_Zeroize(bn_0);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    if (index > poly->degree) {
        ret = BN_Copy(coeff, bn_0);
    } else {
        ret = BN_Copy(coeff, poly->coeffs[index]);
    }
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
ERR:
    BN_Destroy(bn_0);
    return ret;
}

int32_t CKKS_Poly_ZeroizeCoeffs(CKKS_Poly *poly)
{
    int32_t ret;
    if (poly == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    for (uint32_t i = 0; i <= poly->degree; i++) {
        ret = BN_Zeroize(poly->coeffs[i]);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    return ret;
}

int32_t CKKS_PolyCtx_Set(CKKS_PolyCtx *poly_ctx, uint32_t bits, uint32_t m)
{
    if (poly_ctx == NULL || m == 0 || (m != 0 && (m & (m - 1)) == 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    poly_ctx->bits = bits;
    poly_ctx->m = m;
    poly_ctx->phiM = m / 2;
    poly_ctx->logM = (int)(log2(m) + 0.5); // 0.5 is added to avoid floating point errors
    poly_ctx->slots_size = m / 4;
    if (poly_ctx->T == NULL) {
        poly_ctx->T = (uint32_t *)BSL_SAL_Malloc(poly_ctx->slots_size * sizeof(uint32_t));
    }
    if (poly_ctx->Tidx == NULL) {
        poly_ctx->Tidx = (int32_t *)BSL_SAL_Malloc(m * sizeof(int32_t));
    }

    uint32_t *gens = (uint32_t *)BSL_SAL_Malloc(m * sizeof(uint32_t));
    uint32_t gens_sz = Get_ZMStar_Gens(gens, m);
    uint32_t *buffer = (uint32_t *)BSL_SAL_Malloc(gens_sz * sizeof(uint32_t));
    uint32_t *ZMStar = Get_ZMStar(m);
    (void)memset_s(buffer, gens_sz * sizeof(uint32_t), 0, gens_sz * sizeof(uint32_t));
    (void)memset_s(poly_ctx->Tidx, m * sizeof(uint32_t), -1, m * sizeof(uint32_t));

    uint32_t ctr = 0;
    int32_t i = 0;
    do {
        ctr++;
        uint32_t t = Get_T_Ele(buffer, gens_sz, gens, gens_sz, m);
        poly_ctx->T[i] = t;
        poly_ctx->Tidx[t] = i++;
    } while (Lexico_Order(buffer, ZMStar, gens_sz, m / 2));
    if (ctr != poly_ctx->slots_size) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_ERR_CAL_VALUE);
        return CRYPT_CKKS_ERR_CAL_VALUE;
    }
    BSL_SAL_Free(gens);
    BSL_SAL_Free(buffer);
    return CRYPT_SUCCESS;
}

int32_t CKKS_PolyCtx_Copy(CKKS_PolyCtx *dst, const CKKS_PolyCtx *src)
{
    if (dst == NULL || src == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    dst->bits = src->bits;
    dst->m = src->m;
    dst->phiM = src->phiM;
    dst->logM = src->logM;
    dst->slots_size = src->slots_size;
    return CRYPT_SUCCESS;
}

bool CKKS_PolyCtx_Cmp(const CKKS_PolyCtx *Pctx1, const CKKS_PolyCtx *Pctx2)
{
    if (Pctx1 == NULL || Pctx2 == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return false;
    }
    if ((Pctx1->bits == Pctx2->bits) && (Pctx1->m == Pctx2->m) && (Pctx1->phiM == Pctx2->phiM) &&
        (Pctx1->logM == Pctx2->logM) && (Pctx1->slots_size == Pctx2->slots_size)) {
        return true;
    }
    return false;
}

int32_t CKKS_Poly_Normalized(CKKS_Poly *poly)
{
    int32_t ret;
    if (poly == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    int32_t max_deg = (int32_t)poly->degree;
    if (max_deg < 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG); // zero polynomial
        return CRYPT_INVALID_ARG;
    }
    BN_BigNum *bn_0 = BN_Create(poly->polyctx->bits);
    ret = BN_Zeroize(bn_0);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    while (max_deg >= 0 && BN_Cmp(poly->coeffs[max_deg], bn_0)) {
        max_deg--;
    }
    poly->degree = (uint32_t)max_deg;
    BN_Destroy(bn_0);
    return ret;
}

int32_t CKKS_Poly_Add(CKKS_Poly *res, const CKKS_Poly *p1, const CKKS_Poly *p2)
{
    if (res == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (!CKKS_PolyCtx_Cmp(p1->polyctx, p2->polyctx)) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_INCOMPATIBLE_OBJECT);
        return CRYPT_CKKS_INCOMPATIBLE_OBJECT;
    }
    int32_t ret;
    uint32_t max_deg = (p1->degree > p2->degree) ? p1->degree : p2->degree;
    res->degree = max_deg;
    for (uint32_t i = 0; i <= max_deg; i++) {
        ret = BN_Add(res->coeffs[i], p1->coeffs[i], p2->coeffs[i]);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    ret = CKKS_PolyCtx_Copy(res->polyctx, p1->polyctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return ret;
}

int32_t CKKS_Poly_Mul(CKKS_Poly *res, const CKKS_Poly *p1, const CKKS_Poly *p2, BN_Optimizer *opt)
{
    if (res == NULL || p1 == NULL || p2 == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (!CKKS_PolyCtx_Cmp(p1->polyctx, p2->polyctx)) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_INCOMPATIBLE_OBJECT);
        return CRYPT_CKKS_INCOMPATIBLE_OBJECT;
    }
    int32_t ret;
    uint32_t bits = p1->polyctx->bits;
    uint32_t new_deg = p1->degree + p2->degree;
    res->degree = new_deg;
    ret = CKKS_Poly_Init(res, p1->polyctx->bits, p1->polyctx->m);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    for (uint32_t i = 0; i <= new_deg; i++) {
        for (uint32_t j = 0; j <= new_deg; j++) {
            BN_BigNum *temp = BN_Create(bits);
            ret = BN_Mul(temp, p1->coeffs[i], p2->coeffs[j], opt);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            ret = BN_Add(res->coeffs[i + j], res->coeffs[i + j], temp);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            BN_Destroy(temp);
        }
    }
    return ret;
}

int32_t CKKS_Poly_Int_Mul(CKKS_Poly *res, const CKKS_Poly *p, const uint32_t w, BN_Optimizer *opt)
{
    if (res == NULL || p == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret;
    uint32_t bits = p->polyctx->bits;
    uint32_t new_deg = p->degree;
    res->degree = new_deg;
    ret = CKKS_Poly_Init(res, p->polyctx->bits, p->polyctx->m);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    for (uint32_t i = 0; i <= new_deg; i++) {
        for (uint32_t j = 0; j <= new_deg; j++) {
            BN_BigNum *temp = BN_Create(bits);
            ret = BN_SetLimb(temp, w);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            ret = BN_Mul(temp, p->coeffs[i], temp, opt);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            BN_Destroy(temp);
        }
    }
    return ret;
}

/*************************** Modular chain **************************/
/********************************************************************/

bool Check_Prime_In_Chain(const CKKS_Moduli *moduli, const BN_BigNum *q)
{
    for (size_t i = 0; i < moduli->modLen; i++) {
        if (BN_Cmp(moduli->primes[i], q) == 0) {
            return true;
        }
    }
    return false;
}

BN_BigNum *Get_ModularQ(const CKKS_Moduli *moduli, uint32_t nbits, BN_Optimizer *opt)
{
    if (moduli == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    BN_BigNum *Q = BN_Create(nbits);
    int32_t ret = BN_Copy(Q, moduli->primes[0]);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }

    uint32_t i = 1;
    while (i < moduli->modLen) {
        ret = BN_Mul(Q, Q, moduli->primes[i], opt);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return NULL;
        }
    }
    return Q;
}

uint32_t CKKS_Get_Prime_Size(uint32_t nBits)
{
    double x = -1.0 / (1u << PRIME_BIT_BOUND);
    double bit_loss = -log1p(x) / log(2.0);
    uint32_t maxPsize = SIMD_MAX_NBITS - bit_loss;
    uint32_t nprimes = (nBits + maxPsize - 1) / maxPsize;
    uint32_t len = SIMD_MAX_NBITS;
    while (len > 30 && 10 * len >= 9 * SIMD_MAX_NBITS && (len - bit_loss) * nprimes >= nBits) {
        len--;
    }
    return len;
}

BN_BigNum *CKKS_Gen_Ctx_Prime(uint32_t len, const BN_BigNum *q_lowerB, const BN_BigNum *q_upperB,
                              const BN_BigNum *m_lshift_k, const uint32_t m, uint32_t k, BN_Optimizer *opt)
{
    /** q_cand=2^k*t*m+1 to satisify q_cand=1(mod m*2^k). 2^len - 2^{len-3} <= q_cand < 2^len).The upper bopund of t is ceil((2^{len}-1)/(m*2^k))*/
    BN_BigNum *t_upperB = BN_Create(len);
    BN_BigNum *q_upperB_dec = BN_Create(len);
    int32_t ret = BN_SubLimb(q_upperB_dec, q_upperB, 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_ERR_CAL_VALUE);
        return NULL;
    }
    ret = BN_Div(t_upperB, NULL, q_upperB_dec, m_lshift_k, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_ERR_CAL_VALUE);
        return NULL;
    }

    BN_BigNum *t = BN_Dup(t_upperB);
    while (1) {
        ret = BN_AddLimb(t, t, 1);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(CRYPT_CKKS_ERR_CAL_VALUE);
            return NULL;
        }
        if (BN_Cmp(t, t_upperB) >= 0) {
            k--;
            uint32_t k_lowerB = (m % 2 == 0) ? 0 : 1;
            if (k < k_lowerB) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return NULL;
            }
            ret = BN_SubLimb(t, q_lowerB, 1);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(CRYPT_CKKS_ERR_CAL_VALUE);
                return NULL;
            }
            ret = BN_Div(t, NULL, t, m_lshift_k, opt);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(CRYPT_CKKS_ERR_CAL_VALUE);
                return NULL;
            }
            ret = BN_Div(t_upperB, NULL, q_upperB_dec, m_lshift_k, opt);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(CRYPT_CKKS_ERR_CAL_VALUE);
                return NULL;
            }
        }

        /** An even number t may lead to more cases where it is easy to judge that the number is not prime, and by considering only odd t, 
         * it is possible to skip these candidate values that clearly do not meet the prime condition, reducing redundant prime test calculations. */
        if (BN_IsOdd(t) == false) {
            continue;
        }
        BN_BigNum *q_cand = BN_Create(len);
        ret = BN_Mul(q_cand, t, m_lshift_k, opt);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(CRYPT_CKKS_ERR_CAL_VALUE);
            return NULL;
        }
        ret = BN_AddLimb(q_cand, q_cand, 1);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(CRYPT_CKKS_ERR_CAL_VALUE);
            return NULL;
        }

        if (BN_Cmp(q_lowerB, q_cand) == 1 || BN_Cmp(q_upperB, q_cand) <= 0) {
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return NULL;
        }

        ret = BN_PrimeCheck(q_cand, opt);
        if (ret != CRYPT_SUCCESS) {
            BN_Destroy(q_cand);
        } else {
            BN_Destroy(t_upperB);
            BN_Destroy(q_upperB_dec);
            BN_Destroy(t);
            return q_cand;
        }
    }
}

int32_t CKKS_Add_Ctx_Prime(CKKS_Moduli *moduli, const BN_BigNum *q)
{
    int32_t ret = CRYPT_INVALID_ARG;
    if (Check_Prime_In_Chain(moduli, q)) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (moduli->modLen >= moduli->mod_capacity) {
        size_t new_capacity = (moduli->mod_capacity == 0) ? 4 : moduli->mod_capacity * 2;
        BN_BigNum **new_primes = (BN_BigNum **)BSL_SAL_Realloc(moduli->primes, new_capacity * sizeof(BN_BigNum *),
                                                               moduli->modLen * sizeof(BN_BigNum *));
        if (new_primes == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
        moduli->primes = new_primes;
        moduli->mod_capacity = new_capacity;
    }
    if (moduli->primes[moduli->modLen] == NULL) {
        moduli->primes[moduli->modLen] = BN_Create(BN_Bits(q));
    }
    ret = BN_Copy(moduli->primes[moduli->modLen], q);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        CKKS_Moduli_Destroy(moduli);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    moduli->modLen++;
    return ret;
}

int32_t CKKS_Gen_Ctx_Primes(CKKS_Moduli *moduli, uint32_t m, uint32_t nBits, uint32_t len, BN_Optimizer *opt)
{
    /** The product of the chain of modes must be large enough to resist noise growth */
    if (len < 30) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    /** By allowing a floating lower limit of 0.9 times, a certain margin can be left for the prime number generation process to ensure that
     *  the actual prime number is still close to the design goal even under the influence of bit loss */
    if (len < 0.9 * SIMD_MAX_NBITS || len > SIMD_MAX_NBITS) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    int32_t ret;
    uint32_t k = 0;
    BN_BigNum *bn_m = BN_Create(len);
    BN_BigNum *interval = BN_Create(len);
    BN_BigNum *q_lowerB = BN_Create(len);
    BN_BigNum *q_upperB = BN_Create(len);
    BN_BigNum *two_to_k = BN_Create(k + 1);
    BN_BigNum *m_lshift_k = BN_Create(len);
    if (bn_m == NULL || q_lowerB == NULL || q_upperB == NULL || two_to_k == NULL||m_lshift_k==NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto EXIT;
    }
    ret = BN_SetLimb(bn_m, m);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = BN_SetBit(q_upperB, len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = BN_SetBit(interval, (len - PRIME_BIT_BOUND));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = BN_Sub(q_lowerB, q_upperB, interval);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret=BN_Copy(m_lshift_k,bn_m);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    while (BN_Cmp(m_lshift_k, q_lowerB) != 0) {
        ret = BN_SetBit(two_to_k, k);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }
        ret = BN_Mul(m_lshift_k, bn_m, two_to_k, opt);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }
        k++;
    }

    double bitLen = 0;
    while (bitLen < nBits - 0.5) {
        BN_BigNum *q = CKKS_Gen_Ctx_Prime(len, q_lowerB, q_upperB, m_lshift_k, m, k, opt);
        if (q == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            ret = CRYPT_MEM_ALLOC_FAIL;
            goto EXIT;
        }
        ret = CKKS_Add_Ctx_Prime(moduli, q);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }
        bitLen += BN_Bits(q);
    }
EXIT:
    BN_Destroy(bn_m);
    BN_Destroy(interval);
    BN_Destroy(q_lowerB);
    BN_Destroy(q_upperB);
    BN_Destroy(m_lshift_k);
    BN_Destroy(two_to_k);
    return ret;
}

int32_t Build_Ctx_Primes(CKKS_Moduli *moduli, CRYPT_CKKS_Para *para, BN_Optimizer *opt)
{
    if (moduli == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    uint32_t nBits = para->bits;
    uint32_t m = para->m;
    moduli->modLen = 0;
    moduli->mod_capacity = 0;
    uint32_t qlen = CKKS_Get_Prime_Size(nBits);
    para->qsz = qlen;
    if (qlen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_ERR_CAL_VALUE);
        return CRYPT_CKKS_ERR_CAL_VALUE;
    }
    int32_t ret = CKKS_Gen_Ctx_Primes(moduli, m, nBits, qlen, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return ret;
}

int32_t CKKS_Moduli_Copy(CKKS_Moduli *dst, CKKS_Moduli *src)
{
    if (dst == NULL || src == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    dst->modLen = src->modLen;
    dst->mod_capacity = src->mod_capacity;
    for (uint32_t i = 0; i <= src->modLen; i++) {
        dst->primes[i] = BN_Dup(src->primes[i]);
        if (dst->primes[i] == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            CKKS_Moduli_Destroy(dst);
            return CRYPT_MEM_ALLOC_FAIL;
        }
    }
    return CRYPT_SUCCESS;
}

CKKS_Moduli *CKKS_Moduli_Dup(const CKKS_Moduli *src)
{
    if (src == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    CKKS_Moduli *dst = (CKKS_Moduli *)BSL_SAL_Malloc(sizeof(CKKS_Moduli));
    dst->primes = (BN_BigNum **)BSL_SAL_Malloc(src->modLen * sizeof(BN_BigNum *));
    dst->modLen = src->modLen;
    dst->mod_capacity = src->mod_capacity;
    for (uint32_t i = 0; i <= src->modLen; i++) {
        dst->primes[i] = BN_Dup(src->primes[i]);
        if (dst->primes[i] == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            CKKS_Moduli_Destroy(dst);
            return NULL;
        }
    }
    return dst;
}

bool CKKS_Moduli_Cmp(const CKKS_Moduli *m1, const CKKS_Moduli *m2)
{
    if (m1 == NULL || m2 == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (m1->modLen == m2->modLen) {
        for (uint32_t i = 0; i <= m1->modLen; i++) {
            if (BN_Cmp(m1->primes[i], m2->primes[i]) != 0) {
                return false;
            }
        }
    }
    return true;
}

void CKKS_Moduli_Destroy(CKKS_Moduli *moduli)
{
    if (moduli != NULL && moduli->primes != NULL) {
        for (uint32_t i = 0; i < moduli->modLen; i++) {
            BN_Destroy(moduli->primes[i]);
        }
    }
    BSL_SAL_Free(moduli);
}

/************************ DoubleCRT Operation ***********************/
/********************************************************************/

int32_t CKKS_DoubleCRT_Init(CKKS_DoubleCRT *doubleCRT, uint32_t bits, uint32_t m, const CKKS_Moduli *moduli)
{
    if (doubleCRT == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    doubleCRT->poly = (CKKS_Poly *)BSL_SAL_Malloc(sizeof(CKKS_Poly *));
    if (doubleCRT->poly == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = CKKS_Poly_Init(doubleCRT->poly, bits, m);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    doubleCRT->map = (BN_BigNum **)BSL_SAL_Malloc(moduli->modLen * (m / 2) * sizeof(BN_BigNum *));
    if (doubleCRT->map == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
    doubleCRT->L = moduli->modLen;
    return CRYPT_SUCCESS;

ERR:
    CKKS_DoubleCRT_Destroy(doubleCRT);
    return ret;
}

int32_t Randomize_Map(BN_BigNum **map, const CKKS_Moduli *moduli, uint32_t phiM)
{
    if (moduli == NULL || map == NULL || phiM <= 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret;
    for (uint32_t i = 0; i < moduli->modLen; i++) {
        BN_BigNum *max_pad = BN_Dup(moduli->primes[i]);
        ret = BN_SubLimb(max_pad, max_pad, 1);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        uint32_t bit = BN_Bits(max_pad);
        uint32_t j = 0;
        while (j < phiM) {
            BN_BigNum *rand_bn = BN_Create(bit);
            ret = BN_RandRange(rand_bn, max_pad);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            ret = BN_Copy(map[i * phiM + j], rand_bn);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            j++;
        }
    }
    return ret;
}

int32_t CKKS_Map_Copy(BN_BigNum **dst, BN_BigNum **src, uint32_t row, uint32_t column)
{
    if (dst == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret=CRYPT_SUCCESS;
    for (uint32_t i = 0; i < row; i++) {
        for (uint32_t j = 0; i < column; i++) {
            dst[i * column + j] = BN_Dup(src[i * column + j]);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
        }
    }
    return ret;
}

bool CKKS_Map_Cmp(BN_BigNum **m1, BN_BigNum **m2, uint32_t row, uint32_t column)
{
    if(m1==NULL||m2==NULL){
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return false;
    }
    for (uint32_t i = 0; i < row; i++) {
        for (uint32_t j = 0; i < column; i++) {
            if (BN_Cmp(m1[i * column + j], m2[i * column + j]) != 0) {
                BSL_ERR_PUSH_ERROR(CRYPT_CKKS_INCOMPATIBLE_OBJECT);
                return false;
            }
        }
    }
    return true;
}

void CKKS_Map_Destroy(BN_BigNum **map, uint32_t row, uint32_t column)
{
    for (uint32_t i = 0; i < row; i++) {
        for (uint32_t j = 0; j < column; j++) {
            BN_Destroy(map[i * column + j]);
        }
    }
}

int32_t CKKS_Poly2DoubleCRT(CKKS_DoubleCRT *doubleCRT, const CKKS_Poly *poly, const CKKS_Moduli *moduli,
                            BN_Optimizer *optimizer)
{
    if (doubleCRT == NULL || poly == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret;
    uint32_t L = doubleCRT->L;
    uint32_t phiM = poly->polyctx->phiM;
    uint32_t qsz = moduli->qsz;

    for (uint32_t i = 0; i < L; i++) {
        for (uint32_t j = 0; i < phiM; j++) {
            BN_BigNum *tmp = BN_Create(qsz);
            ret = BN_Mod(tmp, poly->coeffs[i], moduli->primes[j], optimizer);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            ret = BN_Copy(doubleCRT->map[i * phiM + j], tmp);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            BN_Destroy(tmp);
        }
    }
    return ret;
}

int32_t CKKS_DoubleCRT_AddSubMul(CKKS_DoubleCRT *res, const CKKS_DoubleCRT *d1, const CKKS_DoubleCRT *d2,
                                 CKKS_Moduli *moduli, BN_Optimizer *opt, const int32_t flag)
{
    if (!CKKS_PolyCtx_Cmp(d1->poly->polyctx, d2->poly->polyctx)) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_INCOMPATIBLE_OBJECT);
        return CRYPT_CKKS_INCOMPATIBLE_OBJECT;
    }
    int32_t ret;
    uint32_t L = d1->L;
    uint32_t phiM = d1->poly->polyctx->phiM;

    for (uint32_t i = 0; i < L; i++) {
        for (uint32_t j = 0; i < phiM; j++) {
            switch (flag) {
                case 0:
                    ret = BN_ModAdd(res->map[i * phiM + j], d1->map[i * phiM + j], d2->map[i * phiM + j],
                                    moduli->primes[i], opt);
                    break;
                case 1:
                    ret = BN_ModSub(res->map[i * phiM + j], d1->map[i * phiM + j], d2->map[i * phiM + j],
                                    moduli->primes[i], opt);
                    break;
                case 2:
                    ret = BN_ModMul(res->map[i * phiM + j], d1->map[i * phiM + j], d2->map[i * phiM + j],
                                    moduli->primes[i], opt);
                    break;
                default:
                    BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                    ret = CRYPT_INVALID_ARG;
                    break;
            }
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
        }
    }
    return ret;
}

int32_t CKKS_DoubleCRT_Copy(CKKS_DoubleCRT *dst, const CKKS_DoubleCRT *src)
{
    if (dst == NULL || src == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret;
    uint32_t phiM = src->poly->polyctx->phiM;
    uint32_t L = src->L;

    dst->L = src->L;
    if (dst->poly->coeffs == NULL) {
        dst->poly->coeffs = BSL_SAL_Malloc(phiM * sizeof(BN_BigNum *));
    }
    if (dst->poly->coeffs == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        CKKS_Poly_Destroy(dst->poly);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = CKKS_Poly_Copy(dst->poly, src->poly);
    if (ret != CRYPT_SUCCESS) {
        CKKS_Poly_Destroy(dst->poly);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (dst->map == NULL) {
        dst->map = (BN_BigNum **)BSL_SAL_Malloc(phiM * L * sizeof(BN_BigNum *));
    }
    if (dst->map == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        CKKS_DoubleCRT_Destroy(dst);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    ret = CKKS_Map_Copy(dst->map, src->map, L, phiM);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        CKKS_DoubleCRT_Destroy(dst);
        return ret;
    }
    return ret;
}

CKKS_DoubleCRT *CKKS_DoubleCRT_Dup(const CKKS_DoubleCRT *src)
{
    if (src == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    int32_t ret;
    uint32_t phiM = src->poly->polyctx->phiM;

    CKKS_DoubleCRT *dst = (CKKS_DoubleCRT *)BSL_SAL_Malloc(sizeof(CKKS_DoubleCRT));
    dst->poly = (CKKS_Poly *)BSL_SAL_Malloc(sizeof(CKKS_Poly *));
    if (dst->poly == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    ret = CKKS_Poly_Copy(dst->poly, src->poly);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }

    dst->map = (BN_BigNum **)BSL_SAL_Malloc(src->L * phiM * sizeof(BN_BigNum *));
    if (dst->map == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    ret = CKKS_Map_Copy(dst->map, src->map, src->L, phiM);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    dst->L = src->L;
    return dst;
}

void CKKS_DoubleCRT_Destroy(CKKS_DoubleCRT *doubleCRT)
{
    if (doubleCRT != NULL) {
        uint32_t column = doubleCRT->poly->polyctx->phiM;
        uint32_t row = doubleCRT->L;
        if (doubleCRT->poly != NULL) {
            CKKS_Poly_Destroy(doubleCRT->poly);
        }
        if (doubleCRT->map != NULL) {
            CKKS_Map_Destroy(doubleCRT->map, row, column);
        }
    }
    BSL_SAL_Free(doubleCRT);
}

int32_t CKKS_DoubleCRT2Bin(const CKKS_DoubleCRT *doubleCRT, uint8_t *bin, uint32_t *binLen)
{
    if (doubleCRT == NULL || bin == NULL || binLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CKKS_PolyCtx *ctx = doubleCRT->poly->polyctx;
    uint8_t *ptr = bin;
    uint32_t totalSize = 0;

    totalSize += sizeof(uint32_t); // L
    totalSize += 5 * sizeof(uint32_t); // bits, m, phiM, logM, slots_size
    if (ctx->T) {
        totalSize += sizeof(uint32_t) * ctx->slots_size;
    }
    if (ctx->Tidx) {
        totalSize += sizeof(int32_t) * ctx->m;
    }

    for (uint32_t i = 0; i < ctx->phiM; i++) { // coeffs
        BN_BigNum *bn = BN_Dup(doubleCRT->poly->coeffs[i]);
        uint32_t bytes = BN_Bytes(bn);
        bytes = (bytes == 0) ? 1 : bytes;
        totalSize += sizeof(uint32_t) + bytes; // Length + data
    }

    for (uint32_t i = 0; i < doubleCRT->L; i++) { // map
        for (uint32_t j = 0; j < ctx->phiM; j++) {
            BN_BigNum *bn = BN_Dup(doubleCRT->map[i * ctx->phiM + j]);
            uint32_t bytes = BN_Bytes(bn);
            bytes = (bytes == 0) ? 1 : bytes;
            totalSize += sizeof(uint32_t) + bytes; // Length + data
            BN_Destroy(bn);
        }
    }

    uint8_t *originalBin = bin;
    bin = (uint8_t *)BSL_SAL_Realloc(bin, totalSize, *binLen);
    if (bin == NULL) {
        BSL_SAL_FREE(originalBin);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    *binLen = totalSize;

    memcpy_s(ptr, totalSize, &doubleCRT->L, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    memcpy_s(ptr, totalSize, &ctx->bits, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy_s(ptr, totalSize, &ctx->m, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy_s(ptr, totalSize, &ctx->phiM, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy_s(ptr, totalSize, &ctx->logM, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy_s(ptr, totalSize, &ctx->slots_size, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    uint32_t t_len = ctx->slots_size;
    memcpy_s(ptr, totalSize, &t_len, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy_s(ptr, totalSize, ctx->T, t_len * sizeof(uint32_t));
    ptr += t_len * sizeof(uint32_t);

    uint32_t tidx_len = ctx->m;
    memcpy_s(ptr, totalSize, &tidx_len, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy_s(ptr, totalSize, ctx->Tidx, tidx_len * sizeof(int32_t));
    ptr += tidx_len * sizeof(int32_t);

    for (uint32_t i = 0; i < doubleCRT->L; i++) {
        for (uint32_t j = 0; j < ctx->phiM; j++) {
            BN_BigNum *bn = BN_Dup(doubleCRT->map[i * ctx->phiM + j]);
            uint32_t bytes = BN_Bytes(bn);
            bytes = (bytes == 0) ? 1 : bytes;
            uint8_t *tmp = (uint8_t *)BSL_SAL_Malloc(bytes);
            uint32_t tmp_len = bytes;
            int32_t ret = BN_Bn2Bin(bn, tmp, &tmp_len);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                BN_Destroy(bn);
                BSL_SAL_Free(tmp);
                return ret;
            }
            memcpy_s(ptr, totalSize, &tmp_len, sizeof(uint32_t));
            ptr += sizeof(uint32_t);
            memcpy_s(ptr, totalSize, tmp, tmp_len);
            ptr += tmp_len;
            BN_Destroy(bn);
            BSL_SAL_Free(tmp);
        }
    }
    return CRYPT_SUCCESS;
}

int32_t CKKS_Bin2DoubleCRT(CKKS_DoubleCRT *doubleCRT, const uint8_t *bin, uint32_t binLen)
{
    if (doubleCRT == NULL || bin == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    int32_t ret;
    const uint8_t *ptr = bin;
    uint32_t bytesRead = 0;

    uint32_t L; // Read L
    memcpy_s(&L, sizeof(uint32_t), ptr, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    bytesRead += sizeof(uint32_t);
    doubleCRT->L = L;

    CKKS_PolyCtx *ctx = (CKKS_PolyCtx *)BSL_SAL_Malloc(sizeof(CKKS_PolyCtx)); // Read polyctx
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    memcpy_s(&ctx->bits, sizeof(uint32_t), ptr, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy_s(&ctx->m, sizeof(uint32_t), ptr, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy_s(&ctx->phiM, sizeof(uint32_t), ptr, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy_s(&ctx->logM, sizeof(uint32_t), ptr, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy_s(&ctx->slots_size, sizeof(uint32_t), ptr, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    bytesRead += 5 * sizeof(uint32_t);

    ctx->T = (uint32_t *)BSL_SAL_Malloc(ctx->slots_size * sizeof(uint32_t)); // Read T
    if (ctx->T == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
    memcpy_s(ctx->T, ctx->slots_size * sizeof(uint32_t), ptr, ctx->slots_size * sizeof(uint32_t));
    ptr += ctx->slots_size * sizeof(uint32_t);
    bytesRead += ctx->slots_size * sizeof(uint32_t);

    ctx->Tidx = (int32_t *)BSL_SAL_Malloc(ctx->m * sizeof(int32_t)); // Read Tidx
    if (ctx->Tidx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
    memcpy(ctx->Tidx, ptr, ctx->m * sizeof(int32_t));
    ptr += ctx->m * sizeof(int32_t);
    bytesRead += ctx->m * sizeof(int32_t);

    doubleCRT->poly = (CKKS_Poly *)BSL_SAL_Malloc(sizeof(CKKS_Poly)); // Read poly
    if (doubleCRT->poly == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
    doubleCRT->poly->polyctx = ctx;
    doubleCRT->poly->degree = ctx->phiM - 1;

    doubleCRT->map = (BN_BigNum **)BSL_SAL_Malloc(L * ctx->phiM * sizeof(BN_BigNum *)); // Read map
    if (doubleCRT->map == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }

    for (uint32_t i = 0; i < L; i++) {
        for (uint32_t j = 0; j < ctx->phiM; j++) {
            uint32_t bn_len;
            memcpy_s(&bn_len, sizeof(uint32_t), ptr, sizeof(uint32_t));
            ptr += sizeof(uint32_t);
            bytesRead += sizeof(uint32_t);
            ret = BN_Bin2Bn(doubleCRT->map[i * ctx->phiM + j], ptr, bn_len);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                goto ERR;
            }
            ptr += bn_len;
            bytesRead += bn_len;
        }
    }

    if (bytesRead != binLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_ERR_CAL_VALUE);
        ret = CRYPT_CKKS_ERR_CAL_VALUE;
        goto ERR;
    }
    return CRYPT_SUCCESS;
ERR:
    BSL_SAL_Free(ctx->T);
    BSL_SAL_Free(ctx->Tidx);
    BSL_SAL_Free(ctx);
    BSL_SAL_Free(doubleCRT->map);
    return ret;
}

int32_t CKKS_DoubleCRT_Cipher2Bin(CKKS_DoubleCRT *crt1, CKKS_DoubleCRT *crt2, uint8_t *bin, uint32_t *binLen)
{
    if (crt1 == NULL || crt2 == NULL || bin == NULL || binLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    uint32_t len1 = 0;
    uint32_t len2 = 0;
    uint32_t totalSize = 0;
    uint8_t *ptr = bin;
    uint8_t *bin1 = (uint8_t *)BSL_SAL_Malloc(len1);
    uint8_t *bin2 = (uint8_t *)BSL_SAL_Malloc(len2);
    int32_t ret = CKKS_DoubleCRT2Bin(crt1, bin1, &len1);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    bin1 = (uint8_t *)BSL_SAL_Malloc(len1);
    ret = CKKS_DoubleCRT2Bin(crt1, bin1, &len1);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(bin1);
        return ret;
    }
    ret = CKKS_DoubleCRT2Bin(crt2, bin2, &len2);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(bin1);
        BSL_SAL_Free(bin2);
        return ret;
    }
    totalSize = len1 + len2 + 2 * sizeof(uint32_t); // sizeof(crt1)+sizeof(crt2)+sizeof(len1)+sizeof(len2)
    if (*binLen < totalSize) {
        BSL_SAL_Free(bin1);
        BSL_SAL_Free(bin2);
        BSL_ERR_PUSH_ERROR(CRYPT_BN_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_BN_BUFF_LEN_NOT_ENOUGH;
    }

    memcpy_s(ptr, totalSize, &len1, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy_s(ptr, totalSize, bin1, len1);
    ptr += len1;
    memcpy_s(ptr, totalSize, &len2, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy_s(ptr, totalSize, bin2, len2);
    ptr += len2;
    *binLen = totalSize;

    BSL_SAL_Free(bin1);
    BSL_SAL_Free(bin2);

    return CRYPT_SUCCESS;
}

int32_t CKKS_DoubleCRT_Bin2Cipher(const uint8_t *bin, uint32_t binLen, CKKS_DoubleCRT *crt1, CKKS_DoubleCRT *crt2)
{
    if (bin == NULL || crt1 == NULL || crt2 == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    uint32_t len1 = 0, len2 = 0;

    // Reads the length of the first CKKS_DoubleCRT
    const uint8_t *ptr = bin;
    uint32_t bytesRead = 0;

    // Read len1
    memcpy_s(&len1, sizeof(uint32_t), ptr, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    bytesRead += sizeof(uint32_t);
    int32_t ret = CKKS_Bin2DoubleCRT(crt1, ptr, len1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    bytesRead += len1;

    memcpy_s(&len2, sizeof(uint32_t), ptr, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    bytesRead += sizeof(uint32_t);
    ret = CKKS_Bin2DoubleCRT(crt2, ptr, len2);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    bytesRead += len2;

    if (bytesRead != binLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_ERR_CAL_VALUE);
        return CRYPT_CKKS_ERR_CAL_VALUE;
    }

    return CRYPT_SUCCESS;
}

#endif //HITLS_CRYPTO_CKKS