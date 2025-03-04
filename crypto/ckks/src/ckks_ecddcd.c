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

#include "crypt_utils.h"
#include "crypt_ckks.h"
#include "ckks_local.h"
#include "ckks_ecddcd.h"
#include "crypt_errno.h"
#include "securec.h"
#include "bsl_err_internal.h"

#define CKKS_FFT_Granularity 4 //Granularity of upward alignment
#define CKKS_FFT_THRESH      10

#if defined(PD4_START)
int32_t CKKS_FFT_SIMD_Enabled()
{
    return true;
}

void *CKKS_Aligned_Allocate(size_t n, size_t n_size)
{
    if (n > SIZE_MAX / n_size || n == 0 || n_size == 0) {
        return NULL;
    }
    size_t sz = n * n_size;
    size_t alignment = CKKS_FFT_ALIGN;
    if (sz > SIZE_MAX - alignment) {
        return NULL;
    }
    sz += alignment;
    char *buffer = (char *)BSL_SAL_Malloc(sz);
    if (buffer == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    uintptr_t ptr_addr = (uintptr_t)buffer;
    uint8_t offset = alignment - (ptr_addr % alignment);
    offset = (offset == alignment) ? 0 : offset;
    char *aligned_ptr = buffer + offset;
    aligned_ptr[-1] = offset; // The offset information is stored for subsequent release
    return aligned_ptr;
}

void CKKS_Aligned_Deallocate(void *ptr)
{
    if (ptr == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return;
    }
    char *aligned_ptr = (char *)ptr;
    char *orginal_ptr = aligned_ptr - aligned_ptr[-1];
    BSL_SAL_Free(orginal_ptr);
}

static inline void Fwd_Butterfly_Cal(uint32_t size, CKKS_Complex *xp0, CKKS_Complex *xp1,
                                     const CKKS_Complex *twiddle_tab)
{
    /** The SIMD instruction can directly manipulate the original double precision data 
     * by using the characteristic of continuous storage of complex type in memory */
    double *d_xp0 = (double *)xp0;
    double *d_xp1 = (double *)xp1;
    const double *d_wtab = (const double *)twiddle_tab;
    for (uint32_t j = 0; j < size; j += 4) {
        __m256d x0_0 = PD4_Load(d_xp0 + 2 * (j + 0));
        __m256d x0_1 = PD4_Load(d_xp0 + 2 * (j + 2));
        __m256d x1_0 = PD4_Load(d_xp1 + 2 * (j + 0));
        __m256d x1_1 = PD4_Load(d_xp1 + 2 * (j + 2));
        __m256d w_0 = PD4_Load(d_wtab + 2 * (j + 0));
        __m256d w_1 = PD4_Load(d_wtab + 2 * (j + 2));

        __m256d xx0_0 = PD4_Add(x0_0, x1_0);
        __m256d xx0_1 = PD4_Add(x0_1, x1_1);

        __m256d diff_0 = PD4_Sub(x0_0, x1_0);
        __m256d diff_1 = PD4_Sub(x0_1, x1_1);

        __m256d xx1_0, xx1_1;
        PD4_Complex_MUL(&xx1_0, &xx1_1, diff_0, diff_1, w_0, w_1);

        PD4_Store(d_xp0 + 2 * (j + 0), xx0_0);
        PD4_Store(d_xp0 + 2 * (j + 2), xx0_1);
        PD4_Store(d_xp1 + 2 * (j + 0), xx1_0);
        PD4_Store(d_xp1 + 2 * (j + 2), xx1_1);
    }
}

static inline void Inv_Butterfly_Cal(uint32_t size, CKKS_Complex *xp0, CKKS_Complex *xp1,
                                     const CKKS_Complex *twiddle_tab)
{
    double *d_xp0 = (double *)xp0;
    double *d_xp1 = (double *)xp1;
    const double *d_wtab = (const double *)twiddle_tab;
    for (uint32_t j = 0; j < size; j += 4) {
        __m256d x0_0 = PD4_Load(d_xp0 + 2 * (j + 0));
        __m256d x0_1 = PD4_Load(d_xp0 + 2 * (j + 2));
        __m256d x1_0 = PD4_Load(d_xp1 + 2 * (j + 0));
        __m256d x1_1 = PD4_Load(d_xp1 + 2 * (j + 2));
        __m256d w_0 = PD4_Load(d_wtab + 2 * (j + 0));
        __m256d w_1 = PD4_Load(d_wtab + 2 * (j + 2));

        __m256d *t_0, *t_1;
        PD4_Complex_Conj_MUL(&t_0, &t_1, x1_0, x1_1, w_0, w_1);

        __m256d xx0_0 = PD4_Add(x0_0, t_0);
        __m256d xx0_1 = PD4_Add(x0_1, t_1);

        __m256d xx1_0 = PD4_Sub(x0_0, t_0);
        __m256d xx1_1 = PD4_Sub(x0_1, t_1);

        PD4_Store(d_xp0 + 2 * (j + 0), xx0_0);
        PD4_Store(d_xp0 + 2 * (j + 2), xx0_1);
        PD4_Store(d_xp1 + 2 * (j + 0), xx1_0);
        PD4_Store(d_xp1 + 2 * (j + 2), xx1_1);
    }
}

#else
int32_t CKKS_FFT_SIMD_Enabled()
{
    return false;
}

void *CKKS_Aligned_Allocate(size_t n, size_t n_size)
{
    if (n > SIZE_MAX / n_size) {
        return NULL;
    }
    size_t sz = n * n_size;
    char *ptr = (char *)BSL_SAL_Malloc(sz);
    if (ptr == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    return ptr;
}

void CKKS_Aligned_Deallocate(void *ptr)
{
    if (ptr == NULL) {
        return;
    }
    BSL_SAL_Free(ptr);
}

static inline void Fwd_Factor_W_Mul(CKKS_Complex *xx0, CKKS_Complex *xx1, CKKS_Complex w)
{
    CKKS_Complex x0 = *xx0;
    CKKS_Complex x1 = *xx1;
    CKKS_Complex t = CKKS_Complex_Sub(x0, x1);
    *xx0 = CKKS_Complex_Add(x0, x1);
    *xx1 = CKKS_Complex_Mul(t, w);
}

static inline void Inv_Factor_W_Mul(CKKS_Complex *xx0, CKKS_Complex *xx1, CKKS_Complex w)
{
    CKKS_Complex x0 = *xx0;
    CKKS_Complex x1 = *xx1;
    CKKS_Complex t = CKKS_Complex_Conj_Mul(x1, w);
    *xx0 = CKKS_Complex_Add(x0, t);
    *xx1 = CKKS_Complex_Sub(x0, t);
}

static inline void Fwd_Butterfly_Cal(uint32_t size, CKKS_Complex *xp0, CKKS_Complex *xp1,
                                     const CKKS_Complex *twiddle_tab)
{
    CKKS_Complex complex_one = (CKKS_Complex){1.0, 0.0};
    Fwd_Factor_W_Mul(&xp0[0 + 0], &xp1[0 + 0], complex_one);
    Fwd_Factor_W_Mul(&xp0[0 + 1], &xp1[0 + 1], twiddle_tab[0 + 1]);
    Fwd_Factor_W_Mul(&xp0[0 + 2], &xp1[0 + 2], twiddle_tab[0 + 2]);
    Fwd_Factor_W_Mul(&xp0[0 + 3], &xp1[0 + 3], twiddle_tab[0 + 3]);
    for (long j = 4; j < size; j += 4) {
        Fwd_Factor_W_Mul(&xp0[j + 0], &xp1[j + 0], twiddle_tab[j + 0]);
        Fwd_Factor_W_Mul(&xp0[j + 1], &xp1[j + 1], twiddle_tab[j + 1]);
        Fwd_Factor_W_Mul(&xp0[j + 2], &xp1[j + 2], twiddle_tab[j + 2]);
        Fwd_Factor_W_Mul(&xp0[j + 3], &xp1[j + 3], twiddle_tab[j + 3]);
    }
}

static inline void Inv_Butterfly_Cal(uint32_t size, CKKS_Complex *xp0, CKKS_Complex *xp1,
                                     const CKKS_Complex *twiddle_tab)
{
    CKKS_Complex complex_one = (CKKS_Complex){1.0, 0.0};
    Inv_Factor_W_Mul(&xp0[0 + 0], &xp1[0 + 0], complex_one);
    Inv_Factor_W_Mul(&xp0[0 + 1], &xp1[0 + 1], twiddle_tab[0 + 1]);
    Inv_Factor_W_Mul(&xp0[0 + 2], &xp1[0 + 2], twiddle_tab[0 + 2]);
    Inv_Factor_W_Mul(&xp0[0 + 3], &xp1[0 + 3], twiddle_tab[0 + 3]);
    for (uint32_t j = 4; j < size; j += 4) {
        Inv_Factor_W_Mul(&xp0[j + 0], &xp1[j + 0], twiddle_tab[j + 0]);
        Inv_Factor_W_Mul(&xp0[j + 1], &xp1[j + 1], twiddle_tab[j + 1]);
        Inv_Factor_W_Mul(&xp0[j + 2], &xp1[j + 2], twiddle_tab[j + 2]);
        Inv_Factor_W_Mul(&xp0[j + 3], &xp1[j + 3], twiddle_tab[j + 3]);
    }
}
#endif //PD4_START

uint32_t Adjust_To_Tar_size(uint32_t in_size, uint32_t k)
{
    uint32_t n = 1u << k;
    if (in_size <= 0) {
        return n;
    }
    uint32_t min_size = 1u << CKKS_FFT_Granularity;
    in_size = (in_size + min_size - 1) >> CKKS_FFT_Granularity << CKKS_FFT_Granularity;
    if (k >= 10) {
        if (in_size > n - (n >> 4)) {
            in_size = n;
        }
    } else {
        if (in_size > n - (n >> 3)) {
            in_size = n;
        }
    }
    return in_size;
}

static uint32_t Bit_Rev(uint32_t a, uint32_t k)
{
    uint32_t j = k;
    uint32_t m = 1u << (k - 1);
    while (j && (m & a)) {
        a ^= m;
        m >>= 1;
        j--;
    }
    if (j) {
        a ^= m;
    }
    return a;
}

static int32_t Bit_Rev_Tab(uint32_t k, uint32_t *Bit_Rev_Table)
{
    uint32_t n = 1u << k;
    if (Bit_Rev_Table == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    uint32_t i, j;
    for (i = 0, j = 0; i < n; i++, j = Bit_Rev(j, k)) {
        Bit_Rev_Table[i] = j;
    }
    return CRYPT_SUCCESS;
}

static int32_t Compute_Tab(CKKS_Complex_Array ***Twiddle_Factor_Tab, uint32_t k)
{
    if (k < 2) {
        return CRYPT_INVALID_ARG;
    }
    if (Twiddle_Factor_Tab == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret;
    uint32_t n = (*Twiddle_Factor_Tab)[0]->size;
    CKKS_Complex_Array **newTwiddle_Factor_Tab = (CKKS_Complex_Array **)BSL_SAL_Realloc(
        *Twiddle_Factor_Tab, (k + 1) * sizeof(CKKS_Complex_Array *), sizeof(CKKS_Complex_Array *) * n);
    if (newTwiddle_Factor_Tab == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    *Twiddle_Factor_Tab = newTwiddle_Factor_Tab;

    for (uint32_t s = 2; s <= k; s++) {
        uint32_t m = 1 << s;
        (*Twiddle_Factor_Tab)[s] = (CKKS_Complex_Array *)BSL_SAL_Malloc(sizeof(CKKS_Complex_Array));
        if ((*Twiddle_Factor_Tab)[s] == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
        ret = CKKS_Complex_Array_Init((*Twiddle_Factor_Tab)[s], m / 2);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        for (uint32_t j = 0; j < m / 2; j++) {
            double angle = -2.0 * PI * j / m;
            (*Twiddle_Factor_Tab)[s]->data[j].real = cos(angle);
            (*Twiddle_Factor_Tab)[s]->data[j].imag = sin(angle);
        }
    }
    return CRYPT_SUCCESS;
}

static int32_t CKKS_FFT_Layers(CKKS_Complex *ptr, uint32_t blocks, uint32_t size, const CKKS_Complex *twiddle_tab)
{
    if (ptr == NULL || twiddle_tab == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    do {
        CKKS_Complex *ptr1 = ptr;
        CKKS_Complex *ptr2 = ptr + (size / 2);
        Fwd_Butterfly_Cal(size / 2, ptr1, ptr2, twiddle_tab);
        ptr += size;
    } while (--blocks != 0);
    return CRYPT_SUCCESS;
}

static int32_t CKKS_FFT_Last_Two_Layers(CKKS_Complex *ptr, uint32_t blocks, const CKKS_Complex *twiddle_tab)
{
    if (ptr == NULL || twiddle_tab == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    // CKKS_Complex x = twiddle_tab[1]; // 4th unit root
    do {
        CKKS_Complex u0 = ptr[0];
        CKKS_Complex u1 = ptr[1];
        CKKS_Complex u2 = ptr[2];
        CKKS_Complex u3 = ptr[3];

        CKKS_Complex v0 = CKKS_Complex_Add(u0, u2);
        CKKS_Complex v2 = CKKS_Complex_Sub(u0, u2);
        CKKS_Complex v1 = CKKS_Complex_Add(u1, u3);
        CKKS_Complex t = CKKS_Complex_Sub(u1, u3);
        CKKS_Complex v3 = (CKKS_Complex){t.imag, -t.real};

        ptr[0] = CKKS_Complex_Add(v0, v1);
        ptr[1] = CKKS_Complex_Sub(v0, v1);
        ptr[2] = CKKS_Complex_Add(v2, v3);
        ptr[3] = CKKS_Complex_Sub(v2, v3);
        ptr += 4;
    } while (--blocks != 0);
    return CRYPT_SUCCESS;
}

static int32_t CKKS_FFT_Base(CKKS_Complex *ptr, uint32_t logN, CKKS_Complex_Array **Twiddle_Factor_Tab)
{
    if (ptr == NULL || logN == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    if (logN == 1) {
        CKKS_Complex x0 = ptr[0];
        CKKS_Complex x1 = ptr[1];
        CKKS_Complex_Copy(&ptr[0], CKKS_Complex_Add(x0, x1));
        CKKS_Complex_Copy(&ptr[1], CKKS_Complex_Sub(x0, x1));
        return CRYPT_SUCCESS;
    }
    uint32_t N = 1u << logN;
    int32_t ret;
    for (uint32_t j = logN, size = N, blocks = 1; j > 2; j--, blocks <<= 1, size >>= 1) {
        ret = CKKS_FFT_Layers(ptr, blocks, size, Twiddle_Factor_Tab[j]->data);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    ret = CKKS_FFT_Last_Two_Layers(ptr, N / 4, Twiddle_Factor_Tab[2]->data);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return ret;
}

static int32_t CKKS_FFT_DC(CKKS_Complex *ptr, uint32_t input_size, uint32_t output_size, uint32_t logN,
                           CKKS_Complex_Array **Twiddle_Factor_Tab)
{
    uint32_t N = 1u << logN;
    int32_t ret;
    if (input_size == N && logN <= CKKS_FFT_THRESH) {
        ret = CKKS_FFT_Base(ptr, logN, Twiddle_Factor_Tab);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        return ret;
    }
    uint32_t half_n = N >> 1;
    if (output_size <= half_n) {
        if (input_size <= half_n) { //Directly recursively compute the first half.
            ret = CKKS_FFT_DC(ptr, output_size, input_size, logN - 1, Twiddle_Factor_Tab);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
        } else { //valid input points >=half_n,The first half needs to add part of the second half of the data
            input_size -= half_n;
            for (uint32_t i = 0; i < input_size; i++) {
                ptr[i] = CKKS_Complex_Add(ptr[i], ptr[i + half_n]);
            }
            ret = CKKS_FFT_DC(ptr, output_size, input_size, logN - 1, Twiddle_Factor_Tab);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
        }
    } else { //The number of output points>=half_n
        output_size -= half_n;
        CKKS_Complex *ptr_1 = ptr;
        CKKS_Complex *ptr_2 = ptr + half_n;
        CKKS_Complex *twiddle_tab = Twiddle_Factor_Tab[logN]->data;
        if (input_size <= half_n) {
            for (uint32_t j = 0; j < input_size; j++) {
                ptr_2[j] = CKKS_Complex_Mul(ptr_1[j], twiddle_tab[j]);
            }
            ret = CKKS_FFT_DC(ptr_1, half_n, half_n, logN - 1, Twiddle_Factor_Tab);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            ret = CKKS_FFT_DC(ptr_2, output_size, input_size, logN - 1, Twiddle_Factor_Tab);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
        } else {
            input_size -= half_n;
            Fwd_Butterfly_Cal(input_size, ptr_1, ptr_2, twiddle_tab);
            for (uint32_t j = input_size; j < half_n; j++) {
                ptr_2[j] = CKKS_Complex_Mul(ptr_1[j], twiddle_tab[j]);
            }
            ret = CKKS_FFT_DC(ptr_1, half_n, half_n, logN - 1, Twiddle_Factor_Tab);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            ret = CKKS_FFT_DC(ptr_2, output_size, half_n, logN - 1, Twiddle_Factor_Tab);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
        }
    }
    return ret;
}

static int32_t CKKS_IFFT_Layers(CKKS_Complex *ptr, uint32_t blocks, uint32_t size, const CKKS_Complex *twiddle_tab)
{
    if (ptr == NULL || twiddle_tab == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    do {
        CKKS_Complex *ptr1 = ptr;
        CKKS_Complex *ptr2 = ptr + size / 2;
        Fwd_Butterfly_Cal(size / 2, ptr1, ptr2, twiddle_tab);
        ptr += size;
    } while (--blocks != 0);
    return CRYPT_SUCCESS;
}

static int32_t CKKS_IFFT_First_Two_Layers(CKKS_Complex *ptr, uint32_t blocks, const CKKS_Complex *twiddle_tab)
{
    if (ptr == NULL || twiddle_tab == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    // CKKS_Complex x = twiddle_tab[1]; // 4th unit root
    do {
        CKKS_Complex u0 = ptr[0];
        CKKS_Complex u1 = ptr[1];
        CKKS_Complex u2 = ptr[2];
        CKKS_Complex u3 = ptr[3];

        CKKS_Complex v0 = CKKS_Complex_Add(u0, u1);
        CKKS_Complex v1 = CKKS_Complex_Sub(u0, u1);
        CKKS_Complex v2 = CKKS_Complex_Add(u2, u3);
        CKKS_Complex t = CKKS_Complex_Sub(u2, u3);
        CKKS_Complex v3 = (CKKS_Complex){-t.imag, t.real};

        ptr[0] = CKKS_Complex_Add(v0, v2);
        ptr[1] = CKKS_Complex_Sub(v0, v2);
        ptr[2] = CKKS_Complex_Add(v1, v3);
        ptr[3] = CKKS_Complex_Sub(v1, v3);
        ptr += 4;
    } while (--blocks != 0);
    return CRYPT_SUCCESS;
}

static int32_t CKKS_IFFT_Base(CKKS_Complex *ptr, uint32_t logN, CKKS_Complex_Array **Twiddle_Factor_Tab)
{
    if (logN == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    if (logN == 1) {
        CKKS_Complex x0 = ptr[0];
        CKKS_Complex x1 = ptr[1];
        ptr[0] = CKKS_Complex_Add(x0, x1);
        ptr[1] = CKKS_Complex_Sub(x0, x1);
        return CRYPT_SUCCESS;
    }
    uint32_t blocks = 1u << (logN - 2);
    int32_t ret = CKKS_IFFT_First_Two_Layers(ptr, blocks, Twiddle_Factor_Tab[2]->data);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    blocks >>= 1;

    for (uint32_t j = 3, size = 8; j <= logN; j++, blocks >>= 1, size <<= 1) {
        ret = CKKS_IFFT_Layers(ptr, blocks, size, Twiddle_Factor_Tab[j]->data);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    return ret;
}

static int32_t CKKS_IFFT_DC(CKKS_Complex *ptr, uint32_t output_size, uint32_t logN,
                            CKKS_Complex_Array **Twiddle_Factor_Tab, bool is_full_input)
{
    uint32_t N = 1u << logN;
    int32_t ret;
    if (output_size == N && logN <= CKKS_FFT_THRESH) {
        ret = CKKS_IFFT_Base(ptr, logN, Twiddle_Factor_Tab);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        return ret;
    }
    uint32_t half_n = N >> 1;
    if (output_size <= half_n) {
        for (uint32_t i = 0; i < output_size; i++) {
            ptr[i] = CKKS_Complex_ADouble_Mul(ptr[i], 2.0);
        }
        if (is_full_input) {
            for (uint32_t i = output_size; i < half_n; i++) {
                ptr[i] = CKKS_Complex_Add(ptr[i], ptr[i + half_n]);
            }
        }
        ret = CKKS_IFFT_DC(ptr, output_size, logN - 1, Twiddle_Factor_Tab, is_full_input);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        if (is_full_input) {
            for (uint32_t i = output_size; i < half_n; i++) {
                ptr[i] = CKKS_Complex_Sub(ptr[i], ptr[i + half_n]);
            }
        }
    } else { //The number of output points>=half_n
        CKKS_Complex *ptr_1 = ptr;
        CKKS_Complex *ptr_2 = ptr + half_n;
        CKKS_Complex *twiddle_tab = Twiddle_Factor_Tab[logN]->data;
        ret = CKKS_IFFT_DC(ptr_1, half_n, logN - 1, Twiddle_Factor_Tab, !is_full_input);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        output_size -= half_n;
        if (is_full_input) {
            for (uint32_t j = output_size; j < half_n; j++) {
                CKKS_Complex ele1 = ptr_1[j];
                CKKS_Complex ele2 = ptr_2[j];
                CKKS_Complex u = CKKS_Complex_Sub(ele1, ele2);
                ptr_1[j] = CKKS_Complex_Add(ele1, u);
                ptr_2[j] = CKKS_Complex_Mul(u, twiddle_tab[j]);
            }
        } else {
            for (uint32_t j = output_size; j < half_n; j++) {
                CKKS_Complex ele1 = ptr_1[j];
                CKKS_Complex_Copy(&ptr_1[j], CKKS_Complex_ADouble_Mul(ele1, 2.0));
                ptr_2[j] = CKKS_Complex_Mul(ele1, twiddle_tab[j]);
            }
        }
        ret = CKKS_IFFT_DC(ptr_2, output_size, logN - 1, Twiddle_Factor_Tab, !is_full_input);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        Inv_Butterfly_Cal(output_size, ptr_1, ptr_1, twiddle_tab);
    }
    return ret;
}

static uint32_t CKKS_FFT_P2prec(uint32_t n, uint32_t *Bit_Rev_Table, CKKS_Complex_Array ***Twiddle_Factor_Tab)
{
    uint32_t k = 0;
    while ((1u << k) < n) {
        k++;
    }
    if (Compute_Tab(Twiddle_Factor_Tab, k) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_COMPLEX_ARRAY_CAL_ERROR);
        return 0;
    }
    if (Bit_Rev_Tab(k, Bit_Rev_Table) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_COMPLEX_ARRAY_CAL_ERROR);
        return 0;
    }
    return k;
}

static int32_t CKKS_FFT_P2comp(const CKKS_Complex *src, CKKS_Complex *dst, uint32_t n, uint32_t k,
                               const uint32_t *Bit_Rev_Table, CKKS_Complex_Array **Twiddle_Factor_Tab)
{
    CKKS_Complex_Array *mem = (CKKS_Complex_Array *)BSL_SAL_Malloc(sizeof(CKKS_Complex_Array));
    if (CKKS_Complex_Array_Init(mem, n) != CRYPT_SUCCESS) {
        CKKS_Complex_Array_Destroy(mem);
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_AGLIN_ALLOC_FAIL);
        return CRYPT_CKKS_AGLIN_ALLOC_FAIL;
    }
    memcpy_s(mem->data, n * sizeof(CKKS_Complex), src, n * sizeof(CKKS_Complex));
    uint32_t N = 1u << k;
    int32_t ret = CKKS_FFT_DC(mem->data, N, N, k, Twiddle_Factor_Tab);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    for (uint32_t i = 0; i < n; i++) {
        CKKS_Complex_Copy(&dst[Bit_Rev_Table[i]], mem->data[i]);
    }
    CKKS_Complex_Array_Destroy(mem);
    return CRYPT_SUCCESS;
}

static uint32_t CKKS_FFT_Bluepre(uint32_t n, CKKS_Complex_Array *powers, CKKS_Complex_Array **rb,
                                 CKKS_Complex_Array ***Twiddle_Factor_Tab)
{
    uint32_t k = 0;
    while ((1u << k) < 2 * n - 1) { //Convolution kernel length >= 2*n-1
        k++;
    }
    if (Compute_Tab(Twiddle_Factor_Tab, k) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_COMPLEX_ARRAY_CAL_ERROR);
        return 0;
    }
    powers->data[0] = (CKKS_Complex){1.0, 0.0};
    uint32_t i_sqr = 0;
    for (uint32_t i = 1; i < n; i++) {
        i_sqr = (i_sqr + 2 * i - 1) % (2 * n);
        double angle = -2.0 * PI * i_sqr / (2 * n);
        powers->data[i].real = cos(angle);
        powers->data[i].imag = sin(angle);
    }

    uint32_t N = 1u << k;
    (*rb)->data = (CKKS_Complex *)BSL_SAL_Realloc((*rb)->data, N * sizeof(CKKS_Complex), n * sizeof(CKKS_Complex));
    (*rb)->size = N;
    for (uint32_t i = 0; i < n; i++) {
        (*rb)->data[i] = (CKKS_Complex){0.0, 0.0};
    }
    (*rb)->data[n - 1] = (CKKS_Complex){1.0, 0.0};
    i_sqr = 0;
    for (uint32_t i = 1; i < n; i++) {
        i_sqr = (i_sqr + 2 * i - 1) % (2 * n);
        double angle = -2.0 * PI * i_sqr / (2 * n);
        (*rb)->data[n - 1 + i].real = cos(angle);
        (*rb)->data[n - 1 + i].imag = sin(angle);
    }
    int32_t ret = CKKS_FFT_DC((*rb)->data, N, N, k, *Twiddle_Factor_Tab);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    double Nive = (double)(1 / N);
    for (uint32_t i = 0; i < N; i++) {
        (*rb)->data[i].real *= Nive;
        (*rb)->data[i].imag *= Nive;
    }
    return k;
}

static int32_t CKKS_FFT_Bluecomp(const CKKS_Complex *src, CKKS_Complex *dst, uint32_t n, uint32_t k,
                                 const CKKS_Complex_Array *powers, const CKKS_Complex_Array *rb,
                                 CKKS_Complex_Array **Twiddle_Factor_Tab)
{
    uint32_t N = 1u << k;
    CKKS_Complex_Array *mem = (CKKS_Complex_Array *)BSL_SAL_Malloc(sizeof(CKKS_Complex_Array));
    if (CKKS_Complex_Array_Init(mem, N) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_AGLIN_ALLOC_FAIL);
        return CRYPT_CKKS_AGLIN_ALLOC_FAIL;
    }
    for (uint32_t i = 0; i < n; i++) {
        CKKS_Complex tmp = CKKS_Complex_Mul(src[i], powers->data[i]);
        CKKS_Complex_Copy(&mem->data[i], tmp);
    }
    for (uint32_t i = n; i < N; i++) {
        mem->data[i] = (CKKS_Complex){0.0, 0.0};
    }
    int32_t ret = CKKS_FFT_DC(mem->data, N, N, k, Twiddle_Factor_Tab);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    CKKS_Complex_Mul_Loop(N, mem->data, rb->data);
    ret = CKKS_IFFT_DC(mem->data, N, k, Twiddle_Factor_Tab, false);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    for (uint32_t i = 0; i < N; i++) {
        dst[i] = CKKS_Complex_Mul(mem->data[n - 1 + i], powers->data[i]);
    }
    return CRYPT_SUCCESS;
}

static uint32_t CKKS_FFT_TBluepre(uint32_t n, CKKS_Complex_Array *powers, CKKS_Complex_Array **rb,
                                  CKKS_Complex_Array ***Twiddle_Factor_Tab)
{
    uint32_t k = 0;
    while ((1u << k) < 2 * n - 1) {
        k++;
    }
    if (Compute_Tab(Twiddle_Factor_Tab, k) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_COMPLEX_ARRAY_CAL_ERROR);
        return 0;
    }

    powers->data[0] = (CKKS_Complex){1.0, 0.0};
    uint32_t i_sqr = 0;
    if (n % 2 == 0) {
        for (uint32_t i = 1; i < n; i++) {
            i_sqr = (i_sqr + 2 * i - 1) % (2 * n);
            double angle = -2.0 * PI * i_sqr / (2 * n);
            powers->data[i].real = cos(angle);
            powers->data[i].imag = sin(angle);
        }
    } else {
        for (uint32_t i = 1; i < n; i++) {
            i_sqr = (i_sqr + i + (n - 1) / 2) % n;
            double angle = -2.0 * PI * i_sqr / (n);
            powers->data[i].real = cos(angle);
            powers->data[i].imag = sin(angle);
        }
    }

    uint32_t N = 1u << k;
    CKKS_Complex *new_data =
        (CKKS_Complex *)BSL_SAL_Realloc((*rb)->data, N * sizeof(CKKS_Complex), n * sizeof(CKKS_Complex));
    if (new_data == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return 0;
    }
    (*rb)->data = new_data;
    (*rb)->size = N;
    for (uint32_t i = 0; i < n; i++) {
        (*rb)->data[i] = (CKKS_Complex){0.0, 0.0};
    }
    (*rb)->data[0] = (CKKS_Complex){1.0, 0.0};

    i_sqr = 0;
    if (n % 2 == 0) {
        for (uint32_t i = 1; i < n; i++) {
            i_sqr = (i_sqr + 2 * i - 1) % (2 * n);
            double angle = -2.0 * PI * i_sqr / (2 * n);
            (*rb)->data[i].real = cos(angle);
            (*rb)->data[i].imag = sin(angle);
        }
    } else {
        for (uint32_t i = 1; i < n; i++) {
            i_sqr = (i_sqr + i + (n - 1) / 2) % n;
            double angle = -2.0 * PI * i_sqr / (2 * n);
            (*rb)->data[i].real = cos(angle);
            (*rb)->data[i].imag = sin(angle);
        }
    }
    int32_t ret = CKKS_FFT_DC((*rb)->data, N, N, k, *Twiddle_Factor_Tab);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    double Nive = 1.0 / N;
    for (uint32_t i = 0; i < N; i++) {
        (*rb)->data[i] = CKKS_Complex_ADouble_Mul((*rb)->data[i], Nive);
    }
    return k;
}

static int32_t CKKS_FFT_TBluecomp(const CKKS_Complex *src, CKKS_Complex *dst, uint32_t n, uint32_t k,
                                  const CKKS_Complex_Array *powers, const CKKS_Complex_Array *rb,
                                  CKKS_Complex_Array **Twiddle_Factor_Tab)
{
    uint32_t N = 1u << k;
    int32_t ret;
    CKKS_Complex_Array *mem = (CKKS_Complex_Array *)BSL_SAL_Malloc(sizeof(CKKS_Complex_Array));
    ;
    if (CKKS_Complex_Array_Init(mem, N) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_AGLIN_ALLOC_FAIL);
        return CRYPT_CKKS_AGLIN_ALLOC_FAIL;
    }
    for (uint32_t i = 0; i < n; i++) {
        CKKS_Complex_Copy(&mem->data[i], CKKS_Complex_Mul(src[i], powers->data[i]));
    }
    long len = Adjust_To_Tar_size(2 * n - 1, k);
    long ilen = Adjust_To_Tar_size(n, k);
    for (uint32_t i = n; i < N; i++) {
        mem->data[i] = (CKKS_Complex){0.0, 0.0};
    }
    ret = CKKS_FFT_DC(mem->data, len, ilen, k, Twiddle_Factor_Tab);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    CKKS_Complex_Mul_Loop(len, mem->data, rb->data);
    ret = CKKS_IFFT_DC(mem->data, len, k, Twiddle_Factor_Tab, false);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    for (uint32_t i = 0; i < n - 1; i++) {
        CKKS_Complex tmp = CKKS_Complex_Add(mem->data[i], mem->data[n + i]);
        CKKS_Complex tmp2 = CKKS_Complex_Mul(tmp, powers->data[n - 1]);
        CKKS_Complex_Copy(&dst[i], tmp2);
    }
    CKKS_Complex_Copy(&dst[n - 1], CKKS_Complex_Mul(mem->data[n - 1], powers->data[n - 1]));
    return CRYPT_SUCCESS;
}

#define CKKS_FFT_NULL          0
#define CKKS_FFT_POW2          1
#define CKKS_FFT_BLUESTEIN     2
#define CKKS_FFT_TRUCBLUESTEIN 3

static int32_t Choose_Strategy(uint32_t n)
{
    if (n == 1) {
        return CKKS_FFT_NULL;
    }
    if ((n & (n - 1)) == 0) {
        return CKKS_FFT_POW2;
    }
    uint32_t k = 0;
    while ((1u << k) < 2 * n - 1) {
        k++;
    }
    uint32_t adsz = Adjust_To_Tar_size(2 * n - 1, k);
    if (adsz == (1u << k)) {
        return CKKS_FFT_BLUESTEIN;
    }
    return CKKS_FFT_TRUCBLUESTEIN;
}

int32_t Corr_Factor_Cal(CKKS_Complex_Array *corr_factor, const uint32_t n)
{
    if (corr_factor == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    for (uint32_t i = 0; i < n; i++) {
        double angle = -2.0 * PI * i / (2 * n);
        corr_factor->data[i].real = cos(angle);
        corr_factor->data[i].imag = sin(angle);
    }
    return CRYPT_SUCCESS;
}

int32_t CKKS_FFT_Init(CKKS_FFT *fft, uint32_t n)
{
    if (n <= 0) {
        BSL_SAL_Free(fft);
        return CRYPT_INVALID_ARG;
    }
    fft->n = n;
    int32_t ret = CRYPT_MEM_ALLOC_FAIL;

    fft->Bit_Rev_Table = (uint32_t *)BSL_SAL_Malloc(n * sizeof(uint32_t));
    fft->Twiddle_Factor_Tab = (CKKS_Complex_Array **)BSL_SAL_Malloc(n * sizeof(CKKS_Complex_Array *));
    fft->powers = (CKKS_Complex_Array *)BSL_SAL_Malloc(sizeof(CKKS_Complex_Array *));
    fft->rb = (CKKS_Complex_Array *)BSL_SAL_Malloc(sizeof(CKKS_Complex_Array *));
    fft->corr_factor = (CKKS_Complex_Array *)BSL_SAL_Malloc(sizeof(CKKS_Complex_Array *));

    if (fft->Bit_Rev_Table || fft->Twiddle_Factor_Tab == NULL || fft->powers == NULL || fft->rb == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        goto ERR;
    }

    GOTO_ERR_IF(CKKS_Complex_Array_Init(fft->powers, n), ret);
    GOTO_ERR_IF(CKKS_Complex_Array_Init(fft->rb, n), ret);
    GOTO_ERR_IF(CKKS_Complex_Array_Init(fft->corr_factor, n), ret);
    GOTO_ERR_IF(Corr_Factor_Cal(fft->corr_factor, n), ret);
    return ret;

ERR:
    CKKS_FFT_Destroy(fft);
    return ret;
}

int32_t CKKS_FFT_Apply(CKKS_FFT *fft, CKKS_Complex *src, CKKS_Complex *dst, uint32_t n)
{
    if (fft == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    fft->n = n;
    fft->strategy = Choose_Strategy(fft->n);
    int32_t ret;
    switch (fft->strategy) {
        case CKKS_FFT_NULL:
            ret = CRYPT_SUCCESS;
            break;
        case CKKS_FFT_POW2:
            fft->k = CKKS_FFT_P2prec(fft->n, fft->Bit_Rev_Table, &fft->Twiddle_Factor_Tab);
            ret = CKKS_FFT_P2comp(src, dst, fft->n, fft->k, fft->Bit_Rev_Table, fft->Twiddle_Factor_Tab);
            break;
        case CKKS_FFT_BLUESTEIN:
            fft->k = CKKS_FFT_Bluepre(fft->n, fft->powers, &fft->rb, &fft->Twiddle_Factor_Tab);
            ret = CKKS_FFT_Bluecomp(src, dst, fft->n, fft->k, fft->powers, fft->rb, fft->Twiddle_Factor_Tab);
            break;
        case CKKS_FFT_TRUCBLUESTEIN:
            fft->k = CKKS_FFT_TBluepre(fft->n, fft->powers, &fft->rb, &fft->Twiddle_Factor_Tab);
            ret = CKKS_FFT_TBluecomp(src, dst, fft->n, fft->k, fft->powers, fft->rb, fft->Twiddle_Factor_Tab);
            break;
        default:
            ret = CRYPT_CKKS_ERR_CAL_VALUE;
            break;
    }
    if (fft->k == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_ERR_CAL_VALUE);
        return CRYPT_CKKS_ERR_CAL_VALUE;
    }
    return ret;
}

void CKKS_FFT_Destroy(CKKS_FFT *fft)
{
    if (fft) {
        if (fft->Twiddle_Factor_Tab) {
            for (uint32_t i = 0; i < fft->k; i++) {
                if (fft->Twiddle_Factor_Tab[i]) {
                    CKKS_Complex_Array_Destroy(fft->Twiddle_Factor_Tab[i]);
                }
            }
            BSL_SAL_Free(fft->Twiddle_Factor_Tab);
        }
        if (fft->powers) {
            CKKS_Complex_Array_Destroy(fft->powers);
        }
        if (fft->rb) {
            CKKS_Complex_Array_Destroy(fft->rb);
        }
        if (fft->Bit_Rev_Table) {
            BSL_SAL_Free(fft->Bit_Rev_Table);
        }
        BSL_SAL_Free(fft);
    }
}

double Embedding_Largest_Coeff(CKKS_Poly *poly)
{
    if (poly == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = CRYPT_MEM_ALLOC_FAIL;
    uint32_t m = poly->polyctx->m;
    uint32_t sz = poly->polyctx->phiM;
    if (sz > m / 2) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    CKKS_Complex_Array *buffer = (CKKS_Complex_Array *)BSL_SAL_Malloc(sizeof(CKKS_Complex_Array));
    double *double_poly = (double *)BSL_SAL_Malloc(m * sizeof(double));
    if (buffer == NULL || double_poly == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = CKKS_Complex_Array_Init(buffer, m / 2);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        CKKS_Complex_Array_Destroy(buffer);
        return ret;
    }
    CKKS_FFT *fft = NULL;
    fft = (CKKS_FFT *)BSL_SAL_Malloc(sizeof(CKKS_FFT));
    if (fft == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        CKKS_Complex_Array_Destroy(buffer);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = CKKS_FFT_Init(fft, m / 2);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    // Convert BN_BigNum to a single double
    for (uint32_t i = 0; i < sz; i++) {
        GOTO_ERR_IF(CKKS_BN2Double(poly->coeffs[i], &double_poly[i]), ret);
    }
    CKKS_Complex *D2Complex = (CKKS_Complex *)BSL_SAL_Malloc((m / 2) * sizeof(CKKS_Complex));
    for (uint32_t i = 0; i < sz; i++) {
        CKKS_Complex tmp;
        tmp = CKKS_ADouble2Complex(double_poly[i]);
        CKKS_Complex_Copy(&D2Complex[i], tmp);
    }

    for (uint32_t i = 0; i < sz; i++) {
        CKKS_Complex tmp;
        tmp = CKKS_Complex_Mul(D2Complex[i], fft->corr_factor->data[i]);
        CKKS_Complex_Copy(&buffer->data[i], tmp);
    }
    for (uint32_t i = sz; i < m / 2; i++) {
        buffer->data[i] = (CKKS_Complex){0.0, 0.0};
    }
    ret = CKKS_FFT_Apply(fft, buffer->data, buffer->data, m / 2);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_FFT_CAL_ERROR);
        ret = CRYPT_CKKS_FFT_CAL_ERROR;
        goto ERR;
    }
    double mx = 0;
    for (uint32_t i = 1; i < m / 2; i += 2) {
        if (Check_I_In_ZMStar(poly->polyctx->Tidx, i, m)) {
            double n = CKKS_Complex_Cabs(buffer->data[i >> 1]);
            if (mx < n) {
                mx = n;
            }
        }
    }
    return sqrt(mx);

ERR:
    CKKS_Complex_Array_Destroy(buffer);
    CKKS_FFT_Destroy(fft);
    return ret;
}

int32_t CKKS_Pi_Inverse(CKKS_Complex_Array *slot_vec, CKKS_Poly *Eptxt, const uint32_t m,
                        const CKKS_Complex_Array *complex_arr)
{
    if (slot_vec == NULL || Eptxt == NULL || complex_arr == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    uint32_t quarter_m = m / 4;
    size_t complex_arr_sz = complex_arr->size;
    /*Insert conjugate pairs to extend the compressed slot vector*/
    for (uint32_t i = 0; i < quarter_m; i++) {
        uint32_t j = (i < Eptxt->polyctx->slots_size) ? Eptxt->polyctx->T[i] : 0;
        uint32_t ii = quarter_m - i - 1;
        if (ii < complex_arr_sz) {
            CKKS_Complex tmp = CKKS_Complex_Conj(complex_arr->data[ii]);
            CKKS_Complex_Copy(&slot_vec->data[j >> 1], tmp);
            CKKS_Complex_Copy(&slot_vec->data[(m - j) >> 1], complex_arr->data[ii]);
        }
    }
    return CRYPT_SUCCESS;
}

int32_t CKKS_Pi(CKKS_Complex_Array *out, const uint32_t ratfactor, const uint32_t m, const uint32_t *T)
{
    if (out == NULL || T == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    uint32_t quarter_m = m / 4;
    for (size_t i = 0; i < quarter_m; i++) {
        CKKS_Complex complex_T;
        complex_T = CKKS_U32t2Complex(T[i] >> 1);
        CKKS_Complex_Copy(&out->data[quarter_m - i - 1], complex_T);
    }
    for (uint32_t i = 0; i < quarter_m; i++) {
        CKKS_Complex tmp = CKKS_Complex_Int_Div(out->data[i], ratfactor);
        CKKS_Complex_Copy(&out->data[i], tmp);
    }
    return CRYPT_SUCCESS;
}

int32_t Diagonal_Factor_Correction(CKKS_FFT *fft, CKKS_Complex_Array *mem, CKKS_Poly *Eptxt, double scaling)
{
    int32_t ret = CRYPT_MEM_ALLOC_FAIL;
    if (fft == NULL || mem == NULL || Eptxt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    uint32_t m = Eptxt->polyctx->m;

    CKKS_Complex_Array *pow = (CKKS_Complex_Array *)BSL_SAL_Malloc(sizeof(CKKS_Complex_Array));
    if (pow == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = CKKS_Complex_Array_Init(pow, m);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_COMPLEX_ARRAY_INIT_FAILED);
        ret = CRYPT_CKKS_COMPLEX_ARRAY_INIT_FAILED;
        goto EXIT;
    }

    scaling /= (m / 2.0);
    BN_UINT temp_val;
    /*Inverse Fourier transform and diagonal factor correction*/
    for (uint32_t i = 0; i < Eptxt->polyctx->slots_size; i++) {
        CKKS_Complex tmp = CKKS_Complex_Mul(mem->data[i], fft->corr_factor->data[i]);
        double val = tmp.real * scaling;
        temp_val = (BN_UINT)Coordinate_Wise_Random_Rounding(val);
        BN_BigNum *bn_val = BN_Create(Eptxt->polyctx->bits);
        ret = BN_SetLimb(bn_val, temp_val);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(CRYPT_CKKS_ERR_CAL_VALUE);
            ret = CRYPT_CKKS_ERR_CAL_VALUE;
            BN_Destroy(bn_val);
            goto EXIT;
        }
        ret = CKKS_Poly_Set_Coeff(Eptxt, i, bn_val);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(CRYPT_CKKS_ERR_CAL_VALUE);
            ret = CRYPT_CKKS_ERR_CAL_VALUE;
            BN_Destroy(bn_val);
            goto EXIT;
        }
        BN_Destroy(bn_val);
    }
    CKKS_Poly_Normalized(Eptxt);

EXIT:
    CKKS_Complex_Array_Destroy(pow);
    CKKS_Complex_Array_Destroy(mem);
    CKKS_FFT_Destroy(fft);
    return ret;
}

int32_t CRYPT_CKKS_Encode(const CRYPT_CKKS_Ctx *ctx, CKKS_Poly *Eptxt, CKKS_Complex_Array *data)
{
    if (data == NULL || ctx == NULL || Eptxt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    uint32_t m = ctx->para->m;
    uint32_t scale = ctx->para->scale;

    int32_t ret = CRYPT_MEM_ALLOC_FAIL;
    CKKS_Complex_Array *buffer = (CKKS_Complex_Array *)BSL_SAL_Malloc(sizeof(CKKS_Complex_Array));
    if (buffer == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = CKKS_Complex_Array_Init(buffer, Eptxt->polyctx->phiM);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        CKKS_Complex_Array_Destroy(buffer);
        return ret;
    }
    ret = CKKS_Pi_Inverse(buffer, Eptxt, m, data);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_SIGMA_INV_FAIL);
        CKKS_Complex_Array_Destroy(buffer);
        return CRYPT_CKKS_SIGMA_INV_FAIL;
    }

    CKKS_FFT *fft = (CKKS_FFT *)BSL_SAL_Malloc(sizeof(CKKS_FFT));
    if (fft == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = CKKS_FFT_Init(fft, Eptxt->polyctx->phiM);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = CKKS_FFT_Apply(fft, buffer->data, buffer->data, Eptxt->polyctx->phiM);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_FFT_CAL_ERROR);
        ret = CRYPT_CKKS_FFT_CAL_ERROR;
        goto ERR;
    }
    ret = Diagonal_Factor_Correction(fft, buffer, Eptxt, scale);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    CKKS_Complex_Array_Destroy(buffer);
    CKKS_FFT_Destroy(fft);
    return ret;

ERR:
    CKKS_Poly_Destroy(Eptxt);
    CKKS_Complex_Array_Destroy(buffer);
    CKKS_FFT_Destroy(fft);
    return ret;
}

int32_t CRYPT_CKKS_Decode(const CRYPT_CKKS_Ctx *ctx, const CKKS_Poly *Dptxt, CKKS_Complex_Array *out)
{
    if (out == NULL || ctx == NULL || Dptxt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    int32_t ret = CRYPT_MEM_ALLOC_FAIL;
    uint32_t m = ctx->para->m;
    uint32_t ratfactor = ctx->para->ratfactor;
    uint32_t qsz = ctx->para->qsz;
    uint32_t MAX_BITS = 400;
    int32_t differ = (int32_t)(ctx->para->qsz - MAX_BITS);
    uint32_t sz = Dptxt->polyctx->phiM;

    if (sz > m / 2) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    CKKS_Complex_Array *buffer = (CKKS_Complex_Array *)BSL_SAL_Malloc(sizeof(CKKS_Complex_Array));
    double *double_poly = (double *)BSL_SAL_Malloc(m * sizeof(double));
    if (buffer == NULL || double_poly == NULL) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CKKS_Complex_Array_Init(buffer, m / 2);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        CKKS_Complex_Array_Destroy(buffer);
        return ret;
    }
    CKKS_FFT *fft = (CKKS_FFT *)BSL_SAL_Malloc(sizeof(CKKS_FFT));
    if (fft == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        CKKS_Complex_Array_Destroy(buffer);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = CKKS_FFT_Init(fft, m / 2);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        CKKS_Complex_Array_Destroy(buffer);
        CKKS_FFT_Destroy(fft);
        return ret;
    }
    if (differ > 0) { // This logic prevents floating point overflow
        BN_BigNum *tmp = BN_Create(qsz);
        for (size_t i = 0; i < sz; i++) {
            GOTO_ERR_IF(BN_Rshift(tmp, Dptxt->coeffs[i], differ), ret);
            GOTO_ERR_IF(CKKS_BN2Double(tmp, &double_poly[i]), ret);
        }
        BN_Destroy(tmp);
        ratfactor /= 1 << differ;
    } else {
        for (size_t i = 0; i < sz; i++) {
            GOTO_ERR_IF(CKKS_BN2Double(Dptxt->coeffs[i], &double_poly[i]), ret);
        }
    }

    for (size_t i = 0; i < Dptxt->polyctx->phiM; i++) { // Convert BN_BigNum to a single double
        GOTO_ERR_IF(CKKS_BN2Double(Dptxt->coeffs[i], &double_poly[i]), ret);
    }
    CKKS_Complex *D2Complex = (CKKS_Complex *)BSL_SAL_Malloc((m / 2) * sizeof(CKKS_Complex));
    if (D2Complex == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        CKKS_Complex_Array_Destroy(buffer);
        CKKS_FFT_Destroy(fft);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    for (uint32_t i = 0; i < sz; i++) {
        CKKS_Complex tmp;
        tmp = CKKS_ADouble2Complex(double_poly[i]);
        CKKS_Complex_Copy(&D2Complex[i], tmp);
        tmp = CKKS_Complex_Mul(D2Complex[i], fft->corr_factor->data[i]);
        CKKS_Complex_Copy(&buffer->data[i], tmp);
    }
    CKKS_Aligned_Deallocate(D2Complex);

    for (uint32_t i = sz; i < m / 2; i++) {
        buffer->data[i] = (CKKS_Complex){0.0, 0.0};
    }

    GOTO_ERR_IF(CKKS_FFT_Apply(fft, buffer->data, buffer->data, m / 2), ret);
    GOTO_ERR_IF(CKKS_Pi(out, ratfactor, m, Dptxt->polyctx->T), ret);
    out->size = m / 4;

    CKKS_Complex_Array_Destroy(buffer);
    CKKS_FFT_Destroy(fft);
    BSL_SAL_Free(double_poly);
    return ret;

ERR:
    CKKS_Complex_Array_Destroy(buffer);
    CKKS_FFT_Destroy(fft);
    BSL_SAL_Free(double_poly);
    return ret;
}

#endif // HITLS_CRYPTO_CKKS