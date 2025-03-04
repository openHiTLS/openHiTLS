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

#ifndef CKKS_LOCAL_H
#define CKKS_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CKKS

#include "crypt_ckks.h"
#include "crypt_bn.h"
#include "sal_atomic.h"
#include "crypt_types.h"
#include "crypt_local_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    double real;
    double imag;
} CKKS_Complex;

typedef struct {
    size_t size; // Current size
    size_t elem_size; // element size
    CKKS_Complex *data; // Align the assigned data pointer
} CKKS_Complex_Array;

typedef struct {
    uint32_t n; // The number of points, n>0
    uint32_t k; // Input size
    uint32_t strategy; // Select the optimal policy dynamically
    uint32_t *Bit_Rev_Table; // Bit-Reversal Table
    CKKS_Complex_Array **Twiddle_Factor_Tab; // Twiddle Factor Table
    CKKS_Complex_Array *powers; // Preconditioning factor a_i = e^(-j¦Ðn^2/N)
    CKKS_Complex_Array *rb; // Convolution kernel b, whose elements are conjugate of a_k, b_k = e^(j¦Ðkn^2/n)
    CKKS_Complex_Array *corr_factor; // An additional phase correction after FFT
} CKKS_FFT;

typedef struct {
    uint32_t
        bits; // Ciphertext modular chain depth, That is, the number of homomorphic operations that can be performed
    uint32_t m; // Construct the ring Z[X]/Phi_m(X), Where Phi_m(X) is the m th circular component polynomial
    uint32_t phiM; // Euler function value: phi(m),p^ phiM ¡Ô 1 mod m. In CKKS, the degree of Phi_m(X) is usually m/2.
    uint32_t logM; // if m = 2^k, then pow2 == k.
    uint32_t slots_size; // In CKKS, the number of slots is usually m/4
    uint32_t *T; // T is a subgroup of the multiplicative group (Z/mZ)^* satisfying (Z/mZ)^*/T={\pm 1}
    int32_t *Tidx; // i=Tidx[t] is the index i s.t. T[i]=t. Tidx[t]==-1 if t notin T
} CKKS_PolyCtx;

typedef struct {
    uint32_t degree; // Max degree of polynomial, In CKKS, the max degree of polynormial is m/2-1
    BN_BigNum **coeffs; // Coefficient array
    CKKS_PolyCtx
        *polyctx; // The structure of (Z/mZ)^*, responsible for managing the algebraic structure of polynomial rings.
} CKKS_Poly;

typedef struct {
    BN_BigNum **primes; // Modular chain
    size_t modLen; // Modular chain length
    size_t mod_capacity; // Modular chain capacity
    uint32_t qsz; // The range of primes is [(1-1/2^B)*2^qsz,2^qsz)
} CKKS_Moduli;

typedef struct {
    CKKS_Poly *poly; // Polynomial in the form doubleCRT (in the ring R_Q)
    BN_BigNum **
        map; // In DoubleCRT, the polynomial ring of the module Q (Q refers to the product of all primes in the modular chain) is represented by a matrix.
        // This matrix has L rows and Phi(m) columns. Here a one-dimensional array is used instead of a two-dimensional array
    uint32_t L; // Modular chain length
} CKKS_DoubleCRT;

typedef struct {
    CKKS_DoubleCRT *s; // Private key polynomial
    double prvkey_noiseB; // Noise boundary of private key
} CRYPT_CKKS_PrvKey;

typedef struct {
    CKKS_DoubleCRT *a; // Random ring elements
    CKKS_DoubleCRT *b; // b = -a*s + e
    double pubkey_noiseB; // Noise boundary of public key
    double prvkey_noiseB; // Noise boundary of private key
} CRYPT_CKKS_PubKey;

struct CKKS_Para {
    int32_t precision; // Precision bit number
    uint32_t m; // Order of polynomial ring, a larger m means support for larger ciphertext computations
    uint32_t phiM; // Euler function value: phi(m),p^ phiM ¡Ô 1 mod m. In CKKS, the degree of Phi_m(X) is usually m/2.
    uint32_t bits; // The number of bits in the ciphertext modulus
    uint32_t qsz; // // The range of modular chain primes is [(1-1/2^B)*2^qsz,2^qsz)
    uint32_t slots_size; // In CKKS, the number of slots is usually m/4
    double scale; // Initial Scaling factor
    double mag; // The magnitude of plaintext
    double err; // The theoretical upper boundary of error
    double stdev; // The variance of the LWE error, default = 3.2
    double noise_bound; // The noise bound after encryption
    double ratfactor; // Actual scale factor. The scaling factor also changes during the actual encryption process
    CKKS_Moduli *moduli; // Modular chain
};

struct CKKS_Ctx {
    CRYPT_CKKS_PrvKey *prvKey; // Private key
    CRYPT_CKKS_PubKey *pubKey; // Public key
    CRYPT_CKKS_Para *para; // Parameters
    BSL_SAL_RefCount references; // Reference count
};

// Function declarations
CRYPT_CKKS_PrvKey *CKKS_NewPrvKey(void);
CRYPT_CKKS_PubKey *CKKS_NewPubKey(void);
void CKKS_FreePrvKey(CRYPT_CKKS_PrvKey *prvKey);
void CKKS_FreePubKey(CRYPT_CKKS_PubKey *pubKey);
int32_t CKKS_CalcPrvKey(CRYPT_CKKS_Ctx *ctx);
int32_t CKKS_CalcPubKey(CRYPT_CKKS_Ctx *ctx, BN_Optimizer *optimizer);

// Memory release macro
#define CKKS_FREE_PRV_KEY(prvKey_)  \
    do {                            \
        CKKS_FreePrvKey((prvKey_)); \
        (prvKey_) = NULL;           \
    } while (0)

#define CKKS_FREE_PUB_KEY(pubKey_)  \
    do {                            \
        CKKS_FreePubKey((pubKey_)); \
        (pubKey_) = NULL;           \
    } while (0)

#define CKKS_FREE_PARA(para_)         \
    do {                              \
        CRYPT_CKKS_FreePara((para_)); \
        (para_) = NULL;               \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_CKKS
#endif // CKKS_LOCAL_H