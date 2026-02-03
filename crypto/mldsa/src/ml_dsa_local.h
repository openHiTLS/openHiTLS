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
#ifndef CRYPT_ML_DSA_LOCAL_H
#define CRYPT_ML_DSA_LOCAL_H
#include "crypt_mldsa.h"
#include "sal_atomic.h"
#include "crypt_local_types.h"

#define MLDSA_SEED_BYTES_LEN 32
#define MLDSA_PUBLIC_SEED_LEN 32
#define MLDSA_PRIVATE_SEED_LEN 64
#define MLDSA_SIGNING_SEED_LEN 32
#define MLDSA_EXPANDED_SEED_BYTES_LEN (MLDSA_PUBLIC_SEED_LEN + MLDSA_PRIVATE_SEED_LEN + MLDSA_SIGNING_SEED_LEN)
#define MLDSA_SEED_EXTEND_BYTES_LEN (MLDSA_SEED_BYTES_LEN + 2)

#define MLDSA_K_MAX 8
#define MLDSA_L_MAX 7

#define MLDSA_TR_MSG_LEN  64
#define MLDSA_XOF_MSG_LEN  64
#define MLDSA_N         256
#define MLDSA_N_HALF    (MLDSA_N >> 1)
#define MLDSA_N_BYTE    32

#define GAMMA_BITS_OF_MLDSA_44 18
#define GAMMA_BITS_OF_MLDSA_65_87 20
#define K_VALUE_OF_MLDSA_44 4

#define MLDSA_Q    8380417
#define MLDSA_QINV    58728449  // MLDSA_Q^(-1) mod 2^32
#define MLDSA_D    13
#define MLDSA_PUBKEY_POLYT_PACKEDBYTES 320
#define MLDSA_MAX_CTX_BYTES 255
#define MLDSA_SIGN_PREFIX_BYTES 2

// Reference: https://eprint.iacr.org/2022/956.pdf
// 3.1 Improved Plantard Multiplication
#define MLDSA_PLANTARD_L 32
#define MLDSA_PLANTARD_ALPHA 3
#define MLDSA_PLANTARD_INV 1732267787797143553 // inverse_mod(q, 1 << 64)

// 1783^{bit_rev(1)} * 256^{-1} * (-2^{64}) mod Q, then converted to Plantard domin
#define MLDSA_LAST_ROUND_ZETA (-8751230424634003605LL)

// 8338439 = 256^{-1} * (-2^{64}) mod Q and 8338439 in Plantard domin is -92400822384635461
// -2^{64} because the inputs have factor -2^{64} when multiplying polys using MLDSA_PlantardMulReduce
#define MLDSA_PLANTARD_8338439 (-92400822384635461LL)

// This is Barrett Modular Multiplication, mod is MLDSA_Q.
#define MLDSA_MOD_Q(val) {int32_t m = ((val) + (1 << 22u)) >> 23u; (val) = (val) - m * MLDSA_Q;}

typedef struct {
    int32_t paramId;
    uint8_t k;
    uint8_t l;
    uint8_t eta;
    uint8_t tau;
    uint32_t beta;
    uint32_t gamma1;
    uint32_t gamma2;
    uint8_t omega;
    uint32_t secBits;
    uint32_t publicKeyLen;
    uint32_t privateKeyLen;
    uint32_t signatureLen;
} CRYPT_ML_DSA_Info;

struct CryptMlDsaCtx {
    const CRYPT_ML_DSA_Info *info;
    uint8_t *pubKey;
    uint32_t pubLen;
    uint8_t *prvKey;
    uint32_t prvLen;
    uint8_t *ctxInfo;
    uint32_t ctxLen;
    bool isMuMsg;
    bool needEncodeCtx;
    bool needPreHash;
    bool deterministicSignFlag;
    BSL_SAL_RefCount references;
    void *libCtx;
    CRYPT_ALGO_MLDSA_PRIV_KEY_FORMAT_TYPE prvKeyFormat;
    bool hasSeed;
    uint8_t seed[MLDSA_SEED_BYTES_LEN];
};

void MLDSA_ComputesNTT(int32_t w[MLDSA_N]);
void MLDSA_ComputesINVNTT(int32_t w[MLDSA_N]);

static inline int32_t MLDSA_PlantardMulReduce(int64_t a)
{
    int64_t tmp = a;
    tmp >>= MLDSA_PLANTARD_L;
    tmp = (tmp + (1 << MLDSA_PLANTARD_ALPHA)) * MLDSA_Q;
    tmp >>= MLDSA_PLANTARD_L;
    return (int32_t)tmp;
}

int32_t MLDSA_KeyGenInternal(CRYPT_ML_DSA_Ctx *ctx, const uint8_t *d);

int32_t MLDSA_SignInternal(const CRYPT_ML_DSA_Ctx *ctx, const CRYPT_Data *msg, uint8_t *out, uint32_t *outLen,
    const uint8_t *rand);

int32_t MLDSA_VerifyInternal(const CRYPT_ML_DSA_Ctx *ctx, const CRYPT_Data *msg, const uint8_t *sign, uint32_t signLen);

#ifdef HITLS_CRYPTO_MLDSA_CHECK
// calculate public key from private key
int32_t MLDSA_CalPub(const CRYPT_ML_DSA_Ctx *ctx, uint8_t *pub, uint32_t pubLen);
int32_t MLDSA_KeyConsistenceCheck(CRYPT_ML_DSA_Ctx *ctx);
#endif // HITLS_CRYPTO_MLDSA_CHECK

#endif    // ML_DSA_LOCAL_H