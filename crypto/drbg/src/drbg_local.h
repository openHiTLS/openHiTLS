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

#ifndef DRBG_LOCAL_H
#define DRBG_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_DRBG

#include <stdint.h>
#include "crypt_drbg.h"

#ifdef __cplusplus
extern "C" {
#endif

// Relationship between the number of NONCE and ENTROPY
#define DRBG_NONCE_FROM_ENTROPY (2)

/* Mapping between RAND and specific random number generation algorithms */
#define RAND_TYPE_MD     1
#define RAND_TYPE_MAC    2
#define RAND_TYPE_AES    3
#define RAND_TYPE_AES_DF 4
#define RAND_TYPE_SM4_DF 5

typedef enum {
    DRBG_STATE_UNINITIALISED,
    DRBG_STATE_READY,
    DRBG_STATE_ERROR,
} DRBG_State;

typedef struct {
    int32_t (*instantiate)(DRBG_Ctx *ctx, const CRYPT_Data *entropy,
                           const CRYPT_Data *nonce, const CRYPT_Data *pers);
    int32_t (*generate)(DRBG_Ctx *ctx, uint8_t *out, uint32_t outLen, const CRYPT_Data *adin);
    int32_t (*reseed)(DRBG_Ctx *ctx, const CRYPT_Data *entropy, const CRYPT_Data *adin);
    void (*uninstantiate)(DRBG_Ctx *ctx);
    DRBG_Ctx* (*dup)(DRBG_Ctx *ctx);
    void (*free)(DRBG_Ctx *ctx);
} DRBG_Method;

struct DrbgCtx {
    bool isGm;
    DRBG_State state; /* DRBG state */

    uint32_t reseedCtr; /* reseed counter */
    uint32_t reseedInterval; /* reseed interval times */
#if defined(HITLS_CRYPTO_DRBG_GM)
    uint64_t lastReseedTime; /* last reseed time, uint: second */
    uint64_t reseedIntervalTime; /* Time threshold for reseed, uint: second */
#endif

    uint32_t strength; /* Algorithm strength */
    uint32_t maxRequest; /* Maximum number of bytes per request, which is determined by the algorithm. */

    CRYPT_Range entropyRange; /* entropy size range */
    CRYPT_Range nonceRange; /* nonce size range */

    uint32_t maxPersLen; /* Maximum private data length */
    uint32_t maxAdinLen; /* Maximum additional data length */

    DRBG_Method *meth; /* Internal different mode method */
    void *ctx; /* Mode Context */

    /* seed function, which is related to the entropy source and DRBG generation.
       When seedMeth and seedCtx are empty, the default entropy source is used. */
    CRYPT_RandSeedMethod seedMeth;
    void *seedCtx; /* Seed context */
    bool predictionResistance;

    void *libCtx; /* Library context */

    int32_t forkId;
};

#ifdef HITLS_CRYPTO_DRBG_HASH
/**
 * @ingroup drbg
 * @brief Apply for a context for the Hash_DRBG.
 * @brief This API does not support multiple threads.
 *
 * @param md        HASH method
 * @param seedMeth  DRBG seed hook
 * @param isGM      SM3 DRBG or not
 * @param seedCtx   DRBG seed context
 *
 * @retval DRBG_Ctx* Success
 * @retval NULL      failure
 */
DRBG_Ctx *DRBG_NewHashCtx(const EAL_MdMethod *md, bool isGm, const CRYPT_RandSeedMethod *seedMeth, void *seedCtx);
#endif

#ifdef HITLS_CRYPTO_DRBG_HMAC
/**
 * @ingroup drbg
 * @brief Apply for a context for the HMAC_DRBG.
 * @brief This API does not support multiple threads.
 *
 * @param libCtx    Library context
 * @param hmacMeth  HMAC method
 * @param mdMeth    hash algid
 * @param seedMeth  DRBG seed hook
 * @param seedCtx   DRBG seed context
 *
 * @retval DRBG_Ctx* Success
 * @retval NULL      failure
 */
DRBG_Ctx *DRBG_NewHmacCtx(void *libCtx, const EAL_MacMethod *hmacMeth, CRYPT_MAC_AlgId macId,
    const CRYPT_RandSeedMethod *seedMeth, void *seedCtx);
#endif

#ifdef HITLS_CRYPTO_DRBG_CTR
/**
 * @ingroup drbg
 * @brief Apply for a context for the CTR_DRBG.
 * @brief This API does not support multiple threads.
 *
 * @param ciphMeth  AES method
 * @param keyLen    Key length
 * @param isGm      is sm4
 * @param isUsedDf  Indicates whether to use derivation function.
 * @param seedMeth  DRBG seed hook
 * @param seedCtx   DRBG seed context
 *
 * @retval DRBG_Ctx* Success
 * @retval NULL      failure
 */
DRBG_Ctx *DRBG_NewCtrCtx(const EAL_SymMethod *ciphMeth, uint32_t keyLen, bool isGm,
    bool isUsedDf, const CRYPT_RandSeedMethod *seedMeth, void *seedCtx);
#endif

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_DRBG

#endif // DRBG_LOCAL_H
