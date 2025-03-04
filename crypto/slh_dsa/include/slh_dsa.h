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

#ifndef CRYPT_SLH_DSA_H
#define CRYPT_SLH_DSA_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SLH_DSA

#include <stdint.h>
#include "bsl_params.h"
#include "crypt_algid.h"
#include "crypt_types.h"
#include "crypt_utils.h"

#define SLH_DSA_ADRS_LEN            32
#define SLH_DSA_ADRS_COMPRESSED_LEN 22
#define SLH_DSA_MAX_N               32 // Security parameter (hash output length)
#define SLH_DSA_MAX_M               49

typedef enum {
    WOTS_HASH,
    WOTS_PK,
    TREE,
    FORS_TREE,
    FORS_ROOTS,
    WOTS_PRF,
    FORS_PRF,
} AdrsType;

/**
 * @brief Address structure definition
 * 
 *  all the address is big-endian
 *  it can be a address or a compressed address
 *  Address:
 *  | layer address | 4 bytes
 *  | tree address  | 12 bytes
 *  | type          | 4 bytes
 *  | padding       | 12 bytes
 * 
 *  Compressed Address:
 *  | layer address | 1 bytes
 *  | tree address  | 8 bytes
 *  | type          | 1 bytes
 *  | padding       | 12 bytes
 *  | hole          | 10 bytes
 */
typedef union {
    struct {
        uint8_t layerAddr[4];
        uint8_t treeAddr[12];
        uint8_t type[4];
        uint8_t padding[12];
    } uc;
    struct {
        uint8_t layerAddr;
        uint8_t treeAddr[8];
        uint8_t type;
        uint8_t padding[12];
    } c;
    uint8_t bytes[SLH_DSA_ADRS_LEN];
} SlhDsaAdrs;

// adrs operations functions
typedef void (*fAdrsSetLayerAddr)(SlhDsaAdrs *adrs, uint32_t layer);
typedef void (*fAdrsSetTreeAddr)(SlhDsaAdrs *adrs, uint64_t tree);
typedef void (*fAdrsSetType)(SlhDsaAdrs *adrs, AdrsType type);
typedef void (*fAdrsSetKeyPairAddr)(SlhDsaAdrs *adrs, uint32_t keyPair);
typedef void (*fAdrsSetChainAddr)(SlhDsaAdrs *adrs, uint32_t chain);
typedef void (*fAdrsSetTreeHeight)(SlhDsaAdrs *adrs, uint32_t height);
typedef void (*fAdrsSetHashAddr)(SlhDsaAdrs *adrs, uint32_t hash);
typedef void (*fAdrsSetTreeIndex)(SlhDsaAdrs *adrs, uint32_t index);
typedef uint32_t (*fAdrsGetTreeHeight)(const SlhDsaAdrs *adrs);
typedef uint32_t (*fAdrsGetTreeIndex)(const SlhDsaAdrs *adrs);
typedef void (*fAdrsCopyKeyPairAddr)(SlhDsaAdrs *adrs, const SlhDsaAdrs *adrs2);
typedef uint32_t (*fAdrsGetAdrsLen)();

typedef struct {
    fAdrsSetLayerAddr setLayerAddr;
    fAdrsSetTreeAddr setTreeAddr;
    fAdrsSetType setType;
    fAdrsSetKeyPairAddr setKeyPairAddr;
    fAdrsSetChainAddr setChainAddr;
    fAdrsSetTreeHeight setTreeHeight;
    fAdrsSetHashAddr setHashAddr;
    fAdrsSetTreeIndex setTreeIndex;
    fAdrsGetTreeHeight getTreeHeight;
    fAdrsGetTreeIndex getTreeIndex;
    fAdrsCopyKeyPairAddr copyKeyPairAddr;
    fAdrsGetAdrsLen getAdrsLen;
} AdrsOps;

// Constant definitions

#define SLH_DSA_LGW 4
#define SLH_DSA_W   16 // 2^SLH_DSA_LGW

typedef struct SlhDsaCtx_ SlhDsaCtx;

// PTHF stand for the "PRF, Tl, H, F" functions, which all have same input parameters
typedef int32_t (*PTHF)(const SlhDsaCtx *ctx, bool isHT, const uint8_t *seed, uint32_t seedLen, const SlhDsaAdrs *adrs,
                        const uint8_t *msg, uint32_t msgLen, uint8_t *out, uint32_t *outLen);
typedef int32_t (*PRFmsg)(const SlhDsaCtx *ctx, const uint8_t *prf, uint32_t prfLen, const uint8_t *rand,
                          uint32_t randLen, const uint8_t *msg, uint32_t msgLen, uint8_t *out, uint32_t *outLen);
typedef int32_t (*Hmsg)(const SlhDsaCtx *ctx, const uint8_t *r, uint32_t rLen, const uint8_t *seed, uint32_t seedLen,
                        const uint8_t *root, uint32_t rootLen, const uint8_t *msg, uint32_t msgLen, uint8_t *out,
                        uint32_t *outLen);

// b can be 4, 6, 8, 9, 12, 14
// so use uint32_t to receive the BaseB value
void BaseB(const uint8_t *x, uint32_t xLen, uint32_t b, uint32_t *out, uint32_t outLen);

typedef struct {
    uint32_t len;
    uint8_t bytes[SLH_DSA_MAX_N];
} SlhDsaN;

typedef struct {
    CRYPT_SLH_DSA_AlgId algId;
    bool isCompressed;
    uint32_t n;
    uint32_t h;
    uint32_t d;
    uint32_t hp;
    uint32_t a;
    uint32_t k;
    uint32_t m;
    uint32_t secCategory;
    uint32_t pkBytes;
    uint32_t sigBytes;
} SlhDsaPara;

typedef struct {
    uint8_t seed[SLH_DSA_MAX_N]; // pubkey seed for generating keys
    uint8_t root[SLH_DSA_MAX_N]; // pubkey root for generating keys
} SlhDsaPubKey;
/**
 * @brief SLH-DSA private key structure
 */
typedef struct {
    uint8_t seed[SLH_DSA_MAX_N]; // prvkey seed for generating keys
    uint8_t prf[SLH_DSA_MAX_N]; // prvkey prf for generating keys
    SlhDsaPubKey pub;
} SlhDsaPrvKey;

/**
 * @brief SLH-DSA signature structure
 */
typedef struct {
    uint8_t *sig; // Signature data
    uint32_t sigSize; // Signature size in bytes
} SlhDsaSignature;

struct SlhDsaCtx_ {
    SlhDsaPara para;
    uint8_t *context; // user specific context
    uint32_t contextLen; // length of the user specific context
    bool isDeterministic;
    uint8_t *addrand; // optional random bytes, can be set through CTRL interface, or comes from RNG
    CRYPT_MD_AlgId prehashId;
    SlhDsaPrvKey prvkey;
    PRFmsg prfmsg;
    Hmsg hmsg;
    PTHF pthf;
    AdrsOps adrsOps;
};

typedef SlhDsaCtx CryptSlhDsaCtx;

/**
 * @brief Create a new SLH-DSA context
 * 
 * @return CryptSlhDsaCtx* Pointer to the new SLH-DSA context
 */
CryptSlhDsaCtx *CRYPT_SLH_DSA_NewCtx(void);

/**
 * @brief Free a SLH-DSA context
 * 
 * @param ctx Pointer to the SLH-DSA context
 */
void CRYPT_SLH_DSA_FreeCtx(CryptSlhDsaCtx *ctx);

/**
 * @brief Generate a SLH-DSA key pair
 * 
 * @param ctx Pointer to the SLH-DSA context
 */
int32_t CRYPT_SLH_DSA_Gen(CryptSlhDsaCtx *ctx);

/**
 * @brief Sign data using SLH-DSA, the msg is pre-hashed, and the hash-id should be set before calling this function.
 * 
 * @param ctx Pointer to the SLH-DSA context
 * @param msg Pointer to the message to sign
 * @param msgLen Length of the message
 * @param sig Pointer to the signature
 * @param sigLen Length of the signature
 */
int32_t CRYPT_SLH_DSA_SignData(SlhDsaCtx *ctx, const uint8_t *msg, uint32_t msgLen, uint8_t *sig, uint32_t *sigLen);

/**
 * @brief Verify data using SLH-DSA, the msg is pre-hashed, and the hash-id should be set before calling this function.
 * 
 * @param ctx Pointer to the SLH-DSA context
 * @param msg Pointer to the message to verify
 * @param msgLen Length of the message
 * @param sig Pointer to the signature
 * @param sigLen Length of the signature
 */
int32_t CRYPT_SLH_DSA_VerifyData(const SlhDsaCtx *ctx, const uint8_t *msg, uint32_t msgLen, uint8_t *sig,
                                 uint32_t sigLen);

/**
 * @brief Sign data using SLH-DSA
 * 
 * @param ctx Pointer to the SLH-DSA context
 * @param algId Algorithm ID
 * @param data Pointer to the data to sign
 * @param dataLen Length of the data
 * @param sign Pointer to the signature
 * @param signLen Length of the signature
 */
int32_t CRYPT_SLH_DSA_Sign(SlhDsaCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen, uint8_t *sign,
                           uint32_t *signLen);

/**
 * @brief Verify data using SLH-DSA
 * 
 * @param ctx Pointer to the SLH-DSA context
 * @param algId Algorithm ID
 * @param data Pointer to the data to verify
 * @param dataLen Length of the data
 * @param sign Pointer to the signature
 * @param signLen Length of the signature
 */

int32_t CRYPT_SLH_DSA_Verify(const SlhDsaCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
                             const uint8_t *sign, uint32_t signLen);

/**
 * @brief Control function for SLH-DSA
 * 
 * @param ctx Pointer to the SLH-DSA context
 * @param opt Option
 * @param val Value
 * @param len Length of the value
 */
int32_t CRYPT_SLH_DSA_Ctrl(CryptSlhDsaCtx *ctx, int32_t opt, void *val, uint32_t len);

/**
 * @brief Get the public key of SLH-DSA
 * 
 * @param ctx Pointer to the SLH-DSA context
 * @param para Pointer to the public key
 */
int32_t CRYPT_SLH_DSA_GetPubKey(const SlhDsaCtx *ctx, BSL_Param *para);

/**
 * @brief Get the private key of SLH-DSA
 * 
 * @param ctx Pointer to the SLH-DSA context
 * @param para Pointer to the private key
 */
int32_t CRYPT_SLH_DSA_GetPrvKey(const SlhDsaCtx *ctx, BSL_Param *para);

/**
 * @brief Set the public key of SLH-DSA
 * 
 * @param ctx Pointer to the SLH-DSA context
 * @param para Pointer to the public key
 */
int32_t CRYPT_SLH_DSA_SetPubKey(SlhDsaCtx *ctx, const BSL_Param *para);

/**
 * @brief Set the private key of SLH-DSA
 * 
 * @param ctx Pointer to the SLH-DSA context
 * @param para Pointer to the private key
 */
int32_t CRYPT_SLH_DSA_SetPrvKey(SlhDsaCtx *ctx, const BSL_Param *para);

#endif // HITLS_CRYPTO_SLH_DSA
#endif // CRYPT_SLH_DSA_H