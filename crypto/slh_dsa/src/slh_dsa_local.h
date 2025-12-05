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

#ifndef SLH_DSA_LOCAL_H
#define SLH_DSA_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SLH_DSA

#include <stdint.h>
#include "bsl_params.h"
#include "crypt_algid.h"
#include "crypt_types.h"
#include "crypt_utils.h"
#include "slh_dsa_hash.h"
#include "crypt_types.h"

#define SLH_DSA_ADRS_LEN            32
#define SLH_DSA_ADRS_COMPRESSED_LEN 22
#define SLH_DSA_MAX_N               32 // Security parameter (hash output length)
#define SLH_DSA_MAX_M               49
#define SLH_DSA_LGW                 4
#define SLH_DSA_W                   16 // 2^SLH_DSA_LGW

#define SLH_DSA_PRVKEY 0x1
#define SLH_DSA_PUBKEY 0x10

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
union Adrs {
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
    struct {
        uint8_t layerAddr[4];
        uint8_t treeAddr[8];
        uint8_t type[4];
        uint8_t padding[16];
    } x;
    uint8_t bytes[SLH_DSA_ADRS_LEN];
};

// adrs operations functions
typedef void (*AdrsSetLayerAddr)(SlhDsaAdrs *adrs, uint32_t layer);
typedef void (*AdrsSetTreeAddr)(SlhDsaAdrs *adrs, uint64_t tree);
typedef void (*AdrsSetType)(SlhDsaAdrs *adrs, AdrsType type);
typedef void (*AdrsSetKeyPairAddr)(SlhDsaAdrs *adrs, uint32_t keyPair);
typedef void (*AdrsSetChainAddr)(SlhDsaAdrs *adrs, uint32_t chain);
typedef void (*AdrsSetTreeHeight)(SlhDsaAdrs *adrs, uint32_t height);
typedef void (*AdrsSetHashAddr)(SlhDsaAdrs *adrs, uint32_t hash);
typedef void (*AdrsSetTreeIndex)(SlhDsaAdrs *adrs, uint32_t index);
typedef void (*AdrsSetKeyAndMask)(SlhDsaAdrs *adrs, uint32_t index); // for XMSS only
typedef uint32_t (*AdrsGetTreeHeight)(const SlhDsaAdrs *adrs);
typedef uint32_t (*AdrsGetTreeIndex)(const SlhDsaAdrs *adrs);
typedef void (*AdrsCopyKeyPairAddr)(SlhDsaAdrs *adrs, const SlhDsaAdrs *adrs2);
typedef uint32_t (*AdrsGetAdrsLen)(void);

typedef struct {
    AdrsSetLayerAddr setLayerAddr;
    AdrsSetTreeAddr setTreeAddr;
    AdrsSetType setType;
    AdrsSetKeyPairAddr setKeyPairAddr;
    AdrsSetChainAddr setChainAddr;
    AdrsSetTreeHeight setTreeHeight;
    AdrsSetHashAddr setHashAddr;
    AdrsSetTreeIndex setTreeIndex;
    AdrsSetKeyAndMask setKeyAndMask; // for XMSS only
    AdrsGetTreeHeight getTreeHeight;
    AdrsGetTreeIndex getTreeIndex;
    AdrsCopyKeyPairAddr copyKeyPairAddr;
    AdrsGetAdrsLen getAdrsLen;
} AdrsOps;

// b can be 4, 6, 8, 9, 12, 14
// so use uint32_t to receive the BaseB value
void BaseB(const uint8_t *x, uint32_t xLen, uint32_t b, uint32_t *out, uint32_t outLen);
#define HASH_SIGN_XDR_ALG_TYPE_LEN 4
typedef struct {
    int32_t algId; // CRYPT_PKEY_ParaId (SLH_DSA_AlgId or XMSS_AlgId)
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
    uint8_t xdrAlgId[HASH_SIGN_XDR_ALG_TYPE_LEN]; // RFC8391 Parameter Sets enum, length:4
} SlhDsaPara;

typedef struct {
    uint8_t seed[MAX_MDSIZE]; // pubkey seed for generating keys
    uint8_t root[MAX_MDSIZE]; // pubkey root for generating keys
} SlhDsaPubKey;
/**
 * @brief SLH-DSA private key structure
 */
typedef struct {
    uint8_t seed[MAX_MDSIZE]; // prvkey seed for generating keys
    uint8_t prf[MAX_MDSIZE]; // prvkey prf for generating keys
    uint64_t index; // the next unused WOTS+ key index, for XMSS only
    SlhDsaPubKey pub;
} SlhDsaPrvKey;

struct SlhDsaCtx {
    SlhDsaPara para;
    uint8_t *context; // user specific context
    uint32_t contextLen; // length of the user specific context
    bool isDeterministic;
    uint8_t *addrand; // optional random bytes, can be set through CTRL interface, or comes from RNG
    uint32_t addrandLen; // length of the optional random bytes
    bool isPrehash;
    bool isXmss; /* XMSS and SLH-DSA share common structure,
                  * true : XMSS, false : SLH-DSA */
    SlhDsaPrvKey prvKey;
    SlhDsaHashFuncs hashFuncs;
    AdrsOps adrsOps;
    uint8_t keyType; /* specify the key type */
    void *libCtx;
};

#endif // HITLS_CRYPTO_SLH_DSA
#endif // SLH_DSA_LOCAL_H
