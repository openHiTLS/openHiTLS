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

#ifndef CRYPT_CMVP_H
#define CRYPT_CMVP_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CMVP

#include <stdint.h>
#include "crypt_cmvp.h"
#include "crypt_types.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_md.h"
#include "crypt_eal_mac.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_kdf.h"

#define CRYPT_CMVP_GM_SM2 (1)
#define CRYPT_CMVP_GM_SM3 (1 << 1)
#define CRYPT_CMVP_GM_SM4 (1 << 2)
#define CRYPT_CMVP_GM_DRBG (1 << 3)
#define CRYPT_CMVP_GM_MAC (1 << 4)
#define CRYPT_CMVP_GM_PBKDF (1 << 5)

typedef void* (*CmvpProvNewCtx)(void *provCtx);
typedef const char* (*CmvpGetVersion)(void *ctx);
typedef int32_t (*CmvpSelftest)(void *ctx, int32_t type);
typedef void (*CmvpFreeCtx)(void *ctx);

typedef struct {
    CmvpProvNewCtx provNewCtx;
    CmvpGetVersion getVersion;
    CmvpSelftest selftest;
    CmvpFreeCtx freeCtx;
} EAL_CmvpSelftestMethod;

struct EAL_SelftestCtx {
    bool isProvider;
    EAL_CmvpSelftestMethod *method;
    void *data;
    uint32_t state;
    int32_t id;
};

typedef enum {
    CRYPT_CMVP_MODE_NONAPPROVED,
    CRYPT_CMVP_MODE_ISO19790,
    CRYPT_CMVP_MODE_FIPS,
    CRYPT_CMVP_MODE_NDCPP,
    CRYPT_CMVP_MODE_GM,
    CRYPT_CMVP_MODE_MAX
} CRYPT_CMVP_MODE;

typedef struct {
    CRYPT_MD_AlgId mdId;
} CRYPT_RSA_PkcsV15Para;

typedef struct {
    CRYPT_MD_AlgId mdId;
    CRYPT_MD_AlgId mgfId;
} CRYPT_RSA_OaepPara;

typedef struct {
    CRYPT_MAC_AlgId macId; /**< MAC algorithm ID */
    uint32_t saltLen; /**< Salt length in bytes */
    uint32_t iter;
    uint32_t dkeyLen; /**< Derived key length in bytes */
} CRYPT_EAL_Pbkdf2Param;

typedef struct {
    CRYPT_MAC_AlgId macId; /**< MAC algorithm ID */
    uint32_t keyLen; /**< Derived key length in bytes */
} CRYPT_EAL_HkdfParam;

typedef struct {
    CRYPT_EAL_Pbkdf2Param *pbkdf2;
    CRYPT_EAL_HkdfParam *hkdf;
} CRYPT_EAL_KdfC2Data;

typedef struct {
    const CRYPT_EAL_PkeyPara *para;
    const CRYPT_EAL_PkeyPub *pub;
    const CRYPT_EAL_PkeyPrv *prv;
    CRYPT_MD_AlgId mdId; /**< MD algorithm ID */
    CRYPT_PKEY_ParaId paraId; /**< PKEY parameter ID */
    CRYPT_EVENT_TYPE oper;
    const CRYPT_RSA_PkcsV15Para *pkcsv15;
    BSL_Param *pss;
    BSL_Param *oaep;
} CRYPT_EAL_PkeyC2Data;

typedef bool (*CRYPT_EAL_PkeyC2)(CRYPT_PKEY_AlgId id, const CRYPT_EAL_PkeyC2Data *data);
typedef bool (*CRYPT_EAL_MdC2)(CRYPT_MD_AlgId id);
typedef bool (*CRYPT_EAL_MacC2)(CRYPT_MAC_AlgId id, uint32_t keyLen);
typedef bool (*CRYPT_EAL_CipherC2)(CRYPT_CIPHER_AlgId id);
typedef bool (*CRYPT_EAL_KdfC2)(CRYPT_KDF_AlgId id, const CRYPT_EAL_KdfC2Data *data);
typedef bool (*CRYPT_EAL_RandC2)(CRYPT_RAND_AlgId id);

int32_t CMVP_ModeSet(CRYPT_CMVP_MODE mode);
CRYPT_CMVP_MODE CRYPT_CMVP_ModeGet(void);
int32_t CRYPT_CMVP_StatusGet(void);
int32_t CRYPT_CMVP_ModeSet(CRYPT_CMVP_MODE mode);
int32_t CRYPT_CMVP_MultiThreadEnable(void);

bool CMVP_Pct(CRYPT_EAL_PkeyCtx *pkey);
bool CMVP_PkeyC2(CRYPT_PKEY_AlgId id, const CRYPT_EAL_PkeyC2Data *data);
#endif
#endif
