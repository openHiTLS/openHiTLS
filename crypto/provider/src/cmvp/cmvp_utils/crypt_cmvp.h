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
#include <stdint.h>
#include "bsl_params.h"
#include "crypt_types.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_md.h"
#include "crypt_eal_mac.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_kdf.h"
#include "crypt_cmvp.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef void* (*CmvpProvNewCtx)(void *provCtx);
typedef const char* (*CmvpGetVersion)(void *ctx);
typedef int32_t (*CmvpSelftest)(void *ctx, const BSL_Param *param);
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

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* CRYPT_CMVP_H */
