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

/**
 * @defgroup crypt_eal_provider
 * @ingroup crypt
 * @brief iso19790 provider header
 */

#ifndef CRYPT_EAL_ISO_PROVIDER_H
#define CRYPT_EAL_ISO_PROVIDER_H

#ifdef HITLS_CRYPTO_CMVP_ISO19790

#include <stdint.h>
#include "crypt_eal_implprovider.h"
#include "crypt_eal_cmvp.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define CRYPT_PARAM_EVENT          1
#define CRYPT_PARAM_OPERAID        2
#define CRYPT_PARAM_ALGID          3
#define CRYPT_PARAM_ALGO_TYPE      4
#define CRYPT_PARAM_PCT_CTX        5
#define CRYPT_PARAM_PROV_CTX       6
#define CRYPT_PARAM_OPERA_RET      7
#define CRYPT_PARAM_SELF_TEST_FLAG 8
#define CRYPT_PARAM_LIB_CTX        9

#define CRYPT_EAL_ISO_ATTR "provider=iso19790_provider"

typedef struct EalIsoProvCtx {
    void *libCtx;
    void *mgrCtx;
    CRYPT_EAL_CMVP_LogFunc runLog;
} CRYPT_EAL_IsoProvCtx;

int32_t CRYPT_EAL_ProviderInit(CRYPT_EAL_ProvMgrCtx *mgrCtx, BSL_Param *param, CRYPT_EAL_Func *capFuncs,
    CRYPT_EAL_Func **outFuncs, void **provCtx);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif /* HITLS_CRYPTO_CMVP_ISO19790 */
#endif // CRYPT_EAL_ISO_PROVIDER_H