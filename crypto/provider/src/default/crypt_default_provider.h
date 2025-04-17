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
 * @brief default provider header
 */

#ifndef CRYPT_EAL_DEFAULT_PROVIDER_H
#define CRYPT_EAL_DEFAULT_PROVIDER_H

#ifdef HITLS_CRYPTO_PROVIDER

#include <stdint.h>
#include "crypt_eal_implprovider.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef struct EalDefProvCtx {
    void *libCtx;
} CRYPT_EAL_DefProvCtx;

int32_t CRYPT_EAL_ProviderGetSeed(CRYPT_RandSeedMethod **method, void **seedCtx);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif /* HITLS_CRYPTO_PROVIDER */
#endif // CRYPT_EAL_DEFAULT_PROVIDER_H