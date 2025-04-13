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

#ifndef ES_CF_H
#define ES_CF_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_ENTROPY) && defined(HITLS_CRYPTO_ENTROPY_SYS)

#include <stdint.h>
#include "crypt_local_types.h"

#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
    uint32_t algId;
    union {
        EAL_MdMethod mdMeth;
        EAL_SymMethod ciMeth;
        EAL_MacMethod macMeth;
    } meth;
    uint8_t *ctx;
    /* Conditioning function initialization. */
    void *(*init)(void *mdMeth);
    /* Conditioning Function Conditioning Raw Entropy Output. */
    int32_t (*update)(void *ctx, uint8_t *data, uint32_t dataLen);
    /* Deinitialize the conditioning function. */
    void (*deinit)(void *ctx);
    /* Output length of each conditioning function. */
    uint32_t (*getCfOutLen)(void *ctx);
    /* Obtaining the Entropy Data After Conditioning. */
    uint8_t *(*getEntropyData)(void *ctx, uint32_t *len);
    /* Obtains the entropy required for full entropy output. */
    uint32_t (*getNeedEntropy)(void *ctx);
} ES_CfMethod;

ES_CfMethod *ES_CFGetMethod(uint32_t algId, void *md);

ES_CfMethod *ES_CFGetDfMethod(EAL_MdMethod *mdMeth);

#ifdef __cplusplus
}
#endif

#endif

#endif