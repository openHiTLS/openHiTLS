/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

/**
 * @defgroup crypt_eal_provider
 * @ingroup crypt
 * @brief default provider header
 */

#ifndef CRYPT_EAL_DEFAULT_PROVIDER_H
#define CRYPT_EAL_DEFAULT_PROVIDER_H

#include <stdint.h>
#include "crypt_eal_implprovider.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef struct EalDefProvCtx {
    void *mgrCtxHandle; // default provider may need libCtx
} CRYPT_EAL_DefProvCtx;

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // CRYPT_EAL_DEFAULT_PROVIDER_H