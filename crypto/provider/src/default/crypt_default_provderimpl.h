/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *------------------------- --------------------------------------------------------------------
 */

/**
 * @defgroup crypt_eal_provider
 * @ingroup crypt
 * @brief default provider impl
 */

#ifndef CRYPT_EAL_DEFAULT_PROVIDERIMPL_H
#define CRYPT_EAL_DEFAULT_PROVIDERIMPL_H

#include "crypt_eal_implprovider.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

extern const CRYPT_EAL_Func defMdMd5[];
extern const CRYPT_EAL_Func defMdSha1[];
extern const CRYPT_EAL_Func defMdSha224[];
extern const CRYPT_EAL_Func defMdSha256[];
extern const CRYPT_EAL_Func defMdSha384[];
extern const CRYPT_EAL_Func defMdSha512[];
extern const CRYPT_EAL_Func defMdSha3224[];
extern const CRYPT_EAL_Func defMdSha3256[];
extern const CRYPT_EAL_Func defMdSha3384[];
extern const CRYPT_EAL_Func defMdSha3512[];
extern const CRYPT_EAL_Func defMdShake512[];
extern const CRYPT_EAL_Func defMdShake128[];
extern const CRYPT_EAL_Func defMdShake256[];
extern const CRYPT_EAL_Func defMdSm3[];

extern const CRYPT_EAL_Func defKdfScrypt[];
extern const CRYPT_EAL_Func defKdfPBKdf2[];
extern const CRYPT_EAL_Func defKdfKdfTLS12[];
extern const CRYPT_EAL_Func defKdfHkdf[];

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // CRYPT_EAL_DEFAULT_PROVIDERIMPL_H