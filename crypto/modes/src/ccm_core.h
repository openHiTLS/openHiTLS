/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */
#ifndef CCM_CORE_H
#define CCM_CORE_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CCM

#include "crypt_modes_ccm.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

typedef int32_t (*CcmCore)(MODES_CCM_Ctx *, const uint8_t *, uint8_t *, uint32_t, bool);

int32_t CcmCrypt(MODES_CCM_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, bool enc, const CcmCore func);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif
#endif