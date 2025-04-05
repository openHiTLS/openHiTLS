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

#ifndef CCM_CORE_H
#define CCM_CORE_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CCM

#include "crypt_modes_ccm.h"
#include "modes_local.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

typedef int32_t (*CcmCore)(MODES_CipherCCMCtx *, const uint8_t *, uint8_t *, uint32_t, bool);

int32_t CcmCrypt(MODES_CipherCCMCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, bool enc, const CcmCore func);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif
#endif