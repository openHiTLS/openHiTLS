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

#ifndef CMVP_SM_H
#define CMVP_SM_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CMVP_SM

#include <stdint.h>
#include <stdbool.h>
#include "crypt_cmvp.h"
#include "crypt_algid.h"
#include "crypt_sm_provider.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

bool CMVP_SmPkeyC2(int32_t algId);

bool CMVP_SmKdfC2(const CRYPT_EAL_KdfC2Data *data);

int32_t CMVP_SmKat(void *libCtx, const char *attrName);

int32_t CMVP_SmCheckIntegrity(void *libCtx, const char *attrName);

bool CMVP_SmPkeyPct(void *ctx, int32_t algId);

int32_t CMVP_SmRandomStartupSelftest(void *libCtx, const char *attrName);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* HITLS_CRYPTO_CMVP_SM */
#endif /* CMVP_SM_H */
