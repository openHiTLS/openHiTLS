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

#ifndef CMVP_ISO19790_H
#define CMVP_ISO19790_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CMVP_ISO19790

#include <stdint.h>
#include <stdbool.h>
#include "crypt_cmvp.h"
#include "crypt_algid.h"
#include "crypt_iso_provderimpl.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

void CMVP_Iso19790EventProcess(CRYPT_EVENT_TYPE oper, CRYPT_ALGO_TYPE type, int32_t id, int32_t err);

bool CMVP_Iso19790PkeyC2(CRYPT_PKEY_AlgId id, const CRYPT_EAL_PkeyC2Data *data);

bool CMVP_Iso19790MacC2(CRYPT_MAC_AlgId id, uint32_t keyLen);

bool CMVP_Iso19790KdfC2(CRYPT_KDF_AlgId id, const CRYPT_EAL_KdfC2Data *data);

int32_t CMVP_Iso19790Kat(void *libCtx, const char *attrName);

int32_t CMVP_Iso19790CheckIntegrity(void *libCtx, const char *attrName);

bool CMVP_Iso19790PkeyPct(CRYPT_Iso_Pkey_Ctx *ctx);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* HITLS_CRYPTO_CMVP_ISO19790 */
#endif /* CMVP_ISO19790_H */
