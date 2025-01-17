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

#ifndef ZUC_LOCAL_H
#define ZUC_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_ZUC

#include "crypt_zuc.h"
#include "crypt_utils.h"

void ZUC_Init(CRYPT_ZUC_Ctx *ctx);
void ZUC_GenKeyStream(CRYPT_ZUC_Ctx *ctx, uint8_t* out, int KeyStreamLen);

#endif // HITLS_CRYPTO_ZUC

#endif // ZUC_LOCAL_H
