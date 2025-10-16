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

#ifndef HITLS_APP_PROVIDER_H
#define HITLS_APP_PROVIDER_H
#include <stdint.h>
#include "crypt_types.h"
#include "crypt_eal_provider.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *providerName;
    char *providerPath;
    char *providerAttr;
} AppProvider;

CRYPT_EAL_LibCtx *APP_Create_LibCtx(void);

CRYPT_EAL_LibCtx *APP_GetCurrent_LibCtx(void);

int32_t HITLS_APP_LoadProvider(const char *searchPath, const char *providerName);

void HITLS_APP_FreeLibCtx(void);

#ifdef __cplusplus
}
#endif
#endif