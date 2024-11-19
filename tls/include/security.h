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

#ifndef SECURITY_H
#define SECURITY_H

#include <stdint.h>
#include "hitls_type.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SECURITY_SUCCESS 1
#define SECURITY_ERR 0

/* set the default security level and security callback function */
void SECURITY_SetDefault(HITLS_Config *config);

/* check TLS configuration security */
int32_t SECURITY_CfgCheck(const HITLS_Config *config, int32_t option, int32_t bits, int32_t id, void *other);

/* check TLS link security */
int32_t SECURITY_SslCheck(const HITLS_Ctx *ctx, int32_t option, int32_t bits, int32_t id, void *other);

/* get the security strength corresponding to the security level */
int32_t SECURITY_GetSecbits(int32_t level);

#ifdef __cplusplus
}
#endif

#endif // SECURITY_H