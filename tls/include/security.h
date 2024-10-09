/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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
int32_t SECURITY_CfgCheck(HITLS_Config *config, int32_t option, int32_t bits, int32_t id, void *other);

/* check TLS link security */
int32_t SECURITY_SslCheck(HITLS_Ctx *ctx, int32_t option, int32_t bits, int32_t id, void *other);

/* get the security strength corresponding to the security level */
int32_t SECURITY_GetSecbits(int32_t level);

#ifdef __cplusplus
}
#endif

#endif // SECURITY_H