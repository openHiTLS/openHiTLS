/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include "hitls_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/** clear the TLS configuration */
void CFG_CleanConfig(HITLS_Config *config);

/** copy the TLS configuration */
int32_t CFG_DumpConfig(HITLS_Ctx *ctx, const HITLS_Config *srcConfig);

#ifdef __cplusplus
}
#endif

#endif