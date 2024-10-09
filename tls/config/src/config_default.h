/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef CONFIG_DEFAULT_H
#define CONFIG_DEFAULT_H

#include <stdint.h>
#include "hitls_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/* provide default configuration */
int32_t DefaultTlsAllConfig(HITLS_Config *config);

int32_t DefaultDtlsAllConfig(HITLS_Config *config);

int32_t DefaultConfig(uint16_t version, HITLS_Config *config);

int32_t DefaultTLS13Config(HITLS_Config *config);

#ifdef __cplusplus
}
#endif

#endif