/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef CONFIG_CHECK_H
#define CONFIG_CHECK_H

#include <stdint.h>
#include "hitls_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/** check the version */
int32_t CFG_CheckVersion(uint16_t minVersion, uint16_t maxVersion);

/** check whether the TLS configuration is valid */
int32_t CFG_CheckConfig(const HITLS_Config *config);

#ifdef __cplusplus
}
#endif

#endif