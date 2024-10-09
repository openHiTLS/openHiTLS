/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef CONN_INIT_H
#define CONN_INIT_H

#include <stdint.h>
#include "tls.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Initialize TLS resources.
 *
 * @param   ctx [IN] TLS context
 *
* @retval HITLS_SUCCESS succeeded.
* @retval HITLS_MEMALLOC_FAIL Memory application failed.
* @retval HITLS_INTERNAL_EXCEPTION The input parameter is a null pointer.
 */
int32_t CONN_Init(TLS_Ctx *ctx);

/**
 * @brief   Release TLS resources.
 *
 * @param   ctx [IN] TLS context
 */
void CONN_Deinit(TLS_Ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif