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

#ifndef CONN_INIT_H
#define CONN_INIT_H

#include <stdint.h>
#include "hitls_build.h"
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