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