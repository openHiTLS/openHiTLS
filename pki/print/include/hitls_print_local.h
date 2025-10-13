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

#ifndef HITLS_PRINT_LOCAL_H
#define HITLS_PRINT_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_PKI_INFO
#include <stdint.h>
#include "bsl_uio.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HITLS_PKI_INFO_DN_CONF
int32_t HITLS_PKI_SetPrintFlag(int32_t val);

int32_t HITLS_PKI_GetPrintFlag(void);
#endif

int32_t HITLS_PKI_PrintDnName(uint32_t layer, BslList *list, bool newLine, BSL_UIO *uio);

#ifdef __cplusplus
}
#endif

#endif // HITLS_PKI_INFO

#endif // HITLS_PRINT_LOCAL_H
