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

#ifndef HITLS_APP_LOG_H
#define HITLS_APP_LOG_H
#include <stdio.h>
#include <stdint.h>
#include "bsl_uio.h"
#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup HITLS_APPS
 * @brief Print output to UIO
 *
 * @param uio [IN] UIO to be printed
 * @param format [IN] Log format character string
 * @param... [IN] format Parameter
 * @retval  int32_t
 */
int32_t AppPrint(BSL_UIO *uio, const char *format, ...);

/**
 * @ingroup HiTLS_APPS
 * @brief Print the output to stderr.
 *
 * @param format [IN] Log format character string
 * @param... [IN] format Parameter
 * @retval  void
 */
void AppPrintError(const char *format, ...);

/**
 * @ingroup HiTLS_APPS
 * @brief Initialize the PrintErrUIO.
 *
 * @param fp [IN] File pointer, for example, stderr.
 * @retval  int32_t
 */

int32_t AppPrintErrorUioInit(FILE *fp);

/**
 * @ingroup HiTLS_APPS
 * @brief   Deinitialize the PrintErrUIO.
 *
 * @retval  void
 */

void AppPrintErrorUioUnInit(void);

#ifdef __cplusplus
}
#endif
#endif