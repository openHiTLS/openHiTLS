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
#ifndef CUSTOM_EXTENSIONS_H
#define CUSTOM_EXTENSIONS_H

#include "hitls_build.h"
#include "tls.h"
#include "hitls_custom_extensions.h"

// Forward declaration of struct TlsCtx
struct TlsCtx;

// Define CustomExt_Method structure
typedef struct {
    uint8_t ext_type;
    uint8_t context;
    HITLS_CustomExt_Add_Callback add_cb;
    HITLS_CustomExt_Free_Callback free_cb;
    void *add_arg;
    HITLS_CustomExt_Parse_Callback parse_cb;
    void *parse_arg;
} CustomExt_Method;

// Define CustomExt_Methods structure
typedef struct {
    CustomExt_Method *meths;
    uint32_t meths_count;
} CustomExt_Methods;

int32_t PackCustomExtensions(const struct TlsCtx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *len, uint8_t type);
int32_t ParseCustomExtensions(const struct TlsCtx *ctx, const uint8_t *buf, uint32_t *bufOffset, uint8_t type);

#endif // CUSTOM_EXTENSIONS_H


