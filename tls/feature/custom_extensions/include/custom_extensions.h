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

// Define CustomExt_Method structure
typedef struct {
    uint16_t extType;
    uint32_t context;
    HITLS_AddCustomExtCallback addCb;
    HITLS_FreeCustomExtCallback freeCb;
    void *addArg;
    HITLS_ParseCustomExtCallback parseCb;
    void *parseArg;
} CustomExt_Method;

// Define CustomExt_Methods structure
typedef struct {
    CustomExt_Method *meths;
    uint32_t methsCount;
} CustomExt_Methods;

bool IsPackNeedCustomExtensions(CustomExt_Methods *exts, uint32_t context);
bool IsParseNeedCustomExtensions(CustomExt_Methods *exts, uint16_t extType, uint32_t context);
int32_t PackCustomExtensions(const struct TlsCtx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *len, uint32_t context);
int32_t ParseCustomExtensions(const struct TlsCtx *ctx, const uint8_t *buf, uint16_t extType, uint32_t extLen,
    uint32_t context);

#endif // CUSTOM_EXTENSIONS_H
