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

// Forward declaration of struct TlsCtx
struct TlsCtx;

// Define callback function types, using struct TlsCtx * as parameter
typedef int (*SSL_custom_ext_add_cb_ex)(const struct TlsCtx *ctx, uint8_t ext_type,
                                        uint8_t context,
                                        uint8_t **out,
                                        uint32_t *outlen, void *msg,
                                        uint32_t *al, void *add_arg);

typedef void (*SSL_custom_ext_free_cb_ex)(const struct TlsCtx *ctx, uint8_t ext_type,
                                          uint8_t context,
                                          uint8_t *out,
                                          void *add_arg);

typedef int (*SSL_custom_ext_parse_cb_ex)(const struct TlsCtx *ctx, uint8_t ext_type,
                                          uint8_t context,
                                          const uint8_t **in,
                                          uint32_t *inlen, void *msg,
                                          uint32_t *al, void *parse_arg);

// Define custom_ext_method structure
typedef struct {
    uint8_t ext_type;
    uint8_t context;
    uint32_t ext_flags;
    SSL_custom_ext_add_cb_ex add_cb;
    SSL_custom_ext_free_cb_ex free_cb;
    void *add_arg;
    SSL_custom_ext_parse_cb_ex parse_cb;
    void *parse_arg;
} custom_ext_method;

// Define custom_ext_methods structure
typedef struct {
    custom_ext_method *meths;
    size_t meths_count;
} custom_ext_methods;

// Function declarations
int32_t PackCustomExtensions(const struct TlsCtx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *len, uint8_t type);
int32_t ParseCustomExtensions(const struct TlsCtx *ctx, const uint8_t *buf, uint32_t *bufOffset, uint8_t type);

#endif // CUSTOM_EXTENSIONS_H
