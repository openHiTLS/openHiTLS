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

#ifndef ALPN_H
#define ALPN_H

#include <stdint.h>
#include "hitls_build.h"
#include "tls.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t ClientCheckNegotiatedAlpn(
    TLS_Ctx *ctx, bool haveSelectedAlpn, uint8_t *alpnSelected, uint16_t alpnSelectedSize);

#ifdef __cplusplus
}
#endif
#endif // ALPN_H