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

#ifndef HS_COOKIE_H
#define HS_COOKIE_H

#include <stdint.h>
#include <stdbool.h>
#include "tls.h"
#include "hs_msg.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Calculate the cookie
 * The mackey is updated each time the number of times that Cookie_SECRET_LIFETIME is calculated.
 *
 * @param ctx [IN] Handshake context
 * @param clientHello [IN] Parsed clientHello structure
 * @param cookie [OUT] Calculated cookie
 * @param cookieLen [OUT] Calculated cookie length.
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval For other error codes, see hitls_error.h.
 */
int32_t HS_CalcCookie(TLS_Ctx *ctx, const ClientHelloMsg *clientHello, uint8_t *cookie, uint32_t *cookieLen);

/**
 * @brief Verify the cookie.
 * If the first cookie verification fails, the previous mackey is used for verification again.
 *
 * @param ctx [IN] Handshake context
 * @param clientHello [IN] Parsed clientHello structure
 * @param isCookieValid [OUT] Indicates whether the verification is successful.
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval For other error codes, see hitls_error.h.
 */
int32_t HS_CheckCookie(TLS_Ctx *ctx, const ClientHelloMsg *clientHello, bool *isCookieValid);

#ifdef __cplusplus
}
#endif /* end __cplusplus */
#endif /* end HS_COOKIE_H */
