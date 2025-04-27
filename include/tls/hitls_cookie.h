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


#ifndef HITLS_COOKIE_H
#define HITLS_COOKIE_H

#include <stdint.h>
#include "hitls_type.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HITLS_COOKIE_GENERATE_SUCCESS 1       /* Cookie Generated successfully */
#define HITLS_COOKIE_GENERATE_ERROR 0         /* Cookie Generation failed */
#define HITLS_COOKIE_VERIFY_SUCCESS 1         /* Cookie verification succeeded */
#define HITLS_COOKIE_VERIFY_ERROR 0           /* Cookie verification failed */


/**
 * @ingroup hitls_config
 * @brief   Cookie Generation callback prototype for the server to process the callback.
 *
 * @param   ctx  [IN] Ctx context
 * @param   cookie  [OUT] Generated cookie
 * @param   cookie_len  [OUT] Length of Generated cookie
 * @retval  COOKIE_GEN_SUCCESS: successful. Other values are considered as failure.
 */
typedef int32_t (*HITLS_AppGenCookieCb)(HITLS_Ctx *ctx, uint8_t *cookie, uint32_t *cookieLen);

/**
 * @ingroup hitls_config
 * @brief   Cookie Verification callback prototype for the server to process the callback.
 *
 * @param   ctx  [IN] Ctx context
 * @param   cookie  [IN] Cookie to be verified
 * @param   cookie_len  [IN] Length of Cookie to be verified
 * @retval  COOKIE_VERIFY_SUCCESS: successful. Other values are considered as failure.
 */
typedef int32_t (*HITLS_AppVerifyCookieCb)(HITLS_Ctx *ctx, const uint8_t *cookie, uint32_t cookieLen);

/**
 * @ingroup hitls_config
 * @brief   Set the cookie generation callback on the server.
 *
 * @param   config [OUT] Config context
 * @param   callback  [IN] CookieGenerate callback
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetCookieGenCb(HITLS_Config *config, HITLS_AppGenCookieCb callback);

/**
 * @ingroup hitls_config
 * @brief   Set the cookie verification callback on the server.
 *
 * @param   config [OUT] Config context
 * @param   callback  [IN] CookieVerify callback
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetCookieVerifyCb(HITLS_Config *config, HITLS_AppVerifyCookieCb callback);

#ifdef __cplusplus
}
#endif

#endif // HITLS_COOKIE_H