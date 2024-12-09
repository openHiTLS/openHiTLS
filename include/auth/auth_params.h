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

#ifndef AUTH_PARAMS_H
#define AUTH_PARAMS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Base value for Private Pass Token parameters */
#define CRYPT_PARAM_PRIV_PASS_TOKEN                     20000
#define CRYPT_PARAM_PRIV_PASS_TOKENCHALLENGE_REQUEST    (CRYPT_PARAM_PRIV_PASS_TOKEN + 1)
#define CRYPT_PARAM_PRIV_PASS_TOKENTYPE                 (CRYPT_PARAM_PRIV_PASS_TOKEN + 2)
#define CRYPT_PARAM_PRIV_PASS_ISSUERNAME                (CRYPT_PARAM_PRIV_PASS_TOKEN + 3)
#define CRYPT_PARAM_PRIV_PASS_REDEMPTION                (CRYPT_PARAM_PRIV_PASS_TOKEN + 4)
#define CRYPT_PARAM_PRIV_PASS_ORIGININFO                (CRYPT_PARAM_PRIV_PASS_TOKEN + 5)
#define CRYPT_PARAM_PRIV_PASS_TOKENNONCE                (CRYPT_PARAM_PRIV_PASS_TOKEN + 6)

#ifdef __cplusplus
}
#endif

#endif
