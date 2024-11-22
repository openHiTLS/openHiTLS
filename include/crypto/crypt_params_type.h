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

#ifndef CRYPT_PARAMS_TYPE_H
#define CRYPT_PARAMS_TYPE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CRYPT_PARAM_RSA_BASE         0
#define CRYPT_PARAM_RSA_N            (CRYPT_PARAM_RSA_BASE + 1)
#define CRYPT_PARAM_RSA_E            (CRYPT_PARAM_RSA_BASE + 2)
#define CRYPT_PARAM_RSA_D            (CRYPT_PARAM_RSA_BASE + 3)
#define CRYPT_PARAM_RSA_P            (CRYPT_PARAM_RSA_BASE + 4)
#define CRYPT_PARAM_RSA_Q            (CRYPT_PARAM_RSA_BASE + 5)
#define CRYPT_PARAM_RSA_DQ           (CRYPT_PARAM_RSA_BASE + 6)
#define CRYPT_PARAM_RSA_DP           (CRYPT_PARAM_RSA_BASE + 7)
#define CRYPT_PARAM_RSA_QINV         (CRYPT_PARAM_RSA_BASE + 8)
#define CRYPT_PARAM_RSA_BITS         (CRYPT_PARAM_RSA_BASE + 9)
#define CRYPT_PARAM_RSA_SALTLEN      (CRYPT_PARAM_RSA_BASE + 10)
#define CRYPT_PARAM_RSA_MD_ID        (CRYPT_PARAM_RSA_BASE + 11)
#define CRYPT_PARAM_RSA_MGF1_ID      (CRYPT_PARAM_RSA_BASE + 12)


#define CRYPT_PARAM_KDF_BASE 100
#define CRYPT_PARAM_KDF_PASSWORD     (CRYPT_PARAM_KDF_BASE + 1)
#define CRYPT_PARAM_KDF_MAC_ID       (CRYPT_PARAM_KDF_BASE + 2)
#define CRYPT_PARAM_KDF_SALT         (CRYPT_PARAM_KDF_BASE + 3)
#define CRYPT_PARAM_KDF_ITER         (CRYPT_PARAM_KDF_BASE + 4)
#define CRYPT_PARAM_KDF_MODE         (CRYPT_PARAM_KDF_BASE + 5)
#define CRYPT_PARAM_KDF_KEY          (CRYPT_PARAM_KDF_BASE + 6)
#define CRYPT_PARAM_KDF_PRK          (CRYPT_PARAM_KDF_BASE + 7)
#define CRYPT_PARAM_KDF_INFO         (CRYPT_PARAM_KDF_BASE + 8)
#define CRYPT_PARAM_KDF_EXLEN        (CRYPT_PARAM_KDF_BASE + 9)
#define CRYPT_PARAM_KDF_LABEL        (CRYPT_PARAM_KDF_BASE + 11)
#define CRYPT_PARAM_KDF_SEED         (CRYPT_PARAM_KDF_BASE + 12)
#define CRYPT_PARAM_KDF_N            (CRYPT_PARAM_KDF_BASE + 13)
#define CRYPT_PARAM_KDF_P            (CRYPT_PARAM_KDF_BASE + 14)
#define CRYPT_PARAM_KDF_R            (CRYPT_PARAM_KDF_BASE + 15)

#ifdef __cplusplus
}
#endif

#endif
