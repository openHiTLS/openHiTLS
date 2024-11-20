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

#define CRYPT_DSA_KEY_P    001
#define CRYPT_DSA_KEY_Q    002
#define CRYPT_DSA_KEY_G    003

#define CRYPT_RSA_KEY_N    101
#define CRYPT_RSA_KEY_E    102
#define CRYPT_RSA_KEY_D    103
#define CRYPT_RSA_KEY_P    104
#define CRYPT_RSA_KEY_Q    105
#define CRYPT_RSA_KEY_DQ   106
#define CRYPT_RSA_KEY_DP   107
#define CRYPT_RSA_KEY_QINV 108
#define CRYPT_RSA_KEY_BITS 109

#define CRYPT_DH_KEY_P     201
#define CRYPT_DH_KEY_Q     202
#define CRYPT_DH_KEY_G     203

#define CRYPT_ECC_KEY_P    301
#define CRYPT_ECC_KEY_A    302
#define CRYPT_ECC_KEY_B    303
#define CRYPT_ECC_KEY_N    304
#define CRYPT_ECC_KEY_H    305
#define CRYPT_ECC_KEY_X    306
#define CRYPT_ECC_KEY_Y    307

#define CRYPT_PAILLER_KEY_N      401
#define CRYPT_PAILLER_KEY_LAMBDA 402
#define CRYPT_PAILLER_KEY_MU     403
#define CRYPT_PAILLER_KEY_N2     404
#define CRYPT_PAILLER_KEY_G      405
#define CRYPT_PAILLER_KEY_P      406
#define CRYPT_PAILLER_KEY_Q      407
#define CRYPT_PAILLER_KEY_BITS   408

#define CRYPT_PUBLIC_KEY   901
#define CRYPT_PRIVATE_KEY  902

#ifdef __cplusplus
}
#endif

#endif
