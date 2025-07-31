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
#ifndef HITLS_APP_PASSWD_H
#define HITLS_APP_PASSWD_H

#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#define REC_MAX_ITER_TIMES  999999999
#define REC_DEF_ITER_TIMES       5000
#define REC_MAX_ARRAY_LEN        1025
#define REC_MIN_ITER_TIMES       1000
#define REC_SHA512_BLOCKSIZE       64
#define REC_HASH_BUF_LEN           64
#define REC_MIN_PREFIX_LEN         37
#define REC_MAX_SALTLEN            16
#define REC_SHA512_SALTLEN         16
#define REC_TEN                    10
#define REC_PRE_ITER_LEN            8
#define REC_SEVEN                   7
#define REC_SHA512_ALGTAG           6
#define REC_SHA256_ALGTAG           5
#define REC_PRE_TAG_LEN             3
#define REC_THREE                   3
#define REC_TWO                     2
#define REC_MD5_ALGTAG              1

int32_t HITLS_PasswdMain(int argc, char *argv[]);

#ifdef __cplusplus
}
#endif
#endif
