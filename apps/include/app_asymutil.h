/* Copyright (c) 2025，Shandong University — School of Cyber Science and Technology
* Contributor: Xiaoran Dong, Enyu Liu, Boyu Lu, Haowei Wang, Jiayi Zhou
 * Instructor:  Weijia Wang
*/
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

#ifndef HITLS_APP_ASYMUTIL_H
#define HITLS_APP_ASYMUTIL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define REC_ITERATION_TIMES             10000
#define REC_MAX_FILENAME_LENGTH         PATH_MAX
#define REC_MAX_MAC_KEY_LEN             64
#define REC_HEX_BASE                    16
#define REC_SALT_LEN                    8
#define REC_HEX_BUF_LENGTH              8
#define REC_MIN_PRE_LENGTH              6
#define REC_DOUBLE                      2
#define MAX_BUFSIZE                     4096
#define IS_SUPPORT_GET_EOF              1

#define MAX_ASYM_BUFSIZE   8192

typedef struct {
    const int cipherId;
    const char *cipherAlgName;
} HITLS_CipherAlgList1;

typedef struct {
    const int keyAlgId;
    const char *keyAlgName;
} HITLS_AsymAlgList;

int32_t HITLS_AsymutilMain(int argc, char *argv[]);

#ifdef __cplusplus
}
#endif
#endif