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
#ifndef HITLS_APP_GENRSA_H
#define HITLS_APP_GENRSA_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define REC_MAX_PEM_FILELEN  65537
#define REC_MAX_PKEY_LENGTH  16384
#define REC_MIN_PKEY_LENGTH    512
#define REC_ALG_NUM_EACHLINE     4

int32_t HITLS_GenRSAMain(int argc, char *argv[]);

#ifdef __cplusplus
}
#endif
#endif
