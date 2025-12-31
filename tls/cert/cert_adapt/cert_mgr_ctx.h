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
#ifndef CERT_MGR_CTX_H
#define CERT_MGR_CTX_H

#include <stdint.h>
#include "hitls_crypt_type.h"
#include "hitls_cert_reg.h"
#include "cert.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CERT_DEFAULT_HASH_BKT_SIZE 64u

/* These functions can be stored in a separate header file. */
HITLS_CERT_Chain *SAL_CERT_ChainNew(void);
int32_t SAL_CERT_ChainAppend(HITLS_CERT_Chain *chain, HITLS_CERT_X509 *cert);
HITLS_CERT_Chain *SAL_CERT_ChainDup(CERT_MgrCtx *mgrCtx, HITLS_CERT_Chain *chain);

#ifdef __cplusplus
}
#endif
#endif