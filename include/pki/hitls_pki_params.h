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

#ifndef HITLS_PKI_PARAMS_H
#define HITLS_PKI_PARAMS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HITLS_PKI_PARAM_CMS_BASE                               30000
#define HITLS_CMS_PARAM_DIGEST                      (HITLS_PKI_PARAM_CMS_BASE + 1)
#define HITLS_CMS_PARAM_SIGNERINFO_VERSION          (HITLS_PKI_PARAM_CMS_BASE + 2)
#define HITLS_CMS_PARAM_CA_CERT_LISTS               (HITLS_PKI_PARAM_CMS_BASE + 3)
#define HITLS_CMS_PARAM_UNTRUSTED_CERT_LISTS        (HITLS_PKI_PARAM_CMS_BASE + 4)
#define HITLS_CMS_PARAM_DETACHED                    (HITLS_PKI_PARAM_CMS_BASE + 5)
#define HITLS_CMS_PARAM_CERT_LISTS                  (HITLS_PKI_PARAM_CMS_BASE + 6)
#define HITLS_CMS_PARAM_CRL_LISTS                   (HITLS_PKI_PARAM_CMS_BASE + 7)
#define HITLS_CMS_PARAM_PRIVATE_KEY                 (HITLS_PKI_PARAM_CMS_BASE + 8)
#define HITLS_CMS_PARAM_DEVICE_CERT                 (HITLS_PKI_PARAM_CMS_BASE + 9)
#define HITLS_CMS_PARAM_STORE_FLAGS                 (HITLS_PKI_PARAM_CMS_BASE + 10)
#define HITLS_CMS_PARAM_NO_SIGNED_ATTRS             (HITLS_PKI_PARAM_CMS_BASE + 11)

#ifdef __cplusplus
}
#endif

#endif
