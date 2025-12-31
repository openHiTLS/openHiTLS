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
 /**
 * @defgroup hitls_cert_init
 * @ingroup  hitls
 * @brief    TLS certificate abstraction layer initialization
 */
#ifndef HITLS_CERT_INIT_H
#define HITLS_CERT_INIT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup hitls_cert_init
 *
 * @brief   Certificate initialization interface, default use the HITLS X509 interface.
 * @param   NA
 * @return  void
 */
int32_t HITLS_CertMethodInit(void);

/**
 * @ingroup hitls_cert_init
 *
 * @brief   Deinitialize the certificate, set the certificate registration interface to NULL.
 * @param   NA
 * @return  void
 */
void HITLS_CertMethodDeinit(void);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPT_CERT_H */
