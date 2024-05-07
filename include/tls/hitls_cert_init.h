/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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
 * @brief   Certificate initialization interface, default use the HITLS X509 interface.
 *
 * @attention If HITLS X509 not be used, do not need to call this interface.
 * @param   NA
 * @retval  void
 */
int32_t HITLS_CertMethodInit(void);

/**
 * @ingroup hitls_cert_init
 * @brief   Deinitialize the certificate, set the certificate registration interface to NULL.
 *
 * @param   NA
 * @retval  void
 */
void HITLS_CertMethodDeinit(void);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPT_CERT_H */
