/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */
 /**
 * @defgroup hitls_crypt_init
 * @ingroup hitls
 * @brief  algorithm abstraction layer initialization
 */

#ifndef HITLS_CRYPT_INIT_H
#define HITLS_CRYPT_INIT_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup  hitls_crypt_init
 * @brief   Initialize the algorithm interface. By default, the hicrypto interface is used.
 *
 * @attention If hicrypto is not used, you do not need to call this API.
 */
void HITLS_CryptMethodInit(void);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPT_INIT_H */