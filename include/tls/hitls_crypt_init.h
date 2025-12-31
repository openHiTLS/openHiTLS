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
 * @ingroup hitls_crypt_init
 *
 * @brief   Initialize the algorithm interface. By default, the hicrypto interface is used.
 * @attention If hicrypto is not used, you do not need to call this API.
 * @param   NA
 * @return  void
 */
void HITLS_CryptMethodInit(void);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPT_INIT_H */