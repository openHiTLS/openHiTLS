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
#ifndef CRYPT_EALINIT_H
#define CRYPT_EALINIT_H
 
#include "hitls_build.h"
#ifdef HITLS_CRYPTO_ASM_CHECK
#include <stdint.h>
#include "crypt_algid.h"
 
#ifdef __cplusplus
extern "C" {
#endif // __cplusplus
 
/**
 * @ingroup crypt_asmcap
 * @brief Check cpu capability for assembly implementation
 *
 * @param id [IN] algorithm id
 * @retval CRYPT_SUCCESS                    Instantiation succeeded.
 * @retval CRYPT_EAL_ALG_ASM_NOT_SUPPORT    CPU is not supported for assembly implementation
*/
int32_t CRYPT_ASMCAP_Cipher(CRYPT_CIPHER_AlgId id);
 
/**
 * @ingroup crypt_asmcap
 * @brief Check cpu capability for assembly implementation
 *
 * @param id [IN] algorithm id
 * @retval CRYPT_SUCCESS                    Instantiation succeeded.
 * @retval CRYPT_EAL_ALG_ASM_NOT_SUPPORT    CPU is not supported for assembly implementation
*/
int32_t CRYPT_ASMCAP_Md(CRYPT_MD_AlgId id);
 
/**
 * @ingroup crypt_asmcap
 * @brief Check cpu capability for assembly implementation
 *
 * @param id [IN] algorithm id
 * @retval CRYPT_SUCCESS                    Instantiation succeeded.
 * @retval CRYPT_EAL_ALG_ASM_NOT_SUPPORT    CPU is not supported for assembly implementation
*/
int32_t CRYPT_ASMCAP_Pkey(CRYPT_PKEY_AlgId id);
 
/**
 * @ingroup crypt_asmcap
 * @brief Check cpu capability for assembly implementation
 *
 * @param id [IN] algorithm id
 * @retval CRYPT_SUCCESS                    Instantiation succeeded.
 * @retval CRYPT_EAL_ALG_ASM_NOT_SUPPORT    CPU is not supported for assembly implementation
*/
int32_t CRYPT_ASMCAP_Mac(CRYPT_MAC_AlgId id);
 
/**
 * @ingroup crypt_asmcap
 * @brief Check cpu capability for assembly implementation
 *
 * @param id [IN] algorithm id
 * @retval CRYPT_SUCCESS                    Instantiation succeeded.
 * @retval CRYPT_EAL_ALG_ASM_NOT_SUPPORT    CPU is not supported for assembly implementation
*/
int32_t CRYPT_ASMCAP_Drbg(CRYPT_RAND_AlgId id);
 
 
#ifdef __cplusplus
}
#endif // __cplusplus
#endif // HITLS_CRYPTO_ASM_CHECK
#endif // CRYPT_EALINIT_H