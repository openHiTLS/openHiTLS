/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */
#ifndef CRYPT_EALINIT_H
#define CRYPT_EALINIT_H
 
#include "hitls_build.h"
 
#include <stdint.h>
 
#ifdef __cplusplus
extern "C" {
#endif // __cplusplus
 
 
#ifdef HITLS_CRYPTO_ASM_CHECK
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
 
#endif // HITLS_CRYPTO_ASM_CHECK
 
#ifdef __cplusplus
}
#endif // __cplusplus
#endif // CRYPT_EALINIT_H