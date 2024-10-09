/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef EAL_CIPHER_LOCAL_H
#define EAL_CIPHER_LOCAL_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_CIPHER)

#include "crypt_modes.h"
#include "crypt_algid.h"
#include "crypt_eal_cipher.h"
#include "crypt_local_types.h"
#ifdef HITLS_CRYPTO_GCM
#include "crypt_modes_gcm.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define EAL_MAX_BLOCK_LENGTH 32

/**
 * @ingroup  crypt_cipherstates
 * Symmetry encryption/decryption status */
typedef enum {
    EAL_CIPHER_STATE_NEW,
    EAL_CIPHER_STATE_INIT,
    EAL_CIPHER_STATE_UPDATE,
    EAL_CIPHER_STATE_FINAL
} EAL_CipherStates;

/**
 * @ingroup  alg map
 * Symmetric encryption/decryption mode and ID of the encryption algorithm.
 */
typedef struct {
    uint32_t id;
    CRYPT_MODE_AlgId modeId;
    CRYPT_SYM_AlgId  symId;
} EAL_SymAlgMap;

/**
* @ingroup  EAL
*
* EAL_Cipher is used for mode and algorithm combination.
*/
typedef struct {
    const EAL_CipherMethod *ciphMeth;
    const EAL_CipherMethod *modeMethod;
} EAL_Cipher;

typedef struct {
    uint32_t id;
    const EAL_Cipher *symMeth;
} EAL_SymAlgMapAsm;

/**
* @ingroup  EAL
*
* CRYPT_CipherInfo: User search algorithm information. Currently, only blockSize is available.
*/
typedef struct {
    CRYPT_CIPHER_AlgId id;
    uint8_t blockSize;
    uint32_t keyLen;
    uint32_t ivLen;
} CRYPT_CipherInfo;

/**
 * @ingroup  crypt_eal_cipherctx
 * Asymmetric algorithm data type */
struct CryptEalCipherCtx {
    CRYPT_CIPHER_AlgId id;
    uint8_t data[EAL_MAX_BLOCK_LENGTH];             /**< last data block that may not be processed */
    bool enc;                                       /**< whether encrypted or decrypted */
    uint8_t dataLen;                                /**< size of the last data block that may not be processed. */
    uint8_t blockSize;                              /**< blockSize corresponding to the algorithm */
    CRYPT_PaddingType pad;                          /**< padding type */
    EAL_CipherStates states;                        /**< record status */
    void *ctx;                                      /**< handle of the mode */
    const EAL_CipherMethod *method;                 /**< method corresponding to the encryption/decryption mode */
};

/**
 * @brief Obtain the EAL_Cipher based on the algorithm ID.
 *
 * @param id [IN]     Symmetric encryption/decryption algorithm ID.
 * @param m  [IN/OUT] EAL_Cipher Pointer
 * @return If it's successful, the system returns CRYPT_SUCCESS and assigns the value to the method in m.
 * If it's failed, returns CRYPT_EAL_ERR_ALGID: ID of the unsupported algorithm.
 */
int32_t EAL_FindCipher(CRYPT_CIPHER_AlgId id, EAL_Cipher *m);

/**
 * @brief Obtain the method of the symmetric algorithm based on the algorithm ID.
 *
 * @param id [IN] Symmetric algorithm ID.
 * @return If it's successful, the method of the symmetric algorithm is returned.
 * If it's failed, NULL is returned.
 */
const EAL_CipherMethod *EAL_FindSymMethod(CRYPT_SYM_AlgId id);

/**
 * @brief Obtain keyLen/ivLen/blockSize based on the algorithm ID.
 *
 * @param id [IN] Symmetric algorithm ID.
 * @param id [OUT] Assign the obtained keyLen/ivLen/blockSize to the variable corresponding to info.
 *
 * @return Success: CRYPT_SUCCESS
 *         Failure: CRYPT_ERR_ALGID
 */
int32_t EAL_GetCipherInfo(CRYPT_CIPHER_AlgId id, CRYPT_CipherInfo *info);

/**
 * @brief Obtain mode method based on the algorithm ID
 *
 * @param id [IN] Symmetric encryption/decryption algorithm ID.
 * @return If the operation is successful, the combination of ciphers is returned.
 * If the operation fails, NULL is returned.
 */
const EAL_CipherMethod *EAL_FindModeMethod(CRYPT_MODE_AlgId id);

#ifdef HITLS_CRYPTO_GCM
typedef struct {
    MODES_GCM_Ctx mode;
    int32_t (*encBlock)(MODES_GCM_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
    int32_t (*decBlock)(MODES_GCM_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
} EAL_GCM_Ctx;
#endif

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_CIPHER

#endif // EAL_CIPHER_LOCAL_H
