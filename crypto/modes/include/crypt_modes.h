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

#ifndef CRYPT_MODES_H
#define CRYPT_MODES_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_MODES

#include <stdint.h>
#include "crypt_eal_cipher.h"
#include "crypt_types.h"
#include "crypt_algid.h"
#include "crypt_local_types.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define MODES_MAX_IV_LENGTH 24
#define MODES_MAX_BUF_LENGTH 24
#define DES_BLOCK_BYTE_NUM 8

#define UPDATE_VALUES(l, i, o, len) \
    do { \
        (l) -= (len); \
        (i) += (len); \
        (o) += (len); \
    } while (false)

/**
 * @ingroup crypt_mode_cipherctx
 *   mode handle
 */
typedef struct {
    void *ciphCtx;  /* Context defined by each algorithm  */
    const EAL_CipherMethod *ciphMeth; /* Corresponding to the related methods for each symmetric algorithm */
    uint8_t iv[MODES_MAX_IV_LENGTH];   /* IV information */
    uint8_t buf[MODES_MAX_BUF_LENGTH]; /* Cache the information of the previous block. */
    uint8_t blockSize;                 /* Save the block size. */
    /* Used in CTR and OFB modes. If offset > 0, [0, offset-1] of iv indicates the used data,
       [offset, blockSize-1] indicates unused data. */
    uint8_t offset;
    CRYPT_SYM_AlgId algId;             /* symmetric algorithm ID */
} MODE_CipherCtx;

typedef struct {
    const uint8_t *in;
    uint8_t *out;
    const uint8_t *ctr;
    uint8_t *tag;
} XorCryptData;

/**
 * @brief Initialize the module, register the method of the encryption and decryption algorithm with the module,
 *        and create the algorithm context.
 *
 * @param ctx    [IN/OUT] mode handle
 * @param method [IN] Symmetric encryption and decryption method
 * @return If the operation is successful, the return value is CRYPT_SUCCESS.
 * Other error codes are returned if the operation fails.
 */
int32_t MODE_InitCtx(MODE_CipherCtx *ctx, const EAL_CipherMethod *method);

/**
 * @brief Deinitialize the module, remove the relationship between the module and the algorithm module,
 *        and release the algorithm context.
 *
 * @param ctx    [IN] Mode handle
 * @param method [IN] Symmetric encryption and decryption methods
 */
void MODE_DeInitCtx(MODE_CipherCtx *ctx);

/**
 * @brief Set the encryption key.
 *
 * @param ctx [IN/OUT] mode handle
 * @param key [IN] Encryption key
 * @param len [IN] Encryption key length
 * @return Success: CRYPT_SUCCESS
 *         failure: Other error codes.
 */
int32_t MODE_SetEncryptKey(MODE_CipherCtx *ctx, const uint8_t *key, uint32_t len);


/**
 * @brief Set the decryption key.
 *
 * @param ctx [IN/OUT] mode handle
 * @param key [IN] Decryption key
 * @param len [IN] Decryption key length
 * @return Success: CRYPT_SUCCESS
 * Other error codes are returned if the operation fails.
 */
int32_t MODE_SetDecryptKey(MODE_CipherCtx *ctx, const uint8_t *key, uint32_t len);

#ifdef HITLS_CRYPTO_SM4
/**
 * @brief Set the encryption key in SM4.
 *
 * @param ctx [IN] mode handle
 * @param key [IN] Encryption key
 * @param len [IN] Encryption key length. Only 16 (128 bits) is supported.
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODES_SM4_SetEncryptKey(MODE_CipherCtx *ctx, const uint8_t *key, uint32_t len);

/**
 * @brief Set the decryption key in SM4.
 *
 * @param ctx [IN] mode handle
 * @param key [IN] Decryption key
 * @param len [IN] Decryption key length. Only 16 (128 bits) is supported.
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODES_SM4_SetDecryptKey(MODE_CipherCtx *ctx, const uint8_t *key, uint32_t len);
#endif

/**
 * @brief Operate the mode parameter.
 *
 * @param ctx [IN/OUT] mode handle
 * @param opt [IN] Operation
 * @param val [IN/OUT] Parameter, which can be an input parameter or an output parameter.
 * @param len [IN] Parameter length
 * @return Success: CRYPT_SUCCESS
 *         failure: Other error codes.
 */
int32_t MODE_Ctrl(MODE_CipherCtx *ctx, CRYPT_CipherCtrl opt, void *val, uint32_t len);

/**
 * @brief Clean Mode content and sensitive data. Preserve the memory and methods of algorithm modules
 *
 * @param ctx [IN] Mode handle
 * @return None
 */
void MODE_Clean(MODE_CipherCtx *ctx);

int32_t MODE_SetIv(MODE_CipherCtx *ctx, uint8_t *val, uint32_t len);
int32_t MODE_GetIv(MODE_CipherCtx *ctx, uint8_t *val, uint32_t len);

static inline void MODE_IncCounter(uint8_t *counter, uint32_t counterLen)
{
    uint32_t i = counterLen;
    uint16_t carry = 1;

    while (i > 0) {
        i--;
        carry += counter[i];
        counter[i] = carry & (0xFFu);
        carry >>= 8;  // Take the upper 8 bits.
    }
}

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_MODES

#endif // CRYPT_MODES_H
