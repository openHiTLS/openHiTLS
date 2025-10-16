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

#ifndef CRYPT_ML_KEM_H
#define CRYPT_ML_KEM_H
#include <stdint.h>
#include "crypt_types.h"
#include "bsl_params.h"

typedef struct CryptMlKemCtx CRYPT_ML_KEM_Ctx;

CRYPT_ML_KEM_Ctx *CRYPT_ML_KEM_NewCtx(void);

CRYPT_ML_KEM_Ctx *CRYPT_ML_KEM_NewCtxEx(void *libCtx);

void CRYPT_ML_KEM_FreeCtx(CRYPT_ML_KEM_Ctx *ctx);

CRYPT_ML_KEM_Ctx *CRYPT_ML_KEM_DupCtx(CRYPT_ML_KEM_Ctx *ctx);

int32_t CRYPT_ML_KEM_Ctrl(CRYPT_ML_KEM_Ctx *ctx, int32_t opt, void *val, uint32_t len);

int32_t CRYPT_ML_KEM_GenKey(CRYPT_ML_KEM_Ctx *ctx);

int32_t CRYPT_ML_KEM_SetEncapsKey(CRYPT_ML_KEM_Ctx *ctx, const CRYPT_KemEncapsKey *ek);

int32_t CRYPT_ML_KEM_GetEncapsKey(const CRYPT_ML_KEM_Ctx *ctx, CRYPT_KemEncapsKey *ek);

int32_t CRYPT_ML_KEM_SetDecapsKey(CRYPT_ML_KEM_Ctx *ctx, const CRYPT_KemDecapsKey *dk);

int32_t CRYPT_ML_KEM_GetDecapsKey(const CRYPT_ML_KEM_Ctx *ctx, CRYPT_KemDecapsKey *dk);

#ifdef HITLS_BSL_PARAMS
int32_t CRYPT_ML_KEM_SetEncapsKeyEx(CRYPT_ML_KEM_Ctx *ctx, const BSL_Param *para);

int32_t CRYPT_ML_KEM_GetEncapsKeyEx(const CRYPT_ML_KEM_Ctx *ctx, BSL_Param *para);

int32_t CRYPT_ML_KEM_SetDecapsKeyEx(CRYPT_ML_KEM_Ctx *ctx, const BSL_Param *para);

int32_t CRYPT_ML_KEM_GetDecapsKeyEx(const CRYPT_ML_KEM_Ctx *ctx, BSL_Param *para);
#endif

#ifdef HITLS_CRYPTO_MLKEM_CMP
int32_t CRYPT_ML_KEM_Cmp(const CRYPT_ML_KEM_Ctx *a, const CRYPT_ML_KEM_Ctx *b);
#else
#define CRYPT_ML_KEM_Cmp NULL
#endif

int32_t CRYPT_ML_KEM_GetSecBits(const CRYPT_ML_KEM_Ctx *ctx);

int32_t CRYPT_ML_KEM_Encaps(const CRYPT_ML_KEM_Ctx *ctx, uint8_t *cipher, uint32_t *cipherLen,
    uint8_t *share, uint32_t *shareLen);

int32_t CRYPT_ML_KEM_Decaps(const CRYPT_ML_KEM_Ctx *ctx, uint8_t *cipher, uint32_t cipherLen,
    uint8_t *share, uint32_t *shareLen);

#ifdef HITLS_CRYPTO_MLKEM_CHECK

/**
 * @ingroup mlkem
 * @brief check the key pair consistency
 *
 * @param checkType [IN] check type
 * @param pkey1 [IN] mlkem key context structure
 * @param pkey2 [IN] mlkem key context structure
 *
 * @retval CRYPT_SUCCESS    check success.
 * Others. For details, see error code in errno.
 */
int32_t CRYPT_ML_KEM_Check(uint32_t checkType, const CRYPT_ML_KEM_Ctx *pkey1, const CRYPT_ML_KEM_Ctx *pkey2);

#endif // HITLS_CRYPTO_MLKEM_CHECK

#endif    // CRYPT_ML_KEM_H
