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

#ifndef CRYPT_DECODE_KEY_IMPL_H
#define CRYPT_DECODE_KEY_IMPL_H

#ifdef __cplusplus
extern "C" {
#endif

#include "hitls_build.h"

#ifdef HITLS_CRYPTO_ENCODE_DECODE_KEY
#include <stdint.h>
#include "bsl_params.h"

typedef struct {
    const char *outFormat;
    const char *outType;
} DECODER_CommonCtx;

int32_t DECODER_CommonGetParam(const DECODER_CommonCtx *commonCtx, BSL_Param *param);

void *DECODER_EPki2Pki_NewCtx(void *provCtx);
int32_t DECODER_EPki2Pki_GetParam(void *ctx, BSL_Param *param);
int32_t DECODER_EPki2Pki_SetParam(void *ctx, const BSL_Param *param);
int32_t DECODER_EPki2Pki_Decode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam);
void DECODER_EPki2Pki_FreeOutData(void *ctx, BSL_Param *outParam);
void DECODER_EPki2Pki_FreeCtx(void *ctx);

int32_t DECODER_Der2Key_GetParam(void *ctx, BSL_Param *param);
int32_t DECODER_Der2Key_SetParam(void *ctx, const BSL_Param *param);
void DECODER_Der2Key_FreeOutData(void *ctx, BSL_Param *outParam);
void DECODER_Der2Key_FreeCtx(void *ctx);

#ifdef HITLS_CRYPTO_RSA
void *DECODER_RsaDer2Key_NewCtx(void *provCtx);
int32_t DECODER_RsaPrvKeyDer2Key_Decode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam);
int32_t DECODER_RsaPubKeyDer2Key_Decode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam);
int32_t DECODER_RsaSubPubKeyDer2Key_Decode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam);
int32_t DECODER_RsaSubPubKeyWithOutSeqDer2Key_Decode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam);
int32_t DECODER_RsaPkcs8Der2Key_Decode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam);
#endif

#ifdef HITLS_CRYPTO_ECDSA
void *DECODER_EcdsaDer2Key_NewCtx(void *provCtx);
int32_t DECODER_EcdsaPrvKeyDer2Key_Decode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam);
int32_t DECODER_EcdsaSubPubKeyDer2Key_Decode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam);
int32_t DECODER_EcdsaSubPubKeyWithOutSeqDer2Key_Decode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam);
int32_t DECODER_EcdsaPkcs8Der2Key_Decode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam);
#endif

#ifdef HITLS_CRYPTO_SM2
void *DECODER_Sm2Der2Key_NewCtx(void *provCtx);
int32_t DECODER_Sm2PrvKeyDer2Key_Decode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam);
int32_t DECODER_Sm2SubPubKeyDer2Key_Decode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam);
int32_t DECODER_Sm2SubPubKeyWithOutSeqDer2Key_Decode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam);
int32_t DECODER_Sm2Pkcs8Der2Key_Decode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam);
#endif

#ifdef HITLS_CRYPTO_ED25519
void *DECODER_Ed25519Der2Key_NewCtx(void *provCtx);
int32_t DECODER_Ed25519SubPubKeyDer2Key_Decode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam);
int32_t DECODER_Ed25519SubPubKeyWithOutSeqDer2Key_Decode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam);
int32_t DECODER_Ed25519Pkcs8Der2Key_Decode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam);
#endif

#ifdef HITLS_BSL_PEM
void *DECODER_Pem2Der_NewCtx(void *provCtx);
int32_t DECODER_Pem2Der_GetParam(void *ctx, BSL_Param *param);
int32_t DECODER_Pem2Der_SetParam(void *ctx, const BSL_Param *param);
int32_t DECODER_Pem2Der_Decode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam);
void DECODER_Pem2Der_FreeOutData(void *ctx, BSL_Param *outParam);
void DECODER_Pem2Der_FreeCtx(void *ctx);
#endif

void *DECODER_LowKeyObject2PkeyObject_NewCtx(void *provCtx);
int32_t DECODER_LowKeyObject2PkeyObject_SetParam(void *ctx, const BSL_Param *param);
int32_t DECODER_LowKeyObject2PkeyObject_GetParam(void *ctx, BSL_Param *param);
int32_t DECODER_LowKeyObject2PkeyObject_Decode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam);
void DECODER_LowKeyObject2PkeyObject_FreeOutData(void *ctx, BSL_Param *outParam);
void DECODER_LowKeyObject2PkeyObject_FreeCtx(void *ctx);

#endif /* HITLS_CRYPTO_ENCODE_DECODE_KEY */

#ifdef __cplusplus
}
#endif

#endif /* CRYPT_DECODE_KEY_IMPL_H */
