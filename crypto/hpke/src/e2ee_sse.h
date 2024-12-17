#ifndef E2EE_SSE_H
#define E2EE_SSE_H

#include "crypt_errno.h"
#include "crypt_params_key.h"
#include "e2ee_key_exch.h"

typedef struct E2EE_SelfEncryptionCtx E2EE_SelfEncryptionCtx;

int32_t CreateSelfEncryptionCtx(E2EE_AlgId *algId, uint8_t *salt, uint32_t saltLen, uint8_t *secret, uint32_t secretLen,
    E2EE_SelfEncryptionCtx **ctx);

void DestroySelfEncryptionCtx(E2EE_SelfEncryptionCtx *ctx);

int32_t E2eeAeadEncrypt(E2EE_SelfEncryptionCtx *ctx, uint8_t *aad, uint32_t aadLen, const uint8_t *plainText,
    uint32_t plainTextLen, uint8_t *cipherText, uint32_t *cipherTextLen);

int32_t E2eeAeadDecrypt(E2EE_SelfEncryptionCtx *ctx, uint8_t *aad, uint32_t aadLen, const uint8_t *cipherText,
    uint32_t cipherTextLen, uint8_t *plainText, uint32_t *plainTextLen);

int32_t E2eeSha256(const uint8_t *data, uint32_t dataLen, uint8_t *hash, uint32_t hashLen);

#endif