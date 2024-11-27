#include <string.h>
#include "securec.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_kdf.h"
#include "crypt_eal_md.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_params_key.h"
#include "e2ee_key_exch_err.h"
#include "e2ee_key_exch.h"

#include "e2ee_sse.h"

#define E2EE_AEAD_NONCE_LEN  12
#define E2EE_AEAD_TAG_LEN 16
#define E2EE_HKDF_MAX_EXTRACT_LEN 64

struct E2EE_SelfEncryptionCtx {
    uint8_t *symKey;
    uint8_t *baseNonce;
    uint32_t symKeyLen;
    uint32_t baseNonceLen;
    uint64_t seq;
    CRYPT_EAL_CipherCtx *cipherCtx;
};

static int32_t HkdfExtract(CRYPT_MAC_AlgId macId, uint8_t *key, uint32_t keyLen, uint8_t *salt, uint32_t saltLen,
    uint8_t *out, uint32_t outLen)
{
    int32_t ret;
    CRYPT_HKDF_MODE mode = CRYPT_KDF_HKDF_MODE_EXTRACT;

    BSL_Param params[6] = {{0}, {0}, {0}, {0}, {0}, BSL_PARAM_END}; // 6 parameters
    ret = BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, (void *)&macId, 
        sizeof(int32_t));
    if (ret != CRYPT_SUCCESS) {
        return E2EE_ERR_CRYPTO;
    }

    ret = BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_MODE, BSL_PARAM_TYPE_UINT32, (void *)&mode, sizeof(mode));
    if (ret != CRYPT_SUCCESS) {
        return E2EE_ERR_CRYPTO;
    }

    ret = BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS, (void *)key, keyLen); // param 2
    if (ret != CRYPT_SUCCESS) {
        return E2EE_ERR_CRYPTO;
    }

    ret = BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS, (void *)salt, // param 3
        saltLen);
    if (ret != CRYPT_SUCCESS) {
        return E2EE_ERR_CRYPTO;
    }

    ret = BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_EXLEN, BSL_PARAM_TYPE_UINT32_PTR, (void *)&outLen, // param 4
        sizeof(outLen));
    if (ret != CRYPT_SUCCESS) {
        return E2EE_ERR_CRYPTO;
    }

    CRYPT_EAL_KdfCTX *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
    if (ctx == NULL) {
        return E2EE_ERR_CRYPTO;
    }

    ret = CRYPT_EAL_KdfSetParam(ctx, params);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_KdfFreeCtx(ctx);
        return E2EE_ERR_CRYPTO;
    }

    ret = CRYPT_EAL_KdfDerive(ctx, out, outLen);
    CRYPT_EAL_KdfFreeCtx(ctx);
    if (ret != CRYPT_SUCCESS) {
        return E2EE_ERR_CRYPTO;
    }
    return E2EE_SUCCESS;
}

static int32_t HkdfExpand(CRYPT_MAC_AlgId macId, uint8_t *prk, uint32_t prkLen, uint8_t *info,
    uint32_t infoLen, uint8_t *out, uint32_t outLen)
{
    int32_t ret;
    CRYPT_HKDF_MODE mode = CRYPT_KDF_HKDF_MODE_EXPAND;

    BSL_Param params[5] = {{0}, {0}, {0}, {0}, BSL_PARAM_END}; // 5 parameters
    ret = BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, (void *)&macId,
        sizeof(int32_t));
    if (ret != CRYPT_SUCCESS) {
        return E2EE_ERR_CRYPTO;
    }

    ret = BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_MODE, BSL_PARAM_TYPE_UINT32, (void *)&mode, sizeof(mode));
    if (ret != CRYPT_SUCCESS) {
        return E2EE_ERR_CRYPTO;
    }

    ret = BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_PRK, BSL_PARAM_TYPE_OCTETS, (void *)prk, prkLen); // param 2
    if (ret != CRYPT_SUCCESS) {
        return E2EE_ERR_CRYPTO;
    }

    ret = BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_INFO, BSL_PARAM_TYPE_OCTETS, (void *)info, // param 3
        infoLen); 
    if (ret != CRYPT_SUCCESS) {
        return E2EE_ERR_CRYPTO;
    }

    CRYPT_EAL_KdfCTX *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
    if (ctx == NULL) {
        return E2EE_ERR_CRYPTO;
    }

    ret = CRYPT_EAL_KdfSetParam(ctx, params);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_KdfFreeCtx(ctx);
        return E2EE_ERR_CRYPTO;
    }

    ret = CRYPT_EAL_KdfDerive(ctx, out, outLen);
    CRYPT_EAL_KdfFreeCtx(ctx);
    if (ret != CRYPT_SUCCESS) {
        return E2EE_ERR_CRYPTO;
    }

    return E2EE_SUCCESS;
}

static uint32_t GetHkdfExtractLen(CRYPT_MAC_AlgId algId)
{
    switch (algId) {
        case CRYPT_MAC_HMAC_SHA256:
            return 32;
        case CRYPT_MAC_HMAC_SHA384:
            return 48;
        case CRYPT_MAC_HMAC_SHA512:
            return 64;
        default:
            return 0;
    }
}

static CRYPT_MAC_AlgId GetKdfMacAlgId(E2EE_KDF_AlgId algId)
{
    switch (algId) {
        case E2EE_HKDF_SHA256:
            return CRYPT_MAC_HMAC_SHA256;
        case E2EE_HKDF_SHA384:
            return CRYPT_MAC_HMAC_SHA384;
        case E2EE_HKDF_SHA512:
            return CRYPT_MAC_HMAC_SHA512;
        default:
            return CRYPT_MAC_MAX;
    }
}

static int32_t SseDeriveKey(E2EE_SelfEncryptionCtx *ctx, E2EE_KDF_AlgId kdfAlgId, uint8_t *salt, uint32_t saltLen,
    uint8_t *secret, uint32_t secretLen)
{
    CRYPT_MAC_AlgId macId = GetKdfMacAlgId(kdfAlgId);
    uint8_t prk[E2EE_HKDF_MAX_EXTRACT_LEN];
    uint32_t prkLen = GetHkdfExtractLen(macId);
    int32_t ret = HkdfExtract(macId, secret, secretLen, salt, saltLen, prk, prkLen);
    if (ret != E2EE_SUCCESS) {
        return ret;
    }

    ret = HkdfExpand(macId, prk, prkLen, (uint8_t *)"key", strlen("key"), ctx->symKey, ctx->symKeyLen);
    if (ret != E2EE_SUCCESS) {
        goto end;
    }

    ret = HkdfExpand(macId, prk, prkLen, (uint8_t *)"base_nonce", strlen("base_nonce"), ctx->baseNonce, ctx->baseNonceLen);
    if (ret != E2EE_SUCCESS) {
        goto end;
    }

end:
    memset_s(prk, prkLen, 0, prkLen);
    return ret;
}

static uint32_t GetAeadKeyLen(E2EE_AEAD_AlgId algId)
{
    switch (algId) {
        case E2EE_AES_128_GCM:
            return 16;
        case E2EE_AES_256_GCM:
            return 32;
        case E2EE_CHACHA20_POLY1305:
            return 32;
        default:
            return 0;
    }
}

static CRYPT_CIPHER_AlgId GetAeadCipherAlgid(E2EE_AEAD_AlgId algId)
{
    switch (algId) {
        case E2EE_AES_128_GCM:
            return CRYPT_CIPHER_AES128_GCM;
        case E2EE_AES_256_GCM:
            return CRYPT_CIPHER_AES256_GCM;
        case E2EE_CHACHA20_POLY1305:
            return CRYPT_CIPHER_CHACHA20_POLY1305;
        default:
            return CRYPT_CIPHER_MAX;
    }
}

int32_t CreateSelfEncryptionCtx(E2EE_AlgId *algId, uint8_t *salt, uint32_t saltLen, uint8_t *secret,
    uint32_t secretLen, E2EE_SelfEncryptionCtx **ctx)
{
    int32_t ret;
    E2EE_SelfEncryptionCtx *tmpCtx = malloc(sizeof(E2EE_SelfEncryptionCtx));
    if (tmpCtx == NULL) {
        return E2EE_ERR_MALLOC;
    }
    memset_s(tmpCtx, sizeof(E2EE_SelfEncryptionCtx), 0, sizeof(E2EE_SelfEncryptionCtx));

    tmpCtx->symKeyLen = GetAeadKeyLen(algId->aeadAlgId);
    tmpCtx->symKey = malloc(tmpCtx->symKeyLen);
    if (tmpCtx->symKey == NULL) {
        free(tmpCtx);
        return E2EE_ERR_MALLOC;
    }

    tmpCtx->baseNonceLen = E2EE_AEAD_NONCE_LEN;
    tmpCtx->baseNonce = malloc(tmpCtx->baseNonceLen);
    if (tmpCtx->baseNonce == NULL) {
        ret = E2EE_ERR_MALLOC;
        goto end;
    }

    ret = SseDeriveKey(tmpCtx, algId->kdfAlgId, salt, saltLen, secret, secretLen);
    if (ret != E2EE_SUCCESS) {
        goto end;
    }

    tmpCtx->cipherCtx = CRYPT_EAL_ProviderCipherNewCtx(NULL, GetAeadCipherAlgid(algId->aeadAlgId), NULL);
    if (tmpCtx->cipherCtx == NULL) {
        ret = E2EE_ERR_CRYPTO;
        goto end;
    }

    *ctx = tmpCtx;
    return E2EE_SUCCESS;
end:
    DestroySelfEncryptionCtx(tmpCtx);
    return ret;
}

void DestroySelfEncryptionCtx(E2EE_SelfEncryptionCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    if (ctx->symKey != NULL) {
        memset_s(ctx->symKey, ctx->symKeyLen, 0, ctx->symKeyLen);
        free(ctx->symKey);
    }

    if (ctx->baseNonce != NULL) {
        memset_s(ctx->baseNonce, ctx->baseNonceLen, 0, ctx->baseNonceLen);
        free(ctx->baseNonce);
    }

    if (ctx->cipherCtx != NULL) {
        CRYPT_EAL_CipherFreeCtx(ctx->cipherCtx);
    }

    free(ctx);
}

static void ComputeNonce(E2EE_SelfEncryptionCtx *ctx, uint8_t *nonce, uint32_t nonceLen)
{
    uint64_t seq = ctx->seq;
    for (uint32_t i = 0; i < sizeof(seq); i++) {
        nonce[nonceLen - i -1] = seq & 0xFF;
        seq = seq >> 8;
    }

    for (uint32_t i = 0; i < nonceLen; i++) {
        nonce[i] ^= ctx->baseNonce[i];
    }
}

int32_t E2eeAeadEncrypt(E2EE_SelfEncryptionCtx *ctx, uint8_t *aad, uint32_t aadLen, const uint8_t *plainText,
    uint32_t plainTextLen, uint8_t *cipherText, uint32_t *cipherTextLen)
{
    uint8_t nonce[E2EE_AEAD_NONCE_LEN] = { 0 };
    ComputeNonce(ctx, nonce, E2EE_AEAD_NONCE_LEN);

    CRYPT_EAL_CipherCtx *cipherCtx = ctx->cipherCtx;
    uint32_t outLen = *cipherTextLen;
    int32_t ret = CRYPT_EAL_CipherInit(cipherCtx, ctx->symKey, ctx->symKeyLen, nonce, E2EE_AEAD_NONCE_LEN, true);
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }

    if (aad != NULL && aadLen > 0) {
        ret = CRYPT_EAL_CipherCtrl(cipherCtx, CRYPT_CTRL_SET_AAD, aad, aadLen);
        if (ret != CRYPT_SUCCESS) {
            goto end;
        }
    }

    ret = CRYPT_EAL_CipherUpdate(cipherCtx, plainText, plainTextLen, cipherText, &outLen);
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }

    ret = CRYPT_EAL_CipherCtrl(cipherCtx, CRYPT_CTRL_GET_TAG, cipherText + outLen, E2EE_AEAD_TAG_LEN);
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }

    *cipherTextLen = outLen + E2EE_AEAD_TAG_LEN;
end:
    CRYPT_EAL_CipherDeinit(cipherCtx);
    if (ret == CRYPT_SUCCESS) {
        ret = E2EE_SUCCESS;
        ctx->seq++;
    } else {
        ret = E2EE_ERR_CRYPTO;
    }
    return ret;
}

int32_t E2eeAeadDecrypt(E2EE_SelfEncryptionCtx *ctx, uint8_t *aad, uint32_t aadLen, const uint8_t *cipherText,
    uint32_t cipherTextLen, uint8_t *plainText, uint32_t *plainTextLen)
{
    CRYPT_EAL_CipherCtx *cipherCtx = ctx->cipherCtx;
    uint8_t nonce[E2EE_AEAD_NONCE_LEN] = { 0 };
    ComputeNonce(ctx, nonce, E2EE_AEAD_NONCE_LEN);

    int32_t ret = CRYPT_EAL_CipherInit(cipherCtx, ctx->symKey, ctx->symKeyLen, nonce, E2EE_AEAD_NONCE_LEN, false);
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }

    if (aad != NULL && aadLen > 0) {
        ret = CRYPT_EAL_CipherCtrl(cipherCtx, CRYPT_CTRL_SET_AAD, (void *)aad, aadLen);
        if (ret != CRYPT_SUCCESS) {
            goto end;
        }
    }

    ret = CRYPT_EAL_CipherUpdate(cipherCtx, cipherText, cipherTextLen - E2EE_AEAD_TAG_LEN, plainText, plainTextLen);
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }

    uint8_t newTag[E2EE_AEAD_TAG_LEN];
    ret = CRYPT_EAL_CipherCtrl(cipherCtx, CRYPT_CTRL_GET_TAG, (void *)newTag, E2EE_AEAD_TAG_LEN);
    if (ret != CRYPT_SUCCESS) {
        memset_s(plainText, *plainTextLen, 0, *plainTextLen);
        goto end;
    }

    if (memcmp(newTag, cipherText + (cipherTextLen - E2EE_AEAD_TAG_LEN), E2EE_AEAD_TAG_LEN) != 0) {
        memset_s(plainText, *plainTextLen, 0, *plainTextLen);
        CRYPT_EAL_CipherDeinit(cipherCtx);
        return E2EE_ERR_CHECK_AEAD_TAG;
    }

end:
    if (ret == CRYPT_SUCCESS) {
        ret = E2EE_SUCCESS;
        ctx->seq++;
    }

    CRYPT_EAL_CipherDeinit(cipherCtx);
    return ret;
}

int32_t E2eeSha256(const uint8_t *data, uint32_t dataLen, uint8_t *hash, uint32_t hashLen)
{
    if (hashLen != 32) {
        return E2EE_ERR_CRYPTO;
    }

    uint32_t len = hashLen;
    CRYPT_EAL_MdCTX *hashCtx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA256);
    if (hashCtx == NULL) {
        return E2EE_ERR_CRYPTO;
    }

    int32_t ret = CRYPT_EAL_MdInit(hashCtx);
    if (ret != CRYPT_SUCCESS) {
        ret = E2EE_ERR_CRYPTO;
        goto exit;
    }

    ret = CRYPT_EAL_MdUpdate(hashCtx, data, dataLen);
    if (ret != CRYPT_SUCCESS) {
        ret = E2EE_ERR_CRYPTO;
        goto exit;
    }

    ret = CRYPT_EAL_MdFinal(hashCtx, hash, &len);
    if (ret != CRYPT_SUCCESS) {
        ret = E2EE_ERR_CRYPTO;
        goto exit;
    }

    ret = E2EE_SUCCESS;
exit:
    CRYPT_EAL_MdFreeCtx(hashCtx);
    return ret;
}
