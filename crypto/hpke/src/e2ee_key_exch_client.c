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

#include "hitls_build.h"

#include <string.h>
#include "securec.h"

#include "crypt_eal_hpke.h"
#include "crypt_errno.h"
#include "e2ee_key_exch_err.h"
#include "e2ee_sse.h"
#include "e2ee_mem.h"
#include "e2ee_key_exch_msg.h"
#include "e2ee_key_exch.h"

#define CIPHER_CUITE_LEN 6
#define E2EE_CIPHER_CUITE_ITEM_NUM 3
#define E2EE_MAX_RESPONSE_NONCE_LEN 1024
#define E2EE_MAX_SHARED_SECRET_LEN 64
#define E2EE_MAX_PUBKEY_LEN 133

typedef enum {
    E2EE_CLIENT_INIT,
    E2EE_CLIENT_KEY_EXCH,
    E2EE_CLIENT_ENCRYPT,
} E2EE_ClientStates;

struct E2EE_ClientCtx {
    E2EE_AlgId algId;
    CRYPT_EAL_HpkeCtx *sender;
    E2EE_SelfEncryptionCtx *recipient;
    E2EE_ClientStates senderState;
    E2EE_ClientStates recipientState;
    E2EE_KemEncapsulateCallbackFunc keyDeriveFunc;
    void *callbackArg;
    uint8_t *encapsulatedKey;
    uint8_t *serverPubKeyId;
    uint32_t encapsulatedKeyLen;
    uint32_t serverPubKeyIdLen;
};

E2EE_ClientCtx *E2EE_ClientCreate(E2EE_AlgId algId)
{
    E2EE_ClientCtx *ctx = (E2EE_ClientCtx *)E2EE_Calloc(1, sizeof(E2EE_ClientCtx));
    if (ctx == NULL) {
        return NULL;
    }

    CRYPT_HPKE_CipherSuite cipher = {(CRYPT_HPKE_KEM_AlgId)algId.kemAlgId, (CRYPT_HPKE_KDF_AlgId)algId.kdfAlgId,
        (CRYPT_HPKE_AEAD_AlgId)algId.aeadAlgId};
    ctx->sender = CRYPT_EAL_HpkeNewCtx(NULL, NULL, CRYPT_HPKE_SENDER, CRYPT_HPKE_MODE_BASE, cipher);
    if (ctx->sender == NULL) {
        E2EE_Free(ctx);
        return NULL;
    }
    ctx->algId = algId;
    ctx->senderState = E2EE_CLIENT_INIT;
    return ctx;
}

static int32_t InitClientSenderWithCallback(E2EE_ClientCtx *ctx, uint8_t *serverPubKey, uint32_t serverPubKeyLen,
    uint8_t *info, uint32_t infoLen)
{
    uint32_t encapKeyLen = 0;
    CRYPT_HPKE_CipherSuite cipher = {(CRYPT_HPKE_KEM_AlgId)ctx->algId.kemAlgId,
        (CRYPT_HPKE_KDF_AlgId)ctx->algId.kdfAlgId, (CRYPT_HPKE_AEAD_AlgId)ctx->algId.aeadAlgId};
    int32_t ret = CRYPT_EAL_HpkeGetEncapKeyLen(cipher, &encapKeyLen);
    if (ret != CRYPT_SUCCESS) {
        return E2EE_ERR_CRYPTO;
    }

    uint8_t *encapKey = E2EE_Malloc(encapKeyLen);
    uint8_t *sharedSecret = E2EE_Malloc(E2EE_MAX_SHARED_SECRET_LEN);
    uint8_t *serverPubKeyId = E2EE_Malloc(E2EE_MSG_PUBKEY_ID_SIZE);
    if (encapKey == NULL || sharedSecret == NULL || serverPubKeyId == NULL) {
        ret = E2EE_ERR_MALLOC;
        goto end;
    }

    E2EE_KemEncapsulateResult result = {sharedSecret, E2EE_MAX_SHARED_SECRET_LEN, encapKey, encapKeyLen,
        serverPubKeyId, E2EE_MSG_PUBKEY_ID_SIZE};
    ret = ctx->keyDeriveFunc(ctx->callbackArg, ctx->algId.kemAlgId, serverPubKey, serverPubKeyLen, &result);
    if (ret != E2EE_SUCCESS) {
        ret = E2EE_ERR_KEY_EXCH;
        goto end;
    }

    ret = CRYPT_EAL_HpkeSetSharedSecret(ctx->sender, info, infoLen, result.sharedSecret, result.sharedSecretLen);
    if (ret != CRYPT_SUCCESS) {
        ret = E2EE_ERR_CRYPTO;
        goto end;
    }
    ctx->encapsulatedKey = encapKey;
    ctx->encapsulatedKeyLen = encapKeyLen;
    ctx->serverPubKeyId = serverPubKeyId;
    ctx->serverPubKeyIdLen = E2EE_MSG_PUBKEY_ID_SIZE;
end:
    E2EE_ClearFree(sharedSecret, E2EE_MAX_SHARED_SECRET_LEN);
    if (ret != E2EE_SUCCESS) {
        E2EE_ClearFree(encapKey, encapKeyLen);
        E2EE_Free(serverPubKeyId);
    }
    return ret;
}

static int32_t InitClientSenderWithDefault(E2EE_ClientCtx *ctx, uint8_t *serverPubKey, uint32_t serverPubKeyLen,
    uint8_t *info, uint32_t infoLen)
{
    if (serverPubKey == NULL || serverPubKeyLen == 0) {
        return E2EE_ERR_NULL_INPUT;
    }

    uint32_t encapKeyLen = 0;
    CRYPT_HPKE_CipherSuite cipher = {(CRYPT_HPKE_KEM_AlgId)ctx->algId.kemAlgId,
        (CRYPT_HPKE_KDF_AlgId)ctx->algId.kdfAlgId, (CRYPT_HPKE_AEAD_AlgId)ctx->algId.aeadAlgId};
    int32_t ret = CRYPT_EAL_HpkeGetEncapKeyLen(cipher, &encapKeyLen);
    if (ret != CRYPT_SUCCESS) {
        return E2EE_ERR_CRYPTO;
    }
    uint8_t *encapKey = E2EE_Malloc(encapKeyLen);
    uint8_t *serverPubKeyId = E2EE_Malloc(E2EE_MSG_PUBKEY_ID_SIZE);
    if (encapKey == NULL || serverPubKeyId == NULL) {
        ret = E2EE_ERR_MALLOC;
        goto end;
    }

    ret = E2eeSha256(serverPubKey, serverPubKeyLen, serverPubKeyId, E2EE_MSG_PUBKEY_ID_SIZE);
    if (ret != E2EE_SUCCESS) {
        goto end;
    }

    ret = CRYPT_EAL_HpkeSetupSender(ctx->sender, NULL, info, infoLen, serverPubKey, serverPubKeyLen, encapKey,
        &encapKeyLen);
    if (ret != CRYPT_SUCCESS) {
        ret = E2EE_ERR_CRYPTO;
        goto end;
    }
    ctx->encapsulatedKey = encapKey;
    ctx->encapsulatedKeyLen = encapKeyLen;
    ctx->serverPubKeyId = serverPubKeyId;
    ctx->serverPubKeyIdLen = E2EE_MSG_PUBKEY_ID_SIZE;
end:
    if (ret != E2EE_SUCCESS) {
        E2EE_Free(encapKey);
        E2EE_Free(serverPubKeyId);
    }
    return ret;
}

int32_t E2EE_ClientInit(E2EE_ClientCtx *ctx, uint8_t *serverPubKey, uint32_t serverPubKeyLen, uint8_t *info,
    uint32_t infoLen)
{
    if (ctx == NULL) {
        return E2EE_ERR_NULL_INPUT;
    }

    if (ctx->senderState != E2EE_CLIENT_INIT) {
        return E2EE_FAILED;
    }

    int32_t ret;
    if (ctx->keyDeriveFunc != NULL) {
        ret = InitClientSenderWithCallback(ctx, serverPubKey, serverPubKeyLen, info, infoLen);
        if (ret != E2EE_SUCCESS) {
            return ret;
        }
    } else {
        ret = InitClientSenderWithDefault(ctx, serverPubKey, serverPubKeyLen, info, infoLen);
        if (ret != E2EE_SUCCESS) {
            return ret;
        }
    }

    if (ret == E2EE_SUCCESS) {
        ctx->senderState = E2EE_CLIENT_KEY_EXCH;
    }
    return ret;
}

static uint16_t Uint16ToBigEndian(uint16_t value)
{
    uint16_t a = 0x1213;
    uint8_t *p = (uint8_t *)&a;
    if (p[0] == 0x13) { // little-endian
        return ((value & 0xFF00) >> 8) | ((value & 0x00FF) << 8);
    } else {
        return value;
    }
}

static uint8_t *SerializeCipherCuite(E2EE_AlgId *algId, uint16_t cipherCuite[])
{
    cipherCuite[0] = Uint16ToBigEndian(algId->kemAlgId);
    cipherCuite[1] = Uint16ToBigEndian(algId->kdfAlgId);
    cipherCuite[2] = Uint16ToBigEndian(algId->aeadAlgId);
    return (uint8_t *)cipherCuite;
}

static int32_t ClientGenKeyExchMsg(E2EE_ClientCtx *ctx, uint8_t *plainText, uint32_t plainTextLen,
    uint8_t *aad, uint32_t aadLen, uint8_t *cipherText, uint32_t *cipherTextLen)
{
    int32_t ret;
    uint32_t realCipherTextLen;
    ret = CRYPT_EAL_HpkeSeal(ctx->sender, aad, aadLen, plainText, plainTextLen, NULL, &realCipherTextLen);
    if (ret != CRYPT_SUCCESS) {
        return E2EE_FAILED;
    }

    uint32_t e2eeCipherTextLen = 0;
    E2EE_Tlv tlvs[E2EE_MSG_C2S_KEY_EXCH_TLV_NUM] = {0};
    tlvs[0].tag = E2EE_MSG_CIPHER_CUITE_TAG;
    tlvs[0].len = E2EE_CIPHER_CUITE_ITEM_NUM * sizeof(uint16_t);
    tlvs[1].tag = E2EE_MSG_ENCAPSULATED_KEY_TAG;
    tlvs[1].len = ctx->encapsulatedKeyLen;
    tlvs[2].tag = E2EE_MSG_CIPHER_TEXT_TAG; // param 2
    tlvs[2].len = realCipherTextLen; // param 2
    tlvs[3].tag = E2EE_MSG_PUBKEY_ID_TAG;
    tlvs[3].len = ctx->serverPubKeyIdLen;

    ret = E2EE_SerializeMsg(E2EE_MSG_VERSION, E2EE_MSG_C2S_KEY_EXCH_TYPE, tlvs, E2EE_MSG_C2S_KEY_EXCH_TLV_NUM, NULL,
        &e2eeCipherTextLen);
    if (ret != E2EE_SUCCESS) {
        return E2EE_FAILED;
    }

    if (cipherText == NULL) {
        *cipherTextLen = e2eeCipherTextLen;
        return E2EE_SUCCESS;
    }

    if (*cipherTextLen < e2eeCipherTextLen) {
        return E2EE_ERR_INVALID_ARG;
    }

    uint64_t cipherTextOffet = E2EE_GetTagValueOffset(E2EE_MSG_VERSION, tlvs, E2EE_MSG_C2S_KEY_EXCH_TLV_NUM,
        E2EE_MSG_CIPHER_TEXT_TAG);
    if (*cipherTextLen < cipherTextOffet) {
        return E2EE_ERR_INVALID_ARG;
    }
    uint32_t len = *cipherTextLen - cipherTextOffet;
    ret = CRYPT_EAL_HpkeSeal(ctx->sender, aad, aadLen, plainText, plainTextLen, cipherText + cipherTextOffet, &len);
    if (ret != CRYPT_SUCCESS) {
        return E2EE_FAILED;
    }

    uint16_t cipherCuite[E2EE_CIPHER_CUITE_ITEM_NUM];
    tlvs[0].value = SerializeCipherCuite(&ctx->algId, cipherCuite);
    tlvs[1].value = ctx->encapsulatedKey;
    tlvs[2].value = cipherText + cipherTextOffet;
    tlvs[3].value = ctx->serverPubKeyId;

    ret = E2EE_SerializeMsg(E2EE_MSG_VERSION, E2EE_MSG_C2S_KEY_EXCH_TYPE, tlvs, E2EE_MSG_C2S_KEY_EXCH_TLV_NUM,
        cipherText, &e2eeCipherTextLen);
    if (ret == E2EE_SUCCESS) {
        *cipherTextLen = e2eeCipherTextLen;
        ctx->senderState = E2EE_CLIENT_ENCRYPT;
        ctx->recipientState = E2EE_CLIENT_KEY_EXCH;
        E2EE_Free(ctx->serverPubKeyId); // No more pubKey id needed
        ctx->serverPubKeyId = NULL;
        ctx->serverPubKeyIdLen = 0;
    }
    return ret;
}

static int32_t ClientGenAppDataMsg(E2EE_ClientCtx *ctx, uint8_t *plainText, uint32_t plainTextLen,
    uint8_t *aad, uint32_t aadLen, uint8_t *cipherText, uint32_t *cipherTextLen)
{
    int32_t ret;
    uint32_t realCipherTextLen;
    ret = CRYPT_EAL_HpkeSeal(ctx->sender, aad, aadLen, plainText, plainTextLen, NULL, &realCipherTextLen);
    if (ret != CRYPT_SUCCESS) {
        return E2EE_FAILED;
    }

    uint32_t e2eeCipherTextLen = 0;
    E2EE_Tlv tlvs[E2EE_MSG_APP_DATA_TLV_NUM] = {0};
    tlvs[0].tag = E2EE_MSG_CIPHER_TEXT_TAG;
    tlvs[0].len = realCipherTextLen;

    ret = E2EE_SerializeMsg(E2EE_MSG_VERSION, E2EE_MSG_APP_DATA_TYPE, tlvs, E2EE_MSG_APP_DATA_TLV_NUM, NULL,
        &e2eeCipherTextLen);
    if (ret != E2EE_SUCCESS) {
        return ret;
    }

    if (cipherText == NULL) {
        *cipherTextLen = e2eeCipherTextLen;
        return E2EE_SUCCESS;
    }

    if (*cipherTextLen < e2eeCipherTextLen) {
        return E2EE_ERR_INVALID_ARG;
    }

    uint64_t cipherTextOffet = E2EE_GetTagValueOffset(E2EE_MSG_VERSION, tlvs, E2EE_MSG_APP_DATA_TLV_NUM,
        E2EE_MSG_CIPHER_TEXT_TAG);
    if (*cipherTextLen < cipherTextOffet) {
        return E2EE_ERR_INVALID_ARG;
    }
    uint32_t len = *cipherTextLen - cipherTextOffet;
    ret = CRYPT_EAL_HpkeSeal(ctx->sender, aad, aadLen, plainText, plainTextLen, cipherText + cipherTextOffet, &len);
    if (ret != CRYPT_SUCCESS) {
        return E2EE_FAILED;
    }

    tlvs[0].value = cipherText + cipherTextOffet;

    ret = E2EE_SerializeMsg(E2EE_MSG_VERSION, E2EE_MSG_APP_DATA_TYPE, tlvs, E2EE_MSG_APP_DATA_TLV_NUM, cipherText,
        &e2eeCipherTextLen);
    if (ret == E2EE_SUCCESS) {
        *cipherTextLen = e2eeCipherTextLen;
    }
    return ret;
}

static int32_t InitClientRecipient(E2EE_ClientCtx *ctx, uint8_t *responseNonce, uint32_t responseNonceLen)
{
    if (responseNonceLen > E2EE_MAX_RESPONSE_NONCE_LEN) {
        return E2EE_ERR_MSG_LEN;
    }

    uint32_t saltLen = ctx->encapsulatedKeyLen + responseNonceLen;
    uint8_t *salt = E2EE_Malloc(saltLen);
    (void)memcpy_s(salt, ctx->encapsulatedKeyLen, ctx->encapsulatedKey, ctx->encapsulatedKeyLen);
    (void)memcpy_s(salt + ctx->encapsulatedKeyLen, responseNonceLen, responseNonce, responseNonceLen);

    uint8_t secret[E2EE_MAX_SHARED_SECRET_LEN];
    uint32_t secretLen = E2EE_MAX_SHARED_SECRET_LEN;
    int32_t ret = CRYPT_EAL_HpkeGetSharedSecret(ctx->sender, secret, &secretLen);
    if (ret != CRYPT_SUCCESS) {
        E2EE_Free(salt);
        return E2EE_FAILED;
    }

    E2EE_SelfEncryptionCtx *recipient = NULL;
    ret = CreateSelfEncryptionCtx(&ctx->algId, salt, saltLen, secret, secretLen, &recipient);
    E2EE_Free(salt);
    memset_s(secret, secretLen, 0, secretLen);
    if (ret != E2EE_SUCCESS) {
        return ret;
    }

    ctx->recipient = recipient;
    return E2EE_SUCCESS;
}

static void DeInitClientRecipient(E2EE_ClientCtx *ctx)
{
    if (ctx->recipient != NULL) {
        DestroySelfEncryptionCtx(ctx->recipient);
        ctx->recipient = NULL;
    }
}

static int32_t ProcessServerKeyExchMsg(E2EE_ClientCtx *ctx, uint8_t *cipherText, uint32_t cipherTextLen,
    uint8_t *aad, uint32_t aadLen, uint8_t *plainText, uint32_t *plainTextLen)
{
    uint32_t ret = E2EE_CheckMsgBaseInfo(cipherText, cipherTextLen, E2EE_MSG_VERSION, E2EE_MSG_S2C_KEY_EXCH_TYPE);
    if (ret != E2EE_SUCCESS) {
        return ret;
    }

    E2EE_Tlv tlvs[E2EE_MSG_S2C_KEY_EXCH_TLV_NUM] = {0};
    uint32_t tlvNum = E2EE_MSG_S2C_KEY_EXCH_TLV_NUM;

    ret = E2EE_DeserializeMsg(cipherText, cipherTextLen, tlvs, &tlvNum);
    if (ret != E2EE_SUCCESS) {
        return ret;
    }

    if (tlvNum != E2EE_MSG_S2C_KEY_EXCH_TLV_NUM) {
        return E2EE_ERR_MSG_LEN;
    }

    int32_t responseNonceIndex = -1;
    int32_t cipherTextIndex = -1;
    for (int i = 0; i < E2EE_MSG_S2C_KEY_EXCH_TLV_NUM; i++) {
        switch (tlvs[i].tag) {
            case E2EE_MSG_RESPONSE_NONCE_TAG:
                responseNonceIndex = i;
                break;
            case E2EE_MSG_CIPHER_TEXT_TAG:
                cipherTextIndex = i;
                break;
            default:
                break;
        }
    }

    if (responseNonceIndex == -1 || cipherTextIndex == -1) {
        return E2EE_ERR_INVALID_MSG;
    }

    ret = InitClientRecipient(ctx, tlvs[responseNonceIndex].value, tlvs[responseNonceIndex].len);
    if (ret != E2EE_SUCCESS) {
        return ret;
    }

    ret = E2eeAeadDecrypt(ctx->recipient, aad, aadLen, tlvs[cipherTextIndex].value, tlvs[cipherTextIndex].len,
        plainText, plainTextLen);
    if (ret != E2EE_SUCCESS) {
        DeInitClientRecipient(ctx);
        return ret;
    }

    ctx->recipientState = E2EE_CLIENT_ENCRYPT;
    E2EE_Free(ctx->encapsulatedKey); // No more peer public key needed
    ctx->encapsulatedKey = NULL;
    ctx->encapsulatedKeyLen = 0;
    return E2EE_SUCCESS;
}

int32_t E2EE_ClientEncrypt(E2EE_ClientCtx *ctx, uint8_t *plainText, uint32_t plainTextLen,
    uint8_t *aad, uint32_t aadLen, uint8_t *cipherText, uint32_t *cipherTextLen)
{
    if (ctx == NULL || plainText == NULL || plainTextLen == 0 || cipherTextLen == NULL) {
        return E2EE_ERR_NULL_INPUT;
    }

    if (plainTextLen > E2EE_MAX_PLIANTEXT_LEN) {
        return E2EE_ERR_INVALID_ARG;
    }

    switch (ctx->senderState) {
        case E2EE_CLIENT_KEY_EXCH:
            return ClientGenKeyExchMsg(ctx, plainText, plainTextLen, aad, aadLen, cipherText, cipherTextLen);
        case E2EE_CLIENT_ENCRYPT:
            return ClientGenAppDataMsg(ctx, plainText, plainTextLen, aad, aadLen, cipherText, cipherTextLen);
        default:
            return E2EE_ERR_CALL;
    }
}

static int32_t ProcessAppDataMsg(E2EE_ClientCtx *ctx, uint8_t *cipherText, uint32_t cipherTextLen,
    uint8_t *aad, uint32_t aadLen, uint8_t *plainText, uint32_t *plainTextLen)
{
    uint8_t *realCipherText = NULL;
    uint32_t realCipherTextLen = 0;
    uint32_t ret = ParseAppDataMsg(cipherText, cipherTextLen, &realCipherText, &realCipherTextLen);
    if (ret != E2EE_SUCCESS) {
        return ret;
    }

    return E2eeAeadDecrypt(ctx->recipient, aad, aadLen, realCipherText, realCipherTextLen, plainText, plainTextLen);
}

int32_t E2EE_ClientDecrypt(E2EE_ClientCtx *ctx, uint8_t *cipherText, uint32_t cipherTextLen,
    uint8_t *aad, uint32_t aadLen, uint8_t *plainText, uint32_t *plainTextLen)
{
    if (ctx == NULL || cipherText == NULL || cipherTextLen == 0 || plainText == NULL || plainTextLen == NULL) {
        return E2EE_ERR_NULL_INPUT;
    }

    switch (ctx->recipientState) {
        case E2EE_CLIENT_KEY_EXCH:
            return ProcessServerKeyExchMsg(ctx, cipherText, cipherTextLen, aad, aadLen, plainText, plainTextLen);
        case E2EE_CLIENT_ENCRYPT:
            return ProcessAppDataMsg(ctx, cipherText, cipherTextLen, aad, aadLen, plainText, plainTextLen);
        default:
            return E2EE_ERR_CALL;
    }
}

void E2EE_ClientDestroy(E2EE_ClientCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->sender != NULL) {
        CRYPT_EAL_HpkeFreeCtx(ctx->sender);
    }

    DestroySelfEncryptionCtx(ctx->recipient);

    if (ctx->encapsulatedKey != NULL) {
        E2EE_Free(ctx->encapsulatedKey);
    }

    if (ctx->serverPubKeyId != NULL) {
        E2EE_Free(ctx->serverPubKeyId);
    }
    E2EE_Free(ctx);
}

void E2EE_SetClientKemCallback(E2EE_ClientCtx *ctx, E2EE_KemEncapsulateCallbackFunc keyDeriveFunc, void *callbackArg)
{
    if (ctx == NULL) {
        return;
    }

    ctx->keyDeriveFunc = keyDeriveFunc;
    ctx->callbackArg = callbackArg;
}