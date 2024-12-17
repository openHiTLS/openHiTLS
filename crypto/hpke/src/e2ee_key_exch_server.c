#include <string.h>
#include "securec.h"
#include "crypt_eal_hpke.h"
#include "crypt_eal_rand.h"
#include "crypt_errno.h"
#include "e2ee_mem.h"
#include "e2ee_log.h"
#include "e2ee_key_exch.h"
#include "e2ee_key_exch_err.h"
#include "e2ee_sse.h"
#include "e2ee_key_exch_msg.h"

#define E2EE_MAX_SERVER_KEY_EXCH_INFO_NUM 5
#define E2EE_MAX_PRIVATE_KEY_LEN 1024
#define E2EE_MAX_INFO_LEN 1024
#define E2EE_MAX_SHARED_SECRET_LEN 64

#define E2EE_MSG_MAX_PUBKEY_LEN 133

typedef struct {
    CRYPT_EAL_PkeyCtx *pkey;
    uint8_t pubKeyId[E2EE_MSG_PUBKEY_ID_SIZE]; // sha256
    uint8_t *info;
    uint32_t infoLen;
} E2EE_KeyExchInfo;

typedef enum {
    E2EE_SERVER_INIT,
    E2EE_SERVER_KEY_EXCH,
    E2EE_SERVER_ENCRYPT,
} E2EE_ServerStates;

struct E2EE_ServerCtx {
    E2EE_AlgId algId;
    CRYPT_EAL_HpkeCtx *recipient;
    E2EE_SelfEncryptionCtx *sender;
    E2EE_ServerStates senderState;
    E2EE_ServerStates recipientState;
    E2EE_KemDecapsulateCallbackFunc keyDeriveFunc;
    void *callbackArg;
    uint8_t *encapsulatedKey;
    E2EE_KeyExchInfo *keyExchInfo;
    uint32_t encapsulatedKeyLen;
    uint32_t keyExchInfoNum;
};

typedef struct {
    CRYPT_PKEY_AlgId pkeyId;
    CRYPT_PKEY_ParaId curveId;
} E2EE_PkeyInfo;

static E2EE_PkeyInfo g_hpkeKemAlgInfo[] = {
    {CRYPT_PKEY_ECDH, CRYPT_ECC_NISTP256},
    {CRYPT_PKEY_ECDH, CRYPT_ECC_NISTP384},
    {CRYPT_PKEY_ECDH, CRYPT_ECC_NISTP521},
    {CRYPT_PKEY_X25519, CRYPT_PKEY_PARAID_MAX},
};

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

static uint16_t BigEndianToUint16(uint16_t value)
{
    return Uint16ToBigEndian(value);
}

#define E2EE_CIPHER_CUITE_LEN 6

static int32_t DeserializeCipherCuite(uint8_t *in, uint32_t inLen, E2EE_AlgId *algId)
{
    if (inLen != E2EE_CIPHER_CUITE_LEN) {
        E2EE_LOG_ERROR("Invalid cipher suite length: %u, expected: %u", inLen, E2EE_CIPHER_CUITE_LEN);
        return E2EE_ERR_MSG_LEN;
    }
    uint16_t *p = (uint16_t *)in;
    algId->kemAlgId = BigEndianToUint16(*p);
    p++;
    algId->kdfAlgId = BigEndianToUint16(*p);
    p++;
    algId->aeadAlgId = BigEndianToUint16(*p);
    return E2EE_SUCCESS;
}

E2EE_ServerCtx *E2EE_ServerCreate(void)
{
    E2EE_ServerCtx *ctx = (E2EE_ServerCtx *)E2EE_Calloc(1, sizeof(E2EE_ServerCtx));
    if (ctx == NULL) {
        E2EE_LOG_ERROR("Failed to allocate server context");
        return NULL;
    }

    ctx->recipientState = E2EE_SERVER_INIT;
    ctx->senderState = E2EE_SERVER_INIT;
    return ctx;
}

static int32_t CreatePriKey(E2EE_PkeyInfo *pkeyInfo, uint8_t *priKey, uint32_t priKeyLen,
    CRYPT_EAL_PkeyCtx **pkey)
{
    CRYPT_EAL_PkeyCtx *tmpPkey = CRYPT_EAL_PkeyNewCtx(pkeyInfo->pkeyId);
    if (pkey == NULL) {
        E2EE_LOG_ERROR("Failed to create pkey context");
        return E2EE_ERR_CRYPTO;
    }

    int32_t ret;
    if (pkeyInfo->pkeyId == CRYPT_PKEY_ECDH) {
        ret = CRYPT_EAL_PkeySetParaById(tmpPkey, pkeyInfo->curveId);
        if (ret != CRYPT_SUCCESS) {
            CRYPT_EAL_PkeyFreeCtx(tmpPkey);
            E2EE_LOG_ERROR("Failed to set pkey parameters, ret: %d", ret);
            return E2EE_ERR_CRYPTO;
        }
    }

    CRYPT_EAL_PkeyPrv prv = {0};
    prv.id = pkeyInfo->pkeyId;
    prv.key.eccPrv.data = priKey;
    prv.key.eccPrv.len = priKeyLen;

    ret = CRYPT_EAL_PkeySetPrv(tmpPkey, &prv);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(tmpPkey);
        E2EE_LOG_ERROR("Failed to set private key, ret: %d", ret);
        return E2EE_ERR_CRYPTO;
    }

    if (pkeyInfo->pkeyId == CRYPT_PKEY_X25519) {
        ret = CRYPT_EAL_PkeyCtrl(tmpPkey, CRYPT_CTRL_GEN_X25519_PUBLICKEY, NULL, 0);
    } else {
        ret = CRYPT_EAL_PkeyCtrl(tmpPkey, CRYPT_CTRL_GEN_ECC_PUBLICKEY, NULL, 0);
    }

    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(tmpPkey);
        E2EE_LOG_ERROR("Failed to generate public key, ret: %d", ret);
        return E2EE_ERR_CRYPTO;
    }

    *pkey = tmpPkey;
    return E2EE_SUCCESS;
}

static void FreeKeyExchInfo(E2EE_ServerCtx *ctx)
{
    uint32_t keyExchInfoNum = ctx->keyExchInfoNum;
    E2EE_KeyExchInfo *keyExchInfo = ctx->keyExchInfo;
    for (uint32_t i = 0; i < keyExchInfoNum; i++) {
        CRYPT_EAL_PkeyFreeCtx(keyExchInfo[i].pkey);
        E2EE_Free(keyExchInfo[i].info);
        keyExchInfo[i].info = NULL;
        keyExchInfo[i].infoLen = 0;
    }
    E2EE_Free(keyExchInfo);
    ctx->keyExchInfo = NULL;
    ctx->keyExchInfoNum = 0;
}

static int32_t ComputePubKeyID(E2EE_KeyExchInfo *keyExchInfo)
{
    CRYPT_EAL_PkeyCtx *pkey = keyExchInfo->pkey;
    CRYPT_EAL_PkeyPub pub = {0};
    uint8_t pubKeyId[E2EE_MSG_MAX_PUBKEY_LEN] = {0};
    pub.id = CRYPT_EAL_PkeyGetId(pkey);
    pub.key.eccPub.data = pubKeyId;
    pub.key.eccPub.len = E2EE_MSG_MAX_PUBKEY_LEN;
    int32_t ret = CRYPT_EAL_PkeyGetPub(pkey, &pub);
    if (ret != CRYPT_SUCCESS) {
        E2EE_LOG_ERROR("Failed to get public key, ret: %d", ret);
        return E2EE_ERR_CRYPTO;
    }

    ret = E2eeSha256(pub.key.eccPub.data, pub.key.eccPub.len, keyExchInfo->pubKeyId, E2EE_MSG_PUBKEY_ID_SIZE);
    if (ret != E2EE_SUCCESS) {
        E2EE_LOG_ERROR("Failed to compute public key ID, ret: %d", ret);
        return ret;
    }
    return E2EE_SUCCESS;
}

static int32_t ProcessKeyExchInfo(E2EE_ServerCtx *ctx, E2EE_ServerKeyExchInfo keyExchInfo[], uint32_t keyExchInfoNum)
{
    int32_t ret;
    uint32_t i;
    if (keyExchInfoNum == 0 && ctx->keyDeriveFunc != NULL) {
        return E2EE_SUCCESS;
    }
    if (keyExchInfoNum == 0 || keyExchInfoNum > E2EE_MAX_SERVER_KEY_EXCH_INFO_NUM) {
        E2EE_LOG_ERROR("Invalid key exchange info number: %u", keyExchInfoNum);
        return E2EE_ERR_INVALID_ARG;
    }

    ctx->keyExchInfo = (E2EE_KeyExchInfo *)E2EE_Calloc(keyExchInfoNum, sizeof(E2EE_KeyExchInfo));
    if (ctx->keyExchInfo == NULL) {
        E2EE_LOG_ERROR("Failed to allocate memory for key exchange info");
        return E2EE_ERR_MALLOC;
    }
    ctx->keyExchInfoNum = keyExchInfoNum;

    for (i = 0; i < keyExchInfoNum; i++) {
        if (keyExchInfo[i].type > E2EE_X25519) {
            E2EE_LOG_ERROR("Invalid key type: %u", keyExchInfo[i].type);
            ret = E2EE_ERR_INVALID_ARG;
            break;
        }

        if (keyExchInfo[i].infoLen > E2EE_MAX_INFO_LEN) {
            E2EE_LOG_ERROR("Info length too large: %u", keyExchInfo[i].infoLen);
            ret = E2EE_ERR_INVALID_ARG;
            break;
        }

        if (keyExchInfo[i].privKeyLen > E2EE_MAX_PRIVATE_KEY_LEN) {
            E2EE_LOG_ERROR("Private key length too large: %u", keyExchInfo[i].privKeyLen);
            ret = E2EE_ERR_INVALID_ARG;
            break;
        }

        ret = CreatePriKey(&g_hpkeKemAlgInfo[keyExchInfo[i].type], keyExchInfo[i].privKey, keyExchInfo[i].privKeyLen,
            &ctx->keyExchInfo[i].pkey);
        if (ret != E2EE_SUCCESS) {
            E2EE_LOG_ERROR("Failed to create private key, ret: %d", ret);
            break;
        }

        ret = ComputePubKeyID(&ctx->keyExchInfo[i]);
        if (ret != E2EE_SUCCESS) {
            E2EE_LOG_ERROR("Failed to compute public key ID, ret: %d", ret);
            break;
        }

        if (keyExchInfo[i].info != NULL) {
            ctx->keyExchInfo[i].info = E2EE_Dump(keyExchInfo[i].info, keyExchInfo[i].infoLen);
            if (ctx->keyExchInfo[i].info == NULL) {
                E2EE_LOG_ERROR("Failed to allocate memory for info");
                ret = E2EE_ERR_MALLOC;
                break;
            }
            ctx->keyExchInfo[i].infoLen = keyExchInfo[i].infoLen;
        }
    }

    if (ret != E2EE_SUCCESS) {
        FreeKeyExchInfo(ctx);
        return ret;
    }

    return E2EE_SUCCESS;
}


int32_t E2EE_ServerInit(E2EE_ServerCtx *ctx, E2EE_ServerKeyExchInfo keyExchInfo[], uint32_t keyExchInfoNum)
{
    if (ctx == NULL) {
        E2EE_LOG_ERROR("Null context");
        return E2EE_ERR_NULL_INPUT;
    }

    if (ctx->senderState != E2EE_SERVER_INIT) {
        E2EE_LOG_ERROR("Invalid sender state: %d", ctx->senderState);
        return E2EE_ERR_CALL;
    }

    int32_t ret = ProcessKeyExchInfo(ctx, keyExchInfo, keyExchInfoNum);
    if (ret != E2EE_SUCCESS) {
        E2EE_LOG_ERROR("Failed to process key exchange info, ret: %d", ret);
        return ret;
    }

    ctx->recipientState = E2EE_SERVER_KEY_EXCH;
    return E2EE_SUCCESS;
}

static int32_t FindPubKeyIdIndex(E2EE_ServerCtx *ctx, uint8_t *pubKeyId, uint32_t pubKeyIdLen, uint32_t *index)
{
    if (pubKeyIdLen != E2EE_MSG_PUBKEY_ID_SIZE) {
        E2EE_LOG_ERROR("Invalid public key ID length: %u", pubKeyIdLen);
        return E2EE_ERR_MSG_LEN;
    }
    for (uint32_t i = 0; i < ctx->keyExchInfoNum; i++) {
        if (memcmp(ctx->keyExchInfo[i].pubKeyId, pubKeyId, E2EE_MSG_PUBKEY_ID_SIZE) == 0) {
            *index = i;
            return E2EE_SUCCESS;
        }
    }
    E2EE_LOG_ERROR("No suitable key found for public key ID");
    return E2EE_ERR_NO_SUITABLE_KEY;
}

static int32_t InitServerRecipient(E2EE_ServerCtx *ctx, uint8_t *encapsulatedKey, uint32_t encapsulatedKeyLen, 
    uint8_t *pubKeyId, uint32_t pubKeyIdLen)
{
    CRYPT_HPKE_CipherSuite cipher = {(CRYPT_HPKE_KEM_AlgId)ctx->algId.kemAlgId,
        (CRYPT_HPKE_KDF_AlgId)ctx->algId.kdfAlgId, (CRYPT_HPKE_AEAD_AlgId)ctx->algId.aeadAlgId};
    CRYPT_EAL_HpkeCtx *hpkeCtx = CRYPT_EAL_HpkeNewCtx(NULL, NULL, CRYPT_HPKE_RECIPIENT, CRYPT_HPKE_MODE_BASE, cipher);
    if (hpkeCtx == NULL) {
        E2EE_LOG_ERROR("Failed to create HPKE context");
        return E2EE_ERR_CRYPTO;
    }

    int32_t ret;
    if (ctx->keyDeriveFunc != NULL) {
        uint8_t sharedSecret[E2EE_MAX_SHARED_SECRET_LEN];
        uint32_t sharedSecretLen = E2EE_MAX_SHARED_SECRET_LEN;
        uint8_t info[E2EE_MAX_INFO_LEN];
        uint32_t infoLen = E2EE_MAX_INFO_LEN;
        E2EE_KemDecapsulateResult out = {sharedSecret, sharedSecretLen, info, infoLen};
        ret = ctx->keyDeriveFunc(ctx->callbackArg, ctx->algId.kemAlgId, encapsulatedKey, encapsulatedKeyLen, pubKeyId,
            pubKeyIdLen, &out);
        if (ret != 0) {
            E2EE_LOG_ERROR("KEM callback failed with error: %d", ret);
            CRYPT_EAL_HpkeFreeCtx(hpkeCtx);
            return E2EE_ERR_KEM_CALLBACK;
        }
        ret = CRYPT_EAL_HpkeSetSharedSecret(hpkeCtx, out.info, out.infoLen, out.sharedSecret, out.sharedSecretLen);
        memset_s(sharedSecret, sharedSecretLen, 0, sharedSecretLen);
        if (ret != CRYPT_SUCCESS) {
            CRYPT_EAL_HpkeFreeCtx(hpkeCtx);
            E2EE_LOG_ERROR("Failed to set shared secret, ret: %d", ret);
            return E2EE_ERR_CRYPTO;
        }
    } else {
        uint32_t index;
        ret = FindPubKeyIdIndex(ctx, pubKeyId, pubKeyIdLen, &index);
        if (ret != E2EE_SUCCESS) {
            CRYPT_EAL_HpkeFreeCtx(hpkeCtx);
            E2EE_LOG_ERROR("Failed to setup recipient, ret: %d", ret);
            return E2EE_ERR_CRYPTO;
        }

        ret = CRYPT_EAL_HpkeSetupRecipient(hpkeCtx, ctx->keyExchInfo[index].pkey, ctx->keyExchInfo[index].info,
            ctx->keyExchInfo[index].infoLen, encapsulatedKey, encapsulatedKeyLen);
        if (ret != CRYPT_SUCCESS) {
            CRYPT_EAL_HpkeFreeCtx(hpkeCtx);
            E2EE_LOG_ERROR("Failed to setup recipient, ret: %d", ret);
            return E2EE_ERR_CRYPTO;
        }
    }

    ctx->encapsulatedKey = E2EE_Dump(encapsulatedKey, encapsulatedKeyLen);
    if (ctx->encapsulatedKey == NULL) {
        CRYPT_EAL_HpkeFreeCtx(hpkeCtx);
        E2EE_LOG_ERROR("Failed to allocate memory for encapsulated key");
        return E2EE_ERR_MALLOC;
    }
    ctx->encapsulatedKeyLen = encapsulatedKeyLen;

    ctx->recipient = hpkeCtx;
    return E2EE_SUCCESS;
}

static void DeInitServerRecipient(E2EE_ServerCtx *ctx)
{
    if (ctx->recipient != NULL) {
        CRYPT_EAL_HpkeFreeCtx(ctx->recipient);
        ctx->recipient = NULL;
    }

    if (ctx->encapsulatedKey != NULL) {
        E2EE_Free(ctx->encapsulatedKey);
        ctx->encapsulatedKey = NULL;
        ctx->encapsulatedKeyLen = 0;
    }
}

static int32_t ProcessClientKeyExchMsg(E2EE_ServerCtx *ctx, uint8_t *cipherText, uint32_t cipherTextLen,
    uint8_t *aad, uint32_t aadLen, uint8_t *plainText, uint32_t *plainTextLen)
{
    uint32_t ret = E2EE_CheckMsgBaseInfo(cipherText, cipherTextLen, E2EE_MSG_VERSION, E2EE_MSG_C2S_KEY_EXCH_TYPE);
    if (ret != E2EE_SUCCESS) {
        E2EE_LOG_ERROR("Invalid message base info, ret: %d", ret);
        return ret;
    }

    E2EE_Tlv tlvs[E2EE_MSG_C2S_KEY_EXCH_TLV_NUM] = {0};
    uint32_t tlvNum = E2EE_MSG_C2S_KEY_EXCH_TLV_NUM;

    ret = E2EE_DeserializeMsg(cipherText, cipherTextLen, tlvs, &tlvNum);
    if (ret != E2EE_SUCCESS) {
        E2EE_LOG_ERROR("Failed to deserialize message, ret: %d", ret);
        return ret;
    }

    if (tlvNum != E2EE_MSG_C2S_KEY_EXCH_TLV_NUM) {
        E2EE_LOG_ERROR("Invalid TLV number: %u, expected: %u", tlvNum, E2EE_MSG_C2S_KEY_EXCH_TLV_NUM);
        return E2EE_ERR_MSG_LEN;
    }

    int32_t cipherCuiteIndex = -1;
    int32_t encapsulatedKeyIndex = -1;
    int32_t cipherTextIndex = -1;
    int32_t pubKeyIdIndex = -1;
    for (int i = 0; i < E2EE_MSG_C2S_KEY_EXCH_TLV_NUM; i++) {
        switch (tlvs[i].tag) {
            case E2EE_MSG_CIPHER_CUITE_TAG:
                cipherCuiteIndex = i;
                break;
            case E2EE_MSG_ENCAPSULATED_KEY_TAG:
                encapsulatedKeyIndex = i;
                break;
            case E2EE_MSG_CIPHER_TEXT_TAG:
                cipherTextIndex = i;
                break;
            case E2EE_MSG_PUBKEY_ID_TAG:
                pubKeyIdIndex = i;
                break;
            default:
                break;
        }
    }

    if (cipherCuiteIndex == -1 || encapsulatedKeyIndex == -1 || cipherTextIndex == -1 || pubKeyIdIndex == -1) {
        E2EE_LOG_ERROR("Missing required TLV tags");
        return E2EE_ERR_INVALID_MSG;
    }

    ret = DeserializeCipherCuite(tlvs[cipherCuiteIndex].value, tlvs[cipherCuiteIndex].len, &ctx->algId);
    if (ret != E2EE_SUCCESS) {
        E2EE_LOG_ERROR("Failed to deserialize cipher suite, ret: %d", ret);
        return ret;
    }

    ret = InitServerRecipient(ctx, tlvs[encapsulatedKeyIndex].value, tlvs[encapsulatedKeyIndex].len,
        tlvs[pubKeyIdIndex].value, tlvs[pubKeyIdIndex].len);
    if (ret != E2EE_SUCCESS) {
        E2EE_LOG_ERROR("Failed to init server recipient, ret: %d", ret);
        return ret;
    }

    ret = CRYPT_EAL_HpkeOpen(ctx->recipient, aad, aadLen, tlvs[cipherTextIndex].value, tlvs[cipherTextIndex].len,
        plainText, plainTextLen);
    if (ret != CRYPT_SUCCESS) {
        DeInitServerRecipient(ctx);
        E2EE_LOG_ERROR("Failed to open HPKE message, ret: %d", ret);
        return E2EE_ERR_CRYPTO;
    }

    ctx->recipientState = E2EE_SERVER_ENCRYPT;
    FreeKeyExchInfo(ctx); // No more key exchange info needed
    ctx->senderState = E2EE_SERVER_KEY_EXCH;
    return E2EE_SUCCESS;
}

static int32_t InitServerSender(E2EE_ServerCtx *ctx, uint8_t *responseNonce, uint32_t responseNonceLen)
{
    uint8_t secret[E2EE_MAX_SHARED_SECRET_LEN];
    uint32_t secretLen = E2EE_MAX_SHARED_SECRET_LEN;
    int32_t ret = CRYPT_EAL_HpkeGetSharedSecret(ctx->recipient, secret, &secretLen);
    if (ret != CRYPT_SUCCESS) {
        E2EE_LOG_ERROR("Failed to get shared secret, ret: %d", ret);
        return E2EE_ERR_CRYPTO;
    }

    uint8_t *salt = E2EE_Malloc(ctx->encapsulatedKeyLen + responseNonceLen);
    if (salt == NULL) {
        memset_s(secret, secretLen, 0, secretLen);
        E2EE_LOG_ERROR("Failed to allocate memory for salt");
        return E2EE_ERR_MALLOC;
    }
    (void)memcpy_s(salt, ctx->encapsulatedKeyLen, ctx->encapsulatedKey, ctx->encapsulatedKeyLen);
    (void)memcpy_s(salt + ctx->encapsulatedKeyLen, responseNonceLen, responseNonce, responseNonceLen);

    E2EE_SelfEncryptionCtx *sender = NULL;
    ret = CreateSelfEncryptionCtx(&ctx->algId, salt, ctx->encapsulatedKeyLen + responseNonceLen, secret, secretLen,
        &sender);
    E2EE_Free(salt);
    memset_s(secret, secretLen, 0, secretLen);
    if (ret != E2EE_SUCCESS) {
        E2EE_LOG_ERROR("Failed to create self encryption context, ret: %d", ret);
        return ret;
    }

    ctx->sender = sender;
    return E2EE_SUCCESS;
}

static void DeInitServerSender(E2EE_ServerCtx *ctx)
{
    if (ctx->sender != NULL) {
        DestroySelfEncryptionCtx(ctx->sender);
        ctx->sender = NULL;
    }
}

static int32_t ServerGenKeyExchMsg(E2EE_ServerCtx *ctx, uint8_t *plainText, uint32_t plainTextLen,
    uint8_t *aad, uint32_t aadLen, uint8_t *cipherText, uint32_t *cipherTextLen)
{
    int32_t ret;
    uint32_t realCipherTextLen = plainTextLen + 16; // Tag length is 16

    uint32_t e2eeCipherTextLen = 0;
    E2EE_Tlv tlvs[2] = {0};
    tlvs[0].tag = E2EE_MSG_RESPONSE_NONCE_TAG;
    tlvs[0].len = E2EE_RESPONSE_NONCE_LEN;
    tlvs[1].tag = E2EE_MSG_CIPHER_TEXT_TAG;
    tlvs[1].len = realCipherTextLen;

    ret = E2EE_SerializeMsg(E2EE_MSG_VERSION, E2EE_MSG_S2C_KEY_EXCH_TYPE, tlvs, 2, NULL, &e2eeCipherTextLen);
    if (ret != E2EE_SUCCESS) {
        E2EE_LOG_ERROR("Failed to serialize message, ret: %d", ret);
        return ret;
    }

    if (cipherText == NULL) {
        *cipherTextLen = e2eeCipherTextLen;
        return E2EE_SUCCESS;
    }

    if (*cipherTextLen < e2eeCipherTextLen) {
        E2EE_LOG_ERROR("Buffer too small: need %u, got %u", e2eeCipherTextLen, *cipherTextLen);
        return E2EE_ERR_INVALID_ARG;
    }

    uint8_t responseNonce[E2EE_RESPONSE_NONCE_LEN];
    uint32_t responseNonceLen = E2EE_RESPONSE_NONCE_LEN;
    ret = CRYPT_EAL_Randbytes(responseNonce, responseNonceLen);
    if (ret != CRYPT_SUCCESS) {
        E2EE_LOG_ERROR("Failed to generate random nonce, ret: %d", ret);
        return E2EE_ERR_CRYPTO;
    }

    ret = InitServerSender(ctx, responseNonce, responseNonceLen);
    if (ret != E2EE_SUCCESS) {
        E2EE_LOG_ERROR("Failed to init server sender, ret: %d", ret);
        return ret;
    }

    uint64_t cipherTextOffet = E2EE_GetTagValueOffset(E2EE_MSG_VERSION, tlvs, 2, E2EE_MSG_CIPHER_TEXT_TAG);
    uint32_t len = *cipherTextLen - cipherTextOffet;
    ret = E2eeAeadEncrypt(ctx->sender, aad, aadLen, plainText, plainTextLen, cipherText + cipherTextOffet, &len);
    if (ret != E2EE_SUCCESS) {
        DeInitServerSender(ctx);
        E2EE_LOG_ERROR("Failed to encrypt message, ret: %d", ret);
        return ret;
    }

    tlvs[0].value = responseNonce;
    tlvs[1].value = cipherText + cipherTextOffet;

    ret = E2EE_SerializeMsg(E2EE_MSG_VERSION, E2EE_MSG_S2C_KEY_EXCH_TYPE, tlvs, 2, cipherText, &e2eeCipherTextLen);
    if (ret != E2EE_SUCCESS) {
        DeInitServerSender(ctx);
        E2EE_LOG_ERROR("Failed to serialize final message, ret: %d", ret);
        return ret;
    }

    *cipherTextLen = e2eeCipherTextLen;
    ctx->senderState = E2EE_SERVER_ENCRYPT;
    E2EE_Free(ctx->encapsulatedKey); // No more peer public key needed
    ctx->encapsulatedKey = NULL;
    ctx->encapsulatedKeyLen = 0;
    return ret;
}

static int32_t ServerGenAppDataMsg(E2EE_ServerCtx *ctx, uint8_t *plainText, uint32_t plainTextLen,
    uint8_t *aad, uint32_t aadLen, uint8_t *cipherText, uint32_t *cipherTextLen)
{
    int32_t ret;
    uint32_t realCipherTextLen = plainTextLen + 16; // Tag length is 16

    uint32_t e2eeCipherTextLen = 0;
    E2EE_Tlv tlvs[E2EE_MSG_APP_DATA_TLV_NUM] = {0};
    tlvs[0].tag = E2EE_MSG_CIPHER_TEXT_TAG;
    tlvs[0].len = realCipherTextLen;

    ret = E2EE_SerializeMsg(E2EE_MSG_VERSION, E2EE_MSG_APP_DATA_TYPE, tlvs, E2EE_MSG_APP_DATA_TLV_NUM, NULL,
        &e2eeCipherTextLen);
    if (ret != E2EE_SUCCESS) {
        E2EE_LOG_ERROR("Failed to serialize message, ret: %d", ret);
        return ret;
    }

    if (cipherText == NULL) {
        *cipherTextLen = e2eeCipherTextLen;
        return E2EE_SUCCESS;
    }

    if (*cipherTextLen < e2eeCipherTextLen) {
        E2EE_LOG_ERROR("Buffer too small: need %u, got %u", e2eeCipherTextLen, *cipherTextLen);
        return E2EE_ERR_INVALID_ARG;
    }

    uint64_t cipherTextOffet = E2EE_GetTagValueOffset(E2EE_MSG_VERSION, tlvs, E2EE_MSG_APP_DATA_TLV_NUM,
        E2EE_MSG_CIPHER_TEXT_TAG);
    uint32_t len = *cipherTextLen - cipherTextOffet;
    ret = E2eeAeadEncrypt(ctx->sender, aad, aadLen, plainText, plainTextLen, cipherText + cipherTextOffet, &len);
    if (ret != E2EE_SUCCESS) {
        E2EE_LOG_ERROR("Failed to encrypt message, ret: %d", ret);
        return ret;
    }

    tlvs[0].value = cipherText + cipherTextOffet;

    ret = E2EE_SerializeMsg(E2EE_MSG_VERSION, E2EE_MSG_APP_DATA_TYPE, tlvs, E2EE_MSG_APP_DATA_TLV_NUM, cipherText,
        &e2eeCipherTextLen);
    if (ret != E2EE_SUCCESS) {
        E2EE_LOG_ERROR("Failed to serialize final message, ret: %d", ret);
        return ret;
    }

    *cipherTextLen = e2eeCipherTextLen;
    return ret;
}

static int32_t ProcessAppDataMsg(E2EE_ServerCtx *ctx, uint8_t *cipherText, uint32_t cipherTextLen,
    uint8_t *aad, uint32_t aadLen, uint8_t *plainText, uint32_t *plainTextLen)
{
    uint8_t *realCipherText = NULL;
    uint32_t realCipherTextLen = 0;
    uint32_t ret = ParseAppDataMsg(cipherText, cipherTextLen, &realCipherText, &realCipherTextLen);
    if (ret != E2EE_SUCCESS) {
        E2EE_LOG_ERROR("Failed to parse app data message, ret: %d", ret);
        return ret;
    }

    ret = CRYPT_EAL_HpkeOpen(ctx->recipient, aad, aadLen, realCipherText, realCipherTextLen, plainText, plainTextLen);
    if (ret != CRYPT_SUCCESS) {
        E2EE_LOG_ERROR("Failed to decrypt message, ret: %d", ret);
        return E2EE_ERR_CRYPTO;
    }

    return E2EE_SUCCESS;
}

int32_t E2EE_ServerDecrypt(E2EE_ServerCtx *ctx, uint8_t *cipherText, uint32_t cipherTextLen,
    uint8_t *aad, uint32_t aadLen, uint8_t *plainText, uint32_t *plainTextLen)
{
    if (ctx == NULL || cipherText == NULL || cipherTextLen == 0 || plainText == NULL || plainTextLen == NULL) {
        E2EE_LOG_ERROR("Null input parameter");
        return E2EE_ERR_NULL_INPUT;
    }

    switch (ctx->recipientState) {
        case E2EE_SERVER_KEY_EXCH:
            return ProcessClientKeyExchMsg(ctx, cipherText, cipherTextLen, aad, aadLen, plainText, plainTextLen);
        case E2EE_SERVER_ENCRYPT:
            return ProcessAppDataMsg(ctx, cipherText, cipherTextLen, aad, aadLen, plainText, plainTextLen);
        default:
            E2EE_LOG_ERROR("Invalid server state: %d", ctx->recipientState);
            return E2EE_ERR_CALL;
    }
}

int32_t E2EE_ServerEncrypt(E2EE_ServerCtx *ctx, uint8_t *plainText, uint32_t plainTextLen,
    uint8_t *aad, uint32_t aadLen, uint8_t *cipherText, uint32_t *cipherTextLen)
{
    if (ctx == NULL || plainText == NULL || plainTextLen == 0 || cipherTextLen == NULL) {
        E2EE_LOG_ERROR("Null input parameter");
        return E2EE_ERR_NULL_INPUT;
    }

    if (plainTextLen > E2EE_MAX_PLIANTEXT_LEN) {
        E2EE_LOG_ERROR("Plain text length too large: %u", plainTextLen);
        return E2EE_ERR_INVALID_ARG;
    }

    switch (ctx->senderState) {
        case E2EE_SERVER_KEY_EXCH:
            return ServerGenKeyExchMsg(ctx, plainText, plainTextLen, aad, aadLen, cipherText, cipherTextLen);
        case E2EE_SERVER_ENCRYPT:
            return ServerGenAppDataMsg(ctx, plainText, plainTextLen, aad, aadLen, cipherText, cipherTextLen);
        default:
            E2EE_LOG_ERROR("Invalid server state: %d", ctx->senderState);
            return E2EE_ERR_CALL;
    }
}

void E2EE_ServerDestroy(E2EE_ServerCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    if (ctx->sender != NULL) {
        DestroySelfEncryptionCtx(ctx->sender);
    }

    DeInitServerRecipient(ctx);

    FreeKeyExchInfo(ctx);

    E2EE_Free(ctx);
}

void E2EE_SetServerKemCallback(E2EE_ServerCtx *ctx, E2EE_KemDecapsulateCallbackFunc keyDeriveFunc, void *callbackArg)
{
    if (ctx == NULL) {
        return;
    }

    ctx->keyDeriveFunc = keyDeriveFunc;
    ctx->callbackArg = callbackArg;
}