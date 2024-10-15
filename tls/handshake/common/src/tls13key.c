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

#include <stdbool.h>
#include "securec.h"
#include "bsl_bytes.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "hitls_crypt_type.h"
#include "tls.h"
#include "crypt.h"
#include "rec.h"
#include "hs_kx.h"
#include "transcript_hash.h"

int32_t HS_TLS13DeriveSecret(CRYPT_KeyDeriveParameters *deriveInfo, bool isHashed, uint8_t *outSecret, uint32_t outLen)
{
    int32_t ret;
    uint8_t transcriptHash[MAX_DIGEST_SIZE] = {0};
    uint32_t hashLen = SAL_CRYPT_DigestSize(deriveInfo->hashAlgo);
    if (hashLen == 0) {
        return HITLS_CRYPT_ERR_DIGEST;
    }
    if (!isHashed) {
        ret = SAL_CRYPT_Digest(deriveInfo->hashAlgo, deriveInfo->seed, deriveInfo->seedLen, transcriptHash, &hashLen);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }

        deriveInfo->seed = transcriptHash;
        deriveInfo->seedLen = hashLen;
    }

    return SAL_CRYPT_HkdfExpandLabel(deriveInfo, outSecret, outLen);
}

int32_t TLS13HkdfExtract(HITLS_CRYPT_HkdfExtractInput *extractInput, uint8_t *prk, uint32_t *prkLen)
{
    uint32_t hashLen = SAL_CRYPT_DigestSize(extractInput->hashAlgo);
    if (hashLen == 0) {
        return HITLS_CRYPT_ERR_DIGEST;
    }
    uint8_t zeros[MAX_DIGEST_SIZE] = {0};

    if (extractInput->salt == NULL) {
        extractInput->salt = zeros;
        extractInput->saltLen = hashLen;
    }

    if (extractInput->ikm == NULL) {
        extractInput->ikm = zeros;
        extractInput->ikmLen = hashLen;
    }

    return SAL_CRYPT_HkdfExtract(extractInput, prk, prkLen);
}

/**
             0
             |
             v
    PSK ->  HKDF-Extract = Early Secret
 */
int32_t HS_TLS13DeriveEarlySecret(HITLS_HashAlgo hashAlgo, const uint8_t *psk, uint32_t pskLen,
    uint8_t *earlySecret, uint32_t *outLen)
{
    HITLS_CRYPT_HkdfExtractInput extractInput = {0};
    extractInput.hashAlgo = hashAlgo;
    extractInput.salt = NULL;
    extractInput.saltLen = 0;
    extractInput.ikm = psk;
    extractInput.ikmLen = pskLen;

    return TLS13HkdfExtract(&extractInput, earlySecret, outLen);
}

int32_t HS_TLS13DeriveBinderKey(HITLS_HashAlgo hashAlgo, bool isExternalPsk,
    const uint8_t *earlySecret, uint32_t secretLen, uint8_t *binderKey, uint32_t keyLen)
{
    uint8_t *binderLabel;
    uint32_t labelLen;
    uint8_t extBinderLabel[] = "ext binder";
    uint8_t resBinderLabel[] = "res binder";
    if (isExternalPsk) {
        binderLabel = extBinderLabel;
        labelLen = sizeof(extBinderLabel) - 1;
    } else {
        binderLabel = resBinderLabel;
        labelLen = sizeof(resBinderLabel) - 1;
    }

    CRYPT_KeyDeriveParameters deriveInfo = {0};
    deriveInfo.hashAlgo = hashAlgo;
    deriveInfo.secret = earlySecret;
    deriveInfo.secretLen = secretLen;
    deriveInfo.label = binderLabel;
    deriveInfo.labelLen = labelLen;
    deriveInfo.seed = NULL;
    deriveInfo.seedLen = 0;
    int32_t ret = HS_TLS13DeriveSecret(&deriveInfo, false, binderKey, keyLen);
    return ret;
}

/**
            Early Secret
             |
             v
       Derive-Secret(., "derived", empty string)
             |
             v
   (EC)DHE -> HKDF-Extract = Handshake Secret
             |
             v
       Derive-Secret(., "derived", empty string)
             |
             v
   0 -> HKDF-Extract = Master Secret
*/
int32_t HS_TLS13DeriveNextStageSecret(HITLS_HashAlgo hashAlgo, const uint8_t *inSecret, uint32_t inLen,
    const uint8_t *givenSecret, uint32_t givenLen, uint8_t *outSecret, uint32_t *outLen)
{
    int32_t ret;
    uint8_t label[] = "derived";
    uint8_t tmpSecret[MAX_DIGEST_SIZE];
    uint32_t hashLen = SAL_CRYPT_DigestSize(hashAlgo);
    if (hashLen == 0) {
        return HITLS_CRYPT_ERR_DIGEST;
    }

    CRYPT_KeyDeriveParameters deriveInfo = {0};
    deriveInfo.hashAlgo = hashAlgo;
    deriveInfo.secret = inSecret;
    deriveInfo.secretLen = inLen;
    deriveInfo.label = label;
    deriveInfo.labelLen = sizeof(label) - 1;
    deriveInfo.seed = NULL;
    deriveInfo.seedLen = 0;
    ret = HS_TLS13DeriveSecret(&deriveInfo, false, tmpSecret, hashLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    HITLS_CRYPT_HkdfExtractInput extractInput = {0};
    extractInput.hashAlgo = hashAlgo;
    extractInput.salt = tmpSecret;
    extractInput.saltLen = hashLen;
    extractInput.ikm = givenSecret;
    extractInput.ikmLen = givenLen;
    return TLS13HkdfExtract(&extractInput, outSecret, outLen);
}

/**
        Early Secret
             |
             v
       Derive-Secret(., "derived", empty string)
             |
             v
   (EC)DHE -> HKDF-Extract = Handshake Secret
 */
int32_t TLS13DeriveHandshakeSecret(TLS_Ctx *ctx)
{
    uint16_t hashAlg = ctx->negotiatedInfo.cipherSuiteInfo.hashAlg;
    uint32_t hashLen = SAL_CRYPT_DigestSize(hashAlg);
    if (hashLen == 0) {
        return HITLS_CRYPT_ERR_DIGEST;
    }
    uint8_t preMasterSecret[MAX_PRE_MASTER_SECRET_SIZE] = {0};
    uint32_t preMasterSecretLen = MAX_PRE_MASTER_SECRET_SIZE;
    KeyExchCtx *keyCtx = ctx->hsCtx->kxCtx;
    int32_t ret;
    if (keyCtx->peerPubkey != NULL) {
        ret = SAL_CRYPT_CalcEcdhSharedSecret(keyCtx->key, keyCtx->peerPubkey, keyCtx->pubKeyLen,
            preMasterSecret, &preMasterSecretLen);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    } else {
        /* In psk-only mode, the key is an all-zero array of the hash length. */
        preMasterSecretLen = hashLen;
    }

    uint32_t handshakeSecretLen = hashLen;
    ret = HS_TLS13DeriveNextStageSecret(hashAlg, ctx->hsCtx->earlySecret, hashLen,
        preMasterSecret, preMasterSecretLen, ctx->hsCtx->handshakeSecret, &handshakeSecretLen);

    BSL_SAL_CleanseData(preMasterSecret, MAX_PRE_MASTER_SECRET_SIZE);
    return ret;
}

/**
   (EC)DHE -> HKDF-Extract = Handshake Secret
             |
             v
       Derive-Secret(., "derived", "")
             |
             v
   0 -> HKDF-Extract = Master Secret
*/
int32_t TLS13DeriveMasterSecret(TLS_Ctx *ctx)
{
    uint16_t hashAlg = ctx->negotiatedInfo.cipherSuiteInfo.hashAlg;
    uint32_t hashLen = SAL_CRYPT_DigestSize(hashAlg);
    if (hashLen == 0) {
        return HITLS_CRYPT_ERR_DIGEST;
    }
    uint32_t masterKeyLen = hashLen;

    int32_t ret;
    ret = HS_TLS13DeriveNextStageSecret(hashAlg, ctx->hsCtx->handshakeSecret, hashLen,
        NULL, 0, ctx->hsCtx->masterKey, &masterKeyLen);
    return ret;
}

/**
    finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
*/
int32_t HS_TLS13DeriveFinishedKey(HITLS_HashAlgo hashAlgo, const uint8_t *baseKey, uint32_t baseKeyLen,
    uint8_t *finishedkey, uint32_t finishedkeyLen)
{
    uint8_t label[] = "finished";

    CRYPT_KeyDeriveParameters deriveInfo = {0};
    deriveInfo.hashAlgo = hashAlgo;
    deriveInfo.secret = baseKey;
    deriveInfo.secretLen = baseKeyLen;
    deriveInfo.label = label;
    deriveInfo.labelLen = sizeof(label) - 1;
    deriveInfo.seed = NULL;
    deriveInfo.seedLen = 0;
    return SAL_CRYPT_HkdfExpandLabel(&deriveInfo, finishedkey, finishedkeyLen);
}

/**
    HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length)
*/
int32_t HS_TLS13DeriveResumePsk(const TLS_Ctx *ctx, const uint8_t *ticketNonce, uint32_t ticketNonceSize,
    uint8_t *resumePsk, uint32_t resumePskLen)
{
    const uint8_t label[] = "resumption";
    HITLS_HashAlgo hashAlg = ctx->negotiatedInfo.cipherSuiteInfo.hashAlg;
    uint32_t hashLen = SAL_CRYPT_DigestSize(hashAlg);
    if (hashLen == 0) {
        return HITLS_CRYPT_ERR_DIGEST;
    }
    CRYPT_KeyDeriveParameters deriveInfo = {0};
    deriveInfo.hashAlgo = hashAlg;
    deriveInfo.secret = ctx->resumptionMasterSecret;
    deriveInfo.secretLen = hashLen;
    deriveInfo.label = label;
    deriveInfo.labelLen = sizeof(label) - 1;
    deriveInfo.seed = ticketNonce;
    deriveInfo.seedLen = ticketNonceSize;

    return SAL_CRYPT_HkdfExpandLabel(&deriveInfo, resumePsk, resumePskLen);
}

int32_t TLS13GetTrafficSecretDeriveInfo(TLS_Ctx *ctx, CRYPT_KeyDeriveParameters *deriveInfo,
    uint8_t *seed, uint32_t seedLen)
{
    uint32_t tmpSeedLen = seedLen;
    int32_t ret;
    ret = VERIFY_CalcSessionHash(ctx->hsCtx->verifyCtx, seed, &tmpSeedLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    uint16_t hashAlg = ctx->negotiatedInfo.cipherSuiteInfo.hashAlg;
    uint32_t hashLen = SAL_CRYPT_DigestSize(hashAlg);
    if (hashLen == 0) {
        return HITLS_CRYPT_ERR_DIGEST;
    }
    deriveInfo->hashAlgo = hashAlg;
    deriveInfo->seed = seed;
    deriveInfo->seedLen = tmpSeedLen;
    deriveInfo->secretLen = hashLen;
    return HITLS_SUCCESS;
}

/**
    Derive-Secret(Handshake Secret, label, ClientHello...ServerHello)
*/
int32_t HS_TLS13DeriveHandshakeTrafficSecret(TLS_Ctx *ctx)
{
    uint8_t seed[MAX_DIGEST_SIZE] = {0};
    uint32_t seedLen = MAX_DIGEST_SIZE;
    CRYPT_KeyDeriveParameters deriveInfo = {0};
    int32_t ret;
    ret = TLS13GetTrafficSecretDeriveInfo(ctx, &deriveInfo, seed, seedLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    deriveInfo.secret = ctx->hsCtx->handshakeSecret;
    uint32_t hashLen = deriveInfo.secretLen;
    uint8_t clientLabel[] = "c hs traffic";
    deriveInfo.label = clientLabel;
    deriveInfo.labelLen = sizeof(clientLabel) - 1;
    ret = HS_TLS13DeriveSecret(&deriveInfo, true, ctx->hsCtx->clientHsTrafficSecret, hashLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint8_t serverLabel[] = "s hs traffic";
    deriveInfo.label = serverLabel;
    deriveInfo.labelLen = sizeof(serverLabel) - 1;
    ret = HS_TLS13DeriveSecret(&deriveInfo, true, ctx->hsCtx->serverHsTrafficSecret, hashLen);
    return ret;
}

/**
    Derive-Secret(Master Secret, label, ClientHello...ServerHello)
*/
int32_t TLS13DeriveApplicationTrafficSecret(TLS_Ctx *ctx)
{
    uint8_t seed[MAX_DIGEST_SIZE] = {0};
    uint32_t seedLen = MAX_DIGEST_SIZE;
    CRYPT_KeyDeriveParameters deriveInfo = {0};
    int32_t ret;
    ret = TLS13GetTrafficSecretDeriveInfo(ctx, &deriveInfo, seed, seedLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    deriveInfo.secret = ctx->hsCtx->masterKey;
    uint32_t hashLen = deriveInfo.secretLen;
    uint8_t clientLabel[] = "c ap traffic";
    deriveInfo.label = clientLabel;
    deriveInfo.labelLen = sizeof(clientLabel) - 1;
    ret = HS_TLS13DeriveSecret(&deriveInfo, true, ctx->clientAppTrafficSecret, hashLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint8_t serverLabel[] = "s ap traffic";
    deriveInfo.label = serverLabel;
    deriveInfo.labelLen = sizeof(serverLabel) - 1;
    ret = HS_TLS13DeriveSecret(&deriveInfo, true, ctx->serverAppTrafficSecret, hashLen);
    return ret;
}

/**
    Derive-Secret(., "res master", ClientHello...client Finished) = resumption_master_secret
*/
int32_t HS_TLS13DeriveResumptionMasterSecret(TLS_Ctx *ctx)
{
    uint8_t seed[MAX_DIGEST_SIZE] = {0};
    uint32_t seedLen = MAX_DIGEST_SIZE;
    CRYPT_KeyDeriveParameters deriveInfo = {0};
    int32_t ret;

    ret = TLS13GetTrafficSecretDeriveInfo(ctx, &deriveInfo, seed, seedLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    deriveInfo.secret = ctx->hsCtx->masterKey;
    uint32_t hashLen = deriveInfo.secretLen;

    const uint8_t resLabel[] = "res master";
    deriveInfo.label = resLabel;
    deriveInfo.labelLen = sizeof(resLabel) - 1;

    return HS_TLS13DeriveSecret(&deriveInfo, true, ctx->resumptionMasterSecret, hashLen);
}

int32_t HS_TLS13CalcServerHelloProcessSecret(TLS_Ctx *ctx)
{
    PskInfo13 *pskInfo = &ctx->hsCtx->kxCtx->pskInfo13;
    uint16_t hashAlg = ctx->negotiatedInfo.cipherSuiteInfo.hashAlg;
    uint32_t hashLen = SAL_CRYPT_DigestSize(hashAlg);
    if (hashLen == 0 || hashLen > MAX_DIGEST_SIZE) {
        return HITLS_CRYPT_ERR_DIGEST;
    }
    uint8_t zero[MAX_DIGEST_SIZE] = {0};
    uint8_t *psk = NULL;
    uint32_t pskLen = 0;

    if (pskInfo->psk != NULL) {
        psk = pskInfo->psk;
        pskLen = pskInfo->pskLen;
    } else {
        psk = zero;
        pskLen = hashLen;
    }

    uint32_t earlySecretLen = hashLen;
    int32_t ret = HS_TLS13DeriveEarlySecret(hashAlg, psk, pskLen, ctx->hsCtx->earlySecret, &earlySecretLen);
    BSL_SAL_CleanseData(psk, pskLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    return TLS13DeriveHandshakeSecret(ctx);
}

int32_t HS_TLS13CalcServerFinishProcessSecret(TLS_Ctx *ctx)
{
    int32_t ret;
    ret = TLS13DeriveMasterSecret(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = TLS13DeriveApplicationTrafficSecret(ctx);
    return ret;
}

int32_t HS_SwitchTrafficKey(TLS_Ctx *ctx, uint8_t *secret, uint32_t secretLen, bool isOut)
{
    int32_t ret;
    CipherSuiteInfo *cipherSuiteInfo = &(ctx->negotiatedInfo.cipherSuiteInfo);
    uint32_t hashLen = SAL_CRYPT_DigestSize(cipherSuiteInfo->hashAlg);
    if (hashLen == 0) {
        return HITLS_CRYPT_ERR_DIGEST;
    }
    REC_SecParameters keyPara = {0};
    ret = HS_SetInitPendingStateParam(ctx, ctx->isClient, &keyPara);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    if (hashLen > sizeof(keyPara.masterSecret)) {
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        return HITLS_INTERNAL_EXCEPTION;
    }

    if (memcpy_s(keyPara.masterSecret, sizeof(keyPara.masterSecret), secret, secretLen) != EOK) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        return HITLS_MEMCPY_FAIL;
    }

    ret = REC_TLS13InitPendingState(ctx, &keyPara, isOut);
    (void)memset_s(keyPara.masterSecret, sizeof(keyPara.masterSecret), 0, sizeof(keyPara.masterSecret));
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /** enable key specification */
    ret = REC_ActivePendingState(ctx, isOut);
    return ret;
}

/**
    application_traffic_secret_N+1 = HKDF-Expand-Label(application_traffic_secret_N, "traffic upd", "", Hash.length)
*/
int32_t HS_TLS13UpdateTrafficSecret(TLS_Ctx *ctx, bool isOut)
{
    HITLS_HashAlgo hashAlg = ctx->negotiatedInfo.cipherSuiteInfo.hashAlg;
    uint32_t hashLen = SAL_CRYPT_DigestSize(hashAlg);
    if (hashLen == 0) {
        return HITLS_CRYPT_ERR_DIGEST;
    }
    uint8_t trafficSecret[MAX_DIGEST_SIZE] = {0};
    uint8_t *trafficSecretPointer = trafficSecret;
    uint32_t trafficSecretLen = hashLen;
    uint8_t *baseKey = NULL;
    uint32_t baseKeyLen = hashLen;
    if ((ctx->isClient && isOut) || (!ctx->isClient && !isOut)) {
        baseKey = ctx->clientAppTrafficSecret;
    } else {
        baseKey = ctx->serverAppTrafficSecret;
    }

    uint8_t label[] = "traffic upd";
    CRYPT_KeyDeriveParameters deriveInfo = {0};
    deriveInfo.hashAlgo = hashAlg;
    deriveInfo.secret = baseKey;
    deriveInfo.secretLen = baseKeyLen;
    deriveInfo.label = label;
    deriveInfo.labelLen = sizeof(label) - 1;
    deriveInfo.seed = NULL;
    deriveInfo.seedLen = 0;
    int32_t ret = SAL_CRYPT_HkdfExpandLabel(&deriveInfo, trafficSecretPointer, trafficSecretLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    if (memcpy_s(baseKey, baseKeyLen, trafficSecret, trafficSecretLen) != EOK) {
        return HITLS_MEMCPY_FAIL;
    }

    ret = HS_SwitchTrafficKey(ctx, baseKey, baseKeyLen, isOut);

    return ret;
}
