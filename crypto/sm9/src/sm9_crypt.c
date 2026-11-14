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
#ifdef HITLS_CRYPTO_SM9

#include "sm9_local.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "crypt_util_rand.h"
#include "bsl_sal.h"
#include "bsl_bytes.h"
#include <string.h>

#define SM9_C1_BYTE_LEN (2 * SM9_BN_BYTES)
#define SM9_C3_BYTE_LEN SM9_BN_BYTES

static const uint8_t SM9_HID_ENC[1] = {0x03};

int32_t SM9_SetEncMasterKey(SM9_Ctx *ctx, uint8_t *masterPrivateKey)
{
    if (ctx == NULL || masterPrivateKey == NULL) {
        return CRYPT_SM9_ERR_BAD_INPUT;
    }

    memcpy(ctx->encMsk, masterPrivateKey, SM9_ENC_SYS_PRIKEY_BYTES);

    int32_t ret = SM9_Alg_MEKG(ctx->encMsk, ctx->encMpk);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = SM9_Alg_Pair(ctx->encG, ctx->encMpk, g_sm9G2);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ctx->hasEncSys = 1;
    ctx->hasEncG = 1;
    ctx->hasEncMsk = 1;

    return CRYPT_SUCCESS;
}

int32_t SM9_GenEncUserKey(SM9_Ctx *ctx, const uint8_t *userId, uint32_t userIdLen)
{
    if (ctx == NULL || userId == NULL || userIdLen == 0 || userIdLen > 256) {
        return CRYPT_SM9_ERR_BAD_INPUT;
    }

    if (ctx->hasEncSys == 0 || ctx->hasEncMsk == 0) {
        return CRYPT_SM9_ERR_BAD_INPUT;
    }

    memcpy(ctx->userId, userId, userIdLen);
    ctx->userIdLen = userIdLen;

    int32_t ret = SM9_Alg_UEKG(userId, userIdLen, ctx->encMsk, ctx->encDek);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ctx->hasEncUsr = 1;

    return CRYPT_SUCCESS;
}

int32_t SM9_SetEncUserKey(SM9_Ctx *ctx, uint8_t *userId, uint32_t userIdLen, uint8_t *userPrivateKey)
{
    if (ctx == NULL || userId == NULL || userIdLen == 0 || userIdLen > 256 || userPrivateKey == NULL) {
        return CRYPT_SM9_ERR_BAD_INPUT;
    }
    int32_t ret = SM9_Ecp2A_ValidateBytes(userPrivateKey);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    memcpy(ctx->userId, userId, userIdLen);
    ctx->userIdLen = userIdLen;

    memcpy(ctx->encDek, userPrivateKey, SM9_ENC_USR_PRIKEY_BYTES);

    ctx->hasEncUsr = 1;

    return CRYPT_SUCCESS;
}

static void SM9_Xor(uint8_t *output, uint32_t len, const uint8_t *data, uint8_t *keyStream)
{
    for (uint32_t i = 0; i < len; i++) {
        output[i] = data[i] ^ keyStream[i];
    }
}

static int32_t SM9_Alg_CheckEncUserKey(const uint8_t *masterPubKey, const uint8_t *userId, uint32_t userIdLen,
                                       const uint8_t *userPrivateKey)
{
    uint32_t h1[SM9_BN_WORDS];
    SM9_EcpA masterPub;
    SM9_EcpA idPoint;
    SM9_EcpA userPub;
    SM9_EcpJ userPubJ;
    SM9_Ecp2A userKey;
    int32_t ret = CRYPT_SM9_ERR_BAD_INPUT;

    if (masterPubKey == NULL || userId == NULL || userIdLen == 0 || userIdLen > 256 || userPrivateKey == NULL) {
        return ret;
    }

    SM9_EcpA_ReadBytes(&masterPub, masterPubKey);
    SM9_Ecp2A_ReadBytes(&userKey, userPrivateKey);
    GOTO_ERR_IF_EX(SM9_Hash_H(h1, 0x01, userId, userIdLen, SM9_HID_ENC, sizeof(SM9_HID_ENC)), ret);
    SM9_Ecp_KP(&idPoint, &g_sm9SysPara.ecFpGMont, h1);
    SM9_EcpA_ToJ(&userPubJ, &masterPub);
    SM9_EcpJ_AddA(&userPubJ, &userPubJ, &idPoint);
    SM9_EcpJ_ToA(&userPub, &userPubJ);

    ret = SM9_Alg_PairEqual(&userPub, &userKey, &masterPub, &g_sm9SysPara.ecFp2GMont);
ERR:
    BSL_SAL_CleanseData(h1, sizeof(h1));
    BSL_SAL_CleanseData(&masterPub, sizeof(masterPub));
    BSL_SAL_CleanseData(&idPoint, sizeof(idPoint));
    BSL_SAL_CleanseData(&userPub, sizeof(userPub));
    BSL_SAL_CleanseData(&userPubJ, sizeof(userPubJ));
    BSL_SAL_CleanseData(&userKey, sizeof(userKey));
    return ret;
}

int32_t SM9_Alg_MEKG(uint8_t *masterPrivateKey, uint8_t *masterPubKey)
{
    uint32_t masterScalar[SM9_BN_WORDS];
    SM9_EcpA masterPoint;

    // Read System PriKey to BN
    SM9_BN_ReadBytes(masterScalar, masterPrivateKey);
    // Genarate System PubKey(in APoint MontMode)
    SM9_Ecp_KP(&masterPoint, &g_sm9SysPara.ecFpGMont, masterScalar);
    // Convert System PubKey to bytes(in NormMode)
    SM9_EcpA_WriteBytes(masterPubKey, &masterPoint);

    return CRYPT_SUCCESS;
}

int32_t SM9_Alg_UEKG(const uint8_t *userId, uint32_t userIdLen, uint8_t *masterPrivateKey, uint8_t *userPrivateKey)
{
    uint32_t identityScalar[SM9_BN_WORDS];
    uint32_t keyScalar[SM9_BN_WORDS];
    SM9_Ecp2A userPoint;

    int32_t ret;

    // Read System PriKey to BN
    SM9_BN_ReadBytes(keyScalar, masterPrivateKey);

    // Compute t1 = H1(IDA||hid, N)+ks
    GOTO_ERR_IF_EX(SM9_Hash_H(identityScalar, 0x01, userId, userIdLen, SM9_HID_ENC, 1), ret);
    SM9_BN_ModAdd(identityScalar, identityScalar, keyScalar, g_sm9SysPara.ecN, g_sm9SysPara.wordSize);
    // Check t1 != 0
    if (SM9_BN_IsZero(identityScalar, g_sm9SysPara.wordSize) != 0) {
        ret = CRYPT_SM9_ERR_KEY_ERR;
        goto ERR;
    }
    // Compute t2 = ks*(t1^-1)
    SM9_BN_GetInvMont(identityScalar, identityScalar, g_sm9SysPara.ecN, g_sm9SysPara.nMc, g_sm9SysPara.nR2,
                      g_sm9SysPara.wordSize);
    SM9_BN_MontMul(keyScalar, identityScalar, keyScalar, g_sm9SysPara.ecN, g_sm9SysPara.nMc, g_sm9SysPara.wordSize);
    // Compute userPrivateKey = [t2]P1
    SM9_Ecp2_KP(&userPoint, &g_sm9SysPara.ecFp2GMont, keyScalar);

    // Convert User PriKey to bytes(in NormMode)
    SM9_Ecp2A_WriteBytes(userPrivateKey, &userPoint);

    ret = CRYPT_SUCCESS;
ERR:
    BSL_SAL_CleanseData(identityScalar, sizeof(identityScalar));
    BSL_SAL_CleanseData(keyScalar, sizeof(keyScalar));
    BSL_SAL_CleanseData(&userPoint, sizeof(userPoint));
    return ret;
}

static int32_t SM9_Hash_KDFInit(SM9_AlgCtx *ctx, const uint8_t *c1, uint8_t *pairingBytes, const uint8_t *userId,
                                uint32_t userIdLen)
{
    int32_t ret;

    RETURN_RET_IF_ERR_EX(CRYPT_SM3_Init(&ctx->enc.xorCtx), ret);
    RETURN_RET_IF_ERR_EX(CRYPT_SM3_Update(&ctx->enc.xorCtx, c1, 2 * SM9_BN_BYTES), ret);
    RETURN_RET_IF_ERR_EX(CRYPT_SM3_Update(&ctx->enc.xorCtx, pairingBytes, 12 * SM9_BN_BYTES), ret);
    RETURN_RET_IF_ERR_EX(CRYPT_SM3_Update(&ctx->enc.xorCtx, userId, userIdLen), ret);
    ctx->enc.cnt[0] = ctx->enc.cnt[1] = ctx->enc.cnt[2] = 0;
    ctx->enc.cnt[3] = 1;
    return CRYPT_SUCCESS;
}

static int32_t SM9_Hash_KDFBlock(SM9_AlgCtx *ctx, uint32_t blockIndex, uint8_t *output)
{
    CRYPT_SM3_Ctx hashCtx;
    uint32_t hashLen = CRYPT_SM3_DIGESTSIZE;
    uint8_t counterBytes[4];
    int32_t ret;

    counterBytes[0] = (blockIndex & 0xFF000000) >> 24;
    counterBytes[1] = (blockIndex & 0x00FF0000) >> 16;
    counterBytes[2] = (blockIndex & 0x0000FF00) >> 8;
    counterBytes[3] = blockIndex & 0x000000FF;
    memcpy(&hashCtx, &ctx->enc.xorCtx, sizeof(hashCtx));

    GOTO_ERR_IF_EX(CRYPT_SM3_Update(&hashCtx, counterBytes, 4), ret);
    GOTO_ERR_IF_EX(CRYPT_SM3_Final(&hashCtx, output, &hashLen), ret);
ERR:
    BSL_SAL_CleanseData(&hashCtx, sizeof(hashCtx));
    return ret;
}

static int32_t SM9_EncInit(SM9_AlgCtx *ctx, const uint8_t *userId, uint32_t userIdLen, uint8_t *randomBytes,
                           const uint8_t *precomputedPairing, const uint8_t *masterPubKey, uint8_t *c1)
{
    uint32_t nonceScalar[SM9_BN_WORDS];
    uint32_t identityHash[SM9_BN_WORDS];
    SM9_EcpA recipientPoint;
    SM9_EcpA ephemeralPoint;
    SM9_Fp12 pairingValue;
    uint8_t encodedPairing[12 * SM9_BN_BYTES];
    int32_t ret = SM9_EcpA_ValidateBytes(masterPubKey);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    // Read Random number randomBytes(in NormMode), ensure randomBytes in [1, N-1]
    SM9_BN_ReadBytes(nonceScalar, randomBytes);
    SM9_Fn_LastRes(nonceScalar);
    SM9_BN_AddInt(nonceScalar, nonceScalar, 1, SM9_BN_WORDS);
    SM9_Fn_LastRes(nonceScalar);
    // Read System PubKey to JPoint in MontMode
    SM9_EcpA_ReadBytes(&recipientPoint, masterPubKey);

    // Get System Element precomputedPairing and convert to MontMode
    if (precomputedPairing != NULL) {
        // Read from input
        SM9_Fp12_ReadBytes(&pairingValue, precomputedPairing);
        // w = precomputedPairing^randomBytes
        SM9_Fp12_Exp(&pairingValue, &pairingValue, nonceScalar);
    } else {
        // Compute by input
        SM9_Ecp_KP(&ephemeralPoint, &recipientPoint, nonceScalar);
        SM9_Pairing_RAte(&pairingValue, &ephemeralPoint, &g_sm9SysPara.ecFp2GMont);
    }
    SM9_Fp12_WriteBytes(encodedPairing, &pairingValue);

    // h1 = H1(IDB||hid, N)
    GOTO_ERR_IF_EX(SM9_Hash_H(identityHash, 0x01, userId, userIdLen, SM9_HID_ENC, 1), ret);

    // QB=[h1]P1+Ppub-e
    SM9_FpEcp_KPAddAToA(&recipientPoint, &g_sm9SysPara.ecFpGMont, identityHash, &recipientPoint, &g_sm9SysPara);

    // c1=[randomBytes]QB
    SM9_Ecp_KP(&recipientPoint, &recipientPoint, nonceScalar);
    SM9_EcpA_WriteBytes(c1, &recipientPoint);

    GOTO_ERR_IF_EX(SM9_Hash_KDFInit(ctx, c1, encodedPairing, userId, userIdLen), ret);
    ctx->enc.bytes = 0;
    ret = CRYPT_SUCCESS;
ERR:
    BSL_SAL_CleanseData(nonceScalar, sizeof(nonceScalar));
    BSL_SAL_CleanseData(identityHash, sizeof(identityHash));
    BSL_SAL_CleanseData(encodedPairing, sizeof(encodedPairing));
    BSL_SAL_CleanseData(&pairingValue, sizeof(pairingValue));
    BSL_SAL_CleanseData(&recipientPoint, sizeof(recipientPoint));
    BSL_SAL_CleanseData(&ephemeralPoint, sizeof(ephemeralPoint));
    return ret;
}

// Key derivation function for public key encryption
// Mode-1: msg is not null, generate key stream and xor msg to enc
// Mode-2: msg is null and mlen is null, generate key stream with ctx's bytes record to enc
// Mode-3: msg is null and mlen is not null, generate key stream with mlen to enc
static int32_t SM9_PkeKdf(SM9_AlgCtx *ctx, const uint8_t *msg, uint32_t msgLen, uint8_t *output)
{
    uint8_t keyStream[2 * CRYPT_SM3_DIGESTSIZE];
    uint32_t i;
    uint32_t blockIndex;
    uint32_t blockOffset;
    int32_t ret = CRYPT_SUCCESS;

    blockIndex = ctx->enc.bytes / CRYPT_SM3_DIGESTSIZE + 1;
    blockOffset = ctx->enc.bytes % CRYPT_SM3_DIGESTSIZE;

    if (msg == NULL) {
        if (msgLen != 0) {
            blockIndex = msgLen / CRYPT_SM3_DIGESTSIZE + 1;
            blockOffset = msgLen % CRYPT_SM3_DIGESTSIZE;
        }
        GOTO_ERR_IF_EX(SM9_Hash_KDFBlock(ctx, blockIndex++, keyStream), ret);
        if (blockOffset != 0) {
            GOTO_ERR_IF_EX(SM9_Hash_KDFBlock(ctx, blockIndex++, keyStream + CRYPT_SM3_DIGESTSIZE), ret);
        }
        memcpy(output, keyStream + blockOffset, CRYPT_SM3_DIGESTSIZE);
        goto ERR;
    }

    if (blockOffset != 0) {
        GOTO_ERR_IF_EX(SM9_Hash_KDFBlock(ctx, blockIndex++, keyStream), ret);
        SM9_Xor(&output[blockOffset], CRYPT_SM3_DIGESTSIZE - blockOffset, msg, keyStream);
        output += CRYPT_SM3_DIGESTSIZE - blockOffset;
        msg += CRYPT_SM3_DIGESTSIZE - blockOffset;
        msgLen -= CRYPT_SM3_DIGESTSIZE - blockOffset;
        ctx->enc.bytes += CRYPT_SM3_DIGESTSIZE - blockOffset;
    }

    for (i = 1; i <= msgLen / CRYPT_SM3_DIGESTSIZE; i++) {
        GOTO_ERR_IF_EX(SM9_Hash_KDFBlock(ctx, blockIndex++, keyStream), ret);
        SM9_Xor(output, CRYPT_SM3_DIGESTSIZE, msg, keyStream);
        output += CRYPT_SM3_DIGESTSIZE;
        msg += CRYPT_SM3_DIGESTSIZE;
    }
    if ((blockOffset = msgLen % CRYPT_SM3_DIGESTSIZE) != 0) {
        GOTO_ERR_IF_EX(SM9_Hash_KDFBlock(ctx, blockIndex++, keyStream), ret);
        SM9_Xor(output, blockOffset, msg, keyStream);
    }
    ctx->enc.bytes += msgLen;
ERR:
    BSL_SAL_CleanseData(keyStream, sizeof(keyStream));
    return ret;
}

int32_t SM9_Alg_Enc(const uint8_t *msg, uint32_t msgLen, const uint8_t *userId, uint32_t userIdLen,
                    uint8_t *randomBytes, const uint8_t *precomputedPairing, const uint8_t *masterPubKey,
                    uint8_t *ciphertext, uint32_t *ciphertextLen)
{
    SM9_AlgCtx ctx;
    uint32_t hashLen = CRYPT_SM3_DIGESTSIZE;
    uint8_t *c1;
    uint8_t *c2;
    uint8_t *c3;
    uint8_t macKey[CRYPT_SM3_DIGESTSIZE];
    int32_t ret;

    c1 = ciphertext;
    c3 = c1 + SM9_C1_BYTE_LEN;
    c2 = c3 + SM9_C3_BYTE_LEN;

    if ((c2 > msg) && (c2 < msg + msgLen)) {
        return CRYPT_SM9_ERR_BAD_INPUT;
    }

    GOTO_ERR_IF_EX(SM9_EncInit(&ctx, userId, userIdLen, randomBytes, precomputedPairing, masterPubKey, c1), ret);
    GOTO_ERR_IF_EX(CRYPT_SM3_Init(&ctx.macCtx), ret);

    GOTO_ERR_IF_EX(SM9_PkeKdf(&ctx, msg, msgLen, c2), ret);

    GOTO_ERR_IF_EX(CRYPT_SM3_Update(&ctx.macCtx, c2, msgLen), ret);

    // K1 is all zeros if c2 == msg after XOR, must reject per GM/T 0044-2016 A6 a.1
    // ConstTimeMemcmp returns non-zero when equal
    if (msgLen > 0 && ConstTimeMemcmp(c2, msg, msgLen) != 0) {
        ret = CRYPT_SM9_ERR_ENCRYPT_FAILED;
        goto ERR;
    }

    GOTO_ERR_IF_EX(SM9_PkeKdf(&ctx, 0, 0, macKey), ret);
    GOTO_ERR_IF_EX(CRYPT_SM3_Update(&ctx.macCtx, macKey, CRYPT_SM3_DIGESTSIZE), ret);
    GOTO_ERR_IF_EX(CRYPT_SM3_Final(&ctx.macCtx, c3, &hashLen), ret);

    if (ciphertextLen != NULL) {
        *ciphertextLen = msgLen + SM9_C1_BYTE_LEN + SM9_C3_BYTE_LEN;
    }

    ret = CRYPT_SUCCESS;
ERR:
    BSL_SAL_CleanseData(macKey, sizeof(macKey));
    BSL_SAL_CleanseData(&ctx, sizeof(ctx));
    return ret;
}

static int32_t SM9_DecInit(SM9_AlgCtx *ctx, const uint8_t *userPrivateKey, const uint8_t *userId, uint32_t userIdLen,
                           const uint8_t *c1)
{
    SM9_EcpA ephemeralPoint;
    SM9_Ecp2A userKeyPoint;
    SM9_Fp12 pairingValue;
    uint8_t encodedPairing[12 * SM9_BN_BYTES];
    int32_t ret;

    if (SM9_EcpA_ValidateBytes(c1) != CRYPT_SUCCESS) {
        return CRYPT_SM9_ERR_DECRYPT_FAILED;
    }

    // Read User Prikey and convert to MontMode
    SM9_Ecp2A_ReadBytes(&userKeyPoint, userPrivateKey);
    // Read Cipher Part1(in APoint MontMode)
    SM9_EcpA_ReadBytes(&ephemeralPoint, c1);

    // w'=e(c1, userPrivateKey)
    SM9_Pairing_RAte(&pairingValue, &ephemeralPoint, &userKeyPoint);
    SM9_Fp12_WriteBytes(encodedPairing, &pairingValue);

    GOTO_ERR_IF_EX(SM9_Hash_KDFInit(ctx, c1, encodedPairing, userId, userIdLen), ret);
    ctx->enc.bytes = 0;

    ret = CRYPT_SUCCESS;
ERR:
    BSL_SAL_CleanseData(encodedPairing, sizeof(encodedPairing));
    BSL_SAL_CleanseData(&pairingValue, sizeof(pairingValue));
    BSL_SAL_CleanseData(&userKeyPoint, sizeof(userKeyPoint));
    return ret;
}

int32_t SM9_Alg_Dec(const uint8_t *ciphertext, uint32_t ciphertextLen, const uint8_t *userPrivateKey,
                    const uint8_t *userId, uint32_t userIdLen, uint8_t *msg, uint32_t *msgLen)
{
    SM9_AlgCtx ctx;
    uint32_t hashLen = CRYPT_SM3_DIGESTSIZE;
    const uint8_t *c1;
    const uint8_t *c2;
    const uint8_t *c3;
    uint8_t derivedKey[2 * CRYPT_SM3_DIGESTSIZE];
    uint8_t mac[SM9_C3_BYTE_LEN];
    uint32_t plaintextLen;
    int32_t ret;

    if (ciphertextLen < SM9_C1_BYTE_LEN + SM9_C3_BYTE_LEN) {
        return CRYPT_SM9_ERR_BAD_INPUT;
    }
    plaintextLen = ciphertextLen - SM9_C1_BYTE_LEN - SM9_C3_BYTE_LEN;

    c1 = ciphertext;
    c3 = c1 + SM9_C1_BYTE_LEN;
    c2 = c3 + SM9_C3_BYTE_LEN;

    GOTO_ERR_IF_EX(SM9_DecInit(&ctx, userPrivateKey, userId, userIdLen, c1), ret);
    GOTO_ERR_IF_EX(CRYPT_SM3_Init(&ctx.macCtx), ret);
    GOTO_ERR_IF_EX(CRYPT_SM3_Update(&ctx.macCtx, c2, plaintextLen), ret);
    GOTO_ERR_IF_EX(SM9_PkeKdf(&ctx, 0, plaintextLen, derivedKey), ret);
    GOTO_ERR_IF_EX(CRYPT_SM3_Update(&ctx.macCtx, derivedKey, CRYPT_SM3_DIGESTSIZE), ret);
    GOTO_ERR_IF_EX(CRYPT_SM3_Final(&ctx.macCtx, mac, &hashLen), ret);
    // Compute MAC(K2', c2) and Compare to c3

    if (ConstTimeMemcmp(mac, c3, SM9_C3_BYTE_LEN) == 0) {
        ret = CRYPT_SM9_ERR_DECRYPT_FAILED;
        goto ERR;
    }
    GOTO_ERR_IF_EX(SM9_PkeKdf(&ctx, c2, plaintextLen, msg), ret);

    if (msgLen != NULL) {
        *msgLen = ciphertextLen - SM9_C1_BYTE_LEN - SM9_C3_BYTE_LEN;
    }

    ret = CRYPT_SUCCESS;
ERR:
    BSL_SAL_CleanseData(&ctx, sizeof(ctx));
    BSL_SAL_CleanseData(derivedKey, sizeof(derivedKey));
    BSL_SAL_CleanseData(mac, sizeof(mac));
    return ret;
}

int32_t SM9_CheckEncKeyPair(const CRYPT_SM9_Ctx *masterCtx, const CRYPT_SM9_Ctx *userCtx)
{
    if (userCtx->userIdLen == 0 || userCtx->userIdLen > sizeof(userCtx->userId) ||
        (masterCtx->userIdLen > 0 && (masterCtx->userIdLen != userCtx->userIdLen ||
                                      memcmp(masterCtx->userId, userCtx->userId, userCtx->userIdLen) != 0))) {
        return CRYPT_SM9_PAIRWISE_CHECK_FAIL;
    }
    return SM9_Alg_CheckEncUserKey(masterCtx->encMpk, userCtx->userId, userCtx->userIdLen, userCtx->encDek);
}

int32_t CRYPT_SM9_Encrypt(const CRYPT_SM9_Ctx *ctx, const uint8_t *data, uint32_t dataLen, uint8_t *out,
                          uint32_t *outLen)
{
    if (ctx == NULL || data == NULL || out == NULL || outLen == NULL) {
        return CRYPT_NULL_INPUT;
    }

    /* SM9 encryption needs user ID - must be stored in context */
    if (ctx->userIdLen == 0) {
        return CRYPT_SM9_ERR_NO_USER_ID;
    }

    uint32_t requiredLen = dataLen + SM9_ENC_OVERHEAD_BYTES;
    if (requiredLen < dataLen || *outLen < requiredLen) {
        return CRYPT_SM9_BUFF_LEN_NOT_ENOUGH;
    }

    if (ctx->hasEncSys == 0) {
        return CRYPT_SM9_ERR_ENCRYPT_FAILED;
    }
    uint8_t randBuf[SM9_CURVE_MODULE_BYTES];
    int32_t ret = CRYPT_RandEx(NULL, randBuf, sizeof(randBuf));
    if (ret != CRYPT_SUCCESS) {
        return CRYPT_SM9_ERR_ENCRYPT_FAILED;
    }
    uint32_t cipherLen = *outLen;
    ret = SM9_Alg_Enc(data, dataLen, ctx->userId, ctx->userIdLen, randBuf, ctx->hasEncG != 0 ? ctx->encG : NULL,
                      ctx->encMpk, out, &cipherLen);
    BSL_SAL_CleanseData(randBuf, sizeof(randBuf));
    if (ret != CRYPT_SUCCESS) {
        return CRYPT_SM9_ERR_ENCRYPT_FAILED;
    }

    *outLen = cipherLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM9_Decrypt(const CRYPT_SM9_Ctx *ctx, const uint8_t *data, uint32_t dataLen, uint8_t *out,
                          uint32_t *outLen)
{
    if (ctx == NULL || data == NULL || out == NULL || outLen == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (dataLen < SM9_ENC_OVERHEAD_BYTES) {
        return CRYPT_SM9_ERR_DECRYPT_FAILED;
    }

    uint32_t plaintextLen = dataLen - SM9_ENC_OVERHEAD_BYTES;
    if (*outLen < plaintextLen) {
        return CRYPT_SM9_BUFF_LEN_NOT_ENOUGH;
    }

    if (ctx->hasEncUsr == 0) {
        return CRYPT_SM9_ERR_DECRYPT_FAILED;
    }
    uint32_t plainLen = *outLen;
    int32_t ret = SM9_Alg_Dec(data, dataLen, ctx->encDek, ctx->userId, ctx->userIdLen, out, &plainLen);
    if (ret != CRYPT_SUCCESS) {
        return CRYPT_SM9_ERR_DECRYPT_FAILED;
    }

    *outLen = plainLen;
    return CRYPT_SUCCESS;
}

#endif // HITLS_CRYPTO_SM9
