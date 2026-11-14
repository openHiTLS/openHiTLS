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
#include <string.h>

static const uint8_t SM9_HID_SIGN[1] = {0x01};

int32_t SM9_SetSignMasterKey(SM9_Ctx *ctx, uint8_t *masterPrivateKey)
{
    if (ctx == NULL || masterPrivateKey == NULL) {
        return CRYPT_SM9_ERR_BAD_INPUT;
    }

    memcpy(ctx->sigMsk, masterPrivateKey, SM9_SIG_SYS_PRIKEY_BYTES);

    int32_t ret = SM9_Alg_MSKG(ctx->sigMsk, ctx->sigMpk);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = SM9_Alg_Pair(ctx->sigG, g_sm9G1, ctx->sigMpk);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ctx->hasSigSys = 1;
    ctx->hasSigG = 1;
    ctx->hasSigMsk = 1;

    return CRYPT_SUCCESS;
}

static int32_t SM9_Alg_USKG(const uint8_t *userId, uint32_t userIdLen, uint8_t *masterPrivateKey,
                            uint8_t *userPrivateKey)
{
    uint32_t identityScalar[SM9_BN_WORDS];
    uint32_t keyScalar[SM9_BN_WORDS];
    SM9_EcpA userPoint;

    int32_t ret;

    // Read System PriKey to BN
    SM9_BN_ReadBytes(keyScalar, masterPrivateKey);

    // Compute t1 = H1(IDA||hid, N)+masterPrivateKey
    GOTO_ERR_IF_EX(SM9_Hash_H(identityScalar, 0x01, userId, userIdLen, SM9_HID_SIGN, 1), ret);
    SM9_Fn_Add(identityScalar, identityScalar, keyScalar);
    // Check t1 != 0
    if (SM9_BN_IsZero(identityScalar, g_sm9SysPara.wordSize) != 0) {
        ret = CRYPT_SM9_ERR_KEY_ERR;
        goto ERR;
    }
    // Compute t2 = masterPrivateKey*(t1^-1)
    SM9_BN_GetInvMont(identityScalar, identityScalar, g_sm9SysPara.ecN, g_sm9SysPara.nMc, g_sm9SysPara.nR2,
                      g_sm9SysPara.wordSize);
    SM9_BN_MontMul(keyScalar, identityScalar, keyScalar, g_sm9SysPara.ecN, g_sm9SysPara.nMc, g_sm9SysPara.wordSize);
    // Compute userPrivateKey = [t2]P1
    SM9_Ecp_KP(&userPoint, &g_sm9SysPara.ecFpGMont, keyScalar);

    // Convert User PriKey to bytes(in NormMode)
    SM9_EcpA_WriteBytes(userPrivateKey, &userPoint);

    ret = CRYPT_SUCCESS;
ERR:
    BSL_SAL_CleanseData(identityScalar, sizeof(identityScalar));
    BSL_SAL_CleanseData(keyScalar, sizeof(keyScalar));
    BSL_SAL_CleanseData(&userPoint, sizeof(userPoint));
    return ret;
}

int32_t SM9_GenSignUserKey(SM9_Ctx *ctx, const uint8_t *userId, uint32_t userIdLen)
{
    if (ctx == NULL || userId == NULL || userIdLen == 0 || userIdLen > 256) {
        return CRYPT_SM9_ERR_BAD_INPUT;
    }

    if (ctx->hasSigSys == 0) {
        return CRYPT_SM9_ERR_BAD_INPUT;
    }

    memcpy(ctx->userId, userId, userIdLen);
    ctx->userIdLen = userIdLen;

    int32_t ret = SM9_Alg_USKG(userId, userIdLen, ctx->sigMsk, ctx->sigDsk);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ctx->hasSigUsr = 1;

    return CRYPT_SUCCESS;
}

int32_t SM9_SetSignUserKey(SM9_Ctx *ctx, uint8_t *userId, uint32_t userIdLen, uint8_t *userPrivateKey)
{
    if (ctx == NULL || userId == NULL || userIdLen == 0 || userIdLen > 256 || userPrivateKey == NULL) {
        return CRYPT_SM9_ERR_BAD_INPUT;
    }
    int32_t ret = SM9_EcpA_ValidateBytes(userPrivateKey);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    memcpy(ctx->userId, userId, userIdLen);
    ctx->userIdLen = userIdLen;

    memcpy(ctx->sigDsk, userPrivateKey, SM9_SIG_USR_PRIKEY_BYTES);

    ctx->hasSigUsr = 1;

    return CRYPT_SUCCESS;
}

static int32_t SM9_Alg_CheckSignUserKey(const uint8_t *masterPubKey, const uint8_t *userId, uint32_t userIdLen,
                                        const uint8_t *userPrivateKey)
{
    uint32_t h1[SM9_BN_WORDS];
    SM9_EcpA userKey;
    SM9_Ecp2A masterPub;
    SM9_Ecp2A idPoint;
    SM9_Ecp2A userPub;
    SM9_Ecp2J userPubJ;
    int32_t ret = CRYPT_SM9_ERR_BAD_INPUT;

    if (masterPubKey == NULL || userId == NULL || userIdLen == 0 || userIdLen > 256 || userPrivateKey == NULL) {
        return ret;
    }

    SM9_EcpA_ReadBytes(&userKey, userPrivateKey);
    SM9_Ecp2A_ReadBytes(&masterPub, masterPubKey);
    GOTO_ERR_IF_EX(SM9_Hash_H(h1, 0x01, userId, userIdLen, SM9_HID_SIGN, sizeof(SM9_HID_SIGN)), ret);
    SM9_Ecp2_KP(&idPoint, &g_sm9SysPara.ecFp2GMont, h1);
    SM9_Ecp2A_ToJ(&userPubJ, &masterPub);
    SM9_Ecp2J_AddA(&userPubJ, &userPubJ, &idPoint);
    SM9_Ecp2J_ToA(&userPub, &userPubJ);

    ret = SM9_Alg_PairEqual(&userKey, &userPub, &g_sm9SysPara.ecFpGMont, &masterPub);
ERR:
    BSL_SAL_CleanseData(h1, sizeof(h1));
    BSL_SAL_CleanseData(&userKey, sizeof(userKey));
    BSL_SAL_CleanseData(&masterPub, sizeof(masterPub));
    BSL_SAL_CleanseData(&idPoint, sizeof(idPoint));
    BSL_SAL_CleanseData(&userPub, sizeof(userPub));
    BSL_SAL_CleanseData(&userPubJ, sizeof(userPubJ));
    return ret;
}

int32_t SM9_Alg_MSKG(uint8_t *masterPrivateKey, uint8_t *masterPubKey)
{
    uint32_t masterScalar[SM9_BN_WORDS];
    SM9_Ecp2A masterPoint;

    // Read System PriKey to BN
    SM9_BN_ReadBytes(masterScalar, masterPrivateKey);
    // Genarate System PubKey(in APoint MontMode)
    SM9_Ecp2_KP(&masterPoint, &g_sm9SysPara.ecFp2GMont, masterScalar);
    // Convert System PubKey to bytes(in NormMode)
    SM9_Ecp2A_WriteBytes(masterPubKey, &masterPoint);

    return CRYPT_SUCCESS;
}

static int32_t SM9_Alg_SignInner(const uint8_t *msg, uint32_t msgLen, const uint8_t *userPrivateKey,
                                 uint8_t *randomBytes, const uint8_t *precomputedPairing, const uint8_t *masterPubKey,
                                 uint32_t *signatureHash, SM9_EcpA *signaturePoint)
{
    uint32_t nonceScalar[SM9_BN_WORDS];
    uint8_t encodedPairing[12 * SM9_BN_BYTES];
    SM9_Fp12 pairingValue;
    SM9_Ecp2A masterPoint;
    int32_t ret = SM9_EcpA_ValidateBytes(userPrivateKey);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (precomputedPairing == NULL) {
        ret = SM9_Ecp2A_ValidateBytes(masterPubKey);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }

    // Read Random number randomBytes(in NormMode), ensure randomBytes in [1, N-1]
    SM9_BN_ReadBytes(nonceScalar, randomBytes);
    SM9_Fn_LastRes(nonceScalar);
    SM9_BN_AddInt(nonceScalar, nonceScalar, 1, SM9_BN_WORDS);
    SM9_Fn_LastRes(nonceScalar);

    // Get System Element precomputedPairing and compute precomputedPairing^randomBytes
    if (precomputedPairing != NULL) // If precomputedPairing is given
    {
        // Read precomputedPairing from input and convert to MontMode
        SM9_Fp12_ReadBytes(&pairingValue, precomputedPairing);
        // w = precomputedPairing^randomBytes
        SM9_Fp12_Exp(&pairingValue, &pairingValue, nonceScalar);
    } else // If precomputedPairing is not given
    {
        // Read Ppub from input
        SM9_Ecp2A_ReadBytes(&masterPoint, masterPubKey);
        // Compute w = e(randomBytes*P1, Ppub)
        SM9_Ecp_KP(signaturePoint, &g_sm9SysPara.ecFpGMont, nonceScalar);
        SM9_Pairing_RAte(&pairingValue, signaturePoint, &masterPoint);
    }
    SM9_Fp12_WriteBytes(encodedPairing, &pairingValue);

    // h = H2(M||w, N)
    GOTO_ERR_IF_EX(SM9_Hash_H(signatureHash, 0x02, msg, msgLen, encodedPairing, 12 * SM9_BN_BYTES), ret);

    // l = (randomBytes-h) mod N (l should not be zero)
    SM9_Fn_Sub(nonceScalar, nonceScalar, signatureHash);
    if (SM9_BN_IsZero(nonceScalar, g_sm9SysPara.wordSize) != 0) {
        ret = CRYPT_SM9_ERR_SIGN_FAILED;
        goto ERR;
    }
    // Read User Prikey and convert to MontMode
    SM9_EcpA_ReadBytes(signaturePoint, userPrivateKey);
    // S = l * dsA
    SM9_Ecp_KP(signaturePoint, signaturePoint, nonceScalar);

    ret = CRYPT_SUCCESS;
ERR:
    BSL_SAL_CleanseData(nonceScalar, sizeof(nonceScalar));
    BSL_SAL_CleanseData(encodedPairing, sizeof(encodedPairing));
    BSL_SAL_CleanseData(&pairingValue, sizeof(pairingValue));
    return ret;
}

int32_t SM9_Alg_Sign(const uint8_t *msg, uint32_t msgLen, const uint8_t *userPrivateKey, uint8_t *randomBytes,
                     const uint8_t *precomputedPairing, const uint8_t *masterPubKey, uint8_t *signature)
{
    // Signature buf
    uint32_t signatureHash[SM9_BN_WORDS];
    SM9_EcpA signaturePoint;
    int32_t ret;

    ret = SM9_Alg_SignInner(msg, msgLen, userPrivateKey, randomBytes, precomputedPairing, masterPubKey, signatureHash,
                            &signaturePoint);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    // Output Signature to bytes
    SM9_BN_ToByte(signatureHash, SM9_BN_WORDS, signature, NULL);
    SM9_EcpA_WriteBytes(signature + g_sm9SysPara.wordSize * SM9_BN_WORD_BYTES, &signaturePoint);

    return CRYPT_SUCCESS;
}

static int32_t SM9_Alg_VerifyInner(const uint8_t *msg, uint32_t msgLen, const uint8_t *userId, uint32_t userIdLen,
                                   const uint8_t *precomputedPairing, const uint8_t *masterPubKey,
                                   uint32_t *signatureHash, SM9_EcpA *signaturePoint)
{
    SM9_Fp12 pairingValue;
    SM9_Fp12 userPairing;
    uint8_t encodedPairing[12 * SM9_BN_BYTES];

    // uint32_t signatureHash[SM9_BN_WORDS];
    // SM9_EcpA signaturePoint;
    uint32_t calculatedHash[SM9_BN_WORDS];
    SM9_Ecp2A verificationPoint;

    SM9_Ecp2J verificationPointJ;

    SM9_EcpJ combinedPointJ;
    SM9_EcpA combinedPoint;

    int32_t ret;

    // Read System PubKey to JPoint in MontMode
    SM9_Ecp2A_ReadBytes(&verificationPoint, masterPubKey);

    // h1 = H1(IDA||hid, N)
    GOTO_ERR_IF_EX(SM9_Hash_H(calculatedHash, 0x01, userId, userIdLen, SM9_HID_SIGN, 1), ret);

    // Get System Element precomputedPairing and convert to MontMode
    if (precomputedPairing != NULL) {
        // Read from input
        SM9_Fp12_ReadBytes(&pairingValue, precomputedPairing);
        // t = precomputedPairing^h
        SM9_Fp12_Exp(&pairingValue, &pairingValue, signatureHash);

        // P = [h1]P2 + Ppub-s
        SM9_Ecp2A_ToJ(&verificationPointJ, &verificationPoint);
        SM9_Ecp2_KP(&verificationPoint, &g_sm9SysPara.ecFp2GMont, calculatedHash);
        SM9_Ecp2J_AddA(&verificationPointJ, &verificationPointJ, &verificationPoint);
        SM9_Ecp2J_ToA(&verificationPoint, &verificationPointJ);
        // u = e(S', P)
        SM9_Pairing_RAte(&userPairing, signaturePoint, &verificationPoint);
    } else {
        // Compute by input
        // t = e([h]P1 + S, Ppub-s)
        SM9_Ecp_KP(&combinedPoint, &g_sm9SysPara.ecFpGMont, signatureHash);
        SM9_EcpA_ToJ(&combinedPointJ, &combinedPoint);
        SM9_EcpJ_AddA(&combinedPointJ, &combinedPointJ, signaturePoint);
        SM9_EcpJ_ToA(&combinedPoint, &combinedPointJ);
        SM9_Pairing_RAte(&pairingValue, &combinedPoint, &verificationPoint);

        // u = e([h1]S, P2)
        SM9_Ecp_KP(signaturePoint, signaturePoint, calculatedHash);
        SM9_Pairing_RAte(&userPairing, signaturePoint, &g_sm9SysPara.ecFp2GMont);
    }

    // w' = u * t
    SM9_Fp12_Mul(&pairingValue, &pairingValue, &userPairing);
    SM9_Fp12_WriteBytes(encodedPairing, &pairingValue);
    // h2 = H2(M'||w', N)
    GOTO_ERR_IF_EX(SM9_Hash_H(calculatedHash, 0x02, msg, msgLen, encodedPairing, 12 * SM9_BN_BYTES), ret);
    // Verify h2 ?= h
    ret = SM9_BN_Equal(calculatedHash, signatureHash, SM9_BN_WORDS) != 0 ? CRYPT_SUCCESS : CRYPT_SM9_VERIFY_FAIL;
ERR:
    BSL_SAL_CleanseData(encodedPairing, sizeof(encodedPairing));
    BSL_SAL_CleanseData(calculatedHash, sizeof(calculatedHash));
    BSL_SAL_CleanseData(&pairingValue, sizeof(pairingValue));
    BSL_SAL_CleanseData(&userPairing, sizeof(userPairing));
    return ret;
}

static int32_t SM9_Alg_Verify(const uint8_t *msg, uint32_t msgLen, const uint8_t *userId, uint32_t userIdLen,
                              const uint8_t *precomputedPairing, const uint8_t *masterPubKey, const uint8_t *signature)
{
    int32_t ret;
    uint32_t signatureHash[SM9_BN_WORDS];
    uint32_t pointX[SM9_BN_WORDS];
    uint32_t pointY[SM9_BN_WORDS];
    SM9_EcpA signaturePoint;

    // Read Signature(h,s) and convert s to MontMode
    SM9_BN_ReadBytes(signatureHash, signature);
    // h must be in [1, N-1]
    if (SM9_BN_IsZero(signatureHash, g_sm9SysPara.wordSize) != 0 ||
        SM9_BN_Compare(signatureHash, g_sm9SysPara.ecN, g_sm9SysPara.wordSize) >= 0) {
        return CRYPT_SM9_VERIFY_FAIL;
    }
    signature += g_sm9SysPara.wordSize * SM9_BN_WORD_BYTES;
    SM9_BN_ByteToBN(signature, SM9_BN_BYTES, pointX, SM9_BN_WORDS);
    SM9_BN_ByteToBN(signature + SM9_BN_BYTES, SM9_BN_BYTES, pointY, SM9_BN_WORDS);
    if (SM9_BN_Compare(pointX, g_sm9SysPara.ecQ, g_sm9SysPara.wordSize) >= 0 ||
        SM9_BN_Compare(pointY, g_sm9SysPara.ecQ, g_sm9SysPara.wordSize) >= 0) {
        return CRYPT_SM9_VERIFY_FAIL;
    }
    // #E(Fq) = q + 1 - trace = N, so affine on-curve points belong to G1.
    SM9_EcpA_ReadBytes(&signaturePoint, signature);
    if (SM9_EcpA_Check(&signaturePoint) != CRYPT_SUCCESS) {
        return CRYPT_SM9_VERIFY_FAIL;
    }
    if (SM9_Ecp2A_ValidateBytes(masterPubKey) != CRYPT_SUCCESS) {
        return CRYPT_SM9_VERIFY_FAIL;
    }

    ret = SM9_Alg_VerifyInner(msg, msgLen, userId, userIdLen, precomputedPairing, masterPubKey, signatureHash,
                              &signaturePoint);

    return ret;
}

int32_t SM9_CheckSignKeyPair(const CRYPT_SM9_Ctx *masterCtx, const CRYPT_SM9_Ctx *userCtx)
{
    if (userCtx->userIdLen == 0 || userCtx->userIdLen > sizeof(userCtx->userId) ||
        (masterCtx->userIdLen > 0 && (masterCtx->userIdLen != userCtx->userIdLen ||
                                      memcmp(masterCtx->userId, userCtx->userId, userCtx->userIdLen) != 0))) {
        return CRYPT_SM9_PAIRWISE_CHECK_FAIL;
    }
    return SM9_Alg_CheckSignUserKey(masterCtx->sigMpk, userCtx->userId, userCtx->userIdLen, userCtx->sigDsk);
}

int32_t CRYPT_SM9_Sign(const CRYPT_SM9_Ctx *ctx, int32_t mdId, const uint8_t *data, uint32_t dataLen, uint8_t *sign,
                       uint32_t *signLen)
{
    if (ctx == NULL || data == NULL || sign == NULL || signLen == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (*signLen < SM9_SIGNATURE_BYTES) {
        return CRYPT_SM9_BUFF_LEN_NOT_ENOUGH;
    }

    /* SM9 signature always uses SM3, mdId is ignored for compatibility */
    (void)mdId;

    if (ctx->hasSigUsr == 0) {
        return CRYPT_SM9_ERR_SIGN_FAILED;
    }
    uint8_t randBuf[SM9_CURVE_MODULE_BYTES];
    int32_t ret = CRYPT_RandEx(NULL, randBuf, sizeof(randBuf));
    if (ret != CRYPT_SUCCESS) {
        return CRYPT_SM9_ERR_SIGN_FAILED;
    }
    ret = SM9_Alg_Sign(data, dataLen, ctx->sigDsk, randBuf, ctx->hasSigG != 0 ? ctx->sigG : NULL,
                       ctx->hasSigSys != 0 ? ctx->sigMpk : NULL, sign);
    BSL_SAL_CleanseData(randBuf, sizeof(randBuf));
    if (ret != CRYPT_SUCCESS) {
        return CRYPT_SM9_ERR_SIGN_FAILED;
    }

    /* SM9 signature length is fixed */
    *signLen = SM9_SIGNATURE_BYTES;

    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM9_Verify(const CRYPT_SM9_Ctx *ctx, int32_t mdId, const uint8_t *data, uint32_t dataLen,
                         const uint8_t *sign, uint32_t signLen)
{
    if (ctx == NULL || data == NULL || sign == NULL) {
        return CRYPT_NULL_INPUT;
    }

    /* SM9 signature always uses SM3, mdId is ignored */
    (void)mdId;

    if (signLen != SM9_SIGNATURE_BYTES) {
        return CRYPT_SM9_ERR_INVALID_SIGNATURE_LEN;
    }

    /* SM9 verify needs user ID - must be stored in context */
    if (ctx->userIdLen == 0) {
        return CRYPT_SM9_ERR_NO_USER_ID;
    }

    if (ctx->hasSigSys == 0) {
        return CRYPT_SM9_VERIFY_FAIL;
    }
    int32_t ret = SM9_Alg_Verify(data, dataLen, ctx->userId, ctx->userIdLen, ctx->hasSigG != 0 ? ctx->sigG : NULL,
        ctx->sigMpk, sign);
    if (ret != CRYPT_SUCCESS) {
        return CRYPT_SM9_VERIFY_FAIL;
    }

    return CRYPT_SUCCESS;
}

#endif // HITLS_CRYPTO_SM9
