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

/* BEGIN_HEADER */
#include <stdint.h>
#include "otp.h"
#include "auth_otp.h"
#include "auth_errno.h"
#include "auth_params.h"
#include "crypt_util_rand.h"
#include "crypt_eal_rand.h"
#include "crypt_errno.h"

/* END_HEADER */

/**
 * @test SDV_AUTH_OTP_INIT_API_TC001
 * @spec OTP Context
 * @title Impact of key validity on initialization Test
 */
/* BEGIN_CASE */
void SDV_AUTH_OTP_INIT_API_TC001(int protocolType, Hex *key)
{
    HITLS_AUTH_OtpCtx *ctx = HITLS_AUTH_OtpNewCtx(protocolType);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(HITLS_AUTH_OtpInit(NULL, key->x, key->len) != HITLS_AUTH_SUCCESS);
    ASSERT_TRUE(HITLS_AUTH_OtpInit(ctx, NULL, 0) != HITLS_AUTH_SUCCESS);
    ASSERT_TRUE(HITLS_AUTH_OtpInit(ctx, NULL, 20) != HITLS_AUTH_SUCCESS); // 20: a common SHA1-HMAC key length
    TestRandInit();
    ASSERT_TRUE(HITLS_AUTH_OtpInit(ctx, NULL, 20) == HITLS_AUTH_SUCCESS); // 20: a common SHA1-HMAC key length
    ASSERT_TRUE(HITLS_AUTH_OtpInit(ctx, key->x, 0) != HITLS_AUTH_SUCCESS);
    ASSERT_TRUE(HITLS_AUTH_OtpInit(ctx, key->x, key->len) == HITLS_AUTH_SUCCESS);
EXIT:
    HITLS_AUTH_OtpFreeCtx(ctx);
    TestRandDeInit();
}
/* END_CASE */

int32_t OtpHmacTmp(void *libCtx, const char *attrName, int32_t algId, const uint8_t *key, uint32_t keyLen,
                   const uint8_t *input, uint32_t inputLen, uint8_t *hmac, uint32_t *hmacLen)
{
    (void)libCtx;
    (void)attrName;
    (void)algId;
    (void)key;
    (void)keyLen;
    (void)input;
    (void)inputLen;
    for (uint32_t i = 0; i < *hmacLen; i++) {
        hmac[i] = i % 0xff;
    }
    return 0;
}

int32_t OtpRandomTmp(uint8_t *buffer, uint32_t bufferLen)
{
    for (uint32_t i = 0; i < bufferLen; i++) {
        buffer[i] = i % 0xff;
    }
    return 0;
}

/**
 * @test SDV_AUTH_OTP_SET_CRYPTO_CB_API_TC001
 * @spec OTP Context
 * @title Test setting and validating crypto callback functionality
 */
/* BEGIN_CASE */
void SDV_AUTH_OTP_SET_CRYPTO_CB_API_TC001(int protocolType)
{
    HITLS_AUTH_OtpCtx *ctx = HITLS_AUTH_OtpNewCtx(protocolType);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(HITLS_AUTH_OtpSetCryptCb(ctx, HITLS_AUTH_OTP_RANDOM_CB - 1, OtpRandomTmp),
              HITLS_AUTH_OTP_INVALID_CRYPTO_CALLBACK_TYPE);

    ASSERT_EQ(HITLS_AUTH_OtpSetCryptCb(ctx, HITLS_AUTH_OTP_RANDOM_CB, OtpRandomTmp), HITLS_AUTH_SUCCESS);
    uint8_t random[4] = {0};
    uint8_t randomTarget[4] = {0x00, 0x01, 0x02, 0x03};
    ASSERT_EQ(ctx->method.random(random, sizeof(random)), 0);
    ASSERT_COMPARE("compare random bytes", random, sizeof(random), randomTarget, sizeof(randomTarget));

    ASSERT_EQ(HITLS_AUTH_OtpSetCryptCb(ctx, HITLS_AUTH_OTP_HMAC_CB, OtpHmacTmp), HITLS_AUTH_SUCCESS);
    uint8_t hmac[4] = {0};
    uint8_t hmacTarget[4] = {0x00, 0x01, 0x02, 0x03};
    uint32_t hmacLen = sizeof(hmac);
    ASSERT_EQ(ctx->method.hmac(NULL, NULL, 0, NULL, 0, NULL, 0, hmac, &hmacLen), 0);
    ASSERT_COMPARE("compare hmac bytes", hmac, sizeof(hmac), hmacTarget, sizeof(hmacTarget));

EXIT:
    HITLS_AUTH_OtpFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test SDV_AUTH_OTP_CTX_CTRL_API_TC001
 * @spec OTP Context
 * @title Test control OTP context
 */
/* BEGIN_CASE */
void SDV_AUTH_OTP_CTX_CTRL_API_TC001(int protocolType)
{
    HITLS_AUTH_OtpCtx *ctx = HITLS_AUTH_OtpNewCtx(protocolType);
    ASSERT_TRUE(ctx != NULL);
    uint8_t key20[] = "12345678901234567890";
    ASSERT_EQ(HITLS_AUTH_OtpInit(ctx, key20, sizeof(key20)), HITLS_AUTH_SUCCESS);

    HITLS_AUTH_OtpType protocolTypeGot;
    uint8_t keyGot[sizeof(key20)];
    uint32_t digitsGot;
    HITLS_AUTH_OtpCryptAlgId algIdGot;

    /* Get default value. */
    BSL_Param paramGet[] = {
        {AUTH_PARAM_OTP_CTX_PROTOCOLTYPE, BSL_PARAM_TYPE_OCTETS, &protocolTypeGot, sizeof(protocolTypeGot),
         sizeof(protocolTypeGot)},
        {AUTH_PARAM_OTP_CTX_KEY, BSL_PARAM_TYPE_OCTETS_PTR, &keyGot, sizeof(keyGot), sizeof(keyGot)},
        {AUTH_PARAM_OTP_CTX_DIGITS, BSL_PARAM_TYPE_UINT32, &digitsGot, sizeof(digitsGot), sizeof(digitsGot)},
        {AUTH_PARAM_OTP_CTX_HASHALGID, BSL_PARAM_TYPE_OCTETS, &algIdGot, sizeof(algIdGot), sizeof(algIdGot)},
        BSL_PARAM_END};
    ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_GET_CTX_PROTOCOLTYPE, paramGet, 0), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_GET_CTX_KEY, paramGet, 0), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_GET_CTX_DIGITS, paramGet, 0), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_GET_CTX_HASHALGID, paramGet, 0), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(protocolTypeGot, protocolType);
    ASSERT_COMPARE("compare key bytes", keyGot, sizeof(keyGot), key20, sizeof(key20));
    ASSERT_EQ(digitsGot, OTP_DEFAULT_DIGITS);
    ASSERT_EQ(algIdGot, HITLS_AUTH_OTP_CRYPTO_SHA1);

    /* Set valid value. */
    uint32_t digitsSet = 8;
    HITLS_AUTH_OtpCryptAlgId algIdSet = HITLS_AUTH_OTP_CRYPTO_SHA512;
    BSL_Param paramSet[] = {
        {AUTH_PARAM_OTP_CTX_DIGITS, BSL_PARAM_TYPE_UINT32, &digitsSet, sizeof(digitsSet), sizeof(digitsSet)},
        {AUTH_PARAM_OTP_CTX_HASHALGID, BSL_PARAM_TYPE_OCTETS, &algIdSet, sizeof(algIdSet), sizeof(algIdSet)},
        BSL_PARAM_END};
    ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_SET_CTX_DIGITS, paramSet, 0), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_SET_CTX_HASHALGID, paramSet, 0), HITLS_AUTH_SUCCESS);

    /* Get modified value. */
    ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_GET_CTX_DIGITS, paramGet, 0), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_GET_CTX_HASHALGID, paramGet, 0), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(digitsGot, digitsSet);
    ASSERT_EQ(algIdGot, algIdSet);

    if (protocolType == HITLS_AUTH_OTP_TOTP) {
        /* Get default value. */
        uint32_t timeStepSizeGot;
        BslUnixTime startOffsetGot;
        uint32_t validWindowGot;
        BSL_Param paramGetTotp[] = {{AUTH_PARAM_OTP_CTX_TOTP_TIMESTEPSIZE, BSL_PARAM_TYPE_UINT32, &timeStepSizeGot,
                                     sizeof(timeStepSizeGot), sizeof(timeStepSizeGot)},
                                    {AUTH_PARAM_OTP_CTX_TOTP_STARTOFFSET, BSL_PARAM_TYPE_OCTETS, &startOffsetGot,
                                     sizeof(startOffsetGot), sizeof(startOffsetGot)},
                                    {AUTH_PARAM_OTP_CTX_TOTP_VALIDWINDOW, BSL_PARAM_TYPE_UINT32, &validWindowGot,
                                     sizeof(validWindowGot), sizeof(validWindowGot)},
                                    BSL_PARAM_END};
        ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_GET_CTX_TOTP_TIMESTEPSIZE, paramGetTotp, 0),
                  HITLS_AUTH_SUCCESS);
        ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_GET_CTX_TOTP_STARTOFFSET, paramGetTotp, 0),
                  HITLS_AUTH_SUCCESS);
        ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_GET_CTX_TOTP_VALIDWINDOW, paramGetTotp, 0),
                  HITLS_AUTH_SUCCESS);
        ASSERT_EQ(timeStepSizeGot, OTP_TOTP_DEFAULT_TIME_STEP_SIZE);
        ASSERT_EQ(startOffsetGot, OTP_TOTP_DEFAULT_START_OFFSET);
        ASSERT_EQ(validWindowGot, OTP_TOTP_DEFAULT_VALID_WINDOW);

        /* Set valid value. */
        uint32_t timeStepSizeSet = 60;
        BslUnixTime startOffsetSet = 985626547;
        uint32_t validWindowSet = 0;
        BSL_Param paramSetTotp[] = {{AUTH_PARAM_OTP_CTX_TOTP_TIMESTEPSIZE, BSL_PARAM_TYPE_UINT32, &timeStepSizeSet,
                                     sizeof(timeStepSizeSet), sizeof(timeStepSizeSet)},
                                    {AUTH_PARAM_OTP_CTX_TOTP_STARTOFFSET, BSL_PARAM_TYPE_OCTETS, &startOffsetSet,
                                     sizeof(startOffsetSet), sizeof(startOffsetSet)},
                                    {AUTH_PARAM_OTP_CTX_TOTP_VALIDWINDOW, BSL_PARAM_TYPE_UINT32, &validWindowSet,
                                     sizeof(validWindowSet), sizeof(validWindowSet)},
                                    BSL_PARAM_END};
        ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_SET_CTX_TOTP_TIMESTEPSIZE, paramSetTotp, 0),
                  HITLS_AUTH_SUCCESS);
        ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_SET_CTX_TOTP_STARTOFFSET, paramSetTotp, 0),
                  HITLS_AUTH_SUCCESS);
        ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_SET_CTX_TOTP_VALIDWINDOW, paramSetTotp, 0),
                  HITLS_AUTH_SUCCESS);

        /* Get modified value. */
        ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_GET_CTX_TOTP_TIMESTEPSIZE, paramGetTotp, 0),
                  HITLS_AUTH_SUCCESS);
        ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_GET_CTX_TOTP_STARTOFFSET, paramGetTotp, 0),
                  HITLS_AUTH_SUCCESS);
        ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_GET_CTX_TOTP_VALIDWINDOW, paramGetTotp, 0),
                  HITLS_AUTH_SUCCESS);
        ASSERT_EQ(timeStepSizeGot, timeStepSizeSet);
        ASSERT_EQ(startOffsetGot, startOffsetSet);
        ASSERT_EQ(validWindowGot, validWindowSet);
    }

EXIT:
    HITLS_AUTH_OtpFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test SDV_AUTH_OTP_CTX_CTRL_API_TC001
 * @spec OTP Context
 * @title Test control OTP context
 */
/* BEGIN_CASE */
void SDV_AUTH_OTP_CTX_CTRL_API_TC002(int protocolType)
{
    HITLS_AUTH_OtpCtx *ctx = HITLS_AUTH_OtpNewCtx(protocolType);
    ASSERT_TRUE(ctx != NULL);
    uint8_t key20[] = "12345678901234567890";
    ASSERT_EQ(HITLS_AUTH_OtpInit(ctx, key20, sizeof(key20)), HITLS_AUTH_SUCCESS);

    /* Set invalid value. */
    uint32_t digitsSet = OTP_MAX_DIGITS + 1;
    HITLS_AUTH_OtpCryptAlgId algIdSet = HITLS_AUTH_OTP_CRYPTO_SHA512 + 100;
    BSL_Param paramSet[] = {
        {AUTH_PARAM_OTP_CTX_DIGITS, BSL_PARAM_TYPE_UINT32, &digitsSet, sizeof(digitsSet), sizeof(digitsSet)},
        {AUTH_PARAM_OTP_CTX_HASHALGID, BSL_PARAM_TYPE_OCTETS, &algIdSet, sizeof(algIdSet), sizeof(algIdSet)},
        BSL_PARAM_END};
    ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_SET_CTX_DIGITS, paramSet, 0), HITLS_AUTH_OTP_INVALID_INPUT);
    ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_SET_CTX_HASHALGID, paramSet, 0), HITLS_AUTH_OTP_INVALID_INPUT);

    if (protocolType == HITLS_AUTH_OTP_TOTP) {
        /* Set invalid value. */
        uint32_t timeStepSizeSet = 0;
        BSL_Param paramSetTotp[] = {{AUTH_PARAM_OTP_CTX_TOTP_TIMESTEPSIZE, BSL_PARAM_TYPE_UINT32, &timeStepSizeSet,
                                     sizeof(timeStepSizeSet), sizeof(timeStepSizeSet)},
                                    BSL_PARAM_END};
        ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_SET_CTX_TOTP_TIMESTEPSIZE, paramSetTotp, 0),
                  HITLS_AUTH_OTP_INVALID_INPUT);
    }

EXIT:
    HITLS_AUTH_OtpFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test SDV_AUTH_OTP_GEN_HOTP_API_TC001
 * @spec OTP Generation Process
 * @title Test HOTP generation process
 */
/* BEGIN_CASE */
void SDV_AUTH_OTP_GEN_HOTP_API_TC001(int counter, Hex *key, int digits, int algId, char *expectRes)
{
    HITLS_AUTH_OtpCtx *ctx = HITLS_AUTH_OtpNewCtx(HITLS_AUTH_OTP_HOTP);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_AUTH_OtpInit(ctx, key->x, key->len), HITLS_AUTH_SUCCESS);

    char otp[10];
    uint32_t otpLen = sizeof(otp);
    ASSERT_TRUE(counter >= 0);
    uint64_t counter64 = (uint64_t)counter;

    BSL_Param paramSet[] = {{AUTH_PARAM_OTP_CTX_DIGITS, BSL_PARAM_TYPE_UINT32, &digits, sizeof(digits), sizeof(digits)},
                            {AUTH_PARAM_OTP_CTX_HASHALGID, BSL_PARAM_TYPE_OCTETS, &algId, sizeof(algId), sizeof(algId)},
                            BSL_PARAM_END};
    ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_SET_CTX_DIGITS, paramSet, 0), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_SET_CTX_HASHALGID, paramSet, 0), HITLS_AUTH_SUCCESS);

    BSL_Param paramGen[] = {
        {AUTH_PARAM_OTP_HOTP_COUNTER, BSL_PARAM_TYPE_OCTETS, &counter64, sizeof(counter64), sizeof(counter64)},
        BSL_PARAM_END};
    ASSERT_EQ(HITLS_AUTH_OtpGen(ctx, paramGen, otp, &otpLen), HITLS_AUTH_SUCCESS);
    ASSERT_COMPARE("compare hotp bytes", otp, otpLen, expectRes, strlen(expectRes));

EXIT:
    HITLS_AUTH_OtpFreeCtx(ctx);
}
/* END_CASE */

BslUnixTime hexToBslUnixTime(uint8_t *hex, uint32_t hexLen)
{
    BslUnixTime res = 0;
    for (uint32_t i = 0; i < hexLen; i++) {
        res += hex[i];
        if (i != hexLen - 1) {
            res <<= 8; // 8: indicates the number of bits in a byte.
        }
    }
    return res;
}

/**
 * @test SDV_AUTH_OTP_GEN_TOTP_API_TC001
 * @spec OTP Generation Process
 * @title Test TOTP generation process
 */
/* BEGIN_CASE */
void SDV_AUTH_OTP_GEN_TOTP_API_TC001(Hex *curTime, Hex *key, int digits, int algId, char *expectRes)
{
    HITLS_AUTH_OtpCtx *ctx = HITLS_AUTH_OtpNewCtx(HITLS_AUTH_OTP_TOTP);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_AUTH_OtpInit(ctx, key->x, key->len), HITLS_AUTH_SUCCESS);

    char otp[10];
    uint32_t otpLen = sizeof(otp);
    ASSERT_TRUE(curTime->len <= sizeof(BslUnixTime));
    BslUnixTime curTime64 = hexToBslUnixTime(curTime->x, curTime->len);

    BSL_Param paramSet[] = {{AUTH_PARAM_OTP_CTX_DIGITS, BSL_PARAM_TYPE_UINT32, &digits, sizeof(digits), sizeof(digits)},
                            {AUTH_PARAM_OTP_CTX_HASHALGID, BSL_PARAM_TYPE_OCTETS, &algId, sizeof(algId), sizeof(algId)},
                            BSL_PARAM_END};
    ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_SET_CTX_DIGITS, paramSet, 0), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_SET_CTX_HASHALGID, paramSet, 0), HITLS_AUTH_SUCCESS);

    BSL_Param paramGen[] = {
        {AUTH_PARAM_OTP_TOTP_CURTIME, BSL_PARAM_TYPE_OCTETS, &curTime64, sizeof(curTime64), sizeof(curTime64)},
        BSL_PARAM_END};
    ASSERT_EQ(HITLS_AUTH_OtpGen(ctx, paramGen, otp, &otpLen), HITLS_AUTH_SUCCESS);
    ASSERT_COMPARE("compare totp bytes", otp, otpLen, expectRes, strlen(expectRes));

EXIT:
    HITLS_AUTH_OtpFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test SDV_AUTH_OTP_GEN_TOTP_API_TC002
 * @spec OTP Generation Process
 * @title Test TOTP generation process
 */
/* BEGIN_CASE */
void SDV_AUTH_OTP_GEN_TOTP_API_TC002(Hex *curTime, Hex *key, int digits, int algId, Hex *startOffset, int timeStepSize,
                                     char *expectRes)
{
    HITLS_AUTH_OtpCtx *ctx = HITLS_AUTH_OtpNewCtx(HITLS_AUTH_OTP_TOTP);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_AUTH_OtpInit(ctx, key->x, key->len), HITLS_AUTH_SUCCESS);

    char otp[10];
    uint32_t otpLen = sizeof(otp);
    ASSERT_TRUE(curTime->len <= sizeof(BslUnixTime));
    BslUnixTime curTime64 = hexToBslUnixTime(curTime->x, curTime->len);
    ASSERT_TRUE(startOffset->len <= sizeof(BslUnixTime));
    BslUnixTime startOffset64 = hexToBslUnixTime(startOffset->x, startOffset->len);
    uint32_t timeStepSize32 = timeStepSize;

    BSL_Param paramSet[] = {{AUTH_PARAM_OTP_CTX_DIGITS, BSL_PARAM_TYPE_UINT32, &digits, sizeof(digits), sizeof(digits)},
                            {AUTH_PARAM_OTP_CTX_HASHALGID, BSL_PARAM_TYPE_OCTETS, &algId, sizeof(algId), sizeof(algId)},
                            {AUTH_PARAM_OTP_CTX_TOTP_STARTOFFSET, BSL_PARAM_TYPE_OCTETS, &startOffset64,
                             sizeof(startOffset64), sizeof(startOffset64)},
                            {AUTH_PARAM_OTP_CTX_TOTP_TIMESTEPSIZE, BSL_PARAM_TYPE_UINT32, &timeStepSize32,
                             sizeof(timeStepSize32), sizeof(timeStepSize32)},
                            BSL_PARAM_END};
    ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_SET_CTX_DIGITS, paramSet, 0), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_SET_CTX_HASHALGID, paramSet, 0), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_SET_CTX_TOTP_STARTOFFSET, paramSet, 0), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_SET_CTX_TOTP_TIMESTEPSIZE, paramSet, 0), HITLS_AUTH_SUCCESS);

    BSL_Param paramGen[] = {
        {AUTH_PARAM_OTP_TOTP_CURTIME, BSL_PARAM_TYPE_OCTETS, &curTime64, sizeof(curTime64), sizeof(curTime64)},
        BSL_PARAM_END};
    ASSERT_EQ(HITLS_AUTH_OtpGen(ctx, paramGen, otp, &otpLen), HITLS_AUTH_SUCCESS);
    ASSERT_COMPARE("compare totp bytes", otp, otpLen, expectRes, strlen(expectRes));

EXIT:
    HITLS_AUTH_OtpFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test SDV_AUTH_OTP_VALIDATE_HOTP_API_TC001
 * @spec OTP Validation Process
 * @title Test HOTP validation process
 */
/* BEGIN_CASE */
void SDV_AUTH_OTP_VALIDATE_HOTP_API_TC001(int counter, Hex *key, int digits, int algId, char *otp, int expectRes)
{
    HITLS_AUTH_OtpCtx *ctx = HITLS_AUTH_OtpNewCtx(HITLS_AUTH_OTP_HOTP);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_AUTH_OtpInit(ctx, key->x, key->len), HITLS_AUTH_SUCCESS);

    ASSERT_TRUE(counter >= 0);
    uint64_t counter64 = (uint64_t)counter;

    BSL_Param paramSet[] = {{AUTH_PARAM_OTP_CTX_DIGITS, BSL_PARAM_TYPE_UINT32, &digits, sizeof(digits), sizeof(digits)},
                            {AUTH_PARAM_OTP_CTX_HASHALGID, BSL_PARAM_TYPE_OCTETS, &algId, sizeof(algId), sizeof(algId)},
                            BSL_PARAM_END};
    ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_SET_CTX_DIGITS, paramSet, 0), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_SET_CTX_HASHALGID, paramSet, 0), HITLS_AUTH_SUCCESS);

    uint64_t matched;
    BSL_Param paramValidate[] = {
        {AUTH_PARAM_OTP_HOTP_COUNTER, BSL_PARAM_TYPE_OCTETS, &counter64, sizeof(counter64), sizeof(counter64)},
        BSL_PARAM_END};
    ASSERT_EQ(HITLS_AUTH_OtpValidate(ctx, paramValidate, otp, strlen(otp), &matched), expectRes);
    if (expectRes == HITLS_AUTH_SUCCESS) {
        ASSERT_EQ(matched, counter64);
    }

EXIT:
    HITLS_AUTH_OtpFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test SDV_AUTH_OTP_VALIDATE_TOTP_API_TC001
 * @spec OTP Validation Process
 * @title Test TOTP validation process
 */
/* BEGIN_CASE */
void SDV_AUTH_OTP_VALIDATE_TOTP_API_TC001(Hex *curTime, Hex *key, int digits, int algId, char *otp, int expectRes)
{
    HITLS_AUTH_OtpCtx *ctx = HITLS_AUTH_OtpNewCtx(HITLS_AUTH_OTP_TOTP);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_AUTH_OtpInit(ctx, key->x, key->len), HITLS_AUTH_SUCCESS);

    ASSERT_TRUE(curTime->len <= sizeof(BslUnixTime));
    BslUnixTime curTime64 = hexToBslUnixTime(curTime->x, curTime->len);

    BSL_Param paramSet[] = {{AUTH_PARAM_OTP_CTX_DIGITS, BSL_PARAM_TYPE_UINT32, &digits, sizeof(digits), sizeof(digits)},
                            {AUTH_PARAM_OTP_CTX_HASHALGID, BSL_PARAM_TYPE_OCTETS, &algId, sizeof(algId), sizeof(algId)},
                            BSL_PARAM_END};
    ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_SET_CTX_DIGITS, paramSet, 0), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_SET_CTX_HASHALGID, paramSet, 0), HITLS_AUTH_SUCCESS);

    uint64_t matched;
    BSL_Param paramValidate[] = {
        {AUTH_PARAM_OTP_TOTP_CURTIME, BSL_PARAM_TYPE_OCTETS, &curTime64, sizeof(curTime64), sizeof(curTime64)},
        BSL_PARAM_END};
    ASSERT_EQ(HITLS_AUTH_OtpValidate(ctx, paramValidate, otp, strlen(otp), &matched), expectRes);
    if (expectRes == HITLS_AUTH_SUCCESS) {
        uint64_t movingFactor = (curTime64 - OTP_TOTP_DEFAULT_START_OFFSET) / OTP_TOTP_DEFAULT_TIME_STEP_SIZE;
        ASSERT_TRUE(matched >= movingFactor - OTP_TOTP_DEFAULT_VALID_WINDOW);
        ASSERT_TRUE(matched <= movingFactor + OTP_TOTP_DEFAULT_VALID_WINDOW);
    }

EXIT:
    HITLS_AUTH_OtpFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test SDV_AUTH_OTP_VALIDATE_TOTP_API_TC002
 * @spec OTP Validation Process
 * @title Test TOTP validation process
 */
/* BEGIN_CASE */
void SDV_AUTH_OTP_VALIDATE_TOTP_API_TC002(Hex *curTime, Hex *key, int digits, int algId, Hex *startOffset,
                                          int timeStepSize, int validWindow, char *otp, int expectRes)
{
    HITLS_AUTH_OtpCtx *ctx = HITLS_AUTH_OtpNewCtx(HITLS_AUTH_OTP_TOTP);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_AUTH_OtpInit(ctx, key->x, key->len), HITLS_AUTH_SUCCESS);

    ASSERT_TRUE(curTime->len <= sizeof(BslUnixTime));
    BslUnixTime curTime64 = hexToBslUnixTime(curTime->x, curTime->len);
    ASSERT_TRUE(startOffset->len <= sizeof(BslUnixTime));
    BslUnixTime startOffset64 = hexToBslUnixTime(startOffset->x, startOffset->len);
    uint32_t timeStepSize32 = timeStepSize;
    uint32_t validWindow32 = validWindow;

    BSL_Param paramSet[] = {{AUTH_PARAM_OTP_CTX_DIGITS, BSL_PARAM_TYPE_UINT32, &digits, sizeof(digits), sizeof(digits)},
                            {AUTH_PARAM_OTP_CTX_HASHALGID, BSL_PARAM_TYPE_OCTETS, &algId, sizeof(algId), sizeof(algId)},
                            {AUTH_PARAM_OTP_CTX_TOTP_STARTOFFSET, BSL_PARAM_TYPE_OCTETS, &startOffset64,
                             sizeof(startOffset64), sizeof(startOffset64)},
                            {AUTH_PARAM_OTP_CTX_TOTP_TIMESTEPSIZE, BSL_PARAM_TYPE_UINT32, &timeStepSize32,
                             sizeof(timeStepSize32), sizeof(timeStepSize32)},
                            {AUTH_PARAM_OTP_CTX_TOTP_VALIDWINDOW, BSL_PARAM_TYPE_UINT32, &validWindow32,
                             sizeof(validWindow32), sizeof(validWindow32)},
                            BSL_PARAM_END};
    ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_SET_CTX_DIGITS, paramSet, 0), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_SET_CTX_HASHALGID, paramSet, 0), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_SET_CTX_TOTP_STARTOFFSET, paramSet, 0), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_SET_CTX_TOTP_TIMESTEPSIZE, paramSet, 0), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_SET_CTX_TOTP_VALIDWINDOW, paramSet, 0), HITLS_AUTH_SUCCESS);

    uint64_t matched;
    BSL_Param paramValidate[] = {
        {AUTH_PARAM_OTP_TOTP_CURTIME, BSL_PARAM_TYPE_OCTETS, &curTime64, sizeof(curTime64), sizeof(curTime64)},
        BSL_PARAM_END};
    ASSERT_EQ(HITLS_AUTH_OtpValidate(ctx, paramValidate, otp, strlen(otp), &matched), expectRes);
    if (expectRes == HITLS_AUTH_SUCCESS) {
        uint64_t movingFactor = (curTime64 - startOffset64) / timeStepSize32;
        ASSERT_TRUE(matched >= movingFactor - validWindow32);
        ASSERT_TRUE(matched <= movingFactor + validWindow32);
    }

EXIT:
    HITLS_AUTH_OtpFreeCtx(ctx);
}
/* END_CASE */
