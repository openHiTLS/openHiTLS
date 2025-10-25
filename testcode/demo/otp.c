#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <inttypes.h>
#include <string.h>
#include "auth_otp.h"
#include "auth_params.h"
#include "bsl_sal.h"
#include "bsl_err.h"
#include "crypt_eal_init.h"
#include "crypt_eal_rand.h"
#include "auth_errno.h"
#include "crypt_errno.h"
#include "securec.h"

void *StdMalloc(uint32_t len)
{
    return malloc((size_t)len);
}

void PrintLastError(void)
{
    const char *file = NULL;
    uint32_t line = 0;
    BSL_ERR_GetLastErrorFileLine(&file, &line);
    printf("failed at file %s at line %d\n", file, line);
}

void PrintPlainHex(const uint8_t *data, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

int32_t setHotpCtx(HITLS_AUTH_OtpCtx *ctx, uint8_t *key, uint32_t keyLen, uint32_t digits)
{
    int32_t ret = HITLS_AUTH_OtpInit(ctx, key, keyLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        return ret;
    }

    BSL_Param param[] = {{AUTH_PARAM_OTP_CTX_DIGITS, BSL_PARAM_TYPE_UINT32, &digits, sizeof(digits), sizeof(digits)},
                         BSL_PARAM_END};
    return HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_SET_CTX_DIGITS, param, 0);
}

int32_t genHotp(HITLS_AUTH_OtpCtx *ctx, uint64_t counter, char *otp, uint32_t *otpLen)
{
    BSL_Param param[] = {
        {AUTH_PARAM_OTP_HOTP_COUNTER, BSL_PARAM_TYPE_OCTETS, &counter, sizeof(counter), sizeof(counter)},
        BSL_PARAM_END};
    return HITLS_AUTH_OtpGen(ctx, param, otp, otpLen);
}

int32_t validateHotp(HITLS_AUTH_OtpCtx *ctx, uint64_t counter, char *otp, uint32_t otpLen)
{
    BSL_Param param[] = {
        {AUTH_PARAM_OTP_HOTP_COUNTER, BSL_PARAM_TYPE_OCTETS, &counter, sizeof(counter), sizeof(counter)},
        BSL_PARAM_END};
    return HITLS_AUTH_OtpValidate(ctx, param, otp, otpLen, NULL);
}

int32_t setTotpCtx(HITLS_AUTH_OtpCtx *ctx, uint8_t *key, uint32_t keyLen, uint32_t digits,
                   HITLS_AUTH_OtpCryptAlgId hashAlgId, uint32_t timeStepSize, BslUnixTime startOffset,
                   uint32_t validWindow)
{
    int32_t ret = HITLS_AUTH_OtpInit(ctx, key, keyLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        return ret;
    }

    BSL_Param param[] = {
        {AUTH_PARAM_OTP_CTX_DIGITS, BSL_PARAM_TYPE_UINT32, &digits, sizeof(digits), sizeof(digits)},
        {AUTH_PARAM_OTP_CTX_HASHALGID, BSL_PARAM_TYPE_OCTETS, &hashAlgId, sizeof(hashAlgId), sizeof(hashAlgId)},
        {AUTH_PARAM_OTP_CTX_TOTP_TIMESTEPSIZE, BSL_PARAM_TYPE_UINT32, &timeStepSize, sizeof(timeStepSize),
         sizeof(timeStepSize)},
        {AUTH_PARAM_OTP_CTX_TOTP_STARTOFFSET, BSL_PARAM_TYPE_OCTETS, &startOffset, sizeof(startOffset),
         sizeof(startOffset)},
        {AUTH_PARAM_OTP_CTX_TOTP_VALIDWINDOW, BSL_PARAM_TYPE_UINT32, &validWindow, sizeof(validWindow),
         sizeof(validWindow)},
        BSL_PARAM_END};
    if ((ret = HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_SET_CTX_DIGITS, param, 0)) != HITLS_AUTH_SUCCESS ||
        (ret = HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_SET_CTX_HASHALGID, param, 0)) != HITLS_AUTH_SUCCESS ||
        (ret = HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_SET_CTX_TOTP_TIMESTEPSIZE, param, 0)) != HITLS_AUTH_SUCCESS ||
        (ret = HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_SET_CTX_TOTP_STARTOFFSET, param, 0)) != HITLS_AUTH_SUCCESS ||
        (ret = HITLS_AUTH_OtpCtxCtrl(ctx, HITLS_AUTH_OTP_SET_CTX_TOTP_VALIDWINDOW, param, 0)) != HITLS_AUTH_SUCCESS) {
        return ret;
    }
    return HITLS_AUTH_SUCCESS;
}

int32_t genTotp(HITLS_AUTH_OtpCtx *ctx, BslUnixTime curTime, char *otp, uint32_t *otpLen)
{
    BSL_Param param[] = {
        {AUTH_PARAM_OTP_TOTP_CURTIME, BSL_PARAM_TYPE_OCTETS, &curTime, sizeof(curTime), sizeof(curTime)},
        BSL_PARAM_END};
    return HITLS_AUTH_OtpGen(ctx, param, otp, otpLen);
}

int32_t validateTotp(HITLS_AUTH_OtpCtx *ctx, BslUnixTime curTime, char *otp, uint32_t otpLen)
{
    BSL_Param param[] = {
        {AUTH_PARAM_OTP_TOTP_CURTIME, BSL_PARAM_TYPE_OCTETS, &curTime, sizeof(curTime), sizeof(curTime)},
        BSL_PARAM_END};
    return HITLS_AUTH_OtpValidate(ctx, param, otp, otpLen, NULL);
}

int main()
{
    BSL_ERR_Init(); // Initialize error code module
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, StdMalloc); // Register memory allocation function
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE, free); // Register memory free function
    int32_t ret = 1;

    uint8_t key20[] = "12345678901234567890";
    uint8_t key32[] = "12345678901234567890123456789012";
    uint8_t key64[] = "1234567890123456789012345678901234567890123456789012345678901234";

    char otp[10] = {0};
    uint32_t otpLen = sizeof(otp);

    HITLS_AUTH_OtpCtx *hotpCtx = HITLS_AUTH_OtpNewCtx(HITLS_AUTH_OTP_HOTP);
    HITLS_AUTH_OtpCtx *totpCtxSHA1 = HITLS_AUTH_OtpNewCtx(HITLS_AUTH_OTP_TOTP);
    HITLS_AUTH_OtpCtx *totpCtxSHA256 = HITLS_AUTH_OtpNewCtx(HITLS_AUTH_OTP_TOTP);
    HITLS_AUTH_OtpCtx *totpCtxSHA512 = HITLS_AUTH_OtpNewCtx(HITLS_AUTH_OTP_TOTP);
    HITLS_AUTH_OtpCtx *hotpCtxRand = HITLS_AUTH_OtpNewCtx(HITLS_AUTH_OTP_HOTP);
    if (!hotpCtx || !totpCtxSHA1 || !totpCtxSHA256 || !totpCtxSHA512 || !hotpCtxRand) {
        printf("Failed to create hotp contexts\n");
        PrintLastError();
        goto EXIT;
    }

    /* HOTP example in RFC4226. */
    char *hotpExpected[] = {"755224", "287082", "359152", "969429", "338314",
                            "254676", "287922", "162583", "399871", "520489"};
    uint32_t hotpDigits = 6;
    if (setHotpCtx(hotpCtx, key20, sizeof(key20), hotpDigits) != HITLS_AUTH_SUCCESS) {
        printf("Failed to set hotp context\n");
        PrintLastError();
        goto EXIT;
    }
    for (uint64_t counter = 0; counter < sizeof(hotpExpected) / sizeof(hotpExpected[0]); counter++) {
        if (genHotp(hotpCtx, counter, otp, &otpLen) != HITLS_AUTH_SUCCESS) {
            printf("Failed to generate hotp\n");
            PrintLastError();
            goto EXIT;
        }
        printf("HOTP(%016" PRIX64 "): %.*s\n", counter, otpLen, otp);

        if (strncmp(hotpExpected[counter], otp, strlen(hotpExpected[counter])) != 0) {
            printf("Hotp mismatch\n");
            PrintLastError();
            goto EXIT;
        }

        if (validateHotp(hotpCtx, counter, otp, otpLen) != HITLS_AUTH_SUCCESS) {
            printf("Failed to validate hotp\n");
            PrintLastError();
            goto EXIT;
        }

        otp[otpLen - 1] = otp[otpLen - 1] == '9' ? '0' : (otp[otpLen - 1] + 1);
        if (validateHotp(hotpCtx, counter, otp, otpLen) != HITLS_AUTH_OTP_VALIDATE_MISMATCH) {
            printf("Failed to validate invalid hotp\n");
            PrintLastError();
            goto EXIT;
        }
    }

    /* TOTP example in RFC6238. */
    char totpExpected[] = "+---------------+-----------------------+------------------+--------+--------+\n"
                          "|  Time(sec)    |   Time (UTC format)   | Value of T(Hex)  |  TOTP  | Mode   |\n"
                          "+---------------+-----------------------+------------------+--------+--------+\n"
                          "|  59           |  1970-01-01 00:00:59  | 0000000000000001 |94287082| SHA1   |\n"
                          "|  59           |  1970-01-01 00:00:59  | 0000000000000001 |46119246| SHA256 |\n"
                          "|  59           |  1970-01-01 00:00:59  | 0000000000000001 |90693936| SHA512 |\n"
                          "+---------------+-----------------------+------------------+--------+--------+\n"
                          "|  1111111109   |  2005-03-18 01:58:29  | 00000000023523EC |07081804| SHA1   |\n"
                          "|  1111111109   |  2005-03-18 01:58:29  | 00000000023523EC |68084774| SHA256 |\n"
                          "|  1111111109   |  2005-03-18 01:58:29  | 00000000023523EC |25091201| SHA512 |\n"
                          "+---------------+-----------------------+------------------+--------+--------+\n"
                          "|  1111111111   |  2005-03-18 01:58:31  | 00000000023523ED |14050471| SHA1   |\n"
                          "|  1111111111   |  2005-03-18 01:58:31  | 00000000023523ED |67062674| SHA256 |\n"
                          "|  1111111111   |  2005-03-18 01:58:31  | 00000000023523ED |99943326| SHA512 |\n"
                          "+---------------+-----------------------+------------------+--------+--------+\n"
                          "|  1234567890   |  2009-02-13 23:31:30  | 000000000273EF07 |89005924| SHA1   |\n"
                          "|  1234567890   |  2009-02-13 23:31:30  | 000000000273EF07 |91819424| SHA256 |\n"
                          "|  1234567890   |  2009-02-13 23:31:30  | 000000000273EF07 |93441116| SHA512 |\n"
                          "+---------------+-----------------------+------------------+--------+--------+\n"
                          "|  2000000000   |  2033-05-18 03:33:20  | 0000000003F940AA |69279037| SHA1   |\n"
                          "|  2000000000   |  2033-05-18 03:33:20  | 0000000003F940AA |90698825| SHA256 |\n"
                          "|  2000000000   |  2033-05-18 03:33:20  | 0000000003F940AA |38618901| SHA512 |\n"
                          "+---------------+-----------------------+------------------+--------+--------+\n"
                          "|  20000000000  |  2603-10-11 11:33:20  | 0000000027BC86AA |65353130| SHA1   |\n"
                          "|  20000000000  |  2603-10-11 11:33:20  | 0000000027BC86AA |77737706| SHA256 |\n"
                          "|  20000000000  |  2603-10-11 11:33:20  | 0000000027BC86AA |47863826| SHA512 |\n"
                          "+---------------+-----------------------+------------------+--------+--------+\n";
    char actually[4096] = {0};

#define APPEND_SAFE(buffer, format, ...)                                                                            \
    do {                                                                                                            \
        size_t currentLen = strlen(buffer);                                                                         \
        size_t bufferSize = sizeof(buffer);                                                                         \
        size_t remaining = bufferSize - currentLen;                                                                 \
        if (remaining <= 0 || snprintf_s(buffer + currentLen, remaining, remaining, format, ##__VA_ARGS__) == -1) { \
            printf("snprintf_s failed\n");                                                                          \
            goto EXIT;                                                                                              \
        }                                                                                                           \
    } while (0)

    otpLen = sizeof(otp);
    uint32_t totpDigits = 8;
    uint32_t x = 30;
    BslUnixTime t0 = 0L;
    BslUnixTime ts[] = {59L, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L};

    APPEND_SAFE(actually, "+---------------+-----------------------+------------------+--------+--------+\n");
    APPEND_SAFE(actually, "|  Time(sec)    |   Time (UTC format)   | Value of T(Hex)  |  TOTP  | Mode   |\n");
    APPEND_SAFE(actually, "+---------------+-----------------------+------------------+--------+--------+\n");

    if (setTotpCtx(totpCtxSHA1, key20, sizeof(key20), totpDigits, HITLS_AUTH_OTP_CRYPTO_SHA1, x, t0, 1) !=
            HITLS_AUTH_SUCCESS ||
        setTotpCtx(totpCtxSHA256, key32, sizeof(key32), totpDigits, HITLS_AUTH_OTP_CRYPTO_SHA256, x, t0, 1) !=
            HITLS_AUTH_SUCCESS ||
        setTotpCtx(totpCtxSHA512, key64, sizeof(key64), totpDigits, HITLS_AUTH_OTP_CRYPTO_SHA512, x, t0, 1) !=
            HITLS_AUTH_SUCCESS) {
        printf("Failed to set totp context\n");
        PrintLastError();
        goto EXIT;
    }

    for (int i = 0; i < sizeof(ts) / sizeof(ts[0]); i++) {
        long T = (ts[i] - t0) / x;
        time_t timeVal = (time_t)ts[i];
        struct tm *utcTime = gmtime(&timeVal);
        char fmtTime[20] = {0};
        if (strftime(fmtTime, sizeof(fmtTime), "%Y-%m-%d %H:%M:%S", utcTime) == 0) {
            printf("strftime failed\n");
            goto EXIT;
        }

        // SHA1
        if (genTotp(totpCtxSHA1, ts[i], otp, &otpLen) != HITLS_AUTH_SUCCESS) {
            printf("Failed to generate totp SHA1\n");
            PrintLastError();
            goto EXIT;
        }
        if (validateTotp(totpCtxSHA1, ts[i], otp, otpLen) != HITLS_AUTH_SUCCESS ||
            validateTotp(totpCtxSHA1, ts[i] + x, otp, otpLen) != HITLS_AUTH_SUCCESS ||
            validateTotp(totpCtxSHA1, ts[i] - x, otp, otpLen) != HITLS_AUTH_SUCCESS ||
            validateTotp(totpCtxSHA1, ts[i] + x + x, otp, otpLen) != HITLS_AUTH_OTP_VALIDATE_MISMATCH ||
            validateTotp(totpCtxSHA1, ts[i] - x - x, otp, otpLen) != HITLS_AUTH_OTP_VALIDATE_MISMATCH) {
            printf("Failed to validate totp SHA1\n");
            PrintLastError();
            goto EXIT;
        }
        APPEND_SAFE(actually, "|  %-11" PRId64 "  |  %s  | %016" PRIX64 " |%.*s| SHA1   |\n", ts[i], fmtTime, T,
                    totpDigits, otp);

        // SHA256
        if (genTotp(totpCtxSHA256, ts[i], otp, &otpLen) != HITLS_AUTH_SUCCESS) {
            printf("Failed to generate totp SHA256\n");
            PrintLastError();
            goto EXIT;
        }
        if (validateTotp(totpCtxSHA256, ts[i], otp, otpLen) != HITLS_AUTH_SUCCESS ||
            validateTotp(totpCtxSHA256, ts[i] + x, otp, otpLen) != HITLS_AUTH_SUCCESS ||
            validateTotp(totpCtxSHA256, ts[i] - x, otp, otpLen) != HITLS_AUTH_SUCCESS ||
            validateTotp(totpCtxSHA256, ts[i] + x + x, otp, otpLen) != HITLS_AUTH_OTP_VALIDATE_MISMATCH ||
            validateTotp(totpCtxSHA256, ts[i] - x - x, otp, otpLen) != HITLS_AUTH_OTP_VALIDATE_MISMATCH) {
            printf("Failed to validate totp SHA256\n");
            PrintLastError();
            goto EXIT;
        }
        APPEND_SAFE(actually, "|  %-11" PRId64 "  |  %s  | %016" PRIX64 " |%.*s| SHA256 |\n", ts[i], fmtTime, T,
                    totpDigits, otp);

        // SHA512
        if (genTotp(totpCtxSHA512, ts[i], otp, &otpLen) != HITLS_AUTH_SUCCESS) {
            printf("Failed to generate totp SHA512\n");
            PrintLastError();
            goto EXIT;
        }
        if (validateTotp(totpCtxSHA512, ts[i], otp, otpLen) != HITLS_AUTH_SUCCESS ||
            validateTotp(totpCtxSHA512, ts[i] + x, otp, otpLen) != HITLS_AUTH_SUCCESS ||
            validateTotp(totpCtxSHA512, ts[i] - x, otp, otpLen) != HITLS_AUTH_SUCCESS ||
            validateTotp(totpCtxSHA512, ts[i] + x + x, otp, otpLen) != HITLS_AUTH_OTP_VALIDATE_MISMATCH ||
            validateTotp(totpCtxSHA512, ts[i] - x - x, otp, otpLen) != HITLS_AUTH_OTP_VALIDATE_MISMATCH) {
            printf("Failed to validate totp SHA512\n");
            PrintLastError();
            goto EXIT;
        }
        APPEND_SAFE(actually, "|  %-11" PRId64 "  |  %s  | %016" PRIX64 " |%.*s| SHA512 |\n", ts[i], fmtTime, T,
                    totpDigits, otp);
        APPEND_SAFE(actually, "+---------------+-----------------------+------------------+--------+--------+\n");
    }

    printf("%s", actually);
    if (strncmp(totpExpected, actually, strlen(totpExpected)) != 0) {
        printf("Totp mismatch\n");
        PrintLastError();
        goto EXIT;
    }

    /* Key generation. */
    if (CRYPT_EAL_ProviderRandInitCtx(NULL, CRYPT_RAND_SHA256, "provider=default", NULL, 0, NULL) != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_RandInit: error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    otpLen = sizeof(otp);
    uint8_t key[20] = {0};
    uint32_t keyLen = 20;
    if (HITLS_AUTH_OtpInit(hotpCtxRand, NULL, keyLen) != HITLS_AUTH_SUCCESS) {
        printf("Failed to generation random key\n");
        PrintLastError();
        goto EXIT;
    }

    BSL_Param paramCtrl[] = {{AUTH_PARAM_OTP_CTX_KEY, BSL_PARAM_TYPE_OCTETS_PTR, &key, sizeof(key), sizeof(key)},
                             BSL_PARAM_END};
    if (HITLS_AUTH_OtpCtxCtrl(hotpCtxRand, HITLS_AUTH_OTP_GET_CTX_KEY, paramCtrl, 0) != HITLS_AUTH_SUCCESS) {
        printf("Failed to get key\n");
        PrintLastError();
        goto EXIT;
    }
    printf("Random key: ");
    PrintPlainHex(key, keyLen);

    uint64_t counter = 0;
    if (genHotp(hotpCtxRand, counter, otp, &otpLen) != HITLS_AUTH_SUCCESS) {
        printf("Failed to generation hotp\n");
        PrintLastError();
        goto EXIT;
    }
    printf("HOTP(%016" PRIX64 "): %.*s\n", counter, otpLen, otp);
    printf("Check it by: oathtool --hotp --counter %" PRIu64 " ", counter);
    PrintPlainHex(key, keyLen);

    printf("pass \n");
    ret = HITLS_AUTH_SUCCESS;

EXIT:
    HITLS_AUTH_OtpFreeCtx(hotpCtx);
    HITLS_AUTH_OtpFreeCtx(totpCtxSHA1);
    HITLS_AUTH_OtpFreeCtx(totpCtxSHA256);
    HITLS_AUTH_OtpFreeCtx(totpCtxSHA512);
    HITLS_AUTH_OtpFreeCtx(hotpCtxRand);
    return ret;
}