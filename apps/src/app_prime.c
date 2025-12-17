/*
* Copyright (c) 2025 Hong Han, Weijia Wang, School of Cyber Science and Technology, Shandong University
*/
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

#include "app_prime.h"
#include <stddef.h>
#include "securec.h"
#include "bsl_uio.h"
#include "crypt_eal_rand.h"
#include "crypt_errno.h"
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "app_opt.h"
#include "app_print.h"
#include "app_errno.h"
#include "app_function.h"
#include "crypt_bn.h"

#define MIN_SAFE_PRIME_BITS  16 // Minimum bits for safe prime generation
#define DEFAULT_PRIME_CHECKS 64 // Default number of primality checks

typedef struct {
    int32_t hex;
    int32_t generate;
    int32_t bits;
    int32_t safe;
    int32_t checks;
} AppPrimeCtx;

typedef enum OptionChoice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_HELP = 1,
    OPT_BITS = 2,
    OPT_HEX = 3,
    OPT_GENERATE = 4,
    OPT_SAFE = 5,
    OPT_CHECKS = 6,
} OPTION_CHOICE;

static const HITLS_CmdOption g_primeOpts[] = {
    {"help", OPT_HELP, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Display this summary"},
    {"bits", OPT_BITS, HITLS_APP_OPT_VALUETYPE_POSITIVE_INT, "Size of number in bits"},
    {"hex", OPT_HEX, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Hex output"},
    {"generate", OPT_GENERATE, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Generate a prime"},
    {"safe", OPT_SAFE, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Generate a safe prime"},
    {"checks", OPT_CHECKS, HITLS_APP_OPT_VALUETYPE_POSITIVE_INT, "Number of checks"},
    {NULL, 0, 0, NULL}
};

static int32_t CheckPrime(const char *numStr, int32_t hex, int32_t checks)
{
    int32_t ret;
    BN_BigNum *bn = NULL;
    BN_Optimizer *optimizer = NULL;

    if (hex) {
        ret = BN_Hex2Bn(&bn, numStr);
    } else {
        ret = BN_Dec2Bn(&bn, numStr);
    }

    if (ret != CRYPT_SUCCESS || bn == NULL) {
        AppPrintError("prime: Invalid number format\n");
        ret = HITLS_APP_INVALID_ARG;
        goto EXIT;
    }

    optimizer = BN_OptimizerCreate();
    if (optimizer == NULL) {
        AppPrintError("prime: Failed to create optimizer\n");
        ret = HITLS_APP_BSL_FAIL;
        goto EXIT;
    }

    uint32_t checkTimes = (checks > 0) ? (uint32_t)checks : DEFAULT_PRIME_CHECKS;

    ret = BN_PrimeCheck(bn, checkTimes, optimizer, NULL);
    if (ret == CRYPT_SUCCESS) {
        AppPrintInfo("%s is prime\n", numStr);
        ret = HITLS_APP_SUCCESS;
    } else if (ret == CRYPT_BN_NOR_CHECK_PRIME) {
        AppPrintInfo("%s is not prime\n", numStr);
        ret = HITLS_APP_SUCCESS;
    } else {
        AppPrintError("prime: Failed to check prime, errCode: 0x%x\n", ret);
        ret = HITLS_APP_CRYPTO_FAIL;
    }

EXIT:
    BN_Destroy(bn);
    BN_OptimizerDestroy(optimizer);
    return ret;
}

static int32_t ConvertPrimeToString(BN_BigNum *bn, int32_t hex)
{
    char *output = NULL;

    if (hex) {
        output = BN_Bn2Hex(bn);
    } else {
        output = BN_Bn2Dec(bn);
    }

    if (output == NULL) {
        AppPrintError("prime: Out of memory\n");
        return HITLS_APP_BSL_FAIL;
    }

    AppPrintInfo("%s\n", output);
    BSL_SAL_FREE(output);

    return HITLS_APP_SUCCESS;
}

static int32_t GeneratePrime(int32_t bits, int32_t hex, int32_t safe)
{
    int32_t ret;
    BN_BigNum *bn = NULL;
    BN_Optimizer *optimizer = NULL;

    bn = BN_Create((uint32_t)bits);
    if (bn == NULL) {
        AppPrintError("prime: Out of memory\n");
        return HITLS_APP_BSL_FAIL;
    }

    optimizer = BN_OptimizerCreate();
    if (optimizer == NULL) {
        AppPrintError("prime: Failed to create optimizer\n");
        ret = HITLS_APP_BSL_FAIL;
        goto EXIT;
    }

    ret = BN_GenPrime(bn, NULL, (uint32_t)bits, (bool)safe, optimizer, NULL);
    if (ret != CRYPT_SUCCESS) {
        AppPrintError("prime: Failed to generate prime, errCode: 0x%x\n", ret);
        if (safe && bits < MIN_SAFE_PRIME_BITS) {
            AppPrintError("prime: Safe prime generation may require more bits (minimum %d)\n",
                                MIN_SAFE_PRIME_BITS);
        }
        ret = HITLS_APP_CRYPTO_FAIL;
        goto EXIT;
    }

    ret = ConvertPrimeToString(bn, hex);

EXIT:
    BN_Destroy(bn);
    BN_OptimizerDestroy(optimizer);
    return ret;
}

static int32_t HandleOptionBits(int32_t *bits)
{
    int32_t ret = HITLS_APP_OptGetInt(HITLS_APP_OptGetValueStr(), bits);
    if (ret != HITLS_APP_SUCCESS || *bits <= 0) {
        AppPrintError("prime: Invalid bits value\n");
        return HITLS_APP_INVALID_ARG;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t HandleOptionChecks(int32_t *checks)
{
    int32_t ret = HITLS_APP_OptGetInt(HITLS_APP_OptGetValueStr(), checks);
    if (ret != HITLS_APP_SUCCESS || *checks <= 0) {
        AppPrintError("prime: Invalid checks value\n");
        return HITLS_APP_INVALID_ARG;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t ProcessOptionSwitch(OPTION_CHOICE option, AppPrimeCtx *ctx)
{
    switch (option) {
        case OPT_ERR:
            AppPrintError("prime: Use -help for summary.\n");
            return HITLS_APP_INVALID_ARG;
        case OPT_HELP:
            (void)HITLS_APP_OptHelpPrint(g_primeOpts);
            return HITLS_APP_HELP;
        case OPT_BITS:
            return HandleOptionBits(&ctx->bits);
        case OPT_HEX:
            ctx->hex = 1;
            return HITLS_APP_SUCCESS;
        case OPT_GENERATE:
            ctx->generate = 1;
            return HITLS_APP_SUCCESS;
        case OPT_SAFE:
            ctx->safe = 1;
            return HITLS_APP_SUCCESS;
        case OPT_CHECKS:
            return HandleOptionChecks(&ctx->checks);
        default:
            AppPrintError("prime: Unknown option\n");
            return HITLS_APP_INVALID_ARG;
    }
}

static int32_t ParsePrimeOptions(int32_t argc, char **argv, AppPrimeCtx *ctx, char **checkNumber)
{
    int32_t ret;
    OPTION_CHOICE option;

    ret = HITLS_APP_OptBegin(argc, argv, g_primeOpts);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }

    while ((option = (OPTION_CHOICE)HITLS_APP_OptNext()) != OPT_EOF) {
        ret = ProcessOptionSwitch(option, ctx);
        if (ret != HITLS_APP_SUCCESS) {
            HITLS_APP_OptEnd();
            return ret;
        }
    }

    int32_t restArgc = HITLS_APP_GetRestOptNum();
    char **restArgv = HITLS_APP_GetRestOpt();
    if (restArgc > 0 && restArgv != NULL) {
        *checkNumber = restArgv[0];
    }

    HITLS_APP_OptEnd();
    return HITLS_APP_SUCCESS;
}

static int32_t ValidatePrimeArgs(int32_t generate, int32_t bits, const char *checkNumber)
{
    if (!generate && checkNumber == NULL) {
        AppPrintError("prime: Must specify -generate or provide a number to check\n");
        return HITLS_APP_INVALID_ARG;
    }

    if (generate && checkNumber != NULL) {
        AppPrintError("prime: Cannot specify both -generate and a number to check\n");
        return HITLS_APP_INVALID_ARG;
    }

    if (generate && bits == 0) {
        AppPrintError("prime: Specify the number of bits with -bits\n");
        return HITLS_APP_INVALID_ARG;
    }

    return HITLS_APP_SUCCESS;
}

static int32_t InitRandGenerator(void)
{
    if (CRYPT_EAL_ProviderRandInitCtx(NULL, CRYPT_RAND_SHA256, "provider=default", NULL, 0, NULL) != CRYPT_SUCCESS) {
        AppPrintError("prime: Failed to initialize random generator\n");
        return HITLS_APP_CRYPTO_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

int32_t HITLS_PrimeMain(int32_t argc, char **argv)
{
    int32_t ret = HITLS_APP_SUCCESS;
    AppPrimeCtx ctx = {0};
    char *checkNumber = NULL;

    ret = ParsePrimeOptions(argc, argv, &ctx, &checkNumber);
    if (ret != HITLS_APP_SUCCESS) {
        goto EXIT;
    }

    ret = ValidatePrimeArgs(ctx.generate, ctx.bits, checkNumber);
    if (ret != HITLS_APP_SUCCESS) {
        goto EXIT;
    }

    ret = InitRandGenerator();
    if (ret != HITLS_APP_SUCCESS) {
        goto EXIT;
    }

    if (ctx.generate) {
        ret = GeneratePrime(ctx.bits, ctx.hex, ctx.safe);
    } else {
        ret = CheckPrime(checkNumber, ctx.hex, ctx.checks);
    }

    CRYPT_EAL_RandDeinitEx(NULL);

EXIT:
    return ret;
}
