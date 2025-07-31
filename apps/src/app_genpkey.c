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

#include "app_genpkey.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stddef.h>
#include <securec.h>
#include <linux/limits.h>
#include "app_errno.h"
#include "app_help.h"
#include "app_print.h"
#include "app_opt.h"
#include "app_list.h"
#include "app_utils.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_rand.h"

#define RSA_KEYGEN_BITS_STR "rsa_keygen_bits:"
#define EC_PARAMGEN_CURVE_STR "ec_paramgen_curve:"
#define RSA_KEYGEN_BITS_STR_LEN ((int)(sizeof(RSA_KEYGEN_BITS_STR) - 1))
#define EC_PARAMGEN_CURVE_LEN ((int)(sizeof(EC_PARAMGEN_CURVE_STR) - 1))
#define MAX_PKEY_OPT_ARG 10U
#define DEFAULT_RSA_KEYGEN_BITS 2048U

typedef enum {
    HITLS_APP_OPT_ALGORITHM = 2,
    HITLS_APP_OPT_PKEYOPT,
    HITLS_APP_OPT_CIPHER_ALG,
    HITLS_APP_OPT_PASS,
    HITLS_APP_OPT_OUT,
} HITLSOptType;

const HITLS_CmdOption g_genPkeyOpts[] = {
    {"help", HITLS_APP_OPT_HELP, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Display this function summary"},
    {"algorithm", HITLS_APP_OPT_ALGORITHM, HITLS_APP_OPT_VALUETYPE_STRING, "Key algorithm"},
    {"pkeyopt", HITLS_APP_OPT_PKEYOPT, HITLS_APP_OPT_VALUETYPE_STRING, "Set key options"},
    {"", HITLS_APP_OPT_CIPHER_ALG, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Any supported cipher"},
    {"pass", HITLS_APP_OPT_PASS, HITLS_APP_OPT_VALUETYPE_STRING, "Output file pass phrase source"},
    {"out", HITLS_APP_OPT_OUT, HITLS_APP_OPT_VALUETYPE_OUT_FILE, "Output file"},
    {NULL},
};

typedef struct {
    char *algorithm;
    char *pkeyOptArg[MAX_PKEY_OPT_ARG];
    uint32_t pkeyOptArgNum;
} InputGenKeyPara;

typedef struct {
    char *outFilePath;
    char *passOutArg;
} OutPutGenKeyPara;

typedef struct {
    uint32_t bits;
    uint32_t pkeyParaId;
} GenPkeyOptPara;

typedef CRYPT_EAL_PkeyCtx *(*GenPkeyCtxFunc)(const GenPkeyOptPara *);

typedef struct {
    CRYPT_EAL_PkeyCtx *pkey;
    GenPkeyCtxFunc genPkeyCtxFunc;
    GenPkeyOptPara genPkeyOptPara;
    char *passout;
    int32_t cipherAlgCid;
    InputGenKeyPara inPara;
    OutPutGenKeyPara outPara;
} GenPkeyOptCtx;

typedef int32_t (*GenPkeyOptHandleFunc)(GenPkeyOptCtx *);

typedef struct {
    int optType;
    GenPkeyOptHandleFunc func;
} GenPkeyOptHandleTable;

static int32_t GenPkeyOptErr(GenPkeyOptCtx *optCtx)
{
    (void)optCtx;
    AppPrintError("genpkey: Use -help for summary.\n");
    return HITLS_APP_OPT_UNKOWN;
}

static int32_t GenPkeyOptHelp(GenPkeyOptCtx *optCtx)
{
    (void)optCtx;
    HITLS_APP_OptHelpPrint(g_genPkeyOpts);
    return HITLS_APP_HELP;
}

static CRYPT_EAL_PkeyCtx *GenRsaPkeyCtx(const GenPkeyOptPara *optPara)
{
    return HITLS_APP_GenRsaPkeyCtx(optPara->bits);
}

static CRYPT_EAL_PkeyCtx *GenEcPkeyCtx(const GenPkeyOptPara *optPara)
{
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_ECDSA,
        CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default");
    if (pkey == NULL) {
        AppPrintError("genpkey: Failed to initialize the EC private key.\n");
        return NULL;
    }
    if (CRYPT_EAL_PkeySetParaById(pkey, optPara->pkeyParaId) != CRYPT_SUCCESS) {
        AppPrintError("genpkey: Failed to set EC parameters.\n");
        CRYPT_EAL_PkeyFreeCtx(pkey);
        return NULL;
    }
    if (CRYPT_EAL_PkeyGen(pkey) != CRYPT_SUCCESS) {
        AppPrintError("genpkey: Failed to generate the EC private key.\n");
        CRYPT_EAL_PkeyFreeCtx(pkey);
        return NULL;
    }
    return pkey;
}

static int32_t GetRsaKeygenBits(const char *algorithm, const char *pkeyOptArg, uint32_t *bits)
{
    uint32_t numBits = 0;
    if ((strcasecmp(algorithm, "RSA") != 0) || (strlen(pkeyOptArg) <= RSA_KEYGEN_BITS_STR_LEN) ||
        (HITLS_APP_OptGetUint32(pkeyOptArg + RSA_KEYGEN_BITS_STR_LEN, &numBits) != HITLS_APP_SUCCESS)) {
        (void)AppPrintError("genpkey: The %s algorithm parameter %s is incorrect.\n", algorithm, pkeyOptArg);
        return HITLS_APP_INVALID_ARG;
    }

    static const uint32_t numBitsArray[] = {1024, 2048, 3072, 4096};
    for (size_t i = 0; i < sizeof(numBitsArray) / sizeof(numBitsArray[0]); i++) {
        if (numBits == numBitsArray[i]) {
            *bits = numBits;
            return HITLS_APP_SUCCESS;
        }
    }
    AppPrintError("genpkey: The RSA key length is error, supporting 1024、2048、3072、4096.\n");
    return HITLS_APP_INVALID_ARG;
}

static int32_t GetParamGenCurve(const char *algorithm, const char *pkeyOptArg, uint32_t *pkeyParaId)
{
    if ((strcasecmp(algorithm, "EC") != 0) || (strlen(pkeyOptArg) <= EC_PARAMGEN_CURVE_LEN)) {
        (void)AppPrintError("genpkey: The %s algorithm parameter %s is incorrect.\n", algorithm, pkeyOptArg);
        return HITLS_APP_INVALID_ARG;
    }
    const char *curesName = pkeyOptArg + EC_PARAMGEN_CURVE_LEN;
    int32_t cid = HITLS_APP_GetCidByName(curesName, HITLS_APP_LIST_OPT_CURVES);
    if (cid == CRYPT_PKEY_PARAID_MAX) {
        (void)AppPrintError("genpkey: The %s algorithm parameter %s is incorrect, Use the [list -all-curves] command "
            "to view supported curves.\n",
            algorithm, pkeyOptArg);
        return HITLS_APP_INVALID_ARG;
    }

    *pkeyParaId = cid;
    return HITLS_APP_SUCCESS;
}

static int32_t SetPkeyPara(GenPkeyOptCtx *optCtx)
{
    if (optCtx->genPkeyCtxFunc == NULL) {
        (void)AppPrintError("genpkey: Algorithm not specified.\n");
        return HITLS_APP_INVALID_ARG;
    }

    for (uint32_t i = 0; i < optCtx->inPara.pkeyOptArgNum; ++i) {
        if (optCtx->inPara.pkeyOptArg[i] == NULL) {
            return HITLS_APP_INVALID_ARG;
        }
        char *algorithm = optCtx->inPara.algorithm;
        char *pkeyOptArg = optCtx->inPara.pkeyOptArg[i];
        // rsa_keygen_bits:numbits
        if (strncmp(pkeyOptArg, RSA_KEYGEN_BITS_STR, RSA_KEYGEN_BITS_STR_LEN) == 0) {
            return GetRsaKeygenBits(algorithm, pkeyOptArg, &optCtx->genPkeyOptPara.bits);
        } else if (strncmp(pkeyOptArg, EC_PARAMGEN_CURVE_STR, EC_PARAMGEN_CURVE_LEN) == 0) {
            // ec_paramgen_curve:curve
            return GetParamGenCurve(algorithm, pkeyOptArg, &optCtx->genPkeyOptPara.pkeyParaId);
        } else {
            (void)AppPrintError("genpkey: The %s algorithm parameter %s is incorrect.\n", algorithm, pkeyOptArg);
            return HITLS_APP_INVALID_ARG;
        }
    }
    return HITLS_APP_SUCCESS;
}

static int32_t GenPkeyOptAlgorithm(GenPkeyOptCtx *optCtx)
{
    optCtx->inPara.algorithm = HITLS_APP_OptGetValueStr();
    if (strcasecmp(optCtx->inPara.algorithm, "RSA") == 0) {
        optCtx->genPkeyCtxFunc = GenRsaPkeyCtx;
    } else if (strcasecmp(optCtx->inPara.algorithm, "EC") == 0) {
        optCtx->genPkeyCtxFunc = GenEcPkeyCtx;
    } else {
        (void)AppPrintError("genpkey: The %s algorithm is not supported.\n", optCtx->inPara.algorithm);
        return HITLS_APP_INVALID_ARG;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t GenPkeyOpt(GenPkeyOptCtx *optCtx)
{
    if (optCtx->inPara.pkeyOptArgNum >= MAX_PKEY_OPT_ARG) {
        return HITLS_APP_INVALID_ARG;
    }
    optCtx->inPara.pkeyOptArg[optCtx->inPara.pkeyOptArgNum] = HITLS_APP_OptGetValueStr();
    ++(optCtx->inPara.pkeyOptArgNum);
    return HITLS_APP_SUCCESS;
}

static int32_t GenPkeyOptCipher(GenPkeyOptCtx *optCtx)
{
    const char *name = HITLS_APP_OptGetUnKownOptName();
    return HITLS_APP_GetAndCheckCipherOpt(name, &optCtx->cipherAlgCid);
}

static int32_t GenPkeyOptPassout(GenPkeyOptCtx *optCtx)
{
    optCtx->outPara.passOutArg = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t GenPkeyOptOut(GenPkeyOptCtx *optCtx)
{
    optCtx->outPara.outFilePath = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static const GenPkeyOptHandleTable g_genPkeyOptHandleTable[] = {
    {HITLS_APP_OPT_ERR, GenPkeyOptErr},
    {HITLS_APP_OPT_HELP, GenPkeyOptHelp},
    {HITLS_APP_OPT_ALGORITHM, GenPkeyOptAlgorithm},
    {HITLS_APP_OPT_PKEYOPT, GenPkeyOpt},
    {HITLS_APP_OPT_CIPHER_ALG, GenPkeyOptCipher},
    {HITLS_APP_OPT_PASS, GenPkeyOptPassout},
    {HITLS_APP_OPT_OUT, GenPkeyOptOut},
};

static int32_t ParseGenPkeyOpt(GenPkeyOptCtx *optCtx)
{
    int32_t ret = HITLS_APP_SUCCESS;
    int optType = HITLS_APP_OPT_ERR;
    while ((ret == HITLS_APP_SUCCESS) && ((optType = HITLS_APP_OptNext()) != HITLS_APP_OPT_EOF)) {
        for (size_t i = 0; i < (sizeof(g_genPkeyOptHandleTable) / sizeof(g_genPkeyOptHandleTable[0])); ++i) {
            if (optType == g_genPkeyOptHandleTable[i].optType) {
                ret = g_genPkeyOptHandleTable[i].func(optCtx);
                break;
            }
        }
    }
    // Obtain the number of parameters that cannot be parsed in the current version,
    // and print the error inFormation and help list.
    if ((ret == HITLS_APP_SUCCESS) && (HITLS_APP_GetRestOptNum() != 0)) {
        AppPrintError("Extra arguments given.\n");
        AppPrintError("genpkey: Use -help for summary.\n");
        ret = HITLS_APP_OPT_UNKOWN;
    }
    return ret;
}

static int32_t HandleGenPkeyOpt(GenPkeyOptCtx *optCtx)
{
    int32_t ret = ParseGenPkeyOpt(optCtx);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }

    // 1. SetPkeyPara
    if (SetPkeyPara(optCtx) != HITLS_APP_SUCCESS) {
        return HITLS_APP_INVALID_ARG;
    }

    // 2. Read Password
    if (HITLS_APP_ParsePasswd(optCtx->outPara.passOutArg, &optCtx->passout) != HITLS_APP_SUCCESS) {
        return HITLS_APP_PASSWD_FAIL;
    }

    // 3. Gen private key
    optCtx->pkey = optCtx->genPkeyCtxFunc(&optCtx->genPkeyOptPara);
    if (optCtx->pkey == NULL) {
        return HITLS_APP_LOAD_KEY_FAIL;
    }

    // 4. Output the private key.
    return HITLS_APP_PrintPrvKey(optCtx->pkey, optCtx->outPara.outFilePath, BSL_FORMAT_PEM, optCtx->cipherAlgCid,
        &optCtx->passout);
}

static void InitGenPkeyOptCtx(GenPkeyOptCtx *optCtx)
{
    optCtx->pkey = NULL;
    optCtx->genPkeyCtxFunc = NULL;
    optCtx->genPkeyOptPara.bits = DEFAULT_RSA_KEYGEN_BITS;
    optCtx->genPkeyOptPara.pkeyParaId = CRYPT_PKEY_PARAID_MAX;

    optCtx->passout = NULL;
    optCtx->cipherAlgCid = CRYPT_CIPHER_MAX;

    optCtx->inPara.algorithm = NULL;
    memset_s(optCtx->inPara.pkeyOptArg, MAX_PKEY_OPT_ARG, 0, MAX_PKEY_OPT_ARG);
    optCtx->inPara.pkeyOptArgNum = 0;

    optCtx->outPara.outFilePath = NULL;
    optCtx->outPara.passOutArg = NULL;
}

static void UnInitGenPkeyOptCtx(GenPkeyOptCtx *optCtx)
{
    CRYPT_EAL_PkeyFreeCtx(optCtx->pkey);
    optCtx->pkey = NULL;
    if (optCtx->passout != NULL) {
        BSL_SAL_ClearFree(optCtx->passout, strlen(optCtx->passout));
    }
}

// genpkey main function
int32_t HITLS_GenPkeyMain(int argc, char *argv[])
{
    GenPkeyOptCtx optCtx = {};
    InitGenPkeyOptCtx(&optCtx);
    int32_t ret = HITLS_APP_SUCCESS;
    do {
        ret = HITLS_APP_OptBegin(argc, argv, g_genPkeyOpts);
        if (ret != HITLS_APP_SUCCESS) {
            AppPrintError("error in opt begin.\n");
            break;
        }
        if (CRYPT_EAL_ProviderRandInitCtx(NULL, CRYPT_RAND_AES128_CTR,
            "provider=default", NULL, 0, NULL) != CRYPT_SUCCESS) {
            ret = HITLS_APP_CRYPTO_FAIL;
            break;
        }
        ret = HandleGenPkeyOpt(&optCtx);
    } while (false);
    CRYPT_EAL_RandDeinitEx(NULL);
    HITLS_APP_OptEnd();
    UnInitGenPkeyOptCtx(&optCtx);
    return ret;
}