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

#include "bsl_sal.h"
#include "bsl_list.h"
#include "crypt_errno.h"
#include "crypt_params_key.h"
#include "crypt_eal_provider.h"
#include "crypt_eal_implprovider.h"
#include "crypt_eal_codecs.h"
#include "crypt_eal_pkey.h"
#include "bsl_types.h"
#include "crypt_types.h"
#include "provider_test_utils.h"
#include <stdlib.h>
#include <string.h>

#define RSA_MAX_MODULUS_BITS 16384
#define RSA_MAX_MODULUS_LEN (RSA_MAX_MODULUS_BITS / 8)

#define PARAMISNULL(a) ((a) == NULL || (a)->value == NULL)
#define PARAMISNULLLENIS0(a) ((a) == NULL || (a)->value == NULL || (a)->valueLen == 0)

/* JSON to PEM decoder context */
typedef struct {
    const char *outFormat;
    const char *outType;
} JSON_PEM_DecoderCtx;

/* JSON to PEM decoder implementation */
static void *JSON_PEM_NewCtx(void *provCtx)
{
    (void)provCtx;
    JSON_PEM_DecoderCtx *ctx = calloc(1, sizeof(JSON_PEM_DecoderCtx));
    if (ctx == NULL) {
        return NULL;
    }
    ctx->outFormat = "PEM";
    ctx->outType = NULL;
    return ctx;
}

static int32_t JSON_PEM_SetParam(void *ctx, const BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        return CRYPT_NULL_INPUT;
    }
    return CRYPT_SUCCESS;
}

static int32_t JSON_PEM_GetParam(void *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        return CRYPT_NULL_INPUT;
    }
    JSON_PEM_DecoderCtx *decoderCtx = (JSON_PEM_DecoderCtx *)ctx;
    BSL_Param *param1 = TestFindParam(param, CRYPT_PARAM_DECODE_OUTPUT_TYPE);
    if (param1 != NULL) {
        if (param1->valueType != BSL_PARAM_TYPE_OCTETS_PTR) {
            return CRYPT_INVALID_ARG;
        }
        param1->value = (void *)(uintptr_t)decoderCtx->outType;
    }
    BSL_Param *param2 = TestFindParam(param, CRYPT_PARAM_DECODE_OUTPUT_FORMAT);
    if (param2 != NULL) {
        if (param2->valueType != BSL_PARAM_TYPE_OCTETS_PTR) {
            return CRYPT_INVALID_ARG;
        }
        param2->value = (void *)(uintptr_t)decoderCtx->outFormat;
    }
    return CRYPT_SUCCESS;
}

static int32_t JSON_PEM_Decode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam)
{
    if (ctx == NULL || inParam == NULL || outParam == NULL) {
        return CRYPT_NULL_INPUT;
    }
    uint8_t *pemData = NULL;
    uint32_t pemLen = 0;
    uint8_t *jsonData = NULL;
    BSL_Param *resultParam = NULL;
    JSON_PEM_DecoderCtx *decoderCtx = (JSON_PEM_DecoderCtx *)ctx;
    const BSL_Param *param1 = TestFindConstParam(inParam, CRYPT_PARAM_DECODE_BUFFER_DATA);
    if (param1 == NULL) {
        return CRYPT_NULL_INPUT;
    }
    /* Get input data */
    if (param1->valueType != BSL_PARAM_TYPE_OCTETS || param1->value == NULL || param1->valueLen == 0) {
        return CRYPT_INVALID_ARG;
    }
    jsonData = (uint8_t *)(uintptr_t)param1->value;
    uint8_t *pemHeader = strstr(jsonData, "{");
    if (pemHeader == NULL) {
        return CRYPT_INVALID_ARG;
    }
    uint8_t *pemFooter = strstr(pemHeader, "}");
    if (pemFooter == NULL) {
        return CRYPT_INVALID_ARG;
    }
    /* Convert JSON to PEM format */
    pemLen = pemFooter - pemHeader + 1;
    pemData = (uint8_t *)malloc(pemLen);
    if (pemData == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    memcpy(pemData, pemHeader, pemLen);
    pemData[pemLen - 1] = '\0';
    /* Create output parameter */
    resultParam = calloc(2, sizeof(BSL_Param));
    if (resultParam == NULL) {
        free(pemData);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    resultParam[0].key = CRYPT_PARAM_DECODE_BUFFER_DATA;
    resultParam[0].valueType = BSL_PARAM_TYPE_OCTETS;
    resultParam[0].value = pemData;
    resultParam[0].valueLen = pemLen;
    *outParam = resultParam;
    return CRYPT_SUCCESS;
}

static void JSON_PEM_FreeOutData(void *ctx, BSL_Param *outData)
{
    if (ctx == NULL || outData == NULL) {
        return;
    }
    free(outData->value);
    free(outData);
}

static void JSON_PEM_FreeCtx(void *ctx)
{
    if (ctx == NULL) {
        return;
    }
    free(ctx);
}

/* RSA key management context */
typedef struct {
    uint32_t bits;                              // RSA key length
    uint8_t e[RSA_MAX_MODULUS_LEN];             // Public key
    uint8_t eLen;                               // Public key length
    uint8_t n[RSA_MAX_MODULUS_LEN];             // Public key
    uint32_t nLen;                              // Public key length
    uint8_t d[RSA_MAX_MODULUS_LEN];             // Private key
    uint32_t dLen;                              // Private key length
    uint8_t p[RSA_MAX_MODULUS_LEN];             // Private key
    uint32_t pLen;                              // Private key length
    uint8_t q[RSA_MAX_MODULUS_LEN];             // Private key
    uint32_t qLen;                              // Private key length
    uint8_t dp[RSA_MAX_MODULUS_LEN];            // Private key
    uint32_t dpLen;                             // Private key length
    uint8_t dq[RSA_MAX_MODULUS_LEN];            // Private key
    uint32_t dqLen;                             // Private key length
    uint8_t qInv[RSA_MAX_MODULUS_LEN];          // Private key
    uint32_t qInvLen;                           // Private key length
    int32_t mdId;                               // MD ID
    int32_t mgf1Id;                             // MGF1 ID
    int32_t saltLen;                            // Salt length
} TestRsaCtx;

/* RSA key management implementation */
static void *TestPkeyMgmtRsaNewCtx(void *provCtx)
{
    (void)provCtx;
    TestRsaCtx *ctx = calloc(1, sizeof(TestRsaCtx));
    if (ctx == NULL) {
        return NULL;
    }
    return ctx;
}

static void TestRsaFreeCtx(void *ctx)
{
    if (ctx == NULL) {
        return;
    }
    free(ctx);
}

static int32_t TestRsaSetParam(void *ctx, const BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        return CRYPT_NULL_INPUT;
    }
    const BSL_Param *e = TestFindConstParam(param, CRYPT_PARAM_RSA_E);
    const BSL_Param *bits = TestFindConstParam(param, CRYPT_PARAM_RSA_BITS);
    if (PARAMISNULL(e) || PARAMISNULL(bits)) {
        return CRYPT_NULL_INPUT;
    }
    if (e->valueType != BSL_PARAM_TYPE_OCTETS || bits->valueType != BSL_PARAM_TYPE_UINT32) {
        return CRYPT_INVALID_ARG;
    }
    TestRsaCtx *rsaCtx = (TestRsaCtx *)ctx;
    rsaCtx->bits = *(uint32_t *)bits->value;
    memcpy(rsaCtx->e, e->value, e->valueLen);
    rsaCtx->eLen = e->valueLen;
    return CRYPT_SUCCESS;
}

static int32_t TestRsaSetPubKey(void *ctx, const BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        return CRYPT_NULL_INPUT;
    }
    const BSL_Param *e = TestFindConstParam(param, CRYPT_PARAM_RSA_E);
    const BSL_Param *n = TestFindConstParam(param, CRYPT_PARAM_RSA_N);
    if (PARAMISNULL(e) || PARAMISNULL(n)) {
        return CRYPT_NULL_INPUT;
    }
    TestRsaCtx *rsaCtx = (TestRsaCtx *)ctx;
    memcpy(rsaCtx->e, e->value, e->valueLen);
    memcpy(rsaCtx->n, n->value, n->valueLen);
    rsaCtx->eLen = e->valueLen;
    rsaCtx->nLen = n->valueLen;
    return CRYPT_SUCCESS;
}

static int32_t TestRsaSetPrvKey(void *ctx, const BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        return CRYPT_NULL_INPUT;
    }
    const BSL_Param *n = TestFindConstParam(param, CRYPT_PARAM_RSA_N);
    const BSL_Param *d = TestFindConstParam(param, CRYPT_PARAM_RSA_D);
    const BSL_Param *p = TestFindConstParam(param, CRYPT_PARAM_RSA_P);
    const BSL_Param *q = TestFindConstParam(param, CRYPT_PARAM_RSA_Q);
    const BSL_Param *dp = TestFindConstParam(param, CRYPT_PARAM_RSA_DP);
    const BSL_Param *dq = TestFindConstParam(param, CRYPT_PARAM_RSA_DQ);
    const BSL_Param *qInv = TestFindConstParam(param, CRYPT_PARAM_RSA_QINV);
    if (PARAMISNULLLENIS0(n) || PARAMISNULLLENIS0(d) || n->valueType != BSL_PARAM_TYPE_OCTETS ||
        d->valueType != BSL_PARAM_TYPE_OCTETS) {
        return CRYPT_NULL_INPUT;
    }
    if (n->valueLen > RSA_MAX_MODULUS_LEN) {
        return CRYPT_RSA_ERR_KEY_BITS;
    }
    // prv->p\q and prv->dP\dQ\qInv must be both empty or not.
    // If prv->p is empty, prv->dP must be empty.
    if ((PARAMISNULL(p) != PARAMISNULL(q)) || (PARAMISNULL(p) && !PARAMISNULL(dp))) {
        return CRYPT_RSA_NO_KEY_INFO;
    }
    if ((PARAMISNULL(dp) || PARAMISNULL(dq) || PARAMISNULL(qInv)) &&
        (!PARAMISNULL(dp) || !PARAMISNULL(dq) || !PARAMISNULL(qInv))) {
        return CRYPT_RSA_NO_KEY_INFO;
    }
    TestRsaCtx *rsaCtx = (TestRsaCtx *)ctx;
    memcpy(rsaCtx->n, n->value, n->valueLen);
    rsaCtx->nLen = n->valueLen;
    memcpy(rsaCtx->d, d->value, d->valueLen);
    rsaCtx->dLen = d->valueLen;
    if (!PARAMISNULL(p)) {
        memcpy(rsaCtx->p, p->value, p->valueLen);
        rsaCtx->pLen = p->valueLen;
    }
    if (!PARAMISNULL(q)) {
        memcpy(rsaCtx->q, q->value, q->valueLen);
        rsaCtx->qLen = q->valueLen;
    }
    if (!PARAMISNULL(dp)) {
        memcpy(rsaCtx->dp, dp->value, dp->valueLen);
        rsaCtx->dpLen = dp->valueLen;
    }
    if (!PARAMISNULL(dq)) {
        memcpy(rsaCtx->dq, dq->value, dq->valueLen);
        rsaCtx->dqLen = dq->valueLen;
    }
    if (!PARAMISNULL(qInv)) {
        memcpy(rsaCtx->qInv, qInv->value, qInv->valueLen);
        rsaCtx->qInvLen = qInv->valueLen;
    }
    return CRYPT_SUCCESS;
}

static int32_t TestRsaImport(void *ctx, const BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CRYPT_SUCCESS;
    TestRsaCtx *rsaCtx = (TestRsaCtx *)ctx;
    const BSL_Param *e = TestFindConstParam(param, CRYPT_PARAM_RSA_E);
    const BSL_Param *n = TestFindConstParam(param, CRYPT_PARAM_RSA_N);
    if (!PARAMISNULL(e) && !PARAMISNULL(n)) {
        ret = TestRsaSetPubKey(ctx, param);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }

    const BSL_Param *d = TestFindConstParam(param, CRYPT_PARAM_RSA_D);
    const BSL_Param *p = TestFindConstParam(param, CRYPT_PARAM_RSA_P);
    const BSL_Param *q = TestFindConstParam(param, CRYPT_PARAM_RSA_Q);
    const BSL_Param *dp = TestFindConstParam(param, CRYPT_PARAM_RSA_DP);
    const BSL_Param *dq = TestFindConstParam(param, CRYPT_PARAM_RSA_DQ);
    const BSL_Param *qInv = TestFindConstParam(param, CRYPT_PARAM_RSA_QINV);
    if (!PARAMISNULL(n) && !PARAMISNULL(d) && (PARAMISNULL(p) == PARAMISNULL(q)) &&
        (PARAMISNULL(dp) == PARAMISNULL(dq)) && PARAMISNULL(dq) == PARAMISNULL(qInv)) {
        ret = TestRsaSetPrvKey(ctx, param);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
    const BSL_Param *mdIdParam = TestFindConstParam(param, CRYPT_PARAM_RSA_MD_ID);
    const BSL_Param *mgf1IdParam = TestFindConstParam(param, CRYPT_PARAM_RSA_MGF1_ID);
    const BSL_Param *saltLenParam = TestFindConstParam(param, CRYPT_PARAM_RSA_SALTLEN);
    if (mdIdParam != NULL && mdIdParam->valueType == BSL_PARAM_TYPE_INT32 && mdIdParam->valueLen == sizeof(int32_t) &&
        mgf1IdParam != NULL && mgf1IdParam->valueType == BSL_PARAM_TYPE_INT32 &&
            mgf1IdParam->valueLen == sizeof(int32_t) &&
        saltLenParam != NULL && saltLenParam->valueType == BSL_PARAM_TYPE_INT32 &&
            saltLenParam->valueLen == sizeof(int32_t)) {
        rsaCtx->mdId = *(int32_t *)mdIdParam->value;
        rsaCtx->mgf1Id = *(int32_t *)mgf1IdParam->value;
        rsaCtx->saltLen = *(int32_t *)saltLenParam->value;
    } else if (mdIdParam != NULL && mdIdParam->valueType == BSL_PARAM_TYPE_INT32 && mdIdParam->valueLen == sizeof(int32_t)) {
         rsaCtx->mdId = *(int32_t *)mdIdParam->value;
    }
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return CRYPT_SUCCESS;
}

/* Provider implementation */
static const CRYPT_EAL_Func g_jsonPemDecoderFuncs[] = {
    {CRYPT_DECODER_IMPL_NEWCTX, (void *)JSON_PEM_NewCtx},
    {CRYPT_DECODER_IMPL_SETPARAM, (void *)JSON_PEM_SetParam},
    {CRYPT_DECODER_IMPL_GETPARAM, (void *)JSON_PEM_GetParam},
    {CRYPT_DECODER_IMPL_DECODE, (void *)JSON_PEM_Decode},
    {CRYPT_DECODER_IMPL_FREEOUTDATA, (void *)JSON_PEM_FreeOutData},
    {CRYPT_DECODER_IMPL_FREECTX, (void *)JSON_PEM_FreeCtx},
    {0, NULL}
};

/* Provider registration */
static const CRYPT_EAL_AlgInfo g_testDecode[] = {
    {BSL_CID_DECODE_UNKNOWN, g_jsonPemDecoderFuncs, "provider=test_decoder, inFormat=JSON, outFormat=PEM"},

    CRYPT_EAL_ALGINFO_END
};

/* SM2 key management context */
typedef struct {
    uint8_t prvKey[32];           // Private key
    uint32_t prvKeyLen;           // Private key length
    uint8_t pubKey[72];          // Public key
    uint32_t pubKeyLen;           // Public key length
} TestSm2OrEd25519Ctx;

/* SM2 key management implementation */
static void *TestPkeyMgmtSm2OrEd25519NewCtx(void *provCtx)
{
    (void)provCtx;
    TestSm2OrEd25519Ctx *ctx = calloc(1, sizeof(TestSm2OrEd25519Ctx));
    if (ctx == NULL) {
        return NULL;
    }
    return ctx;
}

static void TestSm2OrEd25519FreeCtx(void *ctx)
{
    if (ctx == NULL) {
        return;
    }
    free(ctx);
}

static int32_t TestSm2SetPubKey(void *ctx, const BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        return CRYPT_NULL_INPUT;
    }
    const BSL_Param *pubKey = TestFindConstParam(param, CRYPT_PARAM_EC_PUBKEY);
    if (PARAMISNULL(pubKey)) {
        return CRYPT_NULL_INPUT;
    }
    if (pubKey->valueType != BSL_PARAM_TYPE_OCTETS || pubKey->valueLen < 65) {
        return CRYPT_INVALID_ARG;
    }
    TestSm2OrEd25519Ctx *sm2Ctx = (TestSm2OrEd25519Ctx *)ctx;
    memcpy(sm2Ctx->pubKey, pubKey->value, pubKey->valueLen);
    sm2Ctx->pubKeyLen = pubKey->valueLen;
    return CRYPT_SUCCESS;
}

static int32_t TestSm2SetPrvKey(void *ctx, const BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        return CRYPT_NULL_INPUT;
    }
    const BSL_Param *prvKey = TestFindConstParam(param, CRYPT_PARAM_EC_PRVKEY);
    if (PARAMISNULL(prvKey)) {
        return CRYPT_NULL_INPUT;
    }
    if (prvKey->valueType != BSL_PARAM_TYPE_OCTETS || prvKey->valueLen != 32) {
        return CRYPT_INVALID_ARG;
    }
    TestSm2OrEd25519Ctx *sm2Ctx = (TestSm2OrEd25519Ctx *)ctx;
    memcpy(sm2Ctx->prvKey, prvKey->value, prvKey->valueLen);
    sm2Ctx->prvKeyLen = prvKey->valueLen;
    return CRYPT_SUCCESS;
}

static int32_t TestSm2Import(void *ctx, const BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        return CRYPT_NULL_INPUT;
    }
    int32_t ret;
    TestSm2OrEd25519Ctx *sm2Ctx = (TestSm2OrEd25519Ctx *)ctx;

    const BSL_Param *pubKey = TestFindConstParam(param, CRYPT_PARAM_EC_PUBKEY);
    if (!PARAMISNULL(pubKey)) {
        ret = TestSm2SetPubKey(ctx, param);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }

    const BSL_Param *prvKey = TestFindConstParam(param, CRYPT_PARAM_EC_PRVKEY);
    if (!PARAMISNULL(prvKey)) {
        ret = TestSm2SetPrvKey(ctx, param);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }

    return CRYPT_SUCCESS;
}

/* ED25519 key management context */
static int32_t TestEd25519SetPubKey(void *ctx, const BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        return CRYPT_NULL_INPUT;
    }
    const BSL_Param *pubKey = TestFindConstParam(param, CRYPT_PARAM_CURVE25519_PUBKEY);
    if (PARAMISNULL(pubKey)) {
        return CRYPT_NULL_INPUT;
    }
    if (pubKey->valueType != BSL_PARAM_TYPE_OCTETS || pubKey->valueLen != 32) {
        return CRYPT_INVALID_ARG;
    }
    TestSm2OrEd25519Ctx *ed25519Ctx = (TestSm2OrEd25519Ctx *)ctx;
    memcpy(ed25519Ctx->pubKey, pubKey->value, pubKey->valueLen);
    ed25519Ctx->pubKeyLen = pubKey->valueLen;
    return CRYPT_SUCCESS;
}

static int32_t TestEd25519SetPrvKey(void *ctx, const BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        return CRYPT_NULL_INPUT;
    }
    const BSL_Param *prvKey = TestFindConstParam(param, CRYPT_PARAM_CURVE25519_PRVKEY);
    if (PARAMISNULL(prvKey)) {
        return CRYPT_NULL_INPUT;
    }
    if (prvKey->valueType != BSL_PARAM_TYPE_OCTETS || prvKey->valueLen != 32) {
        return CRYPT_INVALID_ARG;
    }
    TestSm2OrEd25519Ctx *ed25519Ctx = (TestSm2OrEd25519Ctx *)ctx;
    memcpy(ed25519Ctx->prvKey, prvKey->value, prvKey->valueLen);
    ed25519Ctx->prvKeyLen = prvKey->valueLen;
    return CRYPT_SUCCESS;
}

static int32_t TestEd25519Import(void *ctx, const BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        return CRYPT_NULL_INPUT;
    }
    int32_t ret;
    TestSm2OrEd25519Ctx *ed25519Ctx = (TestSm2OrEd25519Ctx *)ctx;

    const BSL_Param *pubKey = TestFindConstParam(param, CRYPT_PARAM_CURVE25519_PUBKEY);
    if (!PARAMISNULL(pubKey)) {
        ret = TestEd25519SetPubKey(ctx, param);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }

    const BSL_Param *prvKey = TestFindConstParam(param, CRYPT_PARAM_CURVE25519_PRVKEY);
    if (!PARAMISNULL(prvKey)) {
        ret = TestEd25519SetPrvKey(ctx, param);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
    return CRYPT_SUCCESS;
}

const CRYPT_EAL_Func g_testKeyMgmtRsa[] = {
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (CRYPT_EAL_ImplPkeyMgmtNewCtx)TestPkeyMgmtRsaNewCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPARAM, (CRYPT_EAL_ImplPkeyMgmtSetParam)TestRsaSetParam},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, (CRYPT_EAL_ImplPkeyMgmtSetPrv)TestRsaSetPrvKey},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, (CRYPT_EAL_ImplPkeyMgmtSetPub)TestRsaSetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, (CRYPT_EAL_ImplPkeyMgmtFreeCtx)TestRsaFreeCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_IMPORT, (CRYPT_EAL_ImplPkeyMgmtImport)TestRsaImport},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_testKeyMgmtSm2[] = {
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (CRYPT_EAL_ImplPkeyMgmtNewCtx)TestPkeyMgmtSm2OrEd25519NewCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, (CRYPT_EAL_ImplPkeyMgmtSetPrv)TestSm2SetPrvKey},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, (CRYPT_EAL_ImplPkeyMgmtSetPub)TestSm2SetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, (CRYPT_EAL_ImplPkeyMgmtFreeCtx)TestSm2OrEd25519FreeCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_IMPORT, (CRYPT_EAL_ImplPkeyMgmtImport)TestSm2Import},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_testKeyMgmtEd25519[] = {
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (CRYPT_EAL_ImplPkeyMgmtNewCtx)TestPkeyMgmtSm2OrEd25519NewCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, (CRYPT_EAL_ImplPkeyMgmtSetPrv)TestEd25519SetPrvKey},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, (CRYPT_EAL_ImplPkeyMgmtSetPub)TestEd25519SetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, (CRYPT_EAL_ImplPkeyMgmtFreeCtx)TestSm2OrEd25519FreeCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_IMPORT, (CRYPT_EAL_ImplPkeyMgmtImport)TestEd25519Import},
    CRYPT_EAL_FUNC_END,
};

static const CRYPT_EAL_AlgInfo g_testKeyMgmt[] = {
    {CRYPT_PKEY_RSA, g_testKeyMgmtRsa, "provider=test_decoder"},
    {CRYPT_PKEY_SM2, g_testKeyMgmtSm2, "provider=test_decoder"},
    {CRYPT_PKEY_ED25519, g_testKeyMgmtEd25519, "provider=test_decoder"},
    
    CRYPT_EAL_ALGINFO_END
};

static int32_t TestProvQuery(void *provCtx, int32_t operaId, CRYPT_EAL_AlgInfo **algInfos)
{
    (void)provCtx;
    int32_t ret = CRYPT_SUCCESS;
    switch (operaId) {
        case CRYPT_EAL_OPERAID_KEYMGMT:
            *algInfos = (CRYPT_EAL_AlgInfo *)(uintptr_t)g_testKeyMgmt;
            break;
        case CRYPT_EAL_OPERAID_DECODER:
            *algInfos = (CRYPT_EAL_AlgInfo *)(uintptr_t)g_testDecode;
            break;
        default:
            return CRYPT_NOT_SUPPORT;
    }

    return CRYPT_SUCCESS;
}

static int32_t TestProvFree(void *provCtx)
{
    if (provCtx != NULL) {
        free(provCtx);
    }
    return CRYPT_SUCCESS;
}

static CRYPT_EAL_Func g_testProvOutFuncs[] = {
    {CRYPT_EAL_PROVCB_QUERY, TestProvQuery},
    {CRYPT_EAL_PROVCB_FREE, TestProvFree},
    {CRYPT_EAL_PROVCB_CTRL, NULL},
    {CRYPT_EAL_PROVCB_GETCAPS, NULL},
    CRYPT_EAL_FUNC_END
};

int32_t CRYPT_EAL_ProviderInit(CRYPT_EAL_ProvMgrCtx *mgrCtx, BSL_Param *param,
    CRYPT_EAL_Func *capFuncs, CRYPT_EAL_Func **outFuncs, void **provCtx)
{
   *outFuncs = g_testProvOutFuncs;
    return CRYPT_SUCCESS;
}
