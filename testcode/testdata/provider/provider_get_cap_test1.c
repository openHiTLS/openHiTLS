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

#include "crypt_eal_provider.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "bsl_obj.h"
#include "bsl_err.h"
#include "bsl_params.h"
#include "crypt_errno.h"
#include "crypt_params_key.h"
#include "crypt_eal_implprovider.h"
#include "hitls_type.h"
#include "provider_test_utils.h"

#define NEW_PARA_ALGID (BSL_CID_MAX + 1)
#define NEW_PKEY_ALGID (BSL_CID_MAX + 2)

#define NEW_KEM_ALGID (BSL_CID_MAX + 5)
#define NEW_KEM_PARAM_ID (BSL_CID_MAX + 6)

#define NEW_SIGN_HASH_ALGID (BSL_CID_MAX + 3)
#define NEW_HASH_ALGID (BSL_CID_MAX + 4)
#define TEST_CRYPT_DEFAULT_SIGNLEN 70
#define UINT8_MAX_NUM 255

typedef struct {
    CRYPT_EAL_ProvMgrCtx *mgrCtxHandle;
} TestProvCtx;

typedef struct {
    uint8_t prvkey[72];      // Private key
    uint32_t prvkeyLen;      // Private key length
    uint8_t pubkey[256];     // Public key
    uint32_t pubkeyLen;      // Public key length
    int32_t paraId;          // Parameter ID
} TestEccKeyCtx;

typedef struct {
    uint8_t pubkey[20];     // Public key
    uint32_t pubkeyLen;      // Public key length
    uint8_t shared[20];
    uint32_t sharedLen;
    int32_t paraId;          // Parameter ID
} TestKemKeyCtx;

void *TestPkeyMgmtEcNewCtx(void *provCtx, int32_t algId)
{
    (void)provCtx;
    (void)algId;
    TestEccKeyCtx *pkeyCtx = malloc(sizeof(TestEccKeyCtx));
    if (pkeyCtx == NULL) {
        return NULL;
    }
    return (void *)pkeyCtx;
}

static int32_t TestEccSetPara(TestEccKeyCtx *ctx, const BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        return CRYPT_NULL_INPUT;
    }
    const BSL_Param *para = TestFindConstParam(param, CRYPT_PARAM_EC_CURVE_ID);
    if (para != NULL) {
        if (para->value == NULL || para->valueType != BSL_PARAM_TYPE_INT32 ||
            para->valueLen != sizeof(int32_t)) {
            return CRYPT_INVALID_ARG;
        }
        ctx->paraId = *((int32_t *)para->value);
    }

    return CRYPT_SUCCESS;
}

static int32_t TestEccGetParaPara(TestEccKeyCtx *ctx, BSL_Param *param)
{
    (void)ctx;
    (void)param;
    return CRYPT_SUCCESS;
}

static void RandFunc(uint8_t *randNum, uint32_t randLen)
{
    for (uint32_t i = 0; i < randLen; i++) {
        randNum[i] = (uint8_t)(rand() % UINT8_MAX_NUM);
    }
}

static int32_t TestEccGenKey(TestEccKeyCtx *ctx)
{
    if (ctx == NULL) {
        return CRYPT_NULL_INPUT;
    }
    if (ctx->paraId == BSL_CID_SECP384R1) {
        ctx->prvkeyLen = 48;
        ctx->pubkeyLen = 110;
    } else if (ctx->paraId == NEW_PARA_ALGID) {
        ctx->prvkeyLen = 66;
        ctx->pubkeyLen = 143;
    } else {
        return CRYPT_INVALID_ARG;
    }
    RandFunc(ctx->prvkey, ctx->prvkeyLen);
    RandFunc(ctx->pubkey, ctx->pubkeyLen);
    
    return CRYPT_SUCCESS;
}

static int32_t TestEccSetPrvKey(TestEccKeyCtx *ctx, const BSL_Param *para)
{
    if (ctx == NULL || para == NULL) {
        return CRYPT_NULL_INPUT;
    }
    const BSL_Param *prv = TestFindConstParam(para, CRYPT_PARAM_EC_PRVKEY);
    if (prv == NULL || prv->value == NULL || prv->valueLen == 0) {
        return CRYPT_NULL_INPUT;
    }
    (void)memcpy(ctx->prvkey, prv->value, prv->valueLen);
    ctx->prvkeyLen = prv->valueLen;
    return CRYPT_SUCCESS;
}

static int32_t TestEccSetPubKey(TestEccKeyCtx *ctx, const BSL_Param *para)
{
    if (ctx == NULL || para == NULL) {
        return CRYPT_NULL_INPUT;
    }
    const BSL_Param *pub = TestFindConstParam(para, CRYPT_PARAM_EC_PUBKEY);
    if (pub == NULL) {
        pub = TestFindConstParam(para, CRYPT_PARAM_PKEY_ENCODE_PUBKEY);
    }
    if (pub == NULL || pub->value == NULL || pub->valueLen == 0) {
        return CRYPT_NULL_INPUT;
    }
    (void)memcpy(ctx->pubkey, pub->value, pub->valueLen);
    ctx->pubkeyLen = pub->valueLen;
    return CRYPT_SUCCESS;
}

static int32_t TestEccGetPrvKey(TestEccKeyCtx *ctx, BSL_Param *para)
{
    if (ctx == NULL || para == NULL) {
        return CRYPT_NULL_INPUT;
    }
    BSL_Param *prv = TestFindParam(para, CRYPT_PARAM_EC_PRVKEY);
    if (prv == NULL || prv->value == NULL) {
        return CRYPT_NULL_INPUT;
    }
    if (prv->valueLen < ctx->prvkeyLen) {
        return CRYPT_ECDSA_BUFF_LEN_NOT_ENOUGH;
    }
    (void)memcpy(prv->value, ctx->prvkey, ctx->prvkeyLen);
    prv->useLen = ctx->prvkeyLen;
    return CRYPT_SUCCESS;
}

static int32_t TestEccGetPubKey(TestEccKeyCtx *ctx, BSL_Param *para)
{
    if (ctx == NULL || para == NULL) {
        return CRYPT_NULL_INPUT;
    }
    BSL_Param *pub = TestFindParam(para, CRYPT_PARAM_EC_PUBKEY);
    if (pub == NULL) {
        pub = TestFindParam(para, CRYPT_PARAM_PKEY_ENCODE_PUBKEY);
    }
    if (pub == NULL || pub->value == NULL || pub->valueLen == 0) {
        return CRYPT_NULL_INPUT;
    }
    if (ctx->pubkey == NULL) {
        return CRYPT_ECC_PKEY_ERR_EMPTY_KEY;
    }
    (void)memcpy(para->value, ctx->pubkey, ctx->pubkeyLen);
    para->useLen = ctx->pubkeyLen;
    return CRYPT_SUCCESS;
}

static void *TestEccDupCtx(const void *ctx)
{
    void *dest = malloc(sizeof(TestEccKeyCtx));
    if (dest == NULL) {
        return NULL;
    }
    (void)memcpy(dest, ctx, sizeof(TestEccKeyCtx));
    return dest;
}

int32_t TestEccCtrl(TestEccKeyCtx *ctx, int32_t cmd, void *val, uint32_t valLen)
{
    if (ctx == NULL || val == NULL || valLen == 0) {
        return CRYPT_NULL_INPUT;
    }
    switch (cmd) {
        case CRYPT_CTRL_GET_SECBITS:
            *((uint32_t *)val) = ctx->paraId == BSL_CID_SECP384R1 ? 128 : 1024;
            break;
        case CRYPT_CTRL_GET_PARAID:
            *((int32_t *)val) = ctx->paraId;
            break;
        case CRYPT_CTRL_SET_PARA_BY_ID:
            if (*((int32_t *)val) != BSL_CID_SECP384R1 && *((int32_t *)val) != NEW_PARA_ALGID) {
                return CRYPT_INVALID_ARG;
            }
            ctx->paraId = *((int32_t *)val);
            break;
        case CRYPT_CTRL_GET_SIGNLEN:
            *((uint32_t *)val) = TEST_CRYPT_DEFAULT_SIGNLEN;
            break;
        default:
            return CRYPT_NOT_SUPPORT;
    }
    return CRYPT_SUCCESS;
}

static int32_t TestEccSign(const TestEccKeyCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
    uint8_t *sign, uint32_t *signLen)
{
    (void)algId;
    if (ctx == NULL || data == NULL || sign == NULL || signLen == NULL) {
        return CRYPT_NULL_INPUT;
    }
    if (*signLen < TEST_CRYPT_DEFAULT_SIGNLEN) {
        return CRYPT_INVALID_ARG;
    }
    sign[0] = 0x30;
    sign[1] = 0x44;
    sign[2] = 0x02;
    sign[3] = 0x20;
    for (size_t i = 0; i < 32; i++) {
        sign[i + 4] = ctx->pubkey[i];
    }
    sign[36] = 0x02;
    sign[37] = 0x20;
    for (size_t i = 0; i < 32; i++) {
        sign[i + 38] = ctx->pubkey[i + 32];
    }
    *signLen = TEST_CRYPT_DEFAULT_SIGNLEN;
    return CRYPT_SUCCESS;
}

static void TestEccFreeCtx(TestEccKeyCtx *ctx)
{
    if (ctx != NULL) {
        free(ctx);
    }
}

static int32_t TestEccVerify(const TestEccKeyCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
    const uint8_t *sign, uint32_t signLen)
{
    (void)algId;
    (void)data;
    (void)dataLen;
    if (ctx == NULL || sign == NULL || signLen == 0) {
        return CRYPT_NULL_INPUT;
    }
    if (signLen < TEST_CRYPT_DEFAULT_SIGNLEN) {
        return CRYPT_INVALID_ARG;
    }
    if (sign[0] != 0x30 || sign[1] != 0x44) {
        return CRYPT_ECDSA_VERIFY_FAIL;
    }
    if (sign[2] != 0x02 || sign[3] != 0x20) {
        return CRYPT_ECDSA_VERIFY_FAIL;
    }
    if (sign[36] != 0x02 || sign[37] != 0x20) {
        return CRYPT_ECDSA_VERIFY_FAIL;
    }
    if (memcmp(ctx->pubkey, sign + 4, 32) != 0) {
        return CRYPT_ECDSA_VERIFY_FAIL;
    }
    if (memcmp(ctx->pubkey + 32, sign + 38, 32) != 0) {
        return CRYPT_ECDSA_VERIFY_FAIL;
    }

    return CRYPT_SUCCESS;
}

static int32_t TestEccPkeyExch(const TestEccKeyCtx *ctx, const TestEccKeyCtx *pubCtx, uint8_t *out, uint32_t *outLen)
{
    if (ctx == NULL || pubCtx == NULL || out == NULL || outLen == NULL) {
        return CRYPT_NULL_INPUT;
    }
    int32_t len = pubCtx->pubkeyLen < ctx->pubkeyLen ? pubCtx->pubkeyLen : ctx->pubkeyLen;
    for (uint32_t i = 0; i < len; i++) {
        out[i] = (ctx->pubkey[i] + pubCtx->pubkey[i]) % 256;
    }
    *outLen = len;
    return CRYPT_SUCCESS;
}

int32_t TestEccImport(void *ctx, const BSL_Param *params)
{
    if (ctx == NULL || params == NULL) {
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CRYPT_SUCCESS;
    const BSL_Param *curve = TestFindConstParam(params, CRYPT_PARAM_EC_CURVE_ID);
    const BSL_Param *pub = TestFindConstParam(params, CRYPT_PARAM_EC_PUBKEY);
    const BSL_Param *prv = TestFindConstParam(params, CRYPT_PARAM_EC_PRVKEY);
    if (curve != NULL) {
        ret = TestEccSetPara(ctx, params);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
    if (pub != NULL) {
        ret = TestEccSetPubKey(ctx, params);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
    if (prv != NULL) {
        ret = TestEccSetPrvKey(ctx, params);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
    return ret;
}

int32_t TestEccExport(void *ctx, BSL_Param *params)
{
    (void)ctx;
    (void)params;
    return CRYPT_SUCCESS;
}

void *TestPkeyMgmtKemNewCtx(void *provCtx, int32_t algId)
{
    TestKemKeyCtx *ctx = NULL;
    if (algId != NEW_KEM_ALGID) {
        return NULL;
    }
    ctx = (TestKemKeyCtx *)malloc(sizeof(TestKemKeyCtx));
    if (ctx == NULL) {
        return NULL;
    }
    memset(ctx, 0, sizeof(TestKemKeyCtx));
    return ctx;
}

static int32_t TestKemGenKey(TestKemKeyCtx *ctx)
{
    if (ctx == NULL) {
        return CRYPT_NULL_INPUT;
    }
    if (ctx->paraId == NEW_KEM_PARAM_ID) {
        ctx->pubkeyLen = 20;
    } else {
        return CRYPT_INVALID_ARG;
    }
    RandFunc(ctx->pubkey, ctx->pubkeyLen);
    return CRYPT_SUCCESS;
}

static int32_t TestKemSetPubKey(TestKemKeyCtx *ctx, const BSL_Param *para)
{
    if (ctx == NULL || para == NULL) {
        return CRYPT_NULL_INPUT;
    }
    const BSL_Param *pub = TestFindConstParam(para, CRYPT_PARAM_PKEY_ENCODE_PUBKEY);
    if (pub == NULL || pub->value == NULL || pub->valueLen == 0) {
        return CRYPT_NULL_INPUT;
    }
    (void)memcpy(ctx->pubkey, pub->value, pub->valueLen);
    ctx->pubkeyLen = pub->valueLen;
    return CRYPT_SUCCESS;
}

static int32_t TestKemGetPubKey(const TestKemKeyCtx *ctx, BSL_Param *para)
{
    if (ctx == NULL || para == NULL) {
        return CRYPT_NULL_INPUT;
    }
    BSL_Param *pub = (BSL_Param *)(uintptr_t)TestFindConstParam(para, CRYPT_PARAM_PKEY_ENCODE_PUBKEY);
    if (pub == NULL || pub->value == NULL || pub->valueLen == 0) {
        return CRYPT_NULL_INPUT;
    }
    (void)memcpy(pub->value, ctx->pubkey, ctx->pubkeyLen);
    pub->useLen = ctx->pubkeyLen;
    return CRYPT_SUCCESS;
}

static int32_t TestKemCtrl(TestKemKeyCtx *ctx, int32_t cmd, void *val, uint32_t valLen)
{
    if (ctx == NULL || val == NULL || valLen == 0) {
        return CRYPT_NULL_INPUT;
    }
    switch (cmd) {
        case CRYPT_CTRL_SET_PARA_BY_ID:
            if (*((int32_t *)val) != NEW_KEM_PARAM_ID) {
                return CRYPT_INVALID_ARG;
            }
            ctx->paraId = *((int32_t *)val);
            break;
        default:
            return CRYPT_NOT_SUPPORT;
    }
    return CRYPT_SUCCESS;
}

static void TestKemFreeCtx(TestKemKeyCtx *ctx)
{
    if (ctx != NULL) {
        free(ctx);
    }
}

static int32_t TestEccCheck(const TestEccKeyCtx *ctx1, const TestEccKeyCtx *ctx2)
{
    (void)ctx1;
    (void)ctx2;
    return CRYPT_SUCCESS;
}

const CRYPT_EAL_Func g_testKeyMgmtEcdsa[] = {
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (CRYPT_EAL_ImplPkeyMgmtNewCtx)TestPkeyMgmtEcNewCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPARAM, (CRYPT_EAL_ImplPkeyMgmtSetParam)TestEccSetPara},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPARAM, (CRYPT_EAL_ImplPkeyMgmtGetParam)TestEccGetParaPara},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, (CRYPT_EAL_ImplPkeyMgmtGenKey)TestEccGenKey},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, (CRYPT_EAL_ImplPkeyMgmtSetPrv)TestEccSetPrvKey},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, (CRYPT_EAL_ImplPkeyMgmtSetPub)TestEccSetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, (CRYPT_EAL_ImplPkeyMgmtGetPrv)TestEccGetPrvKey},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, (CRYPT_EAL_ImplPkeyMgmtGetPub)TestEccGetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, (CRYPT_EAL_ImplPkeyMgmtDupCtx)TestEccDupCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, (CRYPT_EAL_ImplPkeyMgmtCtrl)TestEccCtrl},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, (CRYPT_EAL_ImplPkeyMgmtFreeCtx)TestEccFreeCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_IMPORT, (CRYPT_EAL_ImplPkeyMgmtImport)TestEccImport},
    {CRYPT_EAL_IMPLPKEYMGMT_EXPORT, (CRYPT_EAL_ImplPkeyMgmtExport)TestEccExport},
    {CRYPT_EAL_IMPLPKEYMGMT_CHECK, (CRYPT_EAL_ImplPkeyMgmtCheck)TestEccCheck},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_testKeyMgmtEcdh[] = {
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (CRYPT_EAL_ImplPkeyMgmtNewCtx)TestPkeyMgmtEcNewCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPARAM, (CRYPT_EAL_ImplPkeyMgmtSetParam)TestEccSetPara},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPARAM, (CRYPT_EAL_ImplPkeyMgmtGetParam)TestEccGetParaPara},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, (CRYPT_EAL_ImplPkeyMgmtGenKey)TestEccGenKey},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, (CRYPT_EAL_ImplPkeyMgmtSetPrv)TestEccSetPrvKey},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, (CRYPT_EAL_ImplPkeyMgmtSetPub)TestEccSetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, (CRYPT_EAL_ImplPkeyMgmtGetPrv)TestEccGetPrvKey},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, (CRYPT_EAL_ImplPkeyMgmtGetPub)TestEccGetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, (CRYPT_EAL_ImplPkeyMgmtDupCtx)TestEccDupCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, (CRYPT_EAL_ImplPkeyMgmtCtrl)TestEccCtrl},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, (CRYPT_EAL_ImplPkeyMgmtFreeCtx)TestEccFreeCtx},
    CRYPT_EAL_FUNC_END,
};


const CRYPT_EAL_Func g_testKeyMgmtKem[] = {
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (CRYPT_EAL_ImplPkeyMgmtNewCtx)TestPkeyMgmtKemNewCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, (CRYPT_EAL_ImplPkeyMgmtGenKey)TestKemGenKey},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, (CRYPT_EAL_ImplPkeyMgmtSetPub)TestKemSetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, (CRYPT_EAL_ImplPkeyMgmtGetPub)TestKemGetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, (CRYPT_EAL_ImplPkeyMgmtCtrl)TestKemCtrl},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, (CRYPT_EAL_ImplPkeyMgmtFreeCtx)TestKemFreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_testEcdsaSign[] = {
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, (CRYPT_EAL_ImplPkeySign)TestEccSign},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, (CRYPT_EAL_ImplPkeyVerify)TestEccVerify},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_testExchDh[] = {
    {CRYPT_EAL_IMPLPKEYEXCH_EXCH, (CRYPT_EAL_ImplPkeyExch)TestEccPkeyExch},
    CRYPT_EAL_FUNC_END
};

static int32_t TestKemEncapsulate(const void *pkey, uint8_t *cipher, uint32_t *cipherLen, uint8_t *out, uint32_t *outLen)
{
    TestKemKeyCtx *ctx = (TestKemKeyCtx *)(uintptr_t)pkey;
    if (ctx == NULL || cipherLen == NULL || cipher == NULL) {
        return CRYPT_NULL_INPUT;
    }
    if (*cipherLen < 40 || ctx->pubkeyLen != 20) {
        return CRYPT_INVALID_ARG;
    }
    ctx->sharedLen = 20;
    RandFunc(ctx->shared, ctx->sharedLen);
    memcpy(cipher, ctx->pubkey, ctx->pubkeyLen);
    memcpy(&cipher[ctx->pubkeyLen], ctx->shared, ctx->sharedLen);
    memcpy(out, ctx->shared, ctx->sharedLen);
    *outLen = ctx->sharedLen;
    *cipherLen = ctx->pubkeyLen + ctx->sharedLen;
    return CRYPT_SUCCESS;
}

static int32_t TestKemDecapsulate(const void *pkey, uint8_t *data, uint32_t dataLen, uint8_t *out, uint32_t *outLen)
{
    const TestKemKeyCtx *ctx = pkey;
    if (dataLen != 40 || ctx->pubkeyLen != 20 || *outLen < 20) {
        return CRYPT_INVALID_ARG;
    }
    if (memcmp(data, ctx->pubkey, ctx->pubkeyLen) != 0) {
        return CRYPT_INVALID_ARG;
    }
    memcpy(out, &data[ctx->pubkeyLen], dataLen - ctx->pubkeyLen);
    *outLen = dataLen - ctx->pubkeyLen; // 20
    return CRYPT_SUCCESS;
}

const CRYPT_EAL_Func g_testKemInfo[] = {
    {CRYPT_EAL_IMPLPKEYKEM_ENCAPSULATE, (CRYPT_EAL_ImplPkeyKemEncapsulate)TestKemEncapsulate},
    {CRYPT_EAL_IMPLPKEYKEM_DECAPSULATE, (CRYPT_EAL_ImplPkeyKemDecapsulate)TestKemDecapsulate},
    CRYPT_EAL_FUNC_END
};

static CRYPT_EAL_AlgInfo g_testKeyMgmt[] = {
    {CRYPT_PKEY_ECDSA, g_testKeyMgmtEcdsa, "provider=provider_get_cap_test1"}, // For computing sign
    {NEW_PKEY_ALGID, g_testKeyMgmtEcdh, "provider=provider_get_cap_test1"}, // For computing the shared key
    {NEW_KEM_ALGID, g_testKeyMgmtKem, "provider=provider_get_cap_test1"}, // For computing the shared key
    CRYPT_EAL_ALGINFO_END
};

static CRYPT_EAL_AlgInfo g_testSign[] = {
    {CRYPT_PKEY_ECDSA, g_testEcdsaSign, "provider=provider_get_cap_test1"}, // ecdsa nistp2516 sign
    CRYPT_EAL_ALGINFO_END
};

static CRYPT_EAL_AlgInfo g_testKeyExch[] = {
    {NEW_PKEY_ALGID, g_testExchDh, "provider=provider_get_cap_test1"}, // For computing the shared key
    CRYPT_EAL_ALGINFO_END
};

void *TEST_DRBG_RandNewCtx(void *provCtx, int32_t algId, BSL_Param *param)
{
    (void)provCtx;
    (void)algId;
    (void)param;
    return malloc(1);
}

int32_t TEST_DRBG_Instantiate(void *ctx, const uint8_t *person, uint32_t persLen, BSL_Param *param)
{
    (void)ctx;
    (void)person;
    (void)persLen;
    (void)param;
    return CRYPT_SUCCESS;
}

int32_t TEST_DRBG_Uninstantiate(void *ctx)
{
    (void)ctx;
    return CRYPT_SUCCESS;
}

int32_t TEST_DRBG_Generate(void *ctx, uint8_t *out, uint32_t outLen,
    const uint8_t *adin, uint32_t adinLen,  BSL_Param *param)
{
    (void)ctx;
    (void)adin;
    (void)adinLen;
    (void)param;
    RandFunc(out, outLen);
    return CRYPT_SUCCESS;
}

int32_t TEST_DRBG_Reseed(void *ctx, const uint8_t *adin, uint32_t adinLen, BSL_Param *param)
{
    (void)ctx;
    (void)adin;
    (void)adinLen;
    (void)param;
    return CRYPT_SUCCESS;
}

int32_t TEST_DRBG_Ctrl(void *ctx, int32_t cmd, void *val, uint32_t valLen)
{
    (void)ctx;
    (void)cmd;
    (void)val;
    (void)valLen;
    return CRYPT_SUCCESS;
}

void TEST_DRBG_Free(void *ctx)
{
    free(ctx);
}

const CRYPT_EAL_Func g_testRand[] = {
    {CRYPT_EAL_IMPLRAND_DRBGNEWCTX, (CRYPT_EAL_ImplRandDrbgNewCtx)TEST_DRBG_RandNewCtx},
    {CRYPT_EAL_IMPLRAND_DRBGINST, (CRYPT_EAL_ImplRandDrbgInst)TEST_DRBG_Instantiate},
    {CRYPT_EAL_IMPLRAND_DRBGUNINST, (CRYPT_EAL_ImplRandDrbgUnInst)TEST_DRBG_Uninstantiate},
    {CRYPT_EAL_IMPLRAND_DRBGGEN, (CRYPT_EAL_ImplRandDrbgGen)TEST_DRBG_Generate},
    {CRYPT_EAL_IMPLRAND_DRBGRESEED, (CRYPT_EAL_ImplRandDrbgReSeed)TEST_DRBG_Reseed},
    {CRYPT_EAL_IMPLRAND_DRBGCTRL, (CRYPT_EAL_ImplRandDrbgCtrl)TEST_DRBG_Ctrl},
    {CRYPT_EAL_IMPLRAND_DRBGFREECTX, (CRYPT_EAL_ImplRandDrbgFreeCtx)TEST_DRBG_Free},
    CRYPT_EAL_FUNC_END,
};

static CRYPT_EAL_AlgInfo g_testRands[] = {
    {CRYPT_RAND_SHA1, g_testRand, "provider=provider_get_cap_test1"},
    {CRYPT_RAND_SHA224, g_testRand, "provider=provider_get_cap_test1"},
    {CRYPT_RAND_SHA256, g_testRand, "provider=provider_get_cap_test1"},
    {CRYPT_RAND_SHA384, g_testRand, "provider=provider_get_cap_test1"},
    {CRYPT_RAND_SHA512, g_testRand, "provider=provider_get_cap_test1"},
    {CRYPT_RAND_HMAC_SHA1, g_testRand, "provider=provider_get_cap_test1"},
    {CRYPT_RAND_HMAC_SHA224, g_testRand, "provider=provider_get_cap_test1"},
    {CRYPT_RAND_HMAC_SHA256, g_testRand, "provider=provider_get_cap_test1"},
    {CRYPT_RAND_HMAC_SHA384, g_testRand, "provider=provider_get_cap_test1"},
    {CRYPT_RAND_HMAC_SHA512, g_testRand, "provider=provider_get_cap_test1"},
    {CRYPT_RAND_AES128_CTR, g_testRand, "provider=provider_get_cap_test1"},
    {CRYPT_RAND_AES192_CTR, g_testRand, "provider=provider_get_cap_test1"},
    {CRYPT_RAND_AES256_CTR, g_testRand, "provider=provider_get_cap_test1"},
    {CRYPT_RAND_AES128_CTR_DF, g_testRand, "provider=provider_get_cap_test1"},
    {CRYPT_RAND_AES192_CTR_DF, g_testRand, "provider=provider_get_cap_test1"},
    {CRYPT_RAND_AES256_CTR_DF, g_testRand, "provider=provider_get_cap_test1"},
    CRYPT_EAL_ALGINFO_END
};

static CRYPT_EAL_AlgInfo g_testKem[] = {
    {NEW_KEM_ALGID, g_testKemInfo, "provider=provider_get_cap_test1"}, // For computing the shared key
    CRYPT_EAL_ALGINFO_END
};

static int32_t TestProvQuery(void *provCtx, int32_t operaId, CRYPT_EAL_AlgInfo **algInfos)
{
    (void)provCtx;
    int32_t ret = CRYPT_SUCCESS;
    switch (operaId) {
        case CRYPT_EAL_OPERAID_KEYMGMT:
            *algInfos = g_testKeyMgmt;
            break;
        case CRYPT_EAL_OPERAID_SIGN:
            *algInfos = g_testSign;
            break;
        case CRYPT_EAL_OPERAID_KEYEXCH:
            *algInfos = g_testKeyExch;
            break;
        case CRYPT_EAL_OPERAID_RAND:
            *algInfos = g_testRands;
            break;
        case CRYPT_EAL_OPERAID_KEM:
            *algInfos = g_testKem;
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

static int32_t TestCryptGetSigAlgCaps(CRYPT_EAL_ProcessFuncCb cb, void *args)
{
    if (cb == NULL) {
        return CRYPT_NULL_INPUT;
    }
    uint16_t signatureScheme = 23333;
    int32_t keyType = CRYPT_PKEY_ECDSA;
    int32_t paraId = BSL_CID_SECP384R1;
    int32_t signHashAlgId = NEW_SIGN_HASH_ALGID;
    int32_t signAlgId = CRYPT_PKEY_ECDSA;
    int32_t hashAlgId = NEW_HASH_ALGID;
    int32_t secBits = 1024;
    uint32_t certVersionBits = TLS12_VERSION_BIT | TLS13_VERSION_BIT;
    uint32_t chainVersionBits = TLS12_VERSION_BIT | TLS13_VERSION_BIT;
    BSL_Param param[] = {
        {
            CRYPT_PARAM_CAP_TLS_SIGNALG_IANA_SIGN_NAME,
            BSL_PARAM_TYPE_OCTETS_PTR,
            (void *)(uintptr_t)"test_new_sign_alg_name",
            (uint32_t)strlen("test_new_sign_alg_name")
        },
        {
            CRYPT_PARAM_CAP_TLS_SIGNALG_IANA_SIGN_ID,
            BSL_PARAM_TYPE_UINT16,
            (void *)(uintptr_t)&(signatureScheme),
            sizeof(uint16_t)
        },
        {
            CRYPT_PARAM_CAP_TLS_SIGNALG_KEY_TYPE,
            BSL_PARAM_TYPE_INT32,
            (void *)(uintptr_t)&(keyType),
            sizeof(keyType)
        },
        {
            CRYPT_PARAM_CAP_TLS_SIGNALG_PARA_ID,
            BSL_PARAM_TYPE_INT32,
            (void *)(uintptr_t)&(paraId),
            sizeof(paraId)
        },
        {
            CRYPT_PARAM_CAP_TLS_SIGNALG_SIGNWITHMD_ID,
            BSL_PARAM_TYPE_INT32,
            (void *)(uintptr_t)&(signHashAlgId),
            sizeof(signHashAlgId)
        },
        {
            CRYPT_PARAM_CAP_TLS_SIGNALG_SIGNWITHMD_OID,
            BSL_PARAM_TYPE_OCTETS_PTR,
            (void *)(uintptr_t)"\150\40\66\77\55", // 68 20 36 3F 2D
            (uint32_t)strlen("\150\40\66\77\55")
        },
        {
            CRYPT_PARAM_CAP_TLS_SIGNALG_SIGNWITHMD_NAME,
            BSL_PARAM_TYPE_OCTETS_PTR,
            (void *)(uintptr_t)"test_new_sign_with_md_name",
            (uint32_t)strlen("test_new_sign_with_md_name")
        },
        {
            CRYPT_PARAM_CAP_TLS_SIGNALG_SIGN_ID,
            BSL_PARAM_TYPE_INT32,
            (void *)(uintptr_t)&(signAlgId),
            sizeof(signAlgId)
        },
        {
            CRYPT_PARAM_CAP_TLS_SIGNALG_MD_ID,
            BSL_PARAM_TYPE_INT32,
            (void *)(uintptr_t)&(hashAlgId),
            sizeof(hashAlgId)
        },
        {
            CRYPT_PARAM_CAP_TLS_SIGNALG_MD_OID,
            BSL_PARAM_TYPE_OCTETS_PTR,
            (void *)(uintptr_t)"\150\40\66\71\55",
            (uint32_t)strlen("\150\40\66\71\55")
        },
        {
            CRYPT_PARAM_CAP_TLS_SIGNALG_MD_NAME,
            BSL_PARAM_TYPE_OCTETS_PTR,
            (void *)(uintptr_t)"test_new_md_name",
            (uint32_t)strlen("test_new_md_name")
        },
        {
            CRYPT_PARAM_CAP_TLS_SIGNALG_SEC_BITS,
            BSL_PARAM_TYPE_INT32,
            (void *)(uintptr_t)&(secBits),
            sizeof(secBits)
        },
        {
            CRYPT_PARAM_CAP_TLS_SIGNALG_CHAIN_VERSION_BITS,
            BSL_PARAM_TYPE_UINT32,
            (void *)(uintptr_t)&(chainVersionBits),
            sizeof(chainVersionBits)
        },
        {
            CRYPT_PARAM_CAP_TLS_SIGNALG_CERT_VERSION_BITS,
            BSL_PARAM_TYPE_UINT32,
            (void *)(uintptr_t)&(certVersionBits),
            sizeof(certVersionBits)
        },
        BSL_PARAM_END
    };
    return cb(param, args);
}

static const Provider_Group g_tlsGroupInfo[] = {
    {
        "test_new_group",
        NEW_PARA_ALGID,      // paraId
        NEW_PKEY_ALGID,      // algId
        1024,                // secBits
        477,                 // groupId
        143,                 // pubkeyLen
        143,                 // sharedkeyLen
        0,                   // ciphertextLen
        TLS12_VERSION_BIT | TLS13_VERSION_BIT,  // versionBits
        false               // isKem
    },
    {
        "test_new_group_kem",
        NEW_KEM_PARAM_ID,      // paraId
        NEW_KEM_ALGID,      // algId
        1024,                // secBits
        478,                 // groupId
        20,                 // pubkeyLen
        20,                 // sharedkeyLen
        40,                   // ciphertextLen
        TLS13_VERSION_BIT,  // versionBits
        true                // isKem
    }
};

static int32_t TestProvGetCaps(void *provCtx, int32_t cmd, CRYPT_EAL_ProcessFuncCb cb, void *args)
{
    switch (cmd) {
        case CRYPT_EAL_GET_GROUP_CAP:
            return TestCryptGetGroupCaps(g_tlsGroupInfo, sizeof(g_tlsGroupInfo) / sizeof(g_tlsGroupInfo[0]), cb, args);
        case CRYPT_EAL_GET_SIGALG_CAP:
            return TestCryptGetSigAlgCaps(cb, args);
        default:
            return CRYPT_NOT_SUPPORT;
    }
}

static CRYPT_EAL_Func g_testProvOutFuncs[] = {
    {CRYPT_EAL_PROVCB_QUERY, TestProvQuery},
    {CRYPT_EAL_PROVCB_FREE, TestProvFree},
    {CRYPT_EAL_PROVCB_CTRL, NULL},
    {CRYPT_EAL_PROVCB_GETCAPS, TestProvGetCaps},
    CRYPT_EAL_FUNC_END
};

int32_t CRYPT_EAL_ProviderInit(CRYPT_EAL_ProvMgrCtx *mgrCtx, BSL_Param *param,
    CRYPT_EAL_Func *capFuncs, CRYPT_EAL_Func **outFuncs, void **provCtx)
{
   *outFuncs = g_testProvOutFuncs;
    return CRYPT_SUCCESS;
}
