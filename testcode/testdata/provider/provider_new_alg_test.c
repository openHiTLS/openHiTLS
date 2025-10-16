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
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "bsl_obj.h"
#include "bsl_err.h"
#include "bsl_params.h"
#include "bsl_asn1_internal.h"
#include "bsl_obj_internal.h"
#include "crypt_codecskey.h"
#include "crypt_errno.h"
#include "crypt_params_key.h"
#include "crypt_eal_implprovider.h"
#include "hitls_type.h"
#include "crypt_params_key.h"
#include "provider_test_utils.h"

#define NEW_PARA_ALGID (BSL_CID_MAX + 5)
#define NEW_PKEY_ALGID (BSL_CID_MAX + 6)
#define NEW_SIGN_HASH_ALGID (BSL_CID_MAX + 7)
#define NEW_HASH_ALGID (BSL_CID_MAX + 8)
#define TEST_CRYPT_DEFAULT_SIGNLEN 68
#define UINT8_MAX_NUM 255

#define CRYPT_PARAM_NEW_KEY_BASE        3000
#define CRYPT_PARAM_NEW_KEY_PRVKEY      (CRYPT_PARAM_NEW_KEY_BASE + 1)
#define CRYPT_PARAM_NEW_KEY_PUBKEY      (CRYPT_PARAM_NEW_KEY_BASE + 2)
#define CRYPT_PARAM_NEW_KEY_GROUP       (CRYPT_PARAM_NEW_KEY_BASE + 3)

typedef struct {
    CRYPT_EAL_ProvMgrCtx *mgrCtxHandle;
} TestProvCtx;

typedef struct {
    uint8_t prvkey[72];      // Private key
    uint32_t prvkeyLen;      // Private key length
    uint8_t pubkey[256];     // Public key
    uint32_t pubkeyLen;      // Public key length
    int32_t paraId;          // Parameter ID
} TestNewKeyCtx;
typedef struct {
    CRYPT_EAL_ProvMgrCtx *provMgrCtx;
    int32_t keyAlgId;
    const char *outFormat;
    const char *outType;
} TestNewAlgDer2KeyCtx;

static void RandFunc(uint8_t *randNum, uint32_t randLen)
{
    for (uint32_t i = 0; i < randLen; i++) {
        randNum[i] = (uint8_t)(rand() % UINT8_MAX_NUM);
    }
}

void *TestNewKeyMgmtNewCtx(void *provCtx, int32_t algId)
{
    (void)provCtx;
    (void)algId;
    TestNewKeyCtx *pkeyCtx = malloc(sizeof(TestNewKeyCtx));
    if (pkeyCtx == NULL) {
        return NULL;
    }
    return (void *)pkeyCtx;
}

static int32_t TestNewKeySetPara(TestNewKeyCtx *ctx, const BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        return CRYPT_NULL_INPUT;
    }
    const BSL_Param *para = TestFindConstParam(param, CRYPT_PARAM_NEW_KEY_GROUP);
    if (para != NULL) {
        if (para->value == NULL || para->valueType != BSL_PARAM_TYPE_INT32 ||
            para->valueLen != sizeof(int32_t)) {
            return CRYPT_INVALID_ARG;
        }
        ctx->paraId = *((int32_t *)para->value);
    }
    return CRYPT_SUCCESS;
}

static int32_t TestNewKeyGenKey(TestNewKeyCtx *ctx)
{
    if (ctx == NULL) {
        return CRYPT_NULL_INPUT;
    }
    if (ctx->paraId != NEW_PARA_ALGID) {
        return CRYPT_INVALID_ARG;
    }
    ctx->prvkeyLen = 66;
    ctx->pubkeyLen = 143;
    RandFunc(ctx->prvkey, ctx->prvkeyLen);
    RandFunc(ctx->pubkey, ctx->pubkeyLen);
    return CRYPT_SUCCESS;
}

static int32_t TestNewKeySetPrvKey(TestNewKeyCtx *ctx, const BSL_Param *para)
{
    if (ctx == NULL || para == NULL) {
        return CRYPT_NULL_INPUT;
    }
    const BSL_Param *prv = TestFindConstParam(para, CRYPT_PARAM_NEW_KEY_PRVKEY);
    if (prv == NULL || prv->value == NULL || prv->valueLen == 0) {
        return CRYPT_NULL_INPUT;
    }
    (void)memcpy(ctx->prvkey, prv->value, prv->valueLen);
    ctx->prvkeyLen = prv->valueLen;
    return CRYPT_SUCCESS;
}

static int32_t TestNewKeySetPubKey(TestNewKeyCtx *ctx, const BSL_Param *para)
{
    if (ctx == NULL || para == NULL) {
        return CRYPT_NULL_INPUT;
    }
    const BSL_Param *pub = TestFindConstParam(para, CRYPT_PARAM_NEW_KEY_PUBKEY);
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

static int32_t TestNewKeyGetPrvKey(TestNewKeyCtx *ctx, BSL_Param *para)
{
    if (ctx == NULL || para == NULL) {
        return CRYPT_NULL_INPUT;
    }
    BSL_Param *prv = TestFindParam(para, CRYPT_PARAM_NEW_KEY_PRVKEY);
    if (prv == NULL) {
        return CRYPT_NULL_INPUT;
    }
    if (prv->valueLen < ctx->prvkeyLen) {
        return CRYPT_INVALID_ARG;
    }
    (void)memcpy(prv->value, ctx->prvkey, ctx->prvkeyLen);
    prv->useLen = ctx->prvkeyLen;
    return CRYPT_SUCCESS;
}

static int32_t TestNewKeyGetPubKey(TestNewKeyCtx *ctx, BSL_Param *para)
{
    if (ctx == NULL || para == NULL) {
        return CRYPT_NULL_INPUT;
    }
    BSL_Param *pub = TestFindParam(para, CRYPT_PARAM_NEW_KEY_PUBKEY);
    if (pub == NULL) {
        pub = TestFindParam(para, CRYPT_PARAM_PKEY_ENCODE_PUBKEY);
    }
    if (pub == NULL || pub->value == NULL || pub->valueLen == 0) {
        return CRYPT_NULL_INPUT;
    }
    if (ctx->pubkey == NULL) {
        return CRYPT_ECC_PKEY_ERR_EMPTY_KEY;
    }
    (void)memcpy(pub->value, ctx->pubkey, ctx->pubkeyLen);
    pub->useLen = ctx->pubkeyLen;
    return CRYPT_SUCCESS;
}

static int32_t TestNewKeySign(const TestNewKeyCtx *ctx, int32_t algId, 
                            const uint8_t *data, uint32_t dataLen,
                            uint8_t *sign, uint32_t *signLen)
{
    if (ctx == NULL || data == NULL || sign == NULL || signLen == NULL) {
        return CRYPT_NULL_INPUT;
    }
    
    if (*signLen < TEST_CRYPT_DEFAULT_SIGNLEN) {
        return CRYPT_INVALID_ARG;
    }
    sign[0] = 0x30;
    sign[1] = 0x42;
    sign[2] = 0x02;
    sign[3] = 0x40;
    for (uint32_t i = 4; i < TEST_CRYPT_DEFAULT_SIGNLEN; i++) {
        sign[i] = ctx->pubkey[(i - 4) % ctx->pubkeyLen];
    }
    *signLen = TEST_CRYPT_DEFAULT_SIGNLEN;
    
    return CRYPT_SUCCESS;
}

static int32_t TestNewKeyVerify(const TestNewKeyCtx *ctx, int32_t algId,
                              const uint8_t *data, uint32_t dataLen,
                              const uint8_t *sign, uint32_t signLen)
{
    if (ctx == NULL || data == NULL || sign == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (signLen != TEST_CRYPT_DEFAULT_SIGNLEN) {
        return CRYPT_INVALID_ARG;
    }
    if (sign[0] != 0x30 || sign[1] != 0x42) {
        return CRYPT_ECDSA_VERIFY_FAIL;
    }
    if (sign[2] != 0x02 || sign[3] != 0x40) {
        return CRYPT_ECDSA_VERIFY_FAIL;
    }
    for (uint32_t i = 4; i < TEST_CRYPT_DEFAULT_SIGNLEN; i++) {
        if (sign[i] != ctx->pubkey[(i - 4) % ctx->pubkeyLen]) {
            return CRYPT_ECDSA_VERIFY_FAIL;
        }
    }
    return CRYPT_SUCCESS;
}

static void TestNewKeyFreeCtx(TestNewKeyCtx *ctx)
{
    if (ctx != NULL) {
        free(ctx);
    }
}

static int32_t TestNewKeyCheck(const TestNewKeyCtx *ctx1, const TestNewKeyCtx *ctx2)
{
    (void)ctx1;
    (void)ctx2;
    return CRYPT_SUCCESS;
}

static int32_t TestNewKeyCtrl(TestNewKeyCtx *ctx, int32_t cmd, void *val, uint32_t valLen)
{
    if (ctx == NULL || val == NULL) {
        return CRYPT_NULL_INPUT;
    }
    if (valLen != sizeof(uint32_t)) {
        return CRYPT_INVALID_ARG;
    }
    switch (cmd) {
        case CRYPT_CTRL_GET_SECBITS:
            if (valLen != sizeof(uint32_t)) {
                return CRYPT_INVALID_ARG;
            }
            *((uint32_t *)val) = 2048;
            return CRYPT_SUCCESS;
        case CRYPT_CTRL_GET_PARAID:
            if (valLen != sizeof(uint32_t)) {
                return CRYPT_INVALID_ARG;
            }
            *((uint32_t *)val) = NEW_PARA_ALGID;
            return CRYPT_SUCCESS;
        case CRYPT_CTRL_SET_PARA_BY_ID:
            ctx->paraId = *((uint32_t *)val);
            return CRYPT_SUCCESS;
        case CRYPT_CTRL_GET_SIGNLEN:
            *((uint32_t *)val) = TEST_CRYPT_DEFAULT_SIGNLEN;
            return CRYPT_SUCCESS;
        default:
            return CRYPT_NOT_SUPPORT;
    }
}

static int32_t TestNewKeyImport(void *ctx, const BSL_Param *params)
{
    TestNewKeyCtx *keyCtx = (TestNewKeyCtx *)ctx;
    if (keyCtx == NULL || params == NULL) {
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CRYPT_SUCCESS;
    const BSL_Param *para = TestFindConstParam(params, CRYPT_PARAM_NEW_KEY_GROUP);
    const BSL_Param *prv = TestFindConstParam(params, CRYPT_PARAM_NEW_KEY_PRVKEY);
    const BSL_Param *pub = TestFindConstParam(params, CRYPT_PARAM_NEW_KEY_PUBKEY);
    if (para != NULL) {
        ret = TestNewKeySetPara(keyCtx, para);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
    if (prv != NULL) {
        ret = TestNewKeySetPrvKey(keyCtx, prv);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
    if (pub != NULL) {
        ret = TestNewKeySetPubKey(keyCtx, pub);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }

    return CRYPT_SUCCESS;
}

static void *TestNewKeyDupCtx(const void *ctx)
{
    void *dest = malloc(sizeof(TestNewKeyCtx));
    if (dest == NULL) {
        return NULL;
    }
    (void)memcpy(dest, ctx, sizeof(TestNewKeyCtx));
    return dest;
}

static int32_t TestNewKeyExport(void *ctx, BSL_Param *params)
{
    (void)ctx;
    (void)params;
    return CRYPT_SUCCESS;
}

static int32_t TestNewKeyExch(const void *ctx, const void *pubCtx, uint8_t *out, uint32_t *outLen)
{
    if (ctx == NULL || pubCtx == NULL || out == NULL || outLen == NULL) {
        return CRYPT_NULL_INPUT;
    }
    const TestNewKeyCtx *prvKeyCtx = ctx;
    const TestNewKeyCtx *pubKeyCtx = pubCtx;
    int32_t len = pubKeyCtx->pubkeyLen < prvKeyCtx->pubkeyLen ? pubKeyCtx->pubkeyLen : prvKeyCtx->pubkeyLen;
    for (uint32_t i = 0; i < len; i++) {
        out[i] = (prvKeyCtx->pubkey[i] + pubKeyCtx->pubkey[i]) % 256;
    }
    *outLen = len;
    return CRYPT_SUCCESS;
}

const CRYPT_EAL_Func g_testKeyMgmtNewKey[] = {
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (CRYPT_EAL_ImplPkeyMgmtNewCtx)TestNewKeyMgmtNewCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPARAM, (CRYPT_EAL_ImplPkeyMgmtSetParam)TestNewKeySetPara},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, (CRYPT_EAL_ImplPkeyMgmtGenKey)TestNewKeyGenKey},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, (CRYPT_EAL_ImplPkeyMgmtSetPrv)TestNewKeySetPrvKey},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, (CRYPT_EAL_ImplPkeyMgmtSetPub)TestNewKeySetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, (CRYPT_EAL_ImplPkeyMgmtGetPrv)TestNewKeyGetPrvKey},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, (CRYPT_EAL_ImplPkeyMgmtGetPub)TestNewKeyGetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, (CRYPT_EAL_ImplPkeyMgmtDupCtx)TestNewKeyDupCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, (CRYPT_EAL_ImplPkeyMgmtCtrl)TestNewKeyCtrl},
    {CRYPT_EAL_IMPLPKEYMGMT_IMPORT, (CRYPT_EAL_ImplPkeyMgmtImport)TestNewKeyImport},
    {CRYPT_EAL_IMPLPKEYMGMT_EXPORT, (CRYPT_EAL_ImplPkeyMgmtExport)TestNewKeyExport},
    {CRYPT_EAL_IMPLPKEYMGMT_CHECK, (CRYPT_EAL_ImplPkeyMgmtCheck)TestNewKeyCheck},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, (CRYPT_EAL_ImplPkeyMgmtFreeCtx)TestNewKeyFreeCtx},
    CRYPT_EAL_FUNC_END
};

const CRYPT_EAL_Func g_testSignNew[] = {
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, (void *)TestNewKeySign},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, (void *)TestNewKeyVerify},
    CRYPT_EAL_FUNC_END
};

const CRYPT_EAL_Func g_testExchDh[] = {
    {CRYPT_EAL_IMPLPKEYEXCH_EXCH, (CRYPT_EAL_ImplPkeyExch)TestNewKeyExch},
    CRYPT_EAL_FUNC_END
};

static CRYPT_EAL_AlgInfo g_testKeyMgmt[] = {
    {NEW_PKEY_ALGID, g_testKeyMgmtNewKey, "provider=provider_new_alg_test"},
    CRYPT_EAL_ALGINFO_END
};

static CRYPT_EAL_AlgInfo g_testSign[] = {
    {NEW_PKEY_ALGID, g_testSignNew, "provider=provider_new_alg_test"},
    CRYPT_EAL_ALGINFO_END
};

static CRYPT_EAL_AlgInfo g_testKeyExch[] = {
    {NEW_PKEY_ALGID, g_testExchDh, "provider=provider_new_alg_test"}, // For computing the shared key
    CRYPT_EAL_ALGINFO_END
};

static void *DECODER_NewAlgDer2Key_NewCtx(void *provCtx)
{
    (void)provCtx;
    TestNewAlgDer2KeyCtx *ctx = calloc(1, sizeof(TestNewAlgDer2KeyCtx));
    if (ctx == NULL) {
        return NULL;
    }
    ctx->outFormat = "OBJECT";
    ctx->outType = "LOW_KEY";
    ctx->keyAlgId = NEW_PKEY_ALGID;
    return ctx;
}

static int32_t DECODER_NewAlgDer2Key_GetParam(void *ctx, void *param)
{
    if (ctx == NULL || param == NULL) {
        return CRYPT_NULL_INPUT;
    }
    TestNewAlgDer2KeyCtx *decoderCtx = (TestNewAlgDer2KeyCtx *)ctx;
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

static int32_t DECODER_NewAlgDer2Key_SetParam(void *ctx, const void *param)
{
    TestNewAlgDer2KeyCtx *decoderCtx = (TestNewAlgDer2KeyCtx *)ctx;
    if (decoderCtx == NULL || param == NULL) {
        return CRYPT_NULL_INPUT;
    }

    const BSL_Param *input = TestFindConstParam(param, CRYPT_PARAM_DECODE_PROVIDER_CTX);
    if (input != NULL) {
        if (input->valueType != BSL_PARAM_TYPE_CTX_PTR || input->value == NULL) {
            return CRYPT_INVALID_ARG;
        }
        decoderCtx->provMgrCtx = (CRYPT_EAL_ProvMgrCtx *)(uintptr_t)input->value;
    }

    return CRYPT_SUCCESS;
}

#define BSL_ASN1_TAG_NEW_ALG_PRIKEY_PARAM 0

static BSL_ASN1_TemplateItem g_newAlgPrvTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},  // ignore seq header
        {BSL_ASN1_TAG_INTEGER, 0, 1}, /* version */
        {BSL_ASN1_TAG_OCTETSTRING, 0, 1}, /* private key */
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_NEW_ALG_PRIKEY_PARAM,
            BSL_ASN1_FLAG_OPTIONAL, 1},
            {BSL_ASN1_TAG_OBJECT_ID, 0, 2},
        {BSL_ASN1_TAG_OCTETSTRING, 0, 1}, /* private key */
};

typedef enum {
    CRYPT_NEW_ALG_PRV_VERSION_IDX = 0,
    CRYPT_NEW_ALG_PRV_PRVKEY_IDX = 1,
    CRYPT_NEW_ALG_PRV_PRIKEY_PARAM_IDX = 2,
    CRYPT_NEW_ALG_PRV_PUBKEY_IDX = 3,
} CRYPT_NEW_ALG_PRV_TEMPL_IDX;

static int32_t GetParaId(uint8_t *octs, uint32_t octsLen)
{
    BslOidString oidStr = {octsLen, (char *)octs, 0};
    BslCid cid = BSL_OBJ_GetCID(&oidStr);
    if (cid == BSL_CID_UNKNOWN) {
        return CRYPT_PKEY_PARAID_MAX;
    }
    return (int32_t)cid;
}

static int32_t ProcNewAlgKeyPair(uint8_t *buff, uint32_t buffLen, TestNewKeyCtx *newAlgKey)
{
    // decode n and e
    BSL_ASN1_Buffer asn1[CRYPT_NEW_ALG_PRV_PUBKEY_IDX + 1] = {0};
    uint8_t *tmpBuff = buff;
    uint32_t tmpBuffLen = buffLen;
    BSL_ASN1_Template templ = {g_newAlgPrvTempl, sizeof(g_newAlgPrvTempl) / sizeof(g_newAlgPrvTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &tmpBuff, &tmpBuffLen, asn1,
        CRYPT_NEW_ALG_PRV_PUBKEY_IDX + 1);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    const BSL_Param param1[2] = {
        {CRYPT_PARAM_NEW_KEY_PRVKEY, BSL_PARAM_TYPE_OCTETS, asn1[CRYPT_NEW_ALG_PRV_PRVKEY_IDX].buff,
            asn1[CRYPT_NEW_ALG_PRV_PRVKEY_IDX].len, 0},
        BSL_PARAM_END
    };
    ret = TestNewKeySetPrvKey(newAlgKey, param1);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    const BSL_Param param2[2] = {
        {CRYPT_PARAM_NEW_KEY_PUBKEY, BSL_PARAM_TYPE_OCTETS, asn1[CRYPT_NEW_ALG_PRV_PUBKEY_IDX].buff,
            asn1[CRYPT_NEW_ALG_PRV_PUBKEY_IDX].len, 0},
        BSL_PARAM_END
    };
    ret = TestNewKeySetPubKey(newAlgKey, param2);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    int32_t cid = GetParaId(asn1[CRYPT_NEW_ALG_PRV_PRIKEY_PARAM_IDX].buff, asn1[CRYPT_NEW_ALG_PRV_PRIKEY_PARAM_IDX].len);
    if (cid != NEW_PARA_ALGID) {
        return CRYPT_INVALID_ARG;
    }

    BSL_Param param[2] = {
        {CRYPT_PARAM_NEW_KEY_GROUP, BSL_PARAM_TYPE_INT32, &cid, sizeof(cid), 0},
        BSL_PARAM_END
    };
    return TestNewKeySetPara(newAlgKey, param);
}

static int32_t CRYPT_NewAlg_ParsePrikeyAsn1Buff(uint8_t *buffer, uint32_t bufferLen, void **newAlgPriKey)
{
    if (buffer == NULL || bufferLen == 0 || newAlgPriKey == NULL) {
        return CRYPT_NULL_INPUT;
    }
    TestNewKeyCtx *key = TestNewKeyMgmtNewCtx(NULL, NEW_PKEY_ALGID);
    if (key == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = ProcNewAlgKeyPair(buffer, bufferLen, key);
    if (ret != CRYPT_SUCCESS) {
        TestNewKeyFreeCtx(key);
        return ret;
    }
    *newAlgPriKey = key;
    return CRYPT_SUCCESS;
}

static int32_t ConstructOutputParams(TestNewAlgDer2KeyCtx *decoderCtx, void *key, BSL_Param **outParam)
{
    BSL_Param *result = calloc(7, sizeof(BSL_Param));
    if (result == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = TestParamInitValue(&result[0], CRYPT_PARAM_DECODE_OBJECT_DATA, BSL_PARAM_TYPE_CTX_PTR, key, 0);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    ret = TestParamInitValue(&result[1], CRYPT_PARAM_DECODE_OBJECT_TYPE, BSL_PARAM_TYPE_INT32, &decoderCtx->keyAlgId,
        sizeof(decoderCtx->outType));
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    ret = TestParamInitValue(&result[2], CRYPT_PARAM_DECODE_PKEY_EXPORT_METHOD_FUNC, BSL_PARAM_TYPE_FUNC_PTR,
        TestNewKeyExport, 0);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    ret = TestParamInitValue(&result[3], CRYPT_PARAM_DECODE_PKEY_FREE_METHOD_FUNC, BSL_PARAM_TYPE_FUNC_PTR,
        TestNewKeyFreeCtx, 0);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    ret = TestParamInitValue(&result[4], CRYPT_PARAM_DECODE_PKEY_DUP_METHOD_FUNC, BSL_PARAM_TYPE_FUNC_PTR,
        TestNewKeyDupCtx, 0);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    ret = TestParamInitValue(&result[5], CRYPT_PARAM_DECODE_PROVIDER_CTX, BSL_PARAM_TYPE_CTX_PTR,
        decoderCtx->provMgrCtx, 0);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    *outParam = result;
    return CRYPT_SUCCESS;
EXIT:
    TestNewKeyFreeCtx(key);
    free(result);
    return ret;
}

static int32_t DECODER_NewAlgDer2Key_Decode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam)
{
    if (ctx == NULL || inParam == NULL || outParam == NULL) {
        return CRYPT_NULL_INPUT;
    }
    void *key = NULL;
    TestNewAlgDer2KeyCtx *decoderCtx = (TestNewAlgDer2KeyCtx *)ctx;
    const BSL_Param *input = TestFindConstParam(inParam, CRYPT_PARAM_DECODE_BUFFER_DATA);
    if (input == NULL) {
        return CRYPT_NULL_INPUT;
    }
    if (input->value == NULL || input->valueLen == 0 || input->valueType != BSL_PARAM_TYPE_OCTETS) {
        return CRYPT_INVALID_ARG;
    }

    int32_t ret = CRYPT_NewAlg_ParsePrikeyAsn1Buff(input->value, input->valueLen, &key);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return ConstructOutputParams(decoderCtx, key, outParam);
}

static int32_t NewAlgKeySubKeyInfoCb(int32_t type, uint32_t idx, void *data, void *expVal)
{
    (void)idx;
    BSL_ASN1_Buffer *param = (BSL_ASN1_Buffer *)data;

    switch (type) {
        case BSL_ASN1_TYPE_GET_ANY_TAG: {
            BslOidString oidStr = {param->len, (char *)param->buff, 0};
            BslCid cid = BSL_OBJ_GetCID(&oidStr);
            if (cid == NEW_PKEY_ALGID) {
                // note: any It can be encoded empty or it can be null
                *(uint8_t *)expVal = BSL_ASN1_TAG_OBJECT_ID;
            } else {
                *(uint8_t *)expVal = BSL_ASN1_TAG_NULL; // is null
            }
            return CRYPT_SUCCESS;
        }
        default:
            break;
    }
    return CRYPT_DECODE_ASN1_BUFF_FAILED;
}

static int32_t DECODER_NewAlgSubPubKeyDer2Key_Decode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam)
{
    if (ctx == NULL || inParam == NULL || outParam == NULL) {
        return CRYPT_NULL_INPUT;
    }
    TestNewAlgDer2KeyCtx *decoderCtx = (TestNewAlgDer2KeyCtx *)ctx;
    CRYPT_DECODE_SubPubkeyInfo subKeyInfo = {0};
    const BSL_Param *input = TestFindConstParam(inParam, CRYPT_PARAM_DECODE_BUFFER_DATA);
    if (input == NULL) {
        return CRYPT_NULL_INPUT;
    }
    if (input->value == NULL || input->valueLen == 0 || input->valueType != BSL_PARAM_TYPE_OCTETS) {
        return CRYPT_INVALID_ARG;
    }
    int32_t ret = CRYPT_DECODE_SubPubkey((uint8_t *)input->value, input->valueLen, NewAlgKeySubKeyInfoCb, &subKeyInfo, false);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (subKeyInfo.keyType != NEW_PKEY_ALGID) {
        return CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH;
    }

    TestNewKeyCtx *newAlgKey = TestNewKeyMgmtNewCtx(NULL, NEW_PKEY_ALGID);
    if (newAlgKey == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto EXIT;
    }
    int32_t cid = GetParaId(subKeyInfo.keyParam.buff, subKeyInfo.keyParam.len);
    if (cid != NEW_PARA_ALGID) {
        ret = CRYPT_INVALID_ARG;
        goto EXIT;
    }
    const BSL_Param param2[2] = {
        {CRYPT_PARAM_NEW_KEY_PUBKEY, BSL_PARAM_TYPE_OCTETS, subKeyInfo.pubKey.buff,
            subKeyInfo.pubKey.len, 0},
        BSL_PARAM_END
    };
    ret = TestNewKeySetPubKey(newAlgKey, param2);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    ret = ConstructOutputParams(decoderCtx, newAlgKey, outParam);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    return CRYPT_SUCCESS;
EXIT:
    TestNewKeyFreeCtx(newAlgKey);
    return ret;
}

static void DECODER_NewAlgDer2Key_FreeOutData(void *ctx, BSL_Param *outData)
{
    TestNewAlgDer2KeyCtx *decoderCtx = (TestNewAlgDer2KeyCtx *)ctx;
    if (decoderCtx == NULL || outData == NULL) {
        return;
    }
    BSL_Param *outKey = TestFindParam(outData, CRYPT_PARAM_DECODE_OBJECT_DATA);
    if (outKey == NULL) {
        return;
    }
    TestNewKeyFreeCtx(outKey->value);
    BSL_SAL_Free(outData);
}

static void DECODER_NewAlgDer2Key_FreeCtx(void *ctx)
{
    if (ctx == NULL) {
        return;
    }
    TestNewAlgDer2KeyCtx *decoderCtx = (TestNewAlgDer2KeyCtx *)ctx;
    free(decoderCtx);
}

static const CRYPT_EAL_Func g_testDer2NewAlgKey[] = {
    {CRYPT_DECODER_IMPL_NEWCTX, (CRYPT_DECODER_IMPL_NewCtx)DECODER_NewAlgDer2Key_NewCtx},
    {CRYPT_DECODER_IMPL_GETPARAM, (CRYPT_DECODER_IMPL_GetParam)DECODER_NewAlgDer2Key_GetParam},
    {CRYPT_DECODER_IMPL_SETPARAM, (CRYPT_DECODER_IMPL_SetParam)DECODER_NewAlgDer2Key_SetParam},
    {CRYPT_DECODER_IMPL_DECODE, (CRYPT_DECODER_IMPL_Decode)DECODER_NewAlgDer2Key_Decode},
    {CRYPT_DECODER_IMPL_FREEOUTDATA, (CRYPT_DECODER_IMPL_FreeOutData)DECODER_NewAlgDer2Key_FreeOutData},
    {CRYPT_DECODER_IMPL_FREECTX, (CRYPT_DECODER_IMPL_FreeCtx)DECODER_NewAlgDer2Key_FreeCtx},
    CRYPT_EAL_FUNC_END
};

static const CRYPT_EAL_Func g_testSubPubKeyDer2NewAlgKey[] = {
    {CRYPT_DECODER_IMPL_NEWCTX, (CRYPT_DECODER_IMPL_NewCtx)DECODER_NewAlgDer2Key_NewCtx},
    {CRYPT_DECODER_IMPL_GETPARAM, (CRYPT_DECODER_IMPL_GetParam)DECODER_NewAlgDer2Key_GetParam},
    {CRYPT_DECODER_IMPL_SETPARAM, (CRYPT_DECODER_IMPL_SetParam)DECODER_NewAlgDer2Key_SetParam},
    {CRYPT_DECODER_IMPL_DECODE, (CRYPT_DECODER_IMPL_Decode)DECODER_NewAlgSubPubKeyDer2Key_Decode},
    {CRYPT_DECODER_IMPL_FREEOUTDATA, (CRYPT_DECODER_IMPL_FreeOutData)DECODER_NewAlgDer2Key_FreeOutData},
    {CRYPT_DECODER_IMPL_FREECTX, (CRYPT_DECODER_IMPL_FreeCtx)DECODER_NewAlgDer2Key_FreeCtx},
    CRYPT_EAL_FUNC_END
};

static CRYPT_EAL_AlgInfo g_testDecoder[] = {
    {NEW_PKEY_ALGID, g_testDer2NewAlgKey, "provider=provider_new_alg_test, inFormat=ASN1, inType=CRYPT_PKEY_NEW_ALG, outFormat=OBJECT, outType=LOW_KEY"},
    {NEW_PKEY_ALGID, g_testSubPubKeyDer2NewAlgKey, "provider=provider_new_alg_test, inFormat=ASN1, inType=PUBKEY_SUBKEY_WITHOUT_SEQ, outFormat=OBJECT, outType=LOW_KEY"},
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
        case CRYPT_EAL_OPERAID_DECODER:
            *algInfos = g_testDecoder;
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

static const Provider_Group g_tlsGroupInfo[] = {
    {
        "test_new_group_with_new_key_type",
        NEW_PARA_ALGID,      // paraId
        NEW_PKEY_ALGID,      // algId
        1024,                // secBits
        479,                 // groupId
        143,                 // pubkeyLen
        143,                 // sharedkeyLen
        0,                   // ciphertextLen
        TLS12_VERSION_BIT | TLS13_VERSION_BIT,  // versionBits
        false               // isKem
    }
};

static int32_t TestCryptGetSigAlgCaps(CRYPT_EAL_ProcessFuncCb cb, void *args)
{
    if (cb == NULL) {
        return CRYPT_NULL_INPUT;
    }
    uint16_t signatureScheme = 24444;
    int32_t keyType = NEW_PKEY_ALGID;
    int32_t paraId = NEW_PARA_ALGID;
    int32_t signHashAlgId = NEW_SIGN_HASH_ALGID;
    int32_t signAlgId = NEW_PKEY_ALGID;
    int32_t hashAlgId = NEW_HASH_ALGID;
    int32_t secBits = 1024;
    uint32_t certVersionBits = TLS12_VERSION_BIT | TLS13_VERSION_BIT;
    uint32_t chainVersionBits = TLS12_VERSION_BIT | TLS13_VERSION_BIT;
    BSL_Param param[] = {
        {
            CRYPT_PARAM_CAP_TLS_SIGNALG_IANA_SIGN_NAME,
            BSL_PARAM_TYPE_OCTETS_PTR,
            (void *)(uintptr_t)"test_new_sign_alg_name_with_new_key_type",
            (uint32_t)strlen("test_new_sign_alg_name_with_new_key_type")
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
            CRYPT_PARAM_CAP_TLS_SIGNALG_KEY_TYPE_OID,
            BSL_PARAM_TYPE_OCTETS_PTR,
            (void *)(uintptr_t)"\150\40\66\77\57", // 68 20 36 3F 2F
            (uint32_t)strlen("\150\40\66\77\57")
        },
        {
            CRYPT_PARAM_CAP_TLS_SIGNALG_KEY_TYPE_NAME,
            BSL_PARAM_TYPE_OCTETS_PTR,
            (void *)(uintptr_t)"test_new_key_type",
            (uint32_t)strlen("test_new_key_type")
        },
        {
            CRYPT_PARAM_CAP_TLS_SIGNALG_PARA_ID,
            BSL_PARAM_TYPE_INT32,
            (void *)(uintptr_t)&(paraId),
            sizeof(paraId)
        },
        {
            CRYPT_PARAM_CAP_TLS_SIGNALG_PARA_OID,
            BSL_PARAM_TYPE_OCTETS_PTR,
            (void *)(uintptr_t)"\150\40\66\77\56", // 68 20 36 3F 2E
            (uint32_t)strlen("\150\40\66\77\56")
        },
        {
            CRYPT_PARAM_CAP_TLS_SIGNALG_PARA_NAME,
            BSL_PARAM_TYPE_OCTETS_PTR,
            (void *)(uintptr_t)"test_new_para_name",
            (uint32_t)strlen("test_new_para_name")
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
            (void *)(uintptr_t)"\150\40\66\71\65",  // 68 20 36 3F 35
            (uint32_t)strlen("\150\40\66\71\65")
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
        }
    };
    return cb(param, args);
}

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
                              CRYPT_EAL_Func *capFuncs, CRYPT_EAL_Func **outFuncs,
                              void **provCtx)
{
    if (mgrCtx == NULL || capFuncs == NULL || outFuncs == NULL || provCtx == NULL) {
        return CRYPT_NULL_INPUT;
    }
    
    TestProvCtx *ctx = malloc(sizeof(TestProvCtx));
    if (ctx == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    ctx->mgrCtxHandle = mgrCtx;
    *provCtx = ctx;
    *outFuncs = g_testProvOutFuncs;
    
    return CRYPT_SUCCESS;
}
