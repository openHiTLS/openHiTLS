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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "bsl_params.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_eal_implprovider.h"
#include "crypt_eal_provider.h"
#include "crypt_params_key.h"

#define CRYPT_EAL_PAILLIER_HE_TEST_ATTR "provider=paillier_he_test"

static const uint8_t ADD_RESULT[] = {0x70, 0x61, 0x2D, 0x61, 0x64, 0x64};
static const uint8_t MUL_RESULT[] = {0x70, 0x61, 0x2D, 0x6D, 0x75, 0x6C};
static const uint8_t ENCODE_RESULT[] = {0x70, 0x61, 0x2D, 0x65, 0x6E, 0x63};
static const uint8_t DECODE_RESULT[] = {0x70, 0x61, 0x2D, 0x64, 0x65, 0x63};

static void *ProviderPaillierNewCtx(void *provCtx, int32_t algId)
{
    (void)provCtx;
    (void)algId;
    return malloc(sizeof(int32_t));
}

static void ProviderPaillierFreeCtx(void *ctx)
{
    free(ctx);
}

static int32_t WriteResult(const void *ctx, const BSL_Param *input, uint8_t *out, uint32_t *outLen,
    const int32_t *keys, uint32_t keyCount, const uint8_t *result, uint32_t resultLen)
{
    if (ctx == NULL || input == NULL || out == NULL || outLen == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (*outLen < resultLen) {
        *outLen = resultLen;
        return CRYPT_PAILLIER_BUFF_LEN_NOT_ENOUGH;
    }

    (void)memcpy(out, result, resultLen);
    *outLen = resultLen;
    return CRYPT_SUCCESS;
}

static int32_t ProviderPaillierHEAdd(const void *ctx, const BSL_Param *input, uint8_t *out, uint32_t *outLen)
{
    static const int32_t keys[] = {
        CRYPT_PARAM_PKEY_HE_CIPHERTEXT1,
        CRYPT_PARAM_PKEY_HE_CIPHERTEXT2
    };
    return WriteResult(ctx, input, out, outLen, keys, sizeof(keys) / sizeof(keys[0]), ADD_RESULT,
        sizeof(ADD_RESULT));
}

static int32_t ProviderPaillierHEMul(const void *ctx, const BSL_Param *input, uint8_t *out, uint32_t *outLen)
{
    static const int32_t keys[] = {
        CRYPT_PARAM_PKEY_HE_CIPHERTEXT1,
        CRYPT_PARAM_PKEY_ENCODE_PUBKEY
    };
    return WriteResult(ctx, input, out, outLen, keys, sizeof(keys) / sizeof(keys[0]), MUL_RESULT,
        sizeof(MUL_RESULT));
}

static int32_t ProviderPaillierHEMsgEncode(const void *ctx, const BSL_Param *input, uint8_t *out, uint32_t *outLen)
{
    static const int32_t keys[] = {
        CRYPT_PARAM_PKEY_ENCODE_PUBKEY,
        CRYPT_PARAM_PKEY_PROCESS_FUNC,
        CRYPT_PARAM_PKEY_PROCESS_ARGS,
        CRYPT_PARAM_PKEY_SIG_PAD_DIGEST
    };
    return WriteResult(ctx, input, out, outLen, keys, sizeof(keys) / sizeof(keys[0]), ENCODE_RESULT,
        sizeof(ENCODE_RESULT));
}

static int32_t ProviderPaillierHEMsgDecode(const void *ctx, const BSL_Param *input, uint8_t *out, uint32_t *outLen)
{
    static const int32_t keys[] = {
        CRYPT_PARAM_PKEY_ENCODE_PUBKEY,
        CRYPT_PARAM_PKEY_SIG_PAD_DIGEST
    };
    return WriteResult(ctx, input, out, outLen, keys, sizeof(keys) / sizeof(keys[0]), DECODE_RESULT,
        sizeof(DECODE_RESULT));
}

static const CRYPT_EAL_Func g_paillierKeyMgmt[] = {
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, ProviderPaillierNewCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, ProviderPaillierFreeCtx},
    CRYPT_EAL_FUNC_END
};

static const CRYPT_EAL_Func g_paillierAsymCipher[] = {
    {CRYPT_EAL_IMPLPKEYCIPHER_HEADD, ProviderPaillierHEAdd},
    {CRYPT_EAL_IMPLPKEYCIPHER_HEMUL, ProviderPaillierHEMul},
    {CRYPT_EAL_IMPLPKEYCIPHER_MSG_ENCODE, ProviderPaillierHEMsgEncode},
    {CRYPT_EAL_IMPLPKEYCIPHER_MSG_DECODE, ProviderPaillierHEMsgDecode},
    CRYPT_EAL_FUNC_END
};

static const CRYPT_EAL_AlgInfo g_keyMgmt[] = {
    {CRYPT_PKEY_PAILLIER, g_paillierKeyMgmt, CRYPT_EAL_PAILLIER_HE_TEST_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo g_asymCipher[] = {
    {CRYPT_PKEY_PAILLIER, g_paillierAsymCipher, CRYPT_EAL_PAILLIER_HE_TEST_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static int32_t ProviderPaillierQuery(void *provCtx, int32_t operaId, const CRYPT_EAL_AlgInfo **algInfos)
{
    (void)provCtx;
    switch (operaId) {
        case CRYPT_EAL_OPERAID_KEYMGMT:
            *algInfos = g_keyMgmt;
            return CRYPT_SUCCESS;
        case CRYPT_EAL_OPERAID_ASYMCIPHER:
            *algInfos = g_asymCipher;
            return CRYPT_SUCCESS;
        default:
            return CRYPT_NOT_SUPPORT;
    }
}

static void ProviderPaillierFree(void *provCtx)
{
    (void)provCtx;
}

static CRYPT_EAL_Func g_providerOutFuncs[] = {
    {CRYPT_EAL_PROVCB_QUERY, ProviderPaillierQuery},
    {CRYPT_EAL_PROVCB_FREE, ProviderPaillierFree},
    {CRYPT_EAL_PROVCB_CTRL, NULL},
    CRYPT_EAL_FUNC_END
};

int32_t CRYPT_EAL_ProviderInit(CRYPT_EAL_ProvMgrCtx *mgrCtx, BSL_Param *param, CRYPT_EAL_Func *capFuncs,
    CRYPT_EAL_Func **outFuncs, void **provCtx)
{
    (void)mgrCtx;
    (void)param;
    (void)capFuncs;

    *outFuncs = g_providerOutFuncs;
    *provCtx = NULL;
    return CRYPT_SUCCESS;
}
