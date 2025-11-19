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
#if defined(HITLS_CRYPTO_KEY_DECODE_CHAIN) && defined(HITLS_CRYPTO_PROVIDER)
#include <string.h>
#include <stdbool.h>
#ifdef HITLS_CRYPTO_PROVIDER
#include "crypt_eal_implprovider.h"
#include "crypt_default_provderimpl.h"
#include "crypt_provider_local.h"
#endif
#include "crypt_eal_pkey.h"
#include "crypt_algid.h"
#ifdef HITLS_CRYPTO_RSA
#include "crypt_rsa.h"
#endif
#ifdef HITLS_CRYPTO_ECDSA
#include "crypt_ecdsa.h"
#endif
#ifdef HITLS_CRYPTO_SM2
#include "crypt_sm2.h"
#endif
#ifdef HITLS_CRYPTO_ED25519
#include "crypt_curve25519.h"
#endif
#ifdef HITLS_CRYPTO_MLDSA
#include "crypt_mldsa.h"
#endif
#include "eal_pkey.h"
#include "crypt_errno.h"
#include "bsl_sal.h"
#include "bsl_obj.h"
#include "bsl_err_internal.h"
#include "crypt_codecskey_local.h"
#include "crypt_decoder_local.h"
#include "crypt_decoder.h"
#define PKEY_MAX_PARAM_NUM 20

#if defined(HITLS_CRYPTO_RSA) || defined(HITLS_CRYPTO_ECDSA) || defined(HITLS_CRYPTO_SM2) || \
    defined(HITLS_CRYPTO_ED25519) || defined(HITLS_CRYPTO_MLDSA)
typedef struct {
    CRYPT_EAL_ProvMgrCtx *provMgrCtx;
    EAL_PkeyUnitaryMethod method;
    int32_t keyAlgId;
    const char *outFormat;
    const char *outType;
} DECODER_Der2KeyCtx;

DECODER_Der2KeyCtx *DECODER_DER2KEY_NewCtx(void *provCtx)
{
    (void)provCtx;
    DECODER_Der2KeyCtx *ctx = (DECODER_Der2KeyCtx *)BSL_SAL_Calloc(1, sizeof(DECODER_Der2KeyCtx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    ctx->outFormat = "OBJECT";
    ctx->outType = "LOW_KEY";
    return ctx;
}

#define DECODER_DEFINE_DER2KEY_NEW_CTX(keyType, keyId, keyMethod, asyCipherMethod, exchMethod, signMethod, kemMethod) \
void *DECODER_##keyType##Der2KeyNewCtx(void *provCtx) \
{ \
    DECODER_Der2KeyCtx *ctx = DECODER_DER2KEY_NewCtx(provCtx); \
    if (ctx == NULL) { \
        return NULL; \
    } \
    int32_t ret = CRYPT_EAL_SetPkeyMethod(&ctx->method, keyMethod, asyCipherMethod, exchMethod, signMethod, \
        kemMethod); \
    if (ret != CRYPT_SUCCESS) { \
        DECODER_DER2KEY_FreeCtx(ctx); \
        return NULL; \
    } \
    ctx->keyAlgId = keyId; \
    return ctx; \
}

int32_t DECODER_CommonGetParam(const DECODER_CommonCtx *commonCtx, BSL_Param *param)
{
    if (commonCtx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    BSL_Param *param1 = BSL_PARAM_FindParam(param, CRYPT_PARAM_DECODE_OUTPUT_TYPE);
    if (param1 != NULL) {
        if (param1->valueType != BSL_PARAM_TYPE_OCTETS_PTR) {
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
        }
        param1->value = (void *)(uintptr_t)commonCtx->outType;
    }
    BSL_Param *param2 = BSL_PARAM_FindParam(param, CRYPT_PARAM_DECODE_OUTPUT_FORMAT);
    if (param2 != NULL) {
        if (param2->valueType != BSL_PARAM_TYPE_OCTETS_PTR) {
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
        }
        param2->value = (void *)(uintptr_t)commonCtx->outFormat;
    }
    return CRYPT_SUCCESS;
}

int32_t DECODER_DER2KEY_GetParam(void *ctx, BSL_Param *param)
{
    DECODER_Der2KeyCtx *decoderCtx = (DECODER_Der2KeyCtx *)ctx;
    if (decoderCtx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    DECODER_CommonCtx commonCtx = {
        .outFormat = decoderCtx->outFormat,
        .outType = decoderCtx->outType
    };
    return DECODER_CommonGetParam(&commonCtx, param);
}

int32_t DECODER_DER2KEY_SetParam(void *ctx, const BSL_Param *param)
{
    DECODER_Der2KeyCtx *decoderCtx = (DECODER_Der2KeyCtx *)ctx;
    if (decoderCtx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    const BSL_Param *input = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_DECODE_PROVIDER_CTX);
    if (input != NULL) {
        if (input->valueType != BSL_PARAM_TYPE_CTX_PTR || input->value == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
        }
        decoderCtx->provMgrCtx = (CRYPT_EAL_ProvMgrCtx *)(uintptr_t)input->value;
    }

    return CRYPT_SUCCESS;
}

static int32_t CheckParams(DECODER_Der2KeyCtx *decoderCtx, const BSL_Param *inParam, BSL_Param **outParam,
    BSL_Buffer *asn1Encode)
{
    if (decoderCtx == NULL || inParam == NULL || outParam == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    const BSL_Param *input = BSL_PARAM_FindConstParam(inParam, CRYPT_PARAM_DECODE_BUFFER_DATA);
    if (input == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (input->value == NULL || input->valueLen == 0 || input->valueType != BSL_PARAM_TYPE_OCTETS) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    asn1Encode->data = (uint8_t *)(uintptr_t)input->value;
    asn1Encode->dataLen = input->valueLen;
    return CRYPT_SUCCESS;
}

#define DECODER_CHECK_PARAMS(ctx, inParam, outParam) \
    void *key = NULL; \
    BSL_Buffer asn1Encode = {0}; \
    DECODER_Der2KeyCtx *decoderCtx = (DECODER_Der2KeyCtx *)ctx; \
    int32_t ret = CheckParams(decoderCtx, inParam, outParam, &asn1Encode); \
    if (ret != CRYPT_SUCCESS) { \
        BSL_ERR_PUSH_ERROR(ret); \
        return ret; \
    }

static int32_t ConstructOutputParams(DECODER_Der2KeyCtx *decoderCtx, void *key, BSL_Param **outParam)
{
    int32_t ret;
    BSL_Param *result = BSL_SAL_Calloc(7, sizeof(BSL_Param));
    if (result == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        goto EXIT;
    }
    ret = BSL_PARAM_InitValue(&result[0], CRYPT_PARAM_DECODE_OBJECT_DATA, BSL_PARAM_TYPE_CTX_PTR, key, 0);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = BSL_PARAM_InitValue(&result[1], CRYPT_PARAM_DECODE_OBJECT_TYPE, BSL_PARAM_TYPE_INT32, &decoderCtx->keyAlgId,
        sizeof(int32_t));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = BSL_PARAM_InitValue(&result[2], CRYPT_PARAM_DECODE_PKEY_EXPORT_METHOD_FUNC, BSL_PARAM_TYPE_FUNC_PTR,
        decoderCtx->method.export, 0);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = BSL_PARAM_InitValue(&result[3], CRYPT_PARAM_DECODE_PKEY_FREE_METHOD_FUNC, BSL_PARAM_TYPE_FUNC_PTR,
        decoderCtx->method.freeCtx, 0);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = BSL_PARAM_InitValue(&result[4], CRYPT_PARAM_DECODE_PKEY_DUP_METHOD_FUNC, BSL_PARAM_TYPE_FUNC_PTR,
        decoderCtx->method.dupCtx, 0);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = BSL_PARAM_InitValue(&result[5], CRYPT_PARAM_DECODE_PROVIDER_CTX, BSL_PARAM_TYPE_CTX_PTR,
        decoderCtx->provMgrCtx, 0);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    *outParam = result;
    return CRYPT_SUCCESS;
EXIT:
    if (decoderCtx->method.freeCtx != NULL) {
        decoderCtx->method.freeCtx(key);
    }
    BSL_SAL_Free(result);
    return ret;
}

#define DECODER_DEFINE_PRVKEY_DER2KEY_DECODE(keyType, keyStructName, parseFunc) \
int32_t DECODER_##keyType##PrvKeyDer2KeyDecode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam) \
{ \
    DECODER_CHECK_PARAMS(ctx, inParam, outParam); \
    ret = parseFunc(decoderCtx->provMgrCtx->libCtx, asn1Encode.data, asn1Encode.dataLen, NULL, \
        (keyStructName **)&key); \
    if (ret != CRYPT_SUCCESS) { \
        BSL_ERR_PUSH_ERROR(ret); \
        return ret; \
    } \
    return ConstructOutputParams(decoderCtx, key, outParam); \
}

#define DECODER_DEFINE_PUBKEY_DER2KEY_DECODE(keyType, keyStructName, parseFunc) \
int32_t DECODER_##keyType##PubKeyDer2KeyDecode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam) \
{ \
    DECODER_CHECK_PARAMS(ctx, inParam, outParam); \
    ret = parseFunc(decoderCtx->provMgrCtx->libCtx, asn1Encode.data, asn1Encode.dataLen, NULL, \
        (keyStructName **)&key, BSL_CID_UNKNOWN); \
    if (ret != CRYPT_SUCCESS) { \
        BSL_ERR_PUSH_ERROR(ret); \
        return ret; \
    } \
    return ConstructOutputParams(decoderCtx, key, outParam); \
}

#define DECODER_DEFINE_SUBPUBKEY_DER2KEY_DECODE(keyType, keyStructName, parseFunc) \
int32_t DECODER_##keyType##SubPubKeyDer2KeyDecode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam) \
{ \
    DECODER_CHECK_PARAMS(ctx, inParam, outParam) \
    ret = parseFunc(decoderCtx->provMgrCtx->libCtx, asn1Encode.data, asn1Encode.dataLen, \
        (keyStructName **)&key, true); \
    if (ret != CRYPT_SUCCESS) { \
        BSL_ERR_PUSH_ERROR(ret); \
        return ret; \
    } \
    return ConstructOutputParams(decoderCtx, key, outParam); \
}

#define DECODER_DEFINE_SUBPUBKEY_WITHOUT_SEQ_DER2KEY_DECODE(keyType, keyStructName, parseFunc) \
int32_t DECODER_##keyType##SubPubKeyWithOutSeqDer2KeyDecode(void *ctx, const BSL_Param *inParam, \
    BSL_Param **outParam) \
{ \
    DECODER_CHECK_PARAMS(ctx, inParam, outParam) \
    ret = parseFunc(decoderCtx->provMgrCtx->libCtx, asn1Encode.data, asn1Encode.dataLen, (keyStructName **)&key, \
        false); \
    if (ret != CRYPT_SUCCESS) { \
        BSL_ERR_PUSH_ERROR(ret); \
        return ret; \
    } \
    return ConstructOutputParams(decoderCtx, key, outParam); \
}

#define DECODER_DEFINE_PKCS8_DECODE(keyType, keyStructName, parseFunc) \
int32_t DECODER_##keyType##Pkcs8Der2KeyDecode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam) \
{ \
    DECODER_CHECK_PARAMS(ctx, inParam, outParam) \
    ret = parseFunc(decoderCtx->provMgrCtx->libCtx, asn1Encode.data, asn1Encode.dataLen, (keyStructName **)&key); \
    if (ret != CRYPT_SUCCESS) { \
        BSL_ERR_PUSH_ERROR(ret); \
        return ret; \
    } \
    return ConstructOutputParams(decoderCtx, key, outParam); \
}

void DECODER_DER2KEY_FreeOutData(void *ctx, BSL_Param *outParam)
{
    DECODER_Der2KeyCtx *decoderCtx = ctx;
    if (decoderCtx == NULL || outParam == NULL) {
        return;
    }
    if (decoderCtx->method.freeCtx == NULL) {
        return;
    }
    BSL_Param *outKey = BSL_PARAM_FindParam(outParam, CRYPT_PARAM_DECODE_OBJECT_DATA);
    if (outKey == NULL) {
        return;
    }
    decoderCtx->method.freeCtx(outKey->value);
    BSL_SAL_Free(outParam);
}

void DECODER_DER2KEY_FreeCtx(void *ctx)
{
    if (ctx != NULL) {
        BSL_SAL_Free(ctx);
    }
}
#endif

#ifdef HITLS_CRYPTO_PROVIDER
#ifdef HITLS_CRYPTO_RSA
DECODER_DEFINE_DER2KEY_NEW_CTX(Rsa, CRYPT_PKEY_RSA, g_defEalKeyMgmtRsa, g_defEalAsymCipherRsa, NULL, \
    g_defEalSignRsa, NULL)
#endif
#ifdef HITLS_CRYPTO_ECDSA
DECODER_DEFINE_DER2KEY_NEW_CTX(Ecdsa, CRYPT_PKEY_ECDSA, g_defEalKeyMgmtEcdsa, NULL, NULL, g_defEalSignEcdsa, NULL)
#endif
#ifdef HITLS_CRYPTO_SM2
DECODER_DEFINE_DER2KEY_NEW_CTX(Sm2, CRYPT_PKEY_SM2, g_defEalKeyMgmtSm2, g_defEalAsymCipherSm2, g_defEalExchSm2, \
    g_defEalSignSm2, NULL)
#endif
#ifdef HITLS_CRYPTO_ED25519
DECODER_DEFINE_DER2KEY_NEW_CTX(Ed25519, CRYPT_PKEY_ED25519, g_defEalKeyMgmtEd25519, NULL, NULL, \
    g_defEalSignEd25519, NULL)
#endif
#ifdef HITLS_CRYPTO_MLDSA
DECODER_DEFINE_DER2KEY_NEW_CTX(Mldsa, CRYPT_PKEY_ML_DSA, g_defEalKeyMgmtMlDsa, NULL, NULL, g_defEalSignMlDsa, NULL)
#endif
#ifdef HITLS_CRYPTO_RSA
DECODER_DEFINE_PRVKEY_DER2KEY_DECODE(Rsa, CRYPT_RSA_Ctx, CRYPT_RSA_ParsePrikeyAsn1Buff)
DECODER_DEFINE_PUBKEY_DER2KEY_DECODE(Rsa, CRYPT_RSA_Ctx, CRYPT_RSA_ParsePubkeyAsn1Buff)
DECODER_DEFINE_SUBPUBKEY_DER2KEY_DECODE(Rsa, CRYPT_RSA_Ctx, CRYPT_RSA_ParseSubPubkeyAsn1Buff)
DECODER_DEFINE_SUBPUBKEY_WITHOUT_SEQ_DER2KEY_DECODE(Rsa, CRYPT_RSA_Ctx, CRYPT_RSA_ParseSubPubkeyAsn1Buff)
DECODER_DEFINE_PKCS8_DECODE(Rsa, CRYPT_RSA_Ctx, CRYPT_RSA_ParsePkcs8Key)
#endif

#ifdef HITLS_CRYPTO_ECDSA
DECODER_DEFINE_PRVKEY_DER2KEY_DECODE(Ecdsa, void, CRYPT_ECC_ParsePrikeyAsn1Buff)
DECODER_DEFINE_SUBPUBKEY_DER2KEY_DECODE(Ecdsa, void, CRYPT_ECC_ParseSubPubkeyAsn1Buff)
DECODER_DEFINE_SUBPUBKEY_WITHOUT_SEQ_DER2KEY_DECODE(Ecdsa, void, CRYPT_ECC_ParseSubPubkeyAsn1Buff)
DECODER_DEFINE_PKCS8_DECODE(Ecdsa, void, CRYPT_ECC_ParsePkcs8Key)
#endif

#ifdef HITLS_CRYPTO_SM2
DECODER_DEFINE_PRVKEY_DER2KEY_DECODE(Sm2, CRYPT_SM2_Ctx, CRYPT_SM2_ParsePrikeyAsn1Buff)
DECODER_DEFINE_SUBPUBKEY_DER2KEY_DECODE(Sm2, CRYPT_SM2_Ctx, CRYPT_SM2_ParseSubPubkeyAsn1Buff)
DECODER_DEFINE_SUBPUBKEY_WITHOUT_SEQ_DER2KEY_DECODE(Sm2, CRYPT_SM2_Ctx, CRYPT_SM2_ParseSubPubkeyAsn1Buff)
DECODER_DEFINE_PKCS8_DECODE(Sm2, CRYPT_SM2_Ctx, CRYPT_SM2_ParsePkcs8Key)
#endif

#ifdef HITLS_CRYPTO_ED25519
DECODER_DEFINE_SUBPUBKEY_DER2KEY_DECODE(Ed25519, CRYPT_CURVE25519_Ctx, CRYPT_ED25519_ParseSubPubkeyAsn1Buff)
DECODER_DEFINE_SUBPUBKEY_WITHOUT_SEQ_DER2KEY_DECODE(Ed25519, CRYPT_CURVE25519_Ctx, CRYPT_ED25519_ParseSubPubkeyAsn1Buff)
DECODER_DEFINE_PKCS8_DECODE(Ed25519, CRYPT_CURVE25519_Ctx, CRYPT_ED25519_ParsePkcs8Key)
#endif

#ifdef HITLS_CRYPTO_MLDSA
DECODER_DEFINE_SUBPUBKEY_DER2KEY_DECODE(Mldsa, CRYPT_ML_DSA_Ctx, CRYPT_MLDSA_ParseSubPubkeyAsn1Buff)
DECODER_DEFINE_SUBPUBKEY_WITHOUT_SEQ_DER2KEY_DECODE(Mldsa, CRYPT_ML_DSA_Ctx, CRYPT_MLDSA_ParseSubPubkeyAsn1Buff)
DECODER_DEFINE_PKCS8_DECODE(Mldsa, CRYPT_ML_DSA_Ctx, CRYPT_MLDSA_ParsePkcs8key)
#endif
#endif /* HITLS_CRYPTO_PROVIDER */
#endif /* HITLS_CRYPTO_KEY_DECODE_CHAIN && HITLS_CRYPTO_PROVIDER */
