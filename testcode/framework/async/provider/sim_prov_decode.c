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
#ifdef HITLS_CRYPTO_PROVIDER

#include "sim_prov_internal.h"
#include "crypt_eal_codecs.h"
#include "crypt_params_key.h"
#include "crypt_utils.h"
#include "eal_pkey.h"
#include "eal_pkey_local.h"
#include <string.h>

typedef struct {
    int32_t format;
    int32_t type;
    CRYPT_EAL_LibCtx *libCtx;
    const char *attr;
    CRYPT_EAL_ProvMgrCtx *mgr;
} SimDecoder;

typedef struct {
    CRYPT_EAL_ImplPkeyMgmtImport import;
    void *key;
} SimDecoderImportCtx;

static int32_t SimDecoderImportKey(const BSL_Param *param, void *arg)
{
    SimDecoderImportCtx *ctx = arg;
    return ctx->import(ctx->key, param);
}

static int32_t SimDecoderBuiltinKey(CRYPT_EAL_PkeyCtx *source, CRYPT_EAL_PkeyCtx **out)
{
    RETURN_RET_IF(source->method.export == NULL || source->method.import == NULL, CRYPT_NOT_SUPPORT);
    CRYPT_EAL_PkeyCtx *key = CRYPT_EAL_PkeyNewCtx(CRYPT_EAL_PkeyGetId(source));
    if (key == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    SimDecoderImportCtx ctx = {source->method.import, key->key};
    BSL_Param param[] = {{CRYPT_PARAM_PKEY_PROCESS_FUNC, BSL_PARAM_TYPE_FUNC_PTR, SimDecoderImportKey, 0, 0},
                         {CRYPT_PARAM_PKEY_PROCESS_ARGS, BSL_PARAM_TYPE_CTX_PTR, &ctx, 0, 0},
                         BSL_PARAM_END};
    int32_t ret = source->method.export(source->key, param);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(key);
        return ret;
    }
    *out = key;
    return CRYPT_SUCCESS;
}

static void *SimDecoderNew(int32_t format, int32_t type)
{
    SimDecoder *ctx = BSL_SAL_Calloc(1, sizeof(*ctx));
    if (ctx != NULL) {
        ctx->format = format;
        ctx->type = type;
        ctx->attr = SIM_PROV_ATTR;
    }
    return ctx;
}

static int32_t SimDecoderSetParam(void *ctx, const BSL_Param *param)
{
    SimDecoder *decoder = ctx;
    RETURN_RET_IF(decoder == NULL || param == NULL, CRYPT_NULL_INPUT);
    const BSL_Param *p = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_DECODE_LIB_CTX);
    if (p != NULL) {
        RETURN_RET_IF(p->valueType != BSL_PARAM_TYPE_CTX_PTR, CRYPT_INVALID_ARG);
        decoder->libCtx = p->value;
    }
    p = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_DECODE_TARGET_ATTR_NAME);
    if (p != NULL) {
        RETURN_RET_IF(p->valueType != BSL_PARAM_TYPE_OCTETS_PTR, CRYPT_INVALID_ARG);
        decoder->attr = p->value;
    }
    p = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_DECODE_PROVIDER_CTX);
    if (p != NULL) {
        RETURN_RET_IF(p->valueType != BSL_PARAM_TYPE_CTX_PTR, CRYPT_INVALID_ARG);
        decoder->mgr = p->value;
    }
    return CRYPT_SUCCESS;
}

static int32_t SimDecoderGetParam(void *ctx, BSL_Param *param)
{
    RETURN_RET_IF(ctx == NULL || param == NULL, CRYPT_NULL_INPUT);
    BSL_Param *p = BSL_PARAM_FindParam(param, CRYPT_PARAM_DECODE_OUTPUT_FORMAT);
    if (p != NULL) {
        RETURN_RET_IF(p->valueType != BSL_PARAM_TYPE_OCTETS_PTR, CRYPT_INVALID_ARG);
        p->value = "OBJECT";
        p->useLen = sizeof("OBJECT");
    }
    p = BSL_PARAM_FindParam(param, CRYPT_PARAM_DECODE_OUTPUT_TYPE);
    if (p != NULL) {
        RETURN_RET_IF(p->valueType != BSL_PARAM_TYPE_OCTETS_PTR, CRYPT_INVALID_ARG);
        p->value = "HIGH_KEY";
        p->useLen = sizeof("HIGH_KEY");
    }
    return CRYPT_SUCCESS;
}

static int32_t SimDecoderDecode(void *ctx, const BSL_Param *input, BSL_Param **output)
{
    SimDecoder *decoder = ctx;
    RETURN_RET_IF(decoder == NULL || input == NULL || output == NULL, CRYPT_NULL_INPUT);
    RETURN_RET_IF(*output != NULL, CRYPT_INVALID_ARG);
    if (decoder->attr == NULL || strcmp(decoder->attr, SIM_PROV_ATTR) != 0) {
        return CRYPT_NOT_SUPPORT;
    }
    const BSL_Param *data = BSL_PARAM_FindConstParam(input, CRYPT_PARAM_DECODE_BUFFER_DATA);
    RETURN_RET_IF(data == NULL || data->value == NULL || data->valueLen == 0, CRYPT_NULL_INPUT);
    RETURN_RET_IF(data->valueType != BSL_PARAM_TYPE_OCTETS, CRYPT_INVALID_ARG);
    const BSL_Param *password = BSL_PARAM_FindConstParam(input, CRYPT_PARAM_DECODE_PASSWORD);
    RETURN_RET_IF(password != NULL && password->valueType != BSL_PARAM_TYPE_OCTETS, CRYPT_INVALID_ARG);
    SimOpCtx op = {.kind = SIM_OP_KIND_DECODE,
                   .operaId = CRYPT_EAL_OPERAID_DECODER,
                   .decodeFormat = decoder->format,
                   .decodeType = decoder->type,
                   .data = data->value,
                   .dataLen = data->valueLen,
                   .password = password == NULL ? NULL : password->value,
                   .passwordLen = password == NULL ? 0 : password->valueLen};
    int32_t ret = SimCryptoEntry(&op);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(op.decoded);
        return ret;
    }
    CRYPT_EAL_PkeyMgmtInfo info = {0};
    ret = CRYPT_EAL_GetPkeyAlgInfo(decoder->libCtx, CRYPT_EAL_PkeyGetId(op.decoded), decoder->attr, &info);
    if (ret != CRYPT_SUCCESS || info.mgrCtx != decoder->mgr) {
        CRYPT_EAL_PkeyFreeCtx(op.decoded);
        return ret != CRYPT_SUCCESS ? ret : CRYPT_NOT_SUPPORT;
    }
    BSL_Param *result = BSL_SAL_Calloc(2, sizeof(*result));
    if (result == NULL) {
        CRYPT_EAL_PkeyFreeCtx(op.decoded);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    /* Import into a built-in key so delegated operations retain NULL libCtx. */
    CRYPT_EAL_PkeyCtx *inner = NULL;
    ret = SimDecoderBuiltinKey(op.decoded, &inner);
    CRYPT_EAL_PkeyFreeCtx(op.decoded);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(result);
        return ret;
    }
    CRYPT_EAL_PkeyCtx *key = CRYPT_EAL_MakeKeyByPkeyAlgInfo(&info, inner);
    if (key == NULL) {
        CRYPT_EAL_PkeyFreeCtx(inner);
        BSL_SAL_Free(result);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    result[0] = (BSL_Param){CRYPT_PARAM_DECODE_OBJECT_DATA, BSL_PARAM_TYPE_CTX_PTR, key, 0, 0};
    *output = result;
    return CRYPT_SUCCESS;
}

static void SimDecoderFreeOutput(void *ctx, BSL_Param *output)
{
    (void)ctx;
    if (output != NULL) {
        BSL_Param *p = BSL_PARAM_FindParam(output, CRYPT_PARAM_DECODE_OBJECT_DATA);
        if (p != NULL) {
            CRYPT_EAL_PkeyFreeCtx(p->value);
        }
        BSL_SAL_Free(output);
    }
}

#define SIM_DECODER(name, format, type)                                 \
    static void *name##New(void *provCtx)                               \
    {                                                                   \
        (void)provCtx;                                                  \
        return SimDecoderNew(format, type);                             \
    }                                                                   \
    static const CRYPT_EAL_Func name[] = {                              \
        {CRYPT_DECODER_IMPL_NEWCTX, (void *)name##New},                 \
        {CRYPT_DECODER_IMPL_SETPARAM, (void *)SimDecoderSetParam},      \
        {CRYPT_DECODER_IMPL_GETPARAM, (void *)SimDecoderGetParam},      \
        {CRYPT_DECODER_IMPL_DECODE, (void *)SimDecoderDecode},          \
        {CRYPT_DECODER_IMPL_FREEOUTDATA, (void *)SimDecoderFreeOutput}, \
        {CRYPT_DECODER_IMPL_FREECTX, (void *)BSL_SAL_Free},             \
        CRYPT_EAL_FUNC_END,                                             \
    }

SIM_DECODER(g_simPkcs8, BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT);
SIM_DECODER(g_simEncrypted, BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_ENCRYPT);
SIM_DECODER(g_simEcc, BSL_FORMAT_ASN1, CRYPT_PRIKEY_ECC);
SIM_DECODER(g_simRsa, BSL_FORMAT_ASN1, CRYPT_PRIKEY_RSA);
SIM_DECODER(g_simDsa, BSL_FORMAT_ASN1, CRYPT_PRIKEY_DSA);
SIM_DECODER(g_simPubRsa, BSL_FORMAT_ASN1, CRYPT_PUBKEY_RSA);
SIM_DECODER(g_simPub, BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY);
SIM_DECODER(g_simPubRaw, BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY_WITHOUT_SEQ);

const CRYPT_EAL_AlgInfo g_simDecoderAlgs[] = {
    {BSL_CID_DECODE_UNKNOWN, g_simPkcs8,
     SIM_PROV_ATTR ",inFormat=ASN1,inType=PRIKEY_PKCS8_UNENCRYPT,outFormat=OBJECT,outType=HIGH_KEY"},
    {BSL_CID_DECODE_UNKNOWN, g_simEncrypted,
     SIM_PROV_ATTR ",inFormat=ASN1,inType=PRIKEY_PKCS8_ENCRYPT,outFormat=OBJECT,outType=HIGH_KEY"},
    {BSL_CID_DECODE_UNKNOWN, g_simEcc,
     SIM_PROV_ATTR ",inFormat=ASN1,inType=PRIKEY_ECC,outFormat=OBJECT,outType=HIGH_KEY"},
    {BSL_CID_DECODE_UNKNOWN, g_simRsa,
     SIM_PROV_ATTR ",inFormat=ASN1,inType=PRIKEY_RSA,outFormat=OBJECT,outType=HIGH_KEY"},
    {BSL_CID_DECODE_UNKNOWN, g_simDsa,
     SIM_PROV_ATTR ",inFormat=ASN1,inType=PRIKEY_DSA,outFormat=OBJECT,outType=HIGH_KEY"},
    {BSL_CID_DECODE_UNKNOWN, g_simPubRsa,
     SIM_PROV_ATTR ",inFormat=ASN1,inType=PUBKEY_RSA,outFormat=OBJECT,outType=HIGH_KEY"},
    {BSL_CID_DECODE_UNKNOWN, g_simPub,
     SIM_PROV_ATTR ",inFormat=ASN1,inType=PUBKEY_SUBKEY,outFormat=OBJECT,outType=HIGH_KEY"},
    {BSL_CID_DECODE_UNKNOWN, g_simPubRaw,
     SIM_PROV_ATTR ",inFormat=ASN1,inType=PUBKEY_SUBKEY_WITHOUT_SEQ,outFormat=OBJECT,outType=HIGH_KEY"},
    CRYPT_EAL_ALGINFO_END,
};

#endif /* HITLS_CRYPTO_PROVIDER */
