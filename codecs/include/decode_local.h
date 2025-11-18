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

#ifndef DECODE_LOCAL_H
#define DECODE_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CODECS
#include "crypt_eal_implprovider.h"
#include "crypt_eal_codecs.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define CRYPT_DECODER_STATE_UNTRIED 1
#define CRYPT_DECODER_STATE_TRING 2
#define CRYPT_DECODER_STATE_TRIED 3
#define CRYPT_DECODER_STATE_SUCCESS 4
#define MAX_CRYPT_DECODER_FORMAT_TYPE_STR_LEN 64
/**
 * @brief Decoder context structure
 */
typedef struct CRYPT_DECODER_Method {
    CRYPT_DECODER_IMPL_NewCtx newCtx;               /* New context function */
    CRYPT_DECODER_IMPL_SetParam setParam;           /* Set parameter function */
    CRYPT_DECODER_IMPL_GetParam getParam;           /* Get parameter function */
    CRYPT_DECODER_IMPL_Decode decode;               /* Decode function */
    CRYPT_DECODER_IMPL_FreeOutData freeOutData;     /* Free output data function */
    CRYPT_DECODER_IMPL_FreeCtx freeCtx;             /* Free context function */
} CRYPT_DECODER_Method;

struct CRYPT_DecoderCtx {
    /* To get the provider manager context when query */
    CRYPT_EAL_ProvMgrCtx *providerMgrCtx;     /* Provider manager context */
    char *attrName;                     /* Attribute name */
    const char *inFormat;                     /* Input data format */
    const char *inType;                       /* Input data type */
    const char *outFormat;                    /* Output data format */
    const char *outType;                      /* Output data type */
    void *decoderCtx;                   /* Decoder internal context */
    CRYPT_DECODER_Method *method;             /* Decoder method */
    int32_t decoderState;               /* Decoder state */
};

typedef struct {
    const char *format;                    /* Data format */
    const char *type;                      /* Data type */
    BSL_Param *data;                       /* Data */
} DataInfo;

typedef struct CRYPT_DECODER_Node {
    DataInfo inData;                       /* Input data */
    DataInfo outData;                      /* Output data */
    CRYPT_DECODER_Ctx *decoderCtx;         /* Decoder context */
} CRYPT_DECODER_Node;


#define MAX_CRYPT_DECODE_FORMAT_TYPE_SIZE 128
struct CRYPT_DECODER_PoolCtx {
    CRYPT_EAL_LibCtx *libCtx;               /* EAL library context */
    const char *attrName;                   /* Attribute name */
    const char *inputFormat;                /* Input data format */
    const char *inputType;                  /* Input data type */
    int32_t inputPkeyAlgId;                 /* Input pkey algorithm ID */
    BSL_Param *input;                       /* Input data */
    const char *targetFormat;               /* Target format */
    const char *targetType;                 /* Target type */
    int32_t targetKeyType;                  /* Target data key type */
    BslList *decoders;                      /* The decoders pool of all provider, the entry is CRYPT_DECODER_Ctx */
    BslList *decoderPath;                   /* The path of the decoder, the entry is CRYPT_DECODER_Node */
};

typedef struct {
    char *attrName;
    const char *inFormat;
    const char *inType;
    const char *outFormat;
    const char *outType;
} DECODER_AttrInfo;

int32_t CRYPT_DECODE_ParseDecoderAttr(const char *attrName, DECODER_AttrInfo *info);

CRYPT_DECODER_Ctx *CRYPT_DECODE_NewDecoderCtxByMethod(const CRYPT_EAL_Func *funcs, CRYPT_EAL_ProvMgrCtx *mgrCtx,
    const char *attrName);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* HITLS_CRYPTO_CODECS */

#endif /* DECODE_LOCAL_H */