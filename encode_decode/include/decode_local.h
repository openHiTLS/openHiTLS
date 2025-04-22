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

#ifdef HITLS_CRYPTO_PROVIDER
#include "crypt_eal_implprovider.h"

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
typedef struct _Decoder_Method {
    CRYPT_DECODER_IMPL_NewCtx newCtx;               /* New context function */
    CRYPT_DECODER_IMPL_SetParam setParam;           /* Set parameter function */
    CRYPT_DECODER_IMPL_GetParam getParam;           /* Get parameter function */
    CRYPT_DECODER_IMPL_Decode decode;               /* Decode function */
    CRYPT_DECODER_IMPL_FreeOutData freeOutData;     /* Free output data function */
    CRYPT_DECODER_IMPL_FreeCtx freeCtx;             /* Free context function */
} Decoder_Method; 

struct CRYPT_DecoderCtx {
    /* To get the provider manager context when query */
    CRYPT_EAL_ProvMgrCtx *providerMgrCtx;     /* Provider manager context */
    char *inFormat;                     /* Input data format */
    char *inType;                       /* Input data type */
    char *outFormat;                    /* Output data format */
    char *outType;                      /* Output data type */
    void *decoderCtx;                         /* Decoder internal context */
    Decoder_Method *method;                   /* Decoder method */
    int32_t decoderState;                     /* Decoder state */
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
    const char *inFormat, const char *inType, const char *outFormat, const char *outType);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* HITLS_CRYPTO_PROVIDER */

#endif /* DECODE_LOCAL_H */