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
#ifdef HITLS_CRYPTO_ZUC

#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "securec.h"
#include "crypt_utils.h"
#include "crypt_errno.h"
#include "crypt_zuc_local.h"
#include "crypt_local_types.h"

int32_t CRYPT_ZUC_SetKey128(CRYPT_ZUC_Ctx *ctx, const uint8_t *key, uint32_t len){
    if (ctx == NULL || key == NULL || len == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != CRYPT_ZUC128_KEYLEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_ZUC_KEYLEN_ERROR);
        return CRYPT_ZUC_KEYLEN_ERROR;
    }

    memcpy_s(ctx->key, CRYPT_ZUC128_KEYLEN, key, CRYPT_ZUC128_KEYLEN);
    ctx->set |= KEYSET;
    ctx->type = CRYPT_ZUC128;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_ZUC_SetKey256(CRYPT_ZUC_Ctx *ctx, const uint8_t *key, uint32_t len){
    if (ctx == NULL || key == NULL || len == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != CRYPT_ZUC256_KEYLEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_ZUC_KEYLEN_ERROR);
        return CRYPT_ZUC_KEYLEN_ERROR;
    }

    memcpy_s(ctx->key, CRYPT_ZUC256_KEYLEN, key, CRYPT_ZUC256_KEYLEN);
    ctx->set |= KEYSET;
    ctx->type = CRYPT_ZUC256;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_ZUC_SetIV(CRYPT_ZUC_Ctx *ctx, const uint8_t *iv, uint32_t len){
    if (ctx == NULL || iv == NULL || len == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    // MODES ZUC-GXM will always set key first, so ctx->type is set
    if (len != CRYPT_ZUC_IVLEN16B && !(len == CRYPT_ZUC_IVLEN23B && ctx->type & CRYPT_ZUC256)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ZUC_IVLEN_ERROR);
        return CRYPT_ZUC_IVLEN_ERROR;
    }
    if (len == CRYPT_ZUC_IVLEN16B) {
        memcpy_s(ctx->iv, CRYPT_ZUC_IVLEN16B, iv, CRYPT_ZUC_IVLEN16B);
        ctx->ivlen = CRYPT_ZUC_IVLEN16B;
    } 
    else {  // CRYPT_ZUC_IVLEN23B
        // IV[0] ... IV[16] is 8 bit, IV[17] ... IV[24] is 6 bit
        memcpy_s(ctx->iv, CRYPT_ZUC_IVLEN23B - 6, iv, CRYPT_ZUC_IVLEN23B - 6);
        ctx->iv[17] = iv[17]>>2;
        ctx->iv[18] = (iv[17]<<4 & 0x3f) | (iv[18] >> 4);
        ctx->iv[19] = (iv[18]<<2 & 0x3f) | (iv[19] >> 6);
        ctx->iv[20] = iv[19] & 0x3f;
        ctx->iv[21] = iv[20]>>2;
        ctx->iv[22] = (iv[20]<<4 & 0x3f) | (iv[21] >> 4);
        ctx->iv[23] = (iv[21]<<2 & 0x3f) | (iv[22] >> 6);
        ctx->iv[24] = iv[22] & 0x3f;
        ctx->ivlen = CRYPT_ZUC_IVLEN23B;
    }
    ctx->set |= IVSET;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_ZUC_Update(CRYPT_ZUC_Ctx *ctx, const uint8_t *in,
    uint8_t *out, uint32_t len)
{
    if (ctx == NULL || out == NULL || in == NULL || len == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if ((ctx->set & KEYSET) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_ZUC_NO_KEYINFO);
        return CRYPT_ZUC_NO_KEYINFO;
    }
    if ((ctx->set & IVSET) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_ZUC_NO_IVINFO);
        return CRYPT_ZUC_NO_IVINFO;
    }
    if (len > CRYPT_ZUC_MAX_KEYSTREAMLEN) { // max key stream len is set 65536 currently.
        BSL_ERR_PUSH_ERROR(CRYPT_ZUC_KEYSTREAM_TOO_LONG);
        return CRYPT_ZUC_KEYSTREAM_TOO_LONG;
    }

    const uint8_t *offIn = in;
    uint8_t *offOut = out;
    uint32_t tlen = len&0xfffffffc;
    uint8_t remLen = (len&0x00000003)? (4 - (len&0x00000003)): 0;
    uint8_t tmp[4];
    ZUC_GenKeyStream(ctx, offOut, tlen);

    for(uint16_t i = 0; i < tlen; i += 4){
        offOut[i]   = offIn[i]   ^ offOut[i];
        offOut[i+1] = offIn[i+1] ^ offOut[i+1];
        offOut[i+2] = offIn[i+2] ^ offOut[i+2];
        offOut[i+3] = offIn[i+3] ^ offOut[i+3];
    }
    if(remLen){
        ZUC_GenKeyStream(ctx, tmp, 4);
        for(uint16_t i = 0; i < remLen; ++i)
            offOut[tlen + i] = offIn[tlen + i] ^ tmp[i];
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_ZUC_Ctrl(CRYPT_ZUC_Ctx *ctx, int32_t opt, void *val, uint32_t len)
{
    if (ctx == NULL || val == NULL || len == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if(!(ctx->set & KEYSET)){
        BSL_ERR_PUSH_ERROR(CRYPT_ZUC_NO_KEYINFO);
        return CRYPT_ZUC_NO_KEYINFO;
    }
    int32_t ret;
    switch (opt) {
        case CRYPT_CTRL_SET_IV: // every time the initialization vecotr is set, 
                                // zuc needs to reinit
            ret = CRYPT_ZUC_SetIV(ctx, val, len);
            if(ret != CRYPT_SUCCESS){
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            ZUC_Init(ctx);
            return CRYPT_SUCCESS;
            
        case CRYPT_CTRL_GET_IV:
            if(!(ctx->set & IVSET)){
                BSL_ERR_PUSH_ERROR(CRYPT_ZUC_NO_IVINFO);
                return CRYPT_ZUC_NO_IVINFO;
            }
            if(ctx->ivlen == CRYPT_ZUC_IVLEN16B)
                ret = memcpy_s(val, CRYPT_ZUC_IVLEN16B, (void*)ctx->iv, CRYPT_ZUC_IVLEN16B);
            else {
                uint8_t * out = (uint8_t *)val;
                ret = memcpy_s(out, CRYPT_ZUC_IVLEN23B - 6, (void*)ctx->iv, CRYPT_ZUC_IVLEN23B - 6);
                out[17] = (ctx->iv[17]<<2) | (ctx->iv[18]>>4);
                out[18] = (ctx->iv[18]<<4) | (ctx->iv[19]>>2);
                out[19] = (ctx->iv[19]<<6) | (ctx->iv[20]);
                out[20] = (ctx->iv[21]<<2) | (ctx->iv[22]>>4);
                out[21] = (ctx->iv[22]<<4) | (ctx->iv[23]>>2);
                out[22] = (ctx->iv[23]<<2) | (ctx->iv[24]);
            }
            if(ret != EOK){
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            return CRYPT_SUCCESS;

        default:
            BSL_ERR_PUSH_ERROR(CRYPT_ZUC_CTRLTYPE_ERROR);
            return CRYPT_ZUC_CTRLTYPE_ERROR;
    }
}

void CRYPT_ZUC_Clean(CRYPT_ZUC_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    memset_s(ctx, sizeof(CRYPT_ZUC_Ctx), 0, sizeof(CRYPT_ZUC_Ctx));
    ctx = NULL;
    return;
}

#endif // HITLS_CRYPTO_ZUC
