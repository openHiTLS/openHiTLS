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

#include "auth_pake.h"
#include "spake2plus.h"
#include "auth_errno.h"
#include "crypt_errno.h"
#include "bsl_errno.h"
#include "bsl_params.h"
#include "securec.h"
#include "crypt_params_key.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"

typedef struct HITLS_AUTH_PakeCtx {
    CRYPT_EAL_LibCtx *libCtx;
    const char *attrName;
    HITLS_AUTH_PAKE_Type type;
    HITLS_AUTH_PAKE_Role role;
    BSL_Buffer password;
    BSL_Buffer prover;
    BSL_Buffer verifier;
    BSL_Buffer context;
    HITLS_AUTH_PAKE_CipherSuite cipherSuite;
    void *ctx;
} HITLS_AUTH_PakeCtx;

void HITLS_AUTH_PakeFreeCtx(HITLS_AUTH_PakeCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    
    BSL_SAL_ClearFree(ctx->password.data, ctx->password.dataLen);
    BSL_SAL_ClearFree(ctx->prover.data, ctx->prover.dataLen);
    BSL_SAL_ClearFree(ctx->verifier.data, ctx->verifier.dataLen);
    BSL_SAL_ClearFree(ctx->context.data, ctx->context.dataLen);
    switch (ctx->type) {
        case HITLS_AUTH_PAKE_SPAKE2PLUS:
            if (ctx->ctx != NULL) {
                Spake2PlusFreeCtx(ctx->ctx);
            }
            break;
        case HITLS_AUTH_PAKE_INVALID:
        default:
            break;
    }

    BSL_SAL_ClearFree(ctx, sizeof(HITLS_AUTH_PakeCtx));
}

HITLS_AUTH_PakeCtx *HITLS_AUTH_PakeNewCtx(CRYPT_EAL_LibCtx *libCtx, const char *attrName,
    HITLS_AUTH_PAKE_Type type, HITLS_AUTH_PAKE_Role role,
    HITLS_AUTH_PAKE_CipherSuite cipherSuite, BSL_Buffer password, BSL_Buffer prover,
    BSL_Buffer verifier, BSL_Buffer context )
{
    int32_t ret = HITLS_AUTH_SUCCESS;
    if (type == HITLS_AUTH_PAKE_INVALID) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_INVALID_PARAM);
        return NULL;
    }
    if (role != HITLS_AUTH_PAKE_REQ && role != HITLS_AUTH_PAKE_RESP) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_INVALID_PARAM);
        return NULL;
    }
    
    HITLS_AUTH_PakeCtx *ctx = (HITLS_AUTH_PakeCtx *)BSL_SAL_Calloc(1, sizeof(HITLS_AUTH_PakeCtx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_MEMORY_ALLOC_FAIL);
        return NULL;
    }

    ctx->libCtx = libCtx;
    ctx->attrName = attrName;
    ctx->type = type;
    ctx->role = role;
    ctx->cipherSuite = cipherSuite;

    switch (cipherSuite.type) {
        case HITLS_AUTH_PAKE_SPAKE2PLUS:
            ctx->ctx = Spake2PlusNewCtx(cipherSuite.params.spake2plus.curve);
            ret = Spake2PlusInitCipherSuite(ctx->ctx, &cipherSuite);
            if (ctx->ctx == NULL|| ret != HITLS_AUTH_SUCCESS) {
                BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_MEMORY_ALLOC_FAIL);
                HITLS_AUTH_PakeFreeCtx(ctx);
                return NULL;
            }
            break;
        case HITLS_AUTH_PAKE_INVALID:
        default:
            BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_INVALID_ALG_TYPE);
            HITLS_AUTH_PakeFreeCtx(ctx);
            return NULL;
    }

    ctx->password = (BSL_Buffer){.data = BSL_SAL_Malloc(password.dataLen), .dataLen = password.dataLen};
    ctx->prover = (BSL_Buffer){.data = BSL_SAL_Malloc(prover.dataLen), .dataLen = prover.dataLen};
    ctx->verifier = (BSL_Buffer){.data = BSL_SAL_Malloc(verifier.dataLen), .dataLen = verifier.dataLen};
    ctx->context = (BSL_Buffer){.data = BSL_SAL_Malloc(context.dataLen), .dataLen = context.dataLen};
    if (ctx->prover.data == NULL || ctx->verifier.data == NULL || ctx->context.data == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_MEMORY_ALLOC_FAIL);
        HITLS_AUTH_PakeFreeCtx(ctx);
        return NULL;
    }
    memcpy_s(ctx->password.data, ctx->password.dataLen, password.data, password.dataLen);
    memcpy_s(ctx->prover.data, ctx->prover.dataLen, prover.data, prover.dataLen);
    memcpy_s(ctx->verifier.data, ctx->verifier.dataLen, verifier.data, verifier.dataLen);
    memcpy_s(ctx->context.data, ctx->context.dataLen, context.data, context.dataLen);

    return ctx;
}
 
static int32_t HITLS_AUTH_PakeReqRegister(HITLS_AUTH_PakeCtx *ctx, CRYPT_EAL_KdfCTX* kdfctx,
    BSL_Buffer in0, BSL_Buffer in1, BSL_Buffer in2)
{
    if (ctx == NULL || kdfctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_NULL_INPUT);
        return HITLS_AUTH_NULL_INPUT;
    }

    if (ctx->role != HITLS_AUTH_PAKE_REQ) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_INVALID_ROLE);
        return HITLS_AUTH_PAKE_INVALID_ROLE;
    }

    int32_t ret = HITLS_AUTH_SUCCESS;
    switch (ctx->type) {
        case HITLS_AUTH_PAKE_SPAKE2PLUS:
            ret=HITLS_AUTH_Spake2plusReqRegister(ctx, kdfctx, in0, in1, in2);
            break;
        default:
            ret=HITLS_AUTH_INVALID_ARG;
            break;
    }
    return ret;
}

static int32_t HITLS_AUTH_PakeRespRegister(HITLS_AUTH_PakeCtx *ctx, CRYPT_EAL_KdfCTX *kdfctx,
    BSL_Buffer in0, BSL_Buffer in1, BSL_Buffer in2)
{
    (void)kdfctx;
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_NULL_INPUT);
        return HITLS_AUTH_NULL_INPUT;
    }

    if (ctx->role != HITLS_AUTH_PAKE_RESP) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_INVALID_ROLE);
        return HITLS_AUTH_PAKE_INVALID_ROLE;
    }

    int32_t ret = HITLS_AUTH_SUCCESS;
    switch (ctx->type) {
        case HITLS_AUTH_PAKE_SPAKE2PLUS:
            ret = HITLS_AUTH_Spake2plusRespRegister(ctx, in0, in1, in2);
            break;
        default:
            ret=HITLS_AUTH_INVALID_ARG;
            break;
    }
    return ret;
}

int32_t HITLS_AUTH_Pake_Ctrl(HITLS_AUTH_PakeCtx *ctx, HITLS_AUTH_PAKE_CtrlCmd cmd, CRYPT_EAL_KdfCTX *kdfctx,
    BSL_Buffer in0, BSL_Buffer in1, BSL_Buffer in2)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_NULL_INPUT);
        return HITLS_AUTH_NULL_INPUT;
    }

    int32_t ret = HITLS_AUTH_SUCCESS;
    switch (cmd) {
        case HITLS_AUTH_PAKE_REQ_REGISTER:
            if (ctx->role != HITLS_AUTH_PAKE_REQ) {
                BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_INVALID_ROLE);
                return HITLS_AUTH_PAKE_INVALID_ROLE;
            }
            ret=HITLS_AUTH_PakeReqRegister(ctx, kdfctx, in0, in1, in2);
            break;
        case HITLS_AUTH_PAKE_RESP_REGISTER:
            if (ctx->role != HITLS_AUTH_PAKE_RESP) {
                BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_INVALID_ROLE);
                return HITLS_AUTH_PAKE_INVALID_ROLE;
            }
            ret = HITLS_AUTH_PakeRespRegister(ctx, kdfctx, in0, in1, in2);
            break;
        default:
            ret = HITLS_AUTH_INVALID_ARG;
            break;
    }
    return ret;
}

int32_t HITLS_AUTH_PakeReqSetup(HITLS_AUTH_PakeCtx *ctx, BSL_Buffer in, BSL_Buffer *out)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_NULL_INPUT);
        return HITLS_AUTH_NULL_INPUT;
    }

    if (ctx->role != HITLS_AUTH_PAKE_REQ) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_INVALID_ROLE);
        return HITLS_AUTH_PAKE_INVALID_ROLE;
    }
    
    int32_t ret = HITLS_AUTH_SUCCESS;
    switch (ctx->type) {
        case HITLS_AUTH_PAKE_SPAKE2PLUS:
            ret = HITLS_AUTH_Spake2plusReqSetup(ctx, in, out);
            break;
        default:
            ret = HITLS_AUTH_INVALID_ARG;
            break;
    }
    return ret;
}

int32_t HITLS_AUTH_PakeRespSetup(HITLS_AUTH_PakeCtx *ctx, BSL_Buffer in0, BSL_Buffer in1,
    BSL_Buffer *out0, BSL_Buffer *out1)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_NULL_INPUT);
        return HITLS_AUTH_NULL_INPUT;
    }
    
    if (ctx->role != HITLS_AUTH_PAKE_RESP) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_INVALID_ROLE);
        return HITLS_AUTH_PAKE_INVALID_ROLE;
    }
    
    int32_t ret = HITLS_AUTH_SUCCESS;
    switch (ctx->type) {
        case HITLS_AUTH_PAKE_SPAKE2PLUS:
            ret = HITLS_AUTH_Spake2plusRespSetup(ctx, in0, in1, out0, out1);
            break;
        case HITLS_AUTH_PAKE_INVALID:
        default:
            ret=HITLS_AUTH_INVALID_ARG;
            break;
    }
    return ret;
}

int32_t HITLS_AUTH_PakeReqDerive(HITLS_AUTH_PakeCtx *ctx, BSL_Buffer in0, BSL_Buffer in1,
    BSL_Buffer *out0, BSL_Buffer *out1)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_NULL_INPUT);
        return HITLS_AUTH_NULL_INPUT;
    }

    if (ctx->role != HITLS_AUTH_PAKE_REQ) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_INVALID_ROLE);
        return HITLS_AUTH_PAKE_INVALID_ROLE;
    }
    
    int32_t ret = HITLS_AUTH_SUCCESS;
    switch (ctx->type) {
        case HITLS_AUTH_PAKE_SPAKE2PLUS:
            ret=HITLS_AUTH_Spake2plusReqDerive(ctx, in0, in1, out0, out1);
            break;
        case HITLS_AUTH_PAKE_INVALID:
        default:
            ret = HITLS_AUTH_INVALID_ARG;
            break;
    }
    return ret;
}

int32_t HITLS_AUTH_PakeRespDerive(HITLS_AUTH_PakeCtx *ctx, BSL_Buffer in0, BSL_Buffer *out0)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_NULL_INPUT);
        return HITLS_AUTH_NULL_INPUT;
    }

    if (ctx->role != HITLS_AUTH_PAKE_RESP) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_INVALID_ROLE);
        return HITLS_AUTH_PAKE_INVALID_ROLE;
    }

    int32_t ret = HITLS_AUTH_SUCCESS;
    switch (ctx->type) {
        case HITLS_AUTH_PAKE_SPAKE2PLUS:
            ret = HITLS_AUTH_Spake2plusRespDerive(ctx, in0, out0);
            break;
        case HITLS_AUTH_PAKE_INVALID:
        default:
            ret = HITLS_AUTH_INVALID_ARG;
            break;
    }
    return ret;
}

CRYPT_EAL_KdfCTX* HITLS_AUTH_PakeGetKdfCtx(HITLS_AUTH_PakeCtx* ctx, HITLS_AUTH_PAKE_KDF kdf)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_NULL_INPUT);
        return NULL;
    }

    switch (kdf.algId) {
        case CRYPT_KDF_PBKDF2: {
            uint32_t totalLen = ctx->password.dataLen + ctx->prover.dataLen + ctx->verifier.dataLen;
            uint8_t *buffer = BSL_SAL_Malloc(totalLen);
            if (buffer == NULL) {
                BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_MEMORY_ALLOC_FAIL);
                return NULL;
            }
            
            CRYPT_MAC_AlgId algId = kdf.param.pbkdf2.mac;
            uint32_t it = kdf.param.pbkdf2.iteration;
            uint32_t saltLen = kdf.param.pbkdf2.salt.dataLen;
            uint8_t *salt = kdf.param.pbkdf2.salt.data;
            int32_t ret = HITLS_AUTH_SUCCESS;

            (void)memcpy_s(buffer, ctx->password.dataLen, ctx->password.data, ctx->password.dataLen);
            (void)memcpy_s(buffer + ctx->password.dataLen, ctx->prover.dataLen, ctx->prover.data, ctx->prover.dataLen);
            (void)memcpy_s(buffer + ctx->password.dataLen + ctx->prover.dataLen, ctx->verifier.dataLen,
                ctx->verifier.data, ctx->verifier.dataLen);
            CRYPT_EAL_KdfCTX *kdfCtx = CRYPT_EAL_KdfNewCtx(kdf.algId);
            if (kdfCtx == NULL) {
                BSL_SAL_Free(buffer);
                BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_MEMORY_ALLOC_FAIL);
                return NULL;
            }
            BSL_Param params[5] = {{0}, {0}, {0}, {0}, BSL_PARAM_END};
            ret = BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, &algId, sizeof(algId));
            if (ret != HITLS_AUTH_SUCCESS) {
                goto ERR;
            }
            ret = BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_PASSWORD, BSL_PARAM_TYPE_OCTETS, buffer, totalLen);
            if (ret != HITLS_AUTH_SUCCESS) {
                goto ERR;
            }
            ret = BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS, salt, saltLen);
            if (ret!=HITLS_AUTH_SUCCESS) {
                goto ERR;
            }
            ret = BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_ITER, BSL_PARAM_TYPE_UINT32, &it, sizeof(it));
            if (ret != HITLS_AUTH_SUCCESS) {
                goto ERR;
            }
            ret = CRYPT_EAL_KdfSetParam(kdfCtx, params);
            if (ret != HITLS_AUTH_SUCCESS) {
                goto ERR;
            }
            BSL_SAL_Free(buffer);
            return kdfCtx;
            ERR:
            BSL_SAL_Free(buffer);
            CRYPT_EAL_KdfFreeCtx(kdfCtx);
            return NULL;
        }
        default:
            BSL_ERR_PUSH_ERROR(HITLS_AUTH_PAKE_INVALID_ALG_TYPE);
            return NULL;
    }
}

void *HITLS_AUTH_PakeGetInternalCtx(HITLS_AUTH_PakeCtx *ctx)
{
    if (ctx == NULL)
        return NULL;
    return ctx->ctx;
}

BSL_Buffer HITLS_AUTH_PakeGetPassword(HITLS_AUTH_PakeCtx *ctx)
{
    if (ctx == NULL)
        return (BSL_Buffer){0};
    return ctx->password;
}

BSL_Buffer HITLS_AUTH_PakeGetProver(HITLS_AUTH_PakeCtx *ctx)
{
    if (ctx == NULL)
        return (BSL_Buffer){0};
    return ctx->prover;
}

BSL_Buffer HITLS_AUTH_PakeGetVerifier(HITLS_AUTH_PakeCtx *ctx)
{
    if (ctx == NULL)
        return (BSL_Buffer){0};
    return ctx->verifier;
}

HITLS_AUTH_PAKE_CipherSuite HITLS_AUTH_PakeGetCipherSuite(HITLS_AUTH_PakeCtx *ctx)
{
    if (ctx == NULL)
        return (HITLS_AUTH_PAKE_CipherSuite){0};
    return ctx->cipherSuite;
}

BSL_Buffer HITLS_AUTH_PakeGetContext(HITLS_AUTH_PakeCtx *ctx)
{
    if (ctx == NULL)
        return (BSL_Buffer){0};
    return ctx->context;
}
