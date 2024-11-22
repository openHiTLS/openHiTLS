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

#include "crypt_eal_implprovider.h"
#include "crypt_md5.h"
#include "crypt_sha1.h"
#include "crypt_sha2.h"
#include "crypt_sha3.h"
#include "crypt_sm3.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "bsl_log_internal.h"
#include "bsl_err_internal.h"
#include "crypt_ealinit.h"

static void *CRYPT_EAL_DefMdNewCtx(void *provCtx, int32_t algId)
{
    (void) provCtx;
    void *mdCtx = NULL;
#ifdef HITLS_CRYPTO_ASM_CHECK
    if (CRYPT_ASMCAP_Md(algId) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return NULL;
    }
#endif
    switch (algId) {
        case CRYPT_MD_MD5:
            mdCtx = CRYPT_MD5_NewCtx();
            break;
        case CRYPT_MD_SHA1:
            mdCtx = CRYPT_SHA1_NewCtx();
            break;
        case CRYPT_MD_SHA224:
            mdCtx = CRYPT_SHA2_224_NewCtx();
            break;
        case CRYPT_MD_SHA256:
            mdCtx = CRYPT_SHA2_256_NewCtx();
            break;
        case CRYPT_MD_SHA384:
            mdCtx = CRYPT_SHA2_384_NewCtx();
            break;
        case CRYPT_MD_SHA512:
            mdCtx = CRYPT_SHA2_512_NewCtx();
            break;
        case CRYPT_MD_SHA3_224:
            mdCtx = CRYPT_SHA3_256_NewCtx();
            break;
        case CRYPT_MD_SHA3_256:
            mdCtx = CRYPT_SHA3_256_NewCtx();
            break;
        case CRYPT_MD_SHA3_384:
            mdCtx = CRYPT_SHA3_256_NewCtx();
            break;
        case CRYPT_MD_SHA3_512:
            mdCtx = CRYPT_SHA3_256_NewCtx();
            break;
        case CRYPT_MD_SHAKE128:
            mdCtx = CRYPT_SHAKE256_NewCtx();
            break;
        case CRYPT_MD_SHAKE256:
            mdCtx = CRYPT_SHAKE256_NewCtx();
            break;
        case CRYPT_MD_SM3:
            mdCtx = CRYPT_SM3_NewCtx();
            break;
    }
    if (mdCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_NOT_SUPPORT);
        return NULL;
    }
    return mdCtx;
}

int32_t CRYPT_EAL_DefMdCtrl(void *ctx, int32_t cmd, void *val, uint32_t valLen)
{
    (void) ctx;
    (void) cmd;
    (void) val;
    (void) valLen;
    BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
    return CRYPT_NOT_SUPPORT;
}

const CRYPT_EAL_Func g_defMdMd5[] = {
    {CRYPT_EAL_IMPLMD_NEWCTX, CRYPT_EAL_DefMdNewCtx},
    {CRYPT_EAL_IMPLMD_INITCTX, CRYPT_MD5_Init},
    {CRYPT_EAL_IMPLMD_UPDATE, CRYPT_MD5_Update},
    {CRYPT_EAL_IMPLMD_FINAL, CRYPT_MD5_Final},
    {CRYPT_EAL_IMPLMD_DEINITCTX, CRYPT_MD5_Deinit},
    {CRYPT_EAL_IMPLMD_DUPCTX, CRYPT_MD5_DupCtx},
    {CRYPT_EAL_IMPLMD_CTRL, CRYPT_EAL_DefMdCtrl},
    {CRYPT_EAL_IMPLMD_FREECTX, CRYPT_MD5_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defMdSha1[] = {
    {CRYPT_EAL_IMPLMD_NEWCTX, CRYPT_EAL_DefMdNewCtx},
    {CRYPT_EAL_IMPLMD_INITCTX, CRYPT_SHA1_Init},
    {CRYPT_EAL_IMPLMD_UPDATE, CRYPT_SHA1_Update},
    {CRYPT_EAL_IMPLMD_FINAL, CRYPT_SHA1_Final},
    {CRYPT_EAL_IMPLMD_DEINITCTX, CRYPT_SHA1_Deinit},
    {CRYPT_EAL_IMPLMD_DUPCTX, CRYPT_SHA1_DupCtx},
    {CRYPT_EAL_IMPLMD_CTRL, CRYPT_EAL_DefMdCtrl},
    {CRYPT_EAL_IMPLMD_FREECTX, CRYPT_SHA1_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defMdSha224[] = {
    {CRYPT_EAL_IMPLMD_NEWCTX, CRYPT_EAL_DefMdNewCtx},
    {CRYPT_EAL_IMPLMD_INITCTX, CRYPT_SHA2_224_Init},
    {CRYPT_EAL_IMPLMD_UPDATE, CRYPT_SHA2_224_Update},
    {CRYPT_EAL_IMPLMD_FINAL, CRYPT_SHA2_224_Final},
    {CRYPT_EAL_IMPLMD_DEINITCTX, CRYPT_SHA2_224_Deinit},
    {CRYPT_EAL_IMPLMD_DUPCTX, CRYPT_SHA2_224_DupCtx},
    {CRYPT_EAL_IMPLMD_CTRL, CRYPT_EAL_DefMdCtrl},
    {CRYPT_EAL_IMPLMD_FREECTX, CRYPT_SHA2_224_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defMdSha256[] = {
    {CRYPT_EAL_IMPLMD_NEWCTX, CRYPT_EAL_DefMdNewCtx},
    {CRYPT_EAL_IMPLMD_INITCTX, CRYPT_SHA2_256_Init},
    {CRYPT_EAL_IMPLMD_UPDATE, CRYPT_SHA2_256_Update},
    {CRYPT_EAL_IMPLMD_FINAL, CRYPT_SHA2_256_Final},
    {CRYPT_EAL_IMPLMD_DEINITCTX, CRYPT_SHA2_256_Deinit},
    {CRYPT_EAL_IMPLMD_DUPCTX, CRYPT_SHA2_256_DupCtx},
    {CRYPT_EAL_IMPLMD_CTRL, CRYPT_EAL_DefMdCtrl},
    {CRYPT_EAL_IMPLMD_FREECTX, CRYPT_SHA2_256_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defMdSha384[] = {
    {CRYPT_EAL_IMPLMD_NEWCTX, CRYPT_EAL_DefMdNewCtx},
    {CRYPT_EAL_IMPLMD_INITCTX, CRYPT_SHA2_384_Init},
    {CRYPT_EAL_IMPLMD_UPDATE, CRYPT_SHA2_384_Update},
    {CRYPT_EAL_IMPLMD_FINAL, CRYPT_SHA2_384_Final},
    {CRYPT_EAL_IMPLMD_DEINITCTX, CRYPT_SHA2_384_Deinit},
    {CRYPT_EAL_IMPLMD_DUPCTX, CRYPT_SHA2_384_DupCtx},
    {CRYPT_EAL_IMPLMD_CTRL, CRYPT_EAL_DefMdCtrl},
    {CRYPT_EAL_IMPLMD_FREECTX, CRYPT_SHA2_384_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defMdSha512[] = {
    {CRYPT_EAL_IMPLMD_NEWCTX, CRYPT_EAL_DefMdNewCtx},
    {CRYPT_EAL_IMPLMD_INITCTX, CRYPT_SHA2_512_Init},
    {CRYPT_EAL_IMPLMD_UPDATE, CRYPT_SHA2_512_Update},
    {CRYPT_EAL_IMPLMD_FINAL, CRYPT_SHA2_512_Final},
    {CRYPT_EAL_IMPLMD_DEINITCTX, CRYPT_SHA2_512_Deinit},
    {CRYPT_EAL_IMPLMD_DUPCTX, CRYPT_SHA2_512_DupCtx},
    {CRYPT_EAL_IMPLMD_CTRL, CRYPT_EAL_DefMdCtrl},
    {CRYPT_EAL_IMPLMD_FREECTX, CRYPT_SHA2_512_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defMdSha3224[] = {
    {CRYPT_EAL_IMPLMD_NEWCTX, CRYPT_EAL_DefMdNewCtx},
    {CRYPT_EAL_IMPLMD_INITCTX, CRYPT_SHA3_224_Init},
    {CRYPT_EAL_IMPLMD_UPDATE, CRYPT_SHA3_224_Update},
    {CRYPT_EAL_IMPLMD_FINAL, CRYPT_SHA3_224_Final},
    {CRYPT_EAL_IMPLMD_DEINITCTX, CRYPT_SHA3_224_Deinit},
    {CRYPT_EAL_IMPLMD_DUPCTX, CRYPT_SHA3_224_DupCtx},
    {CRYPT_EAL_IMPLMD_CTRL, CRYPT_EAL_DefMdCtrl},
    {CRYPT_EAL_IMPLMD_FREECTX, CRYPT_SHA3_224_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defMdSha3256[] = {
    {CRYPT_EAL_IMPLMD_NEWCTX, CRYPT_EAL_DefMdNewCtx},
    {CRYPT_EAL_IMPLMD_INITCTX, CRYPT_SHA3_256_Init},
    {CRYPT_EAL_IMPLMD_UPDATE, CRYPT_SHA3_256_Update},
    {CRYPT_EAL_IMPLMD_FINAL, CRYPT_SHA3_256_Final},
    {CRYPT_EAL_IMPLMD_DEINITCTX, CRYPT_SHA3_256_Deinit},
    {CRYPT_EAL_IMPLMD_DUPCTX, CRYPT_SHA3_256_DupCtx},
    {CRYPT_EAL_IMPLMD_CTRL, CRYPT_EAL_DefMdCtrl},
    {CRYPT_EAL_IMPLMD_FREECTX, CRYPT_SHA3_256_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defMdSha3384[] = {
    {CRYPT_EAL_IMPLMD_NEWCTX, CRYPT_EAL_DefMdNewCtx},
    {CRYPT_EAL_IMPLMD_INITCTX, CRYPT_SHA3_384_Init},
    {CRYPT_EAL_IMPLMD_UPDATE, CRYPT_SHA3_384_Update},
    {CRYPT_EAL_IMPLMD_FINAL, CRYPT_SHA3_384_Final},
    {CRYPT_EAL_IMPLMD_DEINITCTX, CRYPT_SHA3_384_Deinit},
    {CRYPT_EAL_IMPLMD_DUPCTX, CRYPT_SHA3_384_DupCtx},
    {CRYPT_EAL_IMPLMD_CTRL, CRYPT_EAL_DefMdCtrl},
    {CRYPT_EAL_IMPLMD_FREECTX, CRYPT_SHA3_384_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defMdSha3512[] = {
    {CRYPT_EAL_IMPLMD_NEWCTX, CRYPT_EAL_DefMdNewCtx},
    {CRYPT_EAL_IMPLMD_INITCTX, CRYPT_SHA3_512_Init},
    {CRYPT_EAL_IMPLMD_UPDATE, CRYPT_SHA3_512_Update},
    {CRYPT_EAL_IMPLMD_FINAL, CRYPT_SHA3_512_Final},
    {CRYPT_EAL_IMPLMD_DEINITCTX, CRYPT_SHA3_512_Deinit},
    {CRYPT_EAL_IMPLMD_DUPCTX, CRYPT_SHA3_512_DupCtx},
    {CRYPT_EAL_IMPLMD_CTRL, CRYPT_EAL_DefMdCtrl},
    {CRYPT_EAL_IMPLMD_FREECTX, CRYPT_SHA3_512_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defMdShake128[] = {
    {CRYPT_EAL_IMPLMD_NEWCTX, CRYPT_EAL_DefMdNewCtx},
    {CRYPT_EAL_IMPLMD_INITCTX, CRYPT_SHAKE128_Init},
    {CRYPT_EAL_IMPLMD_UPDATE, CRYPT_SHAKE128_Update},
    {CRYPT_EAL_IMPLMD_FINAL, CRYPT_SHAKE128_Final},
    {CRYPT_EAL_IMPLMD_DEINITCTX, CRYPT_SHAKE128_Deinit},
    {CRYPT_EAL_IMPLMD_DUPCTX, CRYPT_SHAKE128_DupCtx},
    {CRYPT_EAL_IMPLMD_CTRL, CRYPT_EAL_DefMdCtrl},
    {CRYPT_EAL_IMPLMD_FREECTX, CRYPT_SHAKE128_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defMdShake256[] = {
    {CRYPT_EAL_IMPLMD_NEWCTX, CRYPT_EAL_DefMdNewCtx},
    {CRYPT_EAL_IMPLMD_INITCTX, CRYPT_SHAKE256_Init},
    {CRYPT_EAL_IMPLMD_UPDATE, CRYPT_SHAKE256_Update},
    {CRYPT_EAL_IMPLMD_FINAL, CRYPT_SHAKE256_Final},
    {CRYPT_EAL_IMPLMD_DEINITCTX, CRYPT_SHAKE256_Deinit},
    {CRYPT_EAL_IMPLMD_DUPCTX, CRYPT_SHAKE256_DupCtx},
    {CRYPT_EAL_IMPLMD_CTRL, CRYPT_EAL_DefMdCtrl},
    {CRYPT_EAL_IMPLMD_FREECTX, CRYPT_SHAKE256_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defMdSm3[] = {
    {CRYPT_EAL_IMPLMD_NEWCTX, CRYPT_EAL_DefMdNewCtx},
    {CRYPT_EAL_IMPLMD_INITCTX, CRYPT_SM3_Init},
    {CRYPT_EAL_IMPLMD_UPDATE, CRYPT_SM3_Update},
    {CRYPT_EAL_IMPLMD_FINAL, CRYPT_SM3_Final},
    {CRYPT_EAL_IMPLMD_DEINITCTX, CRYPT_SM3_Deinit},
    {CRYPT_EAL_IMPLMD_DUPCTX, CRYPT_SM3_DupCtx},
    {CRYPT_EAL_IMPLMD_CTRL, CRYPT_EAL_DefMdCtrl},
    {CRYPT_EAL_IMPLMD_FREECTX, CRYPT_SM3_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

#endif /* HITLS_CRYPTO_PROVIDER */