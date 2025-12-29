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
#if defined(HITLS_CRYPTO_CIPHER) && defined(HITLS_CRYPTO_PROVIDER)

#include "crypt_errno.h"
#include "bsl_err_internal.h"
#include "crypt_ealinit.h"
#include "crypt_eal_implprovider.h"
#include "crypt_modes_cbc.h"
#include "crypt_modes_ccm.h"
#include "crypt_modes_chacha20poly1305.h"
#include "crypt_modes_ctr.h"
#include "crypt_modes_ecb.h"
#include "crypt_modes_gcm.h"
#include "crypt_modes_ofb.h"
#include "crypt_modes_cfb.h"
#include "crypt_modes_hctr.h"
#include "crypt_modes_xts.h"
#include "crypt_modes_aes_wrap.h"
#include "crypt_local_types.h"
#include "crypt_default_provider.h"

static void *GetNewCtxFunc(int32_t algId)
{
    switch (algId) {
#if defined(HITLS_CRYPTO_CBC) && (defined(HITLS_CRYPTO_AES) || defined(HITLS_CRYPTO_SM4))
#ifdef HITLS_CRYPTO_AES
        case CRYPT_CIPHER_AES128_CBC:
        case CRYPT_CIPHER_AES192_CBC:
        case CRYPT_CIPHER_AES256_CBC:
#endif
#ifdef HITLS_CRYPTO_SM4
        case CRYPT_CIPHER_SM4_CBC:
#endif
            return MODES_CBC_NewCtxEx;
#endif
#if defined(HITLS_CRYPTO_CTR) && (defined(HITLS_CRYPTO_AES) || defined(HITLS_CRYPTO_SM4))
#ifdef HITLS_CRYPTO_AES
        case CRYPT_CIPHER_AES128_CTR:
        case CRYPT_CIPHER_AES192_CTR:
        case CRYPT_CIPHER_AES256_CTR:
#endif
#ifdef HITLS_CRYPTO_SM4
        case CRYPT_CIPHER_SM4_CTR:
#endif
            return MODES_CTR_NewCtxEx;
#endif
#if defined(HITLS_CRYPTO_ECB) && (defined(HITLS_CRYPTO_AES) || defined(HITLS_CRYPTO_SM4))
#ifdef HITLS_CRYPTO_AES
        case CRYPT_CIPHER_AES128_ECB:
        case CRYPT_CIPHER_AES192_ECB:
        case CRYPT_CIPHER_AES256_ECB:
#endif
#ifdef HITLS_CRYPTO_SM4
        case CRYPT_CIPHER_SM4_ECB:
#endif
            return MODES_ECB_NewCtxEx;
#endif
#if defined(HITLS_CRYPTO_CCM) && (defined(HITLS_CRYPTO_AES) || defined(HITLS_CRYPTO_SM4))
#ifdef HITLS_CRYPTO_AES
        case CRYPT_CIPHER_AES128_CCM:
        case CRYPT_CIPHER_AES192_CCM:
        case CRYPT_CIPHER_AES256_CCM:
#endif
#ifdef HITLS_CRYPTO_SM4
        case CRYPT_CIPHER_SM4_CCM:
#endif
            return MODES_CCM_NewCtxEx;
#endif
#if defined(HITLS_CRYPTO_GCM) && (defined(HITLS_CRYPTO_AES) || defined(HITLS_CRYPTO_SM4))
#ifdef HITLS_CRYPTO_AES
        case CRYPT_CIPHER_AES128_GCM:
        case CRYPT_CIPHER_AES192_GCM:
        case CRYPT_CIPHER_AES256_GCM:
#endif
#ifdef HITLS_CRYPTO_SM4
        case CRYPT_CIPHER_SM4_GCM:
#endif
            return MODES_GCM_NewCtxEx;
#endif
#if defined(HITLS_CRYPTO_CFB) && (defined(HITLS_CRYPTO_AES) || defined(HITLS_CRYPTO_SM4))
#ifdef HITLS_CRYPTO_AES
        case CRYPT_CIPHER_AES128_CFB:
        case CRYPT_CIPHER_AES192_CFB:
        case CRYPT_CIPHER_AES256_CFB:
#endif
#ifdef HITLS_CRYPTO_SM4
        case CRYPT_CIPHER_SM4_CFB:
#endif
            return MODES_CFB_NewCtxEx;
#endif
#if defined(HITLS_CRYPTO_OFB) && (defined(HITLS_CRYPTO_AES) || defined(HITLS_CRYPTO_SM4))
#ifdef HITLS_CRYPTO_AES
        case CRYPT_CIPHER_AES128_OFB:
        case CRYPT_CIPHER_AES192_OFB:
        case CRYPT_CIPHER_AES256_OFB:
#endif
#ifdef HITLS_CRYPTO_SM4
        case CRYPT_CIPHER_SM4_OFB:
#endif
            return MODES_OFB_NewCtxEx;
#endif
#if defined(HITLS_CRYPTO_XTS) && (defined(HITLS_CRYPTO_AES) || defined(HITLS_CRYPTO_SM4))
#ifdef HITLS_CRYPTO_AES
        case CRYPT_CIPHER_AES128_XTS:
        case CRYPT_CIPHER_AES256_XTS:
#endif
#ifdef HITLS_CRYPTO_SM4
        case CRYPT_CIPHER_SM4_XTS:
#endif
            return MODES_XTS_NewCtxEx;
#endif
#if defined(HITLS_CRYPTO_CHACHA20) && defined(HITLS_CRYPTO_CHACHA20POLY1305)
        case CRYPT_CIPHER_CHACHA20_POLY1305:
            return MODES_CHACHA20POLY1305_NewCtxEx;
#endif
#ifdef HITLS_CRYPTO_WRAP
        case CRYPT_CIPHER_AES128_WRAP_PAD:
        case CRYPT_CIPHER_AES192_WRAP_PAD:
        case CRYPT_CIPHER_AES256_WRAP_PAD:
            return MODES_WRAP_PadNewCtxEx;
        case CRYPT_CIPHER_AES128_WRAP_NOPAD:
        case CRYPT_CIPHER_AES192_WRAP_NOPAD:
        case CRYPT_CIPHER_AES256_WRAP_NOPAD:
            return MODES_WRAP_NoPadNewCtxEx;
#endif
        default:
            return NULL;
    }
}

static void *CRYPT_EAL_DefCipherNewCtx(CRYPT_EAL_DefProvCtx *provCtx, int32_t algId)
{
    void *libCtx = provCtx == NULL ? NULL : provCtx->libCtx;
#ifdef HITLS_CRYPTO_ASM_CHECK
    if (CRYPT_ASMCAP_Cipher(algId) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return NULL;
    }
#endif
    void *newCtxFunc = GetNewCtxFunc(algId);
    if (newCtxFunc != NULL) {
        return ((CipherNewCtx)newCtxFunc)(libCtx, algId);
    }

    return NULL;
}

#ifdef HITLS_CRYPTO_CBC
const CRYPT_EAL_Func g_defEalCbc[] = {
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, (CRYPT_EAL_ImplCipherNewCtx)CRYPT_EAL_DefCipherNewCtx},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, (CRYPT_EAL_ImplCipherInitCtx)MODES_CBC_InitCtxEx},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, (CRYPT_EAL_ImplCipherUpdate)MODES_CBC_UpdateEx},
    {CRYPT_EAL_IMPLCIPHER_FINAL, (CRYPT_EAL_ImplCipherFinal)MODES_CBC_FinalEx},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, (CRYPT_EAL_ImplCipherDeinitCtx)MODES_CBC_DeInitCtx},
    {CRYPT_EAL_IMPLCIPHER_CTRL, (CRYPT_EAL_ImplCipherCtrl)MODES_CBC_Ctrl},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, (CRYPT_EAL_ImplCipherFreeCtx)MODES_CBC_FreeCtx},
    CRYPT_EAL_FUNC_END,
};
#endif

#ifdef HITLS_CRYPTO_CCM
const CRYPT_EAL_Func g_defEalCcm[] = {
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, (CRYPT_EAL_ImplCipherNewCtx)CRYPT_EAL_DefCipherNewCtx},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, (CRYPT_EAL_ImplCipherInitCtx)MODES_CCM_InitCtx},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, (CRYPT_EAL_ImplCipherUpdate)MODES_CCM_UpdateEx},
    {CRYPT_EAL_IMPLCIPHER_FINAL, (CRYPT_EAL_ImplCipherFinal)MODES_CCM_Final},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, (CRYPT_EAL_ImplCipherDeinitCtx)MODES_CCM_DeInitCtx},
    {CRYPT_EAL_IMPLCIPHER_CTRL, (CRYPT_EAL_ImplCipherCtrl)MODES_CCM_Ctrl},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, (CRYPT_EAL_ImplCipherFreeCtx)MODES_CCM_FreeCtx},
    CRYPT_EAL_FUNC_END,
};
#endif

#ifdef HITLS_CRYPTO_CFB
const CRYPT_EAL_Func g_defEalCfb[] = {
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, (CRYPT_EAL_ImplCipherNewCtx)CRYPT_EAL_DefCipherNewCtx},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, (CRYPT_EAL_ImplCipherInitCtx)MODES_CFB_InitCtxEx},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, (CRYPT_EAL_ImplCipherUpdate)MODES_CFB_UpdateEx},
    {CRYPT_EAL_IMPLCIPHER_FINAL, (CRYPT_EAL_ImplCipherFinal)MODES_CFB_Final},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, (CRYPT_EAL_ImplCipherDeinitCtx)MODES_CFB_DeInitCtx},
    {CRYPT_EAL_IMPLCIPHER_CTRL, (CRYPT_EAL_ImplCipherCtrl)MODES_CFB_Ctrl},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, (CRYPT_EAL_ImplCipherFreeCtx)MODES_CFB_FreeCtx},
    CRYPT_EAL_FUNC_END,
};
#endif

#if defined(HITLS_CRYPTO_CHACHA20) && defined(HITLS_CRYPTO_CHACHA20POLY1305)
const CRYPT_EAL_Func g_defEalChaCha[] = {
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, (CRYPT_EAL_ImplCipherNewCtx)CRYPT_EAL_DefCipherNewCtx},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, (CRYPT_EAL_ImplCipherInitCtx)MODES_CHACHA20POLY1305_InitCtx},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, (CRYPT_EAL_ImplCipherUpdate)MODES_CHACHA20POLY1305_Update},
    {CRYPT_EAL_IMPLCIPHER_FINAL, (CRYPT_EAL_ImplCipherFinal)MODES_CHACHA20POLY1305_Final},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, (CRYPT_EAL_ImplCipherDeinitCtx)MODES_CHACHA20POLY1305_DeInitCtx},
    {CRYPT_EAL_IMPLCIPHER_CTRL, (CRYPT_EAL_ImplCipherCtrl)MODES_CHACHA20POLY1305_Ctrl},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, (CRYPT_EAL_ImplCipherFreeCtx)MODES_CHACHA20POLY1305_FreeCtx},
    CRYPT_EAL_FUNC_END,
};
#endif

#ifdef HITLS_CRYPTO_CTR
const CRYPT_EAL_Func g_defEalCtr[] = {
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, (CRYPT_EAL_ImplCipherNewCtx)CRYPT_EAL_DefCipherNewCtx},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, (CRYPT_EAL_ImplCipherInitCtx)MODES_CTR_InitCtxEx},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, (CRYPT_EAL_ImplCipherUpdate)MODES_CTR_UpdateEx},
    {CRYPT_EAL_IMPLCIPHER_FINAL, (CRYPT_EAL_ImplCipherFinal)MODES_CTR_Final},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, (CRYPT_EAL_ImplCipherDeinitCtx)MODES_CTR_DeInitCtx},
    {CRYPT_EAL_IMPLCIPHER_CTRL, (CRYPT_EAL_ImplCipherCtrl)MODES_CTR_Ctrl},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, (CRYPT_EAL_ImplCipherFreeCtx)MODES_CTR_FreeCtx},
    CRYPT_EAL_FUNC_END,
};
#endif

#ifdef HITLS_CRYPTO_ECB
const CRYPT_EAL_Func g_defEalEcb[] = {
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, (CRYPT_EAL_ImplCipherNewCtx)CRYPT_EAL_DefCipherNewCtx},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, (CRYPT_EAL_ImplCipherInitCtx)MODES_ECB_InitCtxEx},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, (CRYPT_EAL_ImplCipherUpdate)MODES_ECB_UpdateEx},
    {CRYPT_EAL_IMPLCIPHER_FINAL, (CRYPT_EAL_ImplCipherFinal)MODES_ECB_FinalEx},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, (CRYPT_EAL_ImplCipherDeinitCtx)MODES_ECB_DeinitCtx},
    {CRYPT_EAL_IMPLCIPHER_CTRL, (CRYPT_EAL_ImplCipherCtrl)MODES_ECB_Ctrl},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, (CRYPT_EAL_ImplCipherFreeCtx)MODES_ECB_FreeCtx},
    CRYPT_EAL_FUNC_END,
};
#endif

#ifdef HITLS_CRYPTO_GCM
const CRYPT_EAL_Func g_defEalGcm[] = {
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, (CRYPT_EAL_ImplCipherNewCtx)CRYPT_EAL_DefCipherNewCtx},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, (CRYPT_EAL_ImplCipherInitCtx)MODES_GCM_InitCtxEx},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, (CRYPT_EAL_ImplCipherUpdate)MODES_GCM_UpdateEx},
    {CRYPT_EAL_IMPLCIPHER_FINAL, (CRYPT_EAL_ImplCipherFinal)MODES_GCM_Final},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, (CRYPT_EAL_ImplCipherDeinitCtx)MODES_GCM_DeInitCtx},
    {CRYPT_EAL_IMPLCIPHER_CTRL, (CRYPT_EAL_ImplCipherCtrl)MODES_GCM_Ctrl},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, (CRYPT_EAL_ImplCipherFreeCtx)MODES_GCM_FreeCtx},
    CRYPT_EAL_FUNC_END,
};
#endif

#ifdef HITLS_CRYPTO_OFB
const CRYPT_EAL_Func g_defEalOfb[] = {
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, (CRYPT_EAL_ImplCipherNewCtx)CRYPT_EAL_DefCipherNewCtx},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, (CRYPT_EAL_ImplCipherInitCtx)MODES_OFB_InitCtxEx},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, (CRYPT_EAL_ImplCipherUpdate)MODES_OFB_UpdateEx},
    {CRYPT_EAL_IMPLCIPHER_FINAL, (CRYPT_EAL_ImplCipherFinal)MODES_OFB_Final},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, (CRYPT_EAL_ImplCipherDeinitCtx)MODES_OFB_DeInitCtx},
    {CRYPT_EAL_IMPLCIPHER_CTRL, (CRYPT_EAL_ImplCipherCtrl)MODES_OFB_Ctrl},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, (CRYPT_EAL_ImplCipherFreeCtx)MODES_OFB_FreeCtx},
    CRYPT_EAL_FUNC_END,
};
#endif

#ifdef HITLS_CRYPTO_XTS
const CRYPT_EAL_Func g_defEalXts[] = {
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, (CRYPT_EAL_ImplCipherNewCtx)CRYPT_EAL_DefCipherNewCtx},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, (CRYPT_EAL_ImplCipherInitCtx)MODES_XTS_InitCtxEx},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, (CRYPT_EAL_ImplCipherUpdate)MODES_XTS_UpdateEx},
    {CRYPT_EAL_IMPLCIPHER_FINAL, (CRYPT_EAL_ImplCipherFinal)MODES_XTS_Final},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, (CRYPT_EAL_ImplCipherDeinitCtx)MODES_XTS_DeInitCtx},
    {CRYPT_EAL_IMPLCIPHER_CTRL, (CRYPT_EAL_ImplCipherCtrl)MODES_XTS_Ctrl},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, (CRYPT_EAL_ImplCipherFreeCtx)MODES_XTS_FreeCtx},
    CRYPT_EAL_FUNC_END,
};
#endif

#ifdef HITLS_CRYPTO_WRAP
const CRYPT_EAL_Func g_defEalWrap[] = {
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, (CRYPT_EAL_ImplCipherNewCtx)CRYPT_EAL_DefCipherNewCtx},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, (CRYPT_EAL_ImplCipherInitCtx)MODES_WRAP_InitCtx},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, (CRYPT_EAL_ImplCipherUpdate)MODES_WRAP_Update},
    {CRYPT_EAL_IMPLCIPHER_FINAL, (CRYPT_EAL_ImplCipherFinal)MODES_WRAP_Final},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, (CRYPT_EAL_ImplCipherDeinitCtx)MODE_WRAP_DeInitCtx},
    {CRYPT_EAL_IMPLCIPHER_CTRL, (CRYPT_EAL_ImplCipherCtrl)MODE_WRAP_Ctrl},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, (CRYPT_EAL_ImplCipherFreeCtx)MODES_WRAP_FreeCtx},
    CRYPT_EAL_FUNC_END,
};
#endif

#ifdef HITLS_CRYPTO_HCTR
const CRYPT_EAL_Func g_defEalHctr[] = {
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, (CRYPT_EAL_ImplCipherNewCtx)CRYPT_EAL_DefCipherNewCtx},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, (CRYPT_EAL_ImplCipherInitCtx)MODES_HCTR_Init},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, (CRYPT_EAL_ImplCipherUpdate)MODES_HCTR_Update},
    {CRYPT_EAL_IMPLCIPHER_FINAL, (CRYPT_EAL_ImplCipherFinal)MODES_HCTR_Final},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, (CRYPT_EAL_ImplCipherDeinitCtx)MODES_HCTR_DeInit},
    {CRYPT_EAL_IMPLCIPHER_CTRL, (CRYPT_EAL_ImplCipherCtrl)MODES_HCTR_Ctrl},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, (CRYPT_EAL_ImplCipherFreeCtx)MODES_HCTR_Free},
    CRYPT_EAL_FUNC_END,
};
#endif

#endif
