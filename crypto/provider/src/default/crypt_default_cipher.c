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
#if (defined(HITLS_CRYPTO_AES) || defined(HITLS_CRYPTO_SM4) || defined(HITLS_CRYPTO_CHACHA20) || \
    defined(HITLS_CRYPTO_CHACHA20POLY1305) || defined(HITLS_CRYPTO_XTS) || defined(HITLS_CRYPTO_CBC) || \
    defined(HITLS_CRYPTO_CCM) || defined(HITLS_CRYPTO_CFB) || defined(HITLS_CRYPTO_ECB) || \
    defined(HITLS_CRYPTO_GCM) || defined(HITLS_CRYPTO_OFB) || defined(HITLS_CRYPTO_CTR)) && \
    defined(HITLS_CRYPTO_PROVIDER)

#include "crypt_eal_implprovider.h"
#include "crypt_modes_cbc.h"
#include "crypt_modes_ccm.h"
#include "crypt_modes_chacha20poly1305.h"
#include "crypt_modes_ctr.h"
#include "crypt_modes_ecb.h"
#include "crypt_modes_gcm.h"
#include "crypt_modes_ofb.h"
#include "crypt_modes_cfb.h"
#include "crypt_modes_xts.h"
#include "crypt_local_types.h"
#include "crypt_errno.h"
#include "bsl_err_internal.h"
#include "crypt_ealinit.h"

static void *CRYPT_EAL_DefCipherNewCtx(void *provCtx, int32_t algId)
{
    (void) provCtx;
#ifdef HITLS_CRYPTO_ASM_CHECK
    if (CRYPT_ASMCAP_Cipher(algId) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return NULL;
    }
#endif
    CRYPT_EAL_Func cipherNewCtxFunc[] = {
        {CRYPT_CIPHER_AES128_CBC, MODES_CBC_NewCtx},
        {CRYPT_CIPHER_AES192_CBC, MODES_CBC_NewCtx},
        {CRYPT_CIPHER_AES256_CBC, MODES_CBC_NewCtx},
        {CRYPT_CIPHER_AES128_CTR, MODES_CTR_NewCtx},
        {CRYPT_CIPHER_AES192_CTR, MODES_CTR_NewCtx},
        {CRYPT_CIPHER_AES256_CTR, MODES_CTR_NewCtx},
        {CRYPT_CIPHER_AES128_ECB, MODES_ECB_NewCtx},
        {CRYPT_CIPHER_AES192_ECB, MODES_ECB_NewCtx},
        {CRYPT_CIPHER_AES256_ECB, MODES_ECB_NewCtx},
#ifdef HITLS_CRYPTO_CCM
        {CRYPT_CIPHER_AES128_CCM, MODES_CCM_NewCtx},
        {CRYPT_CIPHER_AES192_CCM, MODES_CCM_NewCtx},
        {CRYPT_CIPHER_AES256_CCM, MODES_CCM_NewCtx},
        {CRYPT_CIPHER_SM4_CCM, MODES_CCM_NewCtx},
#endif
        {CRYPT_CIPHER_AES128_GCM, MODES_GCM_NewCtx},
        {CRYPT_CIPHER_AES192_GCM, MODES_GCM_NewCtx},
        {CRYPT_CIPHER_AES256_GCM, MODES_GCM_NewCtx},
        {CRYPT_CIPHER_AES128_CFB, MODES_CFB_NewCtx},
        {CRYPT_CIPHER_AES192_CFB, MODES_CFB_NewCtx},
        {CRYPT_CIPHER_AES256_CFB, MODES_CFB_NewCtx},
        {CRYPT_CIPHER_AES128_OFB, MODES_OFB_NewCtx},
        {CRYPT_CIPHER_AES192_OFB, MODES_OFB_NewCtx},
        {CRYPT_CIPHER_AES256_OFB, MODES_OFB_NewCtx},
        {CRYPT_CIPHER_AES128_XTS, MODES_XTS_NewCtx},
        {CRYPT_CIPHER_AES256_XTS, MODES_XTS_NewCtx},
#if defined(HITLS_CRYPTO_CHACHA20) && defined(HITLS_CRYPTO_CHACHA20POLY1305)
        {CRYPT_CIPHER_CHACHA20_POLY1305, MODES_CHACHA20POLY1305_NewCtx},
#endif
        {CRYPT_CIPHER_SM4_XTS, MODES_XTS_NewCtx},
        {CRYPT_CIPHER_SM4_CBC, MODES_CBC_NewCtx},
        {CRYPT_CIPHER_SM4_ECB, MODES_ECB_NewCtx},
        {CRYPT_CIPHER_SM4_CTR, MODES_CTR_NewCtx},
        {CRYPT_CIPHER_SM4_GCM, MODES_GCM_NewCtx},
        {CRYPT_CIPHER_SM4_CFB, MODES_CFB_NewCtx},
        {CRYPT_CIPHER_SM4_OFB, MODES_OFB_NewCtx},
    };
    for (size_t i = 0; i < sizeof(cipherNewCtxFunc)/sizeof(cipherNewCtxFunc[0]); i++) {
        if (cipherNewCtxFunc[i].id == algId) {
            return ((CipherNewCtx)cipherNewCtxFunc[i].func)(algId);
        }
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

#endif