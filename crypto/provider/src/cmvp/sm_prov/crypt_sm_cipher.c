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
#ifdef HITLS_CRYPTO_CMVP_SM

#include "crypt_eal_implprovider.h"
#include "crypt_modes_cbc.h"
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
#include "crypt_sm_provider.h"

static void *CRYPT_EAL_SmCipherNewCtx(CRYPT_EAL_SmProvCtx *provCtx, int32_t algId)
{
#ifdef HITLS_CRYPTO_ASM_CHECK
    if (CRYPT_ASMCAP_Cipher(algId) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return NULL;
    }
#endif
    CRYPT_EAL_Func cipherNewCtxFunc[] = {
        {CRYPT_CIPHER_SM4_XTS, MODES_XTS_NewCtxEx},
        {CRYPT_CIPHER_SM4_CBC, MODES_CBC_NewCtxEx},
        {CRYPT_CIPHER_SM4_ECB, MODES_ECB_NewCtxEx},
        {CRYPT_CIPHER_SM4_CTR, MODES_CTR_NewCtxEx},
        {CRYPT_CIPHER_SM4_GCM, MODES_GCM_NewCtxEx},
        {CRYPT_CIPHER_SM4_CFB, MODES_CFB_NewCtxEx},
        {CRYPT_CIPHER_SM4_OFB, MODES_OFB_NewCtxEx},
    };
    for (size_t i = 0; i < sizeof(cipherNewCtxFunc)/sizeof(cipherNewCtxFunc[0]); i++) {
        if (cipherNewCtxFunc[i].id == algId) {
            return ((CipherNewCtx)cipherNewCtxFunc[i].func)(provCtx->libCtx, algId);
        }
    }
    BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_NOT_SUPPORT);
    return NULL;
}

const CRYPT_EAL_Func g_smCbc[] = {
#ifdef HITLS_CRYPTO_CBC
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, (CRYPT_EAL_ImplCipherNewCtx)CRYPT_EAL_SmCipherNewCtx},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, (CRYPT_EAL_ImplCipherInitCtx)MODES_CBC_InitCtxEx},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, (CRYPT_EAL_ImplCipherUpdate)MODES_CBC_UpdateEx},
    {CRYPT_EAL_IMPLCIPHER_FINAL, (CRYPT_EAL_ImplCipherFinal)MODES_CBC_FinalEx},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, (CRYPT_EAL_ImplCipherDeinitCtx)MODES_CBC_DeInitCtx},
    {CRYPT_EAL_IMPLCIPHER_CTRL, (CRYPT_EAL_ImplCipherCtrl)MODES_CBC_Ctrl},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, (CRYPT_EAL_ImplCipherFreeCtx)MODES_CBC_FreeCtx},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_smCfb[] = {
#ifdef HITLS_CRYPTO_CFB
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, (CRYPT_EAL_ImplCipherNewCtx)CRYPT_EAL_SmCipherNewCtx},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, (CRYPT_EAL_ImplCipherInitCtx)MODES_CFB_InitCtxEx},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, (CRYPT_EAL_ImplCipherUpdate)MODES_CFB_UpdateEx},
    {CRYPT_EAL_IMPLCIPHER_FINAL, (CRYPT_EAL_ImplCipherFinal)MODES_CFB_Final},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, (CRYPT_EAL_ImplCipherDeinitCtx)MODES_CFB_DeInitCtx},
    {CRYPT_EAL_IMPLCIPHER_CTRL, (CRYPT_EAL_ImplCipherCtrl)MODES_CFB_Ctrl},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, (CRYPT_EAL_ImplCipherFreeCtx)MODES_CFB_FreeCtx},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_smCtr[] = {
#ifdef HITLS_CRYPTO_CTR
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, (CRYPT_EAL_ImplCipherNewCtx)CRYPT_EAL_SmCipherNewCtx},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, (CRYPT_EAL_ImplCipherInitCtx)MODES_CTR_InitCtxEx},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, (CRYPT_EAL_ImplCipherUpdate)MODES_CTR_UpdateEx},
    {CRYPT_EAL_IMPLCIPHER_FINAL, (CRYPT_EAL_ImplCipherFinal)MODES_CTR_Final},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, (CRYPT_EAL_ImplCipherDeinitCtx)MODES_CTR_DeInitCtx},
    {CRYPT_EAL_IMPLCIPHER_CTRL, (CRYPT_EAL_ImplCipherCtrl)MODES_CTR_Ctrl},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, (CRYPT_EAL_ImplCipherFreeCtx)MODES_CTR_FreeCtx},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_smEcb[] = {
#ifdef HITLS_CRYPTO_ECB
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, (CRYPT_EAL_ImplCipherNewCtx)CRYPT_EAL_SmCipherNewCtx},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, (CRYPT_EAL_ImplCipherInitCtx)MODES_ECB_InitCtxEx},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, (CRYPT_EAL_ImplCipherUpdate)MODES_ECB_UpdateEx},
    {CRYPT_EAL_IMPLCIPHER_FINAL, (CRYPT_EAL_ImplCipherFinal)MODES_ECB_FinalEx},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, (CRYPT_EAL_ImplCipherDeinitCtx)MODES_ECB_DeinitCtx},
    {CRYPT_EAL_IMPLCIPHER_CTRL, (CRYPT_EAL_ImplCipherCtrl)MODES_ECB_Ctrl},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, (CRYPT_EAL_ImplCipherFreeCtx)MODES_ECB_FreeCtx},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_smGcm[] = {
#ifdef HITLS_CRYPTO_GCM
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, (CRYPT_EAL_ImplCipherNewCtx)CRYPT_EAL_SmCipherNewCtx},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, (CRYPT_EAL_ImplCipherInitCtx)MODES_GCM_InitCtxEx},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, (CRYPT_EAL_ImplCipherUpdate)MODES_GCM_UpdateEx},
    {CRYPT_EAL_IMPLCIPHER_FINAL, (CRYPT_EAL_ImplCipherFinal)MODES_GCM_Final},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, (CRYPT_EAL_ImplCipherDeinitCtx)MODES_GCM_DeInitCtx},
    {CRYPT_EAL_IMPLCIPHER_CTRL, (CRYPT_EAL_ImplCipherCtrl)MODES_GCM_Ctrl},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, (CRYPT_EAL_ImplCipherFreeCtx)MODES_GCM_FreeCtx},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_smOfb[] = {
#ifdef HITLS_CRYPTO_OFB
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, (CRYPT_EAL_ImplCipherNewCtx)CRYPT_EAL_SmCipherNewCtx},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, (CRYPT_EAL_ImplCipherInitCtx)MODES_OFB_InitCtxEx},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, (CRYPT_EAL_ImplCipherUpdate)MODES_OFB_UpdateEx},
    {CRYPT_EAL_IMPLCIPHER_FINAL, (CRYPT_EAL_ImplCipherFinal)MODES_OFB_Final},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, (CRYPT_EAL_ImplCipherDeinitCtx)MODES_OFB_DeInitCtx},
    {CRYPT_EAL_IMPLCIPHER_CTRL, (CRYPT_EAL_ImplCipherCtrl)MODES_OFB_Ctrl},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, (CRYPT_EAL_ImplCipherFreeCtx)MODES_OFB_FreeCtx},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_smXts[] = {
#ifdef HITLS_CRYPTO_XTS
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, (CRYPT_EAL_ImplCipherNewCtx)CRYPT_EAL_SmCipherNewCtx},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, (CRYPT_EAL_ImplCipherInitCtx)MODES_XTS_InitCtxEx},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, (CRYPT_EAL_ImplCipherUpdate)MODES_XTS_UpdateEx},
    {CRYPT_EAL_IMPLCIPHER_FINAL, (CRYPT_EAL_ImplCipherFinal)MODES_XTS_Final},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, (CRYPT_EAL_ImplCipherDeinitCtx)MODES_XTS_DeInitCtx},
    {CRYPT_EAL_IMPLCIPHER_CTRL, (CRYPT_EAL_ImplCipherCtrl)MODES_XTS_Ctrl},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, (CRYPT_EAL_ImplCipherFreeCtx)MODES_XTS_FreeCtx},
#endif
    CRYPT_EAL_FUNC_END,
};

#endif /* HITLS_CRYPTO_CMVP_SM */
