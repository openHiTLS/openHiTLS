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

static void *CRYPT_EAL_DefCipherNewCtx(void *provCtx, int32_t algId)
{
    (void) provCtx;
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
        {CRYPT_CIPHER_AES128_CCM, MODES_CCM_NewCtx},
        {CRYPT_CIPHER_AES192_CCM, MODES_CCM_NewCtx},
        {CRYPT_CIPHER_AES256_CCM, MODES_CCM_NewCtx},
        {CRYPT_CIPHER_AES128_GCM, MODES_GCM_NewCtx},
        {CRYPT_CIPHER_AES192_GCM, MODES_GCM_NewCtx},
        {CRYPT_CIPHER_AES256_GCM, MODES_GCM_NewCtx},
        {CRYPT_CIPHER_AES128_CFB, MODES_CFB_NewCtx},
        {CRYPT_CIPHER_AES192_CFB, MODES_CFB_NewCtx},
        {CRYPT_CIPHER_AES256_CFB, MODES_CFB_NewCtx},
        {CRYPT_CIPHER_AES128_OFB, MODES_OFB_NewCtx},
        {CRYPT_CIPHER_AES192_OFB, MODES_OFB_NewCtx},
        {CRYPT_CIPHER_AES256_OFB, MODES_OFB_NewCtx},
        {CRYPT_CIPHER_CHACHA20_POLY1305, MODES_CHACHA20POLY1305_NewCtx},
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

const CRYPT_EAL_Func g_defCbc[] = {
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, CRYPT_EAL_DefCipherNewCtx},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, MODES_CBC_InitCtxEx},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, MODES_CBC_UpdateEx},
    {CRYPT_EAL_IMPLCIPHER_FINAL, MODES_CBC_FinalEx},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, MODES_CBC_DeInitCtx},
    {CRYPT_EAL_IMPLCIPHER_CTRL, MODES_CBC_Ctrl},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, MODES_CBC_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defCcm[] = {
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, CRYPT_EAL_DefCipherNewCtx},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, MODES_CCM_InitCtx},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, MODES_CCM_UpdateEx},
    {CRYPT_EAL_IMPLCIPHER_FINAL, MODES_CCM_Final},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, MODES_CCM_DeInitCtx},
    {CRYPT_EAL_IMPLCIPHER_CTRL, MODES_CCM_Ctrl},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, MODES_CCM_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defCfb[] = {
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, CRYPT_EAL_DefCipherNewCtx},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, MODES_CFB_InitCtxEx},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, MODES_CFB_UpdateEx},
    {CRYPT_EAL_IMPLCIPHER_FINAL, MODES_CFB_Final},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, MODES_CFB_DeInitCtx},
    {CRYPT_EAL_IMPLCIPHER_CTRL, MODES_CFB_Ctrl},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, MODES_CFB_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defChaCha[] = {
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, CRYPT_EAL_DefCipherNewCtx},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, MODES_CHACHA20POLY1305_InitCtx},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, MODES_CHACHA20POLY1305_Update},
    {CRYPT_EAL_IMPLCIPHER_FINAL, MODES_CHACHA20POLY1305_Final},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, MODES_CHACHA20POLY1305_DeInitCtx},
    {CRYPT_EAL_IMPLCIPHER_CTRL, MODES_CHACHA20POLY1305_Ctrl},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, MODES_CHACHA20POLY1305_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defCtr[] = {
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, CRYPT_EAL_DefCipherNewCtx},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, MODES_CTR_InitCtxEx},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, MODES_CTR_UpdateEx},
    {CRYPT_EAL_IMPLCIPHER_FINAL, MODES_CTR_Final},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, MODES_CTR_DeInitCtx},
    {CRYPT_EAL_IMPLCIPHER_CTRL, MODES_CTR_Ctrl},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, MODES_CTR_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defEcb[] = {
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, CRYPT_EAL_DefCipherNewCtx},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, MODES_ECB_InitCtxEx},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, MODES_ECB_UpdateEx},
    {CRYPT_EAL_IMPLCIPHER_FINAL, MODES_ECB_FinalEx},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, MODES_ECB_DeinitCtx},
    {CRYPT_EAL_IMPLCIPHER_CTRL, MODES_ECB_Ctrl},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, MODES_ECB_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defGcm[] = {
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, CRYPT_EAL_DefCipherNewCtx},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, MODES_GCM_InitCtxEx},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, MODES_GCM_UpdateEx},
    {CRYPT_EAL_IMPLCIPHER_FINAL, MODES_GCM_Final},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, MODES_GCM_DeInitCtx},
    {CRYPT_EAL_IMPLCIPHER_CTRL, MODES_GCM_Ctrl},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, MODES_GCM_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defOfb[] = {
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, CRYPT_EAL_DefCipherNewCtx},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, MODES_OFB_InitCtxEx},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, MODES_OFB_UpdateEx},
    {CRYPT_EAL_IMPLCIPHER_FINAL, MODES_OFB_Final},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, MODES_OFB_DeInitCtx},
    {CRYPT_EAL_IMPLCIPHER_CTRL, MODES_OFB_Ctrl},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, MODES_OFB_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defXts[] = {
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, CRYPT_EAL_DefCipherNewCtx},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, MODES_XTS_InitCtxEx},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, MODES_XTS_UpdateEx},
    {CRYPT_EAL_IMPLCIPHER_FINAL, MODES_XTS_Final},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, MODES_XTS_DeInitCtx},
    {CRYPT_EAL_IMPLCIPHER_CTRL, MODES_XTS_Ctrl},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, MODES_XTS_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

#endif /* HITLS_CRYPTO_PROVIDER */