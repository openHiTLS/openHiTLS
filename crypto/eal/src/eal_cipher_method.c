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
#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_CIPHER)

#include "securec.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "eal_cipher_local.h"
#include "crypt_modes.h"
#include "crypt_local_types.h"

#ifdef HITLS_CRYPTO_CTR
#include "crypt_modes_ctr.h"
#endif
#ifdef HITLS_CRYPTO_HCTR
#include "crypt_modes_hctr.h"
#endif
#ifdef HITLS_CRYPTO_CBC
#include "crypt_modes_cbc.h"
#endif
#ifdef HITLS_CRYPTO_GCM
#include "crypt_modes_gcm.h"
#endif
#ifdef HITLS_CRYPTO_ECB
#include "crypt_modes_ecb.h"
#endif
#ifdef HITLS_CRYPTO_CCM
#include "crypt_modes_ccm.h"
#endif
#ifdef HITLS_CRYPTO_XTS
#include "crypt_modes_xts.h"
#endif
#ifdef HITLS_CRYPTO_AES
#include "crypt_aes.h"
#endif
#if defined(HITLS_CRYPTO_CHACHA20) && defined(HITLS_CRYPTO_CHACHA20POLY1305)
#include "crypt_modes_chacha20poly1305.h"
#endif
#ifdef HITLS_CRYPTO_CHACHA20
#include "crypt_chacha20.h"
#endif
#ifdef HITLS_CRYPTO_SM4
#include "crypt_sm4.h"
#endif
#ifdef HITLS_CRYPTO_CFB
#include "crypt_modes_cfb.h"
#endif
#ifdef HITLS_CRYPTO_OFB
#include "crypt_modes_ofb.h"
#endif
#include "eal_common.h"
#include "bsl_sal.h"

#if defined(HITLS_CRYPTO_CHACHA20) && defined(HITLS_CRYPTO_CHACHA20POLY1305)
static const EAL_CipherMethod CHACHA20_POLY1305_METHOD = {
    (CipherNewCtx)MODES_CHACHA20POLY1305_NewCtxEx,
    (CipherInitCtx)MODES_CHACHA20POLY1305_InitCtx,
    (CipherDeInitCtx)MODES_CHACHA20POLY1305_DeInitCtx,
    (CipherUpdate)MODES_CHACHA20POLY1305_Update,
    (CipherFinal)MODES_CHACHA20POLY1305_Final,
    (CipherCtrl)MODES_CHACHA20POLY1305_Ctrl,
    (CipherFreeCtx)MODES_CHACHA20POLY1305_FreeCtx
};
#endif

#ifdef HITLS_CRYPTO_CTR
static const EAL_CipherMethod CTR_METHOD = {
    (CipherNewCtx)MODES_CTR_NewCtxEx,
    (CipherInitCtx)MODES_CTR_InitCtxEx,
    (CipherDeInitCtx)MODES_CTR_DeInitCtx,
    (CipherUpdate)MODES_CTR_UpdateEx,
    (CipherFinal)MODES_CTR_Final,
    (CipherCtrl)MODES_CTR_Ctrl,
    (CipherFreeCtx)MODES_CTR_FreeCtx
};
#endif

#ifdef HITLS_CRYPTO_CBC
static const EAL_CipherMethod CBC_METHOD = {
    (CipherNewCtx)MODES_CBC_NewCtxEx,
    (CipherInitCtx)MODES_CBC_InitCtxEx,
    (CipherDeInitCtx)MODES_CBC_DeInitCtx,
    (CipherUpdate)MODES_CBC_UpdateEx,
    (CipherFinal)MODES_CBC_FinalEx,
    (CipherCtrl)MODES_CBC_Ctrl,
    (CipherFreeCtx)MODES_CBC_FreeCtx
};
#endif

#ifdef HITLS_CRYPTO_ECB
static const EAL_CipherMethod ECB_METHOD = {
    (CipherNewCtx)MODES_ECB_NewCtxEx,
    (CipherInitCtx)MODES_ECB_InitCtxEx,
    (CipherDeInitCtx)MODES_ECB_DeinitCtx,
    (CipherUpdate)MODES_ECB_UpdateEx,
    (CipherFinal)MODES_ECB_FinalEx,
    (CipherCtrl)MODES_ECB_Ctrl,
    (CipherFreeCtx)MODES_ECB_FreeCtx
};
#endif

#ifdef HITLS_CRYPTO_CCM
static const EAL_CipherMethod CCM_METHOD = {
    (CipherNewCtx)MODES_CCM_NewCtxEx,
    (CipherInitCtx)MODES_CCM_InitCtx,
    (CipherDeInitCtx)MODES_CCM_DeInitCtx,
    (CipherUpdate)MODES_CCM_UpdateEx,
    (CipherFinal)MODES_CCM_Final,
    (CipherCtrl)MODES_CCM_Ctrl,
    (CipherFreeCtx)MODES_CCM_FreeCtx
};
#endif

#ifdef HITLS_CRYPTO_GCM
static const EAL_CipherMethod GCM_METHOD = {
    (CipherNewCtx)MODES_GCM_NewCtxEx,
    (CipherInitCtx)MODES_GCM_InitCtxEx,
    (CipherDeInitCtx)MODES_GCM_DeInitCtx,
    (CipherUpdate)MODES_GCM_UpdateEx,
    (CipherFinal)MODES_GCM_Final,
    (CipherCtrl)MODES_GCM_Ctrl,
    (CipherFreeCtx)MODES_GCM_FreeCtx
};
#endif


#ifdef HITLS_CRYPTO_CFB
static const EAL_CipherMethod CFB_METHOD = {
    (CipherNewCtx)MODES_CFB_NewCtxEx,
    (CipherInitCtx)MODES_CFB_InitCtxEx,
    (CipherDeInitCtx)MODES_CFB_DeInitCtx,
    (CipherUpdate)MODES_CFB_UpdateEx,
    (CipherFinal)MODES_CFB_Final,
    (CipherCtrl)MODES_CFB_Ctrl,
    (CipherFreeCtx)MODES_CFB_FreeCtx
};
#endif

#ifdef HITLS_CRYPTO_OFB
static const EAL_CipherMethod OFB_METHOD = {
    (CipherNewCtx)MODES_OFB_NewCtxEx,
    (CipherInitCtx)MODES_OFB_InitCtxEx,
    (CipherDeInitCtx)MODES_OFB_DeInitCtx,
    (CipherUpdate)MODES_OFB_UpdateEx,
    (CipherFinal)MODES_OFB_Final,
    (CipherCtrl)MODES_OFB_Ctrl,
    (CipherFreeCtx)MODES_OFB_FreeCtx
};
#endif

#ifdef HITLS_CRYPTO_XTS
static const EAL_CipherMethod XTS_METHOD = {
    (CipherNewCtx)MODES_XTS_NewCtxEx,
    (CipherInitCtx)MODES_XTS_InitCtxEx,
    (CipherDeInitCtx)MODES_XTS_DeInitCtx,
    (CipherUpdate)MODES_XTS_UpdateEx,
    (CipherFinal)MODES_XTS_Final,
    (CipherCtrl)MODES_XTS_Ctrl,
    (CipherFreeCtx)MODES_XTS_FreeCtx
};
#endif

#ifdef HITLS_CRYPTO_HCTR
static const EAL_CipherMethod HCTR_METHOD = {
    (CipherNewCtx)MODES_HCTR_NewCtx,
    (CipherInitCtx)MODES_HCTR_Init,
    (CipherDeInitCtx)MODES_HCTR_DeInit,
    (CipherUpdate)MODES_HCTR_Update,
    (CipherFinal)MODES_HCTR_Final,
    (CipherCtrl)MODES_HCTR_Ctrl,
    (CipherFreeCtx)MODES_HCTR_Free
};
#endif

const EAL_CipherMethod *EAL_FindModeMethod(CRYPT_MODE_AlgId id)
{
    switch (id) {
#ifdef HITLS_CRYPTO_CBC
        case HCRYPT_MODE_CBC:
            return &CBC_METHOD;
#endif
#ifdef HITLS_CRYPTO_ECB
        case HCRYPT_MODE_ECB:
            return &ECB_METHOD;
#endif
#ifdef HITLS_CRYPTO_CTR
        case HCRYPT_MODE_CTR:
            return &CTR_METHOD;
#endif
#ifdef HITLS_CRYPTO_XTS
        case HCRYPT_MODE_XTS:
            return &XTS_METHOD;
#endif
#ifdef HITLS_CRYPTO_CCM
        case HCRYPT_MODE_CCM:
            return &CCM_METHOD;
#endif
#ifdef HITLS_CRYPTO_GCM
        case HCRYPT_MODE_GCM:
            return &GCM_METHOD;
#endif
#if defined(HITLS_CRYPTO_CHACHA20) && defined(HITLS_CRYPTO_CHACHA20POLY1305)
        case HCRYPT_MODE_CHACHA20_POLY1305:
            return &CHACHA20_POLY1305_METHOD;
#endif
#ifdef HITLS_CRYPTO_CFB
        case HCRYPT_MODE_CFB:
            return &CFB_METHOD;
#endif
#ifdef HITLS_CRYPTO_OFB
        case HCRYPT_MODE_OFB:
            return &OFB_METHOD;
#endif
#ifdef HITLS_CRYPTO_HCTR
        case HCRYPT_MODE_HCTR:
            return &HCTR_METHOD;
#endif
        default:
            return NULL;
    }
}

static const EAL_SymAlgMap SYM_ID_MAP[] = {
#ifdef HITLS_CRYPTO_AES
#ifdef HITLS_CRYPTO_CBC
    {.id = CRYPT_CIPHER_AES128_CBC, .modeId = HCRYPT_MODE_CBC },
    {.id = CRYPT_CIPHER_AES192_CBC, .modeId = HCRYPT_MODE_CBC },
    {.id = CRYPT_CIPHER_AES256_CBC, .modeId = HCRYPT_MODE_CBC },
#endif
#ifdef HITLS_CRYPTO_ECB
    {.id = CRYPT_CIPHER_AES128_ECB, .modeId = HCRYPT_MODE_ECB },
    {.id = CRYPT_CIPHER_AES192_ECB, .modeId = HCRYPT_MODE_ECB },
    {.id = CRYPT_CIPHER_AES256_ECB, .modeId = HCRYPT_MODE_ECB },
#endif
#ifdef HITLS_CRYPTO_CTR
    {.id = CRYPT_CIPHER_AES128_CTR, .modeId = HCRYPT_MODE_CTR },
    {.id = CRYPT_CIPHER_AES192_CTR, .modeId = HCRYPT_MODE_CTR },
    {.id = CRYPT_CIPHER_AES256_CTR, .modeId = HCRYPT_MODE_CTR },
#endif
#ifdef HITLS_CRYPTO_CCM
    {.id = CRYPT_CIPHER_AES128_CCM, .modeId = HCRYPT_MODE_CCM },
    {.id = CRYPT_CIPHER_AES192_CCM, .modeId = HCRYPT_MODE_CCM },
    {.id = CRYPT_CIPHER_AES256_CCM, .modeId = HCRYPT_MODE_CCM },
#endif
#ifdef HITLS_CRYPTO_GCM
    {.id = CRYPT_CIPHER_AES128_GCM, .modeId = HCRYPT_MODE_GCM },
    {.id = CRYPT_CIPHER_AES192_GCM, .modeId = HCRYPT_MODE_GCM },
    {.id = CRYPT_CIPHER_AES256_GCM, .modeId = HCRYPT_MODE_GCM },
#endif
#ifdef HITLS_CRYPTO_CFB
    {.id = CRYPT_CIPHER_AES128_CFB, .modeId = HCRYPT_MODE_CFB },
    {.id = CRYPT_CIPHER_AES192_CFB, .modeId = HCRYPT_MODE_CFB },
    {.id = CRYPT_CIPHER_AES256_CFB, .modeId = HCRYPT_MODE_CFB },
#endif
#ifdef HITLS_CRYPTO_OFB
    {.id = CRYPT_CIPHER_AES128_OFB, .modeId = HCRYPT_MODE_OFB },
    {.id = CRYPT_CIPHER_AES192_OFB, .modeId = HCRYPT_MODE_OFB },
    {.id = CRYPT_CIPHER_AES256_OFB, .modeId = HCRYPT_MODE_OFB },
#endif
#ifdef HITLS_CRYPTO_XTS
    {.id = CRYPT_CIPHER_AES128_XTS, .modeId = HCRYPT_MODE_XTS },
    {.id = CRYPT_CIPHER_AES256_XTS, .modeId = HCRYPT_MODE_XTS },
#endif
#endif // aes
#ifdef HITLS_CRYPTO_CHACHA20
    {.id = CRYPT_CIPHER_CHACHA20_POLY1305, .modeId = HCRYPT_MODE_CHACHA20_POLY1305},
#endif
#ifdef HITLS_CRYPTO_SM4
#ifdef HITLS_CRYPTO_XTS
    {.id = CRYPT_CIPHER_SM4_XTS, .modeId = HCRYPT_MODE_XTS },
#endif
#ifdef HITLS_CRYPTO_ECB
    {.id = CRYPT_CIPHER_SM4_ECB, .modeId = HCRYPT_MODE_ECB },
#endif
#ifdef HITLS_CRYPTO_CBC
    {.id = CRYPT_CIPHER_SM4_CBC, .modeId = HCRYPT_MODE_CBC },
#endif
#ifdef HITLS_CRYPTO_CTR
    {.id = CRYPT_CIPHER_SM4_CTR, .modeId = HCRYPT_MODE_CTR },
#endif
#ifdef HITLS_CRYPTO_GCM
    {.id = CRYPT_CIPHER_SM4_GCM, .modeId = HCRYPT_MODE_GCM },
#endif
#ifdef HITLS_CRYPTO_CFB
    {.id = CRYPT_CIPHER_SM4_CFB, .modeId = HCRYPT_MODE_CFB },
#endif
#ifdef HITLS_CRYPTO_OFB
    {.id = CRYPT_CIPHER_SM4_OFB, .modeId = HCRYPT_MODE_OFB },
#endif
#ifdef HITLS_CRYPTO_CCM
    {.id = CRYPT_CIPHER_SM4_CCM, .modeId = HCRYPT_MODE_CCM },
#endif
#ifdef HITLS_CRYPTO_HCTR
    {.id = CRYPT_CIPHER_SM4_HCTR, .modeId = HCRYPT_MODE_HCTR },
#endif
#endif // sm4
};

#ifdef HITLS_CRYPTO_AES
static const EAL_SymMethod AES128_METHOD = {
    (SetEncryptKey)CRYPT_AES_SetEncryptKey128,
    (SetDecryptKey)CRYPT_AES_SetDecryptKey128,
    (EncryptBlock)CRYPT_AES_Encrypt,
    (DecryptBlock)CRYPT_AES_Decrypt,
    (DeInitBlockCtx)CRYPT_AES_Clean,
    NULL,
    16,
    sizeof(CRYPT_AES_Key),
    CRYPT_SYM_AES128
};

static const EAL_SymMethod AES192_METHOD = {
    (SetEncryptKey)CRYPT_AES_SetEncryptKey192,
    (SetDecryptKey)CRYPT_AES_SetDecryptKey192,
    (EncryptBlock)CRYPT_AES_Encrypt,
    (DecryptBlock)CRYPT_AES_Decrypt,
    (DeInitBlockCtx)CRYPT_AES_Clean,
    NULL,
    16,
    sizeof(CRYPT_AES_Key),
    CRYPT_SYM_AES192
};

static const EAL_SymMethod AES256_METHOD = {
    (SetEncryptKey)CRYPT_AES_SetEncryptKey256,
    (SetDecryptKey)CRYPT_AES_SetDecryptKey256,
    (EncryptBlock)CRYPT_AES_Encrypt,
    (DecryptBlock)CRYPT_AES_Decrypt,
    (DeInitBlockCtx)CRYPT_AES_Clean,
    NULL,
    16,
    sizeof(CRYPT_AES_Key),
    CRYPT_SYM_AES256
};
#endif

#ifdef HITLS_CRYPTO_CHACHA20
static const EAL_SymMethod CHACHA20_METHOD = {
    (SetEncryptKey)CRYPT_CHACHA20_SetKey,
    (SetDecryptKey)CRYPT_CHACHA20_SetKey,
    (EncryptBlock)CRYPT_CHACHA20_Update,
    (DecryptBlock)CRYPT_CHACHA20_Update,
    (DeInitBlockCtx)CRYPT_CHACHA20_Clean,
    (CipherCtrl)CRYPT_CHACHA20_Ctrl,
    1,
    sizeof(CRYPT_CHACHA20_Ctx),
    CRYPT_SYM_CHACHA20
};
#endif

#ifdef HITLS_CRYPTO_SM4
static const EAL_SymMethod SM4_METHOD = {
    (SetEncryptKey)CRYPT_SM4_SetKey,
    (SetDecryptKey)CRYPT_SM4_SetKey,
    (EncryptBlock)CRYPT_SM4_Encrypt,
    (DecryptBlock)CRYPT_SM4_Decrypt,
    (DeInitBlockCtx)CRYPT_SM4_Clean,
    NULL,
    16,
    sizeof(CRYPT_SM4_Ctx),
    CRYPT_SYM_SM4
};
#endif

const EAL_SymMethod *EAL_GetSymMethod(int32_t algId)
{
    switch (algId) {
#ifdef HITLS_CRYPTO_AES
        case CRYPT_CIPHER_AES128_CBC:
        case CRYPT_CIPHER_AES128_ECB:
        case CRYPT_CIPHER_AES128_XTS:
        case CRYPT_CIPHER_AES128_CTR:
        case CRYPT_CIPHER_AES128_CCM:
        case CRYPT_CIPHER_AES128_GCM:
        case CRYPT_CIPHER_AES128_CFB:
        case CRYPT_CIPHER_AES128_OFB:
            return &AES128_METHOD;
        case CRYPT_CIPHER_AES192_CBC:
        case CRYPT_CIPHER_AES192_ECB:
        case CRYPT_CIPHER_AES192_CTR:
        case CRYPT_CIPHER_AES192_CCM:
        case CRYPT_CIPHER_AES192_GCM:
        case CRYPT_CIPHER_AES192_CFB:
        case CRYPT_CIPHER_AES192_OFB:
            return &AES192_METHOD;
        case CRYPT_CIPHER_AES256_CBC:
        case CRYPT_CIPHER_AES256_ECB:
        case CRYPT_CIPHER_AES256_CTR:
        case CRYPT_CIPHER_AES256_XTS:
        case CRYPT_CIPHER_AES256_CCM:
        case CRYPT_CIPHER_AES256_GCM:
        case CRYPT_CIPHER_AES256_CFB:
        case CRYPT_CIPHER_AES256_OFB:
            return &AES256_METHOD;
#endif
#ifdef HITLS_CRYPTO_SM4
        case CRYPT_CIPHER_SM4_XTS:
        case CRYPT_CIPHER_SM4_CBC:
        case CRYPT_CIPHER_SM4_ECB:
        case CRYPT_CIPHER_SM4_CTR:
        case CRYPT_CIPHER_SM4_GCM:
        case CRYPT_CIPHER_SM4_CFB:
        case CRYPT_CIPHER_SM4_OFB:
        case CRYPT_CIPHER_SM4_CCM:
        case CRYPT_CIPHER_SM4_HCTR:
            return &SM4_METHOD;
#endif
#ifdef HITLS_CRYPTO_CHACHA20
        case CRYPT_CIPHER_CHACHA20_POLY1305:
            return &CHACHA20_METHOD;
#endif
        default:
            return NULL;
    }
}

static CRYPT_CipherInfo g_cipherInfo[] = {
#ifdef HITLS_CRYPTO_AES
#ifdef HITLS_CRYPTO_CBC
    {.id = CRYPT_CIPHER_AES128_CBC, .blockSize = 16, .keyLen = 16, .ivLen = 16},
    {.id = CRYPT_CIPHER_AES192_CBC, .blockSize = 16, .keyLen = 24, .ivLen = 16},
    {.id = CRYPT_CIPHER_AES256_CBC, .blockSize = 16, .keyLen = 32, .ivLen = 16},
#endif
#ifdef HITLS_CRYPTO_ECB
    {.id = CRYPT_CIPHER_AES128_ECB, .blockSize = 16, .keyLen = 16, .ivLen = 0},
    {.id = CRYPT_CIPHER_AES192_ECB, .blockSize = 16, .keyLen = 24, .ivLen = 0},
    {.id = CRYPT_CIPHER_AES256_ECB, .blockSize = 16, .keyLen = 32, .ivLen = 0},
#endif
#ifdef HITLS_CRYPTO_CTR
    {.id = CRYPT_CIPHER_AES128_CTR, .blockSize = 1, .keyLen = 16, .ivLen = 16},
    {.id = CRYPT_CIPHER_AES192_CTR, .blockSize = 1, .keyLen = 24, .ivLen = 16},
    {.id = CRYPT_CIPHER_AES256_CTR, .blockSize = 1, .keyLen = 32, .ivLen = 16},
#endif
#ifdef HITLS_CRYPTO_CCM
    {.id = CRYPT_CIPHER_AES128_CCM, .blockSize = 1, .keyLen = 16, .ivLen = 12},
    {.id = CRYPT_CIPHER_AES192_CCM, .blockSize = 1, .keyLen = 24, .ivLen = 12},
    {.id = CRYPT_CIPHER_AES256_CCM, .blockSize = 1, .keyLen = 32, .ivLen = 12},
#endif
#ifdef HITLS_CRYPTO_GCM
    {.id = CRYPT_CIPHER_AES128_GCM, .blockSize = 1, .keyLen = 16, .ivLen = 12},
    {.id = CRYPT_CIPHER_AES192_GCM, .blockSize = 1, .keyLen = 24, .ivLen = 12},
    {.id = CRYPT_CIPHER_AES256_GCM, .blockSize = 1, .keyLen = 32, .ivLen = 12},
#endif
#ifdef HITLS_CRYPTO_CFB
    {.id = CRYPT_CIPHER_AES128_CFB, .blockSize = 1, .keyLen = 16, .ivLen = 16},
    {.id = CRYPT_CIPHER_AES192_CFB, .blockSize = 1, .keyLen = 24, .ivLen = 16},
    {.id = CRYPT_CIPHER_AES256_CFB, .blockSize = 1, .keyLen = 32, .ivLen = 16},
#endif
#ifdef HITLS_CRYPTO_OFB
    {.id = CRYPT_CIPHER_AES128_OFB, .blockSize = 1, .keyLen = 16, .ivLen = 16},
    {.id = CRYPT_CIPHER_AES192_OFB, .blockSize = 1, .keyLen = 24, .ivLen = 16},
    {.id = CRYPT_CIPHER_AES256_OFB, .blockSize = 1, .keyLen = 32, .ivLen = 16},
#endif
#ifdef HITLS_CRYPTO_XTS
    {.id = CRYPT_CIPHER_AES128_XTS, .blockSize = 1, .keyLen = 32, .ivLen = 16},
    {.id = CRYPT_CIPHER_AES256_XTS, .blockSize = 1, .keyLen = 64, .ivLen = 16},
#endif
#endif
#ifdef HITLS_CRYPTO_CHACHA20
    {.id = CRYPT_CIPHER_CHACHA20_POLY1305, .blockSize = 1, .keyLen = 32, .ivLen = 12},
#endif
#ifdef HITLS_CRYPTO_SM4
#ifdef HITLS_CRYPTO_XTS
    {.id = CRYPT_CIPHER_SM4_XTS, .blockSize = 1, .keyLen = 32, .ivLen = 16},
#endif
#ifdef HITLS_CRYPTO_CBC
    {.id = CRYPT_CIPHER_SM4_CBC, .blockSize = 16, .keyLen = 16, .ivLen = 16},
#endif
#ifdef HITLS_CRYPTO_ECB
    {.id = CRYPT_CIPHER_SM4_ECB, .blockSize = 16, .keyLen = 16, .ivLen = 0},
#endif
#ifdef HITLS_CRYPTO_CTR
    {.id = CRYPT_CIPHER_SM4_CTR, .blockSize = 1, .keyLen = 16, .ivLen = 16},
#endif
#ifdef HITLS_CRYPTO_GCM
    {.id = CRYPT_CIPHER_SM4_GCM, .blockSize = 1, .keyLen = 16, .ivLen = 12},
#endif
#ifdef HITLS_CRYPTO_CFB
    {.id = CRYPT_CIPHER_SM4_CFB, .blockSize = 1, .keyLen = 16, .ivLen = 16},
#endif
#ifdef HITLS_CRYPTO_OFB
    {.id = CRYPT_CIPHER_SM4_OFB, .blockSize = 1, .keyLen = 16, .ivLen = 16},
#endif
#ifdef HITLS_CRYPTO_HCTR
    {.id = CRYPT_CIPHER_SM4_HCTR, .blockSize = 1, .keyLen = 32, .ivLen = 16},
#endif
#endif
};

/**
 * Search for the lengths of the block, key, and IV of algorithm. If ID in g_cipherInfo is changed,
 * synchronize the value of the SDV_CRYPTO_CIPHER_FUN_TC008 test case.
 * The input ID has a mapping relationship with g_ealCipherMethod and CRYPT_CIPHER_AlgId.
 * The corresponding information must be synchronized to symMap.
 * The symMap and CRYPT_SYM_AlgId, CRYPT_MODE_AlgId depend on each other. Synchronize the corresponding information.
 */
int32_t EAL_GetCipherInfo(CRYPT_CIPHER_AlgId id, CRYPT_CipherInfo *info)
{
    uint32_t num = sizeof(g_cipherInfo) / sizeof(g_cipherInfo[0]);
    const CRYPT_CipherInfo *cipherInfoGet = NULL;

    for (uint32_t i = 0; i < num; i++) {
        if (g_cipherInfo[i].id == id) {
            cipherInfoGet = &g_cipherInfo[i];
            break;
        }
    }

    if (cipherInfoGet == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ERR_ALGID);
        return CRYPT_ERR_ALGID;
    }

    info->blockSize = cipherInfoGet->blockSize;
    info->ivLen = cipherInfoGet->ivLen;
    info->keyLen = cipherInfoGet->keyLen;
    return CRYPT_SUCCESS;
}

int32_t EAL_CipherFindMethod(CRYPT_CIPHER_AlgId id, EAL_CipherMethod *method)
{
    if (method == NULL) {
        return CRYPT_NULL_INPUT;
    }

    uint32_t num = sizeof(SYM_ID_MAP) / sizeof(SYM_ID_MAP[0]);
    const EAL_SymAlgMap *symAlgMap = NULL;

    for (uint32_t i = 0; i < num; i++) {
        if (SYM_ID_MAP[i].id == id) {
            symAlgMap = &SYM_ID_MAP[i];
            break;
        }
    }

    if (symAlgMap == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }

    const EAL_CipherMethod *modeMethod = EAL_FindModeMethod(symAlgMap->modeId);
    if (modeMethod == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }
    (void)memcpy_s(method, sizeof(EAL_CipherMethod), modeMethod, sizeof(EAL_CipherMethod));
    return CRYPT_SUCCESS;
}

#ifdef HITLS_CRYPTO_PROVIDER
static int32_t SetCipherMethod(const CRYPT_EAL_Func *funcs, EAL_CipherMethod *method)
{
    int32_t index = 0;
    while (funcs[index].id != 0) {
        switch (funcs[index].id) {
            case CRYPT_EAL_IMPLCIPHER_NEWCTX:
                method->newCtx = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLCIPHER_INITCTX:
                method->initCtx = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLCIPHER_UPDATE:
                method->update = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLCIPHER_FINAL:
                method->final = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLCIPHER_DEINITCTX:
                method->deinitCtx = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLCIPHER_FREECTX:
                method->freeCtx = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLCIPHER_CTRL:
                method->ctrl = funcs[index].func;
                break;
            default:
                BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL);
                return CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL;
        }
        index++;
    }
    return CRYPT_SUCCESS;
}

int32_t EAL_ProviderCipherFindMethod(CRYPT_CIPHER_AlgId id, void *libCtx, const char *attrName,
    EAL_CipherMethod *method, void **provCtx)
{
    if (method == NULL) {
        return CRYPT_NULL_INPUT;
    }

    const CRYPT_EAL_Func *funcs = NULL;
    int32_t ret = CRYPT_EAL_ProviderGetFuncs(libCtx, CRYPT_EAL_OPERAID_SYMMCIPHER, id, attrName,
        &funcs, provCtx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return SetCipherMethod(funcs, method);
}
#endif // HITLS_CRYPTO_PROVIDER

#endif
