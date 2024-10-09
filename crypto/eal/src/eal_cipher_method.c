/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_CIPHER)

#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "eal_cipher_local.h"
#include "crypt_modes.h"
#ifdef HITLS_CRYPTO_CTR
#include "crypt_modes_ctr.h"
#endif
#ifdef HITLS_CRYPTO_CBC
#include "crypt_modes_cbc.h"
#endif
#ifdef HITLS_CRYPTO_GCM
#include "crypt_modes_gcm.h"
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
#ifdef HITLS_CRYPTO_CHACHA20POLY1305
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

typedef int32_t (*InitCtx)(void *ctx, const struct EAL_CipherMethod *m);
typedef void (*DeinitCtx)(void *ctx);
typedef void (*Clean)(void *ctx);
typedef int32_t (*SetEncryptKey)(void *ctx, const uint8_t *key, uint32_t len);
typedef int32_t (*SetDecryptKey)(void *ctx, const uint8_t *key, uint32_t len);
typedef int32_t (*Encrypt)(void *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
typedef int32_t (*Decrypt)(void *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
typedef int32_t (*Ctrl)(void *ctx, uint32_t opt, void *val, uint32_t len);

#ifdef HITLS_CRYPTO_AES
static const EAL_CipherMethod AES128_METHOD = {
    NULL,
    NULL,
    (Clean)CRYPT_AES_Clean,
    (SetEncryptKey)CRYPT_AES_SetEncryptKey128,
    (SetDecryptKey)CRYPT_AES_SetDecryptKey128,
    (Encrypt)CRYPT_AES_Encrypt,
    (Decrypt)CRYPT_AES_Decrypt,
    NULL,
    16,
    sizeof(CRYPT_AES_Key),
    CRYPT_SYM_AES128
};

static const EAL_CipherMethod AES192_METHOD = {
    NULL,
    NULL,
    (Clean)CRYPT_AES_Clean,
    (SetEncryptKey)CRYPT_AES_SetEncryptKey192,
    (SetDecryptKey)CRYPT_AES_SetDecryptKey192,
    (Encrypt)CRYPT_AES_Encrypt,
    (Decrypt)CRYPT_AES_Decrypt,
    NULL,
    16,
    sizeof(CRYPT_AES_Key),
    CRYPT_SYM_AES192
};

static const EAL_CipherMethod AES256_METHOD = {
    NULL,
    NULL,
    (Clean)CRYPT_AES_Clean,
    (SetEncryptKey)CRYPT_AES_SetEncryptKey256,
    (SetDecryptKey)CRYPT_AES_SetDecryptKey256,
    (Encrypt)CRYPT_AES_Encrypt,
    (Decrypt)CRYPT_AES_Decrypt,
    NULL,
    16,
    sizeof(CRYPT_AES_Key),
    CRYPT_SYM_AES256
};

#ifdef HITLS_CRYPTO_GCM
static const EAL_CipherMethod AES_GCM_METHOD = {
    (InitCtx)MODES_GCM_InitCtx,
    (DeinitCtx)MODES_GCM_DeinitCtx,
    (Clean)MODES_GCM_Clean,
    (SetEncryptKey)MODES_GCM_SetKey,
    (SetDecryptKey)MODES_GCM_SetKey,
    (Encrypt)AES_GCM_EncryptBlock,
    (Decrypt)AES_GCM_DecryptBlock,
    (Ctrl)MODES_GCM_Ctrl,
    1,
    sizeof(EAL_GCM_Ctx),
    0
};
#endif

#ifdef HITLS_CRYPTO_CCM
static const EAL_CipherMethod AES_CCM_METHOD = {
    (InitCtx)MODES_CCM_InitCtx,
    (DeinitCtx)MODES_CCM_DeinitCtx,
    (Clean)MODES_CCM_Clean,
    (SetEncryptKey)MODES_CCM_SetKey,
    (SetDecryptKey)MODES_CCM_SetKey,
    (Encrypt)MODES_CCM_Encrypt,
    (Decrypt)MODES_CCM_Decrypt,
    (Ctrl)MODES_CCM_Ctrl,
    1,
    sizeof(MODES_CCM_Ctx),
    0
};
#endif

#ifdef HITLS_CRYPTO_CBC
static const EAL_CipherMethod AES_CBC_METHOD = {
    (InitCtx)MODE_InitCtx,
    (DeinitCtx)MODE_DeInitCtx,
    (Clean)MODE_CBC_Clean,
    (SetEncryptKey)MODE_SetEncryptKey,
    (SetDecryptKey)MODE_SetDecryptKey,
    (Encrypt)AES_CBC_EncryptBlock,
    (Decrypt)AES_CBC_DecryptBlock,
    (Ctrl)MODE_Ctrl,
    16,
    sizeof(MODE_CipherCtx),
    0
};
#endif

#ifdef HITLS_CRYPTO_CTR
static const EAL_CipherMethod AES_CTR_METHOD = {
    (InitCtx)MODE_InitCtx,
    (DeinitCtx)MODE_DeInitCtx,
    (Clean)MODE_CTR_Clean,
    (SetEncryptKey)MODE_SetEncryptKey,
    (SetDecryptKey)MODE_SetEncryptKey,
    (Encrypt)AES_CTR_EncryptBlock,
    (Decrypt)AES_CTR_DecryptBlock,
    (Ctrl)MODE_Ctrl,
    1,
    sizeof(MODE_CipherCtx),
    0
};
#endif

#ifdef HITLS_CRYPTO_CFB
static const EAL_CipherMethod AES_CFB_METHOD = {
    (InitCtx)MODE_CFB_InitCtx,
    (DeinitCtx)MODE_CFB_DeInitCtx,
    (Clean)MODE_CFB_Clean,
    (SetEncryptKey)MODE_CFB_SetEncryptKey,
    (SetDecryptKey)MODE_CFB_SetEncryptKey,
    (Encrypt)MODE_CFB_Encrypt,
    (Decrypt)MODE_AES_CFB_Decrypt,
    (Ctrl)MODE_CFB_Ctrl,
    1,
    sizeof(MODE_CFB_Ctx),
    0
};
#endif

#endif  // HITLS_CRYPTO_AES

#ifdef HITLS_CRYPTO_CHACHA20
static const EAL_CipherMethod CHACHA20_METHOD = {
    NULL,
    NULL,
    NULL,
    (SetEncryptKey)CRYPT_CHACHA20_SetKey,
    (SetDecryptKey)CRYPT_CHACHA20_SetKey,
    (Encrypt)CRYPT_CHACHA20_Update,
    (Decrypt)CRYPT_CHACHA20_Update,
    (Ctrl)CRYPT_CHACHA20_Ctrl,
    1,
    sizeof(CRYPT_CHACHA20_Ctx),
    CRYPT_SYM_CHACHA20
};
#endif

#ifdef HITLS_CRYPTO_SM4
static const EAL_CipherMethod SM4_METHOD = {
    (InitCtx)NULL,
    (DeinitCtx)NULL,
    (Clean)CRYPT_SM4_Clean,
    (SetEncryptKey)CRYPT_SM4_SetKey,
    (SetDecryptKey)CRYPT_SM4_SetKey,
    (Encrypt)CRYPT_SM4_Encrypt,
    (Decrypt)CRYPT_SM4_Decrypt,
    NULL,
    16,
    sizeof(CRYPT_SM4_Ctx),
    CRYPT_SYM_SM4
};

#ifdef HITLS_CRYPTO_CBC
static const EAL_CipherMethod SM4_CBC_METHOD = {
    (InitCtx)MODE_InitCtx,
    (DeinitCtx)MODE_DeInitCtx,
    (Clean)MODE_CBC_Clean,
    (SetEncryptKey)MODES_SM4_SetEncryptKey,
    (SetDecryptKey)MODES_SM4_SetDecryptKey,
    (Encrypt)MODE_SM4_CBC_Encrypt,
    (Decrypt)MODE_SM4_CBC_Decrypt,
    (Ctrl)MODE_Ctrl,
    16,
    sizeof(MODE_CipherCtx),
    0
};
#endif

#ifdef HITLS_CRYPTO_XTS
static const EAL_CipherMethod SM4_XTS_METHOD = {
    (InitCtx)MODE_XTS_InitCtx,
    (DeinitCtx)MODE_DeInitCtx,
    (Clean)MODES_SM4_XTS_Clean,
    (SetEncryptKey)MODES_SM4_XTS_SetEncryptKey,
    (SetDecryptKey)MODES_SM4_XTS_SetDecryptKey,
    (Encrypt)MODES_SM4_XTS_Encrypt,
    (Decrypt)MODES_SM4_XTS_Decrypt,
    (Ctrl)MODE_XTS_Ctrl,
    1,
    sizeof(MODE_CipherCtx),
    0
};
#endif

#ifdef HITLS_CRYPTO_CFB
static const EAL_CipherMethod SM4_CFB_METHOD = {
    (InitCtx)MODE_CFB_InitCtx,
    (DeinitCtx)MODE_CFB_DeInitCtx,
    (Clean)MODE_CFB_Clean,
    (SetEncryptKey)MODES_SM4_CFB_SetEncryptKey,
    (SetDecryptKey)MODES_SM4_CFB_SetEncryptKey,
    (Encrypt)MODE_SM4_CFB_Encrypt,
    (Decrypt)MODE_SM4_CFB_Decrypt,
    (Ctrl)MODE_CFB_Ctrl,
    1,
    sizeof(MODE_CFB_Ctx),
    0
};
#endif

#ifdef HITLS_CRYPTO_OFB
static const EAL_CipherMethod SM4_OFB_METHOD = {
    (InitCtx)MODE_InitCtx,
    (DeinitCtx)MODE_DeInitCtx,
    (Clean)MODE_Clean,
    (SetEncryptKey)MODES_SM4_SetEncryptKey,
    (SetDecryptKey)MODES_SM4_SetEncryptKey,
    (Encrypt)MODE_SM4_OFB_Encrypt,
    (Decrypt)MODE_SM4_OFB_Decrypt,
    (Ctrl)MODE_Ctrl,
    1,
    sizeof(MODE_CipherCtx),
    0
};
#endif

#ifdef HITLS_CRYPTO_GCM
static const EAL_CipherMethod SM4_GCM_METHOD = {
    (InitCtx)MODES_GCM_InitCtx,
    (DeinitCtx)MODES_GCM_DeinitCtx,
    (Clean)MODES_GCM_Clean,
    (SetEncryptKey)MODES_SM4_GCM_SetKey,
    (SetDecryptKey)MODES_SM4_GCM_SetKey,
    (Encrypt)MODES_SM4_GCM_EncryptBlock,
    (Decrypt)MODES_SM4_GCM_DecryptBlock,
    (Ctrl)MODES_GCM_Ctrl,
    1,
    sizeof(EAL_GCM_Ctx),
    0
};
#endif

#ifdef HITLS_CRYPTO_CTR
static const EAL_CipherMethod SM4_CTR_METHOD = {
    (InitCtx)MODE_InitCtx,
    (DeinitCtx)MODE_DeInitCtx,
    (Clean)MODE_CTR_Clean,
    (SetEncryptKey)MODES_SM4_SetEncryptKey,
    (SetDecryptKey)MODES_SM4_SetEncryptKey,
    (Encrypt)MODE_SM4_CTR_Encrypt,
    (Decrypt)MODE_SM4_CTR_Decrypt,
    (Ctrl)MODE_Ctrl,
    1,
    sizeof(MODE_CipherCtx),
    0
};
#endif
#endif  // HITLS_CRYPTO_SM4

#ifdef HITLS_CRYPTO_CTR
static const EAL_CipherMethod CTR_METHOD = {
    (InitCtx)MODE_InitCtx,
    (DeinitCtx)MODE_DeInitCtx,
    (Clean)MODE_CTR_Clean,
    (SetEncryptKey)MODE_SetEncryptKey,
    (SetDecryptKey)MODE_SetEncryptKey,
    (Encrypt)MODE_CTR_Crypt,
    (Decrypt)MODE_CTR_Crypt,
    (Ctrl)MODE_Ctrl,
    1,
    sizeof(MODE_CipherCtx),
    0
};
#endif

#ifdef HITLS_CRYPTO_CBC
static const EAL_CipherMethod CBC_METHOD = {
    (InitCtx)MODE_InitCtx,
    (DeinitCtx)MODE_DeInitCtx,
    (Clean)MODE_CBC_Clean,
    (SetEncryptKey)MODE_SetEncryptKey,
    (SetDecryptKey)MODE_SetDecryptKey,
    (Encrypt)MODE_CBC_Encrypt,
    (Decrypt)MODE_CBC_Decrypt,
    (Ctrl)MODE_Ctrl,
    0,
    sizeof(MODE_CipherCtx),
    0
};
#endif

#ifdef HITLS_CRYPTO_CCM
static const EAL_CipherMethod CCM_METHOD = {
    (InitCtx)MODES_CCM_InitCtx,
    (DeinitCtx)MODES_CCM_DeinitCtx,
    (Clean)MODES_CCM_Clean,
    (SetEncryptKey)MODES_CCM_SetKey,
    (SetDecryptKey)MODES_CCM_SetKey,
    (Encrypt)MODES_CCM_Encrypt,
    (Decrypt)MODES_CCM_Decrypt,
    (Ctrl)MODES_CCM_Ctrl,
    1,
    sizeof(MODES_CCM_Ctx),
    0
};
#endif

#ifdef HITLS_CRYPTO_GCM
static const EAL_CipherMethod GCM_METHOD = {
    (InitCtx)MODES_GCM_InitCtx,
    (DeinitCtx)MODES_GCM_DeinitCtx,
    (Clean)MODES_GCM_Clean,
    (SetEncryptKey)MODES_GCM_SetKey,
    (SetDecryptKey)MODES_GCM_SetKey,
    (Encrypt)MODES_GCM_Encrypt,
    (Decrypt)MODES_GCM_Decrypt,
    (Ctrl)MODES_GCM_Ctrl,
    1,
    sizeof(MODES_GCM_Ctx),
    0
};
#endif

#ifdef HITLS_CRYPTO_CHACHA20POLY1305
static const EAL_CipherMethod CHACHA20_POLY1305_METHOD = {
    (InitCtx)MODES_CHACHA20POLY1305_InitCtx,
    (DeinitCtx)MODES_CHACHA20POLY1305_DeinitCtx,
    (Clean)MODES_CHACHA20POLY1305_Clean,
    (SetEncryptKey)MODES_CHACHA20POLY1305_SetEncryptKey,
    (SetDecryptKey)MODES_CHACHA20POLY1305_SetDecryptKey,
    (Encrypt)MODES_CHACHA20POLY1305_Encrypt,
    (Decrypt)MODES_CHACHA20POLY1305_Decrypt,
    (Ctrl)MODES_CHACHA20POLY1305_Ctrl,
    1,
    sizeof(MODES_CHACHA20POLY1305_Ctx),
    0
};
#endif

#ifdef HITLS_CRYPTO_CFB
static const EAL_CipherMethod CFB_METHOD = {
    (InitCtx)MODE_CFB_InitCtx,
    (DeinitCtx)MODE_CFB_DeInitCtx,
    (Clean)MODE_CFB_Clean,
    (SetEncryptKey)MODE_CFB_SetEncryptKey,
    (SetDecryptKey)MODE_CFB_SetEncryptKey,
    (Encrypt)MODE_CFB_Encrypt,
    (Decrypt)MODE_CFB_Decrypt,
    (Ctrl)MODE_CFB_Ctrl,
    1,
    sizeof(MODE_CFB_Ctx),
    0
};
#endif

#ifdef HITLS_CRYPTO_OFB
static const EAL_CipherMethod OFB_METHOD = {
    (InitCtx)MODE_InitCtx,
    (DeinitCtx)MODE_DeInitCtx,
    (Clean)MODE_Clean,
    (SetEncryptKey)MODE_SetEncryptKey,
    (SetDecryptKey)MODE_SetEncryptKey,
    (Encrypt)MODE_OFB_Crypt,
    (Decrypt)MODE_OFB_Crypt,
    (Ctrl)MODE_Ctrl,
    1,
    sizeof(MODE_CipherCtx),
    0
};
#endif

#ifdef HITLS_CRYPTO_AES
#ifdef HITLS_CRYPTO_GCM
static const EAL_Cipher g_aes128Gcm = {
    &AES128_METHOD,
    &AES_GCM_METHOD
};
static const EAL_Cipher g_aes192Gcm = {
    &AES192_METHOD,
    &AES_GCM_METHOD
};
static const EAL_Cipher g_aes256Gcm = {
    &AES256_METHOD,
    &AES_GCM_METHOD
};
#endif

#ifdef HITLS_CRYPTO_CTR
static const EAL_Cipher g_aes128Ctr = {
    &AES128_METHOD,
    &AES_CTR_METHOD
};
static const EAL_Cipher g_aes192Ctr = {
    &AES192_METHOD,
    &AES_CTR_METHOD
};
static const EAL_Cipher g_aes256Ctr = {
    &AES256_METHOD,
    &AES_CTR_METHOD
};
#endif

#ifdef HITLS_CRYPTO_CBC
static const EAL_Cipher AES128_CBC = {
    &AES128_METHOD,
    &AES_CBC_METHOD
};
static const EAL_Cipher AES192_CBC = {
    &AES192_METHOD,
    &AES_CBC_METHOD
};
static const EAL_Cipher AES256_CBC = {
    &AES256_METHOD,
    &AES_CBC_METHOD
};
#endif

#ifdef HITLS_CRYPTO_CFB
static const EAL_Cipher AES128_CFB = {
    &AES128_METHOD,
    &AES_CFB_METHOD
};
static const EAL_Cipher AES192_CFB = {
    &AES192_METHOD,
    &AES_CFB_METHOD
};
static const EAL_Cipher AES256_CFB = {
    &AES256_METHOD,
    &AES_CFB_METHOD
};
#endif

#ifdef HITLS_CRYPTO_CCM
static const EAL_Cipher AES128_CCM = {
    &AES128_METHOD,
    &AES_CCM_METHOD
};
static const EAL_Cipher AES192_CCM = {
    &AES192_METHOD,
    &AES_CCM_METHOD
};
static const EAL_Cipher AES256_CCM = {
    &AES256_METHOD,
    &AES_CCM_METHOD
};
#endif
#endif  // HITLS_CRYPTO_AES

#ifdef HITLS_CRYPTO_SM4
#ifdef HITLS_CRYPTO_XTS
static const EAL_Cipher g_sm4Xts = {
    &SM4_METHOD,
    &SM4_XTS_METHOD
};
#endif

#ifdef HITLS_CRYPTO_CBC
static const EAL_Cipher g_sm4Cbc = {
    &SM4_METHOD,
    &SM4_CBC_METHOD
};
#endif

#ifdef HITLS_CRYPTO_CFB
static const EAL_Cipher g_sm4Cfb = {
    &SM4_METHOD,
    &SM4_CFB_METHOD
};
#endif

#ifdef HITLS_CRYPTO_OFB
static const EAL_Cipher g_sm4Ofb = {
    &SM4_METHOD,
    &SM4_OFB_METHOD
};
#endif

#ifdef HITLS_CRYPTO_CTR
static const EAL_Cipher g_sm4Ctr = {
    &SM4_METHOD,
    &SM4_CTR_METHOD
};
#endif

#ifdef HITLS_CRYPTO_GCM
static const EAL_Cipher g_sm4Gcm = {
    &SM4_METHOD,
    &SM4_GCM_METHOD
};
#endif
#endif  // HITLS_CRYPTO_SM4

/**
 * 1. Mode and algorithm combination acceleration table (hash table)
 *    (There is a hash mapping relationship based on CRYPT_CIPHER_AlgId. Pay attention to the synchronization.)
 * 2. This table saves the assembly acceleration of the mode and algorithm, for example, aes-gcm and aes-cbc.
 * 3. If the assembly acceleration is not implemented, set the value to NULL.
 *    If the value is NULL, the original C-Language logic is used.
 */
static const EAL_SymAlgMapAsm EAL_CIPHER_METHOD_ASM[] = {
#ifdef HITLS_CRYPTO_AES
#ifdef HITLS_CRYPTO_CBC
    { .id = CRYPT_CIPHER_AES128_CBC, &AES128_CBC },
    { .id = CRYPT_CIPHER_AES192_CBC, &AES192_CBC },
    { .id = CRYPT_CIPHER_AES256_CBC, &AES256_CBC },
#endif

#ifdef HITLS_CRYPTO_CTR
    { .id = CRYPT_CIPHER_AES128_CTR, &g_aes128Ctr },
    { .id = CRYPT_CIPHER_AES192_CTR, &g_aes192Ctr },
    { .id = CRYPT_CIPHER_AES256_CTR, &g_aes256Ctr },
#endif

#ifdef HITLS_CRYPTO_CCM
    { .id = CRYPT_CIPHER_AES128_CCM, &AES128_CCM },
    { .id = CRYPT_CIPHER_AES192_CCM, &AES192_CCM },
    { .id = CRYPT_CIPHER_AES256_CCM, &AES256_CCM },
#endif

#ifdef HITLS_CRYPTO_GCM
    { .id = CRYPT_CIPHER_AES128_GCM, &g_aes128Gcm },
    { .id = CRYPT_CIPHER_AES192_GCM, &g_aes192Gcm },
    { .id = CRYPT_CIPHER_AES256_GCM, &g_aes256Gcm },
#endif

#ifdef HITLS_CRYPTO_CFB
    { .id = CRYPT_CIPHER_AES128_CFB, &AES128_CFB },
    { .id = CRYPT_CIPHER_AES192_CFB, &AES192_CFB },
    { .id = CRYPT_CIPHER_AES256_CFB, &AES256_CFB },
#endif

#ifdef HITLS_CRYPTO_OFB
    { .id = CRYPT_CIPHER_AES128_OFB, NULL },
    { .id = CRYPT_CIPHER_AES192_OFB, NULL },
    { .id = CRYPT_CIPHER_AES256_OFB, NULL },
#endif
#endif  // HITLS_CRYPTO_AES

#ifdef HITLS_CRYPTO_CHACHA20
    { .id = CRYPT_CIPHER_CHACHA20_POLY1305, NULL },
#endif

#ifdef HITLS_CRYPTO_SM4
#ifdef HITLS_CRYPTO_XTS
    { .id = CRYPT_CIPHER_SM4_XTS, &g_sm4Xts },
#endif
#ifdef HITLS_CRYPTO_CBC
    { .id = CRYPT_CIPHER_SM4_CBC, &g_sm4Cbc },
#endif
#ifdef HITLS_CRYPTO_CTR
    { .id = CRYPT_CIPHER_SM4_CTR, &g_sm4Ctr },
#endif
#ifdef HITLS_CRYPTO_GCM
    { .id = CRYPT_CIPHER_SM4_GCM, &g_sm4Gcm },
#endif
#ifdef HITLS_CRYPTO_CFB
    { .id = CRYPT_CIPHER_SM4_CFB, &g_sm4Cfb },
#endif
#ifdef HITLS_CRYPTO_OFB
    { .id = CRYPT_CIPHER_SM4_OFB, &g_sm4Ofb },
#endif
#endif  // HITLS_CRYPTO_SM4
};

/**
 * g_symMethod[id]
 * The content of g_symMethod has a hash mapping relationship with CRYPT_SYM_AlgId. Change the value accordingly.
 */
static const EAL_CipherMethod *g_symMethod[CRYPT_SYM_MAX] = {
#ifdef HITLS_CRYPTO_AES
    &AES128_METHOD,
    &AES192_METHOD,
    &AES256_METHOD,
#else
    NULL,
    NULL,
    NULL,
#endif

#ifdef HITLS_CRYPTO_CHACHA20
    &CHACHA20_METHOD,
#else
    NULL,
#endif

#ifdef HITLS_CRYPTO_SM4
    &SM4_METHOD,
#else
    NULL,
#endif

};

/**
 * g_modeMethod[id]
 * The content of g_modeMethod has a hash mapping relationship with CRYPT_MODE_AlgId. Change the value accordingly.
*/
static const EAL_CipherMethod *g_modeMethod[CRYPT_MODE_MAX] = {
#ifdef HITLS_CRYPTO_CBC
    &CBC_METHOD,
#else
    NULL,
#endif
#ifdef HITLS_CRYPTO_CTR
    &CTR_METHOD,
#else
    NULL,
#endif
    NULL,
    NULL,
#ifdef HITLS_CRYPTO_CCM
    &CCM_METHOD,
#else
    NULL,
#endif
#ifdef HITLS_CRYPTO_GCM
    &GCM_METHOD,
#else
    NULL,
#endif
#ifdef HITLS_CRYPTO_CHACHA20POLY1305
    &CHACHA20_POLY1305_METHOD,
#else
    NULL,
#endif
#ifdef HITLS_CRYPTO_CFB
    &CFB_METHOD,
#else
    NULL,
#endif
#ifdef HITLS_CRYPTO_OFB
    &OFB_METHOD
#else
    NULL
#endif
};

const EAL_CipherMethod *EAL_FindSymMethod(CRYPT_SYM_AlgId id)
{
    if (id < 0 || id >= CRYPT_SYM_MAX) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return NULL;
    }
    return g_symMethod[id];
}

const EAL_CipherMethod *EAL_FindModeMethod(CRYPT_MODE_AlgId id)
{
    if (id < 0 || id >= CRYPT_MODE_MAX) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return NULL;
    }
    return g_modeMethod[id];
}

static const EAL_SymAlgMap SYM_ID_MAP[] = {
#ifdef HITLS_CRYPTO_AES
    {.id = CRYPT_CIPHER_AES128_CBC, .modeId = CRYPT_MODE_CBC, .symId = CRYPT_SYM_AES128 },
    {.id = CRYPT_CIPHER_AES192_CBC, .modeId = CRYPT_MODE_CBC, .symId = CRYPT_SYM_AES192 },
    {.id = CRYPT_CIPHER_AES256_CBC, .modeId = CRYPT_MODE_CBC, .symId = CRYPT_SYM_AES256 },
    {.id = CRYPT_CIPHER_AES128_CTR, .modeId = CRYPT_MODE_CTR, .symId = CRYPT_SYM_AES128 },
    {.id = CRYPT_CIPHER_AES192_CTR, .modeId = CRYPT_MODE_CTR, .symId = CRYPT_SYM_AES192 },
    {.id = CRYPT_CIPHER_AES256_CTR, .modeId = CRYPT_MODE_CTR, .symId = CRYPT_SYM_AES256 },
    {.id = CRYPT_CIPHER_AES128_CCM, .modeId = CRYPT_MODE_CCM, .symId = CRYPT_SYM_AES128 },
    {.id = CRYPT_CIPHER_AES192_CCM, .modeId = CRYPT_MODE_CCM, .symId = CRYPT_SYM_AES192 },
    {.id = CRYPT_CIPHER_AES256_CCM, .modeId = CRYPT_MODE_CCM, .symId = CRYPT_SYM_AES256 },
    {.id = CRYPT_CIPHER_AES128_GCM, .modeId = CRYPT_MODE_GCM, .symId = CRYPT_SYM_AES128 },
    {.id = CRYPT_CIPHER_AES192_GCM, .modeId = CRYPT_MODE_GCM, .symId = CRYPT_SYM_AES192 },
    {.id = CRYPT_CIPHER_AES256_GCM, .modeId = CRYPT_MODE_GCM, .symId = CRYPT_SYM_AES256 },
    {.id = CRYPT_CIPHER_AES128_CFB, .modeId = CRYPT_MODE_CFB, .symId = CRYPT_SYM_AES128 },
    {.id = CRYPT_CIPHER_AES192_CFB, .modeId = CRYPT_MODE_CFB, .symId = CRYPT_SYM_AES192 },
    {.id = CRYPT_CIPHER_AES256_CFB, .modeId = CRYPT_MODE_CFB, .symId = CRYPT_SYM_AES256 },
    {.id = CRYPT_CIPHER_AES128_OFB, .modeId = CRYPT_MODE_OFB, .symId = CRYPT_SYM_AES128 },
    {.id = CRYPT_CIPHER_AES192_OFB, .modeId = CRYPT_MODE_OFB, .symId = CRYPT_SYM_AES192 },
    {.id = CRYPT_CIPHER_AES256_OFB, .modeId = CRYPT_MODE_OFB, .symId = CRYPT_SYM_AES256 },
#endif
#ifdef HITLS_CRYPTO_CHACHA20
    {.id = CRYPT_CIPHER_CHACHA20_POLY1305, .modeId = CRYPT_MODE_CHACHA20_POLY1305, .symId = CRYPT_SYM_CHACHA20 },
#endif
#ifdef HITLS_CRYPTO_SM4
    {.id = CRYPT_CIPHER_SM4_XTS, .modeId = CRYPT_MODE_XTS, .symId = CRYPT_SYM_SM4 },
    {.id = CRYPT_CIPHER_SM4_CBC, .modeId = CRYPT_MODE_CBC, .symId = CRYPT_SYM_SM4 },
    {.id = CRYPT_CIPHER_SM4_CTR, .modeId = CRYPT_MODE_CTR, .symId = CRYPT_SYM_SM4 },
    {.id = CRYPT_CIPHER_SM4_GCM, .modeId = CRYPT_MODE_GCM, .symId = CRYPT_SYM_SM4 },
    {.id = CRYPT_CIPHER_SM4_CFB, .modeId = CRYPT_MODE_CFB, .symId = CRYPT_SYM_SM4 },
    {.id = CRYPT_CIPHER_SM4_OFB, .modeId = CRYPT_MODE_OFB, .symId = CRYPT_SYM_SM4 },
#endif
};

/**
 * Search mode + algorithm
 * symMap[id]
 * It has hash mapping relationship between the input ID and g_ealCipherMethod and CRYPT_CIPHER_AlgId.
 * The corresponding information must be synchronized in the symMap.
 * The symMap content .modeId and .symId are dependent on the CRYPT_SYM_AlgId and CRYPT_MODE_AlgId.
 * The corresponding information must be synchronized.
 */
static int32_t FindCipher(CRYPT_CIPHER_AlgId id, EAL_Cipher *m)
{
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

    m->modeMethod = EAL_FindModeMethod(symAlgMap->modeId);
    if (m->modeMethod == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }
    m->ciphMeth = EAL_FindSymMethod(symAlgMap->symId);
    if (m->ciphMeth == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }
    return CRYPT_SUCCESS;
}

static CRYPT_CipherInfo g_cipherInfo[] = {
#ifdef HITLS_CRYPTO_AES
    {.id = CRYPT_CIPHER_AES128_CBC, .blockSize = 16, .keyLen = 16, .ivLen = 16},
    {.id = CRYPT_CIPHER_AES192_CBC, .blockSize = 16, .keyLen = 24, .ivLen = 16},
    {.id = CRYPT_CIPHER_AES256_CBC, .blockSize = 16, .keyLen = 32, .ivLen = 16},
    {.id = CRYPT_CIPHER_AES128_CTR, .blockSize = 1, .keyLen = 16, .ivLen = 16},
    {.id = CRYPT_CIPHER_AES192_CTR, .blockSize = 1, .keyLen = 24, .ivLen = 16},
    {.id = CRYPT_CIPHER_AES256_CTR, .blockSize = 1, .keyLen = 32, .ivLen = 16},
    {.id = CRYPT_CIPHER_AES128_CCM, .blockSize = 1, .keyLen = 16, .ivLen = 12},
    {.id = CRYPT_CIPHER_AES192_CCM, .blockSize = 1, .keyLen = 24, .ivLen = 12},
    {.id = CRYPT_CIPHER_AES256_CCM, .blockSize = 1, .keyLen = 32, .ivLen = 12},
    {.id = CRYPT_CIPHER_AES128_GCM, .blockSize = 1, .keyLen = 16, .ivLen = 12},
    {.id = CRYPT_CIPHER_AES192_GCM, .blockSize = 1, .keyLen = 24, .ivLen = 12},
    {.id = CRYPT_CIPHER_AES256_GCM, .blockSize = 1, .keyLen = 32, .ivLen = 12},
    {.id = CRYPT_CIPHER_AES128_CFB, .blockSize = 1, .keyLen = 16, .ivLen = 16},
    {.id = CRYPT_CIPHER_AES192_CFB, .blockSize = 1, .keyLen = 24, .ivLen = 16},
    {.id = CRYPT_CIPHER_AES256_CFB, .blockSize = 1, .keyLen = 32, .ivLen = 16},
    {.id = CRYPT_CIPHER_AES128_OFB, .blockSize = 1, .keyLen = 16, .ivLen = 16},
    {.id = CRYPT_CIPHER_AES192_OFB, .blockSize = 1, .keyLen = 24, .ivLen = 16},
    {.id = CRYPT_CIPHER_AES256_OFB, .blockSize = 1, .keyLen = 32, .ivLen = 16},
#endif
#ifdef HITLS_CRYPTO_CHACHA20
    {.id = CRYPT_CIPHER_CHACHA20_POLY1305, .blockSize = 1, .keyLen = 32, .ivLen = 12},
#endif
#ifdef HITLS_CRYPTO_SM4
    {.id = CRYPT_CIPHER_SM4_XTS, .blockSize = 1, .keyLen = 32, .ivLen = 16},
    {.id = CRYPT_CIPHER_SM4_CBC, .blockSize = 16, .keyLen = 16, .ivLen = 16},
    {.id = CRYPT_CIPHER_SM4_CTR, .blockSize = 1, .keyLen = 16, .ivLen = 16},
    {.id = CRYPT_CIPHER_SM4_GCM, .blockSize = 1, .keyLen = 16, .ivLen = 12},
    {.id = CRYPT_CIPHER_SM4_CFB, .blockSize = 1, .keyLen = 16, .ivLen = 16},
    {.id = CRYPT_CIPHER_SM4_OFB, .blockSize = 1, .keyLen = 16, .ivLen = 16},
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

int32_t EAL_FindCipher(CRYPT_CIPHER_AlgId id, EAL_Cipher *m)
{
    uint32_t num = sizeof(EAL_CIPHER_METHOD_ASM) / sizeof(EAL_CIPHER_METHOD_ASM[0]);
    const EAL_SymAlgMapAsm *symAlgMapAsm = NULL;

    for (uint32_t i = 0; i < num; i++) {
        if (EAL_CIPHER_METHOD_ASM[i].id == id) {
            symAlgMapAsm = &EAL_CIPHER_METHOD_ASM[i];
            break;
        }
    }

    if (symAlgMapAsm == NULL || symAlgMapAsm->symMeth == NULL) {
        return FindCipher(id, m);
    }

    m->modeMethod = symAlgMapAsm->symMeth->modeMethod;
    m->ciphMeth = symAlgMapAsm->symMeth->ciphMeth;
    return CRYPT_SUCCESS;
}
#endif
