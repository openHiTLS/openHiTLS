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
#ifdef HITLS_CRYPTO_SM9

#include "sm9_local.h"
#include "crypt_errno.h"
#include "crypt_sm9.h"
#include "crypt_util_rand.h"
#include "crypt_utils.h"
#include "crypt_params_key.h"
#include "bsl_sal.h"
#include "bsl_bytes.h"
#include <string.h>

#define SM9_KEY_TYPE_SIGN 1
#define SM9_KEY_TYPE_ENC  2

static void SM9_ModifyKeyRange(uint8_t *key)
{
    uint32_t scalar[SM9_BN_WORDS];
    SM9_BN_ReadBytes(scalar, key);
    SM9_Fn_LastRes(scalar);
    SM9_BN_AddInt(scalar, scalar, 1, SM9_BN_WORDS);
    SM9_Fn_LastRes(scalar);
    SM9_Fp_WriteBytes(key, scalar);
    BSL_SAL_CleanseData(scalar, sizeof(scalar));
}

static int32_t SM9_ValidateMasterPrivateKey(const uint8_t *masterPrvKey)
{
    uint32_t masterKey[SM9_BN_WORDS];
    int32_t valid;

    SM9_BN_ReadBytes(masterKey, masterPrvKey);
    valid = SM9_BN_IsZero(masterKey, g_sm9SysPara.wordSize) == 0 &&
            SM9_BN_Compare(masterKey, g_sm9SysPara.ecN, g_sm9SysPara.wordSize) < 0;
    BSL_SAL_CleanseData(masterKey, sizeof(masterKey));
    return valid != 0 ? CRYPT_SUCCESS : CRYPT_SM9_INVALID_PRVKEY;
}

static int32_t SM9_ValidateMasterKeyPair(const uint8_t *masterPrvKey, const uint8_t *masterPubKey,
                                         uint32_t masterPubKeyLen, int32_t keyType)
{
    uint8_t masterKey[SM9_ENC_SYS_PRIKEY_BYTES];
    uint8_t derivedPubKey[SM9_SIG_SYS_PUBKEY_BYTES];
    int32_t ret;

    memcpy(masterKey, masterPrvKey, sizeof(masterKey));
    if (keyType == SM9_KEY_TYPE_SIGN) {
        ret = SM9_Alg_MSKG(masterKey, derivedPubKey);
    } else {
        ret = SM9_Alg_MEKG(masterKey, derivedPubKey);
    }
    if (ret == CRYPT_SUCCESS && memcmp(derivedPubKey, masterPubKey, masterPubKeyLen) != 0) {
        ret = CRYPT_SM9_PAIRWISE_CHECK_FAIL;
    }
    BSL_SAL_CleanseData(masterKey, sizeof(masterKey));
    BSL_SAL_CleanseData(derivedPubKey, sizeof(derivedPubKey));
    return ret;
}

static int32_t SM9_ValidateG1PubKey(const uint8_t *pubkey, uint32_t len)
{
    if (len != SM9_ENC_SYS_PUBKEY_BYTES) {
        return CRYPT_SM9_ERR_KEY_ERR;
    }

    return SM9_EcpA_ValidateBytes(pubkey);
}

static int32_t SM9_ValidateG2PubKey(const uint8_t *pubkey, uint32_t len)
{
    if (len != SM9_SIG_SYS_PUBKEY_BYTES) {
        return CRYPT_SM9_ERR_KEY_ERR;
    }

    return SM9_Ecp2A_ValidateBytes(pubkey);
}

CRYPT_SM9_Ctx *CRYPT_SM9_NewCtx(void)
{
    return BSL_SAL_Calloc(1u, sizeof(CRYPT_SM9_Ctx));
}

CRYPT_SM9_Ctx *CRYPT_SM9_DupCtx(const CRYPT_SM9_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    CRYPT_SM9_Ctx *newCtx = CRYPT_SM9_NewCtx();
    if (newCtx == NULL) {
        return NULL;
    }

    /* Deep copy all fields */
    memcpy(newCtx, ctx, sizeof(SM9_Ctx));

    return newCtx;
}

void CRYPT_SM9_FreeCtx(CRYPT_SM9_Ctx *ctx)
{
    BSL_SAL_ClearFree(ctx, sizeof(CRYPT_SM9_Ctx));
}

int32_t CRYPT_SM9_Gen(CRYPT_SM9_Ctx *ctx)
{
    if (ctx == NULL) {
        return CRYPT_NULL_INPUT;
    }

    int32_t ret;
    uint8_t sigMsk[SM9_SIG_SYS_PRIKEY_BYTES];
    uint8_t encMsk[SM9_ENC_SYS_PRIKEY_BYTES];

    /* Generate random master private key for signature in [1, N-1] */
    ret = CRYPT_RandEx(NULL, sigMsk, SM9_SIG_SYS_PRIKEY_BYTES);
    if (ret != CRYPT_SUCCESS) {
        return CRYPT_SM9_ERR_KEY_ERR;
    }
    SM9_ModifyKeyRange(sigMsk);
    ret = SM9_SetSignMasterKey(ctx, sigMsk);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_CleanseData(sigMsk, SM9_SIG_SYS_PRIKEY_BYTES);
        return CRYPT_SM9_ERR_KEY_ERR;
    }

    /* Generate random master private key for encryption in [1, N-1] */
    ret = CRYPT_RandEx(NULL, encMsk, SM9_ENC_SYS_PRIKEY_BYTES);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_CleanseData(sigMsk, SM9_SIG_SYS_PRIKEY_BYTES);
        return CRYPT_SM9_ERR_KEY_ERR;
    }
    SM9_ModifyKeyRange(encMsk);
    ret = SM9_SetEncMasterKey(ctx, encMsk);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_CleanseData(sigMsk, SM9_SIG_SYS_PRIKEY_BYTES);
        BSL_SAL_CleanseData(encMsk, SM9_ENC_SYS_PRIKEY_BYTES);
        return CRYPT_SM9_ERR_KEY_ERR;
    }

    /* If user ID is set, generate user keys */
    if (ctx->userIdLen > 0) {
        ret = SM9_GenSignUserKey(ctx, ctx->userId, ctx->userIdLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_SAL_CleanseData(sigMsk, SM9_SIG_SYS_PRIKEY_BYTES);
            BSL_SAL_CleanseData(encMsk, SM9_ENC_SYS_PRIKEY_BYTES);
            return CRYPT_SM9_ERR_KEY_ERR;
        }

        ret = SM9_GenEncUserKey(ctx, ctx->userId, ctx->userIdLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_SAL_CleanseData(sigMsk, SM9_SIG_SYS_PRIKEY_BYTES);
            BSL_SAL_CleanseData(encMsk, SM9_ENC_SYS_PRIKEY_BYTES);
            return CRYPT_SM9_ERR_KEY_ERR;
        }
    }

    BSL_SAL_CleanseData(sigMsk, SM9_SIG_SYS_PRIKEY_BYTES);
    BSL_SAL_CleanseData(encMsk, SM9_ENC_SYS_PRIKEY_BYTES);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM9_SetPubKeyEx(CRYPT_SM9_Ctx *ctx, const BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        return CRYPT_NULL_INPUT;
    }

    const BSL_Param *p = NULL;
    const uint8_t *masterPrvKey = NULL; /* Master private key (msk) */
    uint32_t masterPrvKeyLen = 0;
    const uint8_t *masterPubKey = NULL; /* Master public key (mpk) */
    uint32_t masterPubKeyLen = 0;
    const uint8_t *userId = NULL; /* User ID (optional, for verification) */
    uint32_t userIdLen = 0;
    int32_t keyType = 0;
    int32_t ret;

    /* Get master private key */
    p = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_SM9_MASTER_KEY);
    if (p != NULL && p->value != NULL) {
        masterPrvKey = (const uint8_t *)p->value;
        masterPrvKeyLen = p->valueLen;
    }

    /* Get master public key (optional) */
    p = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_SM9_MASTER_PUB_KEY);
    if (p != NULL && p->value != NULL) {
        masterPubKey = (const uint8_t *)p->value;
        masterPubKeyLen = p->valueLen;
    }

    /* Get user ID (optional, for verification) */
    p = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_SM9_USER_ID);
    if (p != NULL && p->value != NULL) {
        userId = (const uint8_t *)p->value;
        userIdLen = p->valueLen;
    }

    /* Get key type */
    p = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_SM9_KEY_TYPE);
    if (p != NULL && p->value != NULL) {
        keyType = *(int32_t *)p->value;
    }

    /* Debug: Print parameters to stderr */

    /* Must have at least master private key or master public key */
    if (masterPrvKey == NULL && masterPubKey == NULL) {
        return CRYPT_NULL_INPUT;
    }

    /* If keyType is not set, return error to indicate missing key type */
    if (keyType == 0) {
        return CRYPT_SM9_ERR_NOT_SUPPORT;
    }

    /* Set master keys based on type */
    if (keyType == SM9_KEY_TYPE_SIGN) {
        const uint8_t *keyToCheck = masterPrvKey;

        /* Set master private key if provided */
        if (masterPrvKey != NULL) {
            if (masterPrvKeyLen != SM9_SIG_SYS_PRIKEY_BYTES) {
                return CRYPT_SM9_ERR_BAD_INPUT;
            }
            if (SM9_ValidateMasterPrivateKey(masterPrvKey) != CRYPT_SUCCESS) {
                return CRYPT_SM9_INVALID_PRVKEY;
            }
        } else if (ctx->hasSigMsk != 0) {
            keyToCheck = ctx->sigMsk;
        }

        /* Set master public key if provided, otherwise generate from private key */
        if (masterPubKey != NULL) {
            if (masterPubKeyLen != SM9_SIG_SYS_PUBKEY_BYTES) {
                return CRYPT_SM9_ERR_KEY_ERR;
            }
            /* Validate G2 point is on the curve */
            ret = SM9_ValidateG2PubKey(masterPubKey, masterPubKeyLen);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
            if (keyToCheck != NULL) {
                ret = SM9_ValidateMasterKeyPair(keyToCheck, masterPubKey, masterPubKeyLen, keyType);
                if (ret != CRYPT_SUCCESS) {
                    return ret;
                }
            }
            if (masterPrvKey != NULL) {
                memcpy(ctx->sigMsk, masterPrvKey, SM9_SIG_SYS_PRIKEY_BYTES);
                ctx->hasSigMsk = 1;
            }
            memcpy(ctx->sigMpk, masterPubKey, SM9_SIG_SYS_PUBKEY_BYTES);
        } else if (masterPrvKey != NULL) {
            /* Generate master public key from master private key */
            memcpy(ctx->sigMsk, masterPrvKey, SM9_SIG_SYS_PRIKEY_BYTES);
            ctx->hasSigMsk = 1;
            ret = SM9_Alg_MSKG(ctx->sigMsk, ctx->sigMpk);
            if (ret != CRYPT_SUCCESS) {
                return CRYPT_SM9_ERR_SIGN_FAILED;
            }
        }

        /* Generate sigG from master public key */
        ret = SM9_Alg_Pair(ctx->sigG, g_sm9G1, ctx->sigMpk);
        if (ret != CRYPT_SUCCESS) {
            return CRYPT_SM9_ERR_ENCRYPT_FAILED;
        }

        ctx->hasSigSys = 1;
        ctx->hasSigG = 1;

    } else if (keyType == SM9_KEY_TYPE_ENC) {
        const uint8_t *keyToCheck = masterPrvKey;

        /* Set master private key if provided */
        if (masterPrvKey != NULL) {
            if (masterPrvKeyLen != SM9_ENC_SYS_PRIKEY_BYTES) {
                return CRYPT_SM9_ERR_KEY_ERR;
            }
            if (SM9_ValidateMasterPrivateKey(masterPrvKey) != CRYPT_SUCCESS) {
                return CRYPT_SM9_INVALID_PRVKEY;
            }
        } else if (ctx->hasEncMsk != 0) {
            keyToCheck = ctx->encMsk;
        }

        /* Set master public key if provided, otherwise generate from private key */
        if (masterPubKey != NULL) {
            if (masterPubKeyLen != SM9_ENC_SYS_PUBKEY_BYTES) {
                return CRYPT_SM9_ERR_KEY_ERR;
            }
            /* Validate G1 point is on the curve */
            ret = SM9_ValidateG1PubKey(masterPubKey, masterPubKeyLen);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
            if (keyToCheck != NULL) {
                ret = SM9_ValidateMasterKeyPair(keyToCheck, masterPubKey, masterPubKeyLen, keyType);
                if (ret != CRYPT_SUCCESS) {
                    return ret;
                }
            }
            if (masterPrvKey != NULL) {
                memcpy(ctx->encMsk, masterPrvKey, SM9_ENC_SYS_PRIKEY_BYTES);
                ctx->hasEncMsk = 1;
            }
            memcpy(ctx->encMpk, masterPubKey, SM9_ENC_SYS_PUBKEY_BYTES);
        } else if (masterPrvKey != NULL) {
            /* Generate master public key from master private key */
            memcpy(ctx->encMsk, masterPrvKey, SM9_ENC_SYS_PRIKEY_BYTES);
            ctx->hasEncMsk = 1;
            ret = SM9_Alg_MEKG(ctx->encMsk, ctx->encMpk);
            if (ret != CRYPT_SUCCESS) {
                return CRYPT_SM9_ERR_KEY_ERR;
            }
        }

        /* Generate encG from master public key */
        ret = SM9_Alg_Pair(ctx->encG, ctx->encMpk, g_sm9G2);
        if (ret != CRYPT_SUCCESS) {
            return CRYPT_SM9_ERR_KEY_ERR;
        }

        ctx->hasEncSys = 1;
        ctx->hasEncG = 1;
    }

    /* If user ID is provided, save it for verification */
    if (userId != NULL && userIdLen > 0) {
        if (userIdLen > sizeof(ctx->userId)) {
            return CRYPT_SM9_ERR_KEY_ERR;
        }
        memcpy(ctx->userId, userId, userIdLen);
        ctx->userIdLen = userIdLen;
    }

    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM9_SetPrvKeyEx(CRYPT_SM9_Ctx *ctx, const BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        return CRYPT_NULL_INPUT;
    }

    const BSL_Param *p = NULL;
    const uint8_t *userId = NULL;
    uint32_t userIdLen = 0;
    int32_t keyType = 0;
    int32_t ret;

    /* Get user ID from parameter */
    p = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_SM9_USER_ID);
    if (p != NULL && p->value != NULL) {
        userId = (const uint8_t *)p->value;
        userIdLen = p->valueLen;
        /* Store user ID in context */
        if (userIdLen > sizeof(ctx->userId)) {
            return CRYPT_SM9_ERR_BAD_INPUT;
        }
        memcpy(ctx->userId, userId, userIdLen);
        ctx->userIdLen = userIdLen;
    } else if (ctx->userIdLen > 0) {
        /* Use user ID from context if not provided in parameter */
        userId = ctx->userId;
        userIdLen = ctx->userIdLen;
    }

    /* Get key type */
    p = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_SM9_KEY_TYPE);
    if (p != NULL && p->value != NULL) {
        keyType = *(int32_t *)p->value;
    }

    /* Require user ID */
    if (userId == NULL || userIdLen == 0) {
        return CRYPT_SM9_ERR_NO_USER_ID;
    }

    /* Generate user key from master keys in context based on type */
    if (keyType == SM9_KEY_TYPE_SIGN) {
        /* Check if master keys are set */
        if (ctx->hasSigSys == 0) {
            return CRYPT_SM9_ERR_NO_MASTER_KEY;
        }

        /* Generate signature user key from master key */
        /* Note: SM9_GenSignUserKey will also save userId to ctx, but we already saved it above */
        ret = SM9_GenSignUserKey(ctx, userId, userIdLen);
        if (ret != CRYPT_SUCCESS) {
            return CRYPT_SM9_ERR_KEY_ERR;
        }

    } else if (keyType == SM9_KEY_TYPE_ENC) {
        /* Check if master keys are set */
        if (ctx->hasEncSys == 0) {
            return CRYPT_SM9_ERR_NO_MASTER_KEY;
        }

        /* Generate encryption user key from master key */
        ret = SM9_GenEncUserKey(ctx, userId, userIdLen);
        if (ret != CRYPT_SUCCESS) {
            return CRYPT_SM9_ERR_KEY_ERR;
        }
    }

    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM9_GetPubKeyEx(const CRYPT_SM9_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        return CRYPT_NULL_INPUT;
    }

    BSL_Param *p = NULL;
    int32_t keyType = 0;

    /* Get key type to determine which master public key to return */
    p = BSL_PARAM_FindParam(param, CRYPT_PARAM_SM9_KEY_TYPE);
    if (p != NULL && p->value != NULL) {
        keyType = *(int32_t *)p->value;
    }

    /* Return master public key based on type */
    if (keyType == SM9_KEY_TYPE_SIGN) {
        if (ctx->hasSigSys == 0) {
            return CRYPT_SM9_ERR_NO_MASTER_KEY;
        }

        p = BSL_PARAM_FindParam(param, CRYPT_PARAM_SM9_MASTER_PUB_KEY);
        if (p != NULL) {
            if (p->value == NULL) {
                return CRYPT_NULL_INPUT;
            }
            if (p->valueLen < SM9_SIG_SYS_PUBKEY_BYTES) {
                return CRYPT_SM9_BUFF_LEN_NOT_ENOUGH;
            }
            memcpy(p->value, ctx->sigMpk, SM9_SIG_SYS_PUBKEY_BYTES);
            p->useLen = SM9_SIG_SYS_PUBKEY_BYTES;
        }

    } else if (keyType == SM9_KEY_TYPE_ENC) {
        if (ctx->hasEncSys == 0) {
            return CRYPT_SM9_ERR_NO_MASTER_KEY;
        }

        p = BSL_PARAM_FindParam(param, CRYPT_PARAM_SM9_MASTER_PUB_KEY);
        if (p != NULL) {
            if (p->value == NULL) {
                return CRYPT_NULL_INPUT;
            }
            if (p->valueLen < SM9_ENC_SYS_PUBKEY_BYTES) {
                return CRYPT_SM9_BUFF_LEN_NOT_ENOUGH;
            }
            memcpy(p->value, ctx->encMpk, SM9_ENC_SYS_PUBKEY_BYTES);
            p->useLen = SM9_ENC_SYS_PUBKEY_BYTES;
        }
    }

    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM9_GetPrvKeyEx(const CRYPT_SM9_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        return CRYPT_NULL_INPUT;
    }

    BSL_Param *p = NULL;
    int32_t keyType = 0;

    /* Get key type to determine which user private key to return */
    p = BSL_PARAM_FindParam(param, CRYPT_PARAM_SM9_KEY_TYPE);
    if (p != NULL && p->value != NULL) {
        keyType = *(int32_t *)p->value;
    }

    /* Return user private key based on type */
    if (keyType == SM9_KEY_TYPE_SIGN) {
        if (ctx->hasSigUsr == 0) {
            return CRYPT_SM9_ERR_NO_USER_KEY;
        }

        p = BSL_PARAM_FindParam(param, CRYPT_PARAM_SM9_USER_KEY);
        if (p != NULL) {
            if (p->value == NULL) {
                return CRYPT_NULL_INPUT;
            }
            if (p->valueLen < SM9_SIG_USR_PRIKEY_BYTES) {
                return CRYPT_SM9_BUFF_LEN_NOT_ENOUGH;
            }
            memcpy(p->value, ctx->sigDsk, SM9_SIG_USR_PRIKEY_BYTES);
            p->useLen = SM9_SIG_USR_PRIKEY_BYTES;
        }

    } else if (keyType == SM9_KEY_TYPE_ENC) {
        if (ctx->hasEncUsr == 0) {
            return CRYPT_SM9_ERR_NO_USER_KEY;
        }

        p = BSL_PARAM_FindParam(param, CRYPT_PARAM_SM9_USER_KEY);
        if (p != NULL) {
            if (p->value == NULL) {
                return CRYPT_NULL_INPUT;
            }
            if (p->valueLen < SM9_ENC_USR_PRIKEY_BYTES) {
                return CRYPT_SM9_BUFF_LEN_NOT_ENOUGH;
            }
            memcpy(p->value, ctx->encDek, SM9_ENC_USR_PRIKEY_BYTES);
            p->useLen = SM9_ENC_USR_PRIKEY_BYTES;
        }
    }

    /* Also return user ID if available */
    if (ctx->userIdLen > 0) {
        p = BSL_PARAM_FindParam(param, CRYPT_PARAM_SM9_USER_ID);
        if (p != NULL) {
            if (p->value != NULL && p->valueLen >= ctx->userIdLen) {
                memcpy(p->value, ctx->userId, ctx->userIdLen);
                p->useLen = ctx->userIdLen;
            }
        }
    }

    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM9_Ctrl(CRYPT_SM9_Ctx *ctx, int32_t cmd, void *val, uint32_t valLen)
{
    if (ctx == NULL) {
        return CRYPT_NULL_INPUT;
    }

    switch (cmd) {
        case CRYPT_CTRL_SET_SM9_USER_ID:
            if (val == NULL || valLen == 0 || valLen > sizeof(ctx->userId)) {
                return CRYPT_SM9_ERR_BAD_INPUT;
            }
            memcpy(ctx->userId, val, valLen);
            ctx->userIdLen = valLen;
            return CRYPT_SUCCESS;
        default:
            return CRYPT_SM9_ERR_NOT_SUPPORT;
    }
}

int32_t CRYPT_SM9_Check(int32_t checkType, const CRYPT_SM9_Ctx *ctx1, const CRYPT_SM9_Ctx *ctx2)
{
    if (ctx1 == NULL) {
        return CRYPT_NULL_INPUT;
    }

    /* Check if required keys are present based on type */
    switch (checkType) {
        case CRYPT_PKEY_CHECK_KEYPAIR:
            /* Check if ctx1 and ctx2 form a valid key pair */
            if (ctx2 == NULL) {
                return CRYPT_NULL_INPUT;
            }

            /* Check signature key pair: ctx1 has master public key, ctx2 has user private key */
            if (ctx1->hasSigSys != 0 && ctx2->hasSigUsr != 0) {
                return SM9_CheckSignKeyPair(ctx1, ctx2);
            }

            /* Check encryption key pair */
            if (ctx1->hasEncSys != 0 && ctx2->hasEncUsr != 0) {
                return SM9_CheckEncKeyPair(ctx1, ctx2);
            }

            /* No valid key pair found */
            return CRYPT_SM9_PAIRWISE_CHECK_FAIL;

        case CRYPT_PKEY_CHECK_PRVKEY:
            /* Check if we have any user private key (signature or encryption) */
            if (ctx1->hasSigUsr != 0 || ctx1->hasEncUsr != 0) {
                return CRYPT_SUCCESS;
            }
            return CRYPT_SM9_INVALID_PRVKEY;

        default:
            return CRYPT_SM9_ERR_NOT_SUPPORT;
    }
}

int32_t CRYPT_SM9_Cmp(const CRYPT_SM9_Ctx *ctx1, const CRYPT_SM9_Ctx *ctx2)
{
    if (ctx1 == NULL || ctx2 == NULL) {
        return CRYPT_NULL_INPUT;
    }

    /* Compare relevant fields */
    if (ConstTimeMemcmp((const uint8_t *)ctx1, (const uint8_t *)ctx2, sizeof(SM9_Ctx)) != 0) {
        return CRYPT_SUCCESS;
    }

    return CRYPT_SM9_ERR_KEY_NOT_EQUAL;
}

#endif // HITLS_CRYPTO_SM9
