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

#include <stdio.h>
#include "crypt_sm9_eal.h"
#include "crypt_sm9.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "crypt_params_key.h"
#include "bsl_sal.h"
#include "securec.h"

/* Key type constants */
#define SM9_KEY_TYPE_SIGN  1
#define SM9_KEY_TYPE_ENC   2

CRYPT_SM9_Ctx *CRYPT_SM9_NewCtx(void)
{
    return SM9_NewCtx();
}

CRYPT_SM9_Ctx *CRYPT_SM9_DupCtx(const CRYPT_SM9_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    CRYPT_SM9_Ctx *newCtx = SM9_NewCtx();
    if (newCtx == NULL) {
        return NULL;
    }

    /* Deep copy all fields */
    (void)memcpy_s(newCtx, sizeof(SM9_Ctx), ctx, sizeof(SM9_Ctx));

    return newCtx;
}

void CRYPT_SM9_FreeCtx(CRYPT_SM9_Ctx *ctx)
{
    if (ctx != NULL) {
        SM9_FreeCtx(ctx);
    }
}

int32_t CRYPT_SM9_Gen(CRYPT_SM9_Ctx *ctx)
{
    if (ctx == NULL) {
        return CRYPT_NULL_INPUT;
    }

    int ret;
    unsigned char sig_msk[SM9_SIG_SYS_PRIKEY_BYTES];
    unsigned char enc_msk[SM9_ENC_SYS_PRIKEY_BYTES];

    /* Generate random master private key for signature */
    sm9_rand(sig_msk, SM9_SIG_SYS_PRIKEY_BYTES);
    ret = SM9_SetSignMasterKey(ctx, sig_msk);
    if (ret != SM9_OK) {
        return CRYPT_SM9_ERR_KEY_ERR;
    }

    /* Generate random master private key for encryption */
    sm9_rand(enc_msk, SM9_ENC_SYS_PRIKEY_BYTES);
    ret = SM9_SetEncMasterKey(ctx, enc_msk);
    if (ret != SM9_OK) {
        return CRYPT_SM9_ERR_KEY_ERR;
    }

    /* If user ID is set, generate user keys */
    if (ctx->user_id_len > 0) {
        ret = SM9_GenSignUserKey(ctx, ctx->user_id, ctx->user_id_len);
        if (ret != SM9_OK) {
            return CRYPT_SM9_ERR_KEY_ERR;
        }

        ret = SM9_GenEncUserKey(ctx, ctx->user_id, ctx->user_id_len);
        if (ret != SM9_OK) {
            return CRYPT_SM9_ERR_KEY_ERR;
        }
    }

    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM9_SetPubKeyEx(CRYPT_SM9_Ctx *ctx, const BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        return CRYPT_NULL_INPUT;
    }

    const BSL_Param *p = NULL;
    const uint8_t *masterPrvKey = NULL;  /* Master private key (msk) */
    uint32_t masterPrvKeyLen = 0;
    const uint8_t *masterPubKey = NULL;  /* Master public key (mpk) */
    uint32_t masterPubKeyLen = 0;
    const uint8_t *userId = NULL;        /* User ID (optional, for verification) */
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
        /* Set master private key if provided */
        if (masterPrvKey != NULL) {
            if (masterPrvKeyLen != SM9_SIG_SYS_PRIKEY_BYTES) {
                return CRYPT_SM9_ERR_BAD_INPUT;
            }
            memcpy(ctx->sig_msk, masterPrvKey, SM9_SIG_SYS_PRIKEY_BYTES);
        }

        /* Set master public key if provided, otherwise generate from private key */
        if (masterPubKey != NULL) {
            if (masterPubKeyLen != SM9_SIG_SYS_PUBKEY_BYTES) {
                return CRYPT_SM9_ERR_KEY_ERR;
            }
            memcpy(ctx->sig_mpk, masterPubKey, SM9_SIG_SYS_PUBKEY_BYTES);
        } else if (masterPrvKey != NULL) {
            /* Generate master public key from master private key */
            ret = SM9_Alg_MSKG(ctx->sig_msk, ctx->sig_mpk);
            if (ret != SM9_OK) {
                return CRYPT_SM9_ERR_SIGN_FAILED;
            }
        }

        /* Generate sig_g from master public key */
        ret = SM9_Get_Sig_G(ctx->sig_g, ctx->sig_mpk);
        if (ret != SM9_OK) {
            return CRYPT_SM9_ERR_ENCRYPT_FAILED;
        }

        ctx->has_sig_sys = 1;
        ctx->has_sig_g = 1;

    } else if (keyType == SM9_KEY_TYPE_ENC) {
        /* Set master private key if provided */
        if (masterPrvKey != NULL) {
            if (masterPrvKeyLen != SM9_ENC_SYS_PRIKEY_BYTES) {
                return CRYPT_SM9_ERR_KEY_ERR;
            }
            memcpy(ctx->enc_msk, masterPrvKey, SM9_ENC_SYS_PRIKEY_BYTES);
        }

        /* Set master public key if provided, otherwise generate from private key */
        if (masterPubKey != NULL) {
            if (masterPubKeyLen != SM9_ENC_SYS_PUBKEY_BYTES) {
                return CRYPT_SM9_ERR_KEY_ERR;
            }
            memcpy(ctx->enc_mpk, masterPubKey, SM9_ENC_SYS_PUBKEY_BYTES);
        } else if (masterPrvKey != NULL) {
            /* Generate master public key from master private key */
            ret = SM9_Alg_MEKG(ctx->enc_msk, ctx->enc_mpk);
            if (ret != SM9_OK) {
                return CRYPT_SM9_ERR_KEY_ERR;
            }
        }

        /* Generate enc_g from master public key */
        ret = SM9_Get_Enc_G(ctx->enc_g, ctx->enc_mpk);
        if (ret != SM9_OK) {
            return CRYPT_SM9_ERR_KEY_ERR;
        }

        ctx->has_enc_sys = 1;
        ctx->has_enc_g = 1;
    }

    /* If user ID is provided, save it for verification */
    if (userId != NULL && userIdLen > 0) {
        if (userIdLen > sizeof(ctx->user_id)) {
            return CRYPT_SM9_ERR_KEY_ERR;
        }
        memcpy(ctx->user_id, userId, userIdLen);
        ctx->user_id_len = userIdLen;
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
        if (userIdLen <= sizeof(ctx->user_id)) {
            memcpy(ctx->user_id, userId, userIdLen);
            ctx->user_id_len = userIdLen;
        }
    } else if (ctx->user_id_len > 0) {
        /* Use user ID from context if not provided in parameter */
        userId = ctx->user_id;
        userIdLen = ctx->user_id_len;
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
        if (!ctx->has_sig_sys) {
            return CRYPT_SM9_ERR_NO_MASTER_KEY;
        }

        /* Generate signature user key from master key */
        /* Note: SM9_GenSignUserKey will also save user_id to ctx, but we already saved it above */
        ret = SM9_GenSignUserKey(ctx, userId, userIdLen);
        if (ret != SM9_OK) {
            return CRYPT_SM9_ERR_KEY_ERR;
        }

    } else if (keyType == SM9_KEY_TYPE_ENC) {
        /* Check if master keys are set */
        if (!ctx->has_enc_sys) {
            return CRYPT_SM9_ERR_NO_MASTER_KEY;
        }

        /* Generate encryption user key from master key */
        ret = SM9_GenEncUserKey(ctx, userId, userIdLen);
        if (ret != SM9_OK) {
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
        if (!ctx->has_sig_sys) {
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
            memcpy(p->value, ctx->sig_mpk, SM9_SIG_SYS_PUBKEY_BYTES);
            p->useLen = SM9_SIG_SYS_PUBKEY_BYTES;
        }

    } else if (keyType == SM9_KEY_TYPE_ENC) {
        if (!ctx->has_enc_sys) {
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
            memcpy(p->value, ctx->enc_mpk, SM9_ENC_SYS_PUBKEY_BYTES);
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
        if (!ctx->has_sig_usr) {
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
            memcpy(p->value, ctx->sig_dsk, SM9_SIG_USR_PRIKEY_BYTES);
            p->useLen = SM9_SIG_USR_PRIKEY_BYTES;
        }

    } else if (keyType == SM9_KEY_TYPE_ENC) {
        if (!ctx->has_enc_usr) {
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
            memcpy(p->value, ctx->enc_dek, SM9_ENC_USR_PRIKEY_BYTES);
            p->useLen = SM9_ENC_USR_PRIKEY_BYTES;
        }
    }

    /* Also return user ID if available */
    if (ctx->user_id_len > 0) {
        p = BSL_PARAM_FindParam(param, CRYPT_PARAM_SM9_USER_ID);
        if (p != NULL) {
            if (p->value != NULL && p->valueLen >= ctx->user_id_len) {
                memcpy(p->value, ctx->user_id, ctx->user_id_len);
                p->useLen = ctx->user_id_len;
            }
        }
    }

    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM9_Sign(const CRYPT_SM9_Ctx *ctx, int32_t mdId,
                       const uint8_t *data, uint32_t dataLen,
                       uint8_t *sign, uint32_t *signLen)
{
    if (ctx == NULL || data == NULL || sign == NULL || signLen == NULL) {
        return CRYPT_NULL_INPUT;
    }

    /* SM9 signature always uses SM3, mdId is ignored for compatibility */
    (void)mdId;

    int ret = SM9_SignCtx(ctx, data, dataLen, NULL, sign);
    if (ret != SM9_OK) {
        return CRYPT_SM9_ERR_SIGN_FAILED;
    }

    /* SM9 signature length is fixed */
    *signLen = SM9_SIGNATURE_BYTES;

    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM9_Verify(const CRYPT_SM9_Ctx *ctx, int32_t mdId,
                         const uint8_t *data, uint32_t dataLen,
                         const uint8_t *sign, uint32_t signLen)
{
    if (ctx == NULL || data == NULL || sign == NULL) {
        return CRYPT_NULL_INPUT;
    }

    /* SM9 signature always uses SM3, mdId is ignored */
    (void)mdId;

    if (signLen != SM9_SIGNATURE_BYTES) {
        return CRYPT_SM9_ERR_INVALID_SIGNATURE_LEN;
    }

    /* SM9 verify needs user ID - must be stored in context */
    if (ctx->user_id_len == 0) {
        return CRYPT_SM9_ERR_NO_USER_ID;
    }

    int ret = SM9_VerifyCtx(ctx, ctx->user_id, ctx->user_id_len,
                            data, dataLen, sign);
    if (ret != SM9_OK) {
        return CRYPT_SM9_VERIFY_FAIL;
    }

    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM9_Encrypt(const CRYPT_SM9_Ctx *ctx,
                          const uint8_t *data, uint32_t dataLen,
                          uint8_t *out, uint32_t *outLen)
{
    if (ctx == NULL || data == NULL || out == NULL || outLen == NULL) {
        return CRYPT_NULL_INPUT;
    }

    /* SM9 encryption needs user ID - must be stored in context */
    if (ctx->user_id_len == 0) {
        return CRYPT_SM9_ERR_NO_USER_ID;
    }

    unsigned int cipherLen = *outLen;
    int ret = SM9_EncryptCtx(ctx, ctx->user_id, ctx->user_id_len,
                             data, dataLen, NULL, out, &cipherLen);
    if (ret != SM9_OK) {
        return CRYPT_SM9_ERR_ENCRYPT_FAILED;
    }

    *outLen = cipherLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM9_Decrypt(const CRYPT_SM9_Ctx *ctx,
                          const uint8_t *data, uint32_t dataLen,
                          uint8_t *out, uint32_t *outLen)
{
    if (ctx == NULL || data == NULL || out == NULL || outLen == NULL) {
        return CRYPT_NULL_INPUT;
    }

    unsigned int plainLen = *outLen;
    int ret = SM9_DecryptCtx(ctx, data, dataLen, out, &plainLen);
    if (ret != SM9_OK) {
        return CRYPT_SM9_ERR_DECRYPT_FAILED;
    }

    *outLen = plainLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM9_ComputeShareKey(const CRYPT_SM9_Ctx *selfCtx, const CRYPT_SM9_Ctx *peerCtx,
                                   uint8_t *out, uint32_t *outLen)
{
    if (selfCtx == NULL || peerCtx == NULL || out == NULL || outLen == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (*outLen == 0) {
        return CRYPT_SM9_ERR_BAD_INPUT;
    }

    /* Check if both contexts have required keys for key exchange (encryption keys) */
    if (!selfCtx->has_enc_usr || !selfCtx->has_enc_sys) {
        return CRYPT_SM9_ERR_NO_USER_KEY;
    }

    if (!peerCtx->has_enc_sys) {
        return CRYPT_SM9_ERR_NO_MASTER_KEY;
    }

    /* Check if both contexts have user IDs */
    if (selfCtx->user_id_len == 0 || peerCtx->user_id_len == 0) {
        return CRYPT_SM9_ERR_NO_USER_ID;
    }

    /* Determine initiator/responder roles by comparing user IDs (lexicographic order) */
    int cmp = memcmp(selfCtx->user_id, peerCtx->user_id,
                     selfCtx->user_id_len < peerCtx->user_id_len ? selfCtx->user_id_len : peerCtx->user_id_len);
    if (cmp == 0 && selfCtx->user_id_len != peerCtx->user_id_len) {
        cmp = (selfCtx->user_id_len < peerCtx->user_id_len) ? -1 : 1;
    }

    int is_initiator = (cmp < 0) ? 1 : 0;  /* Self is initiator if self_id < peer_id */

    /* Create temporary contexts for the key exchange process */
    SM9_Ctx *tmpSelfCtx = (SM9_Ctx *)CRYPT_SM9_DupCtx(selfCtx);
    SM9_Ctx *tmpPeerCtx = (SM9_Ctx *)CRYPT_SM9_DupCtx(peerCtx);
    if (tmpSelfCtx == NULL || tmpPeerCtx == NULL) {
        SM9_FreeCtx(tmpSelfCtx);
        SM9_FreeCtx(tmpPeerCtx);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    int ret;
    unsigned char RA[SM9_KEYEX_RA_BYTES];
    unsigned char RB[SM9_KEYEX_RB_BYTES];
    unsigned char SA[SM9_KEYEX_RA_BYTES];
    unsigned char SB[SM9_KEYEX_RB_BYTES];

    /* Generate deterministic random seeds based on user IDs to ensure consistent key exchange */
    unsigned char seed_buffer[512]; /* Buffer to hold both user IDs */
    unsigned int seed_len = 0;
    unsigned char hash[32];
    unsigned char rand_A[SM9_CURVE_MODULE_BYTES];
    unsigned char rand_B[SM9_CURVE_MODULE_BYTES];

    /* Create seed for initiator: H(initiator_id || responder_id || "A") */
    if (is_initiator) {
        memcpy(seed_buffer + seed_len, selfCtx->user_id, selfCtx->user_id_len);
        seed_len += selfCtx->user_id_len;
        memcpy(seed_buffer + seed_len, peerCtx->user_id, peerCtx->user_id_len);
        seed_len += peerCtx->user_id_len;
    } else {
        memcpy(seed_buffer + seed_len, peerCtx->user_id, peerCtx->user_id_len);
        seed_len += peerCtx->user_id_len;
        memcpy(seed_buffer + seed_len, selfCtx->user_id, selfCtx->user_id_len);
        seed_len += selfCtx->user_id_len;
    }
    seed_buffer[seed_len++] = 'A';
    SM9_Hash_Data(seed_buffer, seed_len, hash);
    memcpy(rand_A, hash, SM9_CURVE_MODULE_BYTES);

    /* Create seed for responder: H(initiator_id || responder_id || "B") */
    seed_buffer[seed_len - 1] = 'B'; /* Replace 'A' with 'B' */
    SM9_Hash_Data(seed_buffer, seed_len, hash);
    memcpy(rand_B, hash, SM9_CURVE_MODULE_BYTES);

    /* Step 1: Initiator generates R_initiator with deterministic rand */
    ret = SM9_KeyExchangeInit(tmpSelfCtx, tmpPeerCtx->user_id, tmpPeerCtx->user_id_len,
                              is_initiator, is_initiator ? rand_A : rand_B, is_initiator ? RA : RB);
    if (ret != SM9_OK) {
        SM9_FreeCtx(tmpSelfCtx);
        SM9_FreeCtx(tmpPeerCtx);
        return CRYPT_SM9_ERR_KEY_EXCHANGE_FAILED;
    }

    /* Step 2: Responder generates R_responder with deterministic rand */
    ret = SM9_KeyExchangeInit(tmpPeerCtx, tmpSelfCtx->user_id, tmpSelfCtx->user_id_len,
                              !is_initiator, is_initiator ? rand_B : rand_A, is_initiator ? RB : RA);
    if (ret != SM9_OK) {
        SM9_FreeCtx(tmpSelfCtx);
        SM9_FreeCtx(tmpPeerCtx);
        return CRYPT_SM9_ERR_KEY_EXCHANGE_FAILED;
    }

    /* Step 3: Self computes shared key and S_self */
    ret = SM9_KeyExchangeConfirm(tmpSelfCtx, tmpPeerCtx->user_id, tmpPeerCtx->user_id_len,
                                 is_initiator, is_initiator ? RB : RA, *outLen, out,
                                 is_initiator ? SA : SB);
    if (ret != SM9_OK) {
        SM9_FreeCtx(tmpSelfCtx);
        SM9_FreeCtx(tmpPeerCtx);
        return CRYPT_SM9_ERR_KEY_EXCHANGE_FAILED;
    }

    /* Step 4: Peer computes shared key and S_peer (for verification) */
    unsigned char tmpKey[256];
    unsigned int tmpKeyLen = sizeof(tmpKey);
    ret = SM9_KeyExchangeConfirm(tmpPeerCtx, tmpSelfCtx->user_id, tmpSelfCtx->user_id_len,
                                 !is_initiator, is_initiator ? RA : RB, tmpKeyLen, tmpKey,
                                 is_initiator ? SB : SA);
    if (ret != SM9_OK) {
        SM9_FreeCtx(tmpSelfCtx);
        SM9_FreeCtx(tmpPeerCtx);
        return CRYPT_SM9_ERR_KEY_EXCHANGE_FAILED;
    }

    /* Step 5: Peer verifies S_self */
    ret = SM9_KeyExchangeVerify(tmpPeerCtx, tmpSelfCtx->user_id, tmpSelfCtx->user_id_len,
                                !is_initiator, is_initiator ? RA : RB, is_initiator ? SA : SB);
    if (ret != SM9_OK) {
        SM9_FreeCtx(tmpSelfCtx);
        SM9_FreeCtx(tmpPeerCtx);
        return CRYPT_SM9_ERR_KEY_EXCHANGE_FAILED;
    }

    /* Step 6: Self verifies S_peer */
    ret = SM9_KeyExchangeVerify(tmpSelfCtx, tmpPeerCtx->user_id, tmpPeerCtx->user_id_len,
                                is_initiator, is_initiator ? RB : RA, is_initiator ? SB : SA);
    if (ret != SM9_OK) {
        SM9_FreeCtx(tmpSelfCtx);
        SM9_FreeCtx(tmpPeerCtx);
        return CRYPT_SM9_ERR_KEY_EXCHANGE_FAILED;
    }

    SM9_FreeCtx(tmpSelfCtx);
    SM9_FreeCtx(tmpPeerCtx);

    return CRYPT_SUCCESS;
}

int32_t CRYPT_SM9_Ctrl(CRYPT_SM9_Ctx *ctx, int32_t cmd, void *val, uint32_t valLen)
{
    if (ctx == NULL) {
        return CRYPT_NULL_INPUT;
    }

    switch (cmd) {
        case CRYPT_CTRL_SET_SM2_USER_ID:  /* Reuse SM2's user ID control for SM9 */
            if (val == NULL || valLen == 0 || valLen > sizeof(ctx->user_id)) {
                return CRYPT_SM9_ERR_BAD_INPUT;
            }
            memcpy(ctx->user_id, val, valLen);
            ctx->user_id_len = valLen;
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
            if (ctx1->has_sig_sys && ctx2->has_sig_usr) {
                if (ctx1->user_id_len > 0 && ctx2->user_id_len > 0) {
                    /* User IDs should match */
                    if (ctx1->user_id_len != ctx2->user_id_len ||
                        memcmp(ctx1->user_id, ctx2->user_id, ctx1->user_id_len) != 0) {
                        return CRYPT_SM9_PAIRWISE_CHECK_FAIL;
                    }
                }
                return CRYPT_SUCCESS;
            }

            /* Check encryption key pair */
            if (ctx1->has_enc_sys && ctx2->has_enc_usr) {
                if (ctx1->user_id_len > 0 && ctx2->user_id_len > 0) {
                    if (ctx1->user_id_len != ctx2->user_id_len ||
                        memcmp(ctx1->user_id, ctx2->user_id, ctx1->user_id_len) != 0) {
                        return CRYPT_SM9_PAIRWISE_CHECK_FAIL;
                    }
                }
                return CRYPT_SUCCESS;
            }

            /* No valid key pair found */
            return CRYPT_SM9_PAIRWISE_CHECK_FAIL;

        case CRYPT_PKEY_CHECK_PRVKEY:
            /* Check if we have any user private key (signature or encryption) */
            if (ctx1->has_sig_usr || ctx1->has_enc_usr) {
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
    if (memcmp(ctx1, ctx2, sizeof(SM9_Ctx)) == 0) {
        return CRYPT_SUCCESS;
    }

    return CRYPT_SM9_ERR_KEY_NOT_EQUAL;
}

#endif // HITLS_CRYPTO_SM9
