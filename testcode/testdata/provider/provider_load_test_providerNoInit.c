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

// Source code for the test .so file

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "crypt_errno.h"
#include "crypt_eal_provider.h"
#include "crypt_eal_implprovider.h"

#define CRYPT_EAL_DEFAULT_ATTR "provider=test1,compare1=one,cpmpare3=three"
#define RESULT 1415926

void *Provider_NewCtx(void *provCtx, int32_t algid, BSL_Param *param)
{
    (void)provCtx;
    (void)param;
    int *ctx = malloc(sizeof(int));
    return ctx;
}

int32_t Provider_FreeCtx(void *ctx)
{
    free(ctx);
    return 0;
}

int32_t MD5_Init(void *mdCtx)
{
    mdCtx = NULL;
    return RESULT;
}

const CRYPT_EAL_Func defMdMd5[] = {
    {CRYPT_EAL_IMPLMD_NEWCTX, NULL},
    {CRYPT_EAL_IMPLMD_INITCTX, MD5_Init},
    {CRYPT_EAL_IMPLMD_UPDATE, NULL},
    {CRYPT_EAL_IMPLMD_FINAL, NULL},
    {CRYPT_EAL_IMPLMD_DEINITCTX, NULL},
    {CRYPT_EAL_IMPLMD_DUPCTX, NULL},
    {CRYPT_EAL_IMPLMD_CTRL, NULL},
    {CRYPT_EAL_IMPLMD_FREECTX, NULL},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func defKdfScrypt[] = {
    {CRYPT_EAL_IMPLKDF_NEWCTX, NULL},
    {CRYPT_EAL_IMPLKDF_SETPARAM, NULL},
    {CRYPT_EAL_IMPLKDF_DERIVE, NULL},
    {CRYPT_EAL_IMPLKDF_DEINITCTX, NULL},
    {CRYPT_EAL_IMPLKDF_CTRL, NULL},
    {CRYPT_EAL_IMPLKDF_FREECTX, NULL},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func defMacHmac[] = {
    {CRYPT_EAL_IMPLMAC_NEWCTX, NULL},
    {CRYPT_EAL_IMPLMAC_INIT, NULL},
    {CRYPT_EAL_IMPLMAC_UPDATE, NULL},
    {CRYPT_EAL_IMPLMAC_FINAL, NULL},
    {CRYPT_EAL_IMPLMAC_REINITCTX, NULL},
    {CRYPT_EAL_IMPLMAC_CTRL, NULL},
    {CRYPT_EAL_IMPLMAC_FREECTX, NULL},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func defKeyMgmtDsa[] = {
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, NULL},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPARAM, NULL},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPARAM, NULL},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, NULL},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, NULL},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, NULL},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, NULL},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, NULL},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, NULL},
    {CRYPT_EAL_IMPLPKEYMGMT_CHECK, NULL},
    {CRYPT_EAL_IMPLPKEYMGMT_COMPARE, NULL},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, NULL},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, NULL},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func defAsymCipherRsa[] = {
    {CRYPT_EAL_IMPLPKEYCIPHER_ENCRYPT, NULL},
    {CRYPT_EAL_IMPLPKEYCIPHER_DECRYPT, NULL},
    CRYPT_EAL_FUNC_END
};

const CRYPT_EAL_Func defExchX25519[] = {
    {CRYPT_EAL_IMPLPKEYEXCH_EXCH, NULL},
    CRYPT_EAL_FUNC_END
};

const CRYPT_EAL_Func defSignDsa[] = {
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, NULL},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, NULL},
    CRYPT_EAL_FUNC_END,
};
static const CRYPT_EAL_AlgInfo defMds[] = {
    {CRYPT_MD_MD5, defMdMd5, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo defKdfs[] = {
    {CRYPT_KDF_SCRYPT, defKdfScrypt, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo defKeyMgmt[] = {
    {CRYPT_PKEY_DSA, defKeyMgmtDsa, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo defAsymCiphers[] = {
    {CRYPT_PKEY_RSA, defAsymCipherRsa, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo defKeyExch[] = {
    {CRYPT_PKEY_X25519, defExchX25519, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo defSigns[] = {
    {CRYPT_PKEY_DSA, defSignDsa, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo defMacs[] = {
    {CRYPT_MAC_HMAC_MD5, defMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static int32_t CRYPT_EAL_DefaultProvQuery(void *provCtx, int32_t operaId, const CRYPT_EAL_AlgInfo **algInfos)
{
    (void) provCtx;
    int32_t ret = CRYPT_SUCCESS;
    switch (operaId) {
        case CRYPT_EAL_OPERAID_SYMMCIPHER:
            break;
        case CRYPT_EAL_OPERAID_KEYMGMT:
            *algInfos = defKeyMgmt;
            break;
        case CRYPT_EAL_OPERAID_SIGN:
            *algInfos = defSigns;
            break;
        case CRYPT_EAL_OPERAID_ASYMCIPHER:
            *algInfos = defAsymCiphers;
            break;
        case CRYPT_EAL_OPERAID_KEYEXCH:
            *algInfos = defKeyExch;
            break;
        case CRYPT_EAL_OPERAID_KEM:
            break;
        case CRYPT_EAL_OPERAID_HASH:
            *algInfos = defMds;
            break;
        case CRYPT_EAL_OPERAID_MAC:
            *algInfos = defMacs;
            break;
        case CRYPT_EAL_OPERAID_KDF:
            *algInfos = defKdfs;
            break;
        case CRYPT_EAL_OPERAID_RAND:
            break;
        default:
            ret = CRYPT_NOT_SUPPORT;
            break;
    }
    return ret;
}
static void CRYPT_EAL_DefaultProvFree(void *provCtx)
{
    return;
}

static CRYPT_EAL_Func defProvOutFuncs[] = {
    {CRYPT_EAL_PROVCB_QUERY, CRYPT_EAL_DefaultProvQuery},
    {CRYPT_EAL_PROVCB_FREE, CRYPT_EAL_DefaultProvFree},
    {CRYPT_EAL_PROVCB_CTRL, NULL},
    CRYPT_EAL_FUNC_END
};

int32_t CRYPT_EAL_ProviderInit(CRYPT_EAL_ProvMgrCtx *mgrCtx,
    BSL_Param *param, CRYPT_EAL_Func *capFuncs, CRYPT_EAL_Func **outFuncs, void **provCtx)
{
    *outFuncs = defProvOutFuncs;
    return 0;
}
