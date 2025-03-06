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

#include "crypt_eal_provider.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "crypt_errno.h"
#include "crypt_eal_implprovider.h"

#define TEST_GROUP "test_group"
#define TEST_GROUP_VALUE "test_group_value"

typedef struct {
    CRYPT_EAL_ProvMgrCtx *mgrCtxHandle;
} TestProvCtx;

void *CRYPT_EAL_PkeyMgmtEcNewCtx(void *provCtx, int32_t algId)
{
    (void)provCtx;
    void *pkeyCtx = NULL;
    switch (algId) {
        case CRYPT_PKEY_ECDSA:
            pkeyCtx = CRYPT_ECDSA_NewCtx();
            break;
        case CRYPT_PKEY_ECDH:
            pkeyCtx = CRYPT_ECDH_NewCtx();
            break;
        default:
            return NULL;
    }
    if (pkeyCtx == NULL) {
        return NULL;
    }
    return pkeyCtx;
}
const CRYPT_EAL_Func g_defKeyMgmtEcdsa[] = {
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (CRYPT_EAL_ImplPkeyMgmtNewCtx)CRYPT_EAL_PkeyMgmtEcNewCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPARAM, (CRYPT_EAL_ImplPkeyMgmtSetParam)CRYPT_ECDSA_SetPara},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPARAM, (CRYPT_EAL_ImplPkeyMgmtGetParam)CRYPT_ECDSA_GetPara},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, (CRYPT_EAL_ImplPkeyMgmtGenKey)CRYPT_ECDSA_Gen},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, (CRYPT_EAL_ImplPkeyMgmtSetPrv)CRYPT_ECDSA_SetPrvKey},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, (CRYPT_EAL_ImplPkeyMgmtSetPub)CRYPT_ECDSA_SetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, (CRYPT_EAL_ImplPkeyMgmtGetPrv)CRYPT_ECDSA_GetPrvKey},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, (CRYPT_EAL_ImplPkeyMgmtGetPub)CRYPT_ECDSA_GetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, (CRYPT_EAL_ImplPkeyMgmtDupCtx)CRYPT_ECDSA_DupCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_COMPARE, (CRYPT_EAL_ImplPkeyMgmtCompare)CRYPT_ECDSA_Cmp},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, (CRYPT_EAL_ImplPkeyMgmtCtrl)CRYPT_ECDSA_Ctrl},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, (CRYPT_EAL_ImplPkeyMgmtFreeCtx)CRYPT_ECDSA_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defKeyMgmtEcdh[] = {
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (CRYPT_EAL_ImplPkeyMgmtNewCtx)CRYPT_EAL_DefPkeyMgmtNewCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPARAM, (CRYPT_EAL_ImplPkeyMgmtSetParam)CRYPT_ECDH_SetPara},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPARAM, (CRYPT_EAL_ImplPkeyMgmtGetParam)CRYPT_ECDH_GetPara},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, (CRYPT_EAL_ImplPkeyMgmtGenKey)CRYPT_ECDH_Gen},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, (CRYPT_EAL_ImplPkeyMgmtSetPrv)CRYPT_ECDH_SetPrvKey},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, (CRYPT_EAL_ImplPkeyMgmtSetPub)CRYPT_ECDH_SetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, (CRYPT_EAL_ImplPkeyMgmtGetPrv)CRYPT_ECDH_GetPrvKey},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, (CRYPT_EAL_ImplPkeyMgmtGetPub)CRYPT_ECDH_GetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, (CRYPT_EAL_ImplPkeyMgmtDupCtx)CRYPT_ECDH_DupCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_COMPARE, (CRYPT_EAL_ImplPkeyMgmtCompare)CRYPT_ECDH_Cmp},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, (CRYPT_EAL_ImplPkeyMgmtCtrl)CRYPT_ECDH_Ctrl},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, (CRYPT_EAL_ImplPkeyMgmtFreeCtx)CRYPT_ECDH_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

static const CRYPT_EAL_AlgInfo g_defKeyMgmt[] = {
    {CRYPT_PKEY_ECDSA, g_defKeyMgmtEcdsa, CRYPT_EAL_DEFAULT_ATTR},
    {BSL_CID_MAX + 2, g_defKeyMgmtEcdh, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static int32_t TestProvQuery(void *provCtx, int32_t algid, const char *propQuery, CRYPT_EAL_Func **outFuncs)
{
    (void)provCtx;
    int32_t ret = CRYPT_SUCCESS;
    switch (operaId) {
        case CRYPT_EAL_OPERAID_KEYMGMT:
            *algInfos = g_defKeyMgmt;
            break;
        default:
            ret = CRYPT_NOT_SUPPORT;
            break;
    }

    return CRYPT_SUCCESS;
}

static int32_t TestProvFree(void *provCtx)
{
    if (provCtx != NULL) {
        free(provCtx);
    }
    return CRYPT_SUCCESS;
}

static int32_t TestCryptGetGroupCaps(CRYPT_EAL_ProcCapsCb cb, void *args)
{
    if (cb == NULL) {
        return CRYPT_NULL_INPUT;
    }
    int32_t groupId = 477;
    int32_t paraId = BSL_CID_MAX + 1;
    int32_t algId = BSL_CID_MAX + 2;
    int32_t secBits = 1024;
    int32_t versionBits = TLS_VERSION_MASK;
    bool isKem = false;
    BSL_Param param[] = {
        {
            CRYPT_PARAM_CAP_TLS_GROUP_IANA_GROUP_NAME,
            BSL_PARAM_TYPE_OCTETS_PTR,
            (void *)(uintptr_t)"test_new_group",
            (uint32_t)strlen("test_new_group")
        },
        {
            CRYPT_PARAM_CAP_TLS_GROUP_IANA_GROUP_ID,
            BSL_PARAM_TYPE_UINT16,
            (void *)(uintptr_t)&(groupId),
            sizeof(groupId)
        },
        {
            CRYPT_PARAM_CAP_TLS_GROUP_PARA_ID,
            BSL_PARAM_TYPE_INT32,
            (void *)(uintptr_t)&(paraId),
            sizeof(paraId)
        },
        {
            CRYPT_PARAM_CAP_TLS_GROUP_ALG_ID,
            BSL_PARAM_TYPE_INT32,
            (void *)(uintptr_t)&(algId),
            sizeof(algId)
        },
        {
            CRYPT_PARAM_CAP_TLS_GROUP_SEC_BITS,
            BSL_PARAM_TYPE_INT32,
            (void *)(uintptr_t)&(secBits),
            sizeof(secBits)
        },
        {
            CRYPT_PARAM_CAP_TLS_GROUP_VERSION_BITS,
            BSL_PARAM_TYPE_UINT32,
            (void *)(uintptr_t)&(versionBits),
            sizeof(versionBits)
        },
        {
            CRYPT_PARAM_CAP_TLS_GROUP_IS_KEM,
            BSL_PARAM_TYPE_BOOL,
            (void *)(uintptr_t)&(isKem),
            sizeof(isKem)
        }
    };
    return cb(param, args);
}

typedef struct {
    const char *name;                   // name
    uint16_t signatureScheme;           // HITLS_SignHashAlgo, IANA specified
    int32_t keyType;                    // HITLS_CERT_KeyType
    char *keyTypeOid;                   // key type oid
    char *keyTypeOidName;               // key type oid name
    int32_t paraId;                     // CRYPT_PKEY_ParaId
    char *paraOid;                      // parameter oid
    char *paraOidName;                  // parameter oid name
    int32_t signHashAlgId;              // combined sign hash algorithm id
    char *signHashAlgOid;               // sign hash algorithm oid
    char *signHashAlgOidName;           // sign hash algorithm oid name
    int32_t signAlgId;                  // CRYPT_PKEY_AlgId
    int32_t hashAlgId;                  // CRYPT_MD_AlgId
    char *hashAlgOid;                   // hash algorithm oid
    char *hashAlgOidName;               // hash algorithm oid name
    int32_t secBits;                    // security bits
    uint32_t certVersionBits;           // TLS_VERSION_MASK
    uint32_t chainVersionBits;          // TLS_VERSION_MASK
} TLS_SigSchemeInfo;

static int32_t TestCryptGetSigAlgCaps(CRYPT_EAL_ProcCapsCb cb, void *args)
{
    if (cb == NULL) {
        return CRYPT_NULL_INPUT;
    }
    uint16_t signatureScheme = 23333;
    int32_t keyType = CRYPT_PKEY_ECDH;
    int32_t paraId = BSL_CID_MAX + 1;
    int32_t signHashAlgId = BSL_CID_MAX + 2;
    int32_t signAlgId = BSL_CID_MAX + 3;
    int32_t hashAlgId = BSL_CID_MAX + 4;
    int32_t secBits = 1024;
    uint32_t certVersionBits = TLS_VERSION_MASK;
    uint32_t chainVersionBits = TLS_VERSION_MASK;
    BSL_Param param[] = {
        {
            CRYPT_PARAM_CAP_TLS_SIGNALG_IANA_SIGN_NAME,
            BSL_PARAM_TYPE_OCTETS_PTR,
            (void *)(uintptr_t)"test_new_sign_alg_name",
            (uint32_t)strlen("test_new_sign_alg_name")
        },
        {
            CRYPT_PARAM_CAP_TLS_SIGNALG_IANA_SIGN_ID,
            BSL_PARAM_TYPE_UINT16,
            (void *)(uintptr_t)&(signatureScheme),
            sizeof(signatureScheme)
        },
        {
            CRYPT_PARAM_CAP_TLS_SIGNALG_KEY_TYPE,
            BSL_PARAM_TYPE_INT32,
            (void *)(uintptr_t)&(keyType),
            sizeof(keyType)
        },
        {
            CRYPT_PARAM_CAP_TLS_SIGNALG_PARA_ID,
            BSL_PARAM_TYPE_INT32,
            (void *)(uintptr_t)&(paraId),
            sizeof(paraId)
        },
        {
            CRYPT_PARAM_CAP_TLS_SIGNALG_PARA_OID,
            BSL_PARAM_TYPE_OCTETS_PTR,
            (void *)(uintptr_t)"test_new_para_oid",
            (uint32_t)strlen("test_new_para_oid")
        },
        {
            CRYPT_PARAM_CAP_TLS_SIGNALG_PARA_OID_NAME,
            BSL_PARAM_TYPE_OCTETS_PTR,
            (void *)(uintptr_t)"test_new_para_oid_name",
            (uint32_t)strlen("test_new_para_oid_name")
        },
        {
            CRYPT_PARAM_CAP_TLS_SIGNALG_SIGNWITHMD_ID,
            BSL_PARAM_TYPE_UINT16,
            (void *)(uintptr_t)&(signHashAlgId),
            sizeof(signHashAlgId)
        },
        {
            CRYPT_PARAM_CAP_TLS_SIGNALG_SIGNWITHMD_OID,
            BSL_PARAM_TYPE_OCTETS_PTR,
            (void *)(uintptr_t)"test_new_sign_with_md_oid",
            (uint32_t)strlen("test_new_sign_with_md_oid")
        },
        {
            CRYPT_PARAM_CAP_TLS_SIGNALG_SIGNWITHMD_NAME,
            BSL_PARAM_TYPE_OCTETS_PTR,
            (void *)(uintptr_t)"test_new_sign_with_md_name",
            (uint32_t)strlen("test_new_sign_with_md_name")
        },
        {
            CRYPT_PARAM_CAP_TLS_SIGNALG_SIGN_ID,
            BSL_PARAM_TYPE_INT32,
            (void *)(uintptr_t)&(signAlgId),
            sizeof(signAlgId)
        },
        {
            CRYPT_PARAM_CAP_TLS_SIGNALG_MD_ID,
            BSL_PARAM_TYPE_UINT16,
            (void *)(uintptr_t)&(hashAlgId),
            sizeof(hashAlgId)
        },
        {
            CRYPT_PARAM_CAP_TLS_SIGNALG_MD_OID,
            BSL_PARAM_TYPE_OCTETS_PTR,
            (void *)(uintptr_t)"test_new_md_oid",
            (uint32_t)strlen("test_new_md_oid")
        },
        {
            CRYPT_PARAM_CAP_TLS_SIGNALG_MD_NAME,
            BSL_PARAM_TYPE_OCTETS_PTR,
            (void *)(uintptr_t)"test_new_md_name",
            (uint32_t)strlen("test_new_md_name")
        },
        {
            CRYPT_PARAM_CAP_TLS_SIGNALG_SEC_BITS,
            BSL_PARAM_TYPE_INT32,
            (void *)(uintptr_t)&(secBits),
            sizeof(secBits)
        },
        {
            CRYPT_PARAM_CAP_TLS_SIGNALG_CHAIN_VERSION_BITS,
            BSL_PARAM_TYPE_UINT32,
            (void *)(uintptr_t)&(chainVersionBits),
            sizeof(chainVersionBits)
        },
        {
            CRYPT_PARAM_CAP_TLS_SIGNALG_CERT_VERSION_BITS,
            BSL_PARAM_TYPE_UINT32,
            (void *)(uintptr_t)&(certVersionBits),
            sizeof(certVersionBits)
        }
    };
    return cb(param, args);
}

static int32_t TestProvGetCaps(void *provCtx, int32_t cmd, CRYPT_EAL_ProcCapsCb cb, void *args)
{
    switch (cmd) {
        case CRYPT_EAL_GET_GROUP_CAP:
            return TestCryptGetGroupCaps(cb, args);
        case CRYPT_EAL_GET_SIGALG_CAP:
            return TestCryptGetSigAlgCaps(cb, args);
        default:
            return CRYPT_NOT_SUPPORT;
    }
}

static CRYPT_EAL_Func g_testProvOutFuncs[] = {
    {CRYPT_EAL_PROVCB_QUERY, TestProvQuery},
    {CRYPT_EAL_PROVCB_FREE, TestProvFree},
    {CRYPT_EAL_PROVCB_CTRL, NULL},
    {CRYPT_EAL_PROVCB_GETCAPS, TestProvGetCaps},
    CRYPT_EAL_FUNC_END
};


// 修改初始化函数，添加GetCaps回调
static int32_t CRYPT_EAL_ProviderInit(CRYPT_EAL_ProvMgrCtx *mgrCtx, BSL_Param *param,
    CRYPT_EAL_Func *capFuncs, CRYPT_EAL_Func **outFuncs, void **provCtx)
{
    // ... existing initialization code ...

    // 设置GetCaps回调
    mgrCtx->provGetCap = TestProvGetCaps;

    // ... rest of initialization code ...
    return CRYPT_SUCCESS;
}
