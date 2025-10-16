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

#ifndef EAL_PKEY_H
#define EAL_PKEY_H

#include "crypt_eal_pkey.h"
#include "crypt_eal_provider.h"
#include "crypt_local_types.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef struct {
    int32_t algId;
    CRYPT_EAL_ProvMgrCtx *mgrCtx;
    EAL_PkeyUnitaryMethod keyMgmtMethod;
} CRYPT_EAL_PkeyMgmtInfo;

typedef struct {
    CRYPT_EAL_ProvMgrCtx *mgrCtx;
    const CRYPT_EAL_Func *funcsAsyCipher;
    const CRYPT_EAL_Func *funcsExch;
    const CRYPT_EAL_Func *funcSign;
    const CRYPT_EAL_Func *funcKem;
    const CRYPT_EAL_Func *funcsKeyMgmt;
} CRYPT_EAL_AsyAlgFuncsInfo;

/**
 * @ingroup crypt_eal_pkey
 * @brief Create a new asymmetric key context by key management information.
 *
 * @param pkeyAlgInfo [IN] The key management information.
 * @param keyRef [IN] The reference to the key.
 *
 * @return pkey on success, NULL on failure.
 */
CRYPT_EAL_PkeyCtx *CRYPT_EAL_MakeKeyByPkeyAlgInfo(CRYPT_EAL_PkeyMgmtInfo *pkeyAlgInfo, void *keyRef);

/**
 * @ingroup crypt_eal_pkey
 * @brief Get the key management information by algorithm ID and attribute name.
 *
 * @param libCtx [IN] The library context.
 * @param algId [IN] The algorithm ID.
 * @param attrName [IN] The attribute name.
 * @param pkeyAlgInfo [OUT] The key management information.
 */
int32_t CRYPT_EAL_GetPkeyAlgInfo(CRYPT_EAL_LibCtx *libCtx, int32_t algId, const char *attrName,
    CRYPT_EAL_PkeyMgmtInfo *pkeyAlgInfo);

int32_t CRYPT_EAL_SetPkeyMethod(EAL_PkeyUnitaryMethod *method, const CRYPT_EAL_Func *funcsKeyMgmt,
    const CRYPT_EAL_Func *funcsAsyCipher, const CRYPT_EAL_Func *funcsExch, const CRYPT_EAL_Func *funcSign,
    const CRYPT_EAL_Func *funcKem);

int32_t CRYPT_EAL_ProviderGetAsyAlgFuncs(CRYPT_EAL_LibCtx *libCtx, int32_t algId, uint32_t pkeyOperType,
    const char *attrName, CRYPT_EAL_AsyAlgFuncsInfo *funcs);
#ifdef __cplusplus
}
#endif // __cplusplus

#endif // EAL_PKEY_H
