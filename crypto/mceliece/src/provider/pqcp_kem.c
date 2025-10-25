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

#include "scloudplus.h"
#include "frodokem.h"
#include "mceliece.h"
#include "pqcp_provider.h"
#include "crypt_eal_provider.h"
#include "crypt_eal_implprovider.h"
#include "crypt_errno.h"

void *CRYPT_PQCP_PkeyMgmtNewCtx(void *provCtx, int32_t algId)
{
    (void) provCtx;
    void *pkeyCtx = NULL;
    switch (algId) {
        case CRYPT_PKEY_SCLOUDPLUS:
            pkeyCtx = PQCP_SCLOUDPLUS_NewCtx();
            break;
        case CRYPT_PKEY_FRODOKEM:
            pkeyCtx = PQCP_FRODOKEM_NewCtx();
            break;
        case CRYPT_PKEY_MCELIECE:
            pkeyCtx = PQCP_MCELIECE_NewCtx();
            break;
        default:
            break;
    }
    if (pkeyCtx == NULL) {
        // BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_NOT_SUPPORT);
        return NULL;
    }
    return pkeyCtx;
};

const CRYPT_EAL_Func g_pqcpKeyMgmtScloudPlus[] = {
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (CRYPT_EAL_ImplPkeyMgmtNewCtx)CRYPT_PQCP_PkeyMgmtNewCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, (CRYPT_EAL_ImplPkeyMgmtGenKey)PQCP_SCLOUDPLUS_Gen},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, (CRYPT_EAL_ImplPkeyMgmtSetPrv)PQCP_SCLOUDPLUS_SetPrvKey},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, (CRYPT_EAL_ImplPkeyMgmtSetPub)PQCP_SCLOUDPLUS_SetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, (CRYPT_EAL_ImplPkeyMgmtGetPrv)PQCP_SCLOUDPLUS_GetPrvKey},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, (CRYPT_EAL_ImplPkeyMgmtGetPub)PQCP_SCLOUDPLUS_GetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, (CRYPT_EAL_ImplPkeyMgmtDupCtx)PQCP_SCLOUDPLUS_DupCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_COMPARE, (CRYPT_EAL_ImplPkeyMgmtCompare)PQCP_SCLOUDPLUS_Cmp},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, (CRYPT_EAL_ImplPkeyMgmtCtrl)PQCP_SCLOUDPLUS_Ctrl},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, (CRYPT_EAL_ImplPkeyMgmtFreeCtx)PQCP_SCLOUDPLUS_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_pqcpKemScloudPlus[] = {
    {CRYPT_EAL_IMPLPKEYKEM_ENCAPSULATE_INIT, (CRYPT_EAL_ImplPkeyEncapsInit)PQCP_SCLOUDPLUS_EncapsInit},
    {CRYPT_EAL_IMPLPKEYKEM_DECAPSULATE_INIT, (CRYPT_EAL_ImplPkeyDecapsInit)PQCP_SCLOUDPLUS_DecapsInit},
    {CRYPT_EAL_IMPLPKEYKEM_ENCAPSULATE, (CRYPT_EAL_ImplPkeyKemEncapsulate)PQCP_SCLOUDPLUS_Encaps},
    {CRYPT_EAL_IMPLPKEYKEM_DECAPSULATE, (CRYPT_EAL_ImplPkeyKemDecapsulate)PQCP_SCLOUDPLUS_Decaps},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_pqcpKeyMgmtFrodoKem[] = {
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (CRYPT_EAL_ImplPkeyMgmtNewCtx)CRYPT_PQCP_PkeyMgmtNewCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, (CRYPT_EAL_ImplPkeyMgmtGenKey)PQCP_FRODOKEM_Gen},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, (CRYPT_EAL_ImplPkeyMgmtSetPrv)PQCP_FRODOKEM_SetPrvKey},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, (CRYPT_EAL_ImplPkeyMgmtSetPub)PQCP_FRODOKEM_SetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, (CRYPT_EAL_ImplPkeyMgmtGetPrv)PQCP_FRODOKEM_GetPrvKey},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, (CRYPT_EAL_ImplPkeyMgmtGetPub)PQCP_FRODOKEM_GetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, (CRYPT_EAL_ImplPkeyMgmtDupCtx)PQCP_FRODOKEM_DupCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_COMPARE, (CRYPT_EAL_ImplPkeyMgmtCompare)PQCP_FRODOKEM_Cmp},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, (CRYPT_EAL_ImplPkeyMgmtCtrl)PQCP_FRODOKEM_Ctrl},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, (CRYPT_EAL_ImplPkeyMgmtFreeCtx)PQCP_FRODOKEM_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_pqcpKemFrodoKem[] = {
    {CRYPT_EAL_IMPLPKEYKEM_ENCAPSULATE_INIT, (CRYPT_EAL_ImplPkeyEncapsInit)PQCP_FRODOKEM_EncapsInit},
    {CRYPT_EAL_IMPLPKEYKEM_DECAPSULATE_INIT, (CRYPT_EAL_ImplPkeyDecapsInit)PQCP_FRODOKEM_DecapsInit},
    {CRYPT_EAL_IMPLPKEYKEM_ENCAPSULATE, (CRYPT_EAL_ImplPkeyKemEncapsulate)PQCP_FRODOKEM_Encaps},
    {CRYPT_EAL_IMPLPKEYKEM_DECAPSULATE, (CRYPT_EAL_ImplPkeyKemDecapsulate)PQCP_FRODOKEM_Decaps},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_pqcpKeyMgmtMceliece[] = {
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (CRYPT_EAL_ImplPkeyMgmtNewCtx)CRYPT_PQCP_PkeyMgmtNewCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, (CRYPT_EAL_ImplPkeyMgmtGenKey)PQCP_MCELIECE_Gen},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, (CRYPT_EAL_ImplPkeyMgmtSetPrv)PQCP_MCELIECE_SetPrvKey},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, (CRYPT_EAL_ImplPkeyMgmtSetPub)PQCP_MCELIECE_SetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, (CRYPT_EAL_ImplPkeyMgmtGetPrv)PQCP_MCELIECE_GetPrvKey},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, (CRYPT_EAL_ImplPkeyMgmtGetPub)PQCP_MCELIECE_GetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, (CRYPT_EAL_ImplPkeyMgmtDupCtx)PQCP_MCELIECE_DupCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_COMPARE, (CRYPT_EAL_ImplPkeyMgmtCompare)PQCP_MCELIECE_Cmp},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, (CRYPT_EAL_ImplPkeyMgmtCtrl)PQCP_MCELIECE_Ctrl},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, (CRYPT_EAL_ImplPkeyMgmtFreeCtx)PQCP_MCELIECE_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_pqcpKemMceliece[] = {
    {CRYPT_EAL_IMPLPKEYKEM_ENCAPSULATE_INIT, (CRYPT_EAL_ImplPkeyEncapsInit)PQCP_MCELIECE_EncapsInit},
    {CRYPT_EAL_IMPLPKEYKEM_DECAPSULATE_INIT, (CRYPT_EAL_ImplPkeyDecapsInit)PQCP_MCELIECE_DecapsInit},
    {CRYPT_EAL_IMPLPKEYKEM_ENCAPSULATE, (CRYPT_EAL_ImplPkeyKemEncapsulate)PQCP_MCELIECE_Encaps},
    {CRYPT_EAL_IMPLPKEYKEM_DECAPSULATE, (CRYPT_EAL_ImplPkeyKemDecapsulate)PQCP_MCELIECE_Decaps},
    CRYPT_EAL_FUNC_END,
};