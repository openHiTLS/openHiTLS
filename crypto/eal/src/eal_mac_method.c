/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_MAC)

#include <stdint.h>
#include "securec.h"
#include "crypt_local_types.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "bsl_sal.h"
#include "eal_mac_local.h"
#include "eal_cipher_local.h"
#include "eal_md_local.h"
#ifdef HITLS_CRYPTO_HMAC
#include "crypt_hmac.h"
#endif
#include "bsl_err_internal.h"
#include "eal_common.h"

#define CRYPT_MAC_IMPL_METHOD_DECLARE(name)          \
    EAL_MacMethod g_macMethod_##name = {             \
        (MacInitCtx)CRYPT_##name##_InitCtx, (MacInit)CRYPT_##name##_Init,           \
        (MacUpdate)CRYPT_##name##_Update,   (MacFinal)CRYPT_##name##_Final,         \
        (MacDeinit)CRYPT_##name##_Deinit,   (MacDeinitCtx)CRYPT_##name##_DeinitCtx, \
        (MacReinit)CRYPT_##name##_Reinit,   (MacGetMacLen)CRYPT_##name##_GetMacLen, \
        sizeof(CRYPT_##name##_Ctx)                   \
    }

#ifdef HITLS_CRYPTO_HMAC
CRYPT_MAC_IMPL_METHOD_DECLARE(HMAC);
#endif

static const EAL_MacMethod *g_macMethods[] = {
#ifdef HITLS_CRYPTO_HMAC
    &g_macMethod_HMAC,   // HMAC
#else
    NULL,
#endif
    NULL,
    NULL,
};

static const EAL_MacAlgMap CID_MAC_ALG_MAP[] = {
#ifdef HITLS_CRYPTO_HMAC
    {.id = CRYPT_MAC_HMAC_MD5,      .macId = CRYPT_MAC_HMAC, .mdId = CRYPT_MD_MD5},
    {.id = CRYPT_MAC_HMAC_SHA1,     .macId = CRYPT_MAC_HMAC, .mdId = CRYPT_MD_SHA1},
    {.id = CRYPT_MAC_HMAC_SHA224,   .macId = CRYPT_MAC_HMAC, .mdId = CRYPT_MD_SHA224},
    {.id = CRYPT_MAC_HMAC_SHA256,   .macId = CRYPT_MAC_HMAC, .mdId = CRYPT_MD_SHA256},
    {.id = CRYPT_MAC_HMAC_SHA384,   .macId = CRYPT_MAC_HMAC, .mdId = CRYPT_MD_SHA384},
    {.id = CRYPT_MAC_HMAC_SHA512,   .macId = CRYPT_MAC_HMAC, .mdId = CRYPT_MD_SHA512},
    {.id = CRYPT_MAC_HMAC_SHA3_224, .macId = CRYPT_MAC_HMAC, .mdId = CRYPT_MD_SHA3_224},
    {.id = CRYPT_MAC_HMAC_SHA3_256, .macId = CRYPT_MAC_HMAC, .mdId = CRYPT_MD_SHA3_256},
    {.id = CRYPT_MAC_HMAC_SHA3_384, .macId = CRYPT_MAC_HMAC, .mdId = CRYPT_MD_SHA3_384},
    {.id = CRYPT_MAC_HMAC_SHA3_512, .macId = CRYPT_MAC_HMAC, .mdId = CRYPT_MD_SHA3_512},
    {.id = CRYPT_MAC_HMAC_SM3,      .macId = CRYPT_MAC_HMAC, .mdId = CRYPT_MD_SM3},
#endif
};

static const EAL_MacAlgMap *EAL_FindMacAlgMap(CRYPT_MAC_AlgId id)
{
    uint32_t num = sizeof(CID_MAC_ALG_MAP) / sizeof(CID_MAC_ALG_MAP[0]);
    const EAL_MacAlgMap *macAlgMap = NULL;

    for (uint32_t i = 0; i < num; i++) {
        if (CID_MAC_ALG_MAP[i].id == id) {
            macAlgMap = &CID_MAC_ALG_MAP[i];
            break;
        }
    }
    return macAlgMap;
}

int32_t EAL_MacFindMethod(CRYPT_MAC_AlgId id, EAL_MacMethLookup *lu)
{
    if (lu == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    const EAL_MacAlgMap *macAlgMap = EAL_FindMacAlgMap(id);
    if (macAlgMap == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }

    CRYPT_MAC_ID macId = macAlgMap->macId;
    switch (macId) {
#ifdef HITLS_CRYPTO_MD
        case CRYPT_MAC_HMAC:
            lu->macMethod = g_macMethods[macId];
            // Obtain the ID of the combined algorithm from the map and search for the method based on the ID.
            lu->md = EAL_MdFindMethod(macAlgMap->mdId);
            break;
#endif
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
            return CRYPT_EAL_ERR_ALGID;
    }

    if (lu->masMeth == NULL || lu->depMeth == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }

    return CRYPT_SUCCESS;
}
#endif
