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
#ifdef HITLS_CRYPTO_CMAC
#include "crypt_cmac.h"
#endif
#ifdef HITLS_CRYPTO_CBC_MAC
#include "crypt_cbc_mac.h"
#endif
#ifdef HITLS_CRYPTO_GMAC
#include "crypt_gmac.h"
#endif
#ifdef HITLS_CRYPTO_SIPHASH
#include "crypt_siphash.h"
#endif
#include "bsl_err_internal.h"
#include "eal_common.h"

#define CRYPT_MAC_IMPL_METHOD_DECLARE(name)          \
    EAL_MacMethod g_macMethod_##name = {             \
        (MacNewCtx)CRYPT_##name##_NewCtx,            \
        (MacInit)CRYPT_##name##_Init,                \
        (MacUpdate)CRYPT_##name##_Update,            \
        (MacFinal)CRYPT_##name##_Final,              \
        (MacDeinit)CRYPT_##name##_Deinit,            \
        (MacReinit)CRYPT_##name##_Reinit,            \
        (MacCtrl)CRYPT_##name##_Ctrl,                \
        (MacFreeCtx)CRYPT_##name##_FreeCtx,          \
        (MacDupCtx)CRYPT_##name##_DupCtx,            \
    }

#ifdef HITLS_CRYPTO_HMAC
CRYPT_MAC_IMPL_METHOD_DECLARE(HMAC);
#endif
#ifdef HITLS_CRYPTO_CMAC
CRYPT_MAC_IMPL_METHOD_DECLARE(CMAC);
#endif

#ifdef HITLS_CRYPTO_CBC_MAC
CRYPT_MAC_IMPL_METHOD_DECLARE(CBC_MAC);
#endif

#ifdef HITLS_CRYPTO_GMAC

EAL_MacMethod g_macMethod_GMAC = {
    (MacNewCtx)CRYPT_GMAC_NewCtx,
    (MacInit)CRYPT_GMAC_Init,
    (MacUpdate)CRYPT_GMAC_Update,
    (MacFinal)CRYPT_GMAC_Final,
    (MacDeinit)CRYPT_GMAC_Deinit,
    // (MacReinit)
    NULL,
    (MacCtrl)CRYPT_GMAC_Ctrl,
    (MacFreeCtx)CRYPT_GMAC_FreeCtx,
    (MacDupCtx)CRYPT_GMAC_DupCtx,
};
#endif

#ifdef HITLS_CRYPTO_SIPHASH
CRYPT_MAC_IMPL_METHOD_DECLARE(SIPHASH);
EAL_SiphashMethod g_siphash64Meth = {.hashSize = SIPHASH_MIN_DIGEST_SIZE,
    .compressionRounds = DEFAULT_COMPRESSION_ROUND,
    .finalizationRounds = DEFAULT_FINALIZATION_ROUND};

EAL_SiphashMethod g_siphash128Meth = {.hashSize = SIPHASH_MAX_DIGEST_SIZE,
    .compressionRounds = DEFAULT_COMPRESSION_ROUND,
    .finalizationRounds = DEFAULT_FINALIZATION_ROUND};
#endif

static const EAL_MacMethod *g_macMethods[] = {
#ifdef HITLS_CRYPTO_HMAC
    &g_macMethod_HMAC,   // HMAC
#else
    NULL,
#endif
#ifdef HITLS_CRYPTO_CMAC
    &g_macMethod_CMAC,   // CMAC
#else
    NULL,
#endif
#ifdef HITLS_CRYPTO_CBC_MAC
    &g_macMethod_CBC_MAC,   // CBC-MAC
#else
    NULL,
#endif
#ifdef HITLS_CRYPTO_SIPHASH
    &g_macMethod_SIPHASH,   // SIPHASH
#else
    NULL,
#endif
#ifdef HITLS_CRYPTO_GMAC
    &g_macMethod_GMAC,   // GMAC
#else
    NULL,
#endif
};

static const EAL_MacAlgMap CID_MAC_ALG_MAP[] = {
#ifdef HITLS_CRYPTO_HMAC
#ifdef HITLS_CRYPTO_MD5
    {.id = CRYPT_MAC_HMAC_MD5,      .macId = CRYPT_MAC_HMAC, .mdId = CRYPT_MD_MD5},
#endif
#ifdef HITLS_CRYPTO_SHA1
    {.id = CRYPT_MAC_HMAC_SHA1,     .macId = CRYPT_MAC_HMAC, .mdId = CRYPT_MD_SHA1},
#endif
#ifdef HITLS_CRYPTO_SHA224
    {.id = CRYPT_MAC_HMAC_SHA224,   .macId = CRYPT_MAC_HMAC, .mdId = CRYPT_MD_SHA224},
#endif
#ifdef HITLS_CRYPTO_SHA256
    {.id = CRYPT_MAC_HMAC_SHA256,   .macId = CRYPT_MAC_HMAC, .mdId = CRYPT_MD_SHA256},
#endif
#ifdef HITLS_CRYPTO_SHA384
    {.id = CRYPT_MAC_HMAC_SHA384,   .macId = CRYPT_MAC_HMAC, .mdId = CRYPT_MD_SHA384},
#endif
#ifdef HITLS_CRYPTO_SHA512
    {.id = CRYPT_MAC_HMAC_SHA512,   .macId = CRYPT_MAC_HMAC, .mdId = CRYPT_MD_SHA512},
#endif
#ifdef HITLS_CRYPTO_SHA3
    {.id = CRYPT_MAC_HMAC_SHA3_224, .macId = CRYPT_MAC_HMAC, .mdId = CRYPT_MD_SHA3_224},
    {.id = CRYPT_MAC_HMAC_SHA3_256, .macId = CRYPT_MAC_HMAC, .mdId = CRYPT_MD_SHA3_256},
    {.id = CRYPT_MAC_HMAC_SHA3_384, .macId = CRYPT_MAC_HMAC, .mdId = CRYPT_MD_SHA3_384},
    {.id = CRYPT_MAC_HMAC_SHA3_512, .macId = CRYPT_MAC_HMAC, .mdId = CRYPT_MD_SHA3_512},
#endif
#ifdef HITLS_CRYPTO_SM3
    {.id = CRYPT_MAC_HMAC_SM3,      .macId = CRYPT_MAC_HMAC, .mdId = CRYPT_MD_SM3},
#endif
#endif // HITLS_CRYPTO_HMAC
#ifdef HITLS_CRYPTO_CMAC_AES
    {.id = CRYPT_MAC_CMAC_AES128,   .macId = CRYPT_MAC_CMAC, .symId = CRYPT_SYM_AES128},  // CRYPT_MAC_CMAC_AES128
    {.id = CRYPT_MAC_CMAC_AES192,   .macId = CRYPT_MAC_CMAC, .symId = CRYPT_SYM_AES192},  // CRYPT_MAC_CMAC_AES192
    {.id = CRYPT_MAC_CMAC_AES256,   .macId = CRYPT_MAC_CMAC, .symId = CRYPT_SYM_AES256},  // CRYPT_MAC_CMAC_AES256
#endif
#ifdef HITLS_CRYPTO_CMAC_SM4
    {.id = CRYPT_MAC_CMAC_SM4,   .macId = CRYPT_MAC_CMAC, .symId = CRYPT_SYM_SM4},       // CRYPT_MAC_CMAC_SM4
#endif
#ifdef HITLS_CRYPTO_CBC_MAC
    {.id = CRYPT_MAC_CBC_MAC_SM4,   .macId = CRYPT_MAC_CBC_MAC, .symId = CRYPT_SYM_SM4},  // CRYPT_MAC_CBC_MAC_SM4
#endif
#ifdef HITLS_CRYPTO_GMAC
    {.id = CRYPT_MAC_GMAC_AES128,   .macId = CRYPT_MAC_GMAC, .symId = CRYPT_SYM_AES128},  // CRYPT_MAC_GMAC_AES128
    {.id = CRYPT_MAC_GMAC_AES192,   .macId = CRYPT_MAC_GMAC, .symId = CRYPT_SYM_AES192},  // CRYPT_MAC_GMAC_AES192
    {.id = CRYPT_MAC_GMAC_AES256,   .macId = CRYPT_MAC_GMAC, .symId = CRYPT_SYM_AES256}   // CRYPT_MAC_GMAC_AES256
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

#ifdef HITLS_CRYPTO_CIPHER
static int32_t ConvertSymId2CipherId(CRYPT_SYM_AlgId algId)
{
    switch (algId) {
        case CRYPT_SYM_AES128:
            return CRYPT_CIPHER_AES128_ECB;
        case CRYPT_SYM_AES192:
            return CRYPT_CIPHER_AES192_ECB;
        case CRYPT_SYM_AES256:
            return CRYPT_CIPHER_AES256_ECB;
        case CRYPT_SYM_SM4:
            return CRYPT_CIPHER_SM4_XTS;
        default:
            return CRYPT_CIPHER_MAX;
    }
}
#endif

int32_t EAL_MacFindMethod(CRYPT_MAC_AlgId id, EAL_MacMethLookup *lu)
{
    if (lu == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (id == CRYPT_MAC_SIPHASH64 || id == CRYPT_MAC_SIPHASH128) {
#ifdef HITLS_CRYPTO_SIPHASH
        // @see g_macMethod_SIPHASH
        lu->macMethod = g_macMethods[CRYPT_MAC_SIPHASH];
        lu->sip = (id == CRYPT_MAC_SIPHASH64) ? &g_siphash64Meth : &g_siphash128Meth;
        return CRYPT_SUCCESS;
#else
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
#endif
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
#ifdef HITLS_CRYPTO_CIPHER
        case CRYPT_MAC_CBC_MAC:
        case CRYPT_MAC_CMAC:
        case CRYPT_MAC_GMAC:  // GMAC algorithm is a special example of the GCM algorithm. So search the method of GCM.
            lu->macMethod = g_macMethods[macId];
            // Obtain the ID of the combined algorithm from the map and search for the method based on the ID.
            lu->ciph = EAL_GetSymMethod(ConvertSymId2CipherId(macAlgMap->symId));
            break;
#endif
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
            return CRYPT_EAL_ERR_ALGID;
    }

    if (lu->macMethod == NULL || lu->depMeth == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }

    return CRYPT_SUCCESS;
}
#endif
