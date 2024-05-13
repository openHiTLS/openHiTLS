/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_KDF)

#include <stdint.h>
#include "crypt_eal_kdf.h"
#include "securec.h"
#include "bsl_err_internal.h"
#include "crypt_local_types.h"
#include "crypt_eal_mac.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "eal_mac_local.h"
#ifdef HITLS_CRYPTO_HMAC
#include "crypt_hmac.h"
#endif
#ifdef HITLS_CRYPTO_PBKDF2
#include "crypt_pbkdf2.h"
#endif
#ifdef HITLS_CRYPTO_HKDF
#include "crypt_hkdf.h"
#endif
#ifdef HITLS_CRYPTO_KDFTLS12
#include "crypt_kdf_tls12.h"
#endif
#ifdef HITLS_CRYPTO_SCRYPT
#include "crypt_scrypt.h"
#endif
#include "eal_common.h"
#include "crypt_utils.h"
#include "crypt_ealinit.h"

#ifdef HITLS_CRYPTO_PBKDF2
static const uint32_t PBKDF_ID_LIST[] = {
    CRYPT_MAC_HMAC_MD5,
    CRYPT_MAC_HMAC_SHA1,
    CRYPT_MAC_HMAC_SHA224,
    CRYPT_MAC_HMAC_SHA256,
    CRYPT_MAC_HMAC_SHA384,
    CRYPT_MAC_HMAC_SHA512,
    CRYPT_MAC_HMAC_SM3,
    CRYPT_MAC_HMAC_SHA3_224,
    CRYPT_MAC_HMAC_SHA3_256,
    CRYPT_MAC_HMAC_SHA3_384,
    CRYPT_MAC_HMAC_SHA3_512,
};
#endif

#ifdef HITLS_CRYPTO_HKDF
static const uint32_t HKDF_ID_LIST[] = {
    CRYPT_MAC_HMAC_MD5,
    CRYPT_MAC_HMAC_SHA1,
    CRYPT_MAC_HMAC_SHA224,
    CRYPT_MAC_HMAC_SHA256,
    CRYPT_MAC_HMAC_SHA384,
    CRYPT_MAC_HMAC_SHA512,
};
#endif

#ifdef HITLS_CRYPTO_KDFTLS12
static const uint32_t KDFTLS12_ID_LIST[] = {
    CRYPT_MAC_HMAC_SHA256,
    CRYPT_MAC_HMAC_SHA384,
    CRYPT_MAC_HMAC_SHA512,
};
#endif

bool CRYPT_EAL_HkdfIsValidAlgId(CRYPT_MAC_AlgId id)
{
#ifdef HITLS_CRYPTO_HKDF
    return ParamIdIsValid(id, HKDF_ID_LIST, sizeof(HKDF_ID_LIST) / sizeof(HKDF_ID_LIST[0]));
#else
    (void)id;
    return false;
#endif
}

bool CRYPT_EAL_Pbkdf2IsValidAlgId(CRYPT_MAC_AlgId id)
{
#ifdef HITLS_CRYPTO_PBKDF2
    return ParamIdIsValid(id, PBKDF_ID_LIST, sizeof(PBKDF_ID_LIST) / sizeof(PBKDF_ID_LIST[0]));
#else
    (void)id;
    return false;
#endif
}

bool CRYPT_EAL_Kdftls12IsValidAlgId(CRYPT_MAC_AlgId id)
{
#ifdef HITLS_CRYPTO_KDFTLS12
    return ParamIdIsValid(id, KDFTLS12_ID_LIST, sizeof(KDFTLS12_ID_LIST) / sizeof(KDFTLS12_ID_LIST[0]));
#else
    (void)id;
    return false;
#endif
}

int32_t CRYPT_EAL_Pbkdf2(CRYPT_MAC_AlgId id, const uint8_t *key, uint32_t keyLen, const uint8_t *salt,
    uint32_t saltLen, uint32_t it, uint8_t *out, uint32_t len)
{
#ifdef HITLS_CRYPTO_PBKDF2
#ifdef HITLS_CRYPTO_ASM_CHECK
    if (CRYPT_ASMCAP_Mac(id) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return CRYPT_EAL_ALG_ASM_NOT_SUPPORT;
    }
#endif
    if (!ParamIdIsValid(id, PBKDF_ID_LIST, sizeof(PBKDF_ID_LIST) / sizeof(PBKDF_ID_LIST[0]))) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, CRYPT_KDF_PBKDF2, CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }
    /* According to GM/T 0091-2020, the salt length of pbkdf2-hmac-sm3 cannot be less than 64 bits (8 bytes)
       and the number of iterations cannot be less than 1024. */
    if (id == CRYPT_MAC_HMAC_SM3 && (saltLen < 8 || it < 1024)) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, CRYPT_KDF_PBKDF2, CRYPT_PBKDF2_PARAM_ERROR);
        return CRYPT_PBKDF2_PARAM_ERROR;
    }

    EAL_MacMethLookup method;
    int32_t ret = EAL_MacFindMethod(id, &method);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_METH_NULL_NUMBER);
        return CRYPT_EAL_ERR_METH_NULL_NUMBER;
    }

    ret = CRYPT_PBKDF2_HMAC(method.macMethod, method.md, key, keyLen, salt, saltLen, it, out, len);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, CRYPT_KDF_PBKDF2, ret);
        return ret;
    }
    EAL_EventReport(CRYPT_EVENT_KEYDERIVE, CRYPT_ALGO_KDF, CRYPT_KDF_PBKDF2, CRYPT_SUCCESS);
    return CRYPT_SUCCESS;
#else
    (void)id;
    (void)key;
    (void)keyLen;
    (void)salt;
    (void)saltLen;
    (void)it;
    (void)out;
    (void)len;
    EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, CRYPT_KDF_PBKDF2, CRYPT_PBKDF2_NOT_SUPPORTED);
    return CRYPT_PBKDF2_NOT_SUPPORTED;
#endif
}

int32_t CRYPT_EAL_HkdfExtract(CRYPT_MAC_AlgId id, const uint8_t *key, uint32_t keyLen,
    const uint8_t *salt, uint32_t saltLen, uint8_t *out, uint32_t *len)
{
#ifdef HITLS_CRYPTO_HKDF
    if (!ParamIdIsValid(id, HKDF_ID_LIST, sizeof(HKDF_ID_LIST) / sizeof(HKDF_ID_LIST[0]))) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, CRYPT_KDF_HKDF, CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }
    EAL_MacMethLookup method;
    if (EAL_MacFindMethod(id, &method) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_METH_NULL_NUMBER);
        return CRYPT_EAL_ERR_METH_NULL_NUMBER;
    }

    int ret = CRYPT_HKDF_Extract(method.macMethod, method.md, key, keyLen, salt, saltLen, out, len);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, CRYPT_KDF_HKDF, ret);
        return ret;
    }
    EAL_EventReport(CRYPT_EVENT_KEYDERIVE, CRYPT_ALGO_KDF, CRYPT_KDF_HKDF, CRYPT_SUCCESS);
    return CRYPT_SUCCESS;
#else
    (void)id;
    (void)key;
    (void)keyLen;
    (void)salt;
    (void)saltLen;
    (void)out;
    (void)len;
    EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, CRYPT_KDF_HKDF, CRYPT_HKDF_NOT_SUPPORTED);
    return CRYPT_HKDF_NOT_SUPPORTED;
#endif
}

int32_t CRYPT_EAL_HkdfExpand(CRYPT_MAC_AlgId id, const uint8_t *key, uint32_t keyLen,
    const uint8_t *info, uint32_t infoLen, uint8_t *out, uint32_t len)
{
#ifdef HITLS_CRYPTO_HKDF
    EAL_MacMethLookup method;
    if (!ParamIdIsValid(id, HKDF_ID_LIST, sizeof(HKDF_ID_LIST) / sizeof(HKDF_ID_LIST[0]))) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, CRYPT_KDF_HKDF, CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }

    int32_t ret = EAL_MacFindMethod(id, &method);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_METH_NULL_NUMBER);
        return CRYPT_EAL_ERR_METH_NULL_NUMBER;
    }

    ret = CRYPT_HKDF_Expand(method.macMethod, method.md, key, keyLen, info, infoLen, out, len);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, CRYPT_KDF_HKDF, ret);
        return ret;
    }
    EAL_EventReport(CRYPT_EVENT_KEYDERIVE, CRYPT_ALGO_KDF, CRYPT_KDF_HKDF, CRYPT_SUCCESS);
    return CRYPT_SUCCESS;
#else
    (void)id;
    (void)key;
    (void)keyLen;
    (void)info;
    (void)infoLen;
    (void)out;
    (void)len;
    EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, CRYPT_KDF_HKDF, CRYPT_HKDF_NOT_SUPPORTED);
    return CRYPT_HKDF_NOT_SUPPORTED;
#endif
}

int32_t CRYPT_EAL_Hkdf(CRYPT_MAC_AlgId id, const uint8_t *key, uint32_t keyLen, const uint8_t *salt, uint32_t saltLen,
    const uint8_t *info, uint32_t infoLen, uint8_t *out, uint32_t len)
{
#ifdef HITLS_CRYPTO_HKDF
#ifdef HITLS_CRYPTO_ASM_CHECK
    if (CRYPT_ASMCAP_Mac(id) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return CRYPT_EAL_ALG_ASM_NOT_SUPPORT;
    }
#endif
    if (!ParamIdIsValid(id, HKDF_ID_LIST, sizeof(HKDF_ID_LIST) / sizeof(HKDF_ID_LIST[0]))) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, CRYPT_KDF_HKDF, CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }
    EAL_MacMethLookup method;
    int32_t ret = EAL_MacFindMethod(id, &method);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_METH_NULL_NUMBER);
        return CRYPT_EAL_ERR_METH_NULL_NUMBER;
    }

    ret = CRYPT_HKDF(method.macMethod, method.md, key, keyLen, salt, saltLen, info, infoLen, out, len);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, CRYPT_KDF_HKDF, ret);
        return ret;
    }
    EAL_EventReport(CRYPT_EVENT_KEYDERIVE, CRYPT_ALGO_KDF, CRYPT_KDF_HKDF, CRYPT_SUCCESS);
    return CRYPT_SUCCESS;
#else
    (void)id;
    (void)key;
    (void)keyLen;
    (void)info;
    (void)infoLen;
    (void)salt;
    (void)saltLen;
    (void)out;
    (void)len;
    EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, CRYPT_KDF_HKDF, CRYPT_HKDF_NOT_SUPPORTED);
    return CRYPT_HKDF_NOT_SUPPORTED;
#endif
}

int32_t CRYPT_EAL_KdfTls12(CRYPT_MAC_AlgId id, const uint8_t *key, uint32_t keyLen, const uint8_t *label,
    uint32_t labelLen, const uint8_t *seed, uint32_t seedLen,  uint8_t *out, uint32_t len)
{
#ifdef HITLS_CRYPTO_KDFTLS12
#ifdef HITLS_CRYPTO_ASM_CHECK
    if (CRYPT_ASMCAP_Mac(id) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return CRYPT_EAL_ALG_ASM_NOT_SUPPORT;
    }
#endif
    // For KDF-TLS1.2, only HMAC-SHA256, HMAC-SHA384 and HMAC-SHA512 can be used.
    if (!ParamIdIsValid(id, KDFTLS12_ID_LIST, sizeof(KDFTLS12_ID_LIST) / sizeof(KDFTLS12_ID_LIST[0]))) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, CRYPT_KDF_KDFTLS12, CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }
    int32_t ret;
    EAL_MacMethLookup method;
    ret = EAL_MacFindMethod(id, &method);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_METH_NULL_NUMBER);
        return CRYPT_EAL_ERR_METH_NULL_NUMBER;
    }

    ret = CRYPT_KDF_TLS12(method.macMethod, method.md, key, keyLen, label, labelLen, seed, seedLen, out, len);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, CRYPT_KDF_KDFTLS12, ret);
        return ret;
    }
    EAL_EventReport(CRYPT_EVENT_KEYDERIVE, CRYPT_ALGO_KDF, CRYPT_KDF_KDFTLS12, CRYPT_SUCCESS);
    return CRYPT_SUCCESS;
#else
    (void)id;
    (void)key;
    (void)keyLen;
    (void)label;
    (void)labelLen;
    (void)seed;
    (void)seedLen;
    (void)out;
    (void)len;
    EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, CRYPT_KDF_KDFTLS12, CRYPT_KDFTLS12_NOT_SUPPORTED);
    return CRYPT_KDFTLS12_NOT_SUPPORTED;
#endif
}

int32_t CRYPT_EAL_Scrypt(const uint8_t *key, uint32_t keyLen, const uint8_t *salt, uint32_t saltLen, uint32_t n,
    uint32_t r, uint32_t p, uint8_t *out, uint32_t len)
{
#ifdef HITLS_CRYPTO_SCRYPT
    EAL_MacMethLookup method;
    int32_t ret = EAL_MacFindMethod(CRYPT_MAC_HMAC_SHA256, &method);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_METH_NULL_NUMBER);
        return CRYPT_EAL_ERR_METH_NULL_NUMBER;
    }

    ret = CRYPT_SCRYPT(CRYPT_PBKDF2_HMAC, method.macMethod, method.md, key, keyLen, salt, saltLen, n, r, p, out, len);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, CRYPT_KDF_SCRYPT, ret);
        return ret;
    }
    EAL_EventReport(CRYPT_EVENT_KEYDERIVE, CRYPT_ALGO_KDF, CRYPT_KDF_SCRYPT, CRYPT_SUCCESS);
    return CRYPT_SUCCESS;
#else
    (void)key;
    (void)keyLen;
    (void)salt;
    (void)saltLen;
    (void)n;
    (void)r;
    (void)p;
    (void)out;
    (void)len;
    EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, CRYPT_KDF_SCRYPT, CRYPT_SCRYPT_NOT_SUPPORTED);
    return CRYPT_SCRYPT_NOT_SUPPORTED;
#endif
}
#endif
