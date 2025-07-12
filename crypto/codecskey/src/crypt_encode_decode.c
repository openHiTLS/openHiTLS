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
#ifdef HITLS_CRYPTO_CODECSKEY

#include <stdint.h>
#include <string.h>

#ifdef HITLS_BSL_SAL_FILE
#include "sal_file.h"
#endif
#include "bsl_types.h"
#include "bsl_asn1.h"

#ifdef HITLS_BSL_PEM
#include "bsl_pem_internal.h"
#endif // HITLS_BSL_PEM

#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_types.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_codecs.h"
#include "crypt_encode_decode_local.h"
#include "crypt_encode_decode_key.h"

int32_t CRYPT_EAL_GetEncodeFormat(const char *format)
{
    if (format == NULL) {
        return BSL_FORMAT_UNKNOWN;
    }
    static const struct {
        const char *formatStr;
        int32_t formatInt;
    } FORMAT_MAP[] = {
        {"ASN1", BSL_FORMAT_ASN1},
        {"PEM", BSL_FORMAT_PEM},
        {"PFX_COM", BSL_FORMAT_PFX_COM},
        {"PKCS12", BSL_FORMAT_PKCS12},
        {"OBJECT", BSL_FORMAT_OBJECT}
    };

    for (size_t i = 0; i < sizeof(FORMAT_MAP) / sizeof(FORMAT_MAP[0]); i++) {
        if (strcmp(format, FORMAT_MAP[i].formatStr) == 0) {
            return FORMAT_MAP[i].formatInt;
        }
    }

    return BSL_FORMAT_UNKNOWN;
}

#ifdef HITLS_BSL_PEM
static int32_t EAL_GetPemPubKeySymbol(int32_t type, BSL_PEM_Symbol *symbol)
{
    switch (type) {
        case CRYPT_PUBKEY_SUBKEY:
            symbol->head = BSL_PEM_PUB_KEY_BEGIN_STR;
            symbol->tail = BSL_PEM_PUB_KEY_END_STR;
            return CRYPT_SUCCESS;
#ifdef HITLS_CRYPTO_RSA
        case CRYPT_PUBKEY_RSA:
            symbol->head = BSL_PEM_RSA_PUB_KEY_BEGIN_STR;
            symbol->tail = BSL_PEM_RSA_PUB_KEY_END_STR;
            return CRYPT_SUCCESS;
#endif
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_DECODE_NO_SUPPORT_TYPE);
            return CRYPT_DECODE_NO_SUPPORT_TYPE;
    }
}

static int32_t EAL_GetPemPriKeySymbol(int32_t type, BSL_PEM_Symbol *symbol)
{
    switch (type) {
#ifdef HITLS_CRYPTO_ECDSA
        case CRYPT_PRIKEY_ECC:
            symbol->head = BSL_PEM_EC_PRI_KEY_BEGIN_STR;
            symbol->tail = BSL_PEM_EC_PRI_KEY_END_STR;
            return CRYPT_SUCCESS;
#endif
#ifdef HITLS_CRYPTO_RSA
        case CRYPT_PRIKEY_RSA:
            symbol->head = BSL_PEM_RSA_PRI_KEY_BEGIN_STR;
            symbol->tail = BSL_PEM_RSA_PRI_KEY_END_STR;
            return CRYPT_SUCCESS;
#endif
        case CRYPT_PRIKEY_PKCS8_UNENCRYPT:
            symbol->head = BSL_PEM_PRI_KEY_BEGIN_STR;
            symbol->tail = BSL_PEM_PRI_KEY_END_STR;
            return CRYPT_SUCCESS;
        case CRYPT_PRIKEY_PKCS8_ENCRYPT:
            symbol->head = BSL_PEM_P8_PRI_KEY_BEGIN_STR;
            symbol->tail = BSL_PEM_P8_PRI_KEY_END_STR;
            return CRYPT_SUCCESS;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_DECODE_NO_SUPPORT_TYPE);
            return CRYPT_DECODE_NO_SUPPORT_TYPE;
    }
}
#endif // HITLS_BSL_PEM

#ifdef HITLS_CRYPTO_KEY_DECODE
int32_t CRYPT_EAL_ParseAsn1PriKey(int32_t type, BSL_Buffer *encode, const BSL_Buffer *pwd,
    CRYPT_EAL_PkeyCtx **ealPriKey)
{
    (void)pwd;
    switch (type) {
#ifdef HITLS_CRYPTO_ECDSA
        case CRYPT_PRIKEY_ECC:
            return ParseEccPrikeyAsn1Buff(encode->data, encode->dataLen, NULL, ealPriKey);
#endif
#ifdef HITLS_CRYPTO_RSA
        case CRYPT_PRIKEY_RSA:
            return ParseRsaPrikeyAsn1Buff(encode->data, encode->dataLen, NULL, BSL_CID_UNKNOWN,
                ealPriKey);
#endif
        case CRYPT_PRIKEY_PKCS8_UNENCRYPT:
            return ParsePk8PriKeyBuff(encode, ealPriKey);
#ifdef HITLS_CRYPTO_KEY_EPKI
        case CRYPT_PRIKEY_PKCS8_ENCRYPT:
            return ParsePk8EncPriKeyBuff(encode, pwd, ealPriKey);
#endif
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_DECODE_NO_SUPPORT_TYPE);
            return CRYPT_DECODE_NO_SUPPORT_TYPE;
    }
}

#ifdef HITLS_BSL_PEM
int32_t CRYPT_EAL_ParsePemPriKey(int32_t type, BSL_Buffer *encode, const BSL_Buffer *pwd,
    CRYPT_EAL_PkeyCtx **ealPriKey)
{
    BSL_PEM_Symbol symbol = {0};
    int32_t ret = EAL_GetPemPriKeySymbol(type, &symbol);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    BSL_Buffer asn1 = {0};
    ret = BSL_PEM_DecodePemToAsn1((char **)&(encode->data), &(encode->dataLen), &symbol, &(asn1.data),
        &(asn1.dataLen));
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CRYPT_EAL_ParseAsn1PriKey(type, &asn1, pwd, ealPriKey);
    BSL_SAL_Free(asn1.data);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}
#endif // HITLS_BSL_PEM

int32_t CRYPT_EAL_ParseUnknownPriKey(int32_t type, BSL_Buffer *encode, const BSL_Buffer *pwd,
    CRYPT_EAL_PkeyCtx **ealPriKey)
{
#ifdef HITLS_BSL_PEM
    bool isPem = BSL_PEM_IsPemFormat((char *)(encode->data), encode->dataLen);
    if (isPem) {
        return CRYPT_EAL_ParsePemPriKey(type, encode, pwd, ealPriKey);
    }
#endif
    return CRYPT_EAL_ParseAsn1PriKey(type, encode, pwd, ealPriKey);
}

int32_t CRYPT_EAL_PriKeyParseBuff(BSL_ParseFormat format, int32_t type, BSL_Buffer *encode, const BSL_Buffer *pwd,
    CRYPT_EAL_PkeyCtx **ealPriKey)
{
    if (encode == NULL || encode->data == NULL || encode->dataLen == 0 || ealPriKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    switch (format) {
        case BSL_FORMAT_ASN1:
            return CRYPT_EAL_ParseAsn1PriKey(type, encode, pwd, ealPriKey);
#ifdef HITLS_BSL_PEM
        case BSL_FORMAT_PEM:
            return CRYPT_EAL_ParsePemPriKey(type, encode, pwd, ealPriKey);
#endif // HITLS_BSL_PEM
        case BSL_FORMAT_UNKNOWN:
            return CRYPT_EAL_ParseUnknownPriKey(type, encode, pwd, ealPriKey);
        default:
            return CRYPT_DECODE_NO_SUPPORT_FORMAT;
    }
}

int32_t CRYPT_EAL_ParseAsn1PubKey(int32_t type, BSL_Buffer *encode, CRYPT_EAL_PkeyCtx **ealPubKey)
{
    switch (type) {
        case CRYPT_PUBKEY_SUBKEY_WITHOUT_SEQ:
            return CRYPT_EAL_ParseAsn1SubPubkey(encode->data, encode->dataLen, (void **)ealPubKey, false);
        case CRYPT_PUBKEY_SUBKEY:
            return CRYPT_EAL_ParseAsn1SubPubkey(encode->data, encode->dataLen, (void **)ealPubKey, true);
        default:
#ifdef HITLS_CRYPTO_RSA
            return ParseRsaPubkeyAsn1Buff(encode->data, encode->dataLen, NULL, ealPubKey, BSL_CID_UNKNOWN);
#else
            return CRYPT_DECODE_NO_SUPPORT_TYPE;
#endif
    }
}

#ifdef HITLS_BSL_PEM
int32_t CRYPT_EAL_ParsePemPubKey(int32_t type, BSL_Buffer *encode, CRYPT_EAL_PkeyCtx **ealPubKey)
{
    BSL_PEM_Symbol symbol = {0};
    int32_t ret = EAL_GetPemPubKeySymbol(type, &symbol);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    BSL_Buffer asn1 = {0};
    ret = BSL_PEM_DecodePemToAsn1((char **)&(encode->data), &(encode->dataLen), &symbol, &(asn1.data), &(asn1.dataLen));
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CRYPT_EAL_ParseAsn1PubKey(type, &asn1, ealPubKey);
    BSL_SAL_Free(asn1.data);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

#endif // HITLS_BSL_PEM
int32_t CRYPT_EAL_ParseUnknownPubKey(int32_t type, BSL_Buffer *encode, CRYPT_EAL_PkeyCtx **ealPubKey)
{
#ifdef HITLS_BSL_PEM
    bool isPem = BSL_PEM_IsPemFormat((char *)(encode->data), encode->dataLen);
    if (isPem) {
        return CRYPT_EAL_ParsePemPubKey(type, encode, ealPubKey);
    }
#endif
    return CRYPT_EAL_ParseAsn1PubKey(type, encode, ealPubKey);
}

int32_t CRYPT_EAL_PubKeyParseBuff(BSL_ParseFormat format, int32_t type, BSL_Buffer *encode,
    CRYPT_EAL_PkeyCtx **ealPubKey)
{
    if (encode == NULL || encode->data == NULL || encode->dataLen == 0 || ealPubKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    switch (format) {
        case BSL_FORMAT_ASN1:
            return CRYPT_EAL_ParseAsn1PubKey(type, encode, ealPubKey);
#ifdef HITLS_BSL_PEM
        case BSL_FORMAT_PEM:
            return CRYPT_EAL_ParsePemPubKey(type, encode, ealPubKey);
#endif // HITLS_BSL_PEM
        case BSL_FORMAT_UNKNOWN:
            return CRYPT_EAL_ParseUnknownPubKey(type, encode, ealPubKey);
        default:
            return CRYPT_DECODE_NO_SUPPORT_FORMAT;
    }
}

int32_t CRYPT_EAL_UnKnownKeyParseBuff(BSL_ParseFormat format, const BSL_Buffer *pwd, BSL_Buffer *encode,
    CRYPT_EAL_PkeyCtx **ealPKey)
{
    int32_t ret;
    for (int32_t type = CRYPT_PRIKEY_PKCS8_UNENCRYPT; type <= CRYPT_PRIKEY_ECC; type++) {
        ret = CRYPT_EAL_PriKeyParseBuff(format, type, encode, pwd, ealPKey);
        if (ret == CRYPT_SUCCESS) {
            return ret;
        }
    }

    for (int32_t type = CRYPT_PUBKEY_SUBKEY; type <= CRYPT_PUBKEY_SUBKEY_WITHOUT_SEQ; type++) {
        ret = CRYPT_EAL_PubKeyParseBuff(format, type, encode, ealPKey);
        if (ret == CRYPT_SUCCESS) {
            return ret;
        }
    }

    return CRYPT_DECODE_NO_SUPPORT_TYPE;
}

int32_t CRYPT_EAL_DecodeBuffKey(int32_t format, int32_t type, BSL_Buffer *encode,
    const uint8_t *pwd, uint32_t pwdlen, CRYPT_EAL_PkeyCtx **ealPKey)
{
    BSL_Buffer pwdBuffer = {(uint8_t *)(uintptr_t)pwd, pwdlen};
    switch (type) {
        case CRYPT_PRIKEY_PKCS8_UNENCRYPT:
        case CRYPT_PRIKEY_PKCS8_ENCRYPT:
#ifdef HITLS_CRYPTO_ECDSA
        case CRYPT_PRIKEY_ECC:
#endif
#ifdef HITLS_CRYPTO_RSA
        case CRYPT_PRIKEY_RSA:
#endif
            return CRYPT_EAL_PriKeyParseBuff(format, type, encode, &pwdBuffer, ealPKey);
        case CRYPT_PUBKEY_SUBKEY_WITHOUT_SEQ:
        case CRYPT_PUBKEY_SUBKEY:
#ifdef HITLS_CRYPTO_RSA
        case CRYPT_PUBKEY_RSA:
#endif
            return CRYPT_EAL_PubKeyParseBuff(format, type, encode, ealPKey);
        case CRYPT_ENCDEC_UNKNOW:
            return CRYPT_EAL_UnKnownKeyParseBuff(format, &pwdBuffer, encode, ealPKey);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_DECODE_NO_SUPPORT_TYPE);
            return CRYPT_DECODE_NO_SUPPORT_TYPE;
    }
}

#ifdef HITLS_BSL_SAL_FILE
int32_t CRYPT_EAL_PriKeyParseFile(BSL_ParseFormat format, int32_t type, const char *path, const BSL_Buffer *pwd,
    CRYPT_EAL_PkeyCtx **ealPriKey)
{
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    int32_t ret = BSL_SAL_ReadFile(path, &data, &dataLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_Buffer encode = {data, dataLen};
    ret = CRYPT_EAL_PriKeyParseBuff(format, type, &encode, pwd, ealPriKey);
    BSL_SAL_Free(data);
    return ret;
}

int32_t CRYPT_EAL_PubKeyParseFile(BSL_ParseFormat format, int32_t type, const char *path, CRYPT_EAL_PkeyCtx **ealPubKey)
{
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    int32_t ret = BSL_SAL_ReadFile(path, &data, &dataLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_Buffer encode = {data, dataLen};
    ret = CRYPT_EAL_PubKeyParseBuff(format, type, &encode, ealPubKey);
    BSL_SAL_Free(data);
    return ret;
}

int32_t CRYPT_EAL_UnKnownKeyParseFile(BSL_ParseFormat format, const char *path, const BSL_Buffer *pwd,
    CRYPT_EAL_PkeyCtx **ealKey)
{
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    int32_t ret = BSL_SAL_ReadFile(path, &data, &dataLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_Buffer encode = {data, dataLen};
    ret = CRYPT_EAL_UnKnownKeyParseBuff(format, pwd, &encode, ealKey);
    BSL_SAL_Free(data);
    return ret;
}

int32_t CRYPT_EAL_DecodeFileKey(int32_t format, int32_t type, const char *path,
    uint8_t *pwd, uint32_t pwdlen, CRYPT_EAL_PkeyCtx **ealPKey)
{
    BSL_Buffer pwdBuffer = {(uint8_t *)pwd, pwdlen};
    if (path == NULL || strlen(path) > PATH_MAX_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    switch (type) {
        case CRYPT_PRIKEY_PKCS8_UNENCRYPT:
        case CRYPT_PRIKEY_PKCS8_ENCRYPT:
#ifdef HITLS_CRYPTO_RSA
        case CRYPT_PRIKEY_RSA:
#endif
#ifdef HITLS_CRYPTO_ECDSA
        case CRYPT_PRIKEY_ECC:
#endif
            return CRYPT_EAL_PriKeyParseFile(format, type, path, &pwdBuffer, ealPKey);
        case CRYPT_PUBKEY_SUBKEY_WITHOUT_SEQ:
        case CRYPT_PUBKEY_SUBKEY:
#ifdef HITLS_CRYPTO_RSA
        case CRYPT_PUBKEY_RSA:
            return CRYPT_EAL_PubKeyParseFile(format, type, path, ealPKey);
#endif
        case CRYPT_ENCDEC_UNKNOW:
            return CRYPT_EAL_UnKnownKeyParseFile(format, path, &pwdBuffer, ealPKey);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_DECODE_NO_SUPPORT_TYPE);
            return CRYPT_DECODE_NO_SUPPORT_TYPE;
    }
}
#endif // HITLS_BSL_SAL_FILE

#endif // HITLS_CRYPTO_KEY_DECODE

#ifdef HITLS_CRYPTO_KEY_ENCODE

int32_t CRYPT_EAL_EncodeAsn1PriKey(CRYPT_EAL_LibCtx *libCtx, const char *attrName, CRYPT_EAL_PkeyCtx *ealPriKey,
    const CRYPT_EncodeParam *encodeParam, int32_t type, BSL_Buffer *encode)
{
#ifndef HITLS_CRYPTO_KEY_EPKI
    (void)libCtx;
    (void)attrName;
    (void)encodeParam;
#endif
    switch (type) {
#ifdef HITLS_CRYPTO_ECDSA
        case CRYPT_PRIKEY_ECC:
            return EncodeEccPrikeyAsn1Buff(ealPriKey, NULL, encode);
#endif
#ifdef HITLS_CRYPTO_RSA
        case CRYPT_PRIKEY_RSA:
            return EncodeRsaPrikeyAsn1Buff(ealPriKey, CRYPT_PKEY_RSA, encode);
#endif
        case CRYPT_PRIKEY_PKCS8_UNENCRYPT:
            return EncodePk8PriKeyBuff(ealPriKey, encode);
#ifdef HITLS_CRYPTO_KEY_EPKI
        case CRYPT_PRIKEY_PKCS8_ENCRYPT:
            return EncodePk8EncPriKeyBuff(libCtx, attrName, ealPriKey, encodeParam, encode);
#endif
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_ENCODE_NO_SUPPORT_FORMAT);
            return CRYPT_ENCODE_NO_SUPPORT_FORMAT;
    }
}

#ifdef HITLS_BSL_PEM
int32_t CRYPT_EAL_EncodePemPriKey(CRYPT_EAL_LibCtx *libCtx, const char *attrName, CRYPT_EAL_PkeyCtx *ealPriKey,
    const CRYPT_EncodeParam *encodeParam, int32_t type, BSL_Buffer *encode)
{
    BSL_Buffer asn1 = {0};
    int32_t ret = CRYPT_EAL_EncodeAsn1PriKey(libCtx, attrName, ealPriKey, encodeParam, type, &asn1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_PEM_Symbol symbol = {0};
    ret = EAL_GetPemPriKeySymbol(type, &symbol);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(asn1.data);
        return ret;
    }
    ret = BSL_PEM_EncodeAsn1ToPem(asn1.data, asn1.dataLen, &symbol, (char **)&encode->data, &encode->dataLen);
    BSL_SAL_Free(asn1.data);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}
#endif // HITLS_BSL_PEM

int32_t CRYPT_EAL_PriKeyEncodeBuff(CRYPT_EAL_LibCtx *libCtx, const char *attrName, CRYPT_EAL_PkeyCtx *ealPriKey,
    const CRYPT_EncodeParam *encodeParam, BSL_ParseFormat format, int32_t type, BSL_Buffer *encode)
{
    if (ealPriKey == NULL || encode == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    switch (format) {
        case BSL_FORMAT_ASN1:
            return CRYPT_EAL_EncodeAsn1PriKey(libCtx, attrName, ealPriKey, encodeParam, type, encode);
#ifdef HITLS_BSL_PEM
        case BSL_FORMAT_PEM:
            return CRYPT_EAL_EncodePemPriKey(libCtx, attrName, ealPriKey, encodeParam, type, encode);
#endif // HITLS_BSL_PEM
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_ENCODE_NO_SUPPORT_FORMAT);
            return CRYPT_ENCODE_NO_SUPPORT_FORMAT;
    }
}

int32_t CRYPT_EAL_PubKeyEncodeBuff(CRYPT_EAL_PkeyCtx *ealPubKey,
    BSL_ParseFormat format, int32_t type, BSL_Buffer *encode)
{
    return CRYPT_EAL_EncodePubKeyBuffInternal(ealPubKey, format, type, true, encode);
}

int32_t CRYPT_EAL_GetEncodeType(const char *type)
{
    if (type == NULL) {
        return CRYPT_ENCDEC_UNKNOW;
    }
    static const struct {
        const char *typeStr;
        int32_t typeInt;
    } TYPE_MAP[] = {
        {"PRIKEY_PKCS8_UNENCRYPT", CRYPT_PRIKEY_PKCS8_UNENCRYPT},
        {"PRIKEY_PKCS8_ENCRYPT", CRYPT_PRIKEY_PKCS8_ENCRYPT},
        {"PRIKEY_RSA", CRYPT_PRIKEY_RSA},
        {"PRIKEY_ECC", CRYPT_PRIKEY_ECC},
        {"PUBKEY_SUBKEY", CRYPT_PUBKEY_SUBKEY},
        {"PUBKEY_RSA", CRYPT_PUBKEY_RSA},
        {"PUBKEY_SUBKEY_WITHOUT_SEQ", CRYPT_PUBKEY_SUBKEY_WITHOUT_SEQ}
    };

    for (size_t i = 0; i < sizeof(TYPE_MAP) / sizeof(TYPE_MAP[0]); i++) {
        if (strcmp(type, TYPE_MAP[i].typeStr) == 0) {
            return TYPE_MAP[i].typeInt;
        }
    }

    return CRYPT_ENCDEC_UNKNOW;
}

static int32_t ProviderEncodeBuffKeyInternal(CRYPT_EAL_LibCtx *libCtx, const char *attrName, CRYPT_EAL_PkeyCtx *ealPKey,
    const CRYPT_EncodeParam *encodeParam, int32_t format, int32_t type, BSL_Buffer *encode)
{
    switch (type) {
        case CRYPT_PRIKEY_PKCS8_UNENCRYPT:
        case CRYPT_PRIKEY_PKCS8_ENCRYPT:
#ifdef HITLS_CRYPTO_RSA
        case CRYPT_PRIKEY_RSA:
#endif
#ifdef HITLS_CRYPTO_ECDSA
        case CRYPT_PRIKEY_ECC:
#endif
            return CRYPT_EAL_PriKeyEncodeBuff(libCtx, attrName, ealPKey, encodeParam, format, type, encode);
        case CRYPT_PUBKEY_SUBKEY:
#ifdef HITLS_CRYPTO_RSA
        case CRYPT_PUBKEY_RSA:
#endif
            return CRYPT_EAL_PubKeyEncodeBuff(ealPKey, format, type, encode);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_ENCODE_NO_SUPPORT_TYPE);
            return CRYPT_ENCODE_NO_SUPPORT_TYPE;
    }
}

int32_t CRYPT_EAL_ProviderEncodeBuffKey(CRYPT_EAL_LibCtx *libCtx, const char *attrName, CRYPT_EAL_PkeyCtx *ealPKey,
    const CRYPT_EncodeParam *encodeParam, const char *format, const char *type, BSL_Buffer *encode)
{
    int32_t encodeType = CRYPT_EAL_GetEncodeType(type);
    int32_t encodeFormat = CRYPT_EAL_GetEncodeFormat(format);
    return ProviderEncodeBuffKeyInternal(libCtx, attrName, ealPKey, encodeParam, encodeFormat, encodeType, encode);
}

int32_t CRYPT_EAL_EncodeBuffKey(CRYPT_EAL_PkeyCtx *ealPKey, const CRYPT_EncodeParam *encodeParam,
    int32_t format, int32_t type, BSL_Buffer *encode)
{
    return ProviderEncodeBuffKeyInternal(NULL, NULL, ealPKey, encodeParam, format, type, encode);
}

static int32_t CRYPT_EAL_EncodeAsn1PubKey(CRYPT_EAL_PkeyCtx *ealPubKey,
    int32_t type, bool isComplete, BSL_Buffer *encode)
{
    switch (type) {
        case CRYPT_PUBKEY_SUBKEY:
            return CRYPT_EAL_EncodeAsn1SubPubkey(ealPubKey, isComplete, encode);
#ifdef HITLS_CRYPTO_RSA
        case CRYPT_PUBKEY_RSA:
            return EncodeRsaPubkeyAsn1Buff(ealPubKey, NULL, encode);
#endif
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_ENCODE_NO_SUPPORT_TYPE);
            return CRYPT_ENCODE_NO_SUPPORT_TYPE;
    }
}

#ifdef HITLS_BSL_PEM
static int32_t CRYPT_EAL_EncodePemPubKey(CRYPT_EAL_PkeyCtx *ealPubKey,
    int32_t type, bool isComplete, BSL_Buffer *encode)
{
    BSL_Buffer asn1 = {0};
    int32_t ret = CRYPT_EAL_EncodeAsn1PubKey(ealPubKey, type, isComplete, &asn1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_PEM_Symbol symbol = {0};
    ret = EAL_GetPemPubKeySymbol(type, &symbol);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(asn1.data);
        return ret;
    }
    ret = BSL_PEM_EncodeAsn1ToPem(asn1.data, asn1.dataLen, &symbol, (char **)&encode->data, &encode->dataLen);
    BSL_SAL_Free(asn1.data);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}
#endif // HITLS_BSL_PEM

int32_t CRYPT_EAL_EncodePubKeyBuffInternal(CRYPT_EAL_PkeyCtx *ealPubKey,
    BSL_ParseFormat format, int32_t type, bool isComplete, BSL_Buffer *encode)
{
    if (ealPubKey == NULL || encode == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    switch (format) {
        case BSL_FORMAT_ASN1:
            return CRYPT_EAL_EncodeAsn1PubKey(ealPubKey, type, isComplete, encode);
#ifdef HITLS_BSL_PEM
        case BSL_FORMAT_PEM:
            return CRYPT_EAL_EncodePemPubKey(ealPubKey, type, isComplete, encode);
#endif // HITLS_BSL_PEM
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_ENCODE_NO_SUPPORT_FORMAT);
            return CRYPT_ENCODE_NO_SUPPORT_FORMAT;
    }
}

#ifdef HITLS_BSL_SAL_FILE
int32_t CRYPT_EAL_PriKeyEncodeFile(CRYPT_EAL_LibCtx *libCtx, const char *attrName, CRYPT_EAL_PkeyCtx *ealPriKey,
    const CRYPT_EncodeParam *encodeParam, BSL_ParseFormat format, int32_t type, const char *path)
{
    BSL_Buffer encode = {0};
    int32_t ret = CRYPT_EAL_PriKeyEncodeBuff(libCtx, attrName, ealPriKey, encodeParam, format, type, &encode);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BSL_SAL_WriteFile(path, encode.data, encode.dataLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    BSL_SAL_Free(encode.data);
    return ret;
}

int32_t CRYPT_EAL_PubKeyEncodeFile(CRYPT_EAL_PkeyCtx *ealPubKey, BSL_ParseFormat format, int32_t type, const char *path)
{
    BSL_Buffer encode = {0};
    int32_t ret = CRYPT_EAL_PubKeyEncodeBuff(ealPubKey, format, type, &encode);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BSL_SAL_WriteFile(path, encode.data, encode.dataLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    BSL_SAL_FREE(encode.data);
    return ret;
}

static int32_t ProviderEncodeFileKeyInternal(CRYPT_EAL_LibCtx *libCtx, const char *attrName, CRYPT_EAL_PkeyCtx *ealPKey,
    const CRYPT_EncodeParam *encodeParam, int32_t format, int32_t type, const char *path)
{
    if (path == NULL || strlen(path) > PATH_MAX_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    switch (type) {
        case CRYPT_PRIKEY_PKCS8_UNENCRYPT:
        case CRYPT_PRIKEY_PKCS8_ENCRYPT:
#ifdef HITLS_CRYPTO_RSA
        case CRYPT_PRIKEY_RSA:
#endif
#ifdef HITLS_CRYPTO_ECDSA
        case CRYPT_PRIKEY_ECC:
#endif
            return CRYPT_EAL_PriKeyEncodeFile(libCtx, attrName, ealPKey, encodeParam, format, type, path);
        case CRYPT_PUBKEY_SUBKEY:
#ifdef HITLS_CRYPTO_RSA
        case CRYPT_PUBKEY_RSA:
#endif
            return CRYPT_EAL_PubKeyEncodeFile(ealPKey, format, type, path);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_ENCODE_NO_SUPPORT_TYPE);
            return CRYPT_ENCODE_NO_SUPPORT_TYPE;
    }
}

int32_t CRYPT_EAL_ProviderEncodeFileKey(CRYPT_EAL_LibCtx *libCtx, const char *attrName, CRYPT_EAL_PkeyCtx *ealPKey,
    const CRYPT_EncodeParam *encodeParam, const char *format, const char *type, const char *path)
{
    int32_t encodeType = CRYPT_EAL_GetEncodeType(type);
    int32_t encodeFormat = CRYPT_EAL_GetEncodeFormat(format);
    return ProviderEncodeFileKeyInternal(libCtx, attrName, ealPKey, encodeParam, encodeFormat, encodeType, path);
}

int32_t CRYPT_EAL_EncodeFileKey(CRYPT_EAL_PkeyCtx *ealPKey, const CRYPT_EncodeParam *encodeParam,
    int32_t format, int32_t type, const char *path)
{
    return ProviderEncodeFileKeyInternal(NULL, NULL, ealPKey, encodeParam, format, type, path);
}
#endif // HITLS_BSL_SAL_FILE

#endif // HITLS_CRYPTO_KEY_ENCODE

#endif // HITLS_CRYPTO_CODECSKEY
