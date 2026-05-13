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
#ifdef HITLS_BSL_PEM
#include <stdint.h>
#include <string.h>
#include "securec.h"
#include "bsl_errno.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "bsl_base64_internal.h"
#include "bsl_base64.h"
#include "bsl_pem_local.h"
#include "bsl_pem_internal.h"
#include "bsl_types.h"

/*
 * Length-bounded substring search, replacing strstr to prevent out-of-bounds reads
 * when the input buffer is raw binary (e.g. DER-encoded cert/key) without a '\0' terminator.
 */
static char *PemMemStr(const char *haystack, uint32_t haystackLen, const char *needle, uint32_t needleLen)
{
    if (needleLen == 0 || haystackLen < needleLen) {
        return NULL;
    }
    const char *end = haystack + haystackLen - needleLen;
    const char *p = haystack;
    while (p <= end) {
        // memchr leverages SIMD in most libc implementations to skip non-matching bytes faster than a byte-by-byte loop.
        p = memchr(p, needle[0], (size_t)(end - p + 1));
        if (p == NULL) {
            return NULL;
        }
        if (memcmp(p, needle, needleLen) == 0) {
            return (char *)(uintptr_t)p;
        }
        p++;
    }
    return NULL;
}

int32_t BSL_PEM_GetPemRealEncode(char **encode, uint32_t *encodeLen, BSL_PEM_Symbol *symbol, char **realEncode,
    uint32_t *realLen)
{
    uint32_t headLen = (uint32_t)strlen(symbol->head);
    uint32_t tailLen = (uint32_t)strlen(symbol->tail);
    if (*encodeLen < headLen + tailLen) {
        BSL_ERR_PUSH_ERROR(BSL_PEM_INVALID);
        return BSL_PEM_INVALID;
    }
    if (!BSL_PEM_IsPemFormat(*encode, *encodeLen)) {
        BSL_ERR_PUSH_ERROR(BSL_PEM_INVALID);
        return BSL_PEM_INVALID;
    }
    char *begin = PemMemStr(*encode, *encodeLen, symbol->head, headLen);
    if (begin == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_PEM_SYMBOL_NOT_FOUND);
        return BSL_PEM_SYMBOL_NOT_FOUND;
    }
    uint32_t remaining = *encodeLen - (uint32_t)(begin + headLen - *encode);
    char *end = PemMemStr(begin + headLen, remaining, symbol->tail, tailLen);
    if (end == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_PEM_SYMBOL_NOT_FOUND);
        return BSL_PEM_SYMBOL_NOT_FOUND;
    }
    *realEncode = begin + headLen;
    *realLen = end - *realEncode;
    *encodeLen -= (end - *encode + tailLen);
    *encode = end + tailLen;
    return BSL_SUCCESS;
}

// Obtain asn1 raw data
int32_t BSL_PEM_GetAsn1Encode(const char *encode, const uint32_t encodeLen, uint8_t **asn1Encode,
    uint32_t *asn1Len)
{
    uint64_t needLen = ((uint64_t)encodeLen + BASE64_ENCODE_BYTES) / BASE64_DECODE_BYTES * BASE64_ENCODE_BYTES;
    if (needLen > UINT32_MAX) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    uint32_t len = (uint32_t)needLen;
    uint8_t *asn1 = BSL_SAL_Malloc(len);
    if (asn1 == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = (int32_t)BSL_BASE64_Decode(encode, encodeLen, asn1, &len);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_Free(asn1);
        return ret;
    }
    *asn1Encode = asn1;
    *asn1Len = len;
    return BSL_SUCCESS;
}

#define PEM_LINE_LEN 64

static void PemFormatBase64(char *src, uint32_t srcLen, char **des)
{
    uint32_t len = srcLen;
    char *tmp = *des;
    while (len > PEM_LINE_LEN) {
        *tmp++ = '\n';
        (void)memcpy_s(tmp, PEM_LINE_LEN, src, PEM_LINE_LEN);
        tmp += PEM_LINE_LEN;
        src += PEM_LINE_LEN;
        len -= PEM_LINE_LEN;
    }
    *tmp++ = '\n';
    (void)memcpy_s(tmp, len, src, len);
    tmp += len;
    *tmp++ = '\n';
    *des = tmp;
}

int32_t BSL_PEM_EncodeAsn1ToPem(uint8_t *asn1Encode, uint32_t asn1Len, BSL_PEM_Symbol *symbol,
    char **encode, uint32_t *encodeLen)
{
    int32_t ret;
    uint32_t headLen = (uint32_t)strlen(symbol->head);
    uint32_t tailLen = (uint32_t)strlen(symbol->tail);
    uint64_t needLen = ((uint64_t)asn1Len + 2U) / BASE64_ENCODE_BYTES * BASE64_DECODE_BYTES + 1U;
    if (needLen > UINT32_MAX) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    uint32_t len = (uint32_t)needLen;
    char *buff = BSL_SAL_Malloc(len);
    if (buff == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    char *tmp = buff;
    char *res = NULL;
    do {
        ret = (int32_t)BSL_BASE64_Encode(asn1Encode, asn1Len, tmp, &len);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            break;
        }
        uint64_t line = ((uint64_t)len + PEM_LINE_LEN - 1) / PEM_LINE_LEN;
        uint64_t sumLen64 = line + len + headLen + tailLen + 3; // 3: \n + \n +\0
        if (sumLen64 > UINT32_MAX) {
            BSL_ERR_PUSH_ERROR(BSL_BASE64_BUF_NOT_ENOUGH);
            ret = BSL_BASE64_BUF_NOT_ENOUGH;
            break;
        }
        uint32_t sumLen = (uint32_t)sumLen64;
        res = BSL_SAL_Malloc(sumLen);
        if (res == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            ret = BSL_MALLOC_FAIL;
            break;
        }
        char *resTmp = res;
        (void)memcpy_s(resTmp, headLen, symbol->head, headLen);
        resTmp += headLen;
        PemFormatBase64(tmp, len, &resTmp);
        (void)memcpy_s(resTmp, tailLen, symbol->tail, tailLen);
        resTmp += tailLen;
        *resTmp++ = '\n';
        *resTmp++ = '\0';
        *encode = res;
        *encodeLen = sumLen - 1;
        BSL_SAL_FREE(buff);
        return BSL_SUCCESS;
    } while (0);
    BSL_SAL_FREE(buff);
    BSL_SAL_FREE(res);
    return ret;
}

int32_t BSL_PEM_DecodePemToAsn1(char **encode, uint32_t *encodeLen, BSL_PEM_Symbol *symbol, uint8_t **asn1Encode,
    uint32_t *asn1Len)
{
    char *nextEncode = *encode;
    uint32_t nextEncodeLen = *encodeLen;
    char *realEncode = NULL;
    uint32_t realLen;

    int32_t ret = BSL_PEM_GetPemRealEncode(&nextEncode, &nextEncodeLen, symbol, &realEncode, &realLen);
    if (ret != BSL_SUCCESS) {
        return ret;
    }

    ret = BSL_PEM_GetAsn1Encode(realEncode, realLen, asn1Encode, asn1Len);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *encode = nextEncode;
    *encodeLen = nextEncodeLen;
    return BSL_SUCCESS;
}

/**
 *  reference rfc7468
 *  Textual encoding begins with a line comprising "-----BEGIN ", a label, and "-----",
 *  and ends with a line comprising "-----END ", a label, and "-----".
 */
bool BSL_PEM_IsPemFormat(char *encode, uint32_t encodeLen)
{
    // 2 denote two dash after the begin and end label
    if (encode == NULL || encodeLen < (BSL_PEM_BEGIN_STR_LEN + BSL_PEM_END_STR_LEN + 2 * BSL_PEM_SHORT_DASH_STR_LEN)) {
        return false;
    }
    // match "-----BEGIN"
    char *begin = PemMemStr(encode, encodeLen, BSL_PEM_BEGIN_STR, BSL_PEM_BEGIN_STR_LEN);
    if (begin == NULL) {
        return false;
    }
    // match "-----"
    uint32_t remaining = encodeLen - (uint32_t)(begin + BSL_PEM_BEGIN_STR_LEN - encode);
    char *dashAfterBegin = PemMemStr(begin + BSL_PEM_BEGIN_STR_LEN, remaining, BSL_PEM_SHORT_DASH_STR,
        BSL_PEM_SHORT_DASH_STR_LEN);
    if (dashAfterBegin == NULL) {
        return false;
    }
    // match "-----END"
    remaining = encodeLen - (uint32_t)(dashAfterBegin + BSL_PEM_SHORT_DASH_STR_LEN - encode);
    char *end = PemMemStr(dashAfterBegin + BSL_PEM_SHORT_DASH_STR_LEN, remaining, BSL_PEM_END_STR,
        BSL_PEM_END_STR_LEN);
    if (end == NULL) {
        return false;
    }
    // match "-----"
    remaining = encodeLen - (uint32_t)(end + BSL_PEM_END_STR_LEN - encode);
    return (PemMemStr(end + BSL_PEM_END_STR_LEN, remaining, BSL_PEM_SHORT_DASH_STR,
        BSL_PEM_SHORT_DASH_STR_LEN) != NULL);
}

typedef struct {
    const char *type;
    BSL_PEM_Symbol symbol;
} PemHeaderInfo;

static PemHeaderInfo g_pemHeaderInfo[] = {
    {"PRIKEY_RSA", {BSL_PEM_RSA_PRI_KEY_BEGIN_STR, BSL_PEM_RSA_PRI_KEY_END_STR}},
    {"PRIKEY_ECC", {BSL_PEM_EC_PRI_KEY_BEGIN_STR, BSL_PEM_EC_PRI_KEY_END_STR}},
    {"PRIKEY_PKCS8_UNENCRYPT", {BSL_PEM_PRI_KEY_BEGIN_STR, BSL_PEM_PRI_KEY_END_STR}},
    {"PRIKEY_PKCS8_ENCRYPT", {BSL_PEM_P8_PRI_KEY_BEGIN_STR, BSL_PEM_P8_PRI_KEY_END_STR}},
    {"PUBKEY_SUBKEY", {BSL_PEM_PUB_KEY_BEGIN_STR, BSL_PEM_PUB_KEY_END_STR}},
    {"PUBKEY_RSA", {BSL_PEM_RSA_PUB_KEY_BEGIN_STR, BSL_PEM_RSA_PUB_KEY_END_STR}},
    {"CERT", {BSL_PEM_CERT_BEGIN_STR, BSL_PEM_CERT_END_STR}},
    {"CRL", {BSL_PEM_CRL_BEGIN_STR, BSL_PEM_CRL_END_STR}},
    {"CSR", {BSL_PEM_CERT_REQ_BEGIN_STR, BSL_PEM_CERT_REQ_END_STR}},
};

int32_t BSL_PEM_GetSymbolAndType(char *encode, uint32_t encodeLen, BSL_PEM_Symbol *symbol, const char **type)
{
    if (symbol == NULL || type == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }

    if (!BSL_PEM_IsPemFormat(encode, encodeLen)) {
        BSL_ERR_PUSH_ERROR(BSL_PEM_INVALID);
        return BSL_PEM_INVALID;
    }
    for (uint32_t i = 0; i < sizeof(g_pemHeaderInfo) / sizeof(g_pemHeaderInfo[0]); i++) {
        uint32_t headLen = (uint32_t)strlen(g_pemHeaderInfo[i].symbol.head);
        uint32_t tailLen = (uint32_t)strlen(g_pemHeaderInfo[i].symbol.tail);
        char *beginMarker = PemMemStr(encode, encodeLen, g_pemHeaderInfo[i].symbol.head, headLen);
        if (beginMarker != NULL) {
            uint32_t remaining = encodeLen - (uint32_t)(beginMarker + headLen - encode);
            if (PemMemStr(beginMarker + headLen, remaining, g_pemHeaderInfo[i].symbol.tail, tailLen) != NULL) {
                *symbol = g_pemHeaderInfo[i].symbol;
                *type = g_pemHeaderInfo[i].type;
                return BSL_SUCCESS;
            }
        }
    }

    BSL_ERR_PUSH_ERROR(BSL_PEM_SYMBOL_NOT_FOUND);
    return BSL_PEM_SYMBOL_NOT_FOUND;
}

#endif /* HITLS_BSL_PEM */
