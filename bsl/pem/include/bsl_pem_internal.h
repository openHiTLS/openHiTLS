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
#ifndef BSL_PEM_INTERNAL_H
#define BSL_PEM_INTERNAL_H

#include "hitls_build.h"
#ifdef HITLS_BSL_PEM
#include <stdint.h>
#include "bsl_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BSL_PEM_CERT_BEGIN_STR "-----BEGIN CERTIFICATE-----"
#define BSL_PEM_CERT_END_STR "-----END CERTIFICATE-----"

#define BSL_PEM_CRL_BEGIN_STR "-----BEGIN X509 CRL-----"
#define BSL_PEM_CRL_END_STR "-----END X509 CRL-----"

#define BSL_PEM_PUB_KEY_BEGIN_STR "-----BEGIN PUBLIC KEY-----"
#define BSL_PEM_PUB_KEY_END_STR "-----END PUBLIC KEY-----"

#define BSL_PEM_RSA_PUB_KEY_BEGIN_STR "-----BEGIN RSA PUBLIC KEY-----"
#define BSL_PEM_RSA_PUB_KEY_END_STR "-----END RSA PUBLIC KEY-----"

#define BSL_PEM_RSA_PRI_KEY_BEGIN_STR "-----BEGIN RSA PRIVATE KEY-----"
#define BSL_PEM_RSA_PRI_KEY_END_STR "-----END RSA PRIVATE KEY-----"

/** rfc5915 section 4 */
#define BSL_PEM_EC_PRI_KEY_BEGIN_STR "-----BEGIN EC PRIVATE KEY-----"
#define BSL_PEM_EC_PRI_KEY_END_STR "-----END EC PRIVATE KEY-----"

/** rfc5958 section 5 */
#define BSL_PEM_PRI_KEY_BEGIN_STR "-----BEGIN PRIVATE KEY-----"
#define BSL_PEM_PRI_KEY_END_STR "-----END PRIVATE KEY-----"

/** rfc5958 section 5 */
#define BSL_PEM_P8_PRI_KEY_BEGIN_STR "-----BEGIN ENCRYPTED PRIVATE KEY-----"
#define BSL_PEM_P8_PRI_KEY_END_STR "-----END ENCRYPTED PRIVATE KEY-----"

#define BSL_PEM_CERT_REQ_BEGIN_STR "-----BEGIN CERTIFICATE REQUEST-----"
#define BSL_PEM_CERT_REQ_END_STR "-----END CERTIFICATE REQUEST-----"

/* encode must end in '\0' */
bool BSL_PEM_IsPemFormat(char *encode, uint32_t encodeLen);

int32_t BSL_PEM_GetAsn1Encode(const char *encode, const uint32_t encodeLen, uint8_t **asn1Encode, uint32_t *asn1Len);

typedef struct {
    const char *head;
    const char *tail;
} BSL_PEM_Symbol;

int32_t BSL_PEM_EncodeAsn1ToPem(uint8_t *asn1Encode, uint32_t asn1Len, BSL_PEM_Symbol *symbol,
    char **encode, uint32_t *encodeLen);

/* encode must end in '\0' */
int32_t BSL_PEM_DecodePemToAsn1(char **encode, uint32_t *encodeLen, BSL_PEM_Symbol *symbol, uint8_t **asn1Encode,
    uint32_t *asn1Len);

int32_t BSL_PEM_GetPemRealEncode(char **encode, uint32_t *encodeLen, BSL_PEM_Symbol *symbol, char **realEncode,
    uint32_t *realLen);

int32_t BSL_PEM_GetSymbolAndType(char *encode, uint32_t encodeLen, BSL_PEM_Symbol *symbol, const char **type);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* HITLS_BSL_PEM */
#endif /* BSL_PEM_INTERNAL_H */