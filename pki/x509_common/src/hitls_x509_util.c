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
#ifdef HITLS_PKI_X509_CRT
#include <string.h>
#include <ctype.h>
#include "hitls_pki_errno.h"
#include "securec.h"
#include "bsl_sal.h"
#include "hitls_pki_types.h"
#include "bsl_list.h"
#include "hitls_x509_local.h"
#include "hitls_pki_cert.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"

/**
 *  Matches a string against a pattern containing exactly one wildcard ('*').
 *  The wildcard matches zero or more characters.
*/
static int32_t WildcardMatchLabel(const char *pattern, size_t pLen, const char *text, size_t tLen)
{
    const char *star = (const char *)memchr(pattern, '*', pLen);
    if (star == NULL) {
        return HITLS_X509_ERR_VFY_HOSTNAME_FAIL;
    }
    size_t prefixLen = star - pattern;
    size_t suffixLen = pLen - prefixLen - 1;
    if (tLen < prefixLen + suffixLen) {
        return HITLS_X509_ERR_VFY_HOSTNAME_FAIL;
    }

    // Match prefix from the beginning
    for (size_t i = 0; i < prefixLen; i++) {
        if (tolower((unsigned char)pattern[i]) != tolower((unsigned char)text[i])) {
            return HITLS_X509_ERR_VFY_HOSTNAME_FAIL;
        }
    }

    // Match suffix from the end
    const char *pSuffix = star + 1;
    for (size_t i = 0; i < suffixLen; i++) {
        if (tolower((unsigned char)pSuffix[suffixLen - 1 - i]) != tolower((unsigned char)text[tLen - 1 - i])) {
            return HITLS_X509_ERR_VFY_HOSTNAME_FAIL;
        }
    }

    return HITLS_PKI_SUCCESS;
}

/* ref RFC9525, If wildcards exist, only the leftmost tag with anasterisk
  (*) will be supported, and only *.openhitls.com matches will be supported. */
static int32_t MatchWithSingleWildcard(const char *pattern, const char *hostname)
{
    const char *pDot = strchr(pattern, '*');
    // If no wildcard is present in the pattern, perform a simple case-insensitive exact match.
    if (pDot == NULL) {
        return BSL_SAL_StrcaseCmp(pattern, hostname) == 0 ?
            HITLS_PKI_SUCCESS : HITLS_X509_ERR_VFY_HOSTNAME_FAIL;
    }
    //  Wildcard must be in the first label: must start with "*."
    // due to the pDot is != NULL, so the pDot + 1 is valid.
    if (pDot != pattern || *(pDot + 1) != '.') {
        return HITLS_X509_ERR_VFY_HOSTNAME_FAIL;
    }
    pDot++; // pDot point to the first label after '*'
    const char *hDot = strchr(hostname, '.');
    // Hostname must have a matching domain part, and wildcard must not match a dot.
    if (hDot == NULL || strchr(hDot + 1, '.') == NULL) {
        // Hostname must have at least 2 labels to match a wildcard pattern (e.g., foo.bar)
        return HITLS_X509_ERR_VFY_HOSTNAME_FAIL;
    }

    //  The domain parts must match exactly (case-insensitive).
    if (BSL_SAL_StrcaseCmp(pDot, hDot) != 0) {
        return HITLS_X509_ERR_VFY_HOSTNAME_FAIL;
    }
    return HITLS_PKI_SUCCESS;
}

/* ref RFC6125 to support that match rules similar to  *.a.com matches foo.a.com,
    f*.com matches foo.com. */
static int32_t MatchWithPartialWildcard(const char *pattern, const char *hostname)
{
    const char *p = pattern;
    const char *h = hostname;
    int32_t labelCount = 0;
    while (*p != '\0' && *h != '\0') {
        int32_t wildcardCount = 0;
        const char *pDot = strchr(p, '.');
        const char *hDot = strchr(h, '.');

        size_t pLen = (pDot == NULL) ? strlen(p) : (size_t)(pDot - p);
        size_t hLen = (hDot == NULL) ? strlen(h) : (size_t)(hDot - h);

        for (size_t i = 0; i < pLen; i++) {
            if (p[i] == '*') {
                wildcardCount++;
            }
        }
        if (wildcardCount > 1) { // only one wildcard is allowed in the pattern
            return HITLS_X509_ERR_VFY_HOSTNAME_FAIL;
        }

        if (wildcardCount == 1) {
            // only one wildcard is allowed in the fisrt label.
            if (labelCount != 0 || WildcardMatchLabel(p, pLen, h, hLen) != HITLS_PKI_SUCCESS) {
                return HITLS_X509_ERR_VFY_HOSTNAME_FAIL;
            }
            labelCount++;
        } else {
            if (pLen > 0 && BSL_SAL_StrcaseCmp(p, h) != 0) {
                return HITLS_X509_ERR_VFY_HOSTNAME_FAIL;
            }
        }
        if (pDot == NULL && hDot == NULL) {
            return HITLS_PKI_SUCCESS;
        }
        if ((pDot == NULL) != (hDot == NULL)) {
            return HITLS_X509_ERR_VFY_HOSTNAME_FAIL;
        }

        p = pDot + 1;
        h = hDot + 1;

        labelCount++;
    }
    if (*p == '\0' && *h == '\0') {
        return HITLS_PKI_SUCCESS;
    }
    return HITLS_X509_ERR_VFY_HOSTNAME_FAIL;
}

int32_t HITLS_X509_MatchPattern(uint32_t flags, const char *pattern, const char *hostname)
{
    if (pattern == NULL || hostname == NULL) {
        return HITLS_X509_ERR_VFY_HOSTNAME_FAIL;
    }
    if ((flags & HITLS_X509_FLAG_VFY_WITH_PARTIAL_WILDCARD) != 0) {
        return MatchWithPartialWildcard(pattern, hostname);
    }
    return MatchWithSingleWildcard(pattern, hostname);
}

int32_t X509_VerifyHostnameWithSan(HITLS_X509_Cert *cert, const char *hostname,
    int32_t (*MatchCb)(const char *pattern, const char *hostname))
{
    HITLS_X509_ExtSan san = {0};
    int32_t ret = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_GET_SAN, &san, sizeof(san));
    if (ret != HITLS_PKI_SUCCESS || san.names == NULL) {
        return HITLS_X509_ERR_EXT_NOT_FOUND;
    }
    ret = HITLS_X509_ERR_VFY_HOSTNAME_FAIL;
    HITLS_X509_GeneralName *gn = BSL_LIST_GET_FIRST(san.names);
    while (gn != NULL) {
        if (gn->type == HITLS_X509_GN_DNS) {
            char *dnsName = (char *)BSL_SAL_Malloc(gn->value.dataLen + 1);
            if (dnsName == NULL) {
                BSL_LIST_FREE(san.names, NULL);
                return BSL_MALLOC_FAIL;
            }
            (void)memcpy_s(dnsName, gn->value.dataLen + 1, gn->value.data, gn->value.dataLen);
            dnsName[gn->value.dataLen] = '\0';
            ret = MatchCb(dnsName, hostname);
            BSL_SAL_Free(dnsName);
            if (ret == HITLS_PKI_SUCCESS) {
                break;
            }
        }
        gn = BSL_LIST_GET_NEXT(san.names);
    }

    BSL_LIST_FREE(san.names, NULL);
    return ret;
}

int32_t X509_VerifyHostnameWithCn(HITLS_X509_Cert *cert, const char *hostname,
    int32_t (*MatchCb)(const char *pattern, const char *hostname))
{
    BSL_Buffer cnName = {0};
    int32_t ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_SUBJECT_CN_STR, &cnName, sizeof(cnName));
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = MatchCb((const char *)cnName.data, hostname);
    BSL_SAL_Free(cnName.data);
    return ret;
}
 
int32_t HITLS_X509_VerifyHostname(HITLS_X509_Cert *cert, uint32_t flags, const char *hostname, uint32_t hostnameLen)
{
    if (cert == NULL || hostname == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    if (hostnameLen != (uint32_t)strlen(hostname)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    // according to flag to select match function callback
    int32_t (*MatchCb)(const char *pattern, const char *hostname);
    if ((flags & HITLS_X509_FLAG_VFY_WITH_PARTIAL_WILDCARD) != 0) {
        MatchCb = MatchWithPartialWildcard; // ref RFC6125
    } else {
        MatchCb = MatchWithSingleWildcard; // ref RFC9525
    }

    int32_t ret = X509_VerifyHostnameWithSan(cert, hostname, MatchCb);
    // For compatibility with RFC6125, if SAN is not present, fall back to checking CN.
    if (ret == HITLS_X509_ERR_EXT_NOT_FOUND) {
        return X509_VerifyHostnameWithCn(cert, hostname, MatchCb);
    }
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t HITLS_X509_CheckKey(HITLS_X509_Cert *cert, CRYPT_EAL_PkeyCtx *prvKey)
{
    if (cert == NULL || prvKey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    // Get public key from certificate
    CRYPT_EAL_PkeyCtx *pubKey = NULL;
    int32_t ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_PUBKEY, &pubKey, sizeof(CRYPT_EAL_PkeyCtx *));
    if (ret != HITLS_PKI_SUCCESS || pubKey == NULL) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = CRYPT_EAL_PkeyPairCheck(pubKey, prvKey); // cmp cal speed is higher than CheckPair's.
    CRYPT_EAL_PkeyFreeCtx(pubKey);
    if (ret != CRYPT_SUCCESS ) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CERT_NOT_MATCH_KEY);
        return HITLS_X509_ERR_CERT_NOT_MATCH_KEY;
    }
    return HITLS_PKI_SUCCESS;
}
#endif // HITLS_PKI_X509_CRT
