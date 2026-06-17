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

#include <string.h>
#include <ctype.h>
#include "hitls_build.h"
#include "hitls_pki_errno.h"
#include "bsl_sal.h"
#include "hitls_pki_types.h"
#include "bsl_list.h"
#include "hitls_x509_local.h"
#include "hitls_pki_cert.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "sal_ip_util.h"
#include "hitls_pki_x509.h"

#ifdef HITLS_PKI_X509_VFY_IDENTITY
typedef struct {
    const char *data;
    uint32_t len;
} X509_StringView;

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

static int32_t CaseCmpView(const X509_StringView *left, const X509_StringView *right)
{
    if (left->len != right->len) {
        return HITLS_X509_ERR_VFY_HOSTNAME_FAIL;
    }
    for (uint32_t i = 0; i < left->len; i++) {
        if (tolower((unsigned char)left->data[i]) != tolower((unsigned char)right->data[i])) {
            return HITLS_X509_ERR_VFY_HOSTNAME_FAIL;
        }
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t CopyViewToString(const X509_StringView *view, char **str)
{
    if (view->len == 0 || BSL_SAL_Memchr(view->data, '\0', view->len) != NULL) {
        return HITLS_X509_ERR_VFY_HOSTNAME_FAIL;
    }
    *str = BSL_SAL_Malloc(view->len + 1);
    if (*str == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    (void)memcpy(*str, view->data, view->len);
    (*str)[view->len] = '\0';
    return HITLS_PKI_SUCCESS;
}

static const char *FindCharInView(const char *data, uint32_t len, char ch)
{
    for (uint32_t i = 0; i < len; i++) {
        if (data[i] == ch) {
            return data + i;
        }
    }
    return NULL;
}

static const char *FindLastCharInView(const char *data, uint32_t len, char ch)
{
    for (uint32_t i = len; i > 0; i--) {
        if (data[i - 1] == ch) {
            return data + i - 1;
        }
    }
    return NULL;
}

static uint32_t FindUriPartEnd(const char *data, uint32_t len, bool isAuthority)
{
    for (uint32_t i = 0; i < len; i++) {
        if (data[i] == '?' || data[i] == '#') {
            return i;
        }
        if (isAuthority && data[i] == '/') {
            return i;
        }
        if (!isAuthority && (data[i] == '/' || data[i] == ';')) {
            return i;
        }
    }
    return len;
}

static int32_t CheckUriPort(const char *port, uint32_t portLen)
{
    uint32_t portNum = 0;
    if (portLen == 0) {
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    for (uint32_t i = 0; i < portLen; i++) {
        if (!isdigit((unsigned char)port[i])) {
            return HITLS_X509_ERR_INVALID_PARAM;
        }
        portNum = portNum * 10 + (uint32_t)(port[i] - '0');
        if (portNum > 65535) {
            return HITLS_X509_ERR_INVALID_PARAM;
        }
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t ParseUriId(const char *uri, uint32_t uriLen, X509_StringView *scheme, X509_StringView *host)
{
    const char *colon = FindCharInView(uri, uriLen, ':');
    if (colon == NULL || colon == uri || (uint32_t)(colon - uri) >= uriLen) {
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    scheme->data = uri;
    scheme->len = (uint32_t)(colon - uri);

    const char *hostStart = colon + 1;
    uint32_t remainLen = uriLen - scheme->len - 1;
    bool isAuthority = false;
    if (remainLen >= 2 && hostStart[0] == '/' && hostStart[1] == '/') {
        hostStart += 2;
        remainLen -= 2;
        isAuthority = true;
    }

    uint32_t hostLen = FindUriPartEnd(hostStart, remainLen, isAuthority);
    const char *at = FindLastCharInView(hostStart, hostLen, '@');
    if (at != NULL) {
        hostLen -= (uint32_t)(at + 1 - hostStart);
        hostStart = at + 1;
    }
    const char *port = FindCharInView(hostStart, hostLen, ':');
    if (port != NULL) {
        if (CheckUriPort(port + 1, (uint32_t)(hostLen - (port + 1 - hostStart))) != HITLS_PKI_SUCCESS) {
            return HITLS_X509_ERR_INVALID_PARAM;
        }
        hostLen = (uint32_t)(port - hostStart);
    }
    if (hostLen == 0) {
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    host->data = hostStart;
    host->len = hostLen;
    return HITLS_PKI_SUCCESS;
}

static int32_t ParseSrvId(const char *srv, uint32_t srvLen, X509_StringView *service, X509_StringView *domain)
{
    if (srvLen == 0 || srv[0] != '_') {
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    const char *serviceStart = srv + 1;
    uint32_t remainLen = srvLen - 1;

    const char *dot = FindCharInView(serviceStart, remainLen, '.');
    if (dot == NULL || dot == serviceStart || (uint32_t)(dot + 1 - srv) >= srvLen) {
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    service->data = serviceStart;
    service->len = (uint32_t)(dot - serviceStart);
    domain->data = dot + 1;
    domain->len = srvLen - (uint32_t)(dot + 1 - srv);
    return HITLS_PKI_SUCCESS;
}

static int32_t MatchHostView(const X509_StringView *presented, const X509_StringView *reference,
    int32_t (*MatchCb)(const char *pattern, const char *hostname))
{
    char *presentedStr = NULL;
    char *referenceStr = NULL;
    int32_t ret = CopyViewToString(presented, &presentedStr);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = CopyViewToString(reference, &referenceStr);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_Free(presentedStr);
        return ret;
    }
    ret = MatchCb(presentedStr, referenceStr);
    BSL_SAL_Free(presentedStr);
    BSL_SAL_Free(referenceStr);
    return ret;
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
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    ret = HITLS_X509_ERR_EXT_NOT_FOUND;
    for (BslListNode *nameNode = BSL_LIST_FirstNode(san.names); nameNode != NULL;
        nameNode = BSL_LIST_GetNextNode(san.names, nameNode)) {
        HITLS_X509_GeneralName *gn = (HITLS_X509_GeneralName *)BSL_LIST_GetData(nameNode);
        if (gn == NULL || gn->type != HITLS_X509_GN_DNS) {
            continue;
        }

        if (BSL_SAL_Memchr((const char *)gn->value.data, '\0', gn->value.dataLen)) {
            ret = HITLS_X509_ERR_VFY_HOSTNAME_FAIL;
            continue;
        }

        char *dnsName = (char *)BSL_SAL_Malloc(gn->value.dataLen + 1);
        if (dnsName == NULL) {
            HITLS_X509_ClearSubjectAltName(&san);
            return BSL_MALLOC_FAIL;
        }
        memcpy(dnsName, gn->value.data, gn->value.dataLen);
        dnsName[gn->value.dataLen] = '\0';
        ret = MatchCb(dnsName, hostname);
        BSL_SAL_Free(dnsName);
        if (ret == HITLS_PKI_SUCCESS) {
            break;
        }
    }

    HITLS_X509_ClearSubjectAltName(&san);
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

    if (BSL_SAL_Memchr((const char *)cnName.data, '\0', cnName.dataLen)) {
        BSL_SAL_Free(cnName.data);
        return HITLS_X509_ERR_VFY_HOSTNAME_FAIL;
    }

    ret = MatchCb((const char *)cnName.data, hostname);
    BSL_SAL_Free(cnName.data);
    return ret;
}
 
static int32_t X509_VerifyHostname(HITLS_X509_Cert *cert, uint32_t flags, const char *hostname, uint32_t hostnameLen)
{
    if (cert == NULL || hostname == NULL || hostnameLen == 0) {
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
    // For compatibility with RFC6125, if SAN is not present or there is no DNS in the SAN, fall back to checking CN.
    if (ret == HITLS_X509_ERR_EXT_NOT_FOUND) {
        return X509_VerifyHostnameWithCn(cert, hostname, MatchCb);
    }
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t X509_VerifyIp(HITLS_X509_Cert *cert, const char *ip, uint32_t ipLen)
{
    if (cert == NULL || ip == NULL || strlen(ip) != ipLen) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    unsigned char buff[16];
    int32_t buffLen = sizeof(buff) / sizeof(buff[0]);
    if (SAL_ParseIp(ip, buff, &buffLen) != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    HITLS_X509_ExtSan san = {0};
    int32_t ret = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_GET_SAN, &san, sizeof(san));
    if (ret != HITLS_PKI_SUCCESS || san.names == NULL) {
        return HITLS_X509_ERR_EXT_NOT_FOUND;
    }

    ret = HITLS_X509_ERR_VFY_IP_FAIL;
    for (BslListNode *nameNode = BSL_LIST_FirstNode(san.names); nameNode != NULL;
        nameNode = BSL_LIST_GetNextNode(san.names, nameNode)) {
        HITLS_X509_GeneralName *gn = (HITLS_X509_GeneralName *)BSL_LIST_GetData(nameNode);
        if (gn == NULL || gn->type != HITLS_X509_GN_IP) {
            continue;
        }
        if ((uint32_t)buffLen == gn->value.dataLen && memcmp(gn->value.data, buff, gn->value.dataLen) == 0) {
            ret = HITLS_PKI_SUCCESS;
            break;
        }
    }

    HITLS_X509_ClearSubjectAltName(&san);
    return ret;
}

static int32_t X509_VerifyUriId(HITLS_X509_Cert *cert, uint32_t flags, const char *uri, uint32_t uriLen)
{
    if (cert == NULL || uri == NULL || uriLen == 0 || uriLen != (uint32_t)strlen(uri)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    X509_StringView refScheme = {0};
    X509_StringView refHost = {0};
    int32_t ret = ParseUriId(uri, uriLen, &refScheme, &refHost);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    int32_t (*MatchCb)(const char *pattern, const char *hostname) =
        ((flags & HITLS_X509_FLAG_VFY_WITH_PARTIAL_WILDCARD) != 0) ? MatchWithPartialWildcard : MatchWithSingleWildcard;
    HITLS_X509_ExtSan san = {0};
    BSL_ERR_SET_MARK();
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_GET_SAN, &san, sizeof(san));
    if (ret != HITLS_PKI_SUCCESS || san.names == NULL) {
        BSL_ERR_POP_TO_MARK();
        return HITLS_X509_ERR_VFY_URI_ID_FAIL;
    }
    BSL_ERR_POP_TO_MARK();

    ret = HITLS_X509_ERR_VFY_URI_ID_FAIL;
    for (BslListNode *nameNode = BSL_LIST_FirstNode(san.names); nameNode != NULL;
        nameNode = BSL_LIST_GetNextNode(san.names, nameNode)) {
        HITLS_X509_GeneralName *gn = (HITLS_X509_GeneralName *)BSL_LIST_GetData(nameNode);
        if (gn == NULL || gn->type != HITLS_X509_GN_URI) {
            continue;
        }
        X509_StringView presentedScheme = {0};
        X509_StringView presentedHost = {0};
        if (ParseUriId((const char *)gn->value.data, gn->value.dataLen, &presentedScheme, &presentedHost) !=
            HITLS_PKI_SUCCESS) {
            continue;
        }
        if (CaseCmpView(&presentedScheme, &refScheme) != HITLS_PKI_SUCCESS) {
            continue;
        }
        int32_t matchRet = MatchHostView(&presentedHost, &refHost, MatchCb);
        if (matchRet == BSL_MALLOC_FAIL) {
            ret = matchRet;
            break;
        }
        if (matchRet == HITLS_PKI_SUCCESS) {
            ret = HITLS_PKI_SUCCESS;
            break;
        }
    }

    HITLS_X509_ClearSubjectAltName(&san);
    return ret;
}

static int32_t X509_VerifySrvId(HITLS_X509_Cert *cert, uint32_t flags, const char *srv, uint32_t srvLen)
{
    if (cert == NULL || srv == NULL || srvLen == 0 || srvLen != (uint32_t)strlen(srv)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    X509_StringView refService = {0};
    X509_StringView refDomain = {0};
    int32_t ret = ParseSrvId(srv, srvLen, &refService, &refDomain);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    int32_t (*MatchCb)(const char *pattern, const char *hostname) =
        ((flags & HITLS_X509_FLAG_VFY_WITH_PARTIAL_WILDCARD) != 0) ? MatchWithPartialWildcard : MatchWithSingleWildcard;
    HITLS_X509_ExtSan san = {0};
    BSL_ERR_SET_MARK();
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_GET_SAN, &san, sizeof(san));
    if (ret != HITLS_PKI_SUCCESS || san.names == NULL) {
        BSL_ERR_POP_TO_MARK();
        return HITLS_X509_ERR_VFY_SRV_ID_FAIL;
    }
    BSL_ERR_POP_TO_MARK();

    ret = HITLS_X509_ERR_VFY_SRV_ID_FAIL;
    for (BslListNode *nameNode = BSL_LIST_FirstNode(san.names); nameNode != NULL;
        nameNode = BSL_LIST_GetNextNode(san.names, nameNode)) {
        HITLS_X509_GeneralName *gn = (HITLS_X509_GeneralName *)BSL_LIST_GetData(nameNode);
        if (gn == NULL || gn->type != HITLS_X509_GN_SRV) {
            continue;
        }
        X509_StringView presentedService = {0};
        X509_StringView presentedDomain = {0};
        if (ParseSrvId((const char *)gn->value.data, gn->value.dataLen, &presentedService, &presentedDomain) !=
            HITLS_PKI_SUCCESS) {
            continue;
        }
        if (CaseCmpView(&presentedService, &refService) != HITLS_PKI_SUCCESS) {
            continue;
        }
        int32_t matchRet = MatchHostView(&presentedDomain, &refDomain, MatchCb);
        if (matchRet == BSL_MALLOC_FAIL) {
            ret = matchRet;
            break;
        }
        if (matchRet == HITLS_PKI_SUCCESS) {
            ret = HITLS_PKI_SUCCESS;
            break;
        }
    }

    HITLS_X509_ClearSubjectAltName(&san);
    return ret;
}

int32_t HITLS_X509_VerifyIdentity(HITLS_X509_Cert *cert, uint32_t flags, uint32_t type,
    const char *val, uint32_t valLen)
{
    if (type == HITLS_GEN_DNS) {
        return X509_VerifyHostname(cert, flags, val, valLen);
    } else if (type == HITLS_GEN_IP) {
        return X509_VerifyIp(cert, val, valLen);
    } else if (type == HITLS_GEN_URI) {
        return X509_VerifyUriId(cert, flags, val, valLen);
    } else if (type == HITLS_GEN_SRV) {
        return X509_VerifySrvId(cert, flags, val, valLen);
    }
    return HITLS_X509_ERR_INVALID_PARAM;
}
#endif // HITLS_PKI_X509_VFY_IDENTITY

#ifdef HITLS_PKI_CMS_SIGNEDDATA
int32_t HITLS_X509_CheckKey(HITLS_X509_Cert *cert, CRYPT_EAL_PkeyCtx *prvKey)
{
    if (cert == NULL || prvKey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    CRYPT_EAL_PkeyCtx *pubKey = NULL;
    int32_t ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_PUBKEY, &pubKey, sizeof(CRYPT_EAL_PkeyCtx *));
    if (ret != HITLS_PKI_SUCCESS || pubKey == NULL) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = CRYPT_EAL_PkeyPairCheck(pubKey, prvKey);
    CRYPT_EAL_PkeyFreeCtx(pubKey);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_CERT_NOT_MATCH_KEY);
        return HITLS_X509_ERR_CERT_NOT_MATCH_KEY;
    }
    return HITLS_PKI_SUCCESS;
}
#endif // HITLS_PKI_CMS_SIGNEDDATA
