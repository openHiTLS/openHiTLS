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

#include "app_conf.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#if defined(__linux__) || defined(__unix__) || defined(__APPLE__) || defined(__MACH__)
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#error "only support linux and macOS"
#endif
#include "securec.h"
#include "app_errno.h"
#include "bsl_sal.h"
#include "bsl_obj.h"
#include "bsl_obj_internal.h"
#include "bsl_list.h"
#include "hitls_pki_errno.h"
#include "hitls_x509_local.h"
#include "app_errno.h"
#include "app_opt.h"
#include "app_print.h"
#include "app_conf.h"

#define MAX_DN_LIST_SIZE 99
#define X509_EXT_SAN_VALUE_MAX_CNT 30    // san
#define IPV4_VALUE_MAX_CNT 4
#define IPV6_VALUE_STR_MAX_CNT 8
#define IPV6_VALUE_MAX_CNT 16
#define IPV6_EACH_VALUE_STR_LEN 4

#define EXT_CRITICAL_STR "critical"
#define EXT_CRITICAL_LEN 8

typedef int32_t (*ProcExtCnfFunc)(BSL_CONF *cnf, bool critical, const char *cnfValue, ProcExtCallBack procExt,
    void *ctx);

typedef struct {
    char *name;
    ProcExtCnfFunc func;
} X509ExtInfo;

typedef struct {
    char *name;
    int32_t keyUsage;
} X509KeyUsageMap;

#define X509_EXT_BCONS_VALUE_MAX_CNT 2      // ca and pathlen
#define X509_EXT_BCONS_SUB_VALUE_MAX_CNT 2  // ca:TRUE|FALSE or pathlen:num
#define X509_EXT_SKI_VALUE_MAX_CNT 1        // kid
#define X509_EXT_AKI_VALUE_MAX_CNT 1        // kid
#define X509_EXT_AKI_SUB_VALUE_MAX_CNT 2    // keyid:always

static X509KeyUsageMap g_kuMap[] = {
    {HITLS_CFG_X509_EXT_KU_DIGITAL_SIGN, HITLS_X509_EXT_KU_DIGITAL_SIGN},
    {HITLS_CFG_X509_EXT_KU_NON_REPUDIATION, HITLS_X509_EXT_KU_NON_REPUDIATION},
    {HITLS_CFG_X509_EXT_KU_KEY_ENCIPHERMENT, HITLS_X509_EXT_KU_KEY_ENCIPHERMENT},
    {HITLS_CFG_X509_EXT_KU_DATA_ENCIPHERMENT, HITLS_X509_EXT_KU_DATA_ENCIPHERMENT},
    {HITLS_CFG_X509_EXT_KU_KEY_AGREEMENT, HITLS_X509_EXT_KU_KEY_AGREEMENT},
    {HITLS_CFG_X509_EXT_KU_KEY_CERT_SIGN, HITLS_X509_EXT_KU_KEY_CERT_SIGN},
    {HITLS_CFG_X509_EXT_KU_CRL_SIGN, HITLS_X509_EXT_KU_CRL_SIGN},
    {HITLS_CFG_X509_EXT_KU_ENCIPHER_ONLY, HITLS_X509_EXT_KU_ENCIPHER_ONLY},
    {HITLS_CFG_X509_EXT_KU_DECIPHER_ONLY, HITLS_X509_EXT_KU_DECIPHER_ONLY},
};

#define X509_EXT_KU_VALUE_MAX_CNT (sizeof(g_kuMap) / sizeof(g_kuMap[0]))

static X509KeyUsageMap g_exKuMap[] = {
    {HITLS_CFG_X509_EXT_EXKU_SERVER_AUTH, BSL_CID_KP_SERVERAUTH},
    {HITLS_CFG_X509_EXT_EXKU_CLIENT_AUTH, BSL_CID_KP_CLIENTAUTH},
    {HITLS_CFG_X509_EXT_EXKU_CODE_SING, BSL_CID_KP_CODESIGNING},
    {HITLS_CFG_X509_EXT_EXKU_EMAIL_PROT, BSL_CID_KP_EMAILPROTECTION},
    {HITLS_CFG_X509_EXT_EXKU_TIME_STAMP, BSL_CID_KP_TIMESTAMPING},
    {HITLS_CFG_X509_EXT_EXKU_OCSP_SIGN, BSL_CID_KP_OCSPSIGNING},
};

#define X509_EXT_EXKU_VALUE_MAX_CNT (sizeof(g_exKuMap) / sizeof(g_exKuMap[0]))

static int32_t FindEndIdx(char *str, char separator, int32_t beginIdx, int32_t currIdx, bool allowEmpty)
{
    while (currIdx >= 0 && (isspace(str[currIdx]) || str[currIdx] == separator)) {
        currIdx--;
    }
    if (beginIdx < currIdx) {
        return currIdx + 1;
    } else if (str[beginIdx] != separator) {
        return beginIdx + 1;
    } else if (allowEmpty) {
        return beginIdx; // Empty substring
    } else {  // Empty substrings are not allowed.
        return -1;
    }
}

int32_t HITLS_APP_SplitString(const char *str, char separator, bool allowEmpty, char **strArr, uint32_t maxArrCnt,
    uint32_t *realCnt)
{
    if (str == NULL || strlen(str) == 0 || isspace(separator) || strArr == NULL || maxArrCnt == 0 || realCnt == NULL) {
        return HITLS_APP_INVALID_ARG;
    }

    // Delete leading spaces from input str.
    char *tmp = (char *)(uintptr_t)str;
    tmp += strspn(tmp, " \t\n\v\f\r");

    // split
    int32_t ret = HITLS_APP_SUCCESS;
    char *res = strdup(tmp);
    if (res == NULL) {
        return HITLS_APP_INTERNAL_EXCEPTION;
    }
    int32_t len = strlen(tmp);
    int32_t begin;
    int32_t end;
    bool hasBegin = false;
    *realCnt = 0;
    for (int32_t i = 0; i < len; i++) {
        if (!hasBegin) {
            if (isspace(res[i])) {
                continue;
            }
            if (*realCnt == maxArrCnt) {
                ret = HITLS_APP_CONF_FAIL;
                break;
            }
            begin = i;
            strArr[(*realCnt)++] = res + begin;
            hasBegin = true;
        }
        if ((i + 1) != len && res[i] != separator) {
            continue;
        }
        end = FindEndIdx(res, separator, begin, i, allowEmpty);
        if (end == -1) {
            ret = HITLS_APP_CONF_FAIL;
            break;
        }
        res[end] = '\0';
        hasBegin = false;
    }
    if (ret != HITLS_APP_SUCCESS) {
        *realCnt = 0;
        BSL_SAL_FREE(strArr[0]);
    }
    return ret;
}

static bool ExtGetCritical(char **value)
{
    char *tmp = *value;
    tmp += strspn(tmp, " \t\n\v\f\r");
    if (strlen(tmp) < EXT_CRITICAL_LEN || strncmp(tmp, EXT_CRITICAL_STR, EXT_CRITICAL_LEN) != 0) {
        return false;
    }
    tmp += EXT_CRITICAL_LEN;
    tmp += strspn(tmp, " \t\n\v\f\r");
    if (tmp[0] == ',') {
        tmp++;
    }
    *value = tmp;
    return true;
}

static int32_t ParseBasicConstraints(char **value, HITLS_X509_ExtBCons *bCons)
{
    if (strcmp(value[0], "CA") == 0) {
        if (strcmp(value[1], "FALSE") == 0) {
            bCons->isCa = false;
        } else if (strcmp(value[1], "TRUE") == 0) {
            bCons->isCa = true;
        } else {
            AppPrintError("Illegal value of basicConstraints CA: %s.\n", value[1]);
            return HITLS_APP_CONF_FAIL;
        }
        return HITLS_APP_SUCCESS;
    } else if (strcmp(value[0], "pathlen") != 0) {
        AppPrintError("Unrecognized value of basicConstraints: %s.\n", value[0]);
        return HITLS_APP_CONF_FAIL;
    }
    int32_t pathLen;
    int32_t ret = HITLS_APP_OptGetInt(value[1], &pathLen);
    if (ret != HITLS_APP_SUCCESS || pathLen < 0) {
        AppPrintError("Illegal value of basicConstraints pathLen(>=0): %s.\n", value[1]);
        return HITLS_APP_CONF_FAIL;
    }
    bCons->maxPathLen = pathLen;
    return HITLS_APP_SUCCESS;
}

static int32_t ProcBasicConstraints(BSL_CONF *cnf, bool critical, const char *cnfValue,
    ProcExtCallBack procExt, void *ctx)
{
    (void)cnf;
    HITLS_X509_ExtBCons bCons = {critical, false, -1};

    char *valueList[X509_EXT_BCONS_VALUE_MAX_CNT] = {0};
    uint32_t valueCnt = 0;
    int32_t ret = HITLS_APP_SplitString(cnfValue, ',', false, valueList, X509_EXT_BCONS_VALUE_MAX_CNT, &valueCnt);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("Split basicConstraints failed: %s.\n", cnfValue);
        return ret;
    }

    for (uint32_t i = 0; i < valueCnt; i++) {
        char *subList[X509_EXT_BCONS_VALUE_MAX_CNT] = {0};
        uint32_t subCnt = 0;
        ret = HITLS_APP_SplitString(valueList[i], ':', false, subList, X509_EXT_BCONS_VALUE_MAX_CNT, &subCnt);
        if (ret != HITLS_APP_SUCCESS) {
            AppPrintError("Split sub-value of basicConstraints failed: %s.\n", valueList[i]);
            BSL_SAL_Free(valueList[0]);
            return ret;
        }
        if (subCnt != X509_EXT_BCONS_SUB_VALUE_MAX_CNT) {
            AppPrintError("Illegal value of basicConstraints: %s.\n", valueList[i]);
            BSL_SAL_Free(valueList[0]);
            BSL_SAL_Free(subList[0]);
            return HITLS_APP_CONF_FAIL;
        }
        ret = ParseBasicConstraints(subList, &bCons);
        BSL_SAL_Free(subList[0]);
        if (ret != HITLS_APP_SUCCESS) {
            BSL_SAL_Free(valueList[0]);
            return ret;
        }
    }
    BSL_SAL_Free(valueList[0]);
    return procExt(BSL_CID_CE_BASICCONSTRAINTS, &bCons, ctx);
}

static int32_t ProcKeyUsage(BSL_CONF *cnf, bool critical, const char *cnfValue, ProcExtCallBack procExt, void *ctx)
{
    (void)cnf;
    HITLS_X509_ExtKeyUsage ku = {critical, 0};

    char *valueList[X509_EXT_KU_VALUE_MAX_CNT] = {0};
    uint32_t valueCnt = 0;
    int32_t ret = HITLS_APP_SplitString(cnfValue, ',', false, valueList, X509_EXT_KU_VALUE_MAX_CNT, &valueCnt);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("Split value of keyUsage falied: %s.\n", cnfValue);
        return ret;
    }

    bool found;
    for (uint32_t i = 0; i < valueCnt; i++) {
        found = false;
        for (uint32_t j = 0; j < X509_EXT_KU_VALUE_MAX_CNT; j++) {
            if (strcmp(g_kuMap[j].name, valueList[i]) == 0) {
                ku.keyUsage |= g_kuMap[j].keyUsage;
                found = true;
                break;
            }
        }
        if (!found) {
            AppPrintError("Unrecognized value of keyUsage: %s.\n", valueList[i]);
            BSL_SAL_Free(valueList[0]);
            return HITLS_APP_CONF_FAIL;
        }
    }
    BSL_SAL_Free(valueList[0]);
    return procExt(BSL_CID_CE_KEYUSAGE, &ku, ctx);
}

static int32_t CmpExKeyUsageByOid(const void *pCurr, const void *pOid)
{
    const BSL_Buffer *curr = pCurr;
    const BslOidString *oid = pOid;
    if (curr->dataLen != oid->octetLen) {
        return 1;
    }
    return memcmp(curr->data, oid->octs, curr->dataLen);
}

static int32_t AddExtendKeyUsage(BslOidString *oidStr, BslList *list)
{
    BSL_Buffer *oid = BSL_SAL_Malloc(list->dataSize);
    if (oid == NULL) {
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    oid->data = (uint8_t *)oidStr->octs;
    oid->dataLen = oidStr->octetLen;

    if (BSL_LIST_AddElement(list, oid, BSL_LIST_POS_END) != 0) {
        BSL_SAL_Free(oid);
        return HITLS_APP_SAL_FAIL;
    }

    return HITLS_APP_SUCCESS;
}
static int32_t ProcExtendedKeyUsage(BSL_CONF *cnf, bool critical, const char *cnfValue, ProcExtCallBack procExt,
    void *ctx)
{
    (void)cnf;
    HITLS_X509_ExtExKeyUsage exku = {critical, NULL};

    char *valueList[X509_EXT_EXKU_VALUE_MAX_CNT] = {0};
    uint32_t valueCnt = 0;
    int32_t ret = HITLS_APP_SplitString(cnfValue, ',', false, valueList, X509_EXT_EXKU_VALUE_MAX_CNT, &valueCnt);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("Split value of extendedKeyUsage failed: %s.\n", cnfValue);
        return ret;
    }
    exku.oidList = BSL_LIST_New(sizeof(BSL_Buffer));
    if (exku.oidList == NULL) {
        BSL_SAL_Free(valueList[0]);
        AppPrintError("New list of extendedKeyUsage failed.\n");
        return HITLS_APP_SAL_FAIL;
    }

    int32_t cid;
    BslOidString *oidStr = NULL;
    for (uint32_t i = 0; i < valueCnt; i++) {
        cid = BSL_CID_UNKNOWN;
        for (uint32_t j = 0; j < X509_EXT_EXKU_VALUE_MAX_CNT; j++) {
            if (strcmp(g_exKuMap[j].name, valueList[i]) == 0) {
                cid = g_exKuMap[j].keyUsage;
                break;
            }
        }
        oidStr = BSL_OBJ_GetOID(cid);
        if (oidStr == NULL) {
            AppPrintError("Unsupported extendedKeyUsage: %s.\n", valueList[i]);
            ret = HITLS_APP_CONF_FAIL;
            goto EXIT;
        }
        if (BSL_LIST_Search(exku.oidList, oidStr, (BSL_LIST_PFUNC_CMP)CmpExKeyUsageByOid, NULL) != NULL) {
            continue;
        }
        ret = AddExtendKeyUsage(oidStr, exku.oidList);
        if (ret != HITLS_APP_SUCCESS) {
            AppPrintError("Add extendedKeyUsage failed.\n");
            goto EXIT;
        }
    }
    ret = procExt(BSL_CID_CE_EXTKEYUSAGE, &exku, ctx);
EXIT:
    BSL_SAL_Free(valueList[0]);
    BSL_LIST_FREE(exku.oidList, NULL);
    return ret;
}

static int32_t ProcSubjectKeyIdentifier(BSL_CONF *cnf, bool critical, const char *cnfValue, ProcExtCallBack procExt,
    void *ctx)
{
    (void)cnf;
    HITLS_X509_ExtSki ski = {critical, {0}};

    char *valueList[X509_EXT_SKI_VALUE_MAX_CNT] = {0};
    uint32_t valueCnt = 0;
    int32_t ret = HITLS_APP_SplitString(cnfValue, ',', false, valueList, X509_EXT_SKI_VALUE_MAX_CNT, &valueCnt);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("Split value of subjectKeyIdentifier failed: %s.\n", cnfValue);
        return ret;
    }

    if (strcmp(valueList[0], "hash") != 0) {
        BSL_SAL_Free(valueList[0]);
        AppPrintError("Illegal value of subjectKeyIdentifier: %s, only \"hash\" current is supported.\n", cnfValue);
        return HITLS_APP_CONF_FAIL;
    }

    BSL_SAL_Free(valueList[0]);
    return procExt(BSL_CID_CE_SUBJECTKEYIDENTIFIER, &ski, ctx);
}

static int32_t ParseAuthKeyIdentifier(char **value, uint32_t cnt, uint32_t *flag)
{
    if (strcmp(value[0], "keyid") != 0) {
        AppPrintError("Illegal type of authorityKeyIdentifier keyid: %s.\n", value[0]);
        return HITLS_APP_CONF_FAIL;
    }
    if (cnt == 1) {
        *flag |= HITLS_CFG_X509_EXT_AKI_KID;
        return HITLS_APP_SUCCESS;
    }
    if (strcmp(value[1], "always") != 0) {
        AppPrintError("Illegal value of authorityKeyIdentifier keyid: %s.\n", value[1]);
        return HITLS_APP_CONF_FAIL;
    }
    *flag |= HITLS_CFG_X509_EXT_AKI_KID_ALWAYS;
    return HITLS_APP_SUCCESS;
}

static int32_t ProcAuthKeyIdentifier(BSL_CONF *cnf, bool critical, const char *cnfValue, ProcExtCallBack procExt,
    void *ctx)
{
    (void)cnf;
    HITLS_CFG_ExtAki aki = {{critical, {0}, NULL, {0}}, 0};

    char *valueList[X509_EXT_AKI_VALUE_MAX_CNT] = {0};
    uint32_t valueCnt = 0;
    int32_t ret = HITLS_APP_SplitString(cnfValue, ',', false, valueList, X509_EXT_AKI_VALUE_MAX_CNT, &valueCnt);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("Split value of authorityKeyIdentifier failed: %s.\n", cnfValue);
        return ret;
    }

    for (uint32_t i = 0; i < valueCnt; i++) {
        char *subList[X509_EXT_AKI_SUB_VALUE_MAX_CNT] = {0};
        uint32_t subCnt = 0;
        ret = HITLS_APP_SplitString(valueList[i], ':', false, subList, X509_EXT_AKI_SUB_VALUE_MAX_CNT, &subCnt);
        if (ret != HITLS_APP_SUCCESS) {
            AppPrintError("Split sub-value of authorityKeyIdentifier failed: %s.\n", valueList[i]);
            BSL_SAL_Free(valueList[0]);
            return ret;
        }
        ret = ParseAuthKeyIdentifier(subList, subCnt, &aki.flag);
        BSL_SAL_Free(subList[0]);
        if (ret != HITLS_APP_SUCCESS) {
            BSL_SAL_Free(valueList[0]);
            return ret;
        }
    }
    BSL_SAL_Free(valueList[0]);
    return procExt(BSL_CID_CE_AUTHORITYKEYIDENTIFIER, &aki, ctx);
}

typedef struct {
    char *name;
    HITLS_X509_GeneralNameType genNameType;
} X509GeneralNameMap;

static X509GeneralNameMap g_exSanMap[] = {
    {HITLS_CFG_X509_EXT_SAN_EMAIL, HITLS_X509_GN_EMAIL},
    {HITLS_CFG_X509_EXT_SAN_DNS, HITLS_X509_GN_DNS},
    {HITLS_CFG_X509_EXT_SAN_DIR_NAME, HITLS_X509_GN_DNNAME},
    {HITLS_CFG_X509_EXT_SAN_URI, HITLS_X509_GN_URI},
    {HITLS_CFG_X509_EXT_SAN_IP, HITLS_X509_GN_IP},
};

static int32_t ParseGeneralSanValue(char *value, HITLS_X509_GeneralName *generalName)
{
    generalName->value.data = (uint8_t *)strdup(value);
    if (generalName->value.data == NULL) {
        AppPrintError("Failed to copy value: %s.\n", value);
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    generalName->value.dataLen = strlen(value);
    return HITLS_APP_SUCCESS;
}

static int32_t ParseDirNamenValue(BSL_CONF *conf, char *value, HITLS_X509_GeneralName *generalName)
{
    int32_t ret;
    BslList *dirName = BSL_CONF_GetSection(conf, value);
    if (dirName == NULL) {
        AppPrintError("Failed to get section: %s.\n", value);
        return HITLS_APP_ERR_CONF_GET_SECTION;
    }
    BslList *nameList = BSL_LIST_New(sizeof(HITLS_X509_NameNode *));
    if (nameList == NULL) {
        AppPrintError("New list of directory name list failed.\n");
        ret = HITLS_APP_MEM_ALLOC_FAIL;
        goto EXIT;
    }
    BSL_CONF_KeyValue *node = BSL_LIST_GET_FIRST(dirName);
    while (node != NULL) {
        HITLS_X509_DN *dnName = BSL_SAL_Calloc(1, sizeof(HITLS_X509_DN));
        if (dnName == NULL) {
            AppPrintError("Failed to malloc X509 DN when parsing directory name.\n");
            ret = HITLS_APP_MEM_ALLOC_FAIL;
            goto EXIT;
        }
        const BslAsn1DnInfo *info = BSL_OBJ_GetDnInfoFromShortName(node->key);
        if (info == NULL) {
            ret = HITLS_APP_INVALID_DN_TYPE;
            BSL_SAL_FREE(dnName);
            AppPrintError("Invalid short name of distinguish name.\n");
            goto EXIT;
        }
        dnName->data = (uint8_t *)node->value;
        dnName->dataLen = (uint32_t)strlen(node->value);
        dnName->cid = info->cid;
        ret = HITLS_X509_AddDnName(nameList, dnName, 1);
        BSL_SAL_FREE(dnName);
        if (ret != HITLS_PKI_SUCCESS) {
            AppPrintError("Failed to HITLS_X509_AddDnName.\n");
            goto EXIT;
        }
        node = BSL_LIST_GET_NEXT(dirName);
    }

    generalName->value.data = (uint8_t *)nameList;
    generalName->value.dataLen = (uint32_t)sizeof(BslList *);
    return HITLS_APP_SUCCESS;
EXIT:
    BSL_LIST_FREE(nameList, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeNameNode);
    return ret;
}

static int32_t ParseIPValue(char *value, HITLS_X509_GeneralName *generalName)
{
    struct sockaddr_in sockIpv4 = {};
    struct sockaddr_in6 sockIpv6 = {};
    char *ipv4ValueList[IPV4_VALUE_MAX_CNT] = {0};
    uint32_t ipSize = 0;
    if (inet_pton(AF_INET, value, &(sockIpv4.sin_addr)) == 1) {
        uint32_t valueCnt = 0;
        int32_t ret = HITLS_APP_SplitString(value, '.', false, ipv4ValueList, IPV4_VALUE_MAX_CNT, &valueCnt);
        if (ret != HITLS_APP_SUCCESS) {
            return ret;
        }
        if (valueCnt != IPV4_VALUE_MAX_CNT) {
            AppPrintError("Failed to split IP string, IP: %s.\n", value);
            BSL_SAL_FREE(ipv4ValueList[0]);
            return HITLS_APP_INVALID_IP;
        }
        // Normalize IPv4 octets by removing leading zeros (cross-platform fix)
        // inet_pton() behavior differs on macOS vs Linux for leading zeros
        for (uint32_t i = 0; i < IPV4_VALUE_MAX_CNT; i++) {
            // Skip leading zeros, but keep "0" as "0"
            char *octet = ipv4ValueList[i];
            while (*octet == '0' && *(octet + 1) != '\0') {
                octet++;
            }
            ipv4ValueList[i] = octet;
        }
        ipSize = IPV4_VALUE_MAX_CNT;
    } else if (inet_pton(AF_INET6, value, &(sockIpv6.sin6_addr)) == 1) {
        ipSize = IPV6_VALUE_MAX_CNT;
    } else {
        AppPrintError("Invalid IP format for directory name, IP: %s.\n", value);
        return HITLS_APP_INVALID_IP;
    }
    generalName->value.data = BSL_SAL_Calloc(ipSize, 1);
    if (generalName->value.data == NULL) {
        AppPrintError("Invalid IP format for directory name, IP: %s.\n", value);
        BSL_SAL_FREE(ipv4ValueList[0]);
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    for (uint32_t i = 0; i < ipSize; i++) {
        if (ipSize == IPV4_VALUE_MAX_CNT) {
            generalName->value.data[i] = (uint8_t)BSL_SAL_Atoi(ipv4ValueList[i]);
        } else {
            generalName->value.data[i] = sockIpv6.sin6_addr.s6_addr[i];
        }
    }
    generalName->value.dataLen = ipSize;
    BSL_SAL_FREE(ipv4ValueList[0]);
    return HITLS_APP_SUCCESS;
}

static int32_t ParseGeneralNameValue(BSL_CONF *conf, HITLS_X509_GeneralNameType type, char *value,
    HITLS_X509_GeneralName *generalName)
{
    int32_t ret;
    generalName->type = type;
    switch (type) {
        case HITLS_X509_GN_EMAIL:
        case HITLS_X509_GN_DNS:
        case HITLS_X509_GN_URI:
            ret = ParseGeneralSanValue(value, generalName);
            break;
        case HITLS_X509_GN_DNNAME:
            ret = ParseDirNamenValue(conf, value, generalName);
            break;
        case HITLS_X509_GN_IP:
            ret = ParseIPValue(value, generalName);
            break;
        default:
            generalName->type = 0;
            AppPrintError("Unsupported the type of general name, type: %u.\n", generalName->type);
            return HITLS_APP_INVALID_GENERAL_NAME_TYPE;
    }
    return ret;
}

static int32_t ParseGeneralName(BSL_CONF *conf, char *genNameStr, HITLS_X509_GeneralName *generalName)
{
    char *key = genNameStr;
    char *value = strstr(genNameStr, ":");
    if (value == NULL) {
        return HITLS_APP_INVALID_GENERAL_NAME_TYPE;
    }
    key[value - key] = '\0';
    for (int i = strlen(key) - 1; i >= 0; i--) {
        if (key[i] == ' ') {
            key[i] = '\0';
        }
    }
    value++;
    while (*value == ' ') {
        value++;
    }
    if (strlen(value) == 0) {
        AppPrintError("The value of general name is not set, key: %s.\n", key);
        return HITLS_APP_INVALID_GENERAL_NAME;
    }
    HITLS_X509_GeneralNameType type = HITLS_X509_GN_MAX;
    for (uint32_t j = 0; j < sizeof(g_exSanMap) / sizeof(g_exSanMap[0]); j++) {
        if (strcmp(g_exSanMap[j].name, key) == 0) {
            type = g_exSanMap[j].genNameType;
            break;
        }
    }
    return ParseGeneralNameValue(conf, type, value, generalName);
}

static int32_t ProcExtSubjectAltName(BSL_CONF *conf, bool critical, const char *cnfValue, ProcExtCallBack procExt,
    void *ctx)
{
    HITLS_X509_ExtSan san = {critical, NULL};

    char *valueList[X509_EXT_SAN_VALUE_MAX_CNT] = {0};
    uint32_t valueCnt = 0;
    int32_t ret = HITLS_APP_SplitString(cnfValue, ',', false, valueList, X509_EXT_SAN_VALUE_MAX_CNT, &valueCnt);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    san.names = BSL_LIST_New(sizeof(HITLS_X509_GeneralName *));
    if (san.names == NULL) {
        ret = HITLS_APP_MEM_ALLOC_FAIL;
        goto EXIT;
    }
    // find type
    for (uint32_t i = 0; i < valueCnt; i++) {
        HITLS_X509_GeneralName *generalName = BSL_SAL_Calloc(1, sizeof(HITLS_X509_GeneralName));
        if (generalName == NULL) {
            ret = HITLS_APP_MEM_ALLOC_FAIL;
            goto EXIT;
        }
        ret = ParseGeneralName(conf, valueList[i], generalName);
        if (ret != HITLS_APP_SUCCESS) {
            HITLS_X509_FreeGeneralName(generalName);
            goto EXIT;
        }
        ret = BSL_LIST_AddElement(san.names, generalName, BSL_LIST_POS_END);
        if (ret != HITLS_APP_SUCCESS) {
            HITLS_X509_FreeGeneralName(generalName);
            goto EXIT;
        }
    }

    ret = procExt(BSL_CID_CE_SUBJECTALTNAME, &san, ctx);
    if (ret != HITLS_APP_SUCCESS) {
        goto EXIT;
    }

EXIT:
    BSL_SAL_FREE(valueList[0]);
    BSL_LIST_FREE(san.names, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeGeneralName);
    return ret;
}

static X509ExtInfo g_exts[] = {
    {HITLS_CFG_X509_EXT_AKI, (ProcExtCnfFunc)ProcAuthKeyIdentifier},
    {HITLS_CFG_X509_EXT_SKI, (ProcExtCnfFunc)ProcSubjectKeyIdentifier},
    {HITLS_CFG_X509_EXT_BCONS, (ProcExtCnfFunc)ProcBasicConstraints},
    {HITLS_CFG_X509_EXT_KU, (ProcExtCnfFunc)ProcKeyUsage},
    {HITLS_CFG_X509_EXT_EXKU, (ProcExtCnfFunc)ProcExtendedKeyUsage},
    {HITLS_CFG_X509_EXT_SAN, (ProcExtCnfFunc)ProcExtSubjectAltName},
};

static int32_t AppConfProcExtEntry(BSL_CONF *cnf, BSL_CONF_KeyValue *cnfValue, ProcExtCallBack extCb, void *ctx)
{
    if (cnfValue->key == NULL || cnfValue->value == NULL) {
        return HITLS_APP_CONF_FAIL;
    }

    char *value = cnfValue->value;
    bool critical = ExtGetCritical(&value);
    for (uint32_t i = 0; i < sizeof(g_exts) / sizeof(g_exts[0]); i++) {
        if (strcmp(cnfValue->key, g_exts[i].name) == 0) {
            return g_exts[i].func(cnf, critical, value, extCb, ctx);
        }
    }
    AppPrintError("Unsupported extension: %s.\n", cnfValue->key);
    return HITLS_APP_CONF_FAIL;
}

int32_t HITLS_APP_CONF_ProcExt(BSL_CONF *cnf, const char *section, ProcExtCallBack extCb, void *ctx)
{
    if (cnf == NULL || cnf->data == NULL || section == NULL || extCb == NULL) {
        AppPrintError("Invalid input parameter.\n");
        return HITLS_APP_CONF_FAIL;
    }
    int32_t ret = HITLS_APP_SUCCESS;
    BslList *list = BSL_CONF_GetSection(cnf, section);
    if (list == NULL) {
        AppPrintError("Failed to get extension section: %s.\n", section);
        return HITLS_APP_CONF_FAIL;
    }
    if (BSL_LIST_EMPTY(list)) {
        return HITLS_APP_NO_EXT; // There is no configuration in the section.
    }
    BSL_CONF_KeyValue *cnfNode = BSL_LIST_GET_FIRST(list);
    while (cnfNode != NULL) {
        ret = AppConfProcExtEntry(cnf, cnfNode, extCb, ctx);
        if (ret != HITLS_APP_SUCCESS) {
            AppPrintError("Failed to process each x509 extension conf.\n");
            return ret;
        }
        cnfNode = BSL_LIST_GET_NEXT(list);
    }

    return ret;
}

int32_t HiTLS_AddSubjDnNameToCsr(void *csr, BslList *nameList)
{
    if (csr == NULL) {
        AppPrintError("csr is null when add subject name to csr.\n");
        return HITLS_APP_INVALID_ARG;
    }
    uint32_t count = BSL_LIST_COUNT(nameList);
    HITLS_X509_DN *names = BSL_SAL_Calloc(count, sizeof(HITLS_X509_DN));
    if (names == NULL) {
        AppPrintError("Failed to malloc names when add subject name to csr.\n");
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    size_t index = 0;
    HITLS_X509_DN *node = BSL_LIST_GET_FIRST(nameList);
    while (node != NULL) {
        names[index++] = *node;
        node = BSL_LIST_GET_NEXT(nameList);
    }
    int32_t ret = HITLS_X509_CsrCtrl(csr, HITLS_X509_ADD_SUBJECT_NAME, names, count);
    BSL_SAL_FREE(names);
    if (ret != HITLS_PKI_SUCCESS) {
        AppPrintError("Failed to add subject name to csr.\n");
    }

    return ret;
}

static int32_t SetDnTypeAndValue(HITLS_X509_DN *name, const char *nameTypeStr, const char *nameValueStr)
{
    const BslAsn1DnInfo *asn1DnInfo = BSL_OBJ_GetDnInfoFromShortName(nameTypeStr);
    if (asn1DnInfo == NULL) {
        AppPrintError("warning: Skip unknow distinguish name, name type: %s.\n", nameTypeStr);
        return HITLS_APP_SUCCESS;
    }
    if (strlen(nameValueStr) == 0) {
        AppPrintError("warning: No value provided for name type: %s.\n", nameTypeStr);
        return HITLS_APP_SUCCESS;
    }
    name->cid = asn1DnInfo->cid;
    name->dataLen = strlen(nameValueStr);
    name->data = BSL_SAL_Dump(nameValueStr, strlen(nameValueStr) + 1);
    if (name->data == NULL) {
        AppPrintError("Failed to copy name value when process distinguish name: %s.\n", nameValueStr);
        return HITLS_APP_MEM_ALLOC_FAIL;
    }

    return HITLS_APP_SUCCESS;
}

static int32_t GetDnTypeAndValue(const char **nameStr, HITLS_X509_DN *name, bool *isMultiVal)
{
    char *nameTypeStr = NULL;
    char *nameValueStr = NULL;
    const char *p = *nameStr;
    if (*p == '\0') {
        return HITLS_APP_SUCCESS;
    }
    char *tmp = BSL_SAL_Dump(p, strlen(p) + 1);
    if (tmp == NULL) {
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    nameTypeStr = tmp;
    while (*p != '\0' && *p != '=') {
        *tmp++ = *p++;
    }
    *tmp++ = '\0';
    if (*p == '\0') {
        AppPrintError("The type(%s) must be have value.\n", nameTypeStr);
        BSL_SAL_FREE(nameTypeStr);
        return HITLS_APP_INVALID_DN_VALUE;
    }
    p++; // skip '='
    nameValueStr = tmp;
    while (*p != '\0' && *p != '/') {
        if (*p == '+') {
            *isMultiVal = true;
            break;
        }
        if (*p == '\\' && *++p == '\0') {
            BSL_SAL_FREE(nameTypeStr);
            AppPrintError("Error charactor.\n");
            return HITLS_APP_INVALID_DN_VALUE;
        }
        *tmp++ = *p++;
    }
    if (*p == '/' || *p == '+') {
        *tmp++ = '\0';
    }
    int32_t ret = SetDnTypeAndValue(name, nameTypeStr, nameValueStr);
    BSL_SAL_FREE(nameTypeStr);
    *nameStr = p;
    return ret;
}

static void FreeX509Dn(HITLS_X509_DN *name)
{
    if (name == NULL) {
        return;
    }
    BSL_SAL_FREE(name->data);
    BSL_SAL_FREE(name);
}

/* distinguish name format is /type0=value0/type1=value1/type2=... */
int32_t HITLS_APP_CFG_ProcDnName(const char *nameStr, AddDnNameCb addCb, void *ctx)
{
    if (nameStr == NULL || addCb == NULL || strlen(nameStr) <= 1 || nameStr[0] != '/') {
        return HITLS_APP_INVALID_ARG;
    }
    int32_t ret = HITLS_APP_SUCCESS;
    BslList *dnNameList = NULL;
    const char *p = nameStr;
    bool isMultiVal = false;

    while (*p != '\0') {
        p++;
        if (!isMultiVal) {
            BSL_LIST_FREE(dnNameList, (BSL_LIST_PFUNC_FREE)FreeX509Dn);
            dnNameList = BSL_LIST_New(sizeof(HITLS_X509_DN *));
            if (dnNameList == NULL) {
                return HITLS_APP_MEM_ALLOC_FAIL;
            }
        }
        HITLS_X509_DN *name = BSL_SAL_Calloc(1, sizeof(HITLS_X509_DN));
        if (name == NULL) {
            ret = HITLS_APP_MEM_ALLOC_FAIL;
            goto EXIT;
        }
        ret = GetDnTypeAndValue(&p, name, &isMultiVal);
        if (ret != HITLS_APP_SUCCESS) {
            BSL_SAL_FREE(name);
            goto EXIT;
        }
        if (name->data == NULL) {
            BSL_SAL_FREE(name);
            continue;
        }
        // add to list
        ret = BSL_LIST_AddElement(dnNameList, name, BSL_LIST_POS_END);
        if (ret != BSL_SUCCESS) {
            BSL_SAL_FREE(name->data);
            BSL_SAL_FREE(name);
            goto EXIT;
        }
        if (*p == '/' || *p == '\0') {
            // add to csr or cert
            ret = addCb(ctx, dnNameList);
            BSL_LIST_FREE(dnNameList, (BSL_LIST_PFUNC_FREE)FreeX509Dn);
            if (ret != HITLS_APP_SUCCESS) {
                goto EXIT;
            }
            isMultiVal = false;
        }
    }
    if (ret == HITLS_APP_SUCCESS && dnNameList != NULL && BSL_LIST_COUNT(dnNameList) != 0) {
        ret = addCb(ctx, dnNameList);
    }
EXIT:
    BSL_LIST_FREE(dnNameList, (BSL_LIST_PFUNC_FREE)FreeX509Dn);
    return ret;
}
