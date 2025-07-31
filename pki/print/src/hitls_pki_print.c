/**
 * @copyright Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * @file      hitls_pki_print.c
 * @brief     x509 print functions.
 * @create:   2024-09-14
 */

#include "hitls_build.h"
#ifdef HITLS_PKI_INFO
#include <string.h>
#include <inttypes.h>
#include "bsl_sal.h"
#include "bsl_list.h"
#include "bsl_obj_internal.h"
#include "bsl_err_internal.h"
#include "bsl_print.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_md.h"
#include "crypt_errno.h"
#include "crypt_encode_decode_key.h"
#include "crypt_utils.h"
#include "hitls_pki_errno.h"
#include "hitls_x509_local.h"
#ifdef HITLS_PKI_X509_CRT
#include "hitls_cert_local.h"
#endif
#ifdef HITLS_PKI_X509_CSR
#include "hitls_csr_local.h"
#endif
#include "hitls_pki_utils.h"
#include "hitls_print_local.h"

#define HITLS_X509_IPV4_LEN 4
#define HITLS_X509_IPV6_LEN 16

#define HITLS_X509_UNKOWN "Unknown\n"
#define HITLS_X509_UNSUPPORT "<unsupported>"
#define HITLS_X509_UNSUPPORT_N "<unsupported>\n"
#define HITLS_X509_V3_EXT "X509V3 extensions:\n"
#define HITLS_X509_UNSUPPORT_EXT "<Unsupported extension>\n"
#define HITLS_X509_PRINT_NEW_LINE "\n"

#if defined(HITLS_PKI_X509_CRT) || defined(HITLS_PKI_X509_CSR)
typedef struct {
    uint32_t type;
    const char *name;
} HITLS_X509_TypeNameMap;

static HITLS_X509_TypeNameMap g_keyUsageNameMap[] = {
    {HITLS_X509_EXT_KU_DIGITAL_SIGN, "Digital Signature"},
    {HITLS_X509_EXT_KU_NON_REPUDIATION, "Non Repudiation"},
    {HITLS_X509_EXT_KU_KEY_ENCIPHERMENT, "Key Encipherment"},
    {HITLS_X509_EXT_KU_DATA_ENCIPHERMENT, "Data Encipherment"},
    {HITLS_X509_EXT_KU_KEY_AGREEMENT, "Key Agreement"},
    {HITLS_X509_EXT_KU_KEY_CERT_SIGN, "Certificate Sign"},
    {HITLS_X509_EXT_KU_CRL_SIGN, "CRL Sign"},
    {HITLS_X509_EXT_KU_ENCIPHER_ONLY, "Encipher Only"},
    {HITLS_X509_EXT_KU_DECIPHER_ONLY, "Decipher Only"},
};

static HITLS_X509_TypeNameMap g_gnNameMap[] = {
    {HITLS_X509_GN_OTHER, "OtherName"},
    {HITLS_X509_GN_EMAIL, "Email"},
    {HITLS_X509_GN_DNS, "DNS"},
    {HITLS_X509_GN_X400, "X400Name"},
    {HITLS_X509_GN_DNNAME, "DirName"},
    {HITLS_X509_GN_EDI, "EdiPartyName"},
    {HITLS_X509_GN_URI, "URI"},
    {HITLS_X509_GN_IP, "IP Address"},
    {HITLS_X509_GN_RID, "Registered ID"},
};

#define HITLS_X509_KU_CNT (sizeof(g_keyUsageNameMap) / sizeof(g_keyUsageNameMap[0]))
#define HITLS_X509_GN_NAME_CNT (sizeof(g_gnNameMap) / sizeof(g_gnNameMap[0]))
#endif // HITLS_PKI_X509_CRT || HITLS_PKI_X509_CSR

static int32_t g_nameFlag = HITLS_PKI_PRINT_DN_RFC2253;

static char g_rfc2253Ecsape[] = {',', '+', '"', '\\', '<', '>', ';'};

#define RFC2253_ESCAPE_CHAR_CNT (sizeof(g_rfc2253Ecsape) / sizeof(char))

int32_t HITLS_PKI_SetPrintFlag(int32_t val)
{
    g_nameFlag = val;
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_PKI_GetPrintFlag(void)
{
    return g_nameFlag;
}

static const char *GetNameByOid(BslOidString *oid)
{
    const char *res = NULL;
    if (g_nameFlag == HITLS_PKI_PRINT_DN_RFC2253) {
        BslCid cid = BSL_OBJ_GetCID(oid);
        const BslAsn1DnInfo *dnInfo = BSL_OBJ_GetDnInfoFromCid(cid);
        if (dnInfo != NULL) {
            res = dnInfo->shortName;
        }
        if (res == NULL) {
            res = BSL_OBJ_GetOidNameFromOid(oid);
        }
    } else if (g_nameFlag == HITLS_PKI_PRINT_DN_MULTILINE) {
        res = BSL_OBJ_GetOidNameFromOid(oid);
    } else {
        res = BSL_OBJ_GetOidNameFromOid(oid);
    }
    return res == NULL ? "Unknown" : res;
}

static bool NeedQuote(BSL_ASN1_Buffer *value)
{
    if (g_nameFlag != HITLS_PKI_PRINT_DN_ONELINE) {
        return false;
    }
    for (uint32_t i = 0; i < value->len; i++) {
        if (i == 0 && (value->buff[i] == '#' || value->buff[i] == ' ')) {
            return true;
        }
        if (value->buff[i] == ',' || value->buff[i] == '<' || value->buff[i] == '>') {
            return true;
        }
    }
    return false;
}

static bool CharInList(char c, char *list, uint32_t listSize)
{
    for (uint32_t i = 0; i < listSize; i++) {
        if (c == list[i]) {
            return true;
        }
    }
    return false;
}

/*
 * RFC2253: section 2.4
 * The following characters need to be escaped"
 * (1) a space or "#" character occurring at the beginning of the string
 * (2) a space character occurring at the end of the string
 * (3) one of the characters ",", "+", """, "\", "<", ">" or ";"
 */
static bool Rfc2253Escape(uint8_t *cur, uint64_t c, uint8_t *begin, uint8_t *end)
{
    return g_nameFlag == HITLS_PKI_PRINT_DN_RFC2253 &&               // RFC 2253
           ((cur == begin && (c == ' ' || c == '#')) ||               // (1)
           (cur + 1 == end && c == ' ') ||                            // (2)
           CharInList((char)c, g_rfc2253Ecsape, RFC2253_ESCAPE_CHAR_CNT));  // (3)
}

static int32_t PrintDnNameValue(BSL_ASN1_Buffer *value, BSL_UIO *uio)
{
    uint8_t *cur = value->buff;
    uint8_t *end = value->buff + value->len;
    uint64_t c;
    char quote = '"';
    bool needQuote = NeedQuote(value);
    if (needQuote && BSL_PRINT_Buff(0, uio, &quote, 1) != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_PRINT_ERR_DNNAME_VALUE);
        return HITLS_PRINT_ERR_DNNAME_VALUE;
    }
    char *fmt;
    int32_t ret;
    char tmpC;
    while (cur != end) {
        c = *cur;
        fmt = NULL;
        tmpC = 0;
        if (c < ' ' || c > '~') {  // control character
            fmt = "\\%02"PRIX64"";
        } else if (Rfc2253Escape(cur, c, value->buff, end) == true) {
            fmt = "\\%c";
            tmpC = (char)c;
        } else if (needQuote && c == '"') {
            fmt = "\\\"";
        }
        if (tmpC != 0) {
            ret = fmt == NULL ? BSL_PRINT_Buff(0, uio, &tmpC, 1) : BSL_PRINT_Fmt(0, uio, fmt, tmpC);
        } else {
            tmpC = (char)c;
            ret = fmt == NULL ? BSL_PRINT_Buff(0, uio, &tmpC, 1) : BSL_PRINT_Fmt(0, uio, fmt, c);
        }
        if (ret != 0) {
            BSL_ERR_PUSH_ERROR(HITLS_PRINT_ERR_DNNAME_VALUE);
            return HITLS_PRINT_ERR_DNNAME_VALUE;
        }
        cur++;
    }

    if (needQuote && BSL_PRINT_Buff(0, uio, &quote, 1) != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_PRINT_ERR_DNNAME_VALUE);
        return HITLS_PRINT_ERR_DNNAME_VALUE;
    }
    return HITLS_PKI_SUCCESS;
}

static char *GetPrefixFmt(bool preLayerIs2, bool isFirst)
{
    if (preLayerIs2) {
        if (g_nameFlag == HITLS_PKI_PRINT_DN_RFC2253) {
            return "+%s=";
        }
        return " + %s = ";  // multiline or oneline
    }
    if (g_nameFlag == HITLS_PKI_PRINT_DN_RFC2253) {
        return isFirst ? "%s=" : ",%s=";
    }
    if (g_nameFlag == HITLS_PKI_PRINT_DN_ONELINE) {
        return isFirst ? "%s = " : ", %s = ";
    }
    return "%s = ";  // multiline
}

int32_t HITLS_PKI_PrintDnName(uint32_t layer, BslList *list, bool newLine, BSL_UIO *uio)
{
    BslOidString oid = {0};
    const char *oidName = NULL;
    HITLS_X509_NameNode *name = NULL;
    bool preLayerIs2 = false;
    int8_t namePosFlag = -1;  // -1: not start; 0: first; 1: others
    int32_t ret = HITLS_PKI_SUCCESS;

    for (name = g_nameFlag == HITLS_PKI_PRINT_DN_RFC2253 ? BSL_LIST_GET_LAST(list) : BSL_LIST_GET_FIRST(list);
         name != NULL;
         name = g_nameFlag == HITLS_PKI_PRINT_DN_RFC2253 ? BSL_LIST_GET_PREV(list) : BSL_LIST_GET_NEXT(list)) {
        if (name->layer == 1) {
            preLayerIs2 = false;
            continue;
        }
        namePosFlag = namePosFlag == -1 ? 0 : 1;
        oid.octs = (char *)name->nameType.buff;
        oid.octetLen = name->nameType.len;
        oidName = GetNameByOid(&oid);
        /* prefix: name */
        if (g_nameFlag == HITLS_PKI_PRINT_DN_MULTILINE) {
            if (namePosFlag == 0) {  // first: Only indent
                ret = BSL_PRINT_Buff(layer, uio, NULL, 0);
            } else if (!preLayerIs2) {  // not first or multi: Line wrap and indent
                ret = BSL_PRINT_Fmt(0, uio, "\n") != 0 || BSL_PRINT_Buff(layer, uio, NULL, 0) != 0;
            }
            if (ret != 0) {
                BSL_ERR_PUSH_ERROR(HITLS_PRINT_ERR_DNNAME);
                return HITLS_PRINT_ERR_DNNAME;
            }
        }
        if (BSL_PRINT_Fmt(0, uio, GetPrefixFmt(preLayerIs2, namePosFlag == 0), oidName) != 0) {
            BSL_ERR_PUSH_ERROR(HITLS_PRINT_ERR_DNNAME);
            return HITLS_PRINT_ERR_DNNAME;
        }
        /* value */
        if (name->nameValue.buff != NULL && name->nameValue.len != 0) {
            if (PrintDnNameValue(&name->nameValue, uio) != 0) {
                return HITLS_PRINT_ERR_DNNAME_VALUE;
            }
        }
        preLayerIs2 = name->layer != 1;
    }
    if (newLine) {
        return BSL_PRINT_Buff(0, uio, HITLS_X509_PRINT_NEW_LINE, strlen(HITLS_X509_PRINT_NEW_LINE)) == 0
                   ? HITLS_PKI_SUCCESS
                   : HITLS_PRINT_ERR_DNNAME;
    }

    return HITLS_PKI_SUCCESS;
}

#if defined(HITLS_PKI_X509_CRT) || defined(HITLS_PKI_X509_CSR)
static int32_t PrintBCons(HITLS_X509_Ext *ext, uint32_t layer, BSL_UIO *uio)
{
    HITLS_X509_CertExt *certExt = ext->extData;
    if (certExt == NULL) {
        return HITLS_PKI_SUCCESS;
    }
    if (certExt->maxPathLen >= 0) {
        return BSL_PRINT_Fmt(layer, uio, "CA:%s, pathlen:%d\n", certExt->isCa ? "TRUE" : "FALSE",
            certExt->maxPathLen);
    } else {
        return BSL_PRINT_Fmt(layer, uio, "CA:%s\n", certExt->isCa ? "TRUE" : "FALSE");
    }
}

static int32_t PrintKeyUsage(HITLS_X509_Ext *ext, uint32_t layer, BSL_UIO *uio)
{
    HITLS_X509_CertExt *certExt = ext->extData;
    if (certExt == NULL) {
        return HITLS_PKI_SUCCESS;
    }
    uint32_t cnt = 0;
    char *fmt = NULL;
    for (uint32_t i = 0; i < HITLS_X509_KU_CNT; i++) {
        if ((certExt->keyUsage & g_keyUsageNameMap[i].type) == 0) {
            continue;
        }
        fmt = cnt == 0 ? "%s" : ", %s";
        if (BSL_PRINT_Fmt(cnt == 0 ? layer : 0, uio, fmt, g_keyUsageNameMap[i].name) != 0) {
            BSL_ERR_PUSH_ERROR(HITLS_PRINT_ERR_EXT_KU);
            return HITLS_PRINT_ERR_EXT_KU;
        }
        cnt++;
    }
    if (cnt == 0) {
        return HITLS_PKI_SUCCESS;
    }
    return BSL_PRINT_Buff(0, uio, HITLS_X509_PRINT_NEW_LINE, strlen(HITLS_X509_PRINT_NEW_LINE)) == 0
               ? HITLS_PKI_SUCCESS
               : HITLS_PRINT_ERR_EXT_KU;
}

static int32_t PrintIpAddress(BSL_Buffer *ip, uint32_t layer, BSL_UIO *uio)
{
    if (ip->dataLen == HITLS_X509_IPV4_LEN) {
        return BSL_PRINT_Fmt(layer, uio, "%d.%d.%d.%d", ip->data[0], ip->data[1],
            ip->data[2], ip->data[3]); // 0,1,2,3: Displays the decimal number of each byte of the IP address.
    } else if (ip->dataLen == HITLS_X509_IPV6_LEN) {
        int32_t ret;
        for (uint32_t i = 0; i < HITLS_X509_IPV6_LEN; i += 2) { // Print 2 bytes at a time.
            ret = BSL_PRINT_Fmt(
                layer, uio, (i + 2) == HITLS_X509_IPV6_LEN ? "%X" : "%X:", // Print 2 bytes at a time.
                ip->data[i] << 8 | ip->data[i + 1]); // left shift 8 bits
            if (ret != 0) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
        }
        return HITLS_PKI_SUCCESS;
    } else {
        return BSL_PRINT_Fmt(layer, uio, "<invalid lenth=%d>", ip->dataLen);
    }
}

static int32_t PrintGeneralName(HITLS_X509_GeneralName *gn, bool first, uint32_t layer, BSL_UIO *uio)
{
    const char *name = NULL;
    for (uint32_t i = 0; i < HITLS_X509_GN_NAME_CNT; i++) {
        if (g_gnNameMap[i].type == gn->type) {
            name = g_gnNameMap[i].name;
            break;
        }
    }
    if (name == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PRINT_ERR_GNNAME_UNKNOWN);
        return HITLS_PRINT_ERR_GNNAME_UNKNOWN;
    }
    int32_t ret = BSL_PRINT_Fmt(layer, uio, first ? "%s:" : ", %s:", name);
    if (ret != 0) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    switch (gn->type) {
        case HITLS_X509_GN_EMAIL:
        case HITLS_X509_GN_DNS:
        case HITLS_X509_GN_URI:
            return BSL_PRINT_Buff(0, uio, gn->value.data, gn->value.dataLen);
        case HITLS_X509_GN_IP:
            return PrintIpAddress(&gn->value, 0, uio);
        case HITLS_X509_GN_DNNAME:
            return HITLS_PKI_PrintDnName(0, (BslList *)gn->value.data, false, uio);
        default:
            return BSL_PRINT_Buff(0, uio, HITLS_X509_UNSUPPORT, strlen(HITLS_X509_UNSUPPORT));
    }
}

static int32_t PrintGeneralNames(BslList *list, uint32_t layer, BSL_UIO *uio)
{
    uint32_t cnt = 0;
    int32_t ret;
    for (HITLS_X509_GeneralName *gn = BSL_LIST_GET_FIRST(list); gn != NULL; gn = BSL_LIST_GET_NEXT(list)) {
        ret = PrintGeneralName(gn, cnt == 0, cnt == 0 ? layer : 0, uio);
        if (ret != 0) {
            BSL_ERR_PUSH_ERROR(HITLS_PRINT_ERR_GNNAME);
            return HITLS_PRINT_ERR_GNNAME;
        }
        cnt++;
    }
    if (cnt == 0) {
        return HITLS_PKI_SUCCESS;
    }
    return BSL_PRINT_Buff(0, uio, HITLS_X509_PRINT_NEW_LINE, strlen(HITLS_X509_PRINT_NEW_LINE)) == 0
               ? HITLS_PKI_SUCCESS
               : HITLS_PRINT_ERR_GNNAME;
}

static int32_t PrintAki(HITLS_X509_ExtEntry *entry, uint32_t layer, BSL_UIO *uio)
{
    HITLS_X509_ExtAki aki = {0};
    int32_t ret = HITLS_X509_ParseAuthorityKeyId(entry, &aki);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (aki.kid.data != NULL) {
        if (BSL_PRINT_Fmt(layer, uio, "Keyid: ") != 0 ||
            BSL_PRINT_Hex(0, true, aki.kid.data, aki.kid.dataLen, uio) != 0) {
            HITLS_X509_ClearAuthorityKeyId(&aki);
            BSL_ERR_PUSH_ERROR(HITLS_PRINT_ERR_EXT_AKI_KID);
            return HITLS_PRINT_ERR_EXT_AKI_KID;
        }
    }
    if (aki.issuerName != NULL) {
        if (PrintGeneralNames(aki.issuerName, layer, uio) != 0) {
            HITLS_X509_ClearAuthorityKeyId(&aki);
            BSL_ERR_PUSH_ERROR(HITLS_PRINT_ERR_EXT_AKI_ISSUER);
            return HITLS_PRINT_ERR_EXT_AKI_ISSUER;
        }
    }
    if (aki.serialNum.data != NULL) {
        if (BSL_PRINT_Fmt(layer, uio, "Serial: ") != 0 ||
            BSL_PRINT_Hex(0, true, aki.serialNum.data, aki.serialNum.dataLen, uio) != 0) {
            HITLS_X509_ClearAuthorityKeyId(&aki);
            BSL_ERR_PUSH_ERROR(HITLS_PRINT_ERR_EXT_AKI_SERIAL);
            return HITLS_PRINT_ERR_EXT_AKI_SERIAL;
        }
    }
    HITLS_X509_ClearAuthorityKeyId(&aki);
    return HITLS_PKI_SUCCESS;
}

static int32_t PrintSki(HITLS_X509_ExtEntry *entry, uint32_t layer, BSL_UIO *uio)
{
    HITLS_X509_ExtSki ski = {0};
    int32_t ret = HITLS_X509_ParseSubjectKeyId(entry, &ski);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (ski.kid.data != NULL) {
        if (BSL_PRINT_Hex(layer, true, ski.kid.data, ski.kid.dataLen, uio) != 0) {
            BSL_ERR_PUSH_ERROR(HITLS_PRINT_ERR_EXT_SKI);
            return HITLS_PRINT_ERR_EXT_SKI;
        }
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t PrintSan(HITLS_X509_ExtEntry *entry, uint32_t layer, BSL_UIO *uio)
{
    HITLS_X509_ExtSan san = {0};
    int32_t ret = HITLS_X509_ParseSubjectAltName(entry, &san);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (BSL_LIST_COUNT(san.names) == 0) {
        HITLS_X509_ClearSubjectAltName(&san);
        return HITLS_PKI_SUCCESS;
    }
    ret = PrintGeneralNames(san.names, layer, uio);
    HITLS_X509_ClearSubjectAltName(&san);
    return ret;
}

static int32_t PrintExtendedKeyUsage(HITLS_X509_ExtEntry *entry, uint32_t layer, BSL_UIO *uio)
{
    HITLS_X509_ExtExKeyUsage exKu = {0};
    int32_t ret = HITLS_X509_ParseExtendedKeyUsage(entry, &exKu);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint32_t cnt = 0;
    char *fmt = NULL;
    BslOidString oidStr = {0};
    for (BSL_Buffer *oid = BSL_LIST_GET_FIRST(exKu.oidList); oid != NULL; oid = BSL_LIST_GET_NEXT(exKu.oidList)) {
        fmt = cnt == 0 ? "%s" : ", %s";
        oidStr.octs = (char *)oid->data;
        oidStr.octetLen = oid->dataLen;
        const char *name = BSL_OBJ_GetOidNameFromOid(&oidStr);
        if (name == NULL) {
            if (BSL_PRINT_Fmt(cnt == 0 ? layer : 0, uio, fmt, HITLS_X509_UNKOWN) != 0) {
                HITLS_X509_ClearExtendedKeyUsage(&exKu);
                BSL_ERR_PUSH_ERROR(HITLS_PRINT_ERR_EXT_EXTKU);
                return HITLS_PRINT_ERR_EXT_EXTKU;
            }
        } else {
            if (BSL_PRINT_Fmt(cnt == 0 ? layer : 0, uio, fmt, name) != 0) {
                HITLS_X509_ClearExtendedKeyUsage(&exKu);
                BSL_ERR_PUSH_ERROR(HITLS_PRINT_ERR_EXT_EXTKU);
                return HITLS_PRINT_ERR_EXT_EXTKU;
            }
        }
        cnt++;
    }
    HITLS_X509_ClearExtendedKeyUsage(&exKu);
    if (cnt == 0) {
        return HITLS_PKI_SUCCESS;
    }
    return BSL_PRINT_Buff(0, uio, HITLS_X509_PRINT_NEW_LINE, strlen(HITLS_X509_PRINT_NEW_LINE)) == 0
               ? HITLS_PKI_SUCCESS
               : HITLS_PRINT_ERR_EXT_EXTKU;
}

static int32_t PrintExt(HITLS_X509_Ext *ext, HITLS_X509_ExtEntry *entry, uint32_t layer, BSL_UIO *uio)
{
    switch (entry->cid) {
        case BSL_CID_CE_BASICCONSTRAINTS:
            return PrintBCons(ext, layer, uio);
        case BSL_CID_CE_KEYUSAGE:
            return PrintKeyUsage(ext, layer, uio);
        case BSL_CID_CE_AUTHORITYKEYIDENTIFIER:
            return PrintAki(entry, layer, uio);
        case BSL_CID_CE_SUBJECTKEYIDENTIFIER:
            return PrintSki(entry, layer, uio);
        case BSL_CID_CE_SUBJECTALTNAME:
            return PrintSan(entry, layer, uio);
        case BSL_CID_CE_EXTKEYUSAGE:
            return PrintExtendedKeyUsage(entry, layer, uio);
        default:
            return BSL_PRINT_Buff(layer, uio, HITLS_X509_UNSUPPORT_N, strlen(HITLS_X509_UNSUPPORT_N)) == 0
                       ? HITLS_PKI_SUCCESS
                       : HITLS_PRINT_ERR_EXT;
    }
}

static int32_t PrintX509Ext(HITLS_X509_Ext *ext, bool isCertExt, uint32_t layer, BSL_UIO *uio)
{
    int32_t count = BSL_LIST_COUNT(ext->extList);
    if (count == 0) {
        return HITLS_PKI_SUCCESS;
    }
    if (isCertExt) {
        if (BSL_PRINT_Buff(layer, uio, HITLS_X509_V3_EXT, strlen(HITLS_X509_V3_EXT)) != 0) {
            BSL_ERR_PUSH_ERROR(HITLS_PRINT_ERR_EXT_NAME);
            return HITLS_PRINT_ERR_EXT_NAME;
        }
    }

    HITLS_X509_ExtEntry *entry = BSL_LIST_GET_FIRST(ext->extList);
    const char *extName = NULL;
    int32_t ret;
    int32_t tmpNameFlag = g_nameFlag;
    g_nameFlag = HITLS_PKI_PRINT_DN_RFC2253; /* The ext content must be printed in one line. Therefore, the format of
                                                 dirname is RFC2253. */
    for (entry = BSL_LIST_GET_FIRST(ext->extList); entry != NULL; entry = BSL_LIST_GET_NEXT(ext->extList)) {
        extName = BSL_OBJ_GetOidNameFromCID(entry->cid);
        if (extName == NULL) {
            if (BSL_PRINT_Buff(layer + 1, uio, HITLS_X509_UNSUPPORT_EXT, strlen(HITLS_X509_UNSUPPORT_EXT)) != 0) {
                g_nameFlag = tmpNameFlag;
                BSL_ERR_PUSH_ERROR(HITLS_PRINT_ERR_EXT_NAME);
                return HITLS_PRINT_ERR_EXT_NAME;
            }
            continue;
        }
        if (BSL_PRINT_Fmt(layer + 1, uio, "%s:%s\n", extName, entry->critical ? " critical" : "") != 0) {
            g_nameFlag = tmpNameFlag;
            BSL_ERR_PUSH_ERROR(HITLS_PRINT_ERR_EXT_NAME);
            return HITLS_PRINT_ERR_EXT_NAME;
        }

        ret = PrintExt(ext, entry, layer + 1 + 1, uio);
        if (ret != HITLS_PKI_SUCCESS) {
            g_nameFlag = tmpNameFlag;
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    g_nameFlag = tmpNameFlag;

    return HITLS_PKI_SUCCESS;
}

static const char *GetPkeyAlgName(CRYPT_EAL_PkeyCtx *pkey)
{
    CRYPT_RsaPadType padType = 0;
    int32_t ret;
    switch (CRYPT_EAL_PkeyGetId(pkey)) {
        case CRYPT_PKEY_RSA: {
            ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_RSA_PADDING, &padType, sizeof(CRYPT_RsaPadType));
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return HITLS_X509_UNSUPPORT;
            }
            const char *name = BSL_OBJ_GetOidNameFromCID(padType == CRYPT_EMSA_PSS ? BSL_CID_RSASSAPSS : BSL_CID_RSA);
            return name == NULL ? HITLS_X509_UNSUPPORT : name;
        }
        case CRYPT_PKEY_ECDSA:
        case CRYPT_PKEY_SM2: {
            const char *name = BSL_OBJ_GetOidNameFromCID(BSL_CID_EC_PUBLICKEY);
            return name == NULL ? HITLS_X509_UNSUPPORT : name;
        }
        default:
            return HITLS_X509_UNSUPPORT;
    }
}

static int32_t PrintPubKey(uint32_t layer, CRYPT_EAL_PkeyCtx *pkey, BSL_UIO *uio)
{
    const char *name = GetPkeyAlgName(pkey);
    if (BSL_PRINT_Fmt(layer, uio, "Subject Public Key Info:\n") != 0 ||
        BSL_PRINT_Fmt(layer + 1, uio, "Public Key Algorithm: %s\n", name) != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_PRINT_ERR_PUBKEY);
        return HITLS_PRINT_ERR_PUBKEY;
    }
    return CRYPT_EAL_PrintPubkey(layer + 1 + 1, pkey, uio);
}

static int32_t PrintSignAlgInfo(uint32_t layer, HITLS_X509_Asn1AlgId *algId, BSL_UIO *uio)
{
    const char *name = BSL_OBJ_GetOidNameFromCID(algId->algId);
    if (name == NULL) {
        name = HITLS_X509_UNKOWN;
    }
    if (BSL_PRINT_Fmt(layer, uio, "Signature Algorithm: %s\n", name) != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_PRINT_ERR_SIGN_ALG);
        return HITLS_PRINT_ERR_SIGN_ALG;
    }

    if (algId->algId == BSL_CID_RSASSAPSS) {
#ifdef HITLS_CRYPTO_RSA
        return CRYPT_EAL_PrintRsaPssPara(layer + 1, &algId->rsaPssParam, uio);
#else
        return HITLS_PRINT_ERR_SIGN_ALG_UNSUPPORT;
#endif
    }
    return HITLS_PKI_SUCCESS;
}
#endif

#ifdef HITLS_PKI_X509_CRT
static int32_t PrintCertTbs(uint32_t layer, HITLS_X509_CertTbs *tbs, BSL_UIO *uio)
{
    /* version */
    RETURN_RET_IF(BSL_PRINT_Fmt(layer, uio, "Version: %d (0x%02x)\n", tbs->version + 1, tbs->version) != 0,
        HITLS_PRINT_ERR_CERT_TBS);
    /* serial number */
    RETURN_RET_IF(
        BSL_PRINT_Number(layer, "Serial Number", tbs->serialNum.buff, tbs->serialNum.len, uio) != 0,
        HITLS_PRINT_ERR_CERT_TBS);
    /* signature algorithm */
    int32_t ret = PrintSignAlgInfo(layer, &tbs->signAlgId, uio);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    /* issuer */
    RETURN_RET_IF(BSL_PRINT_Fmt(layer, uio,
        g_nameFlag == HITLS_PKI_PRINT_DN_MULTILINE ? "Issuer: \n" : "Issuer: ") != 0,
        HITLS_PRINT_ERR_DNNAME);
    ret = HITLS_PKI_PrintDnName(layer + 1, tbs->issuerName, true, uio);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    /* validity */
    RETURN_RET_IF(BSL_PRINT_Fmt(layer, uio, "Validity:\n") != 0, HITLS_PRINT_ERR_CERT_TBS);

    RETURN_RET_IF(BSL_PRINT_Fmt(layer + 1, uio, "Not Before: ") != 0 ||
        BSL_PRINT_Time(0, &tbs->validTime.start, uio) != 0,
        HITLS_PRINT_ERR_CERT_TBS);
    RETURN_RET_IF(BSL_PRINT_Fmt(layer + 1, uio, "Not After : ") != 0 ||
        BSL_PRINT_Time(0, &tbs->validTime.end, uio) != 0,
        HITLS_PRINT_ERR_CERT_TBS);

    /* subject */
    RETURN_RET_IF(BSL_PRINT_Fmt(layer, uio,
        g_nameFlag == HITLS_PKI_PRINT_DN_MULTILINE ? "Subject: \n" : "Subject: ") != 0,
        HITLS_PRINT_ERR_DNNAME);
    ret = HITLS_PKI_PrintDnName(layer + 1, tbs->subjectName, true, uio);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    /* pubkey info */
    ret = PrintPubKey(layer, tbs->ealPubKey, uio);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    /* extensions */
    return PrintX509Ext(&tbs->ext, true, layer, uio);
}

static int32_t PrintCert(void *val, BSL_UIO *uio)
{
    uint32_t layer = 0;
    HITLS_X509_Cert *cert = (HITLS_X509_Cert *)val;

    if (BSL_PRINT_Fmt(layer++, uio, "Certificate:\n") != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_PRINT_ERR_CERT);
        return HITLS_PRINT_ERR_CERT;
    }
    if (BSL_PRINT_Fmt(layer, uio, "Data:\n") != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_PRINT_ERR_CERT);
        return HITLS_PRINT_ERR_CERT;
    }
    int32_t ret = PrintCertTbs(layer + 1, &cert->tbs, uio);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = PrintSignAlgInfo(layer, &cert->signAlgId, uio);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return BSL_PRINT_Number(layer, "Signature Value", cert->signature.buff, cert->signature.len, uio);
}
#endif

#ifdef HITLS_PKI_X509_CSR
static int32_t PrintReqExtension(BSL_ASN1_Buffer *reqExtension, uint32_t layer, BSL_UIO *uio)
{
    HITLS_X509_Ext *ext = HITLS_X509_ExtNew(HITLS_X509_EXT_TYPE_CSR);
    if (ext == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = HITLS_X509_ParseExt(reqExtension, ext);
    if (ret != BSL_SUCCESS) {
        HITLS_X509_ExtFree(ext);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = PrintX509Ext(ext, false, layer, uio);
    HITLS_X509_ExtFree(ext);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t PrintAttr(HITLS_X509_AttrEntry *entry, uint32_t layer, BSL_UIO *uio)
{
    switch (entry->cid) {
        case BSL_CID_EXTENSIONREQUEST:
            return PrintReqExtension(&entry->attrValue, layer, uio);
        default:
            return HITLS_X509_ERR_ATTR_UNSUPPORT;
    }
}

static int32_t PrintAttrs(BslList *attrs, uint32_t layer, BSL_UIO *uio)
{
    if (BSL_PRINT_Fmt(layer, uio, "Attributes:\n") != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_PRINT_ERR_CSR_INFO);
        return HITLS_PRINT_ERR_CSR_INFO;
    }

    int32_t count = BSL_LIST_COUNT(attrs);
    if (count == 0) {
        if (BSL_PRINT_Fmt(layer + 1, uio, "(none)\n") != 0) {
            BSL_ERR_PUSH_ERROR(HITLS_PRINT_ERR_CSR_INFO);
            return HITLS_PRINT_ERR_CSR_INFO;
        }
    }
    if (BSL_PRINT_Fmt(layer + 1, uio, "Requested Extensions:\n") != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_PRINT_ERR_CSR_INFO);
        return HITLS_PRINT_ERR_CSR_INFO;
    }
    if (count == 0) {
        return HITLS_PKI_SUCCESS;
    }
    int32_t ret;
    for (HITLS_X509_AttrEntry *entry = BSL_LIST_GET_FIRST(attrs); entry != NULL; entry = BSL_LIST_GET_NEXT(attrs)) {
        ret = PrintAttr(entry, layer + 1, uio);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
    }

    return HITLS_PKI_SUCCESS;
}

static int32_t PrintCsrReqInfo(uint32_t layer, HITLS_X509_ReqInfo *reqInfo, BSL_UIO *uio)
{
    /* version */
    RETURN_RET_IF(BSL_PRINT_Fmt(layer, uio, "Version: %d (0x%02x)\n", reqInfo->version + 1,
        reqInfo->version) != 0, HITLS_PRINT_ERR_CSR_INFO);
    /* subject name */
    RETURN_RET_IF(BSL_PRINT_Fmt(layer, uio,
        g_nameFlag == HITLS_PKI_PRINT_DN_MULTILINE ? "Subject: \n" : "Subject: ") != 0,
        HITLS_PRINT_ERR_DNNAME);
    int32_t ret = HITLS_PKI_PrintDnName(layer + 1, reqInfo->subjectName, true, uio);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    /* pubkey info */
    ret = PrintPubKey(layer, reqInfo->ealPubKey, uio);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    return PrintAttrs(reqInfo->attributes->list, layer, uio);
}

static int32_t PrintCsr(void *val, BSL_UIO *uio)
{
    uint32_t layer = 0;
    HITLS_X509_Csr *csr = (HITLS_X509_Csr *)val;

    if (BSL_PRINT_Fmt(layer++, uio, "Certificate Request:\n") != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_PRINT_ERR_CERT);
        return HITLS_PRINT_ERR_CERT;
    }
    if (BSL_PRINT_Fmt(layer, uio, "Data:\n") != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_PRINT_ERR_CERT);
        return HITLS_PRINT_ERR_CERT;
    }
    int32_t ret = PrintCsrReqInfo(layer + 1, &csr->reqInfo, uio);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = PrintSignAlgInfo(layer, &csr->signAlgId, uio);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return BSL_PRINT_Number(layer, "Signature Value", csr->signature.buff, csr->signature.len, uio);
}
#endif

static int32_t PrintDnNameHash(uint32_t layer, BslList *list, BSL_UIO *uio)
{
    BSL_ASN1_Buffer name = {0};
    uint32_t nameHash = 0;
    uint8_t md[20] = {0};  // 20: CRYPT_SHA1_DIGESTSIZE
    uint32_t mdLen = 20;   // 20: CRYPT_SHA1_DIGESTSIZE

    int32_t ret = HITLS_X509_EncodeCanonNameList(list, &name);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    ret = CRYPT_EAL_Md(CRYPT_MD_SHA1, name.buff, name.len, md, &mdLen);
    BSL_SAL_Free(name.buff);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    nameHash = (((uint32_t)md[0]) |        // 1st byte
                ((uint32_t)md[1] << 8) |   // 2(1+1)nd byte, shift left by 8 bits.
                ((uint32_t)md[2] << 16) |  // 3(2+1)rd byte, shift left by 16 bits.
                ((uint32_t)md[3] << 24));  // 4(3+1)th byte, shift left by 24 bits.

    return BSL_PRINT_Fmt(layer, uio, "%08x\n", nameHash) == 0 ? HITLS_PKI_SUCCESS : HITLS_PRINT_ERR_DNNAME_HASH;
}

int32_t HITLS_PKI_PrintCtrl(int32_t cmd, void *val, uint32_t valLen, BSL_UIO *uio)
{
    if (cmd == HITLS_PKI_SET_PRINT_FLAG) {
        return (val != NULL && valLen == sizeof(int32_t)) ? HITLS_PKI_SetPrintFlag(*(int32_t *)val)
                                                          : HITLS_X509_ERR_INVALID_PARAM;
    }
    if (val == NULL || uio == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    switch (cmd) {
        case HITLS_PKI_PRINT_DNNAME:
            if (valLen != sizeof(BslList)) {
                BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
                return HITLS_X509_ERR_INVALID_PARAM;
            }
            return HITLS_PKI_PrintDnName(g_nameFlag == HITLS_PKI_PRINT_DN_MULTILINE ? 1 : 0, val, true, uio);
        case HITLS_PKI_PRINT_DNNAME_HASH:
            if (valLen != sizeof(BslList)) {
                BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
                return HITLS_X509_ERR_INVALID_PARAM;
            }
            return PrintDnNameHash(0, val, uio);
#ifdef HITLS_PKI_X509_CRT
        case HITLS_PKI_PRINT_CERT:
            if (valLen != sizeof(HITLS_X509_Cert *)) {
                BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
                return HITLS_X509_ERR_INVALID_PARAM;
            }
            return PrintCert(val, uio);
#endif
        case HITLS_PKI_PRINT_NEXTUPDATE:
            if (valLen != sizeof(BSL_TIME)) {
                BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
                return HITLS_X509_ERR_INVALID_PARAM;
            }
            return BSL_PRINT_Time(0, val, uio);
#ifdef HITLS_PKI_X509_CSR
        case HITLS_PKI_PRINT_CSR:
            if (valLen != sizeof(HITLS_X509_Csr *)) {
                BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
                return HITLS_X509_ERR_INVALID_PARAM;
            }
            return PrintCsr(val, uio);
#endif
        default:
            return HITLS_X509_ERR_INVALID_PARAM;
    }
}
#endif // HITLS_PKI_INFO

