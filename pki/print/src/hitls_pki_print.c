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
#ifdef HITLS_PKI_INFO
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "bsl_list.h"
#include "bsl_uio.h"
#include "bsl_asn1.h"
#include "bsl_obj_internal.h"
#include "bsl_err_internal.h"
#include "hitls_x509_local.h"
#include "hitls_pki_errno.h"
#include "hitls_print_local.h"

static uint32_t g_nameFlag = HITLS_PKI_PRINT_DN_RFC2253;

static char g_rfc2253Escape[] = {',', '+', '"', '\\', '<', '>', ';'};

#define RFC2253_ESCAPE_CHAR_CNT (sizeof(g_rfc2253Escape) / sizeof(g_rfc2253Escape[0]))

static char *GetPrefixFmt(bool preLayerIs2, bool isFirst)
{
    if (preLayerIs2) {
        if (g_nameFlag == HITLS_PKI_PRINT_DN_RFC2253) {
            return "+%s=";
        }
        return " + %s = ";
    }
    if (g_nameFlag == HITLS_PKI_PRINT_DN_RFC2253) {
        return isFirst ? "%s=" : ",%s=";
    }

    if (g_nameFlag == HITLS_PKI_PRINT_DN_ONELINE) {
        return isFirst ? "%s = " : ", %s = ";
    }
    return "%s = ";  // multiline
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

static int32_t PrintDnNameValue(BSL_ASN1_Buffer *value, BSL_UIO *uio)
{
    uint8_t *cur = value->buff;
    uint8_t *end = value->buff + value->len;
    char quote = '"';
    bool needQuote = NeedQuote(value);
    if (needQuote && BSL_ASN1_PrintfBuff(0, uio, &quote, 1) != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_PRINT_ERR_DNNAME_VALUE);
        return HITLS_PRINT_ERR_DNNAME_VALUE;
    }
    char c;
    char *fmt;
    int32_t ret;
    while (cur != end) {
        c = *cur;
        /*
         * RFC2253： section 2.4
         * Characters that need escaping:
         * (1) A space or "#" character occurring at the beginning of the string
         * (2) A space character occurring at the end of the string
         * (3) One of the characters: ",", "+", """, "\", "<", ">", ";"
         */
        fmt = NULL;
        if (c < ' ' || c > '~') { // control character
            fmt = "\\%02X";
        } else if (g_nameFlag == HITLS_PKI_PRINT_DN_RFC2253) {
            if ((cur == value->buff && (c == ' ' || c == '#')) ||             // (1)
                (cur + 1 == end && c == ' ') ||                               // (2)
                CharInList(c, g_rfc2253Escape, RFC2253_ESCAPE_CHAR_CNT)) {    // (3)
                fmt = "\\%c";
            }
        } else if (needQuote && c == '"') {
            fmt = "\\%c";
        }
        ret = fmt == NULL ? BSL_ASN1_PrintfBuff(0, uio, &c, 1) : BSL_ASN1_Printf(0, uio, fmt, c);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(HITLS_PRINT_ERR_DNNAME_VALUE);
            return HITLS_PRINT_ERR_DNNAME_VALUE;
        }
        cur++;
    }
    if (needQuote && BSL_ASN1_PrintfBuff(0, uio, &quote, 1) != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_PRINT_ERR_DNNAME_VALUE);
        return HITLS_PRINT_ERR_DNNAME_VALUE;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t PrintDn(uint32_t layer, BSL_ASN1_List *nameList, bool newLine, BSL_UIO *uio)
{
    BslOidString oid = {0};
    const char *oidName = NULL;
    bool preLayerIs2 = false;
    int8_t namePosFlag = -1; // -1: not start; 0: first; 1: other
    int32_t ret;
    HITLS_X509_NameNode *name = g_nameFlag == HITLS_PKI_PRINT_DN_RFC2253 ?
        BSL_LIST_GET_LAST(nameList) : BSL_LIST_GET_FIRST(nameList);
    while (name != NULL) {
        if (name->layer == 1) {
            preLayerIs2 = false;
            name = g_nameFlag == HITLS_PKI_PRINT_DN_RFC2253 ? BSL_LIST_GET_PREV(nameList) :
            BSL_LIST_GET_NEXT(nameList);
            continue;
        }
        namePosFlag = namePosFlag == -1 ? 0 : 1;
        oid.octs = (char *)name->nameType.buff;
        oid.octetLen = name->nameType.len;
        oidName = BSL_OBJ_GetOidNameFromOid(&oid); // multiline format use long name, but now only support short name
        if (oidName == NULL) {
            oidName = "Unknown";
        }
        if (g_nameFlag == HITLS_PKI_PRINT_DN_MULTILINE) {
            if (namePosFlag == 0) {
                ret = BSL_ASN1_PrintfBuff(layer, uio, NULL, 0);
            } else if (!preLayerIs2) {
                ret = BSL_ASN1_PrintfBuff(0, uio, "\n", strlen("\n")) || BSL_ASN1_PrintfBuff(layer, uio, NULL, 0);
            }
            if (ret != BSL_SUCCESS) {
                BSL_ERR_PUSH_ERROR(HITLS_PRINT_ERR_DNNAME);
                return HITLS_PRINT_ERR_DNNAME;
            }
        }
        /* print type */
        if (BSL_ASN1_Printf(0, uio, GetPrefixFmt(preLayerIs2, namePosFlag == 0), oidName) != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(HITLS_PRINT_ERR_DNNAME);
            return HITLS_PRINT_ERR_DNNAME;
        }
        /* print value */
        if (name->nameValue.buff != NULL && name->nameValue.len != 0) {
            ret = PrintDnNameValue(&name->nameValue, uio);
            if (ret != HITLS_PKI_SUCCESS) {
                return ret;
            }
        }
        preLayerIs2 = name->layer != 1;
        name = g_nameFlag == HITLS_PKI_PRINT_DN_RFC2253 ? BSL_LIST_GET_PREV(nameList) :
            BSL_LIST_GET_NEXT(nameList);
    }
    if (newLine) {
        return BSL_ASN1_PrintfBuff(0, uio, "\n", strlen("\n")) != 0 ? HITLS_PRINT_ERR_DNNAME : HITLS_PKI_SUCCESS;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t SetPrintFlag(void *val, uint32_t valLen)
{
    if (val == NULL || valLen != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    g_nameFlag = *(uint32_t *)val;
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_PKI_PrintCtrl(int32_t cmd, void *val, uint32_t valLen, BSL_UIO *uio)
{
    if (cmd == HITLS_PKI_SET_PRINT_FLAG) {
        return SetPrintFlag(val, valLen);
    }
    if (val == NULL || uio == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    switch (cmd) {
        case HITLS_PKI_PRINT_DN:
            if (valLen != sizeof(BslList)) {
                BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
                return HITLS_X509_ERR_INVALID_PARAM;
            }
            return PrintDn(g_nameFlag == HITLS_PKI_PRINT_DN_MULTILINE ? 1 : 0, val, false, uio);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
            return HITLS_X509_ERR_INVALID_PARAM;
    }
}
#endif // HITLS_PKI_INFO
