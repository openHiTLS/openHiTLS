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
#ifdef HITLS_BSL_CONF

#include <ctype.h>
#include <limits.h>
#include "securec.h"
#include "bsl_uio.h"
#include "bsl_sal.h"
#include "bsl_list.h"
#include "bsl_errno.h"
#include "bsl_err_internal.h"
#include "bsl_conf_def.h"

#define BREAK_FLAG      1
#define CONTINUE_FLAG   2

static int32_t IsNameValid(const char *name)
{
    const char table[128] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, // ',' '.'
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, // '0'-'9' ';'
        0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 'A'-'Z'
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, // '_'
        0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 'a'-'z'
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0
    };
    uint32_t nameLen = (uint32_t)strlen(name);
    char pos = 0;
    for (uint32_t i = 0; i < nameLen; i++) {
        pos = name[i];
        if (pos < 0 || table[(uint32_t)pos] != 1) { // invalid name.
            return 0;
        }
    }
    return 1;
}

static int32_t IsEscapeValid(char c)
{
    char table[] = {
        '#', ';', '$', '\\', '\"', '\''
    };
    uint32_t tableSize = (uint32_t)(sizeof(table) / sizeof(table[0]));
    for (uint32_t i = 0; i < tableSize; i++) {
        if (c == table[i]) {
            return 1;
        }
    }
    return 0;
}

static int32_t RemoveSpace(char *str)
{
    if (str == NULL) {
        return 0;
    }
    int32_t strLen = (int32_t)strlen(str);
    if (strLen == 0) {
        return 0;
    }
    int32_t head = 0;
    int32_t tail = strLen - 1;
    while (head <= tail) {
        if (isspace((unsigned char)str[head])) {
            head++;
        } else {
            break;
        }
    }
    while (head <= tail) {
        if (isspace((unsigned char)str[tail])) {
            tail--;
        } else {
            break;
        }
    }
    int32_t realLen = tail - head + 1;
    if (realLen > 0) {
        (void)memmove_s(str, strLen, str + head, realLen);
    }
    str[realLen] = '\0';
    return realLen;
}

// Parses a string enclosed within quotes, handling escape sequences appropriately.
static int32_t ParseQuote(char *str, char quote)
{
    int32_t cnt = 0;
    int32_t strLen = (int32_t)strlen(str);
    int32_t i = 0;
    while (i < strLen) {
        if (str[i] == quote) {
            break; // Exit the loop when the quote character is encountered.
        }
        if (str[i] == '\\') {
            if (IsEscapeValid(str[i + 1]) == 0 && str[i + 1] != 'n') {
                return BSL_CONF_CONTEXT_ERR; // Return error if the escape sequence is invalid.
            }
            i++; // Skip the escaped character.
            if (i >= strLen) {
                return BSL_CONF_CONTEXT_ERR; // Return error if the index exceeds the string length.
            }
            if (str[i] == 'n') { // '\n'
                str[i] = '\n';
            }
        }
        str[cnt] = str[i];
        cnt++;
        i++;
    }
    str[cnt] = '\0'; // Add a null terminator at the end of the parsed string.
    return BSL_SUCCESS;
}

// Removes escape characters and comments from a string.
static int32_t RemoveEscapeAndComments(char *buff)
{
    bool isValue = false;
    int32_t flag = 0;
    int32_t cnt = 0;
    int32_t len = (int32_t)strlen(buff);
    int32_t i = 0;
    while (i < len) {
        if (buff[i] == '=') {
            isValue = true; // Enter the value part when '=' is encountered.
        }
        if (buff[i] == ';' || buff[i] == '#') {
            if (isValue) { // Encounter a comment symbol in the value part, stop processing.
                break;
            }
        }
        if (buff[i] == '\\') {
            // Escape characters are not allowed in the name part, or the escape character is invalid.
            if (isValue == false) {
                return -1;
            }
            if (IsEscapeValid(buff[i + 1]) == 0 && buff[i + 1] != 'n') {
                return -1;
            }
            flag++;
            i++; // Skip the escape character.
            if (i >= len) { // If the index exceeds the string length, return an error.
                return -1;
            }
            if (buff[i] == 'n') { // '\n'
                buff[i] = '\n';
            }
        }
        buff[cnt] = buff[i];
        cnt++;
        i++;
    }
    buff[cnt] = '\0'; // Add a null terminator at the end of the processed string.
    return flag;
}

static void FreeSectionNames(char **names, int32_t namesSize)
{
    if (names == NULL) {
        return;
    }
    for (int32_t i = 0; i < namesSize; i++) {
        BSL_SAL_FREE(names[i]);
    }
    BSL_SAL_FREE(names);
}

char **DefaultGetSectionNames(BslList *sectionList, uint32_t *namesSize)
{
    if (sectionList == NULL || namesSize == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return NULL;
    }
    int32_t cnt = 0;
    int32_t num = BSL_LIST_COUNT(sectionList);
    char **names = (char **)BSL_SAL_Calloc(num, sizeof(char *));
    if (names == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }
    BSL_CONF_Section *secData = NULL;
    BslListNode *node = BSL_LIST_FirstNode(sectionList);
    while (node != NULL && cnt < num) {
        secData = BSL_LIST_GetData(node);
        if (secData == NULL) {
            FreeSectionNames(names, num);
            BSL_ERR_PUSH_ERROR(BSL_CONF_GET_FAIL);
            return NULL;
        }
        names[cnt] = BSL_SAL_Calloc(secData->sectionLen + 1, 1);
        if (names[cnt] == NULL) {
            FreeSectionNames(names, num);
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return NULL;
        }
        (void)memcpy_s(names[cnt], secData->sectionLen, secData->section, secData->sectionLen);
        cnt++;
        node = BSL_LIST_GetNextNode(sectionList, node);
    }
    if (cnt != num) {
        FreeSectionNames(names, num);
        BSL_ERR_PUSH_ERROR(BSL_CONF_GET_FAIL);
        return NULL;
    }
    *namesSize = (uint32_t)num;
    return names;
}

static int32_t CmpSectionFunc(const void *a, const void *b)
{
    const BSL_CONF_Section *aData = (const BSL_CONF_Section *)a;
    const char *bData = (const char *)b;
    if (aData != NULL && aData->section != NULL && bData != NULL) {
        if (strcmp(aData->section, bData) == 0) {
            return 0;
        }
    }
    return 1;
}

static int32_t CmpKeyFunc(const void *a, const void *b)
{
    const BSL_CONF_KeyValue *aData = (const BSL_CONF_KeyValue *)a;
    const char *bData = (const char *)b;
    if (aData != NULL && aData->key != NULL && bData != NULL) {
        if (strcmp(aData->key, bData) == 0) {
            return 0;
        }
    }
    return 1;
}

void DeleteKeyValueNodeFunc(void *data)
{
    if (data == NULL) {
        return;
    }
    BSL_CONF_KeyValue *keyValueNode = (BSL_CONF_KeyValue *)data;
    BSL_SAL_FREE(keyValueNode->key);
    BSL_SAL_FREE(keyValueNode->value);
    BSL_SAL_FREE(keyValueNode);
}

void DeleteSectionNodeFunc(void *data)
{
    if (data == NULL) {
        return;
    }
    BSL_CONF_Section *sectionNode = (BSL_CONF_Section *)data;
    BSL_LIST_FREE(sectionNode->keyValueList, DeleteKeyValueNodeFunc);
    BSL_SAL_FREE(sectionNode->section);
    BSL_SAL_FREE(sectionNode);
}

static int32_t UpdateKeyValue(BSL_CONF_KeyValue *keyValue, const char *value)
{
    uint32_t newValueLen = (uint32_t)strlen(value);
    char *newValue = (char *)BSL_SAL_Calloc(1, newValueLen + 1);
    if (newValue == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_CONF_MEM_ALLOC_FAIL);
        return BSL_CONF_MEM_ALLOC_FAIL;
    }
    (void)memcpy_s(newValue, newValueLen, value, newValueLen);
    BSL_SAL_FREE(keyValue->value);
    keyValue->value = newValue;
    keyValue->valueLen = newValueLen;
    return BSL_SUCCESS;
}

static int32_t AddKeyValue(BslList *keyValueList, const char * key, const char *value)
{
    int32_t ret = BSL_SUCCESS;
    if (IsNameValid(key) == 0) {
        BSL_ERR_PUSH_ERROR(BSL_CONF_INVALID_NAME);
        return BSL_CONF_INVALID_NAME;
    }
    BSL_CONF_KeyValue *keyValue = (BSL_CONF_KeyValue *)BSL_SAL_Calloc(1, sizeof(BSL_CONF_KeyValue));
    if (keyValue == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_CONF_MEM_ALLOC_FAIL);
        return BSL_CONF_MEM_ALLOC_FAIL;
    }
    keyValue->keyLen = (uint32_t)strlen(key);
    keyValue->key = (char *)BSL_SAL_Calloc(1, keyValue->keyLen + 1);
    if (keyValue->key == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_CONF_MEM_ALLOC_FAIL);
        ret = BSL_CONF_MEM_ALLOC_FAIL;
        goto EXIT;
    }
    keyValue->valueLen = (uint32_t)strlen(value);
    keyValue->value = (char *)BSL_SAL_Calloc(1, keyValue->valueLen + 1);
    if (keyValue->value == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_CONF_MEM_ALLOC_FAIL);
        ret = BSL_CONF_MEM_ALLOC_FAIL;
        goto EXIT;
    }
    (void)memcpy_s(keyValue->key, keyValue->keyLen, key, keyValue->keyLen);
    (void)memcpy_s(keyValue->value, keyValue->valueLen, value, keyValue->valueLen);
    ret = BSL_LIST_AddElement(keyValueList, keyValue, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    return BSL_SUCCESS;
EXIT:
    DeleteKeyValueNodeFunc(keyValue);
    return ret;
}

static int32_t AddSection(BslList *sectionList, const char *section, const char *key, const char *value)
{
    int32_t ret = BSL_SUCCESS;
    if (IsNameValid(section) == 0) {
        BSL_ERR_PUSH_ERROR(BSL_CONF_INVALID_NAME);
        return BSL_CONF_INVALID_NAME;
    }
    BSL_CONF_Section *sectionNode = (BSL_CONF_Section *)BSL_SAL_Calloc(1, sizeof(BSL_CONF_Section));
    if (sectionNode == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_CONF_MEM_ALLOC_FAIL);
        return BSL_CONF_MEM_ALLOC_FAIL;
    }
    sectionNode->sectionLen = (uint32_t)strlen(section);
    sectionNode->section = (char *)BSL_SAL_Calloc(1, sectionNode->sectionLen + 1);
    if (sectionNode->section == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_CONF_MEM_ALLOC_FAIL);
        ret = BSL_CONF_MEM_ALLOC_FAIL;
        goto EXIT;
    }
    (void)memcpy_s(sectionNode->section, sectionNode->sectionLen, section, sectionNode->sectionLen);
    sectionNode->keyValueList = BSL_LIST_New(sizeof(BslList));
    if (sectionNode->keyValueList == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_CONF_MEM_ALLOC_FAIL);
        ret = BSL_CONF_MEM_ALLOC_FAIL;
        goto EXIT;
    }
    if (strlen(key) != 0) {
        ret = AddKeyValue(sectionNode->keyValueList, key, value);
        if (ret != BSL_SUCCESS) {
            goto EXIT;
        }
    }
    ret = BSL_LIST_AddElement(sectionList, sectionNode, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    return BSL_SUCCESS;
EXIT:
    DeleteSectionNodeFunc(sectionNode);
    return ret;
}

BslList *DefaultGetSectionNode(BslList *sectionList, const char *section)
{
    if (sectionList == NULL || section == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return NULL;
    }
    BSL_CONF_Section *sectionNode = BSL_LIST_Search(sectionList, section, CmpSectionFunc, NULL);
    if (sectionNode == NULL || sectionNode->keyValueList == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_CONF_GET_FAIL);
        return NULL;
    }
    return sectionNode->keyValueList;
}

int32_t DefaultGetString(BslList *sectionList, const char *section, const char *key, char *str, uint32_t *strLen)
{
    if (sectionList == NULL || section == NULL || key == NULL || str == NULL || strLen == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    BSL_CONF_Section *secCtx = BSL_LIST_Search(sectionList, section, CmpSectionFunc, NULL);
    if (secCtx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_CONF_GET_FAIL);
        return BSL_CONF_GET_FAIL;
    }
    BSL_CONF_KeyValue *keyValue = BSL_LIST_Search(secCtx->keyValueList, key, CmpKeyFunc, NULL);
    if (keyValue == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_CONF_VALUE_NOT_FOUND);
        return BSL_CONF_VALUE_NOT_FOUND;
    }
    if (*strLen < keyValue->valueLen + 1) { // 1 byte for '\0'
        BSL_ERR_PUSH_ERROR(BSL_CONF_GET_FAIL);
        return BSL_CONF_GET_FAIL;
    }
    (void)memcpy_s(str, *strLen, keyValue->value, keyValue->valueLen);
    str[keyValue->valueLen] = '\0';
    *strLen = keyValue->valueLen;
    return BSL_SUCCESS;
}

int32_t DefaultGetNumber(BslList *sectionList, const char *section, const char *key, long int *num)
{
    char str[BSL_CONF_LINE_SIZE + 1] = {0};
    uint32_t strLen = BSL_CONF_LINE_SIZE + 1;
    int32_t ret = DefaultGetString(sectionList, section, key, str, &strLen);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    char *endPtr = NULL;
    errno = 0;
    long int tmpNum = strtol(str, &endPtr, 0);
    if (strlen(endPtr) > 0 || endPtr == str || (tmpNum == LONG_MAX || tmpNum == LONG_MIN) || errno == ERANGE ||
        (tmpNum == 0 && errno != 0)) {
        BSL_ERR_PUSH_ERROR(BSL_CONF_CONTEXT_ERR);
        return BSL_CONF_CONTEXT_ERR;
    }
    *num = tmpNum;
    return BSL_SUCCESS;
}

BslList *DefaultCreate(void)
{
    BslList *sectionList = BSL_LIST_New(sizeof(BslList));
    if (sectionList == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_CONF_MEM_ALLOC_FAIL);
        return NULL;
    }
    int32_t ret = AddSection(sectionList, "default", "", "");
    if (ret != BSL_SUCCESS) {
        BSL_LIST_FREE(sectionList, NULL);
        return NULL;
    }
    return sectionList;
}

void DefaultDestroy(BslList *sectionList)
{
    if (sectionList == NULL) {
        return;
    }
    BSL_LIST_FREE(sectionList, DeleteSectionNodeFunc);
}

static int32_t SetSection(BslList *sectionList, const char *section, const char * key, const char *value)
{
    if (sectionList == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    BSL_CONF_Section *secCtx = NULL;
    BSL_CONF_KeyValue *keyValue = NULL;
    if (strlen(section) == 0) { // default section.
        if (strlen(key) == 0) {
            BSL_ERR_PUSH_ERROR(BSL_CONF_CONTEXT_ERR);
            return BSL_CONF_CONTEXT_ERR;
        }
        secCtx = BSL_LIST_Search(sectionList, "default", CmpSectionFunc, NULL);
        if (secCtx == NULL || secCtx->keyValueList == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_CONF_GET_FAIL);
            return BSL_CONF_GET_FAIL;
        }
        keyValue = BSL_LIST_Search(secCtx->keyValueList, key, CmpKeyFunc, NULL);
        if (keyValue == NULL) {
            return AddKeyValue(secCtx->keyValueList, key, value);
        } else {
            return UpdateKeyValue(keyValue, value);
        }
    } else {
        secCtx = BSL_LIST_Search(sectionList, section, CmpSectionFunc, NULL);
        if (secCtx == NULL) {
            return AddSection(sectionList, section, key, value);
        }
        if (strlen(key) == 0) {
            return BSL_SUCCESS;
        }
        if (secCtx->keyValueList == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_CONF_GET_FAIL);
            return BSL_CONF_GET_FAIL;
        }
        keyValue = BSL_LIST_Search(secCtx->keyValueList, key, CmpKeyFunc, NULL);
        if (keyValue == NULL) {
            return AddKeyValue(secCtx->keyValueList, key, value);
        } else {
            return UpdateKeyValue(keyValue, value);
        }
    }
}

// Reads a line of data from a configuration file.
static int32_t ConfGetLine(BSL_UIO *uio, char *buff, int32_t buffSize, int32_t *offset, int32_t *flag)
{
    int32_t tmpOffset = *offset;
    int32_t buffLen = buffSize - tmpOffset; // Calculate the available buffer length
    if (buffLen <= 0) {
        BSL_ERR_PUSH_ERROR(BSL_CONF_BUFF_OVERFLOW);
        return BSL_CONF_BUFF_OVERFLOW;
    }
    int32_t ret = BSL_UIO_Gets(uio, buff + tmpOffset, (uint32_t *)&buffLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    buffLen += tmpOffset; // Update the buffer length
    if (buffLen == 0) {
        *flag = BREAK_FLAG;
        return BSL_SUCCESS;
    }
    bool isEof = false;
    if (buff[buffLen - 1] != '\n') { // buffer might have been truncated.
        ret = BSL_UIO_Ctrl(uio, BSL_UIO_FILE_GET_EOF, 1, &isEof);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        if (isEof != true) {
            BSL_ERR_PUSH_ERROR(BSL_CONF_BUFF_OVERFLOW);
            return BSL_CONF_BUFF_OVERFLOW;
        }
        (void)RemoveSpace(buff);
        return BSL_SUCCESS;
    }
    buffLen = RemoveSpace(buff);
    if (buffLen > 0) {
        buffLen--;
    }
    if (buff[buffLen] == '\\') { // Handle multi-line cases
        if (buffLen > 0 && buff[buffLen - 1] == '\\') { // Handle escape characters
            tmpOffset = 0;
        } else { // Normal case
            tmpOffset = buffLen; // Set the temporary offset
            *flag = CONTINUE_FLAG;
        }
    } else { // Single-line case
        tmpOffset = 0;
    }
    *offset = tmpOffset;
    return BSL_SUCCESS;
}

// Parses a line of configuration data.
static int32_t ConfParseLine(BslList *sectionList, char *buff, char *section, char *key, char *value)
{
    int32_t ret = BSL_SUCCESS;
    size_t len = strlen(buff);
    int32_t n = 2; // sscanf_s is expected to return 2.
    if (len < 1 || buff[0] == '#' || buff[0] == ';') { // empty or comments
        return BSL_SUCCESS;
    } else if (buff[0] == '[' && buff[len - 1] == ']') {
        len -= 2; // remove '[' and ']' len - 2.
        if (memcpy_s(section, BSL_CONF_SEC_SIZE, &buff[1], len) != 0) {
            BSL_ERR_PUSH_ERROR(BSL_CONF_BUFF_OVERFLOW);
            return BSL_CONF_BUFF_OVERFLOW;
        }
        section[len] = '\0';
    } else if (sscanf_s(buff, "%[^=] = \"%[^\n]", key, BSL_CONF_LINE_SIZE, value, BSL_CONF_LINE_SIZE) == n) {
        ret = ParseQuote(value, '\"');
    } else if (sscanf_s(buff, "%[^=] = \'%[^\n]", key, BSL_CONF_LINE_SIZE, value, BSL_CONF_LINE_SIZE) == n) {
        ret = ParseQuote(value, '\'');
    } else if (RemoveEscapeAndComments(buff) < 0) {
        BSL_ERR_PUSH_ERROR(BSL_CONF_CONTEXT_ERR);
        return BSL_CONF_CONTEXT_ERR;
    } else if (sscanf_s(buff, "%[^=]%[=]", key, BSL_CONF_LINE_SIZE, value, BSL_CONF_LINE_SIZE) == n) {
        char *valPtr = strchr(buff, '=');
        valPtr++;
        len = strlen(valPtr);
        (void)memcpy_s(value, len, valPtr, len);
        value[len] = '\0';
    } else {
        BSL_ERR_PUSH_ERROR(BSL_CONF_CONTEXT_ERR);
        return BSL_CONF_CONTEXT_ERR;
    }
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    (void)RemoveSpace(section);
    (void)RemoveSpace(key);
    (void)RemoveSpace(value);
    return SetSection(sectionList, section, key, value);
}

// Loads configuration data from a UIO into a section list.
int32_t DefaultLoadUio(BslList *sectionList, BSL_UIO *uio)
{
    if (sectionList == NULL || uio == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    int32_t ret;
    int32_t offset = 0;
    int32_t flag;
    char *buff = (char *)BSL_SAL_Calloc(4, (BSL_CONF_LINE_SIZE + 1)); // 4 blocks for buff, secion, key, value.
    if (buff == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    char *section = (char *)(buff + BSL_CONF_LINE_SIZE + 1);
    char *key = (char *)(section + BSL_CONF_LINE_SIZE + 1);
    char *value = (char *)(key + BSL_CONF_LINE_SIZE + 1);
    while (true) {
        flag = 0; // Reset flag.
        // Read one line into buff.
        ret = ConfGetLine(uio, buff, BSL_CONF_LINE_SIZE + 1, &offset, &flag);
        if (ret != BSL_SUCCESS || flag == BREAK_FLAG) {
            break;
        }
        if (flag == CONTINUE_FLAG) {
            continue;
        }
        // Parse section, key, value from buff.
        ret = ConfParseLine(sectionList, buff, section, key, value);
        if (ret != BSL_SUCCESS) {
            break;
        }
        // Clear buff, key, value, do not clear section.
        (void)memset_s(buff, BSL_CONF_LINE_SIZE + 1, 0, BSL_CONF_LINE_SIZE + 1);
        (void)memset_s(key, BSL_CONF_LINE_SIZE + 1, 0, BSL_CONF_LINE_SIZE + 1);
        (void)memset_s(value, BSL_CONF_LINE_SIZE + 1, 0, BSL_CONF_LINE_SIZE + 1);
        offset = 0; // Reset offset.
    }
    BSL_SAL_FREE(buff);
    return ret;
}

int32_t DefaultLoad(BslList *sectionList, const char *file)
{
    if (sectionList == NULL || file == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    BSL_UIO *in = BSL_UIO_New(BSL_UIO_FileMethod());
    if (in == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }
    int32_t ret = BSL_UIO_Ctrl(in, BSL_UIO_FILE_OPEN, BSL_UIO_FILE_READ, (void *)(uintptr_t)file);
    if (ret != BSL_SUCCESS) {
        BSL_UIO_Free(in);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = DefaultLoadUio(sectionList, in);
    BSL_UIO_Free(in);
    return ret;
}

static int32_t DumpSection(BSL_UIO *uio, const BSL_CONF_Section *secData)
{
    uint32_t strLen = secData->sectionLen + 4; // "[]\n\0" == 4
    char *str = (char *)BSL_SAL_Calloc(1, strLen + 1);
    if (str == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t usedLen = sprintf_s(str, strLen, "[%s]\n", secData->section);
    if (usedLen < 0) {
        BSL_SAL_FREE(str);
        BSL_ERR_PUSH_ERROR(BSL_CONF_DUMP_FAIL);
        return BSL_CONF_DUMP_FAIL;
    }
    if (usedLen > BSL_CONF_LINE_SIZE) {
        BSL_SAL_FREE(str);
        BSL_ERR_PUSH_ERROR(BSL_CONF_BUFF_OVERFLOW);
        return BSL_CONF_BUFF_OVERFLOW;
    }
    int32_t ret = BSL_UIO_Puts(uio, str, (uint32_t *)&usedLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    BSL_SAL_FREE(str);
    return ret;
}

static int32_t DumpKeyValue(BSL_UIO *uio, const BSL_CONF_KeyValue *keyValue)
{
    uint32_t strLen = keyValue->keyLen + keyValue->valueLen * 2 + 3; // "=\n\0" == 3, valueLen * 2 for '\\'.
    char *str = (char *)BSL_SAL_Calloc(1, strLen + 1);
    if (str == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t usedLen = sprintf_s(str, strLen, "%s=", keyValue->key);
    if (usedLen < 0) {
        BSL_SAL_FREE(str);
        BSL_ERR_PUSH_ERROR(BSL_CONF_DUMP_FAIL);
        return BSL_CONF_DUMP_FAIL;
    }
    for (uint32_t i = 0; i < keyValue->valueLen; i++) {
        if (IsEscapeValid(keyValue->value[i]) == 1) { // add '\\'.
            str[usedLen] = '\\';
            usedLen++;
        }
        if (keyValue->value[i] == '\n') {
            str[usedLen] = '\\';
            usedLen++;
            str[usedLen] = 'n';
            usedLen++;
            continue;
        }
        str[usedLen] = keyValue->value[i];
        usedLen++;
    }
    str[usedLen] = '\n';
    usedLen++;
    if (usedLen > BSL_CONF_LINE_SIZE) {
        BSL_SAL_FREE(str);
        BSL_ERR_PUSH_ERROR(BSL_CONF_BUFF_OVERFLOW);
        return BSL_CONF_BUFF_OVERFLOW;
    }
    int32_t ret = BSL_UIO_Puts(uio, str, (uint32_t *)&usedLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    BSL_SAL_FREE(str);
    return ret;
}

int32_t DefaultDumpUio(BslList *sectionList, BSL_UIO *uio)
{
    if (sectionList == NULL || uio == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    int32_t ret = BSL_SUCCESS;
    BSL_CONF_Section *secData = NULL;
    BSL_CONF_KeyValue *keyValue = NULL;
    BslListNode *keyValueNode = NULL;
    BslListNode *node = BSL_LIST_FirstNode(sectionList);
    while (node != NULL) {
        secData = BSL_LIST_GetData(node);
        if (secData == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_CONF_GET_FAIL);
            return BSL_CONF_GET_FAIL;
        }
        ret = DumpSection(uio, secData);
        if (ret != BSL_SUCCESS) {
            return ret;
        }
        keyValueNode = BSL_LIST_FirstNode(secData->keyValueList);
        while (keyValueNode != NULL) {
            keyValue = BSL_LIST_GetData(keyValueNode);
            if (keyValue == NULL) {
                BSL_ERR_PUSH_ERROR(BSL_CONF_GET_FAIL);
                return BSL_CONF_GET_FAIL;
            }
            ret = DumpKeyValue(uio, keyValue);
            if (ret != BSL_SUCCESS) {
                return ret;
            }
            keyValueNode = BSL_LIST_GetNextNode(secData->keyValueList, keyValueNode);
        }
        node = BSL_LIST_GetNextNode(sectionList, node);
    }
    return BSL_SUCCESS;
}

int32_t DefaultDump(BslList *sectionList, const char *file)
{
    if (sectionList == NULL || file == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    BSL_UIO *out = BSL_UIO_New(BSL_UIO_FileMethod());
    if (out == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }
    int32_t ret = BSL_UIO_Ctrl(out, BSL_UIO_FILE_OPEN, BSL_UIO_FILE_WRITE, (void *)(uintptr_t)file);
    if (ret != BSL_SUCCESS) {
        BSL_UIO_Free(out);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = DefaultDumpUio(sectionList, out);
    BSL_UIO_SetIsUnderlyingClosedByUio(out, true);
    BSL_UIO_Free(out);
    return ret;
}

const BSL_CONF_Method *BSL_CONF_DefaultMethod(void)
{
    static const BSL_CONF_Method DEFAULT_METHOD = {
        DefaultCreate,
        DefaultDestroy,
        DefaultLoad,
        DefaultLoadUio,
        DefaultDump,
        DefaultDumpUio,
        DefaultGetSectionNode,
        DefaultGetString,
        DefaultGetNumber,
        DefaultGetSectionNames,
    };
    return &DEFAULT_METHOD;
}

#endif /* HITLS_BSL_CONF */
