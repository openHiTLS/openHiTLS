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

#include <stdbool.h>
#include "securec.h"
#include "bsl_err.h"
#include "bsl_log_internal.h"
#include "bsl_binlog_id.h"
#include "bsl_asn1_local.h"
#include "bsl_sal.h"
#include "sal_time.h"

#define BSL_ASN1_INDEFINITE_LENGTH  0x80
#define BSL_ASN1_DEFINITE_MAX_CONTENT_OCTET_NUM 0x7F // 127

typedef struct {
    BSL_ASN1_DecodeListParam *param;
    BSL_ASN1_Buffer *asn;
    BSL_ASN1_ParseListAsnItem parseListItemCb;
    void *cbParam;
    BSL_ASN1_List *list;
} BSL_ASN1_DecodeListInternalParam;

int32_t BSL_ASN1_DecodeLen(uint8_t **encode, uint32_t *encLen, bool completeLen, uint32_t *len)
{
    if (encode == NULL || *encode == NULL || encLen == NULL || len == NULL) {
        return BSL_NULL_INPUT;
    }
    uint8_t *temp = *encode;
    uint32_t tempLen = *encLen;
    uint32_t parseLen = 0;
    if (tempLen < 1) {
        return BSL_ASN1_ERR_DECODE_LEN;
    }

    if ((*temp & BSL_ASN1_INDEFINITE_LENGTH) == 0) {
        parseLen = *temp;
        temp++;
        tempLen--;
        parseLen += ((completeLen) ? 1 : 0);
    } else {
        uint32_t index = *temp - BSL_ASN1_INDEFINITE_LENGTH;
        if (index > sizeof(int32_t)) {
            return BSL_ASN1_ERR_MAX_LEN_NUM;
        }
        temp++;
        tempLen--;
        if (tempLen < index) {
            return BSL_ASN1_ERR_BUFF_NOT_ENOUGH;
        }
        for (uint32_t iter = 0; iter < index; iter++) {
            parseLen = (parseLen << 8) | *temp; // one byte = 8 bits
            temp++;
            tempLen--;
        }
        // anti-flip
        if (parseLen >= ((((uint64_t)1 << 32) - 1) - index - 2)) { // 1<<32:U32_MAX; 2: Tag + length(0x8x)
            return BSL_ASN1_ERR_MAX_LEN_NUM;
        }
        parseLen += ((completeLen) ? (index + 1) : 0);
    }
    uint32_t length = (completeLen) ? *encLen : tempLen;
    /* The length supports a maximum of 4 bytes */
    if (parseLen > length) {
        return BSL_ASN1_ERR_DECODE_LEN;
    }
    *len = parseLen;
    *encode = temp;
    *encLen = tempLen;
    return BSL_SUCCESS;
}

int32_t BSL_ASN1_GetCompleteLen(uint8_t *data, uint32_t *dataLen)
{
    uint8_t *tmp = data;
    uint32_t tmpLen = *dataLen;
    uint32_t len = 0;
    if (tmpLen < 1) {
        return BSL_ASN1_ERR_BUFF_NOT_ENOUGH;
    }

    tmp++;
    tmpLen--;
    int32_t ret = BSL_ASN1_DecodeLen(&tmp, &tmpLen, true, &len);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    *dataLen = len + 1;
    return BSL_SUCCESS;
}

int32_t BSL_ASN1_DecodeTagLen(uint8_t tag, uint8_t **encode, uint32_t *encLen, uint32_t *valLen)
{
    if (encode == NULL || *encode == NULL || encLen == NULL || valLen == NULL) {
        return BSL_NULL_INPUT;
    }
    uint8_t *temp = *encode;
    uint32_t tempLen = *encLen;
    if (tempLen < 1) {
        return BSL_INVALID_ARG;
    }

    if (tag != *temp) {
        return BSL_ASN1_ERR_MISMATCH_TAG;
    }
    temp++;
    tempLen--;
    uint32_t len;
    int32_t ret = BSL_ASN1_DecodeLen(&temp, &tempLen, false, &len);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    if (len > tempLen) {
        return BSL_ASN1_ERR_BUFF_NOT_ENOUGH;
    }
    *valLen = len;
    *encode = temp;
    *encLen = tempLen;
    return BSL_SUCCESS;
}

int32_t BSL_ASN1_DecodeItem(uint8_t **encode, uint32_t *encLen, BSL_ASN1_Buffer *asnItem)
{
    if (encode == NULL || *encode == NULL || encLen == NULL || asnItem == NULL) {
        return BSL_NULL_INPUT;
    }
    uint8_t tag;
    uint32_t len;
    uint8_t *temp = *encode;
    uint32_t tempLen = *encLen;
    if (tempLen < 1) {
        return BSL_INVALID_ARG;
    }
    tag = *temp;
    temp++;
    tempLen--;
    int32_t ret = BSL_ASN1_DecodeLen(&temp, &tempLen, false, &len);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    asnItem->tag = tag;
    asnItem->len = len;
    asnItem->buff = temp;
    temp += len;
    tempLen -= len;
    *encode = temp;
    *encLen = tempLen;
    return BSL_SUCCESS;
}

static int32_t ParseBool(uint8_t *val, uint32_t len, bool *decodeData)
{
    if (len != 1) {
        return BSL_ASN1_ERR_DECODE_BOOL;
    }
    *decodeData = (*val != 0) ? 1 : 0;
    return BSL_SUCCESS;
}

static int32_t ParseInt(uint8_t *val, uint32_t len, int *decodeData)
{
    uint8_t *temp = val;
    if (len < 1 || len > sizeof(int)) {
        return BSL_ASN1_ERR_DECODE_INT;
    }

    *decodeData = 0;
    for (uint32_t i = 0; i < len; i++) {
        *decodeData = (*decodeData << 8) | *temp;
        temp++;
    }
    return BSL_SUCCESS;
}

static int32_t ParseBitString(uint8_t *val, uint32_t len, BSL_ASN1_BitString *decodeData)
{
    if (len < 1 || *val > BSL_ASN1_VAL_MAX_BIT_STRING_LEN) {
        return BSL_ASN1_ERR_DECODE_BIT_STRING;
    }
    decodeData->unusedBits = *val;
    decodeData->buff = val + 1;
    decodeData->len = len - 1;
    return BSL_SUCCESS;
}

// len max support 4
static uint32_t DecodeAsciiNum(uint8_t **encode, uint32_t len)
{
    uint32_t temp = 0;
    uint8_t *data = *encode;
    for (uint32_t i = 0; i < len; i++) {
        temp *= 10; // 10: Process decimal numbers.
        temp += (data[i] - '0');
    }
    *encode += len;
    return temp;
}

static int32_t CheckTime(uint8_t *data, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++) {
        if (data[i] > '9' || data[i] < '0') {
            return BSL_ASN1_ERR_DECODE_TIME;
        }
    }
    return BSL_SUCCESS;
}

// Support utcTime for YYMMDDHHMMSS[Z] and generalizedTime for YYYYMMDDHHMMSS[Z].
static int32_t ParseTime(uint8_t tag, uint8_t *val, uint32_t len, BSL_TIME *decodeData)
{
    int32_t ret;
    uint8_t *temp = val;
    if (tag == BSL_ASN1_TAG_UTCTIME && (len != 12 && len != 13)) { // 12 YYMMDDHHMMSS, 13 YYMMDDHHMMSSZ
        return BSL_ASN1_ERR_DECODE_UTC_TIME;
    }
    
    if (tag == BSL_ASN1_TAG_GENERALIZEDTIME && (len != 14 && len != 15)) { // 14 YYYYMMDDHHMMSS, 15 YYYYMMDDHHMMSSZ
        return BSL_ASN1_ERR_DECODE_GENERAL_TIME;
    }

    // Check if the encoding is within the expected range and prepare for conversion
    ret = tag == BSL_ASN1_TAG_UTCTIME ? CheckTime(val, 12) : CheckTime(val, 14); // 12|14: ignoring Z
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    if (tag == BSL_ASN1_TAG_UTCTIME) {
        decodeData->year = (uint16_t)DecodeAsciiNum(&temp, 2); // 2: YY
        if (decodeData->year < 50) {
            decodeData->year += 2000;
        } else {
            decodeData->year += 1900;
        }
    } else {
        decodeData->year = (uint16_t)DecodeAsciiNum(&temp, 4); // 4: YYYY
    }
    decodeData->month = (uint8_t)DecodeAsciiNum(&temp, 2);  // 2:MM
    decodeData->day = (uint8_t)DecodeAsciiNum(&temp, 2);    // 2: DD
    decodeData->hour = (uint8_t)DecodeAsciiNum(&temp, 2);   // 2: HH
    decodeData->minute = (uint8_t)DecodeAsciiNum(&temp, 2); // 2: MM
    decodeData->second = (uint8_t)DecodeAsciiNum(&temp, 2); // 2: SS
    return BSL_DateTimeCheck(decodeData) ? BSL_SUCCESS : BSL_ASN1_ERR_CHECK_TIME;
}

static int32_t DecodeTwoLayerListInternal(uint32_t layer, BSL_ASN1_Buffer *asn,
    BSL_ASN1_DecodeListInternalParam *internalParam)
{
    int32_t ret;
    uint8_t tag;
    uint32_t encLen;
    uint8_t *buff = asn->buff;
    uint32_t len = asn->len;
    BSL_ASN1_Buffer item;
    while (len > 0) {
        if (*buff != internalParam->param->expTag[layer - 1]) {
            return BSL_ASN1_ERR_MISMATCH_TAG;
        }
        tag = *buff;
        buff++;
        len--;
        ret = BSL_ASN1_DecodeLen(&buff, &len, false, &encLen);
        if (ret != BSL_SUCCESS) {
            return ret;
        }
        item.tag = tag;
        item.len = encLen;
        item.buff = buff;
        ret = internalParam->parseListItemCb(layer, &item, internalParam->cbParam, internalParam->list);
        if (ret != BSL_SUCCESS) {
            return ret;
        }
        buff += encLen;
        len -= encLen;
    }
    return BSL_SUCCESS;
}

static int32_t DecodeOneLayerList(BSL_ASN1_DecodeListInternalParam *internalParam)
{
    return DecodeTwoLayerListInternal(1, internalParam->asn, internalParam);
}

static int32_t DecodeTwoLayerList(BSL_ASN1_DecodeListInternalParam *internalParam)
{
    int32_t ret;
    uint8_t tag;
    uint32_t encLen;
    uint8_t *buff = internalParam->asn->buff;
    uint32_t len = internalParam->asn->len;
    BSL_ASN1_Buffer item;
    while (len > 0) {
        if (*buff != internalParam->param->expTag[0]) {
            return BSL_ASN1_ERR_MISMATCH_TAG;
        }
        tag = *buff;
        buff++;
        len--;
        ret = BSL_ASN1_DecodeLen(&buff, &len, false, &encLen);
        if (ret != BSL_SUCCESS) {
            return ret;
        }
        item.tag = tag;
        item.len = encLen;
        item.buff = buff;
        ret = internalParam->parseListItemCb(1, &item, internalParam->cbParam, internalParam->list);
        if (ret != BSL_SUCCESS) {
            return ret;
        }
        ret = DecodeTwoLayerListInternal(2, &item, internalParam); // Level 2 List.
        if (ret != BSL_SUCCESS) {
            return ret;
        }
        buff += encLen;
        len -= encLen;
    }
    return BSL_SUCCESS;
}

int32_t BSL_ASN1_DecodeListItem(BSL_ASN1_DecodeListParam *param, BSL_ASN1_Buffer *asn,
    BSL_ASN1_ParseListAsnItem parseListItemCb, void *cbParam, BSL_ASN1_List *list)
{
    if (param == NULL || asn == NULL || parseListItemCb == NULL || list == NULL) {
        return BSL_INVALID_ARG;
    }

     // Currently, it supports a maximum of 2 layers
    if (param->layer > BSL_ASN1_MAX_LIST_NEST_EPTH) {
        return BSL_ASN1_ERR_EXCEED_LIST_DEPTH;
    }
    BSL_ASN1_DecodeListInternalParam internalParam = {param, asn, parseListItemCb, cbParam, list};
    return param->layer == 1 ? DecodeOneLayerList(&internalParam)
                             : DecodeTwoLayerList(&internalParam);
}

static int32_t ParseBMPString(const uint8_t *bmp, uint32_t bmpLen, BSL_ASN1_Buffer *decode)
{
    if (bmp == NULL || bmpLen == 0 || decode == NULL) {
        return BSL_NULL_INPUT;
    }
    if (bmpLen % 2 != 0) { // multiple of 2
        return BSL_INVALID_ARG;
    }
    uint8_t *tmp = (uint8_t *)BSL_SAL_Malloc(bmpLen / 2); // decodeLen = bmpLen/2
    if (tmp == NULL) {
        return BSL_MALLOC_FAIL;
    }
    for (uint32_t i = 0; i < bmpLen / 2; i++) { // decodeLen = bmpLen/2
        tmp[i] = bmp[i * 2 + 1];
    }
    decode->buff = tmp;
    decode->len = bmpLen / 2; // decodeLen = bmpLen/2
    return BSL_SUCCESS;
}

static int32_t ParseT61String(const uint8_t *t61, uint32_t t61Len, BSL_ASN1_Buffer *decode)
{
    if (t61 == NULL || t61Len == 0 || decode == NULL) {
        return BSL_NULL_INPUT;
    }
    // Currently only supports single-byte character decoding
    // The lower 128 characters (0x00 - 0x7F) of T.61 are fully compatible with ASCII.
    // This means any pure ASCII text is valid in T.61 encoding and retains the same meaning.
    uint8_t *tmp = (uint8_t *)BSL_SAL_Malloc(t61Len);
    if (tmp == NULL) {
        return BSL_MALLOC_FAIL;
    }
    (void)memcpy_s(tmp, t61Len, t61, t61Len);
    decode->buff = tmp;
    decode->len = t61Len;
    return BSL_SUCCESS;
}

static void EncodeT61String(const uint8_t *in, uint32_t inLen, uint8_t *encode, uint32_t *offset)
{
    (void)memcpy_s(encode + *offset, inLen, in, inLen);
    *offset += inLen;
    return;
}

static void EncodeBMPString(const uint8_t *in, uint32_t inLen, uint8_t *encode, uint32_t *offset)
{
    uint8_t *output = encode + *offset;
    for (uint32_t i = 0; i < inLen; i++) {
        output[2 * i + 1] = in[i]; // need 2 space, [0,0] -> after encode = [0, data];
        output[2 * i + 0] = 0;
    }
    *offset += inLen * 2; // encodeLen = 2 * inLen
    return;
}

/**
 * Big numbers do not need to call this interface,
 * the filled leading 0 has no effect on the result of large numbers, big numbers can be directly used asn's buff.
 *
 * It has been ensured at parsing time that the content to which the buff points is security for length within asn'len
 */
int32_t BSL_ASN1_DecodePrimitiveItem(BSL_ASN1_Buffer *asn, void *decodeData)
{
    if (asn == NULL || decodeData == NULL) {
        return BSL_NULL_INPUT;
    }
    switch (asn->tag) {
        case BSL_ASN1_TAG_BOOLEAN:
            return ParseBool(asn->buff, asn->len, decodeData);
        case BSL_ASN1_TAG_INTEGER:
        case BSL_ASN1_TAG_ENUMERATED:
            return ParseInt(asn->buff, asn->len, decodeData);
        case BSL_ASN1_TAG_BITSTRING:
            return ParseBitString(asn->buff, asn->len, decodeData);
        case BSL_ASN1_TAG_UTCTIME:
        case BSL_ASN1_TAG_GENERALIZEDTIME:
            return ParseTime(asn->tag, asn->buff, asn->len, decodeData);
        case BSL_ASN1_TAG_BMPSTRING:
            return ParseBMPString(asn->buff, asn->len, decodeData);
        case BSL_ASN1_TAG_T61STRING:
            return ParseT61String(asn->buff, asn->len, decodeData);
        default:
            break;
    }
    return BSL_ASN1_FAIL;
}

static int32_t BSL_ASN1_AnyOrChoiceTagProcess(bool isAny, BSL_ASN1_AnyOrChoiceParam *tagCbinfo, uint8_t *tag)
{
    if (tagCbinfo->tagCb == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05065, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "asn1: callback is null", 0, 0, 0, 0);
        return BSL_ASN1_ERR_NO_CALLBACK;
    }
    int32_t type = isAny == true ? BSL_ASN1_TYPE_GET_ANY_TAG : BSL_ASN1_TYPE_CHECK_CHOICE_TAG;
    int32_t ret = tagCbinfo->tagCb(type, tagCbinfo->idx, tagCbinfo->previousAsnOrTag, tag);
    if (ret != BSL_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05066, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "asn1: callback is err %x", ret, 0, 0, 0);
    }
    return ret;
}

static int32_t BSL_ASN1_ProcessWithoutDefOrOpt(BSL_ASN1_AnyOrChoiceParam *tagCbinfo, uint8_t realTag, uint8_t *expTag)
{
    int32_t ret;
    uint8_t tag = *expTag;
    // Any and choice will not have a coexistence scenario, which is meaningless.
    if (tag == BSL_ASN1_TAG_CHOICE) {
        tagCbinfo->previousAsnOrTag = &realTag;
        return BSL_ASN1_AnyOrChoiceTagProcess(false, tagCbinfo, expTag);
    }
    // The tags of any and normal must be present
    if (tag == BSL_ASN1_TAG_ANY) {
        ret = BSL_ASN1_AnyOrChoiceTagProcess(true, tagCbinfo, &tag);
        if (ret != BSL_SUCCESS) {
            return ret;
        }
    }
    if (tag != realTag) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05067, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "asn1: expected tag %x is not match %x", tag, realTag, 0, 0);
        return BSL_ASN1_ERR_TAG_EXPECTED;
    }
    *expTag = realTag;

    return BSL_SUCCESS;
}

/**
 * Reference: X.690 Information technology - ASN.1 encoding rules: 8.3
 * If the contents octect of an integer value encoding consist of more than one octet,
 * then the bits of the first octet and bit 8 of the second octet:
 *     a): shall not all be ones; and
 *     b): shall not all be zero.
 *
 * Note: Currently, only positive integers are supported, and negative integers are not supported.
 */
int32_t ProcessIntegerType(uint8_t *temp, uint32_t len, BSL_ASN1_Buffer *asn)
{
    // Check if it is a negative number
    if (*temp & 0x80) {
        return BSL_ASN1_ERR_DECODE_INT;
    }

    // Check if the first octet is 0 and the second octet is not 0
    if (*temp == 0 && len > 1 && (*(temp + 1) & 0x80) == 0) {
        return BSL_ASN1_ERR_DECODE_INT;
    }

    // Calculate the actual length (remove leading zeros)
    uint32_t actualLen = len;
    uint8_t *actualBuff = temp;
    while (actualLen > 1 && *actualBuff == 0) {
        actualLen--;
        actualBuff++;
    }
    asn->len = actualLen;
    asn->buff = actualBuff;
    return BSL_SUCCESS;
}

static int32_t ProcessTag(uint8_t flags, BSL_ASN1_AnyOrChoiceParam *tagCbinfo, uint8_t *temp, uint32_t tempLen,
    uint8_t *tag, BSL_ASN1_Buffer *asn)
{
    int32_t ret = BSL_SUCCESS;
    if ((flags & BSL_ASN1_FLAG_OPTIONAL_DEFAUL) != 0) {
        if (tempLen < 1) {
            asn->tag = 0;
            asn->len = 0;
            asn->buff = NULL;
            return BSL_SUCCESS;
        }
        if (*tag == BSL_ASN1_TAG_ANY) {
            ret = BSL_ASN1_AnyOrChoiceTagProcess(true, tagCbinfo, tag);
            if (ret != BSL_SUCCESS) {
                return ret;
            }
        }

        if (*tag == BSL_ASN1_TAG_CHOICE) {
            tagCbinfo->previousAsnOrTag = temp;
            ret = BSL_ASN1_AnyOrChoiceTagProcess(false, tagCbinfo, tag);
            if (ret != BSL_SUCCESS) {
                return ret;
            }
        }
        if (*tag == BSL_ASN1_TAG_EMPTY) {
            return BSL_ASN1_ERR_TAG_EXPECTED;
        }

        if (*tag != *temp) { // The optional or default scene is not encoded
            asn->tag = 0;
            asn->len = 0;
            asn->buff = NULL;
        }
    } else {
        /* No optional or default scenes, tag must exist */
        if (tempLen < 1) {
            return BSL_ASN1_ERR_DECODE_LEN;
        }
        ret = BSL_ASN1_ProcessWithoutDefOrOpt(tagCbinfo, *temp, tag);
    }
    return ret;
}

static int32_t BSL_ASN1_ProcessNormal(BSL_ASN1_AnyOrChoiceParam *tagCbinfo,
    BSL_ASN1_TemplateItem *item, uint8_t **encode, uint32_t *encLen, BSL_ASN1_Buffer *asn)
{
    uint32_t len;
    uint8_t tag = item->tag;
    uint8_t *temp = *encode;
    uint32_t tempLen = *encLen;

    asn->tag = tag; // init tag
    int32_t ret = ProcessTag(item->flags, tagCbinfo, temp, tempLen, &tag, asn);
    if (ret != BSL_SUCCESS || asn->tag == 0) {
        return ret;
    }

    temp++;
    tempLen--;
    ret = BSL_ASN1_DecodeLen(&temp, &tempLen, false, &len);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    asn->tag = tag; // update tag
    if ((tag == BSL_ASN1_TAG_INTEGER || tag == BSL_ASN1_TAG_ENUMERATED) && len > 0) {
        ret = ProcessIntegerType(temp, len, asn);
        if (ret != BSL_SUCCESS) {
            return ret;
        }
    } else {
        asn->len = len;
        asn->buff = (tag == BSL_ASN1_TAG_NULL) ? NULL : temp;
    }

    /* struct type, headerOnly flag is set, only the whole is parsed, otherwise the parsed content is traversed */
    if (((item->tag & BSL_ASN1_TAG_CONSTRUCTED) != 0 && (item->flags & BSL_ASN1_FLAG_HEADERONLY) != 0) ||
        (item->tag & BSL_ASN1_TAG_CONSTRUCTED) == 0) {
        temp += len;
        tempLen -= len;
    }

    *encode = temp;
    *encLen = tempLen;
    return BSL_SUCCESS;
}

uint32_t BSL_ASN1_SkipChildNode(uint32_t idx, BSL_ASN1_TemplateItem *item, uint32_t count)
{
    uint32_t i = idx + 1;
    for (; i < count; i++) {
        if (item[i].depth <= item[idx].depth) {
            break;
        }
    }
    return i - idx;
}

static bool BSL_ASN1_IsConstructItem(BSL_ASN1_TemplateItem *item)
{
    return item->tag & BSL_ASN1_TAG_CONSTRUCTED;
}

static int32_t BSL_ASN1_FillConstructItemWithNull(BSL_ASN1_Template *templ, uint32_t *templIdx,
    BSL_ASN1_Buffer *asnArr, uint32_t arrNum, uint32_t *arrIdx)
{
    // The construct type value is marked headeronly
    if ((templ->templItems[*templIdx].flags & BSL_ASN1_FLAG_HEADERONLY) != 0) {
        if (*arrIdx >= arrNum) {
            return BSL_ASN1_ERR_OVERFLOW;
        } else {
            asnArr[*arrIdx].tag = 0;
            asnArr[*arrIdx].len = 0;
            asnArr[*arrIdx].buff = 0;
            (*arrIdx)++;
        }
        (*templIdx) += BSL_ASN1_SkipChildNode(*templIdx, templ->templItems, templ->templNum);
    } else {
        // This scenario does not record information about the parent node
        (*templIdx)++;
    }
    return BSL_SUCCESS;
}

int32_t BSL_ASN1_SkipChildNodeAndFill(uint32_t *idx, BSL_ASN1_Template *templ,
    BSL_ASN1_Buffer *asnArr, uint32_t arrNum, uint32_t *arrIndex)
{
    uint32_t arrIdx = *arrIndex;
    uint32_t i = *idx;
    for (; i < templ->templNum;) {
        if (templ->templItems[i].depth <= templ->templItems[*idx].depth && i > *idx) {
            break;
        }
        // There are also struct types under the processing parent
        if (BSL_ASN1_IsConstructItem(&templ->templItems[i])) {
            int32_t ret = BSL_ASN1_FillConstructItemWithNull(templ, &i, asnArr, arrNum, &arrIdx);
            if (ret != BSL_SUCCESS) {
                return ret;
            }
        } else {
            asnArr[arrIdx].tag = 0;
            asnArr[arrIdx].len = 0;
            asnArr[arrIdx].buff = 0;
            arrIdx++;
            i++;
        }
    }
    *arrIndex = arrIdx;
    *idx = i;
    return BSL_SUCCESS;
}

int32_t BSL_ASN1_ProcessConstructResult(BSL_ASN1_Template *templ, uint32_t *templIdx, BSL_ASN1_Buffer *asn,
    BSL_ASN1_Buffer *asnArr, uint32_t arrNum, uint32_t *arrIdx)
{
    int32_t ret;
    // Optional or default construct type, without any data to be parsed, need to skip all child nodes
    if ((templ->templItems[*templIdx].flags & BSL_ASN1_FLAG_OPTIONAL_DEFAUL) != 0 && asn->tag == 0) {
        ret = BSL_ASN1_SkipChildNodeAndFill(templIdx, templ, asnArr, arrNum, arrIdx);
        if (ret != BSL_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05068, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "asn1: skip and fill node err %x, idx %u", ret, *templIdx, 0, 0);
            return ret;
        }
        return BSL_SUCCESS;
    }

    if ((templ->templItems[*templIdx].flags & BSL_ASN1_FLAG_HEADERONLY) != 0) {
        if (*arrIdx >= arrNum) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05069, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "asn1: array idx %u, overflow %u, templ %u", *arrIdx, arrNum, *templIdx, 0);
            return BSL_ASN1_ERR_OVERFLOW;
        } else {
            // Shallow copy of structure
            asnArr[*arrIdx].tag = asn->tag;
            asnArr[*arrIdx].len = asn->len;
            asnArr[*arrIdx].buff = asn->buff;
            (*arrIdx)++;
        }
        (*templIdx) += BSL_ASN1_SkipChildNode(*templIdx, templ->templItems, templ->templNum);
    } else {
        (*templIdx)++; // Non header only flags, do not fill this parse
    }
    return BSL_SUCCESS;
}

static inline bool IsInvalidTempl(BSL_ASN1_Template *templ)
{
    return templ == NULL || templ->templNum == 0 || templ->templItems == NULL;
}
static inline bool IsInvalidAsns(BSL_ASN1_Buffer *asnArr, uint32_t arrNum)
{
    return asnArr == NULL || arrNum == 0;
}

int32_t BSL_ASN1_DecodeTemplate(BSL_ASN1_Template *templ, BSL_ASN1_DecTemplCallBack decTemlCb,
    uint8_t **encode, uint32_t *encLen, BSL_ASN1_Buffer *asnArr, uint32_t arrNum)
{
    int32_t ret;
    if (IsInvalidTempl(templ) || encode == NULL || *encode == NULL || encLen == NULL || IsInvalidAsns(asnArr, arrNum)) {
        return BSL_NULL_INPUT;
    }
    uint8_t *temp = *encode;
    uint32_t tempLen = *encLen;
    BSL_ASN1_Buffer asn = {0}; // temp var
    uint32_t arrIdx = 0;
    BSL_ASN1_Buffer previousAsn = {0};
    BSL_ASN1_AnyOrChoiceParam tagCbinfo = {0, NULL, decTemlCb};

    for (uint32_t i = 0; i < templ->templNum;) {
        if (templ->templItems[i].depth > BSL_ASN1_MAX_TEMPLATE_DEPTH) {
            return BSL_ASN1_ERR_MAX_DEPTH;
        }
        tagCbinfo.previousAsnOrTag = &previousAsn;
        tagCbinfo.idx = i;
        if (BSL_ASN1_IsConstructItem(&templ->templItems[i])) {
            ret = BSL_ASN1_ProcessNormal(&tagCbinfo, &templ->templItems[i], &temp, &tempLen, &asn);
            if (ret != BSL_SUCCESS) {
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05070, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                    "asn1: parse construct item err %x, idx %u", ret, i, 0, 0);
                return ret;
            }
            ret = BSL_ASN1_ProcessConstructResult(templ, &i, &asn, asnArr, arrNum, &arrIdx);
            if (ret != BSL_SUCCESS) {
                return ret;
            }
        } else {
            ret = BSL_ASN1_ProcessNormal(&tagCbinfo, &templ->templItems[i], &temp, &tempLen, &asn);
            if (ret != BSL_SUCCESS) {
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05071, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                    "asn1: parse primitive item err %x, idx %u", ret, i, 0, 0);
                return ret;
            }
            // Process no construct result
            if (arrIdx >= arrNum) {
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05072, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                    "asn1: array idx %u, overflow %u, templ %u", arrIdx, arrNum, i, 0);
                return BSL_ASN1_ERR_OVERFLOW;
            } else {
                asnArr[arrIdx++] = asn; //  Shallow copy of structure
            }
            i++;
        }
        previousAsn = asn;
    }

    *encode = temp;
    *encLen = tempLen;
    return BSL_SUCCESS;
}

/* Init the depth and flags of the items. */
static int32_t EncodeInitItemFlag(BSL_ASN1_EncodeItem *eItems, BSL_ASN1_TemplateItem *tItems, uint32_t eleNum)
{
    uint32_t stack[BSL_ASN1_MAX_TEMPLATE_DEPTH + 1] = {0}; // store the index of the items
    int32_t peek = 0;

    /* Stack the first item */
    if (tItems[0].depth > BSL_ASN1_MAX_TEMPLATE_DEPTH) {
        return BSL_ASN1_ERR_MAX_DEPTH;
    }
    eItems[0].depth = tItems[0].depth;
    eItems[0].optional = tItems[0].flags & BSL_ASN1_FLAG_OPTIONAL_DEFAUL;
    stack[peek] = 0;

    for (uint32_t i = 1; i < eleNum; i++) {
        if (tItems[i].depth > BSL_ASN1_MAX_TEMPLATE_DEPTH) {
            return BSL_ASN1_ERR_MAX_DEPTH;
        }
        eItems[i].depth = tItems[i].depth;
        while (eItems[i].depth <= eItems[stack[peek]].depth) {
            peek--;
        }
        /* After the above processing, the top of the stack is the parent node of the current node. */
        /* The null type only inherits the optional tag of the parent node. */
        eItems[i].optional = eItems[stack[peek]].optional;
        if (tItems[i].tag != BSL_ASN1_TAG_NULL) {
            eItems[i].optional |= (tItems[i].flags & BSL_ASN1_FLAG_OPTIONAL_DEFAUL);
        }
        eItems[i].skip = eItems[stack[peek]].skip == 1 || (tItems[stack[peek]].flags & BSL_ASN1_FLAG_HEADERONLY) != 0;
        stack[++peek] = i;
    }
    return BSL_SUCCESS;
}

static inline bool IsAnyOrChoice(uint8_t tag)
{
    return tag == BSL_ASN1_TAG_ANY || tag == BSL_ASN1_TAG_CHOICE;
}

static uint8_t GetOctetNumOfUint(uint64_t number)
{
    uint8_t cnt = 0;
    for (uint64_t i = number; i != 0; i >>= 8) { // one byte = 8 bits
        cnt++;
    }
    return cnt;
}

static uint8_t GetLenOctetNum(uint32_t contentOctetNum)
{
    return contentOctetNum <= BSL_ASN1_DEFINITE_MAX_CONTENT_OCTET_NUM ? 1 : 1 + GetOctetNumOfUint(contentOctetNum);
}

static int32_t GetContentLenOfInt(uint8_t *buff, uint32_t len, uint32_t *outLen)
{
    if (len == 0) {
        *outLen = 0;
        return BSL_SUCCESS;
    }
    uint32_t res = len;
    for (uint32_t i = 0; i < len; i++) {
        if (buff[i] != 0) {
            break;
        }
        res--;
    }
    if (res == 0) { // The current int value is 0
        *outLen = 1;
        return BSL_SUCCESS;
    }

    uint8_t high = buff[len - res] & 0x80;
    if (high) {
        if (res == UINT32_MAX) {
            return BSL_ASN1_ERR_LEN_OVERFLOW;
        }
        res++;
    }
    *outLen = res;
    return BSL_SUCCESS;
}

static int32_t GetContentLen(BSL_ASN1_Buffer *asn, uint32_t *len)
{
    if (asn == NULL || len == NULL) {
        return BSL_NULL_INPUT;
    }
    switch (asn->tag) {
        case BSL_ASN1_TAG_NULL:
            *len = 0;
            return BSL_SUCCESS;
        case BSL_ASN1_TAG_INTEGER:
        case BSL_ASN1_TAG_ENUMERATED:
            return GetContentLenOfInt(asn->buff, asn->len, len);
        case BSL_ASN1_TAG_BITSTRING:
            *len = ((BSL_ASN1_BitString *)asn->buff)->len;
            if (*len == UINT32_MAX) {
                return BSL_ASN1_ERR_LEN_OVERFLOW;
            }
            *len += 1;
            return BSL_SUCCESS;
        case BSL_ASN1_TAG_UTCTIME:
            *len = BSL_ASN1_UTCTIME_LEN;
            return BSL_SUCCESS;
        case BSL_ASN1_TAG_GENERALIZEDTIME:
            *len = BSL_ASN1_GENERALIZEDTIME_LEN;
            return BSL_SUCCESS;
        case BSL_ASN1_TAG_BMPSTRING:
            if (asn->len > UINT32_MAX / 2) { // 2: Each character is 2 bytes
                return BSL_ASN1_ERR_LEN_OVERFLOW;
            }
            *len = asn->len * 2; // 2: Each character is 2 bytes
            return BSL_SUCCESS;
        case BSL_ASN1_TAG_T61STRING:
            *len = asn->len;
            return BSL_SUCCESS;
        default:
            *len = asn->len;
            return BSL_SUCCESS;
    }
}

static int32_t ComputeOctetNum(bool optional, BSL_ASN1_EncodeItem *item, BSL_ASN1_Buffer *asn)
{
    if (optional && asn->len == 0 && (asn->tag != BSL_ASN1_TAG_NULL)) {
        return BSL_SUCCESS;
    }
    uint32_t contentOctetNum = 0;
    if (asn->len != 0) {
        int32_t ret = GetContentLen(asn, &contentOctetNum);
        if (ret != BSL_SUCCESS) {
            return ret;
        }
    }

    item->lenOctetNum = GetLenOctetNum(contentOctetNum);
    uint64_t tmp = (uint64_t)item->lenOctetNum + contentOctetNum;
    if (tmp > UINT32_MAX - 1) {
        return BSL_ASN1_ERR_LEN_OVERFLOW;
    }
    
    item->asnOctetNum = 1 + item->lenOctetNum + contentOctetNum;
    return BSL_SUCCESS;
}

static int32_t ComputeConstructAsnOctetNum(bool optional, BSL_ASN1_TemplateItem *templ, BSL_ASN1_EncodeItem *item,
    uint32_t itemNum, uint32_t curIdx)
{
    uint8_t curDepth = templ[curIdx].depth;
    uint32_t contentOctetNum = 0;
    for (uint32_t i = curIdx + 1; i < itemNum && templ[i].depth != curDepth; i++) {
        if (templ[i].depth - curDepth == 1) {
            if (item[i].asnOctetNum > UINT32_MAX - contentOctetNum) {
                return BSL_ASN1_ERR_LEN_OVERFLOW;
            }
            contentOctetNum += item[i].asnOctetNum;
        }
    }
    if (contentOctetNum == 0 && optional) {
        return BSL_SUCCESS;
    }
    item[curIdx].lenOctetNum = GetLenOctetNum(contentOctetNum);

    // Use 64-bit math to prevent overflow during calculation
    uint64_t totalLen = (uint64_t)item[curIdx].lenOctetNum + contentOctetNum;

    // Check for 32-bit overflow (ASN.1 length must fit in uint32_t)
    if (totalLen > UINT32_MAX - 1) { // -1 accounts for tag byte
        return BSL_ASN1_ERR_LEN_OVERFLOW;
    }
    item[curIdx].asnOctetNum = 1 + item[curIdx].lenOctetNum + contentOctetNum;
    return BSL_SUCCESS;
}

/**
 * ASN.1 Encode Init Item Content:
 * 1. Reverse traversal template items (from deepest to root node)
 * 2. Process two types:
 *    - Construct type (SEQUENCE/SET): Calculate total length of contained sub-items
 *    - Basic type: Validate tag and calculate encoding length
 */
static int32_t EncodeInitItemContent(BSL_ASN1_EncodeItem *eItems, BSL_ASN1_TemplateItem *tItems, uint32_t itemNum,
                                     BSL_ASN1_Buffer *asnArr, uint32_t *asnNum)
{
    int64_t asnIdx = (int64_t)*asnNum - 1;
    uint8_t lastDepth = 0;
    int32_t ret;

    for (int64_t i = itemNum - 1; i >= 0; i--) {
        if (eItems[i].skip == 1) {
            continue;
        }
        if (tItems[i].depth < lastDepth) {
            eItems[i].tag = tItems[i].tag;
            ret = ComputeConstructAsnOctetNum(eItems[i].optional, tItems, eItems, itemNum, i);
            if (ret != BSL_SUCCESS) {
                return ret;
            }
        } else {
            if (asnIdx < 0) {
                return BSL_ASN1_ERR_ENCODE_ASN_LACK;
            }
            if (eItems[i].optional == false && asnArr[asnIdx].tag != tItems[i].tag && !IsAnyOrChoice(tItems[i].tag)) {
                return BSL_ASN1_ERR_TAG_EXPECTED;
            }
            ret = ComputeOctetNum(eItems[i].optional, eItems + i, asnArr + asnIdx);
            if (ret != BSL_SUCCESS) {
                return ret;
            }
            eItems[i].tag = asnArr[asnIdx].tag;
            eItems[i].asn = asnArr + asnIdx; // Shallow copy.
            asnIdx--;
        }
        lastDepth = tItems[i].depth;
    }
    *asnNum = asnIdx + 1;  // Update the number of used ASN buffers
    return BSL_SUCCESS;
}

static void EncodeNumber(uint64_t data, uint32_t encodeLen, uint8_t *encode, uint32_t *offset)
{
    uint64_t tmp = data;
    /* Encode from back to front. */
    uint32_t initOff = *offset + encodeLen - 1;
    for (uint32_t i = 0; i < encodeLen; i++) {
        *(encode + initOff - i) = (uint8_t)tmp;
        tmp >>= 8; // one byte = 8 bits
    }
    *offset += encodeLen;
}

static void EncodeLength(uint8_t lenOctetNum, uint32_t contentOctetNum, uint8_t *encode, uint32_t *offset)
{
    if (contentOctetNum <= BSL_ASN1_DEFINITE_MAX_CONTENT_OCTET_NUM) {
        *(encode + *offset) = (uint8_t)contentOctetNum;
        *offset += 1;
        return;
    }

    // the initial octet
    *(encode + *offset) = BSL_ASN1_INDEFINITE_LENGTH | (lenOctetNum - 1);
    *offset += 1;
    // the subsequent octets
    EncodeNumber(contentOctetNum, lenOctetNum - 1, encode, offset);
}

static inline void EncodeBool(bool *data, uint8_t *encode, uint32_t *offset)
{
    *(encode + *offset) = *data == true ? 0xFF : 0x00;
    *offset += 1;
}

static void EncodeBitString(BSL_ASN1_BitString *data, uint32_t encodeLen, uint8_t *encode, uint32_t *offset)
{
    *(encode + *offset) = data->unusedBits;

    for (uint32_t i = 0; i < encodeLen - 1; i++) {
        *(encode + *offset + i + 1) = *(data->buff + i);
    }
    // Last octet: Set unused bits to 0
    *(encode + *offset + encodeLen - 1) >>= data->unusedBits;
    *(encode + *offset + encodeLen - 1) <<= data->unusedBits;
    *offset += encodeLen;
}

static void EncodeNum2Ascii(uint8_t *encode, uint32_t *offset, uint8_t encodeLen, uint16_t number)
{
    uint16_t tmp = number;
    /* Encode from back to front. */
    uint32_t initOff = *offset + encodeLen - 1;
    for (uint32_t i = 0; i < encodeLen; i++) {
        *(encode + initOff - i) = tmp % 10 + '0'; // 10: Take the lowest digit of a decimal number.
        tmp /= 10;                                // 10: Get the number in decimal except for the lowest bit.
    }
    *offset += encodeLen;
}

static void EncodeTime(BSL_TIME *time, uint8_t tag, uint8_t *encode, uint32_t *offset)
{
    if (tag == BSL_ASN1_TAG_UTCTIME) {
        EncodeNum2Ascii(encode, offset, 2, time->year % 100); // 2: YY, %100: Get the lower 2 digits of the number
    } else {
        EncodeNum2Ascii(encode, offset, 4, time->year); // 4: YYYY
    }
    EncodeNum2Ascii(encode, offset, 2, time->month);  // 2: MM
    EncodeNum2Ascii(encode, offset, 2, time->day);    // 2: DD
    EncodeNum2Ascii(encode, offset, 2, time->hour);   // 2: HH
    EncodeNum2Ascii(encode, offset, 2, time->minute); // 2: MM
    EncodeNum2Ascii(encode, offset, 2, time->second); // 2: SS
    *(encode + *offset) = 'Z';
    *offset += 1;
}

static void EncodeInt(BSL_ASN1_Buffer *asn, uint32_t encodeLen, uint8_t *encode, uint32_t *offset)
{
    if (encodeLen < asn->len) {
        /* Skip the copying of high-order octets with all zeros. */
        (void)memcpy_s(encode + *offset, encodeLen, asn->buff + (asn->len - encodeLen), encodeLen);
    } else {
        /* the high bit of positive number octet is 1 */
        (void)memcpy_s(encode + *offset + (encodeLen - asn->len), asn->len, asn->buff, asn->len);
    }
    *offset += encodeLen;
}

static void EncodeContent(BSL_ASN1_Buffer *asn, uint32_t encodeLen, uint8_t *encode, uint32_t *offset)
{
    switch (asn->tag) {
        case BSL_ASN1_TAG_BOOLEAN:
            EncodeBool((bool *)asn->buff, encode, offset);
            return;
        case BSL_ASN1_TAG_INTEGER:
        case BSL_ASN1_TAG_ENUMERATED:
            EncodeInt(asn, encodeLen, encode, offset);
            return;
        case BSL_ASN1_TAG_BITSTRING:
            EncodeBitString((BSL_ASN1_BitString *)asn->buff, encodeLen, encode, offset);
            return;
        case BSL_ASN1_TAG_UTCTIME:
        case BSL_ASN1_TAG_GENERALIZEDTIME:
            EncodeTime((BSL_TIME *)asn->buff, asn->tag, encode, offset);
            return;
        case BSL_ASN1_TAG_BMPSTRING:
            EncodeBMPString(asn->buff, asn->len, encode, offset);
            return;
        case BSL_ASN1_TAG_T61STRING:
            EncodeT61String(asn->buff, asn->len, encode, offset);
            return;
        default:
            (void)memcpy_s(encode + *offset, encodeLen, asn->buff, encodeLen);
            *offset += encodeLen;
            return;
    }
}

static void EncodeItem(BSL_ASN1_EncodeItem *eItems, uint32_t itemNum, uint8_t *encode)
{
    uint8_t *temp = encode;
    uint32_t offset = 0;
    uint32_t contentOctetNum;

    for (uint32_t i = 0; i < itemNum; i++) {
        if (eItems[i].asnOctetNum == 0) {
            continue;
        }
        contentOctetNum = eItems[i].asnOctetNum - 1 - eItems[i].lenOctetNum;

        /* tag */
        *(temp + offset) = eItems[i].tag;
        offset += 1;
        /* length */
        EncodeLength(eItems[i].lenOctetNum, contentOctetNum, encode, &offset);
        /* content */
        if (contentOctetNum != 0 && eItems[i].asn != NULL && eItems[i].asn->len != 0) {
            EncodeContent(eItems[i].asn, contentOctetNum, encode, &offset);
        }
    }
}

static int32_t CheckBslTime(BSL_ASN1_Buffer *asn)
{
    if (asn->len != sizeof(BSL_TIME)) {
        return BSL_ASN1_ERR_CHECK_TIME;
    }
    BSL_TIME *time = (BSL_TIME *)asn->buff;
    if (BSL_DateTimeCheck(time) == false) {
        return BSL_ASN1_ERR_CHECK_TIME;
    }
    if (asn->tag == BSL_ASN1_TAG_UTCTIME && (time->year < 2000 || time->year > 2049)) { // Utc time range: [2000, 2049]
        return BSL_ASN1_ERR_ENCODE_UTC_TIME;
    }
    if (asn->tag == BSL_ASN1_TAG_GENERALIZEDTIME &&
        time->year > 9999) { // 9999: The number of digits for year must be 4.
        return BSL_ASN1_ERR_ENCODE_GENERALIZED_TIME;
    }
    return BSL_SUCCESS;
}

static int32_t CheckBMPString(BSL_ASN1_Buffer *asn)
{
    for (uint32_t i = 0; i < asn->len; i++) {
        if (asn->buff[i] > 127) { // max ascii 127.
            return BSL_INVALID_ARG;
        }
    }
    return BSL_SUCCESS;
}

static int32_t CheckAsn(BSL_ASN1_Buffer *asn)
{
    switch (asn->tag) {
        case BSL_ASN1_TAG_BOOLEAN:
            return asn->len != sizeof(bool) ? BSL_ASN1_ERR_ENCODE_BOOL : BSL_SUCCESS;
        case BSL_ASN1_TAG_BITSTRING:
            if (asn->len != sizeof(BSL_ASN1_BitString)) {
                return BSL_ASN1_ERR_ENCODE_BIT_STRING;
            }
            BSL_ASN1_BitString *bs = (BSL_ASN1_BitString *)asn->buff;
            return bs->unusedBits > BSL_ASN1_VAL_MAX_BIT_STRING_LEN ? BSL_ASN1_ERR_ENCODE_BIT_STRING : BSL_SUCCESS;
        case BSL_ASN1_TAG_UTCTIME:
        case BSL_ASN1_TAG_GENERALIZEDTIME:
            return CheckBslTime(asn);
        case BSL_ASN1_TAG_BMPSTRING:
            return CheckBMPString(asn);
        default:
            return BSL_SUCCESS;
    }
}

static int32_t CheckAsnArr(BSL_ASN1_Buffer *asnArr, uint32_t arrNum)
{
    int32_t ret;
    for (uint32_t i = 0; i < arrNum; i++) {
        if (asnArr[i].buff != NULL) {
            ret = CheckAsn(asnArr + i);
            if (ret != BSL_SUCCESS) {
                return ret;
            }
        }
    }
    return BSL_SUCCESS;
}

static int32_t EncodeItemInit(BSL_ASN1_EncodeItem *eItems, BSL_ASN1_TemplateItem *tItems, uint32_t itemNum,
                              BSL_ASN1_Buffer *asnArr, uint32_t *arrNum)
{
    int32_t ret = EncodeInitItemFlag(eItems, tItems, itemNum);
    if (ret != BSL_SUCCESS) {
        return ret;
    }

    return EncodeInitItemContent(eItems, tItems, itemNum, asnArr, arrNum);
}

static int32_t EncodeInit(BSL_ASN1_EncodeItem *eItems, BSL_ASN1_Template *templ, BSL_ASN1_Buffer *asnArr,
                          uint32_t arrNum, uint32_t *encodeLen)
{
    uint32_t tempArrNum = arrNum;
    uint32_t stBegin;
    uint32_t stEnd = templ->templNum - 1;
    int32_t ret;

    uint32_t i = templ->templNum;
    while (i-- > 0) {
        if (templ->templItems[i].depth > BSL_ASN1_MAX_TEMPLATE_DEPTH) {
            return BSL_ASN1_ERR_MAX_DEPTH;
        }
        if (templ->templItems[i].depth != 0) {
            continue;
        }
        stBegin = i;
        ret = EncodeItemInit(eItems + stBegin, templ->templItems + stBegin, stEnd - stBegin + 1, asnArr, &tempArrNum);
        if (ret != BSL_SUCCESS) {
            return ret;
        }
        if ((eItems + stBegin)->asnOctetNum > UINT32_MAX - *encodeLen) {
            return BSL_ASN1_ERR_LEN_OVERFLOW;
        }
        *encodeLen += (eItems + stBegin)->asnOctetNum;
        stEnd = i - 1;
    }
    if (tempArrNum != 0) { // Check whether all the asn-item has been used.
        return BSL_ASN1_ERR_ENCODE_ASN_TOO_MUCH;
    }
    return BSL_SUCCESS;
}

int32_t BSL_ASN1_EncodeTemplate(BSL_ASN1_Template *templ, BSL_ASN1_Buffer *asnArr, uint32_t arrNum, uint8_t **encode,
                                uint32_t *encLen)
{
    if (IsInvalidTempl(templ) || IsInvalidAsns(asnArr, arrNum) || encode == NULL || *encode != NULL || encLen == NULL) {
        return BSL_INVALID_ARG;
    }
    int32_t ret = CheckAsnArr(asnArr, arrNum);
    if (ret != BSL_SUCCESS) {
        return ret;
    }

    BSL_ASN1_EncodeItem *eItems = (BSL_ASN1_EncodeItem *)BSL_SAL_Calloc(templ->templNum, sizeof(BSL_ASN1_EncodeItem));
    if (eItems == NULL) {
        return BSL_MALLOC_FAIL;
    }
    uint32_t encodeLen = 0;
    ret = EncodeInit(eItems, templ, asnArr, arrNum, &encodeLen);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_Free(eItems);
        return ret;
    }

    *encode = (uint8_t *)BSL_SAL_Calloc(1, encodeLen);
    if (*encode == NULL) {
        BSL_SAL_Free(eItems);
        return BSL_MALLOC_FAIL;
    }
    EncodeItem(eItems, templ->templNum, *encode);
    *encLen = encodeLen;

    BSL_SAL_Free(eItems);
    return BSL_SUCCESS;
}

int32_t BSL_ASN1_EncodeListItem(uint8_t tag, uint32_t listSize, BSL_ASN1_Template *templ, BSL_ASN1_Buffer *asnArr,
                                uint32_t arrNum, BSL_ASN1_Buffer *out)
{
    if ((tag != BSL_ASN1_TAG_SEQUENCE && tag != BSL_ASN1_TAG_SET) || IsInvalidTempl(templ) ||
        IsInvalidAsns(asnArr, arrNum) || listSize == 0 || arrNum % listSize != 0 || out == NULL || out->buff != NULL) {
        return BSL_INVALID_ARG;
    }
    int32_t ret = CheckAsnArr(asnArr, arrNum);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    if (listSize > UINT32_MAX / templ->templNum) {
        return BSL_ASN1_ERR_LEN_OVERFLOW;
    }

    BSL_ASN1_EncodeItem *eItems =
        (BSL_ASN1_EncodeItem *)BSL_SAL_Calloc(templ->templNum * listSize, sizeof(BSL_ASN1_EncodeItem));
    if (eItems == NULL) {
        return BSL_MALLOC_FAIL;
    }
    uint32_t encodeLen = 0;
    uint32_t itemAsnNum;
    for (uint32_t i = 0; i < listSize; i++) {
        itemAsnNum = arrNum / listSize;
        ret = EncodeItemInit(
            eItems + i * templ->templNum, templ->templItems, templ->templNum, asnArr + i * itemAsnNum, &itemAsnNum);
        if (ret != BSL_SUCCESS) {
            BSL_SAL_Free(eItems);
            return ret;
        }
        if (itemAsnNum != 0) {
            BSL_SAL_Free(eItems);
            return BSL_ASN1_ERR_ENCODE_ASN_TOO_MUCH;
        }
        if (eItems[i * templ->templNum].asnOctetNum > UINT32_MAX - encodeLen) {
            BSL_SAL_Free(eItems);
            return BSL_ASN1_ERR_LEN_OVERFLOW;
        }
        encodeLen += eItems[i * templ->templNum].asnOctetNum;
    }

    out->buff = (uint8_t *)BSL_SAL_Calloc(1, encodeLen);
    if (out->buff == NULL) {
        BSL_SAL_Free(eItems);
        return BSL_MALLOC_FAIL;
    }
    uint8_t *encode = out->buff;
    for (uint32_t i = 0; i < listSize; i++) {
        EncodeItem(eItems + i * templ->templNum, templ->templNum, encode);
        encode += (eItems + i * templ->templNum)->asnOctetNum;
    }

    out->tag = tag | BSL_ASN1_TAG_CONSTRUCTED;
    out->len = encodeLen;

    BSL_SAL_Free(eItems);
    return BSL_SUCCESS;
}

int32_t BSL_ASN1_EncodeLimb(uint8_t tag, uint64_t limb, BSL_ASN1_Buffer *asn)
{
    if ((tag != BSL_ASN1_TAG_INTEGER && tag != BSL_ASN1_TAG_ENUMERATED) || asn == NULL || asn->buff != NULL) {
        return BSL_INVALID_ARG;
    }

    asn->tag = tag;
    asn->len = limb == 0 ? 1 : GetOctetNumOfUint(limb);
    asn->buff = (uint8_t *)BSL_SAL_Calloc(1, asn->len);
    if (asn->buff == NULL) {
        return BSL_MALLOC_FAIL;
    }
    if (limb == 0) {
        return BSL_SUCCESS;
    }
    uint32_t offset = 0;
    EncodeNumber(limb, asn->len, asn->buff, &offset);
    return BSL_SUCCESS;
}

int32_t BSL_ASN1_GetEncodeLen(uint32_t contentLen, uint32_t *encodeLen)
{
    if (encodeLen == NULL) {
        return BSL_NULL_INPUT;
    }
    uint8_t lenOctetNum = GetLenOctetNum(contentLen);
    if (contentLen > (UINT32_MAX - lenOctetNum - 1)) {
        return BSL_ASN1_ERR_LEN_OVERFLOW;
    }

    *encodeLen = 1 + lenOctetNum + contentLen;
    return BSL_SUCCESS;
}
