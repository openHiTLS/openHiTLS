/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "bsl_asn1.h"
#include "bsl_err.h"
#include "bsl_bytes.h"
#include "bsl_log_internal.h"
#include "bsl_binlog_id.h"
#include "bsl_asn1.h"
#include "bsl_asn1_local.h"
#include "bsl_sal.h"
#include "sal_time.h"

int32_t BSL_ASN1_DecodeLen(uint8_t **encode, uint32_t *encLen, uint32_t *len)
{
    uint8_t *temp = *encode;
    uint32_t tempLen = *encLen;
    uint32_t parseLen = 0;
    if (tempLen < 1) {
        return BSL_ASN1_ERR_DECODE_LEN;
    }
    
    if (*temp < 0x80) {
        *len = *temp;
        temp++;
        tempLen--;
        *encode = temp;
        *encLen = tempLen;
        return BSL_SUCCESS;
    }
    /* The length supports a maximum of 4 bytes */
    if (*temp > 0x84) {
        return BSL_ASN1_ERR_MAX_LEN_NUM;
    }
    uint8_t count = (*temp & 7);
    temp++;
    tempLen--;
    switch (count) {
        case 1:
            if (tempLen < 1) {
                return BSL_ASN1_ERR_DECODE_LEN;
            }
            parseLen = *temp;
            temp++;
            tempLen--;
            break;
        case 2:
            if (tempLen < 2) {
                return BSL_ASN1_ERR_DECODE_LEN;
            }
            parseLen = (size_t)BSL_ByteToUint16(temp);
            temp += 2;
            tempLen -= 2;
            break;
        case 3:
            if (tempLen < 3) {
                return BSL_ASN1_ERR_DECODE_LEN;
            }
            parseLen = (size_t)BSL_ByteToUint24(temp);
            temp += 3;
            tempLen -= 3;
            break;
        case 4:
            if (tempLen < 4) {
                return BSL_ASN1_ERR_DECODE_LEN;
            }
            parseLen = (size_t)BSL_ByteToUint32(temp);
            temp += 4;
            tempLen -= 4;
            break;
    }
    if (parseLen > tempLen) {
        return BSL_ASN1_ERR_DECODE_LEN;
    }
    *len = parseLen;
    *encode = temp;
    *encLen = tempLen;
    return BSL_SUCCESS;
}

int32_t BSL_ASN1_DecodeTagLen(uint8_t tag, uint8_t **encode, uint32_t *encLen, uint32_t *valLen)
{
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
    int32_t ret = BSL_ASN1_DecodeLen(&temp, &tempLen, &len);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    *valLen = len;
    *encode = temp;
    *encLen = tempLen;
    return BSL_SUCCESS;
}

int32_t BSL_ASN1_DecodeItem(uint8_t **encode, uint32_t *encLen, BSL_ASN1_Buffer *asnItem)
{
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
    int32_t ret = BSL_ASN1_DecodeLen(&temp, &tempLen, &len);
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

// The complement form supports negative numbers, so it cannot parse unsigned integers
static int32_t ParseInt(uint8_t *val, uint32_t len, int *decodeData)
{
    uint8_t *temp = val;
    // Negative numbers not supported
    if (len < 1 || (*val & 0x80) != 0 || len > sizeof(int)) {
        return BSL_ASN1_ERR_DECODE_INT;
    }

    *decodeData = 0;
    for (size_t i = 0; i < len; i++) {
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
static uint32_t DecodeAscllNum(uint8_t **encode, uint32_t len)
{
    uint32_t temp = 0;
    uint8_t *data = *encode;
    for (uint32_t i = 0; i < len; i++) {
        temp *= 10;
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
    if (tag == BSL_ASN1_TAG_UTCTIME) {
        ret = CheckTime(val, 12); // ignoring Z
    } else {
        ret = CheckTime(val, 14); // ignoring Z
    }
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    
    if (tag == BSL_ASN1_TAG_UTCTIME) {
        decodeData->year = DecodeAscllNum(&temp, 2);
        decodeData->year += 2000; // Currently supported after 2000 year
    } else {
        decodeData->year = DecodeAscllNum(&temp, 4);
    }
    decodeData->month = DecodeAscllNum(&temp, 2);
    decodeData->day = DecodeAscllNum(&temp, 2);
    decodeData->hour = DecodeAscllNum(&temp, 2);
    decodeData->minute = DecodeAscllNum(&temp, 2);
    decodeData->second = DecodeAscllNum(&temp, 2);
    return BSL_DateTimeCheck(decodeData) ? BSL_SUCCESS : BSL_ASN1_ERR_CHECK_TIME;
}

static int32_t DecodeTwoLayerListInternal(uint32_t layer, BSL_ASN1_DecodeListParam *param, BSL_ASN1_Buffer *asn,
    BSL_ASN1_ParseListAsnItem parseListItemCb, void *cbParam, BSL_ASN1_List *list)
{
    int32_t ret;
    uint8_t tag;
    uint32_t encLen;
    uint8_t *buff = asn->buff;
    uint32_t len = asn->len;
    BSL_ASN1_Buffer item;
    while (len > 0) {
        if (*buff != param->expTag[layer - 1]) {
            return BSL_ASN1_ERR_MISMATCH_TAG;
        }
        tag = *buff;
        buff++;
        len--;
        ret = BSL_ASN1_DecodeLen(&buff, &len, &encLen);
        if (ret != BSL_SUCCESS) {
            return ret;
        }
        item.tag = tag;
        item.len = encLen;
        item.buff = buff;
        ret = parseListItemCb(layer, &item, cbParam, list);
        if (ret != BSL_SUCCESS) {
            return ret;
        }
        buff += encLen;
        len -= encLen;
    }
    return BSL_SUCCESS;
}

static int32_t DecodeOneLayerList(BSL_ASN1_DecodeListParam *param, BSL_ASN1_Buffer *asn,
    BSL_ASN1_ParseListAsnItem parseListItemCb, void *cbParam, BSL_ASN1_List *list)
{
    return DecodeTwoLayerListInternal(1, param, asn, parseListItemCb, cbParam, list);
}

static int32_t DecodeTwoLayerList(BSL_ASN1_DecodeListParam *param, BSL_ASN1_Buffer *asn,
    BSL_ASN1_ParseListAsnItem parseListItemCb, void *cbParam, BSL_ASN1_List *list)
{
    int32_t ret;
    uint8_t tag;
    uint32_t encLen;
    uint8_t *buff = asn->buff;
    uint32_t len = asn->len;
    BSL_ASN1_Buffer item;
    while (len > 0) {
        if (*buff != param->expTag[0]) {
            return BSL_ASN1_ERR_MISMATCH_TAG;
        }
        tag = *buff;
        buff++;
        len--;
        ret = BSL_ASN1_DecodeLen(&buff, &len, &encLen);
        if (ret != BSL_SUCCESS) {
            return ret;
        }
        item.tag = tag;
        item.len = encLen;
        item.buff = buff;
        ret = parseListItemCb(1, &item, cbParam, list);
        if (ret != BSL_SUCCESS) {
            return ret;
        }
        ret = DecodeTwoLayerListInternal(2, param, &item, parseListItemCb, cbParam, list);
        if (ret != BSL_SUCCESS) {
            return ret;
        }
        buff += encLen;
        len -= encLen;
    }
    return BSL_SUCCESS;
}


int32_t BSL_ASN1_DecodeLsitItem(BSL_ASN1_DecodeListParam *param, BSL_ASN1_Buffer *asn,
    BSL_ASN1_ParseListAsnItem parseListItemCb, void *cbParam, BSL_ASN1_List *list)
{
    if (param == NULL || asn == NULL || parseListItemCb == NULL || list == NULL) {
        return BSL_INVALID_ARG;
    }
    
     // Currently, it supports a maximum of 2 layers
    if (param->layer > BSL_ASN1_MAX_LIST_NEST_EPTH) {
        return BSL_ASN1_ERR_EXCEED_LIST_DEPTH;
    }
    
    if (param->layer == 1) {
        return DecodeOneLayerList(param, asn, parseListItemCb, cbParam, list);
    }
    return DecodeTwoLayerList(param, asn, parseListItemCb, cbParam, list);
}

/*
 * Big numbers do not need to call this interface, 
 * the filled leading 0 has no effect on the result of large numbers, big numbers can be directly used asn's buff.
 *
 * It has been ensured at parsing time that the content to which the buff points is security for length within asn'len
 *  */
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
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05065, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
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
        ret = BSL_ASN1_AnyOrChoiceTagProcess(false, tagCbinfo, expTag);
        if (ret != BSL_SUCCESS) {
            return ret;
        }
    } else { // The tags of any and normal must be present
        if (tag == BSL_ASN1_TAG_ANY) {
            ret = BSL_ASN1_AnyOrChoiceTagProcess(true, tagCbinfo, &tag);
            if (ret != BSL_SUCCESS) {
                return ret;
            }
        }
        if (tag != realTag) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05065, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "asn1: expected tag %x is not match %x", tag, realTag, 0, 0);
            return BSL_ASN1_ERR_TAG_EXPECTED;
        }
        *expTag = realTag;
    }
    return BSL_SUCCESS;
}

int32_t BSL_ASN1_ProcessNormal(BSL_ASN1_AnyOrChoiceParam *tagCbinfo,
    BSL_ASN1_TemplateItem *item, uint8_t **encode, uint32_t *encLen, BSL_ASN1_Buffer *asn)
{
    uint32_t len;
    int32_t ret;
    uint8_t tag = item->tag;
    uint8_t *temp = *encode;
    uint32_t tempLen = *encLen;

    if (item->flags & BSL_ASN1_FLAG_OPTIONAL_DEFAUL) { // optional or default scene
        if (tempLen < 1) { // optional or default scene is normal
            asn->tag = 0;
            asn->len = 0;
            asn->buff = NULL;
            return BSL_SUCCESS;
        }

        if (tag == BSL_ASN1_TAG_ANY) {
            ret = BSL_ASN1_AnyOrChoiceTagProcess(true, tagCbinfo, &tag);
            if (ret != BSL_SUCCESS) {
                return ret;
            }
        }

        if (tag == BSL_ASN1_TAG_CHOICE) {
            tagCbinfo->previousAsnOrTag = temp;
            ret = BSL_ASN1_AnyOrChoiceTagProcess(false, tagCbinfo, &tag);
            if (ret != BSL_SUCCESS) {
                return ret;
            }
        }
        
        if (tag != *temp) { // The optional or default scene is not encoded
            asn->tag = 0;
            asn->len = 0;
            asn->buff = NULL;
            return BSL_SUCCESS;
        }
    } else {
        /* No optional or default scenes, tag must exist */
        if (tempLen < 1) {
            return BSL_ASN1_ERR_DECODE_LEN;
        }
        ret = BSL_ASN1_ProcessWithoutDefOrOpt(tagCbinfo, *temp, &tag);
        if (ret != BSL_SUCCESS) {
            return ret;
        }
    }

    temp++;
    tempLen--;
    ret = BSL_ASN1_DecodeLen(&temp, &tempLen, &len);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    asn->tag = tag;
    asn->len = len;
    asn->buff = (tag == BSL_ASN1_TAG_NULL) ? NULL: temp;
    if (item->tag & BSL_ASN1_TAG_CONSTRUCTED) {
        /* struct type, headerOnly flag is set, only the whole is parsed,
         otherwise the parsed content is traversed */
        if (item->flags & BSL_ASN1_FLAG_HEADERONLY) {
            temp += len;
            tempLen -= len;
        }
    } else {
        temp += len;
        tempLen -= len;
    }
    *encode = temp;
    *encLen = tempLen;
    return BSL_SUCCESS;
}

int32_t BSL_ASN1_SkipChildNode(int32_t idx, BSL_ASN1_TemplateItem *item, uint32_t count)
{
    size_t i = idx + 1;
    for (; i < count; i++) {
        if (item[i].depth <= item[idx].depth) {
            break;
        }
    }
    return i - idx;
}

static bool BSL_ASN1_IsConstructItem(BSL_ASN1_TemplateItem *item)
{
    if (item->tag & BSL_ASN1_TAG_CONSTRUCTED) {
        return true;
    } else {
        return false;
    }
}

static int32_t BSL_ASN1_FillConstructItemWithNull(BSL_ASN1_Template *templ, uint32_t *templIdx,
    BSL_ASN1_Buffer *asnArr, uint32_t arrNum, uint32_t *arrIdx)
{
    // The construct type value is marked headeronly
    if (templ->templItems[*templIdx].flags & BSL_ASN1_FLAG_HEADERONLY) {
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
    if ((templ->templItems[*templIdx].flags & BSL_ASN1_FLAG_OPTIONAL_DEFAUL) && asn->tag == 0) {
        ret = BSL_ASN1_SkipChildNodeAndFill(templIdx, templ, asnArr, arrNum, arrIdx);
        if (ret != BSL_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05065, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "asn1: skip and file node err %x, idx %d", ret, *templIdx, 0, 0);
            return ret;
        }
        return BSL_SUCCESS;
    }

    if (templ->templItems[*templIdx].flags & BSL_ASN1_FLAG_HEADERONLY) {
        if (*arrIdx >= arrNum) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05065, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "asn1: array idx %d, overflow %d, templ %d", *arrIdx, arrNum, *templIdx, 0);
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

int32_t BSL_ASN1_DecodeTemplate(BSL_ASN1_Template *templ, BSL_ASN1_DecTemplCallBack decTemlCb,
    uint8_t **encode, uint32_t *encLen, BSL_ASN1_Buffer *asnArr, uint32_t arrNum)
{
    int32_t ret;
    if (templ == NULL || encode == NULL || encLen == NULL || asnArr == NULL) {
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
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05065, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                    "asn1: parse construct item err %x, idx %d", ret, i, 0, 0);
                return ret;
            }
            ret = BSL_ASN1_ProcessConstructResult(templ, &i, &asn, asnArr, arrNum, &arrIdx);
            if (ret != BSL_SUCCESS) {
                return ret;
            }
        } else {
            ret = BSL_ASN1_ProcessNormal(&tagCbinfo, &templ->templItems[i], &temp, &tempLen, &asn);
            if (ret != BSL_SUCCESS) {
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05065, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                    "asn1: parse primitive item err %x, idx %d", ret, i, 0, 0);
                return ret;
            }
            // Process no construct result
            if (arrIdx >= arrNum) {
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05065, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                    "asn1: array idx %d, overflow %d, templ %d", arrIdx, arrNum, i, 0);
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