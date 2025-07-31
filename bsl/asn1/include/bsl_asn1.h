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

#ifndef BSL_ASN1_H
#define BSL_ASN1_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "bsl_list.h"
#include "bsl_uio.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BSL_ASN1_CLASS_UNIVERSAL       0x0   /* bit8 0, bit7 0 */
#define BSL_ASN1_CLASS_APPLICATION     0x40  /* bit8 0, bit7 1 */
#define BSL_ASN1_CLASS_CTX_SPECIFIC    0x80  /* bit8 1, bit7 0 */
#define BSL_ASN1_CLASS_PRIVATE         0xC0  /* bit8 1, bit7 1 */

#define BSL_ASN1_TAG_CONSTRUCTED       0x20

/* ASN1 tag from x.680  */
#define BSL_ASN1_TAG_BOOLEAN           0x01
#define BSL_ASN1_TAG_INTEGER           0x02
#define BSL_ASN1_TAG_BITSTRING         0x03
#define BSL_ASN1_TAG_OCTETSTRING       0x04
#define BSL_ASN1_TAG_NULL              0x05
#define BSL_ASN1_TAG_OBJECT_ID         0x06
#define BSL_ASN1_TAG_OBJECT_DESCP      0x07
#define BSL_ASN1_TAG_INSTANCE_OF       0x08
#define BSL_ASN1_TAG_REAL              0x09
#define BSL_ASN1_TAG_ENUMERATED        0x0A
#define BSL_ASN1_TAG_EMBEDDED_PDV      0x0B
#define BSL_ASN1_TAG_UTF8STRING        0x0C
#define BSL_ASN1_TAG_RALATIVE_ID       0x0D
#define BSL_ASN1_TAG_TIME              0x0E
#define BSL_ASN1_TAG_SEQUENCE          0x10
#define BSL_ASN1_TAG_SET               0x11
#define BSL_ASN1_TAG_PRINTABLESTRING   0x13
#define BSL_ASN1_TAG_IA5STRING         0x16

#define BSL_ASN1_TAG_UTCTIME           0x17
#define BSL_ASN1_TAG_GENERALIZEDTIME   0x18
#define BSL_ASN1_TAG_BMPSTRING         0x1E

/* Custom types, use private class to prevent conflicts */
#define BSL_ASN1_TAG_CHOICE (BSL_ASN1_CLASS_PRIVATE | 1)
#define BSL_ASN1_TAG_ANY (BSL_ASN1_CLASS_PRIVATE | 2)
#define BSL_ASN1_TAG_EMPTY 0x00 /* Empty tag, used to indicate that the tag is not encoded */

/* The current value is flags, is used to guide asn1 encoding or decoding */
#define BSL_ASN1_FLAG_OPTIONAL 1
/* The current value is default, is used to guide asn1 encoding or decoding */
#define BSL_ASN1_FLAG_DEFAULT  2
/* Only parsing or encoding headers, and child nodes are not traversed */
#define BSL_ASN1_FLAG_HEADERONLY 4
/* The implied values are of the same type */
#define BSL_ASN1_FLAG_SAME 8

#define BSL_ASN1_MAX_TEMPLATE_DEPTH 6

#define BSL_ASN1_UTCTIME_LEN 13         // YYMMDDHHMMSSZ
#define BSL_ASN1_GENERALIZEDTIME_LEN 15 // YYYYMMDDHHMMSSZ

#define BSL_ASN1_List BslList

typedef enum {
    BSL_ASN1_TYPE_GET_ANY_TAG = 0,
    BSL_ASN1_TYPE_CHECK_CHOICE_TAG = 1
} BSL_ASN1_CALLBACK_TYPE;

typedef struct _BSL_ASN1_TemplateItem {
    /* exptect tag */
    uint8_t tag;
    /* corresponding to the tag flag */
    uint8_t flags : 5;
    uint8_t depth : 3;
} BSL_ASN1_TemplateItem;

typedef struct _BSL_ASN1_Template {
    BSL_ASN1_TemplateItem *templItems;
    uint32_t templNum;
} BSL_ASN1_Template;

typedef struct _BSL_ASN1_Buffer {
    uint8_t tag;
    uint32_t len;
    uint8_t *buff;
} BSL_ASN1_Buffer;

typedef struct _BSL_ASN1_BitString {
    uint8_t *buff;
    uint32_t len;
    uint8_t unusedBits;
} BSL_ASN1_BitString;

/**
 * @ingroup bsl_asn1
 * @brief The extension function for template decoding is used to handle decoding of uncertain data types.
 *
 * @param type [IN] BSL_ASN1_CALLBACK_TYPE
 * @param idx [IN] The position of the data to be processed in the template.
 * @param data [IN] The data to be processed.
 * @param expVal [OUT] Output value.
 */
typedef int32_t(*BSL_ASN1_DecTemplCallBack)(int32_t type, uint32_t idx, void *data, void *expVal);

/**
 * @ingroup bsl_asn1
 * @brief The extension function for template decoding is used to convert an ASN item into a list.
 *
 * @param layer [IN] The layer of a list, used to construct the name node will use.
 * @param asn [IN] The asn1 item to be decoded.
 * @param cbParam [IN/OUT] The other parameters for decoding.
 * @param list [OUT] Output value.
 */
typedef int32_t(*BSL_ASN1_ParseListAsnItem)(uint32_t layer, BSL_ASN1_Buffer *asn, void *cbParam, BSL_ASN1_List *list);

typedef struct _BSL_ASN1_DecodeListParam {
    uint32_t layer;
    uint8_t *expTag;
} BSL_ASN1_DecodeListParam;

/**
 * @ingroup bsl_asn1
 * @brief Obtain the length of V or LV in an ASN1 TLV structure.
 *
 * @param encode [IN/OUT] Data to be decoded. Update the offset after decoding.
 * @param encLen [IN/OUT] The length of the data to be decoded.
 * @param completeLen [IN] True: Get the length of L+V; False: Get the length of V.
 * @param len [OUT] Output.
 * @retval  BSL_SUCCESS, success.
 *          Other error codes see the bsl_errno.h.
 */
int32_t BSL_ASN1_DecodeLen(uint8_t **encode, uint32_t *encLen, bool completeLen, uint32_t *len);

/**
 * @ingroup bsl_asn1
 * @brief Decode the tag and length fields of an ASN.1 TLV structure and validate against expected tag.
 *
 * @param tag [IN] Expected ASN.1 tag value to validate against.
 * @param encode [IN/OUT] Pointer to buffer containing encoded data. Updated to point after tag and length fields.
 * @param encLen [IN/OUT] Length of remaining encoded data. Updated to reflect bytes consumed.
 * @param valLen [OUT] Length of the value field in bytes.
 * @retval BSL_SUCCESS Successfully decoded tag and length fields.
 *         BSL_NULL_INPUT Invalid NULL parameters.
 *         BSL_INVALID_ARG Buffer too small.
 *         BSL_ASN1_ERR_MISMATCH_TAG Tag does not match expected value.
 *         Other error codes see bsl_errno.h.
 */
int32_t BSL_ASN1_DecodeTagLen(uint8_t tag, uint8_t **encode, uint32_t *encLen, uint32_t *valLen);

/**
 * @ingroup bsl_asn1
 * @brief Decoding data of type 'SEQUENCE OF' or 'SET OF'.
 *
 * @param param [IN] The parameters of the data to be decoded.
 * @param asn [IN] The data to be decoded.
 * @param parseListItemCb [IN] User defined callback function used to convert an ASN item into a list.
 * @param cbParam [IN/OUT] The parameters in the callback function.
 * @param list [OUT] Decoding result.
 * @retval  BSL_SUCCESS, success.
 *          Other error codes see the bsl_errno.h.
 */
int32_t BSL_ASN1_DecodeListItem(BSL_ASN1_DecodeListParam *param, BSL_ASN1_Buffer *asn,
    BSL_ASN1_ParseListAsnItem parseListItemCb, void *cbParam, BSL_ASN1_List *list);

/**
 * @ingroup bsl_asn1
 * @brief Decoding of primitive type data.
 *
 * @param asn [IN] The data to be decoded.
 * @param decodeData [OUT] Decoding result.
 * @retval  BSL_SUCCESS, success.
 *          Other error codes see the bsl_errno.h.
 */
int32_t BSL_ASN1_DecodePrimitiveItem(BSL_ASN1_Buffer *asn, void *decodeData);

/**
 * @ingroup bsl_asn1
 * @brief Template decoding method.
 *
 * @param templ [IN] Encoding template.
 * @param decTemlCb [IN] Function for handling uncertain types of data.
 * @param encode [IN/OUT] Data to be decoded. Update the offset after decoding.
 * @param encLen [IN/OUT] The length of the data to be decoded.
 * @param asnArr [OUT] List of data to be decoded.
 * @param arrNum [IN] The number of data to be encoded, which is determined by the template.
 * @retval  BSL_SUCCESS, success.
 *          Other error codes see the bsl_errno.h.
 */
int32_t BSL_ASN1_DecodeTemplate(BSL_ASN1_Template *templ, BSL_ASN1_DecTemplCallBack decTemlCb,
    uint8_t **encode, uint32_t *encLen, BSL_ASN1_Buffer *asnArr, uint32_t arrNum);

/**
 * @ingroup bsl_asn1
 * @brief Decode one asn1 item.
 *
 * @param encode [IN/OUT] Data to be decoded. Update the offset after decoding.
 * @param encLen [IN/OUT] The length of the data to be decoded.
 * @param asnItem [OUT] Output.
 * @retval  BSL_SUCCESS, success.
 *          Other error codes see the bsl_errno.h.
 */
int32_t BSL_ASN1_DecodeItem(uint8_t **encode, uint32_t *encLen, BSL_ASN1_Buffer *asnItem);

/**
 * @ingroup bsl_asn1
 * @brief Obtain the length of an ASN1 TLV structure.
 *
 * @param data [IN] Data to be decoded. Update the offset after decoding.
 * @param dataLen [OUT] Decoding result.
 * @retval  BSL_SUCCESS, success.
 *          Other error codes see the bsl_errno.h.
 */
int32_t BSL_ASN1_GetCompleteLen(uint8_t *data, uint32_t *dataLen);

/**
 * @ingroup bsl_asn1
 * @brief Template encoding method.
 *
 * @attention
 *  1. For SET types: The elements in the template should be sorted into tag order.
 *  2. The type for the following types of BSL_ASN1_Buffer.buff are as follows:
 *    a. BSL_ASN1_TAG_BOOLEAN: bool *
 *    b. BSL_ASN1_TAG_BITSTRING: BSL_ASN1_BitString *
 *    c. BSL_ASN1_TAG_UTCTIME|BSL_ASN1_TAG_GENERALIZEDTIME: BSL_TIME *
 *
 * @param templ [IN] Encoding template.
 * @param asnArr [IN] List of data to be encoded.
 * @param arrNum [IN] The number of data to be encoded, which is determined by the template.
 * @param encode [OUT] Encoding result.
 * @param encLen [OUT] Encoding length.
 * @retval  BSL_SUCCESS, success.
 *          Other error codes see the bsl_errno.h.
 */
int32_t BSL_ASN1_EncodeTemplate(BSL_ASN1_Template *templ, BSL_ASN1_Buffer *asnArr, uint32_t arrNum,
    uint8_t **encode, uint32_t *encLen);

/**
 * @ingroup bsl_asn1
 * @brief Encoding data of type 'SEQUENCE OF' or 'SET OF'.
 *
 * @attention
 *   1. BSL_ASN1_TAG_SEQUENCE is type 'SEQUENCE OF'.
 *   2. BSL_ASN1_TAG_SET is type 'SET OF'.
 *   3. The sorting in 'SET OF' is currently not supported.
 *
 * @param tag [IN] BSL_ASN1_TAG_SEQUENCE or BSL_ASN1_TAG_SET
 * @param listSize [IN] The number of elements in the list.
 * @param templ [IN] Template for elements in the list.
 * @param asnArr [IN] List of data to be encoded.
 * @param arrNum [IN] The number of data to be encoded.
 * @param out [OUT] Encoding result.
 * @retval  BSL_SUCCESS, success.
 *          Other error codes see the bsl_errno.h.
 */
int32_t BSL_ASN1_EncodeListItem(uint8_t tag, uint32_t listSize, BSL_ASN1_Template *templ, BSL_ASN1_Buffer *asnArr,
    uint32_t arrNum, BSL_ASN1_Buffer *out);

/**
 * @ingroup bsl_asn1
 * @brief Encode the smaller positive integer.
 *
 * @param tag [IN] BSL_ASN1_TAG_INTEGER or BSL_ASN1_TAG_ENUMERATED
 * @param limb [IN] Positive integer.
 * @param asn [OUT] Encoding result.
 * @retval  BSL_SUCCESS, success.
 *          Other error codes see the bsl_errno.h.
 */
int32_t BSL_ASN1_EncodeLimb(uint8_t tag, uint64_t limb, BSL_ASN1_Buffer *asn);

/**
 * @ingroup bsl_asn1
 * @brief Calculate the total encoding length for a ASN.1 type through the content length.
 *
 * @param contentLen [IN] The length of the content to be encoded.
 * @param encodeLen [OUT] The total number of bytes needed for DER encoding.
 * @retval  BSL_SUCCESS, success.
 *          Other error codes see the bsl_errno.h.
 */
int32_t BSL_ASN1_GetEncodeLen(uint32_t contentLen, uint32_t *encodeLen);

#ifdef __cplusplus
}
#endif

#endif // BSL_ASN1_H
