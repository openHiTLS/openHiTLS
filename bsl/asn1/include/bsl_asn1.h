/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef BSL_ASN1_H
#define BSL_ASN1_H

#include <stdint.h>
#include <stdlib.h>
#include "bsl_list.h"

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

/* Custom types, use private class to prevent conflicts */
#define BSL_ASN1_TAG_CHOICE (BSL_ASN1_CLASS_PRIVATE | 1)
#define BSL_ASN1_TAG_ANY (BSL_ASN1_CLASS_PRIVATE | 2)

/* The current value is flags, is used to guide asn1 encoding or decoding */
#define BSL_ASN1_FLAG_OPTIONAL 1
/* The current value is deflaut, is used to guide asn1 encoding or decoding */
#define BSL_ASN1_FLAG_DEFAULT  2
/* Only parsing or encoding headers, and child nodes are not traversed */
#define BSL_ASN1_FLAG_HEADERONLY 4
/* The implied values are of the same type */
#define BSL_ASN1_FLAG_SAME 8

#define BSL_ASN1_MAX_TEMPLATE_DEPTH 6

#define BSL_ASN1_List BslList

typedef enum {
    BSL_ASN1_TYPE_GET_ANY_TAG = 0,
    BSL_ASN1_TYPE_CHECK_CHOICE_TAG = 1
} BSL_ASN1_CALLBACK_TYPE;

typedef struct _BSL_ASN1_TemplateItem {
    /* exptect tag */
    uint8_t tag;
    /* corresponding to the tag flag */
    uint8_t flags:5;
    uint8_t depth:3;
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


typedef int32_t(*BSL_ASN1_DecTemplCallBack) (int32_t type, int32_t idx, void *data, void *expVal);

// The layer parameter used to construct the name node will use
typedef int32_t(*BSL_ASN1_ParseListAsnItem)(uint32_t layer, BSL_ASN1_Buffer *asn, void *cbParam, BSL_ASN1_List *list);

typedef struct _BSL_ASN1_DecodeListParam {
    uint32_t layer;
    uint8_t *expTag;
} BSL_ASN1_DecodeListParam;

int32_t BSL_ASN1_DecodeLen(uint8_t **encode, uint32_t *encLen, uint32_t *len);
int32_t BSL_ASN1_DecodeTagLen(uint8_t tag, uint8_t **encode, uint32_t *encLen, uint32_t *valLen);

int32_t BSL_ASN1_DecodeListItem(BSL_ASN1_DecodeListParam *param, BSL_ASN1_Buffer *asn,
    BSL_ASN1_ParseListAsnItem parseListItemCb, void *cbParam, BSL_ASN1_List *list);


int32_t BSL_ASN1_DecodePrimitiveItem(BSL_ASN1_Buffer *asn, void *decodeData);
int32_t BSL_ASN1_EncodePrimitiveItem(uint8_t tag, void *decodeData, BSL_ASN1_Buffer *asn);

int32_t BSL_ASN1_DecodeTemplate(BSL_ASN1_Template *templ, BSL_ASN1_DecTemplCallBack decTemlCb,
    uint8_t **encode, uint32_t *encLen, BSL_ASN1_Buffer *asnArr, uint32_t arrNum);

int32_t BSL_ASN1_EncodeTemplate(BSL_ASN1_Template *templ, BSL_ASN1_Buffer *asnArr, int32_t arrNum,
    uint8_t **encode, uint32_t *encLen);

int32_t BSL_ASN1_DecodeItem(uint8_t **encode, uint32_t *encLen, BSL_ASN1_Buffer *asnItem);

#ifdef __cplusplus
}
#endif

#endif // BSL_ASN1_H
