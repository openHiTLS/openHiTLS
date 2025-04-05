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

#ifndef BSL_ASN1_LOCAL_H
#define BSL_ASN1_LOCAL_H

#include <stdint.h>
#include <stdlib.h>
#include "bsl_asn1.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BSL_ASN1_VAL_MAX_BIT_STRING_LEN 7
#define BSL_ASN1_MAX_LIST_NEST_EPTH 2
#define BSL_ASN1_FLAG_OPTIONAL_DEFAUL (BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_DEFAULT)

/* Gets the mask of the class */
#define BSL_ASN1_CLASS_MASK            0xC0

typedef struct _ASN1_AnyOrChoiceParam {
    uint32_t idx;
    void *previousAsnOrTag;
    BSL_ASN1_DecTemplCallBack tagCb;
} BSL_ASN1_AnyOrChoiceParam;

typedef struct _BSL_ASN1_EncodeItem {
    uint32_t asnOctetNum; // tag + len + content
    BSL_ASN1_Buffer *asn;
    uint8_t tag;
    uint8_t depth;
    uint8_t skip; // Whether to skip processing template item
    uint8_t optional;
    uint8_t lenOctetNum; // The maximum number of the length octets is 126 + 1
} BSL_ASN1_EncodeItem;

#ifdef __cplusplus
}
#endif

#endif // BSL_ASN1_LOCAL_H
