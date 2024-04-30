/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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
    int32_t idx;
    void *previousAsnOrTag;
    BSL_ASN1_DecTemplCallBack tagCb;
} BSL_ASN1_AnyOrChoiceParam;

#ifdef __cplusplus
}
#endif

#endif // BSL_ASN1_LOCAL_H
