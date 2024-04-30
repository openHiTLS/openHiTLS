/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

/**
 * @defgroup bsl_uio
 * @ingroup bsl
 * @brief uio module
 */

#ifndef BSL_TYPE_H
#define BSL_TYPE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    BSL_PARSE_FORMAT_UNKNOWN,
    BSL_PARSE_FORMAT_PEM,
    BSL_PARSE_FORMAT_ASN1,
    BSL_PARSE_FORMAT_PKCS12,
} BSL_ParseFormmat;

typedef struct {
    uint8_t *data;
    uint32_t dataLen;
} BSL_Buffer;


#ifdef __cplusplus
}
#endif

#endif // BSL_TYPE_H
