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

/**
 * @defgroup bsl_uio
 * @ingroup bsl
 * @brief uio module
 */

#ifndef BSL_TYPES_H
#define BSL_TYPES_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    BSL_FORMAT_UNKNOWN,
    BSL_FORMAT_PEM,
    BSL_FORMAT_ASN1,
    BSL_FORMAT_PFX_COM,
    BSL_FORMAT_PKCS12,
} BSL_ParseFormat;

typedef struct {
    uint8_t *data;
    uint32_t dataLen;
} BSL_Buffer;

#ifdef __cplusplus
}
#endif

#endif // BSL_TYPES_H
