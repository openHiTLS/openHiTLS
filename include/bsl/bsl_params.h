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

#ifndef BSL_PARAMS_H
#define BSL_PARAMS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BSL_PARAM_END {0, 0, NULL, 0, 0}

typedef enum {
    BSL_PARAM_TYPE_UINT32_PTR,
    BSL_PARAM_TYPE_OCTETS_PTR,
    BSL_PARAM_TYPE_UINT32,
    BSL_PARAM_TYPE_OCTETS,
} BSL_PARAM_VALUE_TYPE;

typedef struct{
    int32_t key;
    uint32_t valueType;
    void *value;
    size_t valueLen;
    size_t useLen;
} BSL_Param;


/* len-> value len */
int32_t BSL_Param_InitValue(BSL_Param *param, int32_t key, int32_t type, void *val, uint32_t len);

/* len --> useLen*/
int32_t BSL_Param_SetValue(BSL_Param *param, int32_t key, int32_t type, void *val, uint32_t len);

int32_t BSL_Param_GetPtrValue(BSL_Param *param, int32_t key, int32_t type, void **val, uint32_t *len);
int32_t BSL_Param_GetValue(BSL_Param *param, int32_t key, int32_t type, void *val, uint32_t *len);

BSL_Param *BSL_Param_FindParam(BSL_Param *param, int32_t key);

#ifdef __cplusplus
}
#endif

#endif