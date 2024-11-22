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
 * @defgroup bsl_param
 * @ingroup bsl
 * @brief bsl param
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

typedef struct {
    int32_t key;
    uint32_t valueType;
    void *value;
    uint32_t valueLen;
    uint32_t useLen;
} BSL_Param;

/**
 * @ingroup bsl_param
 * initialize params
 *
 * @param param [IN] bsl param
 * @param key [IN] the key value of BSL_Param can refer to crypt_params_type.h
 * @param type [IN] the key valueType of BSL_Param can refer to BSL_PARAM_VALUE_TYPE
 * @param val [IN] the value of BSL_Param
 * @param len [IN] the value Len of BSL_Param
 * 
 *
 * @retval The error code.
 * @retval #BSL_SUCCESS If successful.
 */
int32_t BSL_PARAM_InitValue(BSL_Param *param, int32_t key, uint32_t type, void *val, uint32_t len);

/**
 * @ingroup bsl_param
 * set params
 *
 * @param param [IN] bsl param
 * @param key [IN] the key value of BSL_Param can refer to crypt_params_type.h
 * @param type [IN] the key valueType of BSL_Param can refer to BSL_PARAM_VALUE_TYPE
 * @param val [IN] the value of BSL_Param
 * @param len [IN] the value Len of BSL_Param
 *
 * @retval The error code.
 * @retval #BSL_SUCCESS If successful.
 */
int32_t BSL_PARAM_SetValue(BSL_Param *param, int32_t key, uint32_t type, void *val, uint32_t len);

/**
 * @ingroup bsl_param
 * get the pointer to val in param
 *
 * @param param [IN] bsl param
 * @param key [IN] the key value of BSL_Param can refer to crypt_params_type.h
 * @param type [IN] the key valueType of BSL_Param can refer to BSL_PARAM_VALUE_TYPE
 * @param val [OUT] return the value of BSL_Param
 * @param len [OUT] return the value Len of BSL_Param
 *
 * @retval The error code.
 * @retval #BSL_SUCCESS If successful.
 */
int32_t BSL_PARAM_GetPtrValue(const BSL_Param *param, int32_t key, uint32_t type, void **val, uint32_t *len);

/**
 * @ingroup bsl_param
 * get the val in param
 *
 * @param param [IN] bsl param
 * @param key [IN] the key value of BSL_Param can refer to crypt_params_type.h
 * @param type [IN] the key valueType of BSL_Param can refer to BSL_PARAM_VALUE_TYPE
 * @param val [OUT] return the value of BSL_Param
 * @param len [OUT] return the value Len of BSL_Param
 *
 * @retval The error code.
 * @retval #BSL_SUCCESS If successful.
 */
int32_t BSL_PARAM_GetValue(const BSL_Param *param, int32_t key, uint32_t type, void *val, uint32_t *len);

/**
 * @ingroup bsl_param
 * return matching params
 *
 * @param param [IN] bsl param
 * @param key [IN] the key value of BSL_Param can refer to crypt_params_type.h
 *
 * @retval The error code.
 * @retval #BSL_SUCCESS If successful.
 */
const BSL_Param *BSL_PARAM_FindParam(const BSL_Param *param, int32_t key);

#ifdef __cplusplus
}
#endif

#endif
