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
    BSL_PARAM_TYPE_FUNC_PTR,
    BSL_PARAM_TYPE_CTX_PTR,
    BSL_PARAM_TYPE_UINT8,
    BSL_PARAM_TYPE_UINT16,
    BSL_PARAM_TYPE_UINT32,
    BSL_PARAM_TYPE_BOOL,
    BSL_PARAM_TYPE_INT32,
    BSL_PARAM_TYPE_OCTETS,
    BSL_PARAM_TYPE_UTF8_STR,
    BSL_PARAM_TYPE_SIZE_T,
    BSL_PARAM_TYPE_SIZE_T_PTR,
    BSL_PARAM_TYPE_UINT64,
} BSL_PARAM_VALUE_TYPE;

typedef struct BslParam {
    int32_t key;
    uint32_t valueType;
    void *value;
    uint32_t valueLen;
    uint32_t useLen;
} BSL_Param;

typedef struct BslParamMaker BSL_ParamMaker;

/**
 * @brief Initialize a BSL parameter structure
 * @details Initializes a single BSL_Param structure by setting its key, type, value, and length
 *
 * @param param [IN] Pointer to the BSL_Param structure to be initialized
 * @param key [IN] Parameter key value, refer to crypt_params_key.h
 * @param type [IN] Parameter value type, refer to BSL_PARAM_VALUE_TYPE enum
 * @param val [IN] Pointer to the parameter value
 * @param valueLen [IN] Length of the parameter value
 *
 * @return int32_t Returns the operation result
 *         - BSL_SUCCESS indicates successful initialization
 *         - Other values indicate initialization failure
 */
int32_t BSL_PARAM_InitValue(BSL_Param *param, int32_t key, uint32_t type, void *val, uint32_t valueLen);

/**
 * @brief Set BSL parameter value
 * @details Updates the value in an existing BSL_Param structure
 *
 * @param param [IN] Pointer to the BSL_Param structure
 * @param key [IN] Parameter key value, refer to crypt_params_key.h
 * @param type [IN] Parameter value type, refer to BSL_PARAM_VALUE_TYPE enum
 * @param val [IN] Pointer to the new parameter value
 * @param len [IN] Length of the new parameter value
 *
 * @return int32_t Returns the operation result
 *         - BSL_SUCCESS indicates successful setting
 *         - Other values indicate setting failure
 */
int32_t BSL_PARAM_SetValue(BSL_Param *param, int32_t key, uint32_t type, void *val, uint32_t len);

/**
 * @brief Get pointer to BSL parameter value
 * @details Retrieves a pointer to the parameter value for the specified key without copying data
 *
 * @param param [IN] Pointer to the BSL_Param structure
 * @param key [IN] Parameter key value, refer to crypt_params_key.h
 * @param type [IN] Parameter value type, refer to BSL_PARAM_VALUE_TYPE enum
 * @param val [OUT] Pointer to store the parameter value pointer
 * @param valueLen [OUT] Pointer to store the parameter value length
 *
 * @return int32_t Returns the operation result
 *         - BSL_SUCCESS indicates successful retrieval
 *         - Other values indicate retrieval failure
 */
int32_t BSL_PARAM_GetPtrValue(const BSL_Param *param, int32_t key, uint32_t type, void **val, uint32_t *valueLen);

/**
 * @brief Get BSL parameter value
 * @details Retrieves the parameter value for the specified key by copying data to the provided buffer
 *
 * @param param [IN] Pointer to the BSL_Param structure
 * @param key [IN] Parameter key value, refer to crypt_params_key.h
 * @param type [IN] Parameter value type, refer to BSL_PARAM_VALUE_TYPE enum
 * @param val [OUT] Buffer pointer to store the parameter value
 * @param valueLen [OUT] Pointer to store the parameter value length
 *
 * @return int32_t Returns the operation result
 *         - BSL_SUCCESS indicates successful retrieval
 *         - Other values indicate retrieval failure
 */
int32_t BSL_PARAM_GetValue(const BSL_Param *param, int32_t key, uint32_t type, void *val, uint32_t *valueLen);

/**
 * @brief Find BSL parameter by key
 * @details Searches for a parameter with the specified key in the parameter array
 *
 * @param param [IN] Pointer to the BSL_Param structure array
 * @param key [IN] Parameter key value to search for
 *
 * @return const BSL_Param* Returns pointer to the found parameter
 *         - Non-NULL indicates the parameter was found
 *         - NULL indicates the parameter was not found
 */
const BSL_Param *BSL_PARAM_FindConstParam(const BSL_Param *param, int32_t key);

/**
 * @brief Find BSL parameter by key
 * @details Searches for a parameter with the specified key in the parameter array
 *
 * @param param [IN] Pointer to the BSL_Param structure array
 * @param key [IN] Parameter key value to search for
 *
 * @return BSL_Param* Returns pointer to the found parameter
 *         - Non-NULL indicates the parameter was found
 *         - NULL indicates the parameter was not found
 */
BSL_Param *BSL_PARAM_FindParam(BSL_Param *param, int32_t key);

/**
 * @brief Free BSL parameter
 *
 * @param param [IN] Pointer to the BSL_Param structure array
 */
void BSL_PARAM_Free(BSL_Param *param);

/**
 * @brief Create a BSL parameter maker
 *
 * @return BSL_ParamMaker* Returns pointer to the parameter maker
 */
BSL_ParamMaker *BSL_PARAM_MAKER_New(void);

/**
 * @brief Push value to BSL parameter maker
 *
 * @param maker [IN] Pointer to the BSL_ParamMaker structure
 * @param key [IN] Parameter key value, refer to crypt_params_key.h
 * @param type [IN] Parameter value type, refer to BSL_PARAM_VALUE_TYPE enum
 * @param value [IN] Pointer to the new parameter value
 * @param len [IN] Length of the new parameter value
 *
 * @return int32_t Returns the operation result
 *         - BSL_SUCCESS indicates successful setting
 *         - Other values indicate setting failure
 */
int32_t BSL_PARAM_MAKER_PushValue(BSL_ParamMaker *maker, int32_t key, uint32_t type, void *value, uint32_t len);

/**
 * @brief Push value to BSL parameter maker
 *
 * @param maker [IN] Pointer to the BSL_ParamMaker structure
 * @param key [IN] Parameter key value, refer to crypt_params_key.h
 * @param type [IN] Parameter value type, refer to BSL_PARAM_VALUE_TYPE enum
 * @param value [IN] Pointer to the new parameter value
 * @param len [IN] Length of the new parameter value
 *
 * @return int32_t Returns the operation result
 *         - BSL_SUCCESS indicates successful setting
 *         - Other values indicate setting failure
 * @note The value will be depth copy.
 */
int32_t BSL_PARAM_MAKER_DeepPushValue(BSL_ParamMaker *maker, int32_t key, uint32_t type, void *value,
    uint32_t len);

/**
 * @brief BSL parameter maker to BSL parameter
 *
 * @param param [IN] Pointer to the BSL_Param structure array
 *
 * @return BSL_ParamMaker* Returns pointer to the parameter maker
 */
BSL_Param *BSL_PARAM_MAKER_ToParam(BSL_ParamMaker *maker);

/**
 * @brief Free BSL parameter maker
 *
 * @param param [IN] Pointer to the BSL_Param structure array
 */
void BSL_PARAM_MAKER_Free(BSL_ParamMaker *maker);

#ifdef __cplusplus
}
#endif

#endif
