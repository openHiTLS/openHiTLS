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

#ifndef BSL_USER_DATA_H
#define BSL_USER_DATA_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Modify the BSL_MAX_EX_TYPE if a new index is added */
#define BSL_USER_DATA_EX_INDEX_SSL              0
#define BSL_USER_DATA_EX_INDEX_SSL_CTX          1
#define BSL_USER_DATA_EX_INDEX_SESSION          2
#define BSL_USER_DATA_EX_INDEX_X509_STORE       3
#define BSL_USER_DATA_EX_INDEX_X509_STORE_CTX   4
#define BSL_USER_DATA_EX_INDEX_UIO              5


#define BSL_MAX_EX_TYPE 6
#define BSL_MAX_EX_DATA 20

typedef struct {
    void *sk[BSL_MAX_EX_DATA];
} BSL_USER_ExData;

/**
 * @ingroup bsl_user_data
 * @brief Function pointer type for creating new extended data.
 * @attention
 * Thread safe     : Thread-safe function.
 * Blocking risk   : No blocking.
 * Time consuming  : Not time-consuming.
 *
 * @param parent [IN] Pointer to the parent object.
 * @param ptr [IN] Pointer to the object for which the extended data is being created.
 * @param ad [OUT] Pointer to the BSL_USER_ExData structure to be initialized.
 * @param idx [IN] Index of the extended data.
 * @param argl [IN] Additional long argument.
 * @param argp [IN] Additional pointer argument.
 */
typedef void BSL_USER_ExDataNew(void *parent, void *ptr, BSL_USER_ExData *ad, int idx, long argl, void *argp);

/**
 * @ingroup bsl_user_data
 * @brief Function pointer type for freeing extended data.
 * @attention
 * Thread safe     : Thread-safe function.
 * Blocking risk   : No blocking.
 * Time consuming  : Not time-consuming.
 *
 * @param parent [IN] Pointer to the parent object.
 * @param ptr [IN] Pointer to the object for which the extended data is being freed.
 * @param ad [IN] Pointer to the BSL_USER_ExData structure to be freed.
 * @param idx [IN] Index of the extended data.
 * @param argl [IN] Additional long argument.
 * @param argp [IN] Additional pointer argument.
 */
typedef void BSL_USER_ExDataFree(void *parent, void *ptr, BSL_USER_ExData *ad, int idx, long argl, void *argp);

/**
 * @ingroup bsl_user_data
 * @brief Function pointer type for duplicating extended data.
 * @attention
 * Thread safe     : Thread-safe function.
 * Blocking risk   : No blocking.
 * Time consuming  : Not time-consuming.
 *
 * @param to [OUT] Pointer to the BSL_USER_ExData structure where the data will be duplicated.
 * @param from [IN] Pointer to the BSL_USER_ExData structure from which the data is being duplicated.
 * @param fromD [IN] Pointer to the data being duplicated.
 * @param idx [IN] Index of the extended data.
 * @param argl [IN] Additional long argument.
 * @param argp [IN] Additional pointer argument.
 * @return BSL_SUCCESS, success.
 * @return Otherwise, failure.
 */
typedef int BSL_USER_ExDataDup(BSL_USER_ExData *to, const BSL_USER_ExData *from, void **fromD, int idx, long argl,
    void *argp);
/**
 * @ingroup bsl_user_data
 * @brief Set extended data in the user context.
 * @attention
 * Thread safe     : Thread-safe function.
 * Blocking risk   : No blocking.
 * Time consuming  : Not time-consuming.
 *
 * @param ad [IN] Pointer to the user extended data structure.
 * @param idx [IN] Index of the extended data field to set. Must be in the range [0, BSL_MAX_EX_DATA - 1].
 * @param val [IN] Pointer to the value to be set in the extended data field.
 *
 * @retval BSL_SUCCESS, if the operation is successful.
 * @retval BSL_NULL_INPUT, if the input parameters are invalid (ad is NULL, or idx is out of range).
 */
int BSL_USER_SetExData(BSL_USER_ExData *ad, int32_t idx, void *val);

/**
 * @ingroup bsl_user_data
 * @brief Get extended data from the user context.
 * @attention
 * Thread safe     : Thread-safe function.
 * Blocking risk   : No blocking.
 * Time consuming  : Not time-consuming.
 *
 * @param ad [IN] Pointer to the user extended data structure.
 * @param idx [IN] Index of the extended data field to set. Must be in the range [0, BSL_MAX_EX_DATA - 1].
 *
 * @return Pointer to the value of the extended data field.
 * @return NULL if the input parameters are invalid (ad is NULL, or idx is out of range).
 */
void *BSL_USER_GetExData(const BSL_USER_ExData *ad, int32_t idx);

/**
 * @ingroup bsl_user_data
 * @brief Get a new index for extended data in the user context.
 * @attention
 * Thread safe     : Thread-safe function.
 * Blocking risk   : No blocking.
 * Time consuming  : Not time-consuming.
 *
 * @param classIndex [IN] The type of extended data for which a new index is needed.
 * @param argl [IN] Length of the argument (not used in this function).
 * @param argp [IN] Pointer to the argument (not used in this function).
 * @param newFunc [IN] Pointer to the new function (not used in this function).
 * @param dupFunc [IN] Pointer to the duplicate function (not used in this function).
 * @param freeFunc [IN] Pointer to the free function, which will be used to free the extended data.
 *
 * @return int - The new index for the extended data.
 * @retval -1 if the input parameters are invalid or the maximum number of indices is reached.
 */
int BSL_USER_GetExDataNewIndex(int32_t classIndex, int64_t argl, void *argp, void *newFunc, void *dupFunc,
    void *freeFunc);

/**
 * @ingroup bsl_user_data
 * @brief   Create new user data for the specified class index.
 * @param   classIndex [IN] Class index for the user data
 * @param   obj [IN] Pointer to the object for which the user data is being created
 * @param   ad [OUT] Pointer to the user data structure to be initialized
 * @retval  BSL_SUCCESS on success, or an error code on failure.
 */

int BSL_USER_NewExData(int32_t classIndex, void *obj, BSL_USER_ExData *ad);

/**
 * @ingroup bsl_user_data
 * @brief   Allocate user data for the specified class index and index.
 * @param   classIndex [IN] Class index for the user data
 * @param   obj [IN] Pointer to the object for which the user data is being allocated
 * @param   ad [OUT] Pointer to the user data structure to be initialized
 * @param   index [IN] Index of the user data to be allocated
 * @retval  BSL_SUCCESS on success, or an error code on failure.
 */
int BSL_USER_AllocExData(int32_t classIndex, void *obj, BSL_USER_ExData *ad, int index);

/**
 * @ingroup bsl_user_data
 * @brief   Free user data for the specified class index and object.
 * @param   classIndex [IN] Class index for the user data
 * @param   obj [IN] Pointer to the object for which the user data is being freed
 * @param   ad [OUT] Pointer to the user data structure to be freed
 */
void BSL_USER_FreeExData(int32_t classIndex, void *obj, BSL_USER_ExData *ad);

/**
 * @ingroup bsl_user_data
 * @brief   Free user data callback for the specified class index and index.
 * @param   classIndex [IN] Class index for the user data
 * @param   idx [IN] Index of the user data to be freed
 * @retval  BSL_SUCCESS on success, or an error code on failure.
 */
int BSL_USER_FreeExIndex(int32_t classIndex, int idx);

#ifdef __cplusplus
}
#endif

#endif // BSL_USER_DATA_H
