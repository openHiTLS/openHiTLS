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
#ifndef BSL_UI_H
#define BSL_UI_H

#include <stdint.h>
#include <stdbool.h>
#ifdef __cplusplus
extern "C" {
#endif

/**
  * @ingroup bsl_ui
  * @brief BSL_UI method types
  */
typedef enum {
    BSL_UIM_NONE = 0,
    BSL_UIM_OPEN,
    BSL_UIM_WRITE,
    BSL_UIM_READ,
    BSL_UIM_CLOSE
} BSL_UI_MethodTypes;

/**
  * @ingroup bsl_ui
  * @brief BSL_UI data types
  */
typedef enum {
    BSL_UI_DATA_NONE = 0,
    BSL_UI_DATA_READ,
    BSL_UI_DATA_WRITE
} BSL_UI_DataTypes;

/**
  * @ingroup bsl_ui
  * @brief BSL_UI data flags
  */
typedef enum {
    BSL_UI_DATA_FLAG_NONE = 0, // Setting the Echo Display 01, follow with 010 0100
    BSL_UI_DATA_FLAG_ECHO = 0x1,
    BSL_UI_DATA_FLAG_USER = 0x10000
} BSL_UI_DataFlags;

/**
  * @ingroup bsl_ui
  * @brief BSL_UI_Ctrl get parameters
  */
typedef struct {
    uint32_t flags;
    char *buff;
    uint32_t buffLen;
    char *verifyBuff;
} BSL_UI_CtrlRGetParam;

/**
  * @ingroup bsl_ui
  * @brief BSL_UI read pwd parameters
  */
typedef struct {
    const char *desc;
    const char *name;
    bool verify;
} BSL_UI_ReadPwdParam;

typedef struct UI_Control BSL_UI;
typedef struct UI_ControlMethod BSL_UI_Method;
typedef struct UI_ControlDataPack BSL_UI_DataPack;

/**
 * @ingroup bsl_ui
 * @brief Function pointer type for opening a UI.
 *
 * @param ui [IN] Pointer to the BSL_UI structure representing the UI.
 * @return BSL_SUCCESS, success.
 * @return Otherwise, failure.
 * @attention
 * Thread safe     : Not thread-safe function.
 * Blocking risk   : No blocking.
 * Time consuming  : Not time-consuming.
 */
typedef int32_t (*BSL_UI_Open) (BSL_UI *ui);

/**
 * @ingroup bsl_ui
 * @brief Function pointer type for writing data to a UI.
 *
 * @param ui [IN] Pointer to the BSL_UI structure representing the UI.
 * @param data [IN] Pointer to the BSL_UI_DataPack structure containing the data to be written.
 * @return Returns 0 on success, or a negative error code on failure.
 * @attention
 * Thread safe     : Not thread-safe function.
 * Blocking risk   : No blocking.
 * Time consuming  : Not time-consuming.
 */
typedef int32_t (*BSL_UI_Write) (BSL_UI *ui, BSL_UI_DataPack *data);

/**
 * @ingroup bsl_ui
 * @brief Function pointer type for reading data from a UI.
 *
 * This function is called to read data from the user interface (UI).
 *
 * @param ui [IN] Pointer to the BSL_UI structure representing the UI.
 * @param data [OUT] Pointer to the BSL_UI_DataPack structure where the read data will be stored.
 * @return BSL_SUCCESS, success.
 * @return Otherwise, failure.
 * @attention
 * Thread safe     : Not thread-safe function.
 * Blocking risk   : No blocking.
 * Time consuming  : Not time-consuming.
 */
typedef int32_t (*BSL_UI_Read) (BSL_UI *ui, BSL_UI_DataPack *data);

/**
 * @ingroup bsl_ui
 * @brief Function pointer type for closing a UI.
 *
 * @param ui [IN] Pointer to the BSL_UI structure representing the UI.
 * @return BSL_SUCCESS, success.
 * @return Otherwise, failure.
 * @attention
 * Thread safe     : Not thread-safe function.
 * Blocking risk   : No blocking.
 * Time consuming  : Not time-consuming.
 */
typedef int32_t (*BSL_UI_Close) (BSL_UI *ui);

/**
 * @ingroup bsl_ui
 * @brief Function pointer type for a data check callback.
 *
 * @param ui [IN] Pointer to the BSL_UI structure representing the UI.
 * @param buff [IN] Pointer to the buffer containing the data to be checked.
 * @param buffLen [IN] Length of the data buffer.
 * @param callBackData [IN] Pointer to user-defined data passed to the callback.
 * @return Returns 0 if the data is valid, or a negative error code if the data is invalid.
 * @attention
 * Thread safe     : Thread-safe function.
 * Blocking risk   : No blocking.
 * Time consuming  : Not time-consuming.
 */
typedef int32_t (*BSL_UI_CheckDataCallBack) (BSL_UI *ui, char *buff, uint32_t buffLen, void *callBackData);

/**
  * @ingroup bsl_ui
  * @brief The method function is NULL. UI of common default processing functions.
  *        Otherwise, use user-defined functions to create UIs.
  * @attention
  * Thread safe     : Thread-safe function.
  * Blocking risk   : No blocking.
  * Time consuming  : Not time-consuming.
  *
  * @param method [IN] UI function
  *
  * @return If success, BSL_SUCCESS is returned.
  *         If fails, NULL is returned.
  */
BSL_UI *BSL_UI_New(const BSL_UI_Method *method);

/**
  * @ingroup bsl_ui
  * @brief Release the UI
  * @attention
  * Thread safe     : Not thread-safe function.
  * Blocking risk   : No blocking.
  * Time consuming  : Not time-consuming.
  *
  * @param ui [IN] UI object
  *
  * @return   None
  */
void BSL_UI_Free(BSL_UI *ui);

/**
  * @ingroup bsl_ui
  * @brief Create a BSL_UI_Method
  * @attention
  * Thread safe     : Not thread-safe function.
  * Blocking risk   : No blocking.
  * Time consuming  : Not time-consuming.
  *
  * @return  If success, the BSL_UI_Method object is returned;
  *          If fails, NULL is returned.
  */
BSL_UI_Method *BSL_UI_MethodNew(void);

/**
  * @ingroup bsl_ui
  * @brief Release the BSL_UI_Method
  * @attention
  * Thread safe     : Not thread-safe function.
  * Blocking risk   : No blocking.
  * Time consuming  : Not time-consuming.
  *
  * @param method [IN] BSL_UI_Method Object
  *
  * @return  None
  */
void BSL_UI_MethodFree(BSL_UI_Method *method);

/**
  * @ingroup bsl_ui
  * @brief If the ui parameter is NULL, obtain the default UI processing function.
  *        Otherwise, obtain the UI processing function.
  * @attention
  * Thread safe     : Not thread-safe function.
  * Blocking risk   : No blocking.
  * Time consuming  : Not time-consuming.
  *
  * @param ui [IN] UI object
  *
  * @return  If success, the BSL_UI_Method object is returned;
  *          If fails, NULL is returned.
  */
const BSL_UI_Method *BSL_UI_GetOperMethod(const BSL_UI *ui);

/**
  * @ingroup bsl_ui
  * @brief Set the BSL UI method.
  * @attention
  * Thread safe     : Not thread-safe function.
  * Blocking risk   : No blocking.
  * Time consuming  : Not time-consuming.
  *
  * @param method [IN] BSL_UI_Method Object
  * @param type [IN] Method type. For details, see BSL_UI_MethodTypes.
  * @param func [IN] Method to be set. For details, see the callback prototype.
  *
  * @return If success, the BSL_SUCCESS is returned.
  *         If fail, other values are returned.
  */
int32_t BSL_UI_SetMethod(BSL_UI_Method *method, uint8_t type, void *func);

/**
  * @ingroup bsl_ui
  * @brief Obtain the BSL UI method.
  * @attention
  * Thread safe     : Not thread-safe function.
  * Blocking risk   : No blocking.
  * Time consuming  : Not time-consuming.
  *
  * @param method [IN] BSL_UI_Method Object
  * @param type [IN] Method type. For details, see BSL_UI_MethodTypes.
  * @param func [OUT] Pointer to the obtained method function.
  *
  * @return If success, the BSL_SUCCESS is returned.
  *         If fail, other values are returned.
  */
int32_t BSL_UI_GetMethod(const BSL_UI_Method *method, uint8_t type, void **func);

/**
  * @ingroup bsl_ui
  * @brief Read the pwd tool function of the user input
  * @attention
  * Thread safe     : Not thread-safe function.
  * Blocking risk   : No blocking.
  * Time consuming  : Not time-consuming.
  *
  * @param param [IN] The user need input parameter marked as "BSL_UI_ReadPwdParam" that required by pwd tool function.
                      desc: indicates the string description, name: indicates the string object name, and verify
                      indicates whether the verification is required.
  * @param buff [OUT] Indicates the obtained PWD buff.
  * @param buffLen [IN/OUT] Indicates the obtained PWD buff length.
  * @param checkDataCallBack [IN] BSL_UI_CheckDataCallBack checks the input string callback, the value NULL
  * indicates that the check is not required.
  * @param callBackData [IN] BSL_UI_CheckDataCallBack, check the user data of the input string callback.
  *
  * @return  If success, the BSL_SUCCESS is returned.
  *          If fail, other values are returned.
  */
int32_t BSL_UI_ReadPwdUtil(BSL_UI_ReadPwdParam *param, char *buff, uint32_t *buffLen,
    const BSL_UI_CheckDataCallBack checkDataCallBack, void *callBackData);

/**
  * @ingroup bsl_ui
  * @brief Create a DataPack object
  * @attention
  * Thread safe     : Thread-safe function.
  * Blocking risk   : No blocking.
  * Time consuming  : Not time-consuming.
  *
  * @return  If success, the BSL_UI_DataPack object is returned.
  *          If fail, other values are returned.
  */
BSL_UI_DataPack *BSL_UI_DataPackNew(void);

/**
  * @ingroup bsl_ui
  * @brief Release the BSL_UI_DataPack
  * @attention
  * Thread safe     : Not thread-safe function.
  * Blocking risk   : No blocking.
  * Time consuming  : Not time-consuming.
  *
  * @param data [IN] BSL_UI_DataPack Object
  *
  * @return  None
  */
void BSL_UI_DataPackFree(BSL_UI_DataPack *data);

/**
  * @ingroup bsl_ui
  * @brief Set the BSL_UI_DataPack data by type
  * @attention
  * Thread safe     : Not thread-safe function.
  * Blocking risk   : No blocking.
  * Time consuming  : Not time-consuming.
  *
  * @param data [IN] BSL_UI_DataPack Object
  * @param type [IN] Type of the control command.
  * @param parg [IN] Pointer to additional command arguments.
  * @param larg [IN] Large parameter for the command.
  *
  * @return  If success, BSL_SUCCESS is returned.
  *          Else, other values are returned.
  */
int32_t BSL_UI_DataCtrl(BSL_UI_DataPack *data, uint32_t type, void *parg, uint32_t larg);

/**
  * @ingroup bsl_ui
  * @brief Obtaining user data result
  * @attention
  * Thread safe     : Not thread-safe function.
  * Blocking risk   : No blocking.
  * Time consuming  : Not time-consuming.
  *
  * @param data [IN] Data object to be obtained.
  * @param result [OUT] User data result.
  * @param result_len [OUT] User data result length.
  *
  * @return  If success, BSL_SUCCESS is returned.
  *          Else, other values are returned.
  */
int32_t BSL_UI_GetDataResult(BSL_UI_DataPack *data, char **result, uint32_t *resultLen);

/**
  * @ingroup bsl_ui
  * @brief Construct a prompt message
  * @attention
  * Thread safe     : Not thread-safe function.
  * Blocking risk   : No blocking.
  * Time consuming  : Not time-consuming.
  *
  * @param objectDesc [IN] Object description in the prompt message.
  * @param objectName [IN] Object name in the prompt message.
  *
  * @return  If success, constructed prompt string is returned.
  *          Else, NULL is returned.
  */
char *BSL_UI_ConstructPrompt(const char *objectDesc, const char *objectName);

#ifdef __cplusplus
}
#endif

#endif