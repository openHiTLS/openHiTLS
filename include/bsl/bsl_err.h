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
 * @defgroup bsl
 * @brief Base Support Layer
 */

/**
 * @defgroup bsl_err
 * @ingroup bsl
 * @brief error module
 */

#ifndef BSL_ERR_H
#define BSL_ERR_H

#include <stdint.h>
#include <stdbool.h>
#include "bsl_errno.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup bsl_err
 * @brief Start value of the customized level-1 error module.
 *
 * Start value of the customized level-1 error module. The value 0x80 is 128.
 */
#define BSL_ERR_NEW_MODULE 0x80

typedef enum {
    BSL_ERR_LIB_CRYPTO = 1,
    BSL_ERR_LIB_TLS = 2,
    BSL_ERR_LIB_BSL = 3,
    BSL_ERR_LIB_PKI = 4,
    BSL_ERR_LIB_AUTH = 5,
} BSL_ERR_LIB;

#define BSL_ERR_GET_LIB(err) ((err) >> 24)

/**
 * @ingroup bsl_err
 * @brief Initialize Error code module.
 *
 * The user must call this interface to initialize.
 *
 * @attention NONE
 * @retval #BSL_SUCCESS, error code module is successfully initialized.
 * @retval #BSL_MALLOC_FAIL, memory space is insufficient and thread lock space cannot be applied for.
 * @retval #BSL_SAL_ERR_UNKNOWN, thread lock initialization failed.
 */
int32_t BSL_ERR_Init(void);

/**
 * @ingroup bsl_err
 * @brief Error code module deinitialization.
 *
 * Called by the user when the process exits.
 *
 * @attention none
 */
void BSL_ERR_DeInit(void);

/**
 * @ingroup bsl_err
 * @brief Delete the error stack
 *
 * Delete the error stack, which is called when a process or thread exits.
 *
 * @attention This function must be called when the thread exits. Otherwise, memory leakage occurs.
 * @param isRemoveAll [IN] Indicates whether to delete all error stacks.
 *                         The value is true when a process exits and false when a thread exits.
 */
void BSL_ERR_RemoveErrorStack(bool isRemoveAll);

/**
 * @ingroup bsl_err
 * @brief Obtains the error code of the last push in the error stack.
 *
 * This API is called when an error occurs on a HiTLS interface to obtain the error code.
 * The interface can be called continuously. The error code returned each time forms
 * the error stack of the interface until BSL_SUCCESS is returned.
 *
 * @attention None.
 * @retval Error code. The most significant 16 bits indicate the ID of the module where the error occurs,
 *                     and the least significant 16 bits indicate the cause number.
 */
int32_t BSL_ERR_GetLastError(void);

/**
 * @ingroup bsl_err
 * @brief Obtains the error code of the last push in the error stack.
 *
 * This API is called when an error occurs on a HiTLS interface to obtain the error code.
 * The interface can be called continuously. The error code returned each time forms
 * the error stack of the interface until BSL_SUCCESS is returned.
 *
 * @attention
 * Thread safe     : Thread-safe function.
 * @retval Error code. The most significant 16 bits indicate the ID of the module where the error occurs,
 *                     and the least significant 16 bits indicate the cause number.
 */
int32_t BSL_ERR_PeekLastError(void);

/**
 * @ingroup bsl_err
 * @brief Obtain the earliest push error code in the error stack.
 *
 * This API is called when an error occurs on a HiTLS API to obtain the error code.
 * The API can be called all the time.
 * The error code returned each time forms the error stack of the interface until BSL_SUCCESS is returned.
 *
 * @attention
 * Thread safe     : Thread-safe function.
 * @retval Error code. The most significant 16 bits indicate the ID of the module where the error occurs,
 *                     and the least significant 16 bits indicate the cause number.
 */
int32_t BSL_ERR_PeekError(void);

/**
 * @ingroup bsl_err
 * @brief Obtains the error code, file name, and line number of the last push message in the error stack.
 *
 * When an error occurs in a HiTLS interface, the user obtains an error code, file name, and line
 * number. The obtained information is deleted from the error stack.
 * The interface can be called continuously. The error code returned each time forms the error stack of
 * the interface until BSL_SUCCESS is returned.
 *
 * @attention If either of the two parameters is null, the file name and line number cannot be obtained
 * @param file [OUT] Obtains the name of the file where the error occurs, excluding the directory path
 * @param lineNo [OUT] Obtain the line number of the file where the error occurs
 * @retval Error code. The most significant 16 bits indicate the ID of the module where the error occurs,
 *                     and the least significant 16 bits indicate the cause number.
 */
int32_t BSL_ERR_GetLastErrorFileLine(const char **file, uint32_t *lineNo);

/**
 * @ingroup bsl_err
 * @brief Obtain the error code, file name, and line number of the last push message in the error stack.
 *
 * When an error occurs on a HiTLS interface, the user obtains an error code, file name, and line number.
 * The obtained information is not deleted from the error stack.
 *
 * @attention If either of the two parameters is null, the file name and line number cannot be obtained.
 * @param file [OUT] Obtains the name of the file where the error occurs, excluding the directory path.
 * @param lineNo [OUT] Obtain the line number of the file where the error occurs.
 * @retval Error code. The most significant 16 bits indicate the ID of the module where the error occurs,
 *                     and the least significant 16 bits indicate the cause number.
 */
int32_t BSL_ERR_PeekLastErrorFileLine(const char **file, uint32_t *lineNo);

/**
 * @ingroup bsl_err
 * @brief Obtain the earliest push error code in the error stack.
 *
 * This API is called when an error occurs on a HiTLS API to obtain the error code.
 * The API can be called all the time.
 * The error code returned each time forms the error stack of the interface until BSL_SUCCESS is returned.
 *
 * @attention None.
 * @retval Error code. The most significant 16 bits indicate the ID of the module where the error occurs,
 *                     and the least significant 16 bits indicate the cause number.
 */
int32_t BSL_ERR_GetError(void);

/**
 * @ingroup bsl_err
 * @brief Obtain the error code, file name, and line number of the earliest push message in the error stack.
 *
 * The user calls this API after an error occurs on a HiTLS API to obtain an error code,
 * file name, and line number. The obtained information will be deleted from the error stack.
 * This API can be called continuously. The returned error code forms the error stack of the
 * API until BSL_SUCCESS is returned.
 *
 * @attention If either of the two parameters is null, the file name and line number cannot be obtained.
 * @param file [OUT] Obtains the name of the file where the error occurs, excluding the directory path.
 * @param lineNo [OUT] Obtain the line number of the file where the error occurs.
 * @retval Error code. The most significant 16 bits indicate the ID of the module where the error occurs,
 *                     and the least significant 16 bits indicate the cause number.
 */
int32_t BSL_ERR_GetErrorFileLine(const char **file, uint32_t *lineNo);

/**
 * @ingroup bsl_err
 * @brief Obtain the error code, file name, and line number of the earliest push message in the error stack.
 *
 * When an error occurs on a HiTLS interface, the user obtains an error code, file name, and line number.
 * The obtained information is not deleted from the error stack.
 *
 * @attention If either of the two parameters is null, the file name and line number cannot be obtained.
 * @param file [OUT] Obtains the name of the file where the error occurs, excluding the directory path.
 * @param lineNo [OUT] Obtain the line number of the file where the error occurs.
 * @retval Error code. The most significant 16 bits indicate the ID of the module where the error occurs,
 *                     and the least significant 16 bits indicate the cause number.
 */
int32_t BSL_ERR_PeekErrorFileLine(const char **file, uint32_t *lineNo);

/**
 * @ingroup bsl_err
 * @brief Clear the error stack.
 *
 * If an error is detected after the HiTLS API is called, if the error information is ignored,
 * call this API to clear the error information before calling the HiTLS API again.
 *
 * @attention None
 */
void BSL_ERR_ClearError(void);

/**
 * @ingroup bsl_err
 * @brief Add error description.
 */
typedef struct {
    int32_t error; /**< Error code */
    const char *string; /**< Description string corresponding to an error code. */
} BSL_ERR_Desc;

/**
 * @ingroup bsl_err
 * @brief Add an error description string to an error code.
 *
 * The error description string is added to the error code.
 * The error description can be extended to the user side.
 *
 * @attention This function is thread-safe. It stores only string pointers and does not perform deep
 * copy. The same error can be added multiple times and overwrites the previously added error.
 * @param descList [IN] BSL_ERR_Desc array
 * @param num [IN] Length of descList
 * @retval #BSL_SUCCESS.
 * @retval For details, see bsl_errno.h
 */
int32_t BSL_ERR_AddErrStringBatch(const BSL_ERR_Desc *descList, uint32_t num);

/**
 * @ingroup bsl_err
 * @brief Delete the error description
 *
 * The error description is deleted.
 * If BSL_ERR_AddErrStringBatch is called, you need to use this API to release the memory.
 *
 * @attention This API must be called when a process exits.
 *            Otherwise, memory leakage occurs. Called before releasing the lock.
 */
void BSL_ERR_RemoveErrStringBatch(void);

/**
 * @ingroup bsl_err
 * @brief Obtain the error description string based on the error code.
 *
 * Obtain the corresponding error description string based on the error code.
 *
 * @attention None
 * @param error [IN] Error code
 * @retval Error description
 */
const char *BSL_ERR_GetString(int32_t error);

/**
 * @ingroup bsl_err
 * @brief Obtain the error description string based on the error code.
 *
 * Obtain the corresponding error description string based on the error code.
 *
 * @attention
 * Thread safe     : Thread-safe function.
 * @param error [IN] Error code
 * @retval Error description
 */
int32_t BSL_ERR_GetErrAll(const char **file, uint32_t *lineNo, const char **desc);

/**
 * @ingroup bsl_err
 * @brief Set the pop-up flag at the level of the current error stack.
 *
 * Set the pop-up flag.
 *
 * @attention none
 * @retval #BSL_ERR_ERR_ACQUIRE_WRITE_LOCK_FAIL, failed to obtain the write lock.
 * @retval #BSL_ERR_ERR_NO_STACK, no error stack.
 * @retval #BSL_ERR_ERR_NO_ERROR, no error.
 * @retval #BSL_SUCCESS, the flag is set successfully.
 */
int32_t BSL_ERR_SetMark(void);

/**
 * @ingroup bsl_err
 * @brief Pop to the marked error stack level and clear the mark
 *
 * Pop up to the error stack level of the mark and clear the mark
 *
 * @attention none
 * @retval #BSL_ERR_ERR_ACQUIRE_WRITE_LOCK_FAIL, failed to obtain the write lock.
 * @retval #BSL_ERR_ERR_NO_STACK, no error stack.
 * @retval #BSL_ERR_ERR_NO_ERROR, no error.
 * @retval #BSL_ERR_ERR_NO_Mark, no mark.
 * @retval #BSL_SUCCESS, pop-up succeeded.
 */
int32_t BSL_ERR_PopToMark(void);

/**
 * @ingroup bsl_err
 * @brief Clear the latest flag in the error stack.
 *
 * Clear the latest flag in the error stack.
 *
 * @attention None.
 * @retval #BSL_ERR_ERR_ACQUIRE_WRITE_LOCK_FAIL, failed to obtain the write lock.
 * @retval #BSL_ERR_ERR_NO_STACK, no error stack.
 * @retval #BSL_SUCCESS, cleared successfully.
 */
int32_t BSL_ERR_ClearLastMark(void);

/**
 * @ingroup bsl_err
 * @brief Err output callback function type.
 *
 * Callback function type for outputting strings.
 *
 * @param str [IN] String to output, encoded in character format.
 */
typedef void (*BSL_ERR_OutputFunc)(const char *str);

/**
 * @ingroup bsl_err
 * @brief Register a err output callback function with dual protection
 *
 * @param func Callback function to register
 */
void BSL_ERR_RegErrStackLog(const BSL_ERR_OutputFunc func);

/**
 * @ingroup bsl_err
 * @brief Print all error information in the current error stack.
 *
 * Print all error information in the current error stack.
 *
 * @attention none
 */
void BSL_ERR_OutputErrorStack(void);

#ifdef __cplusplus
}
#endif

#endif // BSL_ERR_H
