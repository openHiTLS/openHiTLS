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

#ifndef SAL_FILE_H
#define SAL_FILE_H

#include <stdint.h>

#ifdef HITLS_BSL_SAL_FILE

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup bsl_sal
 * @brief Reads the specified file into the buff
 *
 * Reads the specified file into the buff
 *
 * @attention None.
 * @param path [IN] specified file.
 * @param buff [OUT] return the read memory.
 * @param len [OUT] return the read memory len.
 * @retval if the operation is successful, BSL_SUCCESS is returned, for other errors, see bsl_error.h
 */
int32_t BSL_SAL_ReadFile(const char *path, uint8_t **buff, uint32_t *len);

/**
 * @ingroup bsl_sal
 * @brief Writes the buff to the specified file
 *
 * Writes the buff to the specified file
 *
 * @attention None.
 * @param path [IN] specified file.
 * @param buff [IN] the write memory.
 * @param len [IN] the write memory len.
 * @retval if the operation is successful, BSL_SUCCESS is returned, for other errors, see bsl_error.h
 */
int32_t BSL_SAL_WriteFile(const char *path, const uint8_t *buff, uint32_t len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* HITLS_BSL_SAL_FILE */

#endif // SAL_FILE_H
