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
#ifndef BSL_CONF_H
#define BSL_CONF_H

#include "hitls_build.h"
#ifdef HITLS_BSL_CONF

#include "bsl_conf_def.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct BSL_CONF_Struct {
    const BSL_CONF_Method *meth;
    void *data;
} BSL_CONF;

/**
 * @ingroup bsl
 *
 * @brief Retrieves the default configuration management methods structure
 *
 * @return const BSL_CONF_Method* a pointer to the static structure containing the default methods
 *
 * @details
 * The structure includes the following default methods:
 * - `DefaultCreate`: Creates a new configuration object
 * - `DefaultDestroy`: Destroys an existing configuration object
 * - `DefaultLoad`: Loads configuration data from a file
 * - `DefaultLoadUio`: Loads configuration data from a UIO interface
 * - `DefaultDump`: Dumps configuration data to a file
 * - `DefaultDumpUio`: Dumps configuration data to a UIO interface
 * - `DefaultGetSectionNode`: Retrieves a specific section node from the configuration
 * - `DefaultGetString`: Retrieves a string value from the configuration
 * - `DefaultGetNumber`: Retrieves a numeric value from the configuration
 * - `DefaultGetSectionNames`: Retrieves the names of all sections in the configuration
 *
 */
const BSL_CONF_Method *BSL_CONF_DefaultMethod(void);

/**
 * @ingroup bsl
 *
 * @brief Create a new configuration object.
 *
 * @param meth [IN] Method structure defining the behavior of the configuration object
 *
 * @retval The configuration object is created successfully.
 * @retval NULL Failed to create the configuration.
 */
BSL_CONF *BSL_CONF_New(const BSL_CONF_Method *meth);

/**
 * @ingroup bsl
 *
 * @brief Free a configuration object.
 *
 * @param conf [IN] Configuration object to be freed
 */
void BSL_CONF_Free(BSL_CONF *conf);

/**
 * @ingroup bsl
 *
 * @brief Load configuration information from a UIO object into the configuration object.
 *
 * @param conf [IN] Configuration object
 * @param uio [IN] UIO object
 *
 * @retval BSL_SUCCESS Configuration loaded successfully.
 * @retval BSL_NULL_INPUT Invalid input parameter (if conf or uio is NULL).
 * @retval BSL_CONF_LOAD_FAIL Failed to load configuration (e.g., loadUio method is missing or fails).
 * @retval Other error code.
 */
int32_t BSL_CONF_LoadByUIO(BSL_CONF *conf, BSL_UIO *uio);

/**
 * @ingroup bsl
 *
 * @brief Load configuration information from a file into the configuration object.
 *
 * @param conf [IN] Configuration object
 * @param file [IN] Configuration file path
 *
 * @retval BSL_SUCCESS Configuration loaded successfully.
 * @retval BSL_NULL_INPUT Invalid input parameter (if conf or file is NULL).
 * @retval BSL_CONF_LOAD_FAIL Failed to load configuration (e.g., load method is missing or fails).
 * @retval Other error code.
 */
int32_t BSL_CONF_Load(BSL_CONF *conf, const char *file);

/**
 * @ingroup bsl
 *
 * @brief Get a specific section from the configuration object.
 *
 * @param conf [IN] Configuration object
 * @param section [IN] Section name to retrieve
 *
 * @retval BSL_LIST* a pointer to Section retrieved successfully.
 * @retval NULL Failed to Get Section.
 */
BslList *BSL_CONF_GetSection(const BSL_CONF *conf, const char *section);

/**
 * @ingroup bsl
 *
 * @brief Get a string value from the configuration object based on the specified section and name.
 *
 * @param conf [IN] Configuration object
 * @param section [IN] Section name in the configuration
 * @param name [IN] Name of the configuration item
 * @param str [OUT] Buffer to store the retrieved string
 * @param strLen [IN|OUT] Length of the buffer
 *
 * @retval BSL_SUCCESS String retrieved successfully.
 * @retval BSL_NULL_INPUT Invalid input parameter (if conf, section, name, str, or strLen is NULL).
 * @retval BSL_CONF_GET_FAIL Failed to retrieve the string (e.g., getString method is missing or fails).
 * @retval Other error code.
 */
int32_t BSL_CONF_GetString(const BSL_CONF *conf, const char *section, const char *name, char *str, uint32_t *strLen);

/**
 * @ingroup bsl
 *
 * @brief Get a numeric value from the configuration object based on the specified section and name.
 *
 * @param conf [IN] Configuration object
 * @param section [IN] Section name in the configuration
 * @param name [IN] Name of the configuration item
 * @param value [OUT] Pointer to store the retrieved numeric value
 *
 * @retval BSL_SUCCESS Numeric value retrieved successfully.
 * @retval BSL_NULL_INPUT Invalid input parameter (if conf, section, name, or value is NULL).
 * @retval BSL_CONF_GET_FAIL Failed to retrieve the numeric value (e.g., getNumber method is missing or fails).
 * @retval Other error code.
 */
int32_t BSL_CONF_GetNumber(const BSL_CONF *conf, const char *section, const char *name, long *value);

/**
 * @ingroup bsl
 *
 * @brief Save the configuration object's contents to a specified file.
 *
 * @param conf [IN] Configuration object
 * @param file [IN] File path to save the configuration
 *
 * @retval BSL_SUCCESS Configuration successfully saved to the file.
 * @retval BSL_NULL_INPUT Invalid input parameter (if conf or file is NULL).
 * @retval BSL_CONF_DUMP_FAIL Failed to save the configuration (e.g., dump method is missing or fails).
 * @retval Other error code.
 */
int32_t BSL_CONF_Dump(const BSL_CONF *conf, const char *file);

/**
 * @ingroup bsl
 *
 * @brief Save the configuration object's contents to a specified UIO object.
 *
 * @param conf [IN] Configuration object
 * @param uio [IN] UIO object to save the configuration
 *
 * @retval BSL_SUCCESS Configuration successfully saved to the UIO.
 * @retval BSL_NULL_INPUT Invalid input parameter (if conf or uio is NULL).
 * @retval BSL_CONF_DUMP_FAIL Failed to save the configuration (e.g., dumpUio method is missing or fails).
 * @retval Other error code.
 */
int32_t BSL_CONF_DumpUio(const BSL_CONF *conf, BSL_UIO *uio);

/**
 * @ingroup bsl
 *
 * @brief Get the names of all sections from the configuration object.
 *
 * @param conf [IN] Configuration object
 * @param namesSize [OUT] Pointer to store the size of the returned array
 *
 * @retval BSL_SUCCESS Successfully retrieved section names.
 * @retval BSL_NULL_INPUT Invalid input parameter (if conf or namesSize is NULL).
 * @retval BSL_CONF_GET_FAIL Failed to retrieve section names (e.g., getSectionNames method is missing or fails).
 * @retval char ** a pointer to the section names array, which is retrieved successfully.
 * @retval NULL failed to get section names.
 */
char **BSL_CONF_GetSectionNames(const BSL_CONF *conf, uint32_t *namesSize);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_BSL_CONF */

#endif /* BSL_CONF_H */
