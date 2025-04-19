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
 * @defgroup crypt_eal_provider
 * @ingroup crypt
 * @brief introduced when then provider is used
 */

#ifndef CRYPT_EAL_PROVIDER_H
#define CRYPT_EAL_PROVIDER_H

#include <stdint.h>
#include "crypt_types.h"
#include "bsl_sal.h"
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/* The hitls framework generates context for each provider */
typedef struct EAL_ProviderMgrCtx CRYPT_EAL_ProvMgrCtx;

typedef struct {
    int32_t id;
    void *func;
} CRYPT_EAL_Func;

/**
 * @ingroup crypt_eal_provider
 * @brief create Library context
 *
 * @retval return Library context
*/
CRYPT_EAL_LibCtx *CRYPT_EAL_LibCtxNew(void);

/**
 * @ingroup crypt_eal_provider
 * @brief free Library context
 * @param libCtx [IN] Library context
 *
 */
void CRYPT_EAL_LibCtxFree(CRYPT_EAL_LibCtx *libCtx);

/**
 * @ingroup crypt_eal_provider
 * @brief Provider load interface
 *
 * @param libCtx [IN] Library context
 * @param providerName [IN] provider name
 * @param param [IN] parameter is transparently passed to the initialization function of the underlying provider
 * @param cmd [IN] Command specifying the conversion format for the provider library name.
 *                 This parameter is used to determine how the provider library name should be
 *                 converted or formatted. Possible values are:
 *                 - BSL_SAL_LIB_FMT_SO: Convert to .so format
 *                 - BSL_SAL_LIB_FMT_LIBSO: Convert to lib*.so format
 *                 - BSL_SAL_LIB_FMT_LIBDLL: Convert to lib*.dll format
 *                 - BSL_SAL_LIB_FMT_DLL: Convert to .dll format
 *                 The specific conversion is handled by the BSL_SAL_LibNameFormat function.
 * @param mgrCtx [OUT] Provider context
 *
 * @retval #CRYPT_SUCCESS, if success.
 *         Other error codes see the crypt_errno.h
*/
int32_t CRYPT_EAL_ProviderLoad(CRYPT_EAL_LibCtx *libCtx, BSL_SAL_LibFmtCmd cmd,
    const char *providerName, BSL_Param *param, CRYPT_EAL_ProvMgrCtx **mgrCtx);

/**
 * @ingroup crypt_eal_provider
 * @brief Control provider interface
 *
 * @param ctx [IN] Provider context
 * @param cmd [IN] Control command
 * @param val [IN/OUT] Value associated with the command
 * @param valLen [IN] Length of the value
 *
 * @retval #CRYPT_SUCCESS, if success.
 *         Other error codes see the crypt_errno.h
*/
int32_t CRYPT_EAL_ProviderCtrl(CRYPT_EAL_ProvMgrCtx *ctx, int32_t cmd, void *val, uint32_t valLen);

/**
 * @brief Callback function type for processing provider capabilities
 *
 * @param params [IN] Parameters containing capability information
 * @param args [IN] User-provided arguments for capability processing
 *
 * @retval #CRYPT_SUCCESS if processing succeeds
 *         Other error codes see the crypt_errno.h
 */
typedef int32_t (*CRYPT_EAL_ProcCapsCb)(const BSL_Param *params, void *args);

/**
 * @ingroup crypt_eal_provider
 * @brief Get and process provider capabilities
 *
 * @param ctx [IN] Provider context
 * @param cmd [IN] Command to specify which capabilities to retrieve
 * @param cb [IN] Callback function to process the retrieved capabilities
 * @param args [IN] Arguments to be passed to the callback function
 *
 * @retval #CRYPT_SUCCESS if capability retrieval and processing succeeds
 *         Other error codes see the crypt_errno.h
 */
int32_t CRYPT_EAL_ProviderGetCaps(CRYPT_EAL_ProvMgrCtx *ctx, int32_t cmd, CRYPT_EAL_ProcCapsCb cb, void *args);

/**
 * @ingroup crypt_eal_provider
 * @brief Provider unload interface
 *
 * @param libCtx [IN] Library context
 * @param cmd [IN] Command specifying the conversion format for the provider library name.
 *                 This parameter is used to determine how the provider library name should be
 *                 converted or formatted. Possible values are:
 *                 - BSL_SAL_LIB_FMT_SO: Convert to .so format
 *                 - BSL_SAL_LIB_FMT_LIBSO: Convert to lib*.so format
 *                 - BSL_SAL_LIB_FMT_LIBDLL: Convert to lib*.dll format
 *                 - BSL_SAL_LIB_FMT_DLL: Convert to .dll format
 *                 The specific conversion is handled by the BSL_SAL_LibNameFormat function.
 * @param providerName [IN] provider name
 *
 * @retval #CRYPT_SUCCESS, if success.
 *         Other error codes see the crypt_errno.h
*/
int32_t CRYPT_EAL_ProviderUnload(CRYPT_EAL_LibCtx *libCtx, BSL_SAL_LibFmtCmd cmd, const char *providerName);


/**
 * @ingroup crypt_eal_provider
 * @brief Set the path to load the provider and support duplicate settings.
 *  Repeating settings will release the previous path.
 *
 * @param libCtx [IN] Library context
 * @param serchPath [IN] the path to load the provider
 *
 * @retval #CRYPT_SUCCESS, if success.
 *         Other error codes see the crypt_errno.h
*/
int32_t CRYPT_EAL_ProviderSetLoadPath(CRYPT_EAL_LibCtx *libCtx, const char *searchPath);

/**
 * @ingroup crypt_eal_provider
 * @brief Get function implementations from provider based on operation ID, algorithm ID and attributes
 *
 * @param libCtx [IN] Library context
 * @param operaId [IN] Operation ID
 * @param algId [IN] Algorithm ID
 * @param attribute [IN] Attribute string for matching provider capabilities
 * @param funcs [OUT] Retrieved function implementations
 * @param provCtx [OUT] Provider context associated with the functions
 *
 * @retval #CRYPT_SUCCESS, if success.
 *         Other error codes see the crypt_errno.h
*/
int32_t CRYPT_EAL_ProviderGetFuncs(CRYPT_EAL_LibCtx *libCtx, int32_t operaId, int32_t algId,
    const char *attribute, const CRYPT_EAL_Func **funcs, void **provCtx);

/**
 * @brief Callback function type for processing a single provider
 *
 * @param ctx [IN] Provider context for the current provider being processed
 * @param args [IN] User-provided arguments for provider processing
 *
 * @retval #CRYPT_SUCCESS if processing succeeds
 *         Other error codes see the crypt_errno.h
 */
typedef int32_t (*CRYPT_EAL_ProviderProcessCb)(CRYPT_EAL_ProvMgrCtx *ctx, void *args);

/**
 * @ingroup crypt_eal_provider
 * @brief Process all loaded providers with the specified callback function
 *
 * This function iterates through all providers loaded in the given library context
 * and applies the specified callback function to each provider. It allows performing
 * a common operation across all loaded providers.
 *
 * @param ctx [IN] Library context containing the providers to process
 * @param cb [IN] Callback function to be applied to each provider
 * @param args [IN] Arguments to be passed to the callback function
 *
 * @retval #CRYPT_SUCCESS if all providers were processed successfully
 *         The first error code encountered if any provider processing fails
 *         Other error codes see the crypt_errno.h
 */
int32_t CRYPT_EAL_ProviderProcessAll(CRYPT_EAL_LibCtx *ctx, CRYPT_EAL_ProviderProcessCb cb, void *args);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // CRYPT_EAL_PROVIDER_H
