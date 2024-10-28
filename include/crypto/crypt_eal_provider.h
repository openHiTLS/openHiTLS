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

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef struct EalLibCtx CRYPT_EAL_LibCtx;
/* The hitls framework generates context for each provider */
typedef struct EalProviderMgrCtx CRYPT_EAL_ProvMgrCtx;

/**
 * @ingroup crypt_eal_provider
 * @brief create Library context
 *
 * @retval return Library context
*/
CRYPT_EAL_LibCtx *CRYPT_EAL_NewLibCtx(void);

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
 *                 - BSL_SAL_CONVERTER_SO: Convert to .so format
 *                 - BSL_SAL_CONVERTER_LIBSO: Convert to lib*.so format
 *                 - BSL_SAL_CONVERTER_LIBDLL: Convert to lib*.dll format
 *                 - BSL_SAL_CONVERTER_DLL: Convert to .dll format
 *                 The specific conversion is handled by the BSL_SAL_ConverterName function.
 * @param mgrCtx [OUT] Provider context
 *
 * @retval #CRYPT_SUCCESS, if success.
 *         Other error codes see the crypt_errno.h
*/
int32_t CRYPT_EAL_LoadProvider(CRYPT_EAL_LibCtx *libCtx, BSL_SAL_ConverterCmd cmd,
    const char *providerName, CRYPT_Param *param, CRYPT_EAL_ProvMgrCtx **mgrCtx);

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
int32_t CRYPT_EAL_CtrlProvider(CRYPT_EAL_ProvMgrCtx *ctx, int32_t cmd, void *val, uint32_t valLen);

/**
 * @ingroup crypt_eal_provider
 * @brief Provider unload interface
 *
 * @param libCtx [IN] Library context
 * @param cmd [IN] Command specifying the conversion format for the provider library name.
 *                 This parameter is used to determine how the provider library name should be
 *                 converted or formatted. Possible values are:
 *                 - BSL_SAL_CONVERTER_SO: Convert to .so format
 *                 - BSL_SAL_CONVERTER_LIBSO: Convert to lib*.so format
 *                 - BSL_SAL_CONVERTER_LIBDLL: Convert to lib*.dll format
 *                 - BSL_SAL_CONVERTER_DLL: Convert to .dll format
 *                 The specific conversion is handled by the BSL_SAL_ConverterName function.
 * @param providerName [IN] provider name
 *
 * @retval #CRYPT_SUCCESS, if success.
 *         Other error codes see the crypt_errno.h
*/
int32_t CRYPT_EAL_UnloadProvider(CRYPT_EAL_LibCtx *libctx, BSL_SAL_ConverterCmd cmd, const char *providerName);


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
int32_t CRYPT_EAL_SetLoadProviderPath(CRYPT_EAL_LibCtx *libCtx, const char *searchPath);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // CRYPT_EAL_PROVIDER_H
