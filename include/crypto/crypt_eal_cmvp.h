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
 * @defgroup crypt_eal_cmvp
 * @ingroup crypt
 * @brief EAL CMVP header
 */

#ifndef CRYPT_EAL_CMVP_H
#define CRYPT_EAL_CMVP_H

#include <stdint.h>
#include "crypt_types.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * @ingroup crypt_eal_cmvp
 * @brief   The type of the self-test.
 */
typedef enum {
    CRYPT_CMVP_INTEGRITY_TEST = 0, /**< Integrity test */
    CRYPT_CMVP_KAT_TEST,           /**< Known Answer Test */
    CRYPT_CMVP_MAX
} CRYPT_CMVP_SELFTEST_TYPE;

/**
 * @ingroup crypt_eal_cmvp
 * @brief   Log function for provider.
 *
 * @param   oper [IN] The operation type.
 * @param   type [IN] The algorithm type.
 * @param   id [IN] The algorithm ID.
 * @param   err [IN] The error code.
 */
typedef void (*CRYPT_EAL_CMVP_LogFunc)(CRYPT_EVENT_TYPE oper, CRYPT_ALGO_TYPE type, int32_t id, int32_t err);

typedef struct EAL_SelftestCtx CRYPT_SelftestCtx;

/**
 * @ingroup crypt_eal_cmvp
 * @brief   Create a new context for self-test.
 *
 * @param   libCtx [IN] The library context, if NULL, return NULL.
 * @param   attrName [IN] Specify expected attribute values.
 *
 * @retval  #CRYPT_SelftestCtx pointer.
 *          NULL, if the operation fails.
 */
CRYPT_SelftestCtx *CRYPT_CMVP_SelftestNewCtx(CRYPT_EAL_LibCtx *libCtx, const char *attrName);

/**
 * @ingroup crypt_eal_cmvp
 * @brief   Get the version of the provider.
 *
 * @param   ctx [IN] The self-test context.
 *
 * @retval  The string pointer of the version of the provider.
 *          NULL, if the operation fails.
 */
const char *CRYPT_CMVP_GetVersion(CRYPT_SelftestCtx *ctx);

/**
 * @ingroup crypt_eal_cmvp
 * @brief   Run the self-test.
 *
 * @param   ctx [IN] The self-test context.
 * @param   type [IN] The type of the self-test.
 *
 * @retval  #CRYPT_SUCCESS.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_CMVP_Selftest(CRYPT_SelftestCtx *ctx, CRYPT_CMVP_SELFTEST_TYPE type);

/**
 * @ingroup crypt_eal_cmvp
 * @brief   Free the context of the self-test.
 *
 * @param   ctx [IN] The self-test context.
 */
void CRYPT_CMVP_SelftestFreeCtx(CRYPT_SelftestCtx *ctx);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif // CRYPT_EAL_CMVP_H