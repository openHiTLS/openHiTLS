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

#ifndef CRYPT_EAL_ENTROPY_H
#define CRYPT_EAL_ENTROPY_H

#include <stdbool.h>
#include <stdint.h>
#include "crypt_algid.h"
#include "crypt_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct CryptEalEntropySource CRYPT_EAL_Es;

/**
 * @ingroup crypt_eal_entropy
 * @brief Generate entropy source handle.
 * @attention If the function is called by an external user and the error stack is concerned,
 * it is recommended that BSL_ERR_ClearError() be called before this function is called.
 *
 * @return Success: entropy source ctx.
 *         Fails: NULL.
 */
CRYPT_EAL_Es *CRYPT_EAL_EsNew(void);

/**
 * @ingroup crypt_eal_entropy
 * @brief Release the entropy source handle.
 * @attention If the function is called by an external user and the error stack is concerned, it is recommended
 * that BSL_ERR_ClearError() be called before this function is called.
 *
 * @param es [IN] the entropy source handle. The CTX is set null by the caller.
 * @return None
 */
void CRYPT_EAL_EsFree(CRYPT_EAL_Es *es);

/**
 * @ingroup crypt_eal_entropy
 * @brief Initialize the handle.
 * @attention If the function is called by an external user and the error stack is concerned,
 * you are advised to call BSL_ERR_ClearError() before calling this function.
 *
 * @param es [IN] the entropy source handle.
 * @return CRYPT_SUCCESS,success
 *         For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_EsInit(CRYPT_EAL_Es *es);

/**
 * @ingroup crypt_eal_entropy
 * @brief Set the mode ctx parameters in the CTX.
 *         parameter                data type              Length(len):number of data bytes
 * CRYPT_ENTROPY_SET_CF             string              Adjust the length of the function type name. For example,
                                                        if the function type name is sm3-df, the length is 6.
                                                        This interface can be invoked only once before the
                                                         CRYPT_EAL_EsInit interface is invoked.
 * CRYPT_ENTROPY_SET_POOL_SIZE      uint32_t            Specifies the size of the entropy pool. The recommended value
                                                         ranges from 512 to 4096. The default value is 4096.
                                                        Can only be called before CRYPT_EAL_EsInit interface.
 * CRYPT_ENTROPY_ADD_NS           CRYPT_EAL_NsPara      Add a noise source.Repeated noise sources cannot be added.
                                                         Whether a noise source is repeated is determined based on the
                                                         name.
                                                        The length is the size of the CRYPT_EAL_NsPara structure.
                                                        Can only be called before CRYPT_EAL_EsInit interface.
 * CRYPT_ENTROPY_REMOVE_NS           string             Length of the entropy source name.
                                                        Can only be called before CRYPT_EAL_EsInit interface.
                                                        When an entropy source is created, two noise sources are carried
                                                         by default, that is, timeStamp and CPU-Jitter. If the noise
                                                         sources are not required, you can delete them by using this
                                                         interface.
 * CRYPT_ENTROPY_ENABLE_TEST         bool               Sets whether to enable the health test, length is 1.
                                                        Can only be called before CRYPT_EAL_EsInit interface.
 * CRYPT_ENTROPY_GET_STATE           uint32_t           Obtains the current entropy source status, length is 4.
                                                        Can only be called after CRYPT_EAL_EsInit interface.
 * CRYPT_ENTROPY_GET_POOL_SIZE       uint32_t           Obtains the total entropy pool capacity, length is 4.
                                                        Can only be called after CRYPT_EAL_EsInit interface.
 * CRYPT_ENTROPY_POOL_GET_CURRSIZE   uint32_t           Obtains the current entropy pool capacity, length is 4.
                                                        Can only be called after CRYPT_EAL_EsInit interface.
 * CRYPT_ENTROPY_GET_CF_SIZE         uint32_t           Get the size of the conditioning function, length is 4.
                                                        Can only be called after CRYPT_EAL_EsInit interface.
 * @attention If the function is called by an external user and the error stack is concerned,
 * it is recommended that BSL_ERR_ClearError() be called before this function is called.
 * @param es [IN] the entropy source handle
 * @param type [IN] Parameter type
 * @param data [IN/OUT] Input and output data
 * @param len [IN] Data length
 * @return Success response: CRYPT_SUCCESS
 *         error codes see the crypt_errno.h
 */
int32_t CRYPT_EAL_EsCtrl(CRYPT_EAL_Es *es, int32_t type, void *data, uint32_t len);

/**
  * @ingroup crypt_eal_entropy
  * @brief Get Entropy Output.
  *
  * @param es [IN] the entropy source handle.
  * @param data [OUT] Output data
  * @param len [IN] Data length
  * @return CRYPT_SUCCESS, success
  *         Other error codes see crypt_errno.h
  */
uint32_t CRYPT_EAL_EsEntropyGet(CRYPT_EAL_Es *es, uint8_t *data, uint32_t len);

typedef struct EAL_SeedPool CRYPT_EAL_SeedPoolCtx;

/**
  * @ingroup crypt_eal_entropy
  * @brief Creating an seed pool.
  *
  * @param isCreateNullPool [IN] Whether the entropy pool provides a default entropy source.
  * @return success: seed pool ctx.
  *         failed: NULL
  */
CRYPT_EAL_SeedPoolCtx *CRYPT_EAL_SeedPoolNew(bool isCreateNullPool);

/**
  * @ingroup crypt_eal_entropy
  * @brief Adding an entropy source.
  *
  * @param ctx [IN] seed pool ctx.
  * @param para [IN] Entropy Source para.
  * @return Success: CRYPT_SUCCESS.
  *         failed: Other error codes see crypt_errno.h
  */
int32_t CRYPT_EAL_SeedPoolAddEs(CRYPT_EAL_SeedPoolCtx *ctx, const CRYPT_EAL_EsPara *para);

/**
  * @ingroup crypt_eal_entropy
  * @brief get entropy data.
  *
  * @param ctx [IN] seed pool ctx.
  * @param entropy [OUT] obtained entropy data.
  * @param strength [IN] the amount of entropy required.
  * @param lenRange [IN] entropy data range.
  * @return null.
  */
int32_t CRYPT_EAL_SeedPoolGetEntropy(CRYPT_EAL_SeedPoolCtx *ctx, CRYPT_Data *entropy, uint32_t strength,
    const CRYPT_Range *lenRange);

/**
  * @ingroup crypt_eal_entropy
  * @brief release entropy source.
  *
  * @param ctx [IN] seed pool ctx.
  * @return null.
  */
void CRYPT_EAL_SeedPoolFree(CRYPT_EAL_SeedPoolCtx *ctx);

#ifdef __cplusplus
}
#endif
#endif
