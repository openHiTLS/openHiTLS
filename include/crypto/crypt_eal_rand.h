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
 * @defgroup crypt_eal_rand
 * @ingroup crypt
 * @brief random number module
 */

#ifndef CRYPT_EAL_RAND_H
#define CRYPT_EAL_RAND_H

#include <stdbool.h>
#include <stdint.h>
#include "crypt_algid.h"
#include "crypt_types.h"
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
  * @ingroup crypt_eal_rand
  * @brief rand generate callback
  *
  * rand[out] randomdata
  * randLen[in] len
  *
  * @return  int32_t, defined by users.
  */
  typedef int32_t (*CRYPT_EAL_RandFunc)(uint8_t *rand, uint32_t randLen);

  /**
    * @ingroup crypt_eal_rand
    * @brief set rand func callback
    *
    * func[in] rand func
    *
    * @return  void.
    */
  void CRYPT_EAL_SetRandCallBack(CRYPT_EAL_RandFunc func);

/**
  * @ingroup crypt_eal_rand
  * @brief rand generate callback
  *
  * ctx[in] ctx
  * rand[out] randomdata
  * randLen[in] len
  *
  * @return  int32_t, defined by users.
  */
typedef int32_t (*CRYPT_EAL_RandFuncEx)(void *ctx, uint8_t *rand, uint32_t randLen);

/**
  * @ingroup crypt_eal_rand
  * @brief set rand func callback
  *
  * func[in] rand func
  *
  * @return  void.
  */
void CRYPT_EAL_SetRandCallBackEx(CRYPT_EAL_RandFuncEx func);

/**
 * @ingroup crypt_eal_rand
 * @brief Random number initialization interface. This interface does not support multiple threads.
 *
 *      Initialize global random number to RAND, Entropy sources and addtional random numbers in the seed material
 * which implemented by HiTLS. and this value is provided by the user. if user not provid the entropy source
 * (seedMeth and seedCtx are both NULL), the default software entropy source is used.
 *      In addition, this interface does not support multiple threads.
 *      The global random number is initialized to the random generation algorithm described in Nist 800-90a.
 *      Application scenarios are as follows:
 *      1. seedMeth == NULL && seedCtx == NULL ====> Use the default system entropy source in AES_CTR mode
 * (that is, non-DF cannot use the default entropy source).
 *      2. seedMeth == NULL && seedCtx != NULL ===> Error report.
 *      3. seedMeth != NULL ====> This function can be used normally, seedCtx is not restricted, but make sure
 * seedMeth can handle all kinds of situations.
 *
 * @attention:  Support obtain or generate random numbers with multithreading, but not support initialization
 * and deinitialization with multithreading.
 * @param id [IN] RAND id
 * @param seedMeth [IN] Seed method, which can be set NULL with seedCtx, The default entropy source is used
 * or provided by the user.
 * @param seedCtx [IN] Seed context information, which can be set NULL, But the seedMeth provided by the user can
 * handle the situation where seedCtx is NULL.
 * Generally, seedCtx needs to contain data such as entropy and nonce.
 * @param pers [IN] Personal data, which can be NULL.
 * @param persLen [IN] Length of the personal data, the length ranges from [0,0x7FFFFFF0].
 * @retval #CRYPT_SUCCESS, if successful.
 *         For other error codes, see the crypt_errno.h file.
 */
int32_t CRYPT_EAL_RandInit(CRYPT_RAND_AlgId id, CRYPT_RandSeedMethod *seedMeth, void *seedCtx,
    const uint8_t *pers, uint32_t persLen);

/**
 * @ingroup crypt_eal_rand
 * @brief   Random number initialization in the providers.
 *
 * @param libCtx [IN] Library context
 * @param algId [IN] rand algorithm ID.
 * @param attrName [IN] Specify expected attribute values
 * @param pers [IN] Personal data, which can be NULL.
 * @param persLen [IN] Personal data length. the range is [0,0x7FFFFFF0].
 * @param param [IN] Transparent transmission of underlying parameters
 *
 * @retval #CRYPT_SUCCESS, if successful.
 *         For other error codes, see the crypt_errno.h file.
 */
int32_t CRYPT_EAL_ProviderRandInitCtx(CRYPT_EAL_LibCtx *libCtx, int32_t algId, const char *attrName,
    const uint8_t *pers, uint32_t persLen, BSL_Param *param);

/**
 * @ingroup crypt_eal_rand
 * @brief   Deinitializing the global RAND interface, this interface does not support multiple threads.
 *
 * @retval  void, no return value.
 */
void CRYPT_EAL_RandDeinit(void);

/**
 * @ingroup crypt_eal_rand
 * @brief   Deinitializing the libCtx RAND interface, this interface does not support multiple threads.
 *
 * @param libCtx [IN] Library context
 * 
 * @retval  void, no return value.
 */
void CRYPT_EAL_RandDeinitEx(CRYPT_EAL_LibCtx *libCtx);

/**
 * @ingroup crypt_eal_rand
 * @brief   Generate a random number.
 *
 * The addtional data marked as "addin" can be NULL, and additional data specified by the user.
 * This interface does not support multiple threads.
 *
 * @param byte  [OUT] Output random numbers, the memory is provided by the user.
 * @param len   [IN] Required random number length, the maximum length is (0, 65536].
 * @param addin [IN] Addtional data, which can set be NULL.
 * @param addinLen [IN] Addtional data length, the maximum length is[0,0x7FFFFFF0].
 * @retval #CRYPT_SUCCESS, if successful.
 *         For other error codes, see the crypt_errno.h file.
 */
int32_t CRYPT_EAL_RandbytesWithAdin(uint8_t *byte, uint32_t len, uint8_t *addin, uint32_t addinLen);

/**
 * @ingroup crypt_eal_rand
 * @brief   Generate a random number.
 *
 * The addtional data marked as "addin" can be NULL, and additional data specified by the user.
 * This interface does not support multiple threads.
 *
 * @param libCtx [IN] Library context
 * @param byte  [OUT] Output random numbers, the memory is provided by the user.
 * @param len   [IN] Required random number length, the maximum length is (0, 65536].
 * @param addin [IN] Addtional data, which can set be NULL.
 * @param addinLen [IN] Addtional data length, the maximum length is[0,0x7FFFFFF0].
 * @retval #CRYPT_SUCCESS, if successful.
 *         For other error codes, see the crypt_errno.h file.
 */
int32_t CRYPT_EAL_RandbytesWithAdinEx(CRYPT_EAL_LibCtx *libCtx,
    uint8_t *byte, uint32_t len, uint8_t *addin, uint32_t addinLen);

/**
 * @ingroup crypt_eal_rand
 *
 * Generate a random number, which is equivalent to CRYPT_EAL_RandbytesWithAdin(bytes, len, NULL, 0).
 * This interface supports multi-thread access.
 *
 * @param byte [OUT] Used to store output random numbers, the memory is provided by the user.
 * @param len  [IN] Required random number length, the length range is(0, 65536].
 * @retval #CRYPT_SUCCESS, if successful.
 *         For other error codes, see the crypt_errno.h file.
 */
int32_t CRYPT_EAL_Randbytes(uint8_t *byte, uint32_t len);

/**
 * @ingroup crypt_eal_rand
 *
 * Generate a random number
 * This interface supports multi-thread access.
 *
 * @param libCtx [IN] Library context
 * @param byte [OUT] Used to store output random numbers, the memory is provided by the user.
 * @param len  [IN] Required random number length, the length range is(0, 65536].
 * @retval #CRYPT_SUCCESS, if successful.
 *         For other error codes, see the crypt_errno.h file.
 */
int32_t CRYPT_EAL_RandbytesEx(CRYPT_EAL_LibCtx *libCtx, uint8_t *byte, uint32_t len);

/**
 * @ingroup crypt_eal_rand
 * @brief Regenerate the seed.
 *
 * @attention The addtional data can set be NULL, and this interface supports multi-thread access.
 * @param addin [IN] Additional data, which can set be NULL.
 * @param addinLen [IN] Addtional data length, the range is [0,0x7FFFFFF0].
 * @retval #CRYPT_SUCCESS, if successful.
 *         For other error codes, see crypt_errno.h.
 * 
 * @note After forking, it is necessary to manually supplement the entropy source for the new program
 */
int32_t CRYPT_EAL_RandSeedWithAdin(uint8_t *addin, uint32_t addinLen);

/**
 * @ingroup crypt_eal_rand
 *
 * Regenerate the seed, which is equivalent to CRYPT_EAL_RandSeedWithAdin(NULL, 0), and the interface
 * supports multi-thread access.
 *
 * @retval  #CRYPT_SUCCESS
 *          For other error codes, see crypt_errno.h.
 * 
 * @note After forking, it is necessary to manually supplement the entropy source for the new program
 */
int32_t CRYPT_EAL_RandSeed(void);

/**
 * @ingroup crypt_eal_rand
 *
 * Regenerate the seed, which is equivalent to CRYPT_EAL_RandSeedWithAdin(NULL, 0), and the interface
 * supports multi-thread access.
 * @param libCtx [IN] Library context
 * @retval  #CRYPT_SUCCESS
 *          For other error codes, see crypt_errno.h.
 * 
 * @note After forking, it is necessary to manually supplement the entropy source for the new program
 */
int32_t CRYPT_EAL_RandSeedEx(CRYPT_EAL_LibCtx *libCtx);

typedef struct EAL_RndCtx CRYPT_EAL_RndCtx;

/**
 * @ingroup CRYPT_EAL_DrbgNew
 * @brief Random number initialization interface, and this interface does not support multiple threads.
 *
 *      Initial DRBG with HiTLS, entropy source and addtional random number in the seed material
 * are provided by users. This interface does not support multi-threading, the initial random number is
 * the random number generation algorithm described in Nist 800-90a.
 *      Usage scenes are as follows:
 *      1. seedMeth == NULL && seedCtx == NULL ====> Use the default system entropy source in AES_CTR mode
 * (that is, non-DF cannot use the default entropy source).
 *      2. seedMeth == NULL && seedCtx != NULL ===> error reported.
 *      3. seedMeth != NULL ====> This function can be used normally, seedCtx function is not restricted,
 * but make sure seedMeth can handle all kinds of situations.
 *
 * @attention Initialization and deinitialization
 * @param id [IN] RAND id
 * @param seedMeth [IN] Seed method, this parameter and seedCtx can be null at the same time. The default entropy
 * source is used or provided by the user.
 * @param seedCtx [IN] Seed context information, which can be NULL, but the seedMeth provided by the user needs
 * to be able to handle the situation where seedCtx is null.
 *     seedCtx generally needs to contain the entropy source marked as "entropy", additional random number "nonce", and
 * other data.
 * @retval  DRBG handle, if successful.
 *          NULL, if failed.
 */
CRYPT_EAL_RndCtx *CRYPT_EAL_DrbgNew(CRYPT_RAND_AlgId id, CRYPT_RandSeedMethod *seedMeth, void *seedCtx);

/**
 * @ingroup crypt_eal_rand
 * @brief   Random number initialization in the providers.
 *
 * @param libCtx [IN] Library context
 * @param algId [IN] rand algorithm ID.
 * @param attrName [IN] Specify expected attribute values
 * @param param [IN] Transparent transmission of underlying parameters
 *
 * @retval Success: DRBG ctx.
 *         Fails: NULL.
 */
CRYPT_EAL_RndCtx *CRYPT_EAL_ProviderDrbgNewCtx(CRYPT_EAL_LibCtx *libCtx, int32_t algId, const char *attrName,
    BSL_Param *param);

/**
 * @ingroup CRYPT_EAL_DrbgDeinit
 * @brief   CRYPT_EAL_DrbgDeinit Deinitialization interface, this interface does not support multiple threads.
 *
 * @param ctx  [IN] DRBG handle
 * @retval Void, no value is returned.
*/
void CRYPT_EAL_DrbgDeinit(CRYPT_EAL_RndCtx *ctx);

/**
 * @ingroup crypt_eal_rand
 * @brief Generate a random number.
 *
 * @attention The addtional data can be NULL, user specifies the addtional data,
 * and the interface supports multi-thread access.
 * @param ctx  [IN] DRBG handle
 * @param byte     [OUT] Outputs random numbers. the memory is provided by the user.
 * @param len      [IN] Required random number length. the range is (0, 65536].
 * @param addin    [IN] Addtional data, which can be NULL.
 * @param addinLen [IN] Addtional data length. the range is [0,0x7FFFFFF0].
 * @retval  #CRYPT_SUCCESS, if successful.
 *          For other error codes, see the crypt_errno.h file.
 */
int32_t CRYPT_EAL_DrbgbytesWithAdin(CRYPT_EAL_RndCtx *ctx, uint8_t *byte, uint32_t len, uint8_t *addin, uint32_t addinLen);

/**
 * @ingroup crypt_eal_rand
 *
 * Generate a random number, which is equivalent to CRYPT_EAL_RandbytesWithAdin(bytes, len, NULL, 0).
 * This interface supports multi-thread access.
 *
 * @param ctx  [IN] DRBG handle
 * @param byte     [OUT] Used to store output random numbers. the memory is provided by the user.
 * @param len      [IN] Required random number length. the range is (0, 65536].
 * @retval #CRYPT_SUCCESS, if successful.
 *         For other error codes, see the crypt_errno.h file.
 */
int32_t CRYPT_EAL_Drbgbytes(CRYPT_EAL_RndCtx *ctx, uint8_t *byte, uint32_t len);

/**
 * @ingroup crypt_eal_rand
 * @brief Regenerate the seed. The addtional data can be NULL. This interface supports multi-thread access.
 *
 * @param ctx  [IN] DRBG handle
 * @param addin    [IN] Addtional data, which can be null.
 * @param addinLen [IN] Addtional data length. The maximum length is [0,0x7FFFFFF0].
 * @retval #CRYPT_SUCCESS, if successful.
 *         For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_DrbgSeedWithAdin(CRYPT_EAL_RndCtx *ctx, uint8_t *addin, uint32_t addinLen);

/**
 * @ingroup crypt_eal_rand
 * @brief Regenerate the seed, which is equivalent to CRYPT_EAL_RandSeedWithAdin(NULL, 0).
 *
 * @attention This interface supports multi-thread access.
 * @param ctx  [IN] DRBG handle.
 * @retval  #CRYPT_SUCCESS, if successful.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_DrbgSeed(CRYPT_EAL_RndCtx *ctx);

/**
 * @ingroup crypt_eal_rand
 * @brief   Check whether the id is valid Rand algorithm ID.
 *
 * @param   id [IN] Rand algorithm ID.
 *
 * @retval true, if valid.
 *         false, if invalid.
 */
bool CRYPT_EAL_RandIsValidAlgId(CRYPT_RAND_AlgId id);

/**
 * @ingroup crypt_eal_rand
 * @brief Instantiate the DRBG.
 *
 * This function instantiates the Deterministic Random Bit Generator (DRBG) with personalization string.
 * It supports multi-thread access.
 *
 * @param ctx      [IN] DRBG handle
 * @param pers [IN] Personal data, which can be NULL.
 * @param persLen [IN] Personal data length. the range is [0,0x7FFFFFF0].
 * @retval #CRYPT_SUCCESS, if successful.
 *         For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_DrbgInstantiate(CRYPT_EAL_RndCtx *rndCtx, const uint8_t *pers, uint32_t persLen);

/**
 * @ingroup crypt_eal_rand
 * @brief get or set rand param
 *
 * @param ctx [IN] rand context
 * @param cmd [IN] Option information
 * @param val [IN/OUT] Data to be set/obtained
 * @param valLen [IN] Length of the data marked as "val"
 *
 * @retval  #CRYPT_SUCCESS.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_DrbgCtrl(CRYPT_EAL_RndCtx *ctx, int32_t cmd, void *val, uint32_t valLen);

/**
 * @ingroup crypt_eal_rand
 * @brief Get the seed of Primary DRBG.
 *
 * @param isParentEntropy [IN] If true, return primary DRBG; otherwise, return g_globalRndCtx.
 *
 * @retval  DRBG handle.
 */
CRYPT_EAL_RndCtx *CRYPT_EAL_GetSeedCtx(bool isParentEntropy);

#ifdef __cplusplus
}
#endif

#endif // CRYPT_EAL_RAND_H
