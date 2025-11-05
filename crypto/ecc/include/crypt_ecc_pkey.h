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

#ifndef CRYPT_ECC_PKEY_H
#define CRYPT_ECC_PKEY_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_ECC

#include "crypt_bn.h"
#include "crypt_ecc.h"
#include "crypt_algid.h"
#include "bsl_params.h"
#include "sal_atomic.h"
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef CRYPT_ECC_TRY_MAX_CNT
#define CRYPT_ECC_TRY_MAX_CNT 100 // Maximum number of attempts to generate keys and signatures
#endif

/* ECC key context */
typedef struct ECC_PkeyCtx {
    BN_BigNum *prvkey;      // Private key
    ECC_Point *pubkey;      // Public key
    ECC_Para *para;         // Key parameter
    CRYPT_PKEY_PointFormat pointFormat;   // Public key point format
    uint32_t useCofactorMode;   // Indicates whether to use the cofactor mode. 1 indicates yes, and 0 indicates no.
    uint32_t flags;         // behavior flags, see CRYPT_ECC_Flag
    BSL_SAL_RefCount references;
    void *libCtx;
    char *mdAttr;
} ECC_Pkey;

/**
 * @ingroup ecc
 * @brief After the copied ECC context is used up, call the ECC_FreeCtx to release the memory.
 *
 * @param ctx [IN] Source ECC context
 *
 * @return ECC_Pkey ECC context pointer
 * If the operation fails, null is returned.
 */
ECC_Pkey *ECC_DupCtx(ECC_Pkey *ctx);

/**
 * @ingroup ecc
 * @brief ecc Release the key context structure
 *
 * @param ctx [IN] Pointer to the context structure to be released. The ctx is set NULL by the invoker.
 */
void ECC_FreeCtx(ECC_Pkey *ctx);

/**
 * @ingroup ecc
 * @brief Obtain the valid length of the key, which is used before obtaining the private key.
 *
 * @param ctx [IN] Structure from which the key length is expected to be obtained
 *
 * @retval 0        The input is incorrect or the corresponding key structure does not have a valid key length.
 * @retval uint32_t Valid key length greater than 0
 */
uint32_t ECC_PkeyGetBits(const ECC_Pkey *ctx);

/**
 * @ingroup ecc
 * @brief Obtain curve parameters.
 *
 * @param pkey [IN] Curve parameter information
 * @param eccPara [OUT] Curve parameter information
 *
 * @retval CRYPT_SUCCESS
 * @retval Other            failure
 */
int32_t ECC_GetPara(const ECC_Pkey *pkey, CRYPT_EccPara *eccPara);

/**
 * @ingroup ecc
 * @brief Generate a public key from the public key.
 *
 * @param ctx [IN] ECC key context structure
 *
 * @retval CRYPT_NULL_INPUT         Error null pointer input
 * @retval CRYPT_MEM_ALLOC_FAIL     Memory allocation failure
 * @retval ECC error code.          Internal ECC calculation error
 * @retval BN error code.           An error occurred in the internal BigNum calculation.
 * @retval CRYPT_SUCCESS            The public key is successfully generated.
 */
int32_t ECC_GenPublicKey(ECC_Pkey *ctx);

/**
 * @ingroup ecc
 * @brief Generate the ECC key pair.
 *
 * @param ctx [IN] dh Context structure
 *
 * @retval CRYPT_NULL_INPUT         Invalid null pointer input
 * @retval CRYPT_MEM_ALLOC_FAIL     Memory allocation failure
 * @retval ECC error code.          Internal ECC calculation error
 * @retval BN error code.           An error occurred in the internal BigNum calculation.
 * @retval CRYPT_SUCCESS            The key pair is successfully generated.
 */
int32_t ECC_PkeyGen(ECC_Pkey *ctx);

/**
 * @ingroup ecc
 * @brief ECC Set the private key data.
 *
 * @param ctx [OUT] ECC context structure
 * @param prv [IN] Private key data
 *
 * @retval CRYPT_NULL_INPUT     Error null pointer input
 * @retval CRYPT_MEM_ALLOC_FAIL Memory allocation failure
 * @retval BN error.            An error occurs in the internal BigNum operation.
 * @retval CRYPT_SUCCESS        Set successfully.
 */
int32_t ECC_PkeySetPrvKey(ECC_Pkey *ctx, const CRYPT_EccPrv *prv);

/**
 * @ingroup ecc
 * @brief ECC Set the public key data.
 *
 * @param ctx [OUT] ECC context structure
 * @param pub [IN] Public key data
 *
 * @retval CRYPT_NULL_INPUT     Error null pointer input
 * @retval CRYPT_MEM_ALLOC_FAIL Memory allocation failure
 * @retval BN error.            An error occurs in the internal BigNum operation.
 * @retval CRYPT_SUCCESS        Set successfully.
 */
int32_t ECC_PkeySetPubKey(ECC_Pkey *ctx, const CRYPT_EccPub *pub);
/**
 * @ingroup ecc
 * @brief ECC Obtain the private key data.
 *
 * @param ctx [IN] ECC context structure
 * @param prv [OUT] Private key data
 *
 * @retval CRYPT_NULL_INPUT         Invalid null pointer input
 * @retval ECC_Pkey_KEYINFO_ERROR   The key information is incorrect.
 * @retval BN error.                An error occurred in the internal BigNum calculation.
 * @retval CRYPT_SUCCESS            Obtained successfully.
 */
int32_t ECC_PkeyGetPrvKey(const ECC_Pkey *ctx, CRYPT_EccPrv *prv);

/**
 * @ingroup ecc
 * @brief ECC Obtain the public key data.
 *
 * @param ctx [IN] ECC context structure
 * @param pub [OUT] Public key data
 *
 * @retval CRYPT_NULL_INPUT             Invalid null pointer input
 * @retval ECC_Pkey_BUFF_LEN_NOT_ENOUGH The buffer length is insufficient.
 * @retval ECC_Pkey_KEYINFO_ERROR       The key information is incorrect.
 * @retval BN error.                    An error occurs in the internal BigNum operation.
 * @retval CRYPT_SUCCESS                Obtained successfully.
 */
int32_t ECC_PkeyGetPubKey(const ECC_Pkey *ctx, CRYPT_EccPub *pub);

#ifdef HITLS_BSL_PARAMS
/**
 * @ingroup ecc
 * @brief ECC Set the private key data.
 *
 * @param ctx [OUT] ECC context structure
 * @param para [IN] Private key data
 *
 * @retval CRYPT_NULL_INPUT     Error null pointer input
 * @retval CRYPT_MEM_ALLOC_FAIL Memory allocation failure
 * @retval BN error.            An error occurs in the internal BigNum operation.
 * @retval CRYPT_SUCCESS        Set successfully.
 */
int32_t ECC_PkeySetPrvKeyEx(ECC_Pkey *ctx, const BSL_Param *para);

/**
 * @ingroup ecc
 * @brief ECC Set the public key data.
 *
 * @param ctx [OUT] ECC context structure
 * @param para [IN] Public key data
 *
 * @retval CRYPT_NULL_INPUT     Error null pointer input
 * @retval CRYPT_MEM_ALLOC_FAIL Memory allocation failure
 * @retval BN error.            An error occurs in the internal BigNum operation.
 * @retval CRYPT_SUCCESS        Set successfully.
 */
int32_t ECC_PkeySetPubKeyEx(ECC_Pkey *ctx, const BSL_Param *para);

/**
 * @ingroup ecc
 * @brief ECC Obtain the private key data.
 *
 * @param ctx [IN] ECC context structure
 * @param para [OUT] Private key data
 *
 * @retval CRYPT_NULL_INPUT         Invalid null pointer input
 * @retval ECC_Pkey_KEYINFO_ERROR   The key information is incorrect.
 * @retval BN error.                An error occurred in the internal BigNum calculation.
 * @retval CRYPT_SUCCESS            Obtained successfully.
 */
int32_t ECC_PkeyGetPrvKeyEx(const ECC_Pkey *ctx, BSL_Param *para);

/**
 * @ingroup ecc
 * @brief ECC Obtain the public key data.
 *
 * @param ctx [IN] ECC context structure
 * @param para [OUT] Public key data
 *
 * @retval CRYPT_NULL_INPUT             Invalid null pointer input
 * @retval ECC_Pkey_BUFF_LEN_NOT_ENOUGH The buffer length is insufficient.
 * @retval ECC_Pkey_KEYINFO_ERROR       The key information is incorrect.
 * @retval BN error.                    An error occurs in the internal BigNum operation.
 * @retval CRYPT_SUCCESS                Obtained successfully.
 */
int32_t ECC_PkeyGetPubKeyEx(const ECC_Pkey *ctx, BSL_Param *para);

/**
 * @ingroup ecc
 * @brief Obtain curve parameters.
 *
 * @param pkey [IN] Curve parameter information
 * @param para [OUT] Curve parameter information
 *
 * @retval CRYPT_SUCCESS
 * @retval Other            failure
 */
int32_t ECC_GetParaEx(const ECC_Pkey *ctx, BSL_Param *para);
#endif
/**
 * @ingroup ecc
 * @brief ECC control interface
 *
 * @param ctx [IN/OUT] ECC context structure
 * @param opt [IN] Operation mode. For details, see ECC_CtrlType.
 * @param val [IN] Input parameter
 * @param len [IN] val Length
 *
 * @retval CRYPT_SUCCESS                         Set successfully.
 * @retval CRYPT_NULL_INPUT                      If any input parameter is empty
 * @retval ECC_Pkey_ERR_UNSUPPORTED_CTRL_OPTION  opt mode not supported
 */
int32_t ECC_PkeyCtrl(ECC_Pkey *ctx, int32_t opt, void *val, uint32_t len);

/**
 * @ingroup ecc
 * @brief ecc Create a context.
 *
 * @param id [IN] elliptic curve ID
 * @return ECC_Pkey ECC context pointer
 * If the operation fails, null is returned.
 */
ECC_Pkey *ECC_PkeyNewCtx(CRYPT_PKEY_ParaId id);

#ifdef HITLS_CRYPTO_ECC_CMP
/**
 * @ingroup ecc
 * @brief ecc Compare public keys and parameters
 *
 * @param a [IN] ECC Context structure
 * @param b [IN] ECC context structure
 *
 * @retval CRYPT_SUCCESS                    is the same
 * @retval CRYPT_NULL_INPUT                 Invalid null pointer input
 * @retval CRYPT_ECC_KEY_PUBKEY_NOT_EQUAL   Public keys are not equal
 * @retval CRYPT_ECC_POINT_ERR_CURVE_ID     Parameter curve IDs are not equal.
 * @retval CRYPT_ECC_ERR_POINT_FORMAT       Point compression formats are not equal
 * @retval For other error codes, see crypt_errno.h.
 */
int32_t ECC_PkeyCmp(const ECC_Pkey *a, const ECC_Pkey *b);
#else
#define ECC_PkeyCmp NULL
#endif

/**
 * @ingroup ecc
 * @brief Set the parameter of the ECC context
 *
 * @param ctx [IN] ECC context
 * @param para [IN] ECC parameter
 *
 * @retval CRYPT_SUCCESS succeeded.
 * @retval For details about other errors, see crypt_errno.h.
 */
int32_t ECC_SetPara(ECC_Pkey *ctx, ECC_Para *para);

#ifdef HITLS_CRYPTO_ECC_CHECK

/**
 * @ingroup ecc
 * @brief check the key pair consistency
 *
 * @param pkey1 [IN] ecc key context structure
 * @param pkey2 [IN] ecc key context structure
 * @param checkType [IN] check type
 *
 * @retval CRYPT_SUCCESS    check success.
 * Others. For details, see error code in errno.
 */
int32_t ECC_PkeyCheck(const ECC_Pkey *pkey1, const ECC_Pkey *pkey2, uint32_t checkType);

#endif // HITLS_CRYPTO_ECC_CHECK

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_ECC

#endif // CRYPT_ECC_PKEY_H
