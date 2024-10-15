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

#ifndef SM2_LOCAL_H
#define SM2_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SM2

#include <stdint.h>
#include "crypt_sm2.h"
#include "crypt_local_types.h"
#include "crypt_ecc_pkey.h"
#include "sal_atomic.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

#define SM2_MAX_ID_BITS 65535
#define SM2_MAX_ID_LENGTH (SM2_MAX_ID_BITS / 8)
#define SM2_MAX_PUBKEY_DATA_LENGTH 256
#define MAX_MD_SIZE 64
#define SM3_MD_SIZE 32
#define SM2_POINT_SINGLE_COORDINATE_LEN 32
#define SM2_POINT_COORDINATE_LEN 65
#define SM2_TWO_POINT_COORDINATE_LEN 128
#define SM2_X_LEN 32

/* SM2 key context */
struct SM2_Ctx {
    ECC_Pkey *pkey;
    uint32_t pkgImpl;
    ECC_Point *pointR; // Local R
    const EAL_MdMethod *hashMethod;
    BN_BigNum *r; // Local r
    uint8_t *userId;   // User ID
    uint32_t userIdLen;   // the length of User ID
    int32_t server;    // 1: the initiator, 0: the receiver, and the default value is 1.
    uint8_t sumCheck[SM3_MD_SIZE]; // Hash value used as a check
    uint8_t sumSend[SM3_MD_SIZE]; // Hash value sent to the peer end
    uint8_t isSumValid; // Indicates whether the checksum is valid. 1: valid; 0: invalid.
    BSL_SAL_RefCount references;
};

/**
 * @ingroup sm2
 * @brief The sm2 invokes the SM3 to calculate the hash value.
 *
 * @param ctx [IN] sm2 context structure
 * @param out [IN/OUT] Hash value
 * @param outLen [IN/OUT] Length of the hash value
 *
 * @retval CRYPT_SUCCESS    calculated successfully.
 * @retval Other: The calculation fails. For details about the return value type, see crypt_errno.h.
 */
int32_t Sm2ComputeZDigest(const CRYPT_SM2_Ctx *ctx, uint8_t *out, uint32_t *outLen);

#if defined(HITLS_CRYPTO_SM2_EXCH) || defined(HITLS_CRYPTO_SM2_CRYPT)
/**
 * @ingroup sm2
 * @brief sm2 kdf function
 *
 * @param out [IN/OUT] Calculation result
 * @param outlen [IN/OUT] Output data length
 * @param z [IN] Input data
 * @param zlen [IN] Length of the input data
 * @param hashMethod [IN] hash method
 *
 * @retval CRYPT_SUCCESS    calculated successfully.
 * @retval Other: The calculation fails. For details about the return value type, see crypt_errno.h.
 */
int32_t KdfGmt0032012(uint8_t *out, const uint32_t *outlen, const uint8_t *z, uint32_t zlen,
    const EAL_MdMethod *hashMethod);
#endif

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_SM2

#endif // SM2_LOCAL_H
