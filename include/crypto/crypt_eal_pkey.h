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
 * @defgroup crypt_eal_pkey
 * @ingroup crypt
 * @brief the asym key module
 */

#ifndef CRYPT_EAL_PKEY_H
#define CRYPT_EAL_PKEY_H

#include <stdbool.h>
#include <stdint.h>
#include "crypt_algid.h"
#include "crypt_types.h"
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * @ingroup crypt_eal_pkey
 *
 * EAL public key structure
 */
typedef struct {
    CRYPT_PKEY_AlgId id; /**< Public Key Algorithm ID */
    union {
        CRYPT_RsaPub rsaPub; /**< RSA public key structure */
        CRYPT_DsaPub dsaPub; /**< DSA public key structure */
        CRYPT_DhPub dhPub;   /**< DH public key structure */
        CRYPT_EccPub eccPub; /**< ECC public key structure */
        CRYPT_Curve25519Pub curve25519Pub; /**< ed25519/x25519 public key structure */
        CRYPT_PaillierPub paillierPub; /**< Paillier public key structure */
        CRYPT_KemEncapsKey kemEk; /**< kem encaps key structure */
        CRYPT_ElGamalPub elgamalPub; /**< Elgamal public key structure */
		CRYPT_MlDsaPub mldsaPub;  /**< MLDSA public key structure */
        CRYPT_SlhDsaPub slhDsaPub; /**< SLH-DSA public key structure */
    } key;                           /**< Public key union of all algorithms */
} CRYPT_EAL_PkeyPub;

#define CRYPT_EAL_PKEY_UNKNOWN_OPERATE  0
#define CRYPT_EAL_PKEY_CIPHER_OPERATE   1
#define CRYPT_EAL_PKEY_EXCH_OPERATE     2
#define CRYPT_EAL_PKEY_SIGN_OPERATE     4
#define CRYPT_EAL_PKEY_KEM_OPERATE      8

/**
 * @ingroup crypt_eal_pkey
 *
 * EAL private key structure
 */
typedef struct {
    CRYPT_PKEY_AlgId id; /**< private key algorithm ID */
    union {
        CRYPT_RsaPrv rsaPrv; /**< RSA private key structure */
        CRYPT_DsaPrv dsaPrv; /**< DSA private key structure */
        CRYPT_DhPrv  dhPrv;  /**< DH private key structure */
        CRYPT_EccPrv eccPrv; /**< ECC private key structure */
        CRYPT_Curve25519Prv curve25519Prv; /**< ed25519/x25519 private key structure */
        CRYPT_PaillierPrv paillierPrv; /**< Paillier private key structure */
        CRYPT_KemDecapsKey kemDk; /**< kem decaps key structure */
        CRYPT_ElGamalPrv elgamalPrv; /**< ElGamal private key structure */
		CRYPT_MlDsaPrv mldsaPrv;  /**< MLDSA private key structure */
        CRYPT_SlhDsaPrv slhDsaPrv; /**< SLH-DSA private key structure */
    } key;                           /**<Private key union of all algorithms */
} CRYPT_EAL_PkeyPrv;

/**
 * @ingroup crypt_eal_pkey
 *
 * Structure used by the Para parameter of the asymmetric algorithm, including the algorithm ID and the
 * para combination of the corresponding algorithm.
 */
typedef struct {
    CRYPT_PKEY_AlgId id; /**< asymmetric algorithm ID */
    union {
        CRYPT_RsaPara rsaPara; /**< RSA Para structure */
        CRYPT_DsaPara dsaPara; /**< DSA Para structure */
        CRYPT_DhPara  dhPara;  /**< DH Para structure */
        CRYPT_EccPara eccPara; /**< ECC Para structure */
        CRYPT_PaillierPara paillierPara; /**< Paillier Para structure */
        CRYPT_ElGamalPara elgamalPara; /**< ElGamal Para structure */
    } para;                            /**<Para union of all algorithms */
} CRYPT_EAL_PkeyPara;

/**
 * @ingroup  crypt_eal_pkey
 *
 * Pkey session structure.
 */
typedef struct EAL_PkeyCtx CRYPT_EAL_PkeyCtx;

/**
 * @ingroup crypt_eal_pkey
 * @brief   Check whether the id is valid asymmetric algorithm ID.
 *
 * @param   id [IN] Asymmetric algorithm ID
 *
 * @retval   true, if the value is valid.
 *           false, if the value is invalid.
 */
bool CRYPT_EAL_PkeyIsValidAlgId(CRYPT_PKEY_AlgId id);

/* Pkey external interface */

/**
 * @ingroup crypt_eal_pkey
 * @brief   Create an asymmetric key pair structure.
 *
 * @param   id [IN] Algorithm ID
 *
 * @retval  CRYPT_EAL_PkeyCtx pointer.
 *          NULL, if the operation fails.
 */
CRYPT_EAL_PkeyCtx *CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_AlgId id);

/**
 * @ingroup crypt_eal_pkey
 * @brief   Create an asymmetric key pair structure in the providers.
 *
 * @param libCtx [IN] Library context
 * @param algId [IN] Asymmetric algorithm ID.
 * @param pkeyOperType [IN] Specify operation type.
 * @param attrName [IN] Specify expected attribute values
 *
 * @retval  CRYPT_EAL_PkeyCtx pointer.
 *          NULL, if the operation fails.
 */
CRYPT_EAL_PkeyCtx *CRYPT_EAL_ProviderPkeyNewCtx(CRYPT_EAL_LibCtx *libCtx, int32_t algId, uint32_t pkeyOperType,
    const char *attrName);

/**
 * @ingroup crypt_eal_pkey
 * @brief   Copy the pkey context.
 *
 * @param   to [IN/OUT] Target pkey context
 * @param   from [IN] Source pkey context
 *
 * @retval  #CRYPT_SUCCESS.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_PkeyCopyCtx(CRYPT_EAL_PkeyCtx *to, const CRYPT_EAL_PkeyCtx *from);

/**
 * @ingroup crypt_eal_pkey
 * @brief   Dup the Pkey context.
 *          After the duplication is complete, call the CRYPT_EAL_PkeyFreeCtx interface to release the memory.
 *
 * @param   ctx [IN] Source Pkey context
 *
 * @retval  CRYPT_EAL_PkeyCtx, Pkey context pointer.
 *          NULL, if the operation fails.
 */
CRYPT_EAL_PkeyCtx *CRYPT_EAL_PkeyDupCtx(const CRYPT_EAL_PkeyCtx *pkey);

/**
 * @ingroup crypt_eal_pkey
 * @brief   Release the asymmetric key pair structure.
 *
 * @param   pkey [IN] Pkey context, which need to be set NULL by the caller.
 */
void CRYPT_EAL_PkeyFreeCtx(CRYPT_EAL_PkeyCtx *pkey);

/**
 * @ingroup crypt_eal_pkey
 * @brief   Set the key parameters, the key parameter marked as "para" is applied for and released by the caller.
 *
 * @param   pkey [IN/OUT] Structure of the key pair to be set
 * @param   para [IN] Parameter
 *
 * @retval  #CRYPT_SUCCESS.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_PkeySetPara(CRYPT_EAL_PkeyCtx *pkey, const CRYPT_EAL_PkeyPara *para);

/**
 * @ingroup crypt_eal_pkey
 * @brief   Obtain the key parameter, the key parameter marked as "para" is applied for and released by the caller.
 *
 * @param   pkey [IN] Key pair structure
 * @param   para [OUT] Parameter to be received
 *
 * @retval  #CRYPT_SUCCESS.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_PkeyGetPara(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_EAL_PkeyPara *para);

/**
 * @ingroup crypt_eal_pkey
 * @brief   Set key parameters.
 *
 * @param   pkey [IN/OUT] Structure of the key pair to be set.
 * @param   id [IN] Parameter ID.
 *
 * @retval  #CRYPT_SUCCESS.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_PkeySetParaById(CRYPT_EAL_PkeyCtx *pkey, CRYPT_PKEY_ParaId id);

/**
 * @ingroup crypt_eal_pkey
 * @brief   Generate the key data.
 *
 * @param   pkey [IN/OUT] Key pair structure for receiving key data.
 *
 * @retval  #CRYPT_SUCCESS.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_PkeyGen(CRYPT_EAL_PkeyCtx *pkey);

/**
 * @ingroup crypt_eal_pkey
 * @brief   Set the public key. The caller applies for and releases memory for the public key marked as "key".
 *
 * @param   pkey [OUT] Key pair structure for receiving key data
 * @param   key  [IN] Public key data
 *
 * @retval  #CRYPT_SUCCESS.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_PkeySetPub(CRYPT_EAL_PkeyCtx *pkey, const CRYPT_EAL_PkeyPub *key);

/**
 * @ingroup crypt_eal_pkey
 * @brief   Extended interface to set the public key.
 *
 * This function is an extended version of CRYPT_EAL_PkeySetPub, which allows passing additional parameters
 * to meet more complex public key setting requirements.
 *
 * @param   pkey [OUT] Key pair structure for receiving key data
 * @param   param  [IN] Public key data
 *
 * @retval  #CRYPT_SUCCESS.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_PkeySetPubEx(CRYPT_EAL_PkeyCtx *pkey, const BSL_Param *param);

/**
 * @ingroup crypt_eal_pkey
 * @brief   Set the private key. The caller applies for and releases memory for the private key marked as "key".
 *
 * @param   pkey [OUT] Key pair structure for receiving key data
 * @param   key  [IN] Private key data
 *
 * @retval  #CRYPT_SUCCESS.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_PkeySetPrv(CRYPT_EAL_PkeyCtx *pkey, const CRYPT_EAL_PkeyPrv *key);

/**
 * @ingroup crypt_eal_pkey
 * @brief   Extended interface to set the private key.
 *
 * This function is an extended version of CRYPT_EAL_PkeySetPrv, which allows passing additional parameters
 * to meet more complex public key setting requirements.
 *
 * @param   pkey [OUT] Key pair structure for receiving key data
 * @param   param  [IN] Private key data
 *
 * @retval  #CRYPT_SUCCESS.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_PkeySetPrvEx(CRYPT_EAL_PkeyCtx *pkey, const BSL_Param *param);

/**
 * @ingroup crypt_eal_pkey
 * @brief   Obtain the public key. The caller applies for and releases memory for the public key marked as "key".
 *
 * @param   pkey [IN] Key session
 * @param   key  [OUT] Public key data
 *
 * @retval  #CRYPT_SUCCESS.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_PkeyGetPub(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_EAL_PkeyPub *key);

/**
 * @ingroup crypt_eal_pkey
 * @brief   Extended interface to obtain the public key.
 *
 * This function is an extended version of CRYPT_EAL_PkeyGetPub, which allows passing parameters
 * through the BSL_Param structure to meet more complex public key acquisition requirements.
 *
 * @param   pkey [IN] Key session
 * @param   param [IN] parameters
 *
 * @retval  #CRYPT_SUCCESS.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_PkeyGetPubEx(const CRYPT_EAL_PkeyCtx *pkey, BSL_Param *param);

/**
 * @ingroup crypt_eal_pkey
 * @brief   Obtain the private key. The caller applies for and releases memory for the private key marked as "key".
 *
 * @param   pkey [IN] Key session
 * @param   key  [OUT] Private key data
 *
 * @retval  #CRYPT_SUCCESS.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_PkeyGetPrv(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_EAL_PkeyPrv *key);

/**
 * @ingroup crypt_eal_pkey
 * @brief   Extended interface to obtain the private key.
 *
 * This function is an extended version of CRYPT_EAL_PkeyGetPrv, which allows passing parameters
 * through the BSL_Param structure to meet more complex public key acquisition requirements.
 *
 * @param   pkey [IN] Key session
 * @param   param  [OUT] Private key data
 *
 * @retval  #CRYPT_SUCCESS.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_PkeyGetPrvEx(const CRYPT_EAL_PkeyCtx *pkey, BSL_Param *param);

/**
 * @ingroup crypt_eal_pkey
 * @brief   Signature interface
 *
 * @param   pkey     [IN] Key session
 * @param   id       [IN] Hash algorithm ID.
 * @param   data     [IN] Plaintext data
 * @param   dataLen  [IN] Plaintext length. The maximum length is [0, 0xffffffff].
 * @param   sign     [OUT] Signature data. The length of the memory buff used to save the signature must be
 * greater than or equal to the key modulo length.
 * @param   signLen  [OUT/IN] Length of the signature data, You can obtain the value by calling
 * CRYPT_EAL_PkeyGetSignLen.
 *
 * @retval  #CRYPT_SUCCESS.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_PkeySign(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_MD_AlgId id, const uint8_t *data,
    uint32_t dataLen, uint8_t *sign, uint32_t *signLen);

/**
 * @ingroup crypt_eal_pkey
 * @brief   Signature verification interface
 *
 * @param   pkey      [IN] Key session
 * @param   id        [IN] Hash algorithm ID.
 * @param   data      [IN] Plaintext data
 * @param   dataLen   [IN] Plaintext length. The maximum length is [0,0xffffffff].
 * @param   sign      [IN] Signature data
 * @param   signLen   [IN] Length of the signature data
 *
 * @retval  #CRYPT_SUCCESS.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_PkeyVerify(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_MD_AlgId id, const uint8_t *data,
    uint32_t dataLen, const uint8_t *sign, uint32_t signLen);

/**
 * @ingroup crypt_eal_pkey
 * @brief   Sign hash data(RSA9796-2 Signature is not supported)
 *
 * @param   pkey      [IN] Key session
 * @param   hash      [IN] Hash data
 * @param   hashLen   [IN] Hash length.
 *                         When RSA is used for signature, the hash length should correspond to the
 *                         digest length of the hash algorithm on which the padding method depends.
 * @param   sign      [OUT] Signature data. The length of the memory buff used to save the signature
 *                          must be greater than or equal to the key module length.
 * @param   signLen   [OUT/IN]  Length of the signature data.
 *                              The value can be obtained by calling CRYPT_EAL_PkeyGetSignLen.
 *
 * @retval #CRYPT_SUCCESS, if successful.
 *         For other error codes see crypt_errno.h
 */
int32_t CRYPT_EAL_PkeySignData(const CRYPT_EAL_PkeyCtx *pkey, const uint8_t *hash, uint32_t hashLen,
    uint8_t *sign, uint32_t *signLen);

/**
 * @ingroup crypt_eal_pkey
 * @brief   Verify the signature of the hash data(RSA9796-2 Signature is not supported)
 *
 * @param   pkey     [IN] Key session
 * @param   hash     [IN] Hash data
 * @param   hashLen  [IN] Hash length.
 *                   When RSA is used for signature, the hash length should correspond to the digest
 *                   length of the hash algorithm on which the padding method depends.
 * @param   sign     [IN] Signature data
 * @param   signLen  [IN] Length of the signature data
 *
 * @retval  #CRYPT_SUCCESS, if successful.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_PkeyVerifyData(const CRYPT_EAL_PkeyCtx *pkey, const uint8_t *hash, uint32_t hashLen,
    const uint8_t *sign, uint32_t signLen);

/**
 * @ingroup crypt_eal_pkey
 * @brief   Encrypt data.
 *
 * @param   pkey      [IN] Key session
 * @param   data      [IN] Input plaintext data.
 * @param   dataLen   [IN] Input plaintext data length.
 * @param   out      [OUT] Encrypted data. The buff length of the memory used to store the encrypted data
 *                         must be greater than or equal to the key modulus length.
 * @param   outLen   [OUT/IN] Encrypted data length.
 *
 * @retval  #CRYPT_SUCCESS, if successful.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_PkeyEncrypt(const CRYPT_EAL_PkeyCtx *pkey, const uint8_t *data, uint32_t dataLen,
    uint8_t *out, uint32_t *outLen);

/**
 * @ingroup crypt_eal_pkey
 * @brief   Decrypt the data.
 *
 * @param   pkey      [IN] Key session
 * @param   data      [IN] Input ciphertext data.
 * @param   dataLen   [IN] Input ciphertext data length.
 * @param   out      [OUT] Decrypted data
 * @param   outLen   [OUT/IN] Length of the decrypted data.
 *
 * @retval  #CRYPT_SUCCESS, if successful.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_PkeyDecrypt(const CRYPT_EAL_PkeyCtx *pkey, const uint8_t *data, uint32_t dataLen,
    uint8_t *out, uint32_t *outLen);

/**
 * @ingroup crypt_eal_pkey
 * @brief Check whether the public and private keys match.
 *  Currently not supported in the provider, supported in the future
 *
 * @param   pubKey      [IN] Public key
 * @param   prvKey      [IN] private key
 *
 * @retval  #CRYPT_SUCCESS, if successful.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_PkeyPairCheck(CRYPT_EAL_PkeyCtx *pubKey, CRYPT_EAL_PkeyCtx *prvKey);

/**
 * @ingroup crypt_eal_pkey
 * @brief   Compute the shared key.
 *
 * @param   pkey         [IN] Key session
 * @param   pubKey       [IN] Public key session
 * @param   share        [OUT] Shared key
 * @param   shareLen     [IN/OUT] The input parameter is the share space length, and the output parameter is the
 * valid share space length, the required space can be obtained by calling the CRYPT_EAL_PkeyGetKeyLen interface.
 *
 * @retval  #CRYPT_SUCCESS, if successful.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_PkeyComputeShareKey(const CRYPT_EAL_PkeyCtx *pkey, const CRYPT_EAL_PkeyCtx *pubKey,
    uint8_t *share, uint32_t *shareLen);

/**
 * @ingroup crypt_eal_pkey
 * @brief   Obtain the number of bytes in the key length.
 *
 * @param   pkey [IN] Key session
 *
 * @retval  Key length, if successful.
 *          0, if failed.
 */
uint32_t CRYPT_EAL_PkeyGetKeyLen(const CRYPT_EAL_PkeyCtx *pkey);

/**
 * @ingroup  crypt_eal_pkey
 * @brief    Obtain the key security strength. Only supports CRYPT_PKEY_RSA and CRYPT_PKEY_ECDSA.
 *
 * @param   pkey [IN] Key session
 *
 * @retval  Key security strength, if successful.
 *          0, if failed.
 */
uint32_t CRYPT_EAL_PkeyGetSecurityBits(const CRYPT_EAL_PkeyCtx *pkey);

/**
 * @ingroup crypt_eal_pkey
 * @brief   Obtain the number of bits in the key length.
 *
 * @param   pkey [IN] Key session
 *
 * @retval  Number of key bits, if successful.
 *          0, if failed.
 */
uint32_t CRYPT_EAL_PkeyGetKeyBits(const CRYPT_EAL_PkeyCtx *pkey);

/**
 * @ingroup crypt_eal_pkey
 * @brief   Obtains the signature length of the key for signature, only support algorithm that can be signed.
 *
 * @param   pkey [IN] Key session
 *
 * @retval  Signature length, if successful.
 *          0, if failed.
 */
uint32_t CRYPT_EAL_PkeyGetSignLen(const CRYPT_EAL_PkeyCtx *pkey);

/**
 * @ingroup crypt_eal_pkey
 * @brief   Make specific option for setting/obtain, supported option can see the structure of CRYPT_PkeyCtrl.
 *
 * @param   pkey [IN] Key session
 * @param   opt [IN] Option information
 * @param   val [IN/OUT] Data to be set/obtained
 * @param   len [IN] Length of the data marked as "val"
 *
 * @retval  #CRYPT_SUCCESS, if successful.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_PkeyCtrl(CRYPT_EAL_PkeyCtx *pkey, int32_t opt, void *val, uint32_t len);

/**
 * @ingroup crypt_eal_pkey
 * @brief   Perform blind operation on input data using the specified algorithm.
 *          For RSA BSSA, users need to ensure sufficient entropy in the message if the input has low entropy.
 * @param   pkey [IN] Key session
 * @param   id [IN] md Id for input.
 * @param   input [IN] Data to be blinded
 * @param   inputLen [IN] Length of input data
 * @param   out [OUT] Blinded output data
 * @param   outLen [OUT] Length of blinded data
 *
 * @retval  #CRYPT_SUCCESS, if successful.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_PkeyBlind(CRYPT_EAL_PkeyCtx *pkey, CRYPT_MD_AlgId id, const uint8_t *input, uint32_t inputLen,
    uint8_t *out, uint32_t *outLen);

/**
 * @ingroup crypt_eal_pkey
 * @brief   Perform unblind operation on blinded data.
 *
 * @param   pkey [IN] Key session
 * @param   input [IN] Blinded data to be unblinded
 * @param   inputLen [IN] Length of blinded data
 * @param   out [OUT] Unblinded output data
 * @param   outLen [OUT] Length of unblinded data
 *
 * @retval  #CRYPT_SUCCESS, if successful.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_PkeyUnBlind(CRYPT_EAL_PkeyCtx *pkey, const uint8_t *input, uint32_t inputLen,
    uint8_t *out, uint32_t *outLen);

/**
 * @ingroup crypt_eal_pkey
 * @brief   Obtain the key algorithm type.
 *
 * @param   pkey [IN] Key session
 *
 * @retval  Key algorithm type
 */
CRYPT_PKEY_AlgId CRYPT_EAL_PkeyGetId(const CRYPT_EAL_PkeyCtx *pkey);

/**
 * @ingroup crypt_eal_pkey
 * @brief   Obtain the key algorithm parameter ID.
 *
 * @param   pkey [IN] Key session
 *
 * @retval  Algorithm parameter ID
 */
CRYPT_PKEY_ParaId CRYPT_EAL_PkeyGetParaId(const CRYPT_EAL_PkeyCtx *pkey);


/**
 * @ingroup crypt_eal_pkey
 * @brief   Compare keys or parameters
 *
 * @param   a [IN] Key session
 * @param   b [IN] Key session
 *
 * @retval  #CRYPT_SUCCESS, a and b are the same(include both a and b are null)
 * @retval  #CRYPT_NULL_INPUT, incorrect null pointer input.
 * @retval  For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_PkeyCmp(const CRYPT_EAL_PkeyCtx *a, const CRYPT_EAL_PkeyCtx *b);

/**
 * @ingroup crypt_eal_pkey
 * @brief   Set the user's personal data.
 *
 * @param   pkey [IN] Key session
 * @param   data [IN] Pointer to the user's personal data
 *
 * @retval  #CRYPT_SUCCESS, if successful.
 * @retval  #CRYPT_NULL_INPUT, if pkey is NULL.
 */
int32_t CRYPT_EAL_PkeySetExtData(CRYPT_EAL_PkeyCtx *pkey, void *data);

/**
 * @ingroup crypt_eal_pkey
 * @brief   Obtain the user's personal data.
 *
 * @param   pkey [IN] Key session
 *
 * @retval  void*(user personal data pointer), which indicates successful.
 *          NULL, which indicates failed.
 */
void *CRYPT_EAL_PkeyGetExtData(const CRYPT_EAL_PkeyCtx *pkey);

/**
 * @ingroup crypt_eal_pkey
 * @brief   EAL layer reference counting auto-increment
 *
 * @param   pkey [IN] Key session
 *
 * @retval  #CRYPT_SUCCESS.
 *          For other error codes see crypt_errno.h.
 */
int32_t CRYPT_EAL_PkeyUpRef(CRYPT_EAL_PkeyCtx *pkey);

/**
 * @ingroup crypt_eal_pkey
 * @brief Initialize asymmetric key encapsulation context
 *
 * @param pkey [in] Pointer to the key context
 * @param params [in] Algorithm parameters
 *
 * @retval  #CRYPT_SUCCESS.
 *          For other error codes see crypt_errno.h.
 */
int32_t CRYPT_EAL_PkeyEncapsInit(CRYPT_EAL_PkeyCtx *pkey, BSL_Param *params);

/**
 * @ingroup crypt_eal_pkey
 * @brief Initialize asymmetric key decapsulation context
 *
 * @param pkey [in] Pointer to the key context
 * @param params [in] Algorithm parameters
 *
 * @retval  #CRYPT_SUCCESS.
 *          For other error codes see crypt_errno.h.
 */
int32_t CRYPT_EAL_PkeyDecapsInit(CRYPT_EAL_PkeyCtx *pkey, BSL_Param *params);

/**
 * @ingroup crypt_eal_pkey
 * @brief Perform key encapsulation operation
 *
 * @param pkey [in] Initialized key context
 * @param cipher [out] Output buffer for encapsulated ciphertext
 * @param cipherLen [in,out] Input: buffer capacity, Output: actual ciphertext length
 * @param sharekey [out] Output buffer for shared secret
 * @param shareKeyLen [in,out] Input: buffer capacity, Output: actual secret length
 *
 * @retval  #CRYPT_SUCCESS.
 *          For other error codes see crypt_errno.h.
 */
int32_t CRYPT_EAL_PkeyEncaps(const CRYPT_EAL_PkeyCtx *pkey, uint8_t *cipher, uint32_t *cipherLen, uint8_t *sharekey,
    uint32_t *shareKeyLen);

/**
 * @ingroup crypt_eal_pkey
 * @brief Perform key decapsulation operation
 *
 * @param pkey [in] Initialized key context
 * @param cipher [in] Input encapsulated ciphertext
 * @param cipherLen [in] Length of the input ciphertext
 * @param sharekey [out] Output buffer for shared secret
 * @param shareKeyLen [in,out] Input: buffer capacity, Output: actual secret length
 *
 * @retval  #CRYPT_SUCCESS.
 *          For other error codes see crypt_errno.h.
 */
int32_t CRYPT_EAL_PkeyDecaps(const CRYPT_EAL_PkeyCtx *pkey, uint8_t *cipher, uint32_t cipherLen, uint8_t *sharekey,
    uint32_t *shareKeyLen);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // CRYPT_EAL_PKEY_H
