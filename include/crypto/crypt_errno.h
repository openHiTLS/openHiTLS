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
 * @defgroup crypt_errno
 * @ingroup crypt
 * @brief error number module of crypto module
 */

#ifndef CRYPT_ERRNO_H
#define CRYPT_ERRNO_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup crypt_errno
 * @brief   Return success
 */
#define CRYPT_SUCCESS 0

/**
 * @ingroup crypt_errno
 *
 * CRYPTO module return value.
 */
enum CRYPT_ERROR {
    CRYPT_NULL_INPUT = 0x01010001,      /**< Null pointer input error, bufferLen is 0. */
    CRYPT_SECUREC_FAIL,                 /**< Security function  returns an error. */
    CRYPT_MEM_ALLOC_FAIL,               /**< Failed to apply for memory. */
    CRYPT_NO_REGIST_RAND,               /**< The global random number is not registered.*/
    CRYPT_ERR_ALGID,                    /**< Incorrect algorithm ID. */
    CRYPT_INVALID_ARG,                  /**< Invalid input parameter. */
    CRYPT_NOT_SUPPORT,                  /**< unsupported operation. */
    CRYPT_INCONSISTENT_OPERATION,       /**< Inconsistent operation. */
    CRYPT_MEM_CPY_FAIL,                 /**< Failed to copy memory. */
    CRYPT_INVALID_KEY,                  /**< invalid key. */
    CRYPT_PAIRWISE_CHECK_FAIL,          /**< key-pair check failed. */
    CRYPT_CALLBACK_ERROR,               /**< Get an error in the callback function. */

    CRYPT_BN_BUFF_LEN_NOT_ENOUGH = 0x01020001, /**< Insufficient buffer length. */
    CRYPT_BN_SPACE_NOT_ENOUGH,          /**< Insufficient big number space. */
    CRYPT_BN_BITS_TOO_MAX,              /**< The maximum bit limit is exceeded of the big number. */
    CRYPT_BN_RAND_GEN_FAIL,             /**< Failed to generate the random number. */
    CRYPT_BN_OPTIMIZER_STACK_FULL,      /**< Optimizer stack is full. */
    CRYPT_BN_NO_NEGATIVE_ZERO,          /**< The big number is set to a positive number only. */
    CRYPT_BN_ERR_RAND_ZERO,             /**< Generates a random number smaller than 0. */
    CRYPT_BN_ERR_RAND_NEGATIVE,         /**< Generate a negative random number. */
    CRYPT_BN_ERR_RAND_TOP_BOTTOM,       /**< The top or bottom is invalid during random number generation. */
    CRYPT_BN_ERR_RAND_BITS_NOT_ENOUGH,  /**< The bit is too small during random number generation. */
    CRYPT_BN_OPTIMIZER_GET_FAIL,        /**< Failed to obtain the space from the optimizer. */
    CRYPT_BN_ERR_DIVISOR_ZERO,          /**< The divisor cannot be 0. */
    CRYPT_BN_ERR_EXP_NO_NEGATIVE,       /**< The value of exponent cannot be negative. */
    CRYPT_BN_MONT_BASE_TOO_MAX,         /**< Montgomery module exponentiation base is too large. */
    CRYPT_BN_NOR_GEN_PRIME,             /**< Prime Number Generation Failure. */
    CRYPT_BN_NOR_CHECK_PRIME,           /**< prime number check failed. */
    CRYPT_BN_ERR_GCD_NO_ZERO,           /**< The maximum common divisor cannot contain 0. */
    CRYPT_BN_ERR_NO_INVERSE,            /**< Cannot obtain the inverse module. */
    CRYPT_BN_ERR_SQRT_PARA,             /**< The parameter is incorrect when modulus square root. */
    CRYPT_BN_ERR_LEGENDE_DATA,          /**< Failed to find a specific number for z to p's Legendre sign (z|p)
                                             equal to -1 when calculating the square root. */
    CRYPT_BN_ERR_NO_SQUARE_ROOT,        /**< The square root cannot be found. */
    CRYPT_BN_ERR_MASKCOPY_LEN,          /**< Data lengths are inconsistent when data is copied with masks. */
    CRYPT_BN_ERR_QUICK_MODDATA,         /**< Uses the BN_ModNistEccMul and BN_ModNistEccSqr interfaces,
                                             the module data is not supported. */

    CRYPT_BN_FLAG_INVALID,              /**< Invalid big number flag. */
    CRYPT_BN_CONVERT_INPUT_INVALID,     /**< Invalid input parameter of big number strings. */
    CRYPT_BN_NOT_SUPPORT_EXTENSION,     /**< The big number does not support dynamic extension. */
    CRYPT_BN_INPUT_INVALID,             /**< Invalid external big number input. */
    CRYPT_BN_BITS_INVALID,              /**< The bits of the big number exceeds the limit. */
    CRYPT_BN_ERR_SWAP_LEN,              /**< Data lengths are inconsistent when data is swapped with masks. */

    CRYPT_RSA_BUFF_LEN_NOT_ENOUGH = 0x01030001, /**< The buffer length is insufficient. */
    CRYPT_RSA_NO_KEY_INFO,              /**< Lacks valid key information. */
    CRYPT_RSA_ERR_KEY_BITS,             /**< Incorrect key length. */
    CRYPT_RSA_ERR_E_VALUE,              /**< The value of parameter e is incorrect. */
    CRYPT_RSA_NOR_KEYGEN_FAIL,          /**< Key generation failure, it's normal error. */
    CRYPT_RSA_NOR_VERIFY_FAIL,          /**< Failed to verify the signature. it's normal error. */
    CRYPT_RSA_ERR_ENC_BITS,             /**< Incorrect length of the encrypted plaintext of the public key. */
    CRYPT_RSA_ERR_DEC_BITS,             /**< Incorrect length of the decrypted ciphertext of the private key. */
    CRYPT_RSA_ERR_PSS_SALT_LEN,         /**< Incorrect salt length of the PSS operation. */
    CRYPT_RSA_ERR_PSS_SALT_DATA,        /**< PSS operation salt data error, failed to compare the salt extracted
                                             during signature verification with the user's input. */
    CRYPT_RSA_ERR_PKCSV15_SALT_LEN,     /**< Incorrect salt length of the PKCSV15 operation. */
    CRYPT_RSA_ERR_PKCSV15_SALT_DATA,    /**< PKCSV15 salt data error. */
    CRYPT_RSA_ERR_INPUT_VALUE,          /**< Some special values, which are used as input errors. */
    CRYPT_RSA_ERR_MD_ALGID,             /**< The hash ID of the input parameter is incorrect when
                                             the pkcs1.5 padding mode is set. */
    CRYPT_RSA_PAD_NO_SET_ERROR,         /**< Padding information is not set when using RSA key for
                                             signature verification. */
    CRYPT_RSA_CTRL_NOT_SUPPORT_ERROR,   /**< The Ctrl type is not supported When RSA is used for Ctrl. */
    CRYPT_RSA_SET_SALT_NOT_PSS_ERROR,   /**< When the padding type of the key is not pss, and set the salt
                                             information, return failure. */
    CRYPT_RSA_SET_EMS_PKCSV15_LEN_ERROR,/**< Sets the PKCSV15 padding information, the length of the input data
                                             is incorrect and return failure. */
    CRYPT_RSA_SET_EMS_PSS_LEN_ERROR,    /**< Sets the PSS padding information, the length of the input data is
                                             incorrect, and return failure. */
    CRYPT_RSA_SET_RSAES_OAEP_LEN_ERROR, /**< Sets the OAEP padding information, the length of the input data
                                             is incorrect and return failure. */
    CRYPT_RSA_SET_FLAG_LEN_ERROR,       /**< The length of the input data is incorrect and return failure When
                                             sets the flag. */
    CRYPT_RSA_FLAG_NOT_SUPPORT_ERROR,   /**< Unsupported flag. */
    CRYPT_RSA_ERR_SALT_LEN,             /**< Salt length error. */
    CRYPT_RSA_ERR_ALGID,                /**< The hash ID of the input parameter is incorrect or conflict occurs when
                                             sets the signature, signature verification, and padding parameters. */
    CRYPT_RSA_ERR_GEN_SALT,             /**< An error is returned when salt information fails to be generated
                                             during PSS signature. */
    CRYPT_RSA_ERR_ENC_INPUT_NOT_ENOUGH, /**< The plaintext length is too short for RSA NO PAD encryption. */
    CRYPT_RSA_ERR_DATA_LEN,             /**< Incorrect encryption length. */
    CRYPT_RSA_ERR_PAD_NUM,              /**< Incorrect padding length. */
    CRYPT_RSA_PUBKEY_NOT_EQUAL,         /**< RSA public keys are not equal. */
    CRYPT_RSA_KEYPAIRWISE_CONSISTENCY_FAILURE,   /**< RSA pair-wise consistency failure. */
    CRYPT_RSA_ERR_BLIND_TYPE,           /**< Invalid RSA blinding type. Only RSA-BSSA is currently supported. */
    CRYPT_RSA_ERR_NO_BLIND_INFO,        /**< RSA blinding information is missing.
                                            The blind/unblind operation requires previous blinding parameters. */
    CRYPT_RSA_ERR_NO_PUBKEY_INFO,       /**< The rsa pub key is missing. */
    CRYPT_RSA_PADDING_NOT_SUPPORTED,    /**< The specified RSA padding mode is not supported in blinding. */
    CRYPT_RSA_ERR_BSSA_PARAM,           /**< The param of bssa is not invalid. */
    CRYPT_RSA_GET_SALT_LEN_ERROR,       /**< The input length of getting salt-len is incorrect. */
    CRYPT_RSA_GET_SALT_NOT_PSS_ERROR,   /**< When the padding type of the key is not pss, and get the salt len. */
    CRYPT_RSA_ERR_PSS_PARAMS,            /**< The parameter is error when the padding type of the key is pss. */
    CRYPT_RSA_ERR_NO_PRVKEY_INFO,       /**< The rsa prv key is missing. */
    CRYPT_RSA_ERR_INVALID_PRVKEY,       /**< The private key is invalid. */

    CRYPT_EAL_BUFF_LEN_NOT_ENOUGH = 0x01040001, /**< Insufficient buffer length. */
    CRYPT_EAL_BUFF_LEN_TOO_LONG,        /**< Insufficient buffer length. */
    CRYPT_EAL_ERR_ALGID,                /**< Incorrect algorithm ID. */
    CRYPT_EAL_ALG_NOT_SUPPORT,          /**< Algorithm not supported, algorithm behavior not supported. */
    CRYPT_EAL_ERR_NEW_PARA_FAIL,        /**< Failed to generate parameters. */
    CRYPT_EAL_ERR_RAND_WORKING,         /**< DRBG is in the working state. */
    CRYPT_EAL_ERR_RAND_NO_WORKING,      /**< DRBG is not working. */
    CRYPT_EAL_ERR_METH_NULL_MEMBER,     /**< The method variable member is NULL. */
    CRYPT_EAL_ERR_GLOBAL_DRBG_NULL,     /**< The global DRBG is null. */
    CRYPT_EAL_ERR_DRBG_REPEAT_INIT,     /**< DRBG is initialized repeatedly. */
    CRYPT_EAL_ERR_DRBG_INIT_FAIL,       /**< DRBG initialization failure. */
    CRYPT_EAL_ERR_STATE,                /**< The usage process is incorrect. For example, run the update
                                             command without running the init command.
                                             For details, see related algorithms. */
    CRYPT_EAL_CIPHER_DATA_ERROR,        /**< Data error occurs when unpadding the decrypted data.
                                             For X923, the last bit is the length of the original data, and the
                                             rest data is 0, if this requirement is not met, an error is reported.
                                             For pkcs, all padding data is
                                             (the length of the padding data - the length of the original data),
                                             if this requirement is not met,an error will be reported.
                                             For ISO7816, the first bit of padding data is 0x80, and the other bits
                                             are 0, if this requirement is not met, an error will be reported. */
    CRYPT_EAL_PADDING_NOT_SUPPORT,      /**< Unsupported padding. */
    CRYPT_EAL_CIPHER_CTRL_ERROR,        /**< CRYPT_EAL_CipherCtrl interface unsupported CTRL type. */
    CRYPT_EAL_CIPHER_FINAL_WITH_AEAD_ERROR,  /**< An error occurs when the final operation is performed on the
                                                  AEAD algorithm. */
    CRYPT_EAL_PKEY_CTRL_ERROR,          /**< When the CRYPT_EAL_PkeyCtrl interface performs CTRL,
                                             the function is not supported or the input length is incorrect. */
    CRYPT_EAL_MAC_CTRL_TYPE_ERROR,      /**< When the CRYPT_EAL_PkeyCtrl interface performs CTRL,
                                             the function is not supported or the input length is incorrect. */
    CRYPT_EAL_PKEY_DUP_ERROR,           /**< Pkey context duplicate failure. */
    CRYPT_EAL_PKEY_CMP_DIFF_KEY_TYPE,   /**< Pkey comparison failure: different algorithm types. */
    CRYPT_EAL_ERR_PART_OVERLAP,         /**< Some memory overlap. */
    CRYPT_EAL_INTO_TYPE_NOT_SUPPORT,    /**< The info type is not supported. */
    CRYPT_EAL_ALG_ASM_NOT_SUPPORT,      /**< Algorithm assembly is not supported. */
    CRYPT_EAL_CIPHER_ERR_NEWCTX,
    CRYPT_EAL_PKEY_CHECK_ERROR,         /**< Pkey check failure. */
    CRYPT_EAL_MD_METH_NULL,

    CRYPT_SHA2_INPUT_OVERFLOW = 0x01050001, /**< The length of the input data exceeds the maximum
                                                     processing range of SHA2. */
    CRYPT_SHA2_OUT_BUFF_LEN_NOT_ENOUGH,     /**< The length of the buffer that storing the output
                                             result is insufficient. */

    CRYPT_DRBG_ERR_STATE = 0x01060001,  /**< DRBG status error. */
    CRYPT_DRBG_FAIL_GET_ENTROPY,        /**< Failed to obtain the entropy. */
    CRYPT_DRBG_FAIL_GET_NONCE,          /**< Failed to obtain the nonce. */
    CRYPT_DRBG_ALG_NOT_SUPPORT,         /**< Does not support the given algorithm. */
    CRYPT_DRBG_INVALID_LEN,             /**< Incorrect data length. */
    CRYPT_DRBG_PARAM_ERROR,             /**< Incorrect input parameter. */

    CRYPT_CURVE25519_NO_PUBKEY = 0x01080001,    /**< No public key. */
    CRYPT_CURVE25519_NO_PRVKEY,                 /**< No private key. */
    CRYPT_CURVE25519_KEYLEN_ERROR,              /**< Incorrect key length. */
    CRYPT_CURVE25519_SIGNLEN_ERROR,             /**< Incorrect signature length. */
    CRYPT_CURVE25519_HASH_METH_ERROR,           /**< Hash method is not SHA512. */
    CRYPT_CURVE25519_VERIFY_FAIL,               /**< Signature verification fails due to incorrect signature. */
    CRYPT_CURVE25519_NO_HASH_METHOD,            /**< Hash method not set. */
    CRYPT_CURVE25519_UNSUPPORTED_CTRL_OPTION,   /**< Unsupported mode of operation. */
    CRYPT_CURVE25519_KEY_COMPUTE_FAILED,        /**< Failed to generate the shared key. */
    CRYPT_CURVE25519_INVALID_PUBKEY,            /**< Invalid public key. */
    CRYPT_CURVE25519_PUBKEY_NOT_EQUAL,          /**< Public keys are not equal. */
    CRYPT_CURVE25519_INVALID_PRVKEY,                   /**< Invalid private key. */
    CRYPT_CURVE25519_PAIRWISE_CHECK_FAIL,              /**< The public and private keys are inconsistent. */

    CRYPT_SHA1_INPUT_OVERFLOW = 0x01090001,          /**< The length of the input data exceeds the
                                                           maximum processing range of SHA1. */
    CRYPT_SHA1_OUT_BUFF_LEN_NOT_ENOUGH,              /**< The length of the buffer that storing
                                                          the output result is insufficient. */

    CRYPT_ENTROPY_RCT_FAILURE = 0x010A0001,          /**< RCT detection fails, restart the entropy source. */
    CRYPT_ENTROPY_APT_FAILURE,                       /**< APT detection fails, restart the entropy source. */
    CRYPT_ENTROPY_CONDITION_FAILURE,                 /**< Processing method error after invoking. */
    CRYPT_ENTROPY_RANGE_ERROR,                       /**< Entropy source generation range error */
    CRYPT_ENTROPY_ECF_ALG_ERROR,                     /**< Entropy source conditioning algorithm is incorrect. */
    CRYPT_ENTROPY_ECF_IS_ERROR,                      /**< Entropy source conditioning is incorrect. */
    CRYPT_ENTROPY_ES_CREATE_ERROR,                   /**< Entropy pool creation error. */
    CRYPT_ENTROPY_ES_STATE_ERROR,                    /**< Incorrect entropy pool status. */
    CRYPT_ENTROPY_ES_CTRL_ERROR,                     /**< Incorrect entropy pool settings. */
    CRYPT_ENTROPY_ES_NO_NS,                          /**< No available noise source in the entropy pool. */
    CRYPT_ENTROPY_ES_NS_NOT_FOUND,                   /**< Noise source not found. */
    CRYPT_ENTROPY_ES_DUP_NS,                         /**< Noise source Repetition. */
    CRYPT_ENTROPY_ES_NS_NOT_AVA,                     /**< Noise source not available. */
    CRYPT_ENTROPY_ES_NS_FULL,                        /**< Noise source list is full. */
    CRYPT_ENTROPY_ES_CF_NOT_SUPPORT,                 /**< Nonditioning function not supported. */
    CRYPT_ENTROPY_ES_CF_ERROR,                       /**< Nonditioning function error. */
    CRYPT_ENTROPY_ES_ENTROPY_NOT_ENOUGH,             /**< Not getting enough entropy. */
    CRYPT_ENTROPY_ES_POOL_ERROR,                     /**< Entropy pool error. */
    CRYPT_ENTROPY_ES_POOL_INSUFFICIENT,              /**< Entropy pool capacity is insufficient. */
    CRYPT_ENTROPY_CTRL_INVALID_PARAM,                /**< Entropy invalid parameter. */

    CRYPT_DSA_BUFF_LEN_NOT_ENOUGH = 0x010B0001, /**< Insufficient buffer length. */
    CRYPT_DSA_ERR_KEY_PARA,                     /**< Incorrect key parameter data. */
    CRYPT_DSA_ERR_KEY_INFO,                     /**< Incorrect key information. */
    CRYPT_DSA_VERIFY_FAIL,                      /**< Verification failure. */
    CRYPT_DSA_ERR_TRY_CNT,                      /**< Key generation and signature fail to be
                                                     generated within the specified number of attempts. */
    CRYPT_DSA_DECODE_FAIL,                      /**< Data decoding fails, the data does not meet
                                                     the decoding requirements. */
    CRYPT_DSA_UNSUPPORTED_CTRL_OPTION,          /**< Unsupported mode of operation. */
    CRYPT_DSA_PARA_ERROR,                       /**< The value of the key parameter does not meet
                                                     the requirements. The ctx command does not
                                                     contain necessary parameter information. */
    CRYPT_DSA_PUBKEY_NOT_EQUAL,                 /**< Public keys are not equal. */
    CRYPT_DSA_PARA_NOT_EQUAL,                   /**< Key parameters are not equal. */
    CRYPT_DSA_PKEY_ERR_SIGN_DATA_LEN,
    CRYPT_DSA_INVALID_PRVKEY,                   /**< Invalid private key. */
    CRYPT_DSA_PAIRWISE_CHECK_FAIL,              /**< The public and private keys are inconsistent. */

    CRYPT_HMAC_OUT_BUFF_LEN_NOT_ENOUGH = 0x010C0001, /**< The length of the buffer that storing
                                                          the output result is insufficient. */
    CRYPT_HMAC_ERR_UNSUPPORTED_CTRL_OPTION,  /**< Unsupport the control type. */
    CRYPT_HMAC_ERR_NO_MD_LIB_CTX,            /**< MD library context not set. */
    CRYPT_HMAC_PARAM_ERROR,                  /**< Incorrect input parameter. */

    CRYPT_DH_BUFF_LEN_NOT_ENOUGH = 0x010D0001,   /**< The buffer length is insufficient. */
    CRYPT_DH_PARA_ERROR,                         /**< The value of the key parameter does not meet
                                                      the requirements, the ctx command does not
                                                      contain necessary parameter information. */
    CRYPT_DH_KEYINFO_ERROR,                      /**< The value of the public and private keys do
                                                      not meet the requirements, the ctx does not
                                                      contain the necessary public and private keys. */
    CRYPT_DH_RAND_GENERATE_ERROR,                /**< Key generation fails within the specified
                                                      number of attempts. */
    CRYPT_DH_PAIRWISE_CHECK_FAIL,                /**< The public and private keys are inconsistent. */
    CRYPT_DH_UNSUPPORTED_CTRL_OPTION,            /**< Unsupported mode of operation. */
    CRYPT_DH_CREATE_PARA_FAIL,                   /**< Failed to create the p, q, and g parameters
                                                      of the DH algorithm. */
    CRYPT_DH_PUBKEY_NOT_EQUAL,                   /**< Public keys are not equal. */
    CRYPT_DH_PARA_NOT_EQUAL,                     /**< DH key parameters are not equal. */
    CRYPT_DH_SET_FLAG_LEN_ERROR,                 /**< The length of the input data is incorrect and return failure when
                                                      setting the flag. */
    CRYPT_DH_FLAG_NOT_SUPPORT_ERROR,             /**< Unsupported flag. */
    CRYPT_DH_INVALID_PRVKEY,                     /**< Invalid private key. */

    CRYPT_CHACHA20_KEYLEN_ERROR = 0x010E0001,        /**< The key length input is incorrect during key setting. */
    CRYPT_CHACHA20_NONCELEN_ERROR,                   /**< The length of the input nounce is incorrect when you
                                                          set the nounce. */
    CRYPT_CHACHA20_COUNTLEN_ERROR,                   /**< The length of the input count is incorrect when you
                                                          set the count. */
    CRYPT_CHACHA20_NO_KEYINFO,                       /**< Lack of valid key information during
                                                          encryption and decryption. */
    CRYPT_CHACHA20_NO_NONCEINFO,                     /**< Lack of valid nounce information during
                                                          encryption and decryption. */
    CRYPT_CHACHA20_CTRLTYPE_ERROR,                   /**< The input type is not supported when the
                                                          ctrl interface is used. */

    CRYPT_AES_ERR_KEYLEN = 0x010F0001,               /**< Incorrect key length. */

    CRYPT_MODES_TAGLEN_ERROR = 0x01100001,           /**< In AEAD mode, the length of the TAG
                                                          is incorrect when the tag is obtained and verified. */
    CRYPT_MODES_IVLEN_ERROR,                         /**< The length of the input IV is incorrect
                                                          when setting the IV. */
    CRYPT_MODES_KEYUSE_TOOMANY_TIME,                 /**< In GCM mode, the number of times that a key
                                                          can be used for encryption and decryption is limited.
                                                          When the number of times that a key is used exceeds
                                                          the limit, an error is reported. */
    CRYPT_MODES_CRYPTLEN_OVERFLOW,                   /**< In AEAD mode, the length of the plaintext
                                                          or ciphertext input for a single
                                                          encryption exceeds the limit. */
    CRYPT_MODES_CTRL_TAGLEN_ERROR,                   /**< In GCM or CCM mode, the length of the input
                                                          parameter or the length of the input
                                                          parameter data is incorrect when the ctrl
                                                          interface is used to set the tag length. */
    CRYPT_MODES_AAD_REPEAT_SET_ERROR,                /**< In the AEAD mode, the AAD information
                                                          is set repeatedly. */
    CRYPT_MODE_BUFF_LEN_NOT_ENOUGH,                  /**< The buffer length is insufficient. */
    CRYPT_MODE_ERR_INPUT_LEN,                        /**< The function input length is not the
                                                          expected length. */
    CRYPT_MODES_CTRL_TYPE_ERROR,                     /**< The input type is not supported when the ctrl
                                                          interface is used. */
    CRYPT_MODES_AAD_IS_SET_ERROR,                    /**< In ccm mode, an error is returned when the tagLen and
                                                          msgLen are set after the aad is set. */
    CRYPT_MODES_MSGLEN_OVERFLOW,                     /**< In ccm mode, the length of the input message during
                                                          encryption and decryption exceeds the set msgLen. */
    CRYPT_MODES_CTRL_MSGLEN_ERROR,                   /**< In ccm mode, When the ctrl interface is used to set the
                                                          msg length, the input parameter length or the input
                                                          parameter data length is incorrect. (This
                                                          specification is affected by ivLen.) */
    CRYPT_MODES_MSGLEN_LEFT_ERROR,                   /**< In ccm mode, when the ctrl interface is used to
                                                          obtain the tag, the length of the encrypted and
                                                          decrypted messages does not reach the configured
                                                          number. As a result, an error occurs. */
    CRYPT_MODES_ERR_KEYLEN,                          /**< Incorrect key length set. */
    CRYPT_MODES_ERR_KEY,                             /**< Incorrect key set. */
    CRYPT_MODES_ERR_FEEDBACKSIZE,                    /**< The operation are not support by the algorithm
                                                          on which the pattern depends on. */
    CRYPT_MODES_METHODS_NOT_SUPPORT,                 /**< Mode depends does not support the behavior. */
    CRYPT_MODES_WRAP_DEC_ERROR,                      /**< wrap mode decrypt failed. */
    CRYPT_MODES_FEEDBACKSIZE_NOT_SUPPORT,            /**< The algorithm does not support the setting of feedbacksize. */
    CRYPT_MODES_PADDING_NOT_SUPPORT,                 /**< Unsupported padding. */
    CRYPT_MODES_ERR_HCTR_DATA_TOO_SHORT,          /**< HCTR mode requires input data to be at least one block long. */

    CRYPT_HKDF_DKLEN_OVERFLOW = 0x01110001,          /**< The length of the derived key exceeds the maximum. */
    CRYPT_HKDF_NOT_SUPPORTED,                        /**< Unsupport HKDF algorithm. */
    CRYPT_HKDF_PARAM_ERROR,                          /**< Incorrect input parameter. */
    CRYPT_HKDF_ERR_MAC_METH,                         /**< Mac method err. */

    CRYPT_CMAC_OUT_BUFF_LEN_NOT_ENOUGH = 0x01120001, /**< The length of the buffer that storing the output
                                                          result is insufficient. */
    CRYPT_CMAC_INPUT_OVERFLOW,                       /**< The input length exceeds the limit. As a result,
                                                          the integer type is reversed. */
    CRYPT_CMAC_ERR_UNSUPPORTED_CTRL_OPTION,          /**< Unsupport the control type. */
    CRYPT_GMAC_ERR_UNSUPPORTED_CTRL_OPTION,          /**< Unsupport the control type. */

    CRYPT_SCRYPT_PARAM_ERROR = 0x01130001,           /**< Incorrect input parameter. */
    CRYPT_SCRYPT_NOT_SUPPORTED,                      /**< Unsupport the SCRYPT algorithm. */
    CRYPT_SCRYPT_DATA_TOO_MAX,                       /**< The data calculated by the SCRYPT algorithm is too large. */

    CRYPT_PBKDF2_PARAM_ERROR = 0x01150001,           /**< Incorrect input parameter. */
    CRYPT_PBKDF2_NOT_SUPPORTED,                      /**< Does not support the PBKDF2 algorithm. */
    CRYPT_PBKDF2_ERR_MAC_METH,                       /**< Mac method err. */

    CRYPT_ECC_POINT_AT_INFINITY = 0x01160001,         /**< Point at infinity. */
    CRYPT_ECC_POINT_NOT_ON_CURVE,                    /**< Point is not on the curve. */
    CRYPT_ECC_POINT_ERR_CURVE_ID,                    /**< Curve ID is inconsistent or incorrect. */
    CRYPT_ECC_POINT_WINDOW_TOO_MAX,                  /**< Window is too max. */
    CRYPT_ECC_POINT_NOT_EQUAL,                       /**< The two points are not equal. */
    CRYPT_ECC_POINT_BLIND_WITH_ZERO,                 /**< The random number generated during point salting is 0. */
    CRYPT_ECC_POINT_NOT_AFFINE,                      /**< Point is not affine coordinates. */
    CRYPT_ECC_NOT_SUPPORT,                           /**< This function is not supported. */
    CRYPT_ECC_POINT_MUL_ERR_K_LEN,                    /** The scalar length exceeds the curve specification
                                                          when using the dot multiplication function */
    CRYPT_ECC_BUFF_LEN_NOT_ENOUGH,                   /**< Insufficient buffer length. */
    CRYPT_ECC_ERR_POINT_FORMAT,                      /**< The encoding format input during point encoding
                                                          is incorrect. */
    CRYPT_ECC_ERR_POINT_CODE,                        /**< Incorrect point code information. */
    CRYPT_ECC_PKEY_ERR_UNSUPPORTED_CTRL_OPTION,      /**< Unsupport the control type. */
    CRYPT_ECC_PKEY_ERR_EMPTY_KEY,                    /**< Key is null. */
    CRYPT_ECC_PKEY_ERR_INVALID_POINT_FORMAT,         /**< Invalid dot format. */
    CRYPT_ECC_PKEY_ERR_CTRL_LEN,                     /**< Control input parameter is incorrect. */
    CRYPT_ECC_PKEY_ERR_INVALID_PRIVATE_KEY,          /**< Invalid private key. */
    CRYPT_ECC_PKEY_ERR_INVALID_PUBLIC_KEY,           /**< Invalid public key. */
    CRYPT_ECC_PKEY_ERR_TRY_CNT,                      /**< Key generation or generater signature fail
                                                          within the specified number of attempts. */
    CRYPT_ECC_PKEY_ERR_SIGN_LEN,                     /**< Invalid sign length  */
    CRYPT_ECC_ERR_PARA,                              /**< Incorrect curve parameter. */

    CRYPT_ECC_INVERSE_INPUT_ZERO,                     /** Modulo inverse input is 0. */
    CRYPT_ECC_KEY_PUBKEY_NOT_EQUAL,                   /**< ECC public keys are not equal. */
    CRYPT_ECC_PAIRWISE_CHECK_FAIL,                    /**< The public and private keys are inconsistent. */
    CRYPT_ECC_INVALID_PRVKEY,                         /**< Invalid private key. */

    CRYPT_SHA3_OUT_BUFF_LEN_NOT_ENOUGH = 0x01170001,  /**< Insufficient buffer length for storing output results. */
    CRYPT_SHA3_INVALID_STATE,                       /**< Invalid state. */

    CRYPT_ECDH_ERR_UNSUPPORT_CURVE_TYPE = 0x01180001, /**< Unsupported curve type. */
    CRYPT_ECDH_ERR_EMPTY_KEY,                         /**< Key is null. */
    CRYPT_ECDH_ERR_INVALID_COFACTOR,                  /**< Invalid cofactor value. */
    CRYPT_ECDH_PAIRWISE_CHECK_FAIL,                     /**< The public and private keys are inconsistent. */
    CRYPT_ECDH_INVALID_PRVKEY,                        /**< Invalid private key. */

    CRYPT_ECDSA_ERR_EMPTY_KEY = 0x01190001,           /**< Key is NULL. */
    CRYPT_ECDSA_ERR_TRY_CNT,                          /**< Key generation and generate signature fail
                                                           within the specified number of attempts. */
    CRYPT_ECDSA_VERIFY_FAIL,                          /**< Verification failure. */
    CRYPT_ECDSA_ERR_UNSUPPORTED_CTRL_OPTION,          /**< Unsupport the control type. */
    CRYPT_ECDSA_BUFF_LEN_NOT_ENOUGH,                  /**< BUFF insufficient length. */
    CRYPT_ECDSA_PKEY_ERR_SIGN_DATA_LEN,
    CRYPT_ECDSA_PAIRWISE_CHECK_FAIL,                  /**< The public and private keys are inconsistent. */
    CRYPT_ECDSA_INVALID_PRVKEY,                       /**< Invalid private key. */

    CRYPT_SM3_INPUT_OVERFLOW = 0x011A0001,             /**< The length of the input data exceeds the maximum
                                                           processing range of the SM3. */
    CRYPT_SM3_OUT_BUFF_LEN_NOT_ENOUGH,                /**< The length of the buffer that storing the output
                                                           result is insufficient. */

    CRYPT_SM4_ERR_IV_LEN = 0x011B0001,              /**< Wrong key length set. */
    CRYPT_SM4_ERR_MSG_LEN,                          /**< Wrong data length is set. */
    CRYPT_SM4_ERR_KEY_LEN,                            /**< Wrong key length is set. */
    CRYPT_SM4_UNSAFE_KEY,                             /**< DataKey is the same as tweakKey. */

    CRYPT_SM9_BUFF_LEN_NOT_ENOUGH = 0x01210000,       /**< SM9 buffer length not enough. */
    CRYPT_SM9_ERR_KEY_ERR,                            /**< SM9 key error. */
    CRYPT_SM9_ERR_NOT_SUPPORT,                        /**< SM9 operation not supported. */
    CRYPT_SM9_ERR_SIGN_FAILED,                        /**< SM9 signature failed. */
    CRYPT_SM9_VERIFY_FAIL,                            /**< SM9 verification failure. */
    CRYPT_SM9_ERR_INVALID_SIGNATURE_LEN,              /**< SM9 invalid signature length. */
    CRYPT_SM9_ERR_NO_USER_ID,                         /**< SM9 user ID not set. */
    CRYPT_SM9_ERR_ENCRYPT_FAILED,                     /**< SM9 encryption failed. */
    CRYPT_SM9_ERR_DECRYPT_FAILED,                     /**< SM9 decryption failed. */
    CRYPT_SM9_ERR_KEY_NOT_EQUAL,                      /**< SM9 keys are not equal. */
    CRYPT_SM9_ERR_BAD_INPUT,                          /**< SM9 bad input parameter. */
    CRYPT_SM9_ERR_NO_USER_KEY,                        /**< SM9 user key not set. */
    CRYPT_SM9_ERR_NO_MASTER_KEY,                      /**< SM9 master key not set. */
    CRYPT_SM9_ERR_KEY_EXCHANGE_FAILED,                /**< SM9 key exchange failed. */
    CRYPT_SM9_PAIRWISE_CHECK_FAIL,                    /**< The public and private keys are inconsistent. */
    CRYPT_SM9_INVALID_PRVKEY,                         /**< Invalid private key. */

    CRYPT_MD_INPUT_OVERFLOW = 0x011D0001,             /**< The length of the input data exceeds the
                                                           maximum processing range of the MD5. */
    CRYPT_MD_OUT_BUFF_LEN_NOT_ENOUGH,                /**< The length of the buffer that storing the
                                                           output result is insufficient. */
    CRYPT_MD_ERR_NEWCTX,                              /**< create md ctx failed. */

    CRYPT_SM2_BUFF_LEN_NOT_ENOUGH = 0x01200001,       /**< Insufficient buffer length. */
    CRYPT_SM2_NO_PUBKEY,                              /**< SM2 the public key is not set. */
    CRYPT_SM2_NO_PRVKEY,                              /**< SM2 The private key is not set. */
    CRYPT_SM2_ERR_EMPTY_KEY,                          /**< SM2 key is null. */
    CRYPT_SM2_ERR_TRY_CNT,                            /**< Key generation and generate signature fail
                                                           within the specified number of attempts. */
    CRYPT_SM2_VERIFY_FAIL,                            /**< verification failure. */
    CRYPT_SM2_ERR_UNSUPPORTED_CTRL_OPTION,            /**< Unsupported control type. */
    CRYPT_SM2_ERR_NO_HASH_METHOD,                     /**< No hash method information. */
    CRYPT_SM2_USERID_NOT_SET,                         /**< Unset userID. */
    CRYPT_SM2_R_NOT_SET,                              /**< The peer R value is not set. */
    CRYPT_SM2_INVALID_SERVER_TYPE,                    /**< The user is neither the initiator nor the recipient. */
    CRYPT_SM2_ERR_CTRL_LEN,                           /**< Incorrect ctrl length. */
    CRYPT_SM2_DECRYPT_FAIL,                           /**< Decryption failure. */
    CRYPT_SM2_ERR_DATA_LEN,                           /**< Incorrect data length. */
    CRYPT_SM2_ERR_GET_S,                              /**< Failed to obtain the checksum. */
    CRYPT_SM2_ERR_S_NOT_SET,                          /**< Unset checksum. */
    CRYPT_SM2_EXCH_VERIFY_FAIL,                       /**< Key Negotiation Failure. */
    CRYPT_SM2_DECODE_FAIL,                            /**< Data decoding fails, the data does not meet
                                                            the decoding requirements. */
    CRYPT_SM2_ID_TOO_LARGE,                           /**< User id to large. */
    CRYPT_SM2_K_REPEAT_SET_ERROR,                     /**< the random k is set repeatedly*/
    CRYPT_SM2_PAIRWISE_CHECK_FAIL,                     /**< The public and private keys are inconsistent. */
    CRYPT_SM2_INVALID_PRVKEY,                         /**< Invalid private key. */
    CRYPT_SM2_NO_RANDOM_INFO,                         /**< no r value in sm2 exch. */

    CRYPT_KDFTLS12_NOT_SUPPORTED = 0x01220001,        /**< Unsupport the KDFTLS12 algorithm. */
    CRYPT_KDFTLS12_PARAM_ERROR,                       /**< Incorrect input parameter. */
    CRYPT_KDFTLS12_ERR_MAC_METH,                      /**< Mac method err. */

    CRYPT_SIPHASH_OUT_BUFF_LEN_NOT_ENOUGH = 0x01220001, /**< The buffer size for storing the output
                                                             result is insufficient. */
    CRYPT_SIPHASH_INPUT_OVERFLOW,
    CRYPT_SIPHASH_ERR_UNSUPPORTED_CTRL_OPTION,          /**< Unsupport the control type. */

    CRYPT_CBC_MAC_ERR_CTRL_LEN = 0x01240001,
    CRYPT_CBC_MAC_ERR_UNSUPPORTED_CTRL_OPTION,
    CRYPT_CBC_MAC_PADDING_NOT_SET,
    CRYPT_CBC_MAC_PADDING_NOT_SUPPORT,
    CRYPT_CBC_MAC_OUT_BUFF_LEN_NOT_ENOUGH,

    CRYPT_SEED_POOL_NEW_ERROR = 0x01290001,             /**< The length of the key input is
                                                             incorrect when setting the key. */
    CRYPT_SEED_POOL_STATE_ERROR,                        /**< Incorrect seed pool status. */
    CRYPT_SEED_POOL_ES_LIST_FULL,                       /**< The number of entropy sources exceeds the upper limit. */
    CRYPT_SEED_POOL_NO_SUFFICIENT_ENTROPY,              /**< The seed pool cannot provide sufficient entropy. */
    CRYPT_SEED_POOL_NO_ENTROPY_SOURCE,                  /**< The seed pool has no entropy source. */
    CRYPT_SEED_POOL_NO_ENTROPY_OBTAINED,                /**< No entropy data is obtained from the seed pool. */
    CRYPT_SEED_POOL_NOT_MEET_REQUIREMENT,               /**< The entropy data does not meet the requirements. */
    CRYPT_ENTROPY_CTX_CREATE_FAILED,                    /**< Failed to create the handle for obtaining the entropy. */

    CRYPT_MLKEM_KEYLEN_ERROR = 0x01300001,              /**< Incorrect input data length. */
    CRYPT_MLKEM_LEN_NOT_ENOUGH,                         /**<The buffer size of output is insufficient. */
    CRYPT_MLKEM_KEY_NOT_SET,                            /**<The encaps or decaps key not set. */
    CRYPT_MLKEM_KEYINFO_NOT_SET,                        /**<The algorithm not set. */
    CRYPT_MLKEM_KEY_NOT_EQUAL,                          /**< The MLKEM keys are not equal. */
    CRYPT_MLKEM_CTRL_NOT_SUPPORT,                       /**< The Ctrl type is not supported.*/
    CRYPT_MLKEM_CTRL_INIT_REPEATED,                     /**< The CTX cannot be initialized repeatedly.*/
    CRYPT_MLKEM_PAIRWISE_CHECK_FAIL,                    /**< The public and private keys are inconsistent. */
    CRYPT_MLKEM_INVALID_PRVKEY,                         /**< Invalid private key. */
    CRYPT_MLKEM_DECODE_KEY_OVERFLOW,                    /**< The decoded poly coffs greater than MLKEM_Q */
    CRYPT_MLKEM_KEY_REPEATED_SET,                       /**< PKey context is repeated set*/
    CRYPT_MLKEM_SEED_EXPANDED_KEY_INCONSISTENT,         /**< Seed and expanded key are inconsistent. */
    CRYPT_MLKEM_Z_MISMATCH,                             /**< Implicit rejection secret z mismatch. */
    CRYPT_MLKEM_SEED_NOT_SET,                           /**< Seed is not set in the context. */
    CRYPT_MLKEM_DK_FORMAT_ERROR,                        /**< Invalid decapsulation key format. */

    CRYPT_HPKE_ERR_GEN_ASYM_KEY = 0x01310001,            /**< HPKE Generate asymmetric key error. */
    CRYPT_HPKE_ERR_AEAD_TAG,                             /**< Failed to verify AEAD tag when decrypt. */
    CRYPT_HPKE_ERR_CALL,                                 /**< It is not appropriate to call this function. */
    CRYPT_HPKE_FAILED_FETCH_CIPHER,                      /**< Failed to fetch cipher. */
    CRYPT_HPKE_FAILED_FETCH_PKEY,                        /**< Failed to fetch pkey. */
    CRYPT_HPKE_FAILED_FETCH_KDF,                         /**< Failed to fetch kdf. */

    CRYPT_DECODE_ASN1_BUFF_NUM_NOT_ENOUGH = 0x01320001,  /**< The input number of BSL_ANS1_Buffer is not enough. */
    CRYPT_DECODE_UNSUPPORTED_PUBKEY_TYPE,                /**< Unsupported pubkey type */
    CRYPT_DECODE_UNSUPPORTED_PKCS8_TYPE,                 /**< Unsupported pkcs8 type */
    CRYPT_DECODE_PKCS8_INVALID_ALGO_PARAM,               /**< pkcs8 has no valid algorithm parameters */
    CRYPT_DECODE_UNKNOWN_OID,                            /**< Unknown OID */
    CRYPT_DECODE_ASN1_BUFF_FAILED,                       /**< decode asn1 buffer failed. */
    CRYPT_DECODE_NO_SUPPORT_TYPE,                        /**< decode no support key type. */
    CRYPT_DECODE_NO_SUPPORT_FORMAT,                      /**< decode no support key format. */
    CRYPT_DECODE_PKCS8_INVALID_ITER,                     /**< pkcs8 invalid iter num */
    CRYPT_DECODE_PKCS8_INVALID_KEYLEN,                   /**< pkcs8 invalid keylen */
    CRYPT_DECODE_ERR_RSSPSS_GET_ANY_TAG,                 /**< decode rsapss param failed. */
    CRYPT_DECODE_ERR_RSSPSS,                             /**< decode rsapss param failed. */
    CRYPT_DECODE_ERR_RSSPSS_MD,                          /**< rsapss md is invalid. */
    CRYPT_DECODE_ERR_RSSPSS_MGF1MD,                      /**< rsapss mgf1md is invalid. */
    CRYPT_DECODE_ERR_RSSPSS_TRAILER,                     /**< rsapss trailer field is invalid. */
    CRYPT_DECODE_PKCS7_INVALIDE_ENCRYPTDATA_TYPE,        /**< Invaild pkcs7-encryptedData. */
    CRYPT_DECODE_UNSUPPORTED_PKCS7_TYPE,                 /**< Unsupported pkcs7 type */
    CRYPT_DECODE_UNSUPPORTED_ENCRYPT_TYPE,               /**< Unsupported encrypt type */
    CRYPT_DECODE_BUFF_NOT_ENOUGH,                        /**< The input buffer space is not enough */
    CRYPT_DECODE_ASN1_BUFF_LEN_ZERO,                     /**< The decoding length of asn1 buffer is zero. */
    CRYPT_DECODE_ERR_NO_DECODER,                         /**< No decoder found. */
    CRYPT_DECODE_ERR_NO_USABLE_DECODER,                  /**< No decoder found. */
    CRYPT_DECODE_RETRY,                                  /**< Retry decode. */
    CRYPT_DECODE_ERR_KEY_TYPE_NOT_MATCH,                 /**< Key type not match. */

    CRYPT_ENCODE_NO_SUPPORT_TYPE = 0x01330001,           /**< encode no support key type. */
    CRYPT_ENCODE_NO_SUPPORT_FORMAT,                      /**< encode no support key format. */
    CRYPT_ENCODE_ERR_RSA_PAD,                            /**< rsa pad err. */
    CRYPT_ENCODE_BUFF_NOT_ENOUGH,                        /**< The input buffer space is not enough */
    CRYPT_ENCODE_ERR_SIGN_LEN_OVERFLOW,                  /**< The r and s length is too large. */
    CRYPT_ENCODE_ERR_SM2_ENCRYPT_DATA_LEN_OVERFLOW,      /**< The sm2 encrypt data length is too large. */

    CRYPT_DECODE_PRINT_UNSUPPORT_ALG = 0x01340001,       /**< Failed to print unsupported alg. */
    CRYPT_DECODE_PRINT_NO_KEY,                           /**< Failed to print key. */
    CRYPT_DECODE_PRINT_KEYBITS,                          /**< Failed to print key bist. */
    CRYPT_DECODE_PRINT_MODULUS,                          /**< Failed to print modulus. */
    CRYPT_DECODE_PRINT_EXPONENT,                         /**< Failed to print exponent. */
    CRYPT_DECODE_PRINT_RSAPSS_PARA,                      /**< Failed to print rsapss para. */
    CRYPT_DECODE_PRINT_ECC_PUB,                          /**< Failed to print ecc pubkey. */
    CRYPT_DECODE_PRINT_ECC_OID,                          /**< Failed to print ecc oid. */

    CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL = 0x01350001,     /**< Unexpected impl */
    CRYPT_PROVIDER_ERR_IMPL_NULL,
    CRYPT_PROVIDER_NOT_FOUND,                            /**< Provider not found. */
    CRYPT_PROVIDER_NOT_SUPPORT,
    CRYPT_PROVIDER_ERR_ATTRIBUTE,
    CRYPT_PROVIDER_INVALID_LIB_CTX,

    CRYPT_MLDSA_KEYINFO_NOT_SET = 0x01360001,           /**< The algorithm not set. */
    CRYPT_MLDSA_CTRL_NOT_SUPPORT,                       /**< The Ctrl type is not supported. */
    CRYPT_MLDSA_PAD_TOO_LONG,                           /**< The pad is too long. */
    CRYPT_MLDSA_KEYLEN_ERROR,                           /**< Incorrect input data length. */
    CRYPT_MLDSA_SIGN_DATA_ERROR,                        /**< Invalid signature value. */
    CRYPT_MLDSA_VERIFY_FAIL,                            /**< Failed to verify the signature. */
    CRYPT_MLDSA_KEY_NOT_SET,                            /**< The public key or private not set. */
    CRYPT_MLDSA_LEN_NOT_ENOUGH,                         /**< The buffer size of output is insufficient. */
    CRYPT_MLDSA_KEY_NOT_EQUAL,                          /**< The MLDSA keys are not equal. */
    CRYPT_MLDSA_CTRL_INIT_REPEATED,                     /**< The CTX cannot be initialized repeatedly.*/
    CRYPT_MLDSA_SET_KEY_FAILED,                         /**< Failed to set the key. */
    CRYPT_MLDSA_PAIRWISE_CHECK_FAIL,                    /**< The public and private keys are inconsistent. */
    CRYPT_MLDSA_INVALID_PRVKEY,                         /**< Invalid private key. */
    CRYPT_MLDSA_INVALID_PUBKEY,                         /**< Invalid public key. */
    CRYPT_MLDSA_PRVKEY_FORMAT_ERROR,
    CRYPT_MLDSA_SEED_NOT_SET,                           /**< Invalid private key encode format. */
    CRYPT_MLDSA_PRVKEY_SEED_INCONSISTENT,                /**< Input seed and private key are inconsistent */

    CRYPT_ELGAMAL_BUFF_LEN_NOT_ENOUGH = 0x01370001, /**< The buffer length is insufficient. */
    CRYPT_ELGAMAL_NO_KEY_INFO,              /**< Lacks valid key information. */
    CRYPT_ELGAMAL_ERR_KEY_BITS,             /**< Incorrect key length. */
    CRYPT_ELGAMAL_ERR_ENC_BITS,             /**< Incorrect length of the encrypted plaintext of the public key. */
    CRYPT_ELGAMAL_ERR_DEC_BITS,             /**< Incorrect length of the decrypted ciphertext of the private key. */
    CRYPT_ELGAMAL_ERR_KEY_KBITS,             /**< Incorrect key length. */
    CRYPT_ELGAMAL_ERR_KEY_BITS_KBITS,       /**< Incorrect key length. */
    CRYPT_ELGAMAL_ERR_ENC_KBITS,             /**< Incorrect length of the encrypted plaintext of the public key. */
    CRYPT_ELGAMAL_ERR_DEC_KBITS,             /**< Incorrect length of the decrypted ciphertext of the private key. */
    CRYPT_ELGAMAL_ERR_INPUT_VALUE,          /**< Some special values, which are used as input errors. */
    CRYPT_ELGAMAL_CTRL_NOT_SUPPORT_ERROR,   /**< The Ctrl type is not supported When elgamal is used for Ctrl. */

    CRYPT_SLHDSA_ERR_INVALID_ALGID = 0x01380001,         /**< The algorithm id is invalid. */
    CRYPT_SLHDSA_ERR_INVALID_SIG_LEN,                    /**< The signature length is invalid. */
    CRYPT_SLHDSA_ERR_INVALID_KEYLEN,                     /**< The key length is invalid. */
    CRYPT_SLHDSA_ERR_SIG_LEN_NOT_ENOUGH,                 /**< The signature length is not enough. */
    CRYPT_SLHDSA_ERR_HYPERTREE_VERIFY_FAIL,              /**< Hypertree verify failed. */
    CRYPT_SLHDSA_ERR_PREHASH_ID_NOT_SUPPORTED,           /**< Prehash id is not supported. */
    CRYPT_SLHDSA_ERR_CONTEXT_LEN_OVERFLOW,               /**< Context length is overflow. */
    CRYPT_SLHDSA_PAIRWISE_CHECK_FAIL,                    /**< The public and private keys are inconsistent. */
    CRYPT_SLHDSA_ERR_NO_PUBKEY,                          /**< No public key. */
    CRYPT_SLHDSA_ERR_NO_PRVKEY,                          /**< No private key. */

    CRYPT_PAILLIER_BUFF_LEN_NOT_ENOUGH = 0x01390001, /**< The buffer length is insufficient. */
    CRYPT_PAILLIER_NO_KEY_INFO,              /**< Lacks valid key information. */
    CRYPT_PAILLIER_ERR_KEY_BITS,             /**< Incorrect key length. */
    CRYPT_PAILLIER_ERR_ENC_BITS,             /**< Incorrect length of the encrypted plaintext of the public key. */
    CRYPT_PAILLIER_ERR_DEC_BITS,             /**< Incorrect length of the decrypted ciphertext of the private key. */
    CRYPT_PAILLIER_ERR_INPUT_VALUE,          /**< Some special values, which are used as input errors. */
    CRYPT_PAILLIER_CTRL_NOT_SUPPORT_ERROR,   /**< The Ctrl type is not supported When paillier is used for Ctrl. */

    CRYPT_XMSS_ERR_INVALID_ALGID = 0x013A0001,         /**< The algorithm id is invalid. */
    CRYPT_XMSS_ERR_INVALID_SIG_LEN,                    /**< The signature length is invalid. */
    CRYPT_XMSS_ERR_INVALID_KEYLEN,                     /**< The key length is invalid. */
    CRYPT_XMSS_ERR_KEY_EXPIRED,                        /**< The key has expired. */
    CRYPT_XMSS_ERR_INVALID_KEY,                        /**< The key length is invalid. */
    CRYPT_XMSS_ERR_XDR_ID_UNMATCH,                     /**< XDR parameter design does not match CTX. */
    CRYPT_XMSS_ERR_INVALID_XDR_ID,                     /**< XDR parameter is invalid. */
    CRYPT_XMSS_LEN_NOT_ENOUGH,                         /**< The buffer size of output is insufficient. */
    CRYPT_XMSS_KEYINFO_NOT_SET,                        /**< The key info is not set. */
    CRYPT_XMSS_PAIRWISE_CHECK_FAIL,                    /**< The public and private keys are inconsistent. */
    CRYPT_XMSS_INVALID_PRVKEY,                         /**< Invalid private key. */
    CRYPT_XMSS_INVALID_PUBKEY,                         /**< Invalid public key. */

    CRYPT_CMVP_COMMON_ERR = 0x013B0001, /**< Common error in CMVP selftest. */
    CRYPT_CMVP_ERR_INTEGRITY,           /**< Integrity error in CMVP selftest. */
    CRYPT_CMVP_RANDOMNESS_ERR,          /**< Randomness error in CMVP selftest. */
    CRYPT_CMVP_ERR_ALGO_SELFTEST,       /**< Algorithm selftest error in CMVP selftest. */
    CRYPT_CMVP_ERR_PAIRWISETEST,        /**< Pairwise test error in CMVP selftest. */
    CRYPT_CMVP_ERR_PARAM_CHECK,         /**< Parameter check error in CMVP selftest. */
    CRYPT_CMVP_ERR_CIPHER_SELFTEST,     /**< Cipher selftest error in CMVP selftest. */
    CRYPT_CMVP_ERR_MD_SELFTEST,         /**< Md selftest error in CMVP selftest. */
    CRYPT_CMVP_ERR_MAC_SELFTEST,        /**< Mac selftest error in CMVP selftest. */
    CRYPT_CMVP_ERR_KDF_SELFTEST,        /**< Kdf selftest error in CMVP selftest. */
    CRYPT_CMVP_ERR_DRBG_SELFTEST,       /**< Drbg selftest error in CMVP selftest. */
    CRYPT_CMVP_ERR_PKEY_SELFTEST,       /**< Pkey selftest error in CMVP selftest. */

    CRYPT_FRODOKEM_CTRL_NOT_SUPPORT = 0x013C0001,
    CRYPT_FRODOKEM_CTRL_INIT_REPEATED,
    CRYPT_FRODOKEM_KEYINFO_NOT_SET,
    CRYPT_FRODOKEM_BUFLEN_NOT_ENOUGH,
    CRYPT_FRODOKEM_INVALID_CIPHER,
    CRYPT_FRODOKEM_ABSENT_PUBKEY,
    CRYPT_FRODOKEM_ABSENT_PRVKEY,
    CRYPT_FRODOKEM_KEY_NOT_EQUAL,
    CRYPT_FRODOKEM_ENCRYPT_FAIL,
    CRYPT_FRODOKEM_KEY_REPEATED_SET,

    CRYPT_MCELIECE_CTRL_NOT_SUPPORT = 0x013D0001,
    CRYPT_MCELIECE_CTRL_INIT_REPEATED,
    CRYPT_MCELIECE_KEYINFO_NOT_SET,
    CRYPT_MCELIECE_BUFLEN_NOT_ENOUGH,
    CRYPT_MCELIECE_INVALID_CIPHER,
    CRYPT_MCELIECE_ABSENT_PUBKEY,
    CRYPT_MCELIECE_ABSENT_PRVKEY,
    CRYPT_MCELIECE_KEY_NOT_EQUAL,
    CRYPT_MCELIECE_ENCRYPT_FAIL,
    CRYPT_MCELIECE_INVALID_ARG,
    CRYPT_MCELIECE_KEYGEN_FAIL,
    CRYPT_MCELIECE_ENCODE_FAIL,
    CRYPT_MCELIECE_DECODE_FAIL,
    CRYPT_MCELIECE_KEY_REPEATED_SET,
    CRYPT_MCELIECE_ERR_MATRIX_SIZE,
};
#ifdef __cplusplus
}
#endif

#endif // CRYPT_ERRNO_H
