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

#ifndef CRYPT_LOCAL_TYPES_H
#define CRYPT_LOCAL_TYPES_H

#include <stdint.h>
#include "crypt_algid.h"
#include "crypt_types.h"
#include "crypt_method.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/* Prototype of the MD algorithm operation functions */
typedef int32_t (*MdInit)(void *data);
typedef int32_t (*MdUpdate)(void *data, const uint8_t *input, uint32_t len);
typedef int32_t (*MdFinal)(void *data, uint8_t *out, uint32_t *len);
typedef void (*MdDeinit)(void *data);
typedef int32_t (*MdCopyCtx)(void *dst, void *src);

typedef struct {
    uint16_t blockSize; // Block size processed by the hash algorithm at a time, which is used with other algorithms.
    uint16_t mdSize;    // Output length of the HASH algorithm
    uint16_t ctxSize;   // Context size of the HASH.
    MdInit init;        // Initialize the MD context.
    MdUpdate update;    // Add block data for MD calculation.
    MdFinal final;      // Complete the MD calculation and obtain the MD result.
    MdDeinit deinit;    // Clear the key information of the MD context.
    MdCopyCtx copyCtx;  // Copy the MD context.
} EAL_MdMethod;

typedef struct {
    uint32_t id;
    EAL_MdMethod *mdMeth;
} EAL_CidToMdMeth;

/* provide asymmetric primitive method */
typedef void *(*PkeyNew)(void);
typedef void *(*PkeyDup)(void *key);
typedef void (*PkeyFree)(void *key);
typedef void *(*PkeyNewParaById)(int32_t id);
typedef CRYPT_PKEY_ParaId (*PkeyGetParaId)(const void *key);
typedef void (*PkeyFreePara)(void *para);
typedef int32_t (*PkeySetPara)(void *key, const void *para);
typedef int32_t (*PkeyGetPara)(const void *key, void *para);
typedef int32_t (*PkeyGen)(void *key);
typedef uint32_t (*PkeyBits)(void *key);
typedef uint32_t (*PkeyGetSignLen)(void *key);
typedef int32_t (*PkeyCtrl)(void *key, CRYPT_PkeyCtrl opt, void *val, uint32_t len);
typedef int32_t (*PkeySetPrv)(void *key, const void *prv);
typedef int32_t (*PkeySetPub)(void *key, const void *pub);
typedef int32_t (*PkeyGetPrv)(const void *key, void *prv);
typedef int32_t (*PkeyGetPub)(const void *key, void *pub);
typedef void *(*PkeyNewPara)(const void *para);
typedef int32_t (*PkeySign)(const void *key, const uint8_t *data, uint32_t dataLen,
    uint8_t *sign, uint32_t *signLen);
typedef int32_t (*PkeyVerify)(const void *key, const uint8_t *data, uint32_t dataLen,
    const uint8_t *sign, uint32_t signLen);
typedef int32_t (*PkeyComputeShareKey)(const void *key, const void *pub,
    uint8_t *share, uint32_t *shareLen);
typedef int32_t (*PkeyCrypt)(const void *key, const uint8_t *data, uint32_t dataLen,
    uint8_t *out, uint32_t *outLen);
typedef int32_t (*PkeyCheck)(const void *key);
typedef int32_t (*PkeyCmp)(const void *key1, const void *key2);
typedef int32_t (*PkeyGetSecBits)(const void *key);

/**
* @ingroup  EAL
*
* Method structure of the EAL
*/
typedef struct EAL_PkeyMethod {
    uint32_t id;
    PkeyNew newCtx;                         // Apply for a key pair structure resource.
    PkeyDup dupCtx;                         // Copy key pair structure resource.
    PkeyFree freeCtx;                       // Free the key structure.
    PkeySetPara setPara;                    // Set parameters of the key pair structure.
    PkeyGetPara getPara;                    // Obtain parameters from the key pair structure.
    PkeyGen gen;                            // Generate a key pair.
    PkeyBits bits;                          // Obtain the key length.
    PkeyGetSignLen signLen;                 // Obtain the signature data length.
    PkeyCtrl ctrl;                          // Control function.
    PkeyNewParaById newParaById;            // Generate parameters by parameter ID.
    PkeyGetParaId getParaId;                // Obtain the parameter ID.
    PkeyFreePara freePara;                  // Free key parameters.
    PkeyNewPara newPara;                    // Generate key parameters.
    PkeySetPub setPub;                      // Set the public key.
    PkeySetPrv setPrv;                      // Set the private key.
    PkeyGetPub getPub;                      // Obtain the public key.
    PkeyGetPrv getPrv;                      // Obtain the private key.
    PkeySign sign;                          // Sign the signature.
    PkeyVerify verify;                      // Verify the signature.
    PkeyComputeShareKey computeShareKey;    // Calculate the shared key.
    PkeyCrypt encrypt;                      // Encrypt.
    PkeyCrypt decrypt;                      // Decrypt.
    PkeyCheck check;                        // Check the consistency of the key pair.
    PkeyCmp cmp;                            // Compare keys and parameters.
    PkeyGetSecBits getSecBits;              // get key security bits
} EAL_PkeyMethod;

/**
 * @ingroup  sym_algid
 * Symmetric encryption/decryption algorithm ID
 */
typedef enum {
    CRYPT_SYM_AES128 = 0,
    CRYPT_SYM_AES192,
    CRYPT_SYM_AES256,
    CRYPT_SYM_CHACHA20,
    CRYPT_SYM_SM4,
    CRYPT_SYM_MAX
} CRYPT_SYM_AlgId;

typedef struct EAL_CipherMethod {
    /**
     * @ingroup crypt_type
     * @brief Initialize the handle and register other modules.
     * @return 0 indicates success, and other values indicate failure.
     */
    int32_t (*initCtx)(void *ctx, const struct EAL_CipherMethod *m);
    /**
     * @ingroup crypt_type
     * @brief Deinitialize the handle, return to the state after init is called, including releasing memory.
     * @return void
     */
    void (*deinitCtx)(void *ctx);
    /**
     * @ingroup crypt_type
     * @brief Clear the key and sensitive information, but do not release the memory, return to the state after initCtx.
     * @return void
     */
    void (*clean)(void *ctx);
    /**
     * @ingroup crypt_type
     * @brief Set the encryption key and key length.
     * @return 0 indicates success, and other values indicate failure.
     */
    int32_t (*setEncryptKey)(void *ctx, const uint8_t *key, uint32_t len);
    /**
     * @ingroup crypt_type
     * @brief Set the decryption key and key length.
     * @return 0 indicates success, and other values indicate failure.
     */
    int32_t (*setDecryptKey)(void *ctx, const uint8_t *key, uint32_t len);
    /**
     * @ingroup crypt_type
     * @brief Encrypt the input data. The lengths of the encrypted and decrypted data are the same.
     * @return 0 indicates success, and other values indicate failure.
     */
    int32_t (*encrypt)(void *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
    /**
     * @ingroup crypt_type
     * @brief Decrypt the input data. The lengths of the encrypted and decrypted data are the same.
     * @return 0 indicates success, and other values indicate failure.
     */
    int32_t (*decrypt)(void *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
    /**
     * @ingroup crypt_type
     * @brief Set parameters for the CTX.
     * @return 0 indicates success, and other values indicate failure.
     */
    int32_t (*ctrl)(void *ctx, uint32_t opt, void *val, uint32_t len);

    uint8_t blockSize;   /**< block size in bytes */
    uint16_t ctxSize;    /**< ctx size. The maximum size is 65535 bytes. */
    CRYPT_SYM_AlgId algId;      /**< algorithm ID */
} EAL_CipherMethod;

/* prototype of MAC algorithm operation functions */
// Initialize the memory and set the method.
typedef int32_t (*MacInitCtx)(void *ctx, const void *method);
// Complete key initialization.
typedef int32_t (*MacInit)(void *ctx, const uint8_t *key, uint32_t len);
typedef int32_t (*MacUpdate)(void *ctx, const uint8_t *in, uint32_t len);
typedef int32_t (*MacFinal)(void *ctx, const uint8_t *out, uint32_t *len);
typedef void    (*MacDeinit)(void *ctx);
// The action is opposite to the initCtx. Sensitive data is deleted.
typedef void    (*MacDeinitCtx)(void *ctx);
typedef void    (*MacReinit)(void *ctx);
typedef uint32_t (*MacGetMacLen)(void *ctx);

/* set of MAC algorithm operation methods */
typedef struct {
    MacInitCtx initCtx;     // Allocate memory, initializing, and setting the method
    MacInit init;           // Initialize the MAC context.
    MacUpdate update;       // Add block data for MAC calculation.
    MacFinal final;         // Complete MAC calculation and obtain the MAC result.
    MacDeinit deinit;       // Clear the key information in MAC context.
    MacDeinitCtx deinitCtx; // Delete sensitive data and free memory
    // Re-initialize the key. This method is used where the keys are the same during multiple MAC calculations.
    MacReinit reinit;
    MacGetMacLen getLen;    // Obtain the data length of the MAC calculation result.
    uint16_t ctxSize;       // Context size of the MAC algorithm
} EAL_MacMethod;

typedef struct {
    union {
        const EAL_MacMethod *macMethod;
        const EAL_CipherMethod *modeMethod; // Method of gmac-dependent symmetric algorithms
        const void *masMeth;    // Method pointer of the master algorithm.
    };
    union {
        const EAL_MdMethod *md;        // MD algorithm which HMAC depends on
        const void *depMeth;           // Pointer to the dependent algorithm, which is reserved for extension.
    };
} EAL_MacMethLookup;

/**
 * @ingroup  mode_algid
 * Symmetric encryption/decryption mode ID
 */
typedef enum {
    CRYPT_MODE_CBC = 0,
    CRYPT_MODE_CTR,
    CRYPT_MODE_ECB,
    CRYPT_MODE_XTS,
    CRYPT_MODE_CCM,
    CRYPT_MODE_GCM,
    CRYPT_MODE_CHACHA20_POLY1305,
    CRYPT_MODE_CFB,
    CRYPT_MODE_OFB,
    CRYPT_MODE_MAX
} CRYPT_MODE_AlgId;

/**
 * @ingroup crypt_eal_pkey
 *
 * Structure of the PSS padding mode when RSA is used for signature
 */
typedef struct {
    int32_t saltLen;               /**< pss salt length. -1 indicates hashLen, -2 indicates MaxLen, -3 is AutoLen */
    const EAL_MdMethod *mdMeth;    /**< pss mdid method when padding */
    const EAL_MdMethod *mgfMeth;   /**< pss mgfid method when padding */
    CRYPT_MD_AlgId mdId;           /**< pss mdid when padding */
    CRYPT_MD_AlgId mgfId;          /**< pss mgfid when padding */
} RSA_PadingPara;

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // EAL_LOCAL_TYPES_H
