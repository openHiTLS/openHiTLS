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
#include <stddef.h>
#include "crypt_algid.h"
#include "crypt_types.h"
#include "crypt_eal_provider.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define CRYPT_PKEY_FLAG_DUP             0x01
#define CRYPT_PKEY_FLAG_NEED_EXPORT_CB  0x02

/* length function */
typedef int32_t (*GetLenFunc)(const void *ctx);

/* Prototype of the MD algorithm operation functions */
typedef void* (*MdNewCtx)(void *provCtx, int32_t algId);
typedef int32_t (*MdInit)(void *data, const BSL_Param *param);
typedef int32_t (*MdUpdate)(void *data, const uint8_t *input, uint32_t len);
typedef int32_t (*MdFinal)(void *data, uint8_t *out, uint32_t *len);
typedef int32_t (*MdDeinit)(void *data);
typedef int32_t (*MdCopyCtx)(void *dst, const void *src);
typedef void* (*MdDupCtx)(const void *src);
typedef void (*MdFreeCtx)(void *data);
typedef int32_t (*MdGetParam)(void *data, BSL_Param *param);
typedef int32_t (*MdSqueeze)(void *data, uint8_t *out, uint32_t len);

#ifdef HITLS_CRYPTO_MD_MB
typedef void *(*MdMBNewCtx)(uint32_t num);
typedef void (*MdMBFreeCtx)(void *ctx);
typedef int32_t (*MdMBInit)(void *ctx);
typedef int32_t (*MdMBUpdate)(void *ctx, const uint8_t *data[], uint32_t nbytes[], uint32_t num);
typedef int32_t (*MdMBFinal)(void *ctx, uint8_t *digest[], uint32_t *outlen, uint32_t num);

typedef struct {
    MdMBNewCtx newCtx;
    MdMBFreeCtx freeCtx;
    MdMBInit init;
    MdMBUpdate update;
    MdMBFinal final;
} EAL_MdMBMethod;
#endif // HITLS_CRYPTO_MD_MB

typedef struct {
    int32_t id;
    uint16_t blockSize;  // Block size processed by the hash algorithm at a time, which is used with other algorithms.
    uint16_t mdSize;     // Output length of the HASH algorithm
    MdNewCtx newCtx;     // generate md context
    MdInit init;         // Initialize the MD context.
    MdUpdate update;     // Add block data for MD calculation.
    MdFinal final;       // Complete the MD calculation and obtain the MD result.
    MdDeinit deinit;     // Clear the key information of the MD context.
    MdCopyCtx copyCtx;   // Copy the MD context.
    MdDupCtx dupCtx;     // Dup the MD context.
    MdFreeCtx freeCtx;   // free md context
    MdGetParam getParam; // get/set md param
    MdSqueeze squeeze;   // squeeze the MD context.
} EAL_MdMethod;

typedef struct {
    uint16_t hashSize;              // Output length of the Siphash algorithm
    uint16_t compressionRounds;     // the number of compression rounds
    uint16_t finalizationRounds;    // the number of finalization rounds
} EAL_SiphashMethod;

/* provide asymmetric primitive method */
typedef void *(*PkeyNew)(void);
typedef void* (*PkeyProvNew)(void *provCtx, int32_t algId);
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
typedef int32_t (*PkeyCtrl)(void *key, int32_t opt, void *val, uint32_t len);
typedef int32_t (*PkeySetPrv)(void *key, const void *para);
typedef int32_t (*PkeySetPub)(void *key, const void *para);
typedef int32_t (*PkeyGetPrv)(const void *key, void *para);
typedef int32_t (*PkeyGetPub)(const void *key, void *para);
typedef void *(*PkeyNewPara)(const void *para);
typedef int32_t (*PkeySign)(void *key, int32_t mdAlgId, const uint8_t *data, uint32_t dataLen,
    uint8_t *sign, uint32_t *signLen);
typedef int32_t (*PkeySignData)(void *key, const uint8_t *data, uint32_t dataLen,
    uint8_t *sign, uint32_t *signLen);
typedef int32_t (*PkeyVerify)(const void *key, int32_t mdAlgId, const uint8_t *data, uint32_t dataLen,
    const uint8_t *sign, uint32_t signLen);
typedef int32_t (*PkeyVerifyData)(const void *key, const uint8_t *data, uint32_t dataLen,
    const uint8_t *sign, uint32_t signLen);
typedef int32_t (*PkeyRecover)(const void *key, const uint8_t *sign, uint32_t signLen,
    uint8_t *data, uint32_t *dataLen);
typedef int32_t (*PkeyComputeShareKey)(const void *key, const void *pub, uint8_t *share, uint32_t *shareLen);
typedef int32_t (*PkeyCrypt)(const void *key, const uint8_t *data, uint32_t dataLen, uint8_t *out, uint32_t *outLen);
typedef int32_t (*PkeyHEOperation)(const void *ctx, const BSL_Param *input, uint8_t *out, uint32_t *outLen);
typedef int32_t (*PkeyCheck)(uint32_t checkType, const void *key1, const void *key2);
typedef int32_t (*PkeyCmp)(const void *key1, const void *key2);
typedef int32_t (*PkeyCopyParam)(const void *src, void *dest);
typedef int32_t (*PkeyGetSecBits)(const void *key);
typedef int32_t (*PkeyEncapsulate)(const void *key, uint8_t *cipher, uint32_t *cipherLen,
    uint8_t *share, uint32_t *shareLen);
typedef int32_t (*PkeyDecapsulate)(const void *key, const uint8_t *cipher, uint32_t cipherLen,
    uint8_t *share, uint32_t *shareLen);

typedef int32_t (*PkeyEncapsInit)(const void *key, const void *para);
typedef int32_t (*PkeyDecapsInit)(const void *key, const void *para);
typedef int32_t (*PkeyBlind)(void *pkey, int32_t mdAlgId, const uint8_t *input, uint32_t inputLen,
    uint8_t *out, uint32_t *outLen);
typedef int32_t (*PkeyUnBlind)(const void *pkey, const uint8_t *input, uint32_t inputLen,
    uint8_t *out, uint32_t *outLen);

typedef int32_t (*PkeyImport)(void *key, const BSL_Param *params);

typedef int32_t (*PkeyExport)(const void *key, BSL_Param *params);

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
    PkeyCtrl ctrl;                          // Control function.
    PkeySetPub setPub;                      // Set the public key.
    PkeySetPrv setPrv;                      // Set the private key.
    PkeyGetPub getPub;                      // Obtain the public key.
    PkeyGetPrv getPrv;                      // Obtain the private key.
    PkeySign sign;                          // Sign the signature.
    PkeySignData signData;                  // sign the raw data
    PkeyVerify verify;                      // Verify the signature.
    PkeyVerifyData verifyData;              // Verify the raw data
    PkeyRecover recover;                    // Signature recovery.
    PkeyComputeShareKey computeShareKey;    // Calculate the shared key.
    PkeyCrypt encrypt;                      // Encrypt.
    PkeyCrypt decrypt;                      // Decrypt.
    PkeyHEOperation headd;                  // Add
    PkeyHEOperation hemul;                  // Multiply
    PkeyCheck check;                        // Check the consistency of the key pair.
    PkeyCmp cmp;                            // Compare keys and parameters.
    PkeyCopyParam copyPara;                 // Copy parameter from source to destination
    PkeyEncapsulate pkeyEncaps;             // Key encapsulation.
    PkeyDecapsulate pkeyDecaps;             // Key decapsulation.
    PkeyBlind blind;                        // msg blind
    PkeyUnBlind unBlind;                    // sig unBlind.
} EAL_PkeyMethod;

typedef struct EAL_PkeyUnitaryMethod {
    PkeyNew newCtx;                         // Apply for a key pair structure resource.
    PkeyProvNew provNewCtx;                 // Creat a key pair structure resource for provider
    PkeyDup dupCtx;                         // Copy key pair structure resource.
    PkeyFree freeCtx;                       // Free the key structure.
    PkeySetPara setPara;                    // Set parameters of the key pair structure.
    PkeyGetPara getPara;                    // Obtain parameters from the key pair structure.
    PkeyGen gen;                            // Generate a key pair.
    PkeyCtrl ctrl;                          // Control function.
    PkeySetPub setPub;                      // Set the public key.
    PkeySetPrv setPrv;                      // Set the private key.
    PkeyGetPub getPub;                      // Obtain the public key.
    PkeyGetPrv getPrv;                      // Obtain the private key.
    PkeySign sign;                          // Sign the signature.
    PkeySignData signData;                  // sign the raw data
    PkeyVerify verify;                      // Verify the signature.
    PkeyVerifyData verifyData;              // Verify the raw data
    PkeyRecover recover;                    // Signature recovery.
    PkeyComputeShareKey computeShareKey;    // Calculate the shared key.
    PkeyCrypt encrypt;                      // Encrypt.
    PkeyCrypt decrypt;                      // Decrypt.
    PkeyHEOperation headd;                  // Add
    PkeyHEOperation hemul;                  // Multiply
    PkeyCheck check;                        // Check the consistency of the key pair.
    PkeyCmp cmp;                            // Compare keys and parameters.
    PkeyEncapsInit encapsInit;              // Init the key encapsulation
    PkeyDecapsInit decapsInit;              // Init the key decapsulation
    PkeyEncapsulate pkeyEncaps;             // Key encapsulation.
    PkeyDecapsulate pkeyDecaps;             // Key decapsulation.
    PkeyBlind blind;                        // msg blind
    PkeyUnBlind unBlind;                    // sig unBlind.
    PkeyImport import;                      // import key
    PkeyExport export;                      // export key
} EAL_PkeyUnitaryMethod;
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

typedef void *(*CipherNewCtx)(void *provCtx, int32_t alg);
typedef int32_t (*CipherInitCtx)(void *ctx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, void *param, bool enc);
typedef int32_t (*CipherDeInitCtx)(void *ctx);
typedef int32_t (*CipherUpdate)(void *ctx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);
typedef int32_t (*CipherFinal)(void *ctx, uint8_t *out, uint32_t *outLen);
typedef int32_t (*CipherCtrl)(void *ctx, int32_t opt, void *val, uint32_t len);
typedef void (*CipherFreeCtx)(void *ctx);
typedef void *(*CipherDupCtx)(const void *ctx);

typedef int32_t (*SetEncryptKey)(void *ctx, const uint8_t *key, uint32_t len);
typedef int32_t (*SetDecryptKey)(void *ctx, const uint8_t *key, uint32_t len);
typedef int32_t (*SetKey)(void *ctx, const uint8_t *key, uint32_t len);
// process block or blocks
typedef int32_t (*EncryptBlock)(void *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
typedef int32_t (*DecryptBlock)(void *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
typedef void (*DeInitBlockCtx)(void *ctx);
typedef int32_t (*CipherStreamProcess)(void *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

typedef struct {
    SetEncryptKey setEncryptKey;
    SetDecryptKey setDecryptKey;
    EncryptBlock encryptBlock;
    DecryptBlock decryptBlock;
    DeInitBlockCtx cipherDeInitCtx;
    CipherCtrl cipherCtrl;
    uint8_t blockSize;
    uint16_t ctxSize;
    CRYPT_SYM_AlgId algId;
} EAL_SymMethod;

typedef struct {
    CipherNewCtx newCtx;
    CipherInitCtx initCtx;
    CipherDeInitCtx deinitCtx;
    CipherUpdate update;
    CipherFinal final;
    CipherCtrl ctrl;
    CipherFreeCtx freeCtx;
    CipherDupCtx dupCtx;
} EAL_CipherMethod;

/* Prototype of the KDF algorithm operation functions */
typedef void* (*KdfNewCtx)(void *provCtx, int32_t algId);
typedef int32_t (*KdfSetParam)(void *ctx, const BSL_Param *param);
typedef int32_t (*KdfDerive)(void *ctx, uint8_t *key, uint32_t keyLen);
typedef int32_t (*KdfDeinit)(void *ctx);
typedef int32_t (*KdfCtrl)(void *data, int32_t cmd, void *val, uint32_t valLen);
typedef void (*KdfFreeCtx)(void *ctx);
typedef void *(*KdfDupCtx)(const void *ctx);

typedef struct {
    KdfNewCtx newCtx;
    KdfSetParam setParam;
    KdfDerive derive;
    KdfDeinit deinit;
    KdfCtrl ctrl;
    KdfFreeCtx freeCtx;
    KdfDupCtx dupCtx;
} EAL_KdfMethod;

typedef struct {
    uint32_t id;
    EAL_KdfMethod *kdfMeth;
} EAL_CidToKdfMeth;

/* prototype of MAC algorithm operation functions */
typedef void* (*MacNewCtx)(void *provCtx, int32_t algId);
// Complete key initialization.
typedef int32_t (*MacInit)(void *ctx, const uint8_t *key, uint32_t len, void *param);
typedef int32_t (*MacUpdate)(void *ctx, const uint8_t *in, uint32_t len);
typedef int32_t (*MacFinal)(void *ctx, const uint8_t *out, uint32_t *len);
typedef int32_t (*MacDeinit)(void *ctx);
// The action is opposite to the initCtx. Sensitive data is deleted.
typedef int32_t (*MacReinit)(void *ctx);
typedef int32_t (*MacCtrl)(void *ctx, uint32_t opt, void *val, uint32_t len);
typedef int32_t (*MacSetParam)(void *data, const BSL_Param *param);
typedef void (*MacFreeCtx)(void *ctx);
typedef void* (*MacDupCtx)(const void *ctx);

/* set of MAC algorithm operation methods */
typedef struct {
    MacNewCtx newCtx;
    MacInit init;           // Initialize the MAC context.
    MacUpdate update;       // Add block data for MAC calculation.
    MacFinal final;         // Complete MAC calculation and obtain the MAC result.
    MacDeinit deinit;       // Clear the key information in MAC context.
    // Re-initialize the key. This method is used where the keys are the same during multiple MAC calculations.
    MacReinit reinit;
    MacCtrl ctrl;
    MacSetParam setParam;
    MacFreeCtx freeCtx;
    MacDupCtx dupCtx;
} EAL_MacMethod;

typedef struct {
    union {
        CRYPT_MD_AlgId mdId;
        CRYPT_SYM_AlgId symId;
    } id;
    union {
        EAL_MdMethod *md;        // MD algorithm which HMAC depends on
        const EAL_SymMethod *sym;  // AES function wihch CMAC depends on
        EAL_SiphashMethod *sip;  // siphash method
    } method;
} EAL_MacDepMethod;

/**
 * @ingroup  mode_algid
 * Symmetric encryption/decryption mode ID
 */
typedef enum {
    HCRYPT_MODE_CBC,
    HCRYPT_MODE_ECB,
    HCRYPT_MODE_CTR,
    HCRYPT_MODE_XTS,
    HCRYPT_MODE_CCM,
    HCRYPT_MODE_GCM,
    HCRYPT_MODE_CHACHA20_POLY1305,
    HCRYPT_MODE_CFB,
    HCRYPT_MODE_OFB,
    HCRYPT_MODE_WRAP_NOPAD,
    HCRYPT_MODE_WRAP_PAD,
    HCRYPT_MODE_HCTR,
    HCRYPT_MODE_MAX
} CRYPT_MODE_AlgId;

/**
 * @ingroup crypt_eal_pkey
 *
 * Structure of the PSS padding mode when RSA is used for signature
 */
typedef struct {
    int32_t saltLen;               /**< pss salt length. -1 indicates hashLen, -2 indicates MaxLen, -3 is AutoLen */
    EAL_MdMethod mdMeth;           /**< pss mdid method when padding */
    EAL_MdMethod mgfMeth;          /**< pss mgfid method when padding */
    CRYPT_MD_AlgId mdId;           /**< pss mdid when padding */
    CRYPT_MD_AlgId mgfId;          /**< pss mgfid when padding */
    void *mdProvCtx;
    void *mgfProvCtx;
} RSA_PadingPara;

/* Prototype of the RAND algorithm operation functions */
typedef void *(*RandNewCtx)(void *libCtx, int32_t algId, CRYPT_RandSeedMethod *seedMethod, void *seedCtx);
typedef void *(*RandProvNewCtx)(void *provCtx, int32_t algId, BSL_Param *param);
typedef int32_t (*RandDrbgInst)(void *ctx, const uint8_t *person, uint32_t persLen, void *param);
typedef int32_t (*RandDrbgUnInst)(void *ctx);
typedef int32_t (*RandDrbgGen)(void *ctx, uint8_t *bytes, uint32_t len, const uint8_t *adin,
    uint32_t adinLen, void *param);
typedef int32_t (*RandDrbgReSeed)(void *ctx, const uint8_t *addin, uint32_t addinLen, void *param);
typedef int32_t (*RandDrbgCtrl)(void *ctx, int32_t cmd, void *val, uint32_t valLen);
typedef void (*RandDrbgFreeCtx)(void *ctx);

typedef struct {
    RandNewCtx newCtx;
    RandProvNewCtx provNewCtx;
    RandDrbgInst inst;
    RandDrbgUnInst unInst;
    RandDrbgGen gen;
    RandDrbgReSeed reSeed;
    RandDrbgCtrl ctrl;
    RandDrbgFreeCtx freeCtx;
} EAL_RandUnitaryMethod;

typedef struct {
    uint32_t type;
    int32_t methodId;
    const void *method;
} EAL_RandMethLookup;

/**
 * @ingroup crypt_ctrl_param
 *
 * Set and obtain internal parameters of Pbkdf2.
 */
typedef enum {
    CRYPT_CTRL_GET_MACID = 0,       /* kdf get macId . */
    CRYPT_CTRL_GET_SALTLEN,         /* kdf get saltlen . */
    CRYPT_CTRL_GET_ITER,            /* kdf get iter . */
    CRYPT_CTRL_GET_KEYLEN           /* kdf get keyLen . */
} CRYPT_KdfCtrl;

typedef enum {
    CRYPT_PKEY_CHECK_KEYPAIR = 1, /**< Check the key pair. */
    CRYPT_PKEY_CHECK_PRVKEY = 2,  /**< Check the private key. */
    CRYPT_PKEY_CHECK_MAX,
} CRYPT_KeyCheckType;

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // EAL_LOCAL_TYPES_H
