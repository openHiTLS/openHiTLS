# Cryptographic Algorithm Functions

openHiTLS provides functions such as encryption and decryption, signature verification, and hash calculation based on the cryptographic algorithm standard. Provided by algorithm module, the main function interfaces support the default cryptographic algorithm capability for the certificate and TLS module in the openHiTLS system

## Function Specifications

* Encryption and decryption: supports symmetric encryption and decryption based on SM4, AES, and CHACHA20, and asymmetric encryption and decryption based on SM2 and RSA.
* Signature verification: supports SM2, DSA, ED25519, RSA, and ECDSA.
* Key exchange: supports SM2, X25519, and ECDH.
* Key derivation: supports PBKDF2, HKDF, SCRYPT, and KDFTLS12.
* Integrity algorithm: supports integrity protection based on HMAC.
* Hash calculation: supports digest calculation based on SM3, SHA2, SHA3, MD5, and SHA1.
* Random number generation: supports DRBG-HASH, DRBG-CTR, and DRBG-HMAC.

# Examples of Encryption and Decryption

## Symmetric Encryption and Decryption

This function provides encryption and decryption capabilities based on symmetric algorithms. The following uses the SM4-CBC algorithm as an example to describe the sample code for reference.

## Sample Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "crypt_eal_cipher.h" // Header file of the interfaces for symmetric encryption and decryption.
#include "bsl_sal.h"
#include "bsl_err.h"
#include "crypt_algid.h" // Algorithm ID list.
#include "crypt_errno.h" // Error code list.

void *StdMalloc(uint32_t len) {
    return malloc((size_t)len);
}

void PrintLastError(void) {
    const char *file = NULL;
    uint32_t line = 0;
    BSL_ERR_GetLastErrorFileLine(&file, &line); // Obtain the name and number of lines of the error file.
    printf("failed at file %s at line %d\n", file, line);
}

int main(void)
{
    uint8_t data[10] = {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x1c, 0x14};
    uint8_t iv[16] = {0};
    uint8_t key[16] = {0};
    uint32_t dataLen = sizeof(data);
    uint8_t cipherText[100];
    uint8_t plainText[100];
    uint32_t outTotalLen = 0;
    uint32_t outLen = sizeof(cipherText);
    uint32_t cipherTextLen;
    int32_t ret;

    printf("plain text to be encrypted: ");
    for (uint32_t i = 0; i < dataLen; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");

    // Initialize the error code module.
    BSL_ERR_Init();

    // Before calling the algorithm APIs, call the **BSL_SAL_CallBack_Ctrl** function to register the **malloc** and **free** functions. Execute this step only once.
    // If the memory allocation ability of Linux is available, the two functions can be registered using Linux by default.
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, StdMalloc);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE, free);

    // Create a context.
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_CBC);
    if (ctx == NULL) {
        PrintLastError();
        BSL_ERR_DeInit();
        return 1;
    }
    // During initialization, the last input parameter can be **true** or **false**. **true** indicates encryption, and **false** indicates decryption.
    ret = CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret); // Output the error code. You can find the error information in **crypt_errno.h** based on the error code.
        PrintLastError();
        goto EXIT;
    }
    // Set the padding mode.
    ret = CRYPT_EAL_CipherSetPadding(ctx, CRYPT_PADDING_PKCS7);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    // Enter the data to be calculated. This interface can be called for multiple times. The input value of **outLen** is the length of the ciphertext, and the output value is the amount of processed data.
    ret = CRYPT_EAL_CipherUpdate(ctx, data, dataLen, cipherText, &outLen);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    outTotalLen += outLen;
    outLen = sizeof(cipherText) - outTotalLen;

    ret = CRYPT_EAL_CipherFinal(ctx, cipherText + outTotalLen, &outLen);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    outTotalLen += outLen;
    printf("cipher text value is: ");

    for (uint32_t i = 0; i < outTotalLen; i++) {
        printf("%02x", cipherText[i]);
    }
    printf("\n");

    // Start decryption.
    cipherTextLen = outTotalLen;
    outTotalLen = 0;
    outLen = sizeof(plainText);

    // When initializing the decryption function, set the last input parameter to **false**.
    ret = CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), false);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    //Set the padding mode, which must be the same as that for encryption.
    ret = CRYPT_EAL_CipherSetPadding(ctx, CRYPT_PADDING_PKCS7);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    // Enter the ciphertext data.
    ret = CRYPT_EAL_CipherUpdate(ctx, cipherText, cipherTextLen, plainText, &outLen);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }
    outTotalLen += outLen;
    outLen = sizeof(plainText) - outTotalLen;

    // Decrypt the last segment of data and remove the filled content.
    ret = CRYPT_EAL_CipherFinal(ctx, plainText + outTotalLen, &outLen);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    outTotalLen += outLen;

    printf("decrypted plain text value is: ");
    for (uint32_t i = 0; i < outTotalLen; i++) {
        printf("%02x", plainText[i]);
    }
    printf("\n");

    if (outTotalLen != dataLen || memcmp(plainText, data, dataLen) != 0) {
        printf("plaintext comparison failed\n");
        goto EXIT;
    }
    printf("pass \n");

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
    BSL_ERR_DeInit();
    return ret;
}
```

## Asymmetric Encryption and Decryption

This function provides encryption and decryption capabilities based on asymmetric algorithms. The following uses the SM2 encryption and decryption process as an example to describe the sample code for reference.

## Sample Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "crypt_eal_pkey.h" // Header file of the interfaces for asymmetric encryption and decryption.
#include "bsl_sal.h"
#include "bsl_err.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_init.h"
#include "crypt_types.h"

void *StdMalloc(uint32_t len) {
    return malloc((uint32_t)len);
}
void PrintLastError(void) {
    const char *file = NULL;
    uint32_t line = 0;
    BSL_ERR_GetLastErrorFileLine(&file, &line);
    printf("failed at file %s at line %d\n", file, line);
}

int main(void) {
    int32_t ret;
    BSL_ERR_Init();  // Initialize the error code module.
    // Before calling the algorithm APIs, call the **BSL_SAL_CallBack_Ctrl** function to register the **malloc** and **free** functions. Execute this step only once.
    // If the memory allocation ability of Linux is available, the two functions can be registered using Linux by default.
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, StdMalloc);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE, free);
    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_PROVIDER);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
    if (pkey == NULL) {
        PrintLastError();
        goto EXIT;
    }

    // Initialize the random number.
    ret = CRYPT_EAL_ProviderRandInitCtx(NULL, CRYPT_RAND_SHA256, "provider=default", NULL, 0, NULL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_RandInit: error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    // Generate a key pair.
    ret = CRYPT_EAL_PkeyGen(pkey);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_PkeyGen: error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    // Data to be encrypted.
    char *data = "test enc data";
    uint32_t dataLen = 12;
    uint8_t ecrypt[125] = {0};
    uint32_t ecryptLen = 125;
    uint8_t dcrypt[125] = {0};
    uint32_t dcryptLen = 125;
    // Encrypt data.
    ret = CRYPT_EAL_PkeyEncrypt(pkey, data, dataLen, ecrypt, &ecryptLen);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_PkeyEncrypt: error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    // Decrypt data.
    ret = CRYPT_EAL_PkeyDecrypt(pkey, ecrypt, ecryptLen, dcrypt, &dcryptLen);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_PkeyDecrypt: error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    if (memcmp(dcrypt, data, dataLen) == 0) {
        printf("encrypt and decrypt success\n");
    } else {
        ret = -1;
    }
EXIT:
    // Release the context memory.
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_RandDeinit();
    BSL_ERR_DeInit();
    return ret;
}
```

# Example of Signature Verification

## Algorithm Type

This function provides the signature verification capability based on asymmetric algorithms. The following uses SM2 signature verification as an example to describe the sample code for reference.

## Sample Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "crypt_eal_pkey.h" // Header file for signature verification.
#include "bsl_sal.h"
#include "bsl_err.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_eal_init.h"
#include "crypt_eal_rand.h"

void *StdMalloc(uint32_t len) {
    return malloc((size_t)len);
}

void PrintLastError(void) {
    const char *file = NULL;
    uint32_t line = 0;
    BSL_ERR_GetLastErrorFileLine(&file, &line);// Obtain the name and number of lines of the error file.
    printf("failed at file %s at line %d\n", file, line);
}

int main(void)
{
    int ret;
    uint8_t userId[32] = {0};
    uint8_t key[32] = {0};
    uint8_t msg[32] = {0};
    uint8_t signBuf[100] = {0};
    uint32_t signLen = sizeof(signBuf);
    CRYPT_EAL_PkeyPrv prv = {0};
    CRYPT_EAL_PkeyPub pub = {0};
    CRYPT_EAL_PkeyCtx *ctx = NULL;

    BSL_ERR_Init(); // Initialize the error code module.
    // Before calling the algorithm APIs, call the **BSL_SAL_CallBack_Ctrl** function to register the **malloc** and **free** functions. Execute this step only once.
    // If the memory allocation ability of Linux is available, the two functions can be registered using Linux by default.
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, StdMalloc);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE, free);
    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_PROVIDER);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
    if (ctx == NULL) {
        goto EXIT;
    }

    // Set a user ID.
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_USER_ID, userId, sizeof(userId));
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    // Initialize the random number.
    ret = CRYPT_EAL_ProviderRandInitCtx(NULL, CRYPT_RAND_SHA256, "provider=default", NULL, 0, NULL);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    // Generate a key pair.
    ret = CRYPT_EAL_PkeyGen(ctx);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    // Sign.
    ret = CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SM3, msg, sizeof(msg), signBuf, &signLen);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    // Verify the signature.
    ret = CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SM3, msg, sizeof(msg), signBuf, signLen);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    printf("pass \n");

EXIT:
    // Release the context memory.
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_RandDeinit();
    BSL_ERR_DeInit();
    return ret;
}
```

# Example of Key Exchange

## Algorithm Type

This function provides the key exchange capability based on asymmetric algorithms. The following uses ECDH as an example to describe the sample code for reference.

## Sample Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "crypt_types.h"
#include "crypt_eal_pkey.h" // Header file for key exchange.
#include "bsl_sal.h"
#include "bsl_err.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_init.h"

void *StdMalloc(uint32_t len) {
    return malloc((size_t)len);
}

void PrintLastError(void) {
    const char *file = NULL;
    uint32_t line = 0;
    BSL_ERR_GetLastErrorFileLine(&file, &line);
    printf("failed at file %s at line %d\n", file, line);
}

int main(void)
{
    int ret;

    uint8_t prikey[] =
        {0x7d, 0x7d, 0xc5, 0xf7, 0x1e, 0xb2, 0x9d, 0xda, 0xf8, 0x0d, 0x62, 0x14, 0x63, 0x2e, 0xea, 0xe0,
         0x3d, 0x90, 0x58, 0xaf, 0x1f, 0xb6, 0xd2, 0x2e, 0xd8, 0x0b, 0xad, 0xb6, 0x2b, 0xc1, 0xa5, 0x34};
    uint8_t pubkey[] =
        {0x04, 0x70, 0x0c, 0x48, 0xf7, 0x7f, 0x56, 0x58, 0x4c, 0x5c, 0xc6, 0x32, 0xca, 0x65, 0x64, 0x0d, 0xb9,
         0x1b, 0x6b, 0xac, 0xce, 0x3a, 0x4d, 0xf6, 0xb4, 0x2c, 0xe7, 0xcc, 0x83, 0x88, 0x33, 0xd2, 0x87,
         0xdb, 0x71, 0xe5, 0x09, 0xe3, 0xfd, 0x9b, 0x06, 0x0d, 0xdb, 0x20, 0xba, 0x5c, 0x51, 0xdc, 0xc5,
         0x94, 0x8d, 0x46, 0xfb, 0xf6, 0x40, 0xdf, 0xe0, 0x44, 0x17, 0x82, 0xca, 0xb8, 0x5f, 0xa4, 0xac};
    uint8_t resSharekey[] =
        {0x46, 0xfc, 0x62, 0x10, 0x64, 0x20, 0xff, 0x01, 0x2e, 0x54, 0xa4, 0x34, 0xfb, 0xdd, 0x2d, 0x25,
         0xcc, 0xc5, 0x85, 0x20, 0x60, 0x56, 0x1e, 0x68, 0x04, 0x0d, 0xd7, 0x77, 0x89, 0x97, 0xbd, 0x7b};

    CRYPT_EAL_PkeyPrv prvKey = {0};
    CRYPT_EAL_PkeyPub pubKey = {0};
    uint32_t shareLen;
    uint8_t *shareKey;
    CRYPT_EAL_PkeyCtx *prvCtx = NULL;
    CRYPT_EAL_PkeyCtx *pubCtx = NULL;
    CRYPT_PKEY_ParaId id = CRYPT_ECC_NISTP256;

    BSL_ERR_Init(); // Initialize the error code module.
    // Before calling the algorithm APIs, call the **BSL_SAL_CallBack_Ctrl** function to register the **malloc** and **free** functions. Execute this step only once.
    // If the memory allocation ability of Linux is available, the two functions can be registered using Linux by default.
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, StdMalloc);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE, free);
    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_PROVIDER);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        goto EXIT;
    }
    prvCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDH);
    pubCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDH);
    if (prvCtx == NULL || pubCtx == NULL) {
        goto EXIT;
    }

    // Set the curve parameters.
    ret = CRYPT_EAL_PkeySetParaById(prvCtx, id);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    // Set the private key of one end.
    prvKey.id = CRYPT_PKEY_ECDH;
    prvKey.key.eccPrv.len = sizeof(prikey);
    prvKey.key.eccPrv.data = prikey;
    ret = CRYPT_EAL_PkeySetPrv(prvCtx, &prvKey);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    // Set the curve parameters.
    ret = CRYPT_EAL_PkeySetParaById(pubCtx, id);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    // Set the public key of the other end.
    pubKey.id = CRYPT_PKEY_ECDH;
    pubKey.key.eccPub.len = sizeof(pubkey);
    pubKey.key.eccPub.data = pubkey;
    ret = CRYPT_EAL_PkeySetPub(pubCtx, &pubKey);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    // The shared key involves only the X axis. The length of the public key is not compressed in the returned results.
    shareLen = CRYPT_EAL_PkeyGetKeyLen(prvCtx) / 2;
    shareKey = (uint8_t *)BSL_SAL_Malloc(shareLen);
    if (shareKey == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        PrintLastError();
        goto EXIT;
    }

    // Initialize the random number.
    ret = CRYPT_EAL_ProviderRandInitCtx(NULL, CRYPT_RAND_SHA256, "provider=default", NULL, 0, NULL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_RandInit: error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    // Calculate the shared key.
    ret = CRYPT_EAL_PkeyComputeShareKey(prvCtx, pubCtx, shareKey, &shareLen);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    // Compare the calculation result with the expected one.
    if (shareLen != sizeof(resSharekey) || memcmp(shareKey, resSharekey, shareLen) != 0) {
        printf("failed to compare test results\n");
        ret = -1;
        goto EXIT;
    }

    printf("pass \n");

EXIT:
    // Release the context memory.
    CRYPT_EAL_RandDeinit();
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
    CRYPT_EAL_PkeyFreeCtx(pubCtx);
    BSL_SAL_Free(shareKey);
    BSL_ERR_DeInit();
    return 0;
}
```

# Example of Key Derivation

## Algorithm Type

The PBKDF2, HKDF, SCRYPT, and KDFTLS12 algorithms can be used for key derivation. The following uses PBKDF2 as an example to describe the sample code for reference.

## Sample Code

```c
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "crypt_errno.h"
#include "bsl_sal.h"
#include "bsl_err.h"
#include "crypt_algid.h"
#include "crypt_eal_kdf.h"
#include "bsl_params.h"
#include "crypt_params_key.h"

#define PBKDF2_PARAM_LEN (4)

void *StdMalloc(uint32_t len) {
    return malloc((size_t)len);
}

void PrintLastError(void) {
    const char *file = NULL;
    uint32_t line = 0;
    BSL_ERR_GetLastErrorFileLine(&file, &line);
    printf("failed at file %s at line %d\n", file, line);
}

int main(void)
{
    int32_t ret;
    uint8_t key[] = {0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64};
    uint8_t salt[] = {0x4e, 0x61, 0x43, 0x6c};
    uint32_t iterations = 80000;
    uint8_t result[] = {
        0x4d, 0xdc, 0xd8, 0xf6, 0x0b, 0x98, 0xbe, 0x21,
        0x83, 0x0c, 0xee, 0x5e, 0xf2, 0x27, 0x01, 0xf9,
        0x64, 0x1a, 0x44, 0x18, 0xd0, 0x4c, 0x04, 0x14,
        0xae, 0xff, 0x08, 0x87, 0x6b, 0x34, 0xab, 0x56,
        0xa1, 0xd4, 0x25, 0xa1, 0x22, 0x58, 0x33, 0x54,
        0x9a, 0xdb, 0x84, 0x1b, 0x51, 0xc9, 0xb3, 0x17,
        0x6a, 0x27, 0x2b, 0xde, 0xbb, 0xa1, 0xd0, 0x78,
        0x47, 0x8f, 0x62, 0xb3, 0x97, 0xf3, 0x3c, 0x8d};

    uint8_t out[sizeof(result)] = {0};
    uint32_t outLen = sizeof(result);

    // Initialize the error code module.
    BSL_ERR_Init();

    /**
     * Before calling the algorithm APIs,
     * call the BSL_SAL_CallBack_Ctrl function to register the malloc and free functions.
     * Execute this step only once. If the memory allocation ability of Linux is available,
     * the two functions can be registered using Linux by default.
    */
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, StdMalloc);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE, free);

    CRYPT_EAL_KdfCTX *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_PBKDF2);
    if (ctx == NULL) {
        PrintLastError();
        goto EXIT;
    }
    CRYPT_MAC_AlgId id = CRYPT_MAC_HMAC_SHA256;
    BSL_Param params[5] = {{0}, {0}, {0}, {0}, BSL_PARAM_END};
    (void)BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, &id, sizeof(id));
    (void)BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_PASSWORD, BSL_PARAM_TYPE_OCTETS, key, sizeof(key));
    (void)BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS, salt, sizeof(salt));
    (void)BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_ITER, BSL_PARAM_TYPE_UINT32, &iterations, sizeof(iterations));
    ret = CRYPT_EAL_KdfSetParam(ctx, params);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    ret = CRYPT_EAL_KdfDerive(ctx, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    if (memcmp(out, result, sizeof(result)) != 0) {
        printf("failed to compare test results\n");
        ret = -1;
        goto EXIT;
    }
    printf("pass \n");

EXIT:
    BSL_ERR_DeInit();
    CRYPT_EAL_KdfFreeCtx(ctx);
    return ret;
}
```

# Example of Random Number Generation

## Algorithm Type

The DRBG-SHA, DRBG-HMAC, and DRBG-CTR algorithms can be used for random number generation. The interfaces include global random number interfaces and multi-instance random number interfaces.

```c
/*
*  Global random number initializing and deinitializing interfaces.
 * The **seedMeth** value of initializing interfaces is the entropy source of the callback, and the **seedCtx** value is the context called back by the user.
*  Users can set their own entropy source. If it is not set, the default entropy source is used.
*  Currently, entropy can be obtained from **/dev/random** of Linux.
*/
int32_t CRYPT_EAL_RandInit(CRYPT_RAND_AlgId id, CRYPT_RandSeedMethod *seedMeth, void *seedCtx, const uint8_t *pers, uint32_t persLen);
void CRYPT_EAL_RandDeinit(void);

/* After initialization, users can call the following interfaces to obtain the pseudo-random number and supplement the entropy source.*/
int32_t CRYPT_EAL_Randbytes(uint8_t *byte, uint32_t len);
int32_t CRYPT_EAL_RandSeed(void);

/*The deterministic random bit generator (DRBG) context of the multi-instance random number interfaces is returned to the user. This is the main difference between the two types of interfaces.
 * Multiple DRBG contexts can be created. Different contexts do not interfere with each other during entropy source setting and internal status change.*/
CRYPT_EAL_RndCtx *CRYPT_EAL_DrbgNew(CRYPT_RAND_AlgId id, CRYPT_RandSeedMethod *seedMeth, void *seedCtx);
void CRYPT_EAL_DrbgDeinit(CRYPT_EAL_RndCtx *ctx);
```

The following uses the DRBG-SHA algorithm as an example to describe the sample code for reference.

## Sample Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "crypt_types.h"
#include "bsl_sal.h"
#include "bsl_err.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_eal_init.h"
#include "crypt_eal_rand.h"

void *StdMalloc(uint32_t len) {
    return malloc((size_t)len);
}

void PrintLastError(void) {
    const char *file = NULL;
    uint32_t line = 0;
    BSL_ERR_GetLastErrorFileLine(&file, &line);
    printf("failed at file %s at line %d\n", file, line);
}

int main(void)
{
    int ret;
    uint8_t output[100] = {0};
    uint32_t len = 100;

    // Before calling the algorithm APIs, call the **BSL_SAL_CallBack_Ctrl** function to register the **malloc** and **free** functions. Execute this step only once.
    // If the memory allocation ability of Linux is available, the two functions can be registered using Linux by default.
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, StdMalloc);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE, free);

    BSL_ERR_Init();// Initialize the error module.
    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_PROVIDER);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        goto EXIT;
    }
    // Initialize the global random number by using the default entropy source from **/dev/random** of Linux.
    ret = CRYPT_EAL_ProviderRandInitCtx(NULL, CRYPT_RAND_SHA256, "provider=default", NULL, 0, NULL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_RandInit: error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    // Obtain the random number sequence of the **len** value.
    ret = CRYPT_EAL_RandbytesEx(NULL, output, len);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Randbytes: error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    printf("random value is: ");  // Output the random number.
    for (uint32_t i = 0; i < len; i++) {
        printf("%02x", output[i]);
    }
    printf("\n");

    // Reseeding
    ret = CRYPT_EAL_RandSeedEx(NULL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_RandSeed: error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    // Obtain the random number sequence of the **len** value.
    ret = CRYPT_EAL_RandbytesEx(NULL, output, len);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Randbytes: error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    printf("random value is: "); // Output the random number.
    for (uint32_t i = 0; i < len; i++) {
        printf("%02x", output[i]);
    }
    printf("\n");

EXIT:
    // Release the context memory.
    CRYPT_EAL_RandDeinit();
    BSL_ERR_DeInit();
    return 0;
}
```
