#ifndef E2EE_KEY_EXCH_H
#define E2EE_KEY_EXCH_H

#include "stdint.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    E2EE_P256_HKDF_SHA256 = 0x0010,
    E2EE_P384_HKDF_SHA384 = 0x0011,
    E2EE_P521_HKDF_SHA512 = 0x0012,
    E2EE_X25519_HKDF_SHA256 = 0x0020,
} E2EE_KEM_AlgId;

typedef enum {
    E2EE_HKDF_SHA256 = 0x0001,
    E2EE_HKDF_SHA384 = 0x0002,
    E2EE_HKDF_SHA512 = 0x0003,
} E2EE_KDF_AlgId;

typedef enum {
    E2EE_AES_128_GCM = 0x0001,
    E2EE_AES_256_GCM = 0x0002,
    E2EE_CHACHA20_POLY1305 = 0x0003
} E2EE_AEAD_AlgId;

typedef struct {
    E2EE_KEM_AlgId kemAlgId;
    E2EE_KDF_AlgId kdfAlgId;
    E2EE_AEAD_AlgId aeadAlgId;
} E2EE_AlgId;

typedef enum {
    E2EE_ECC_P256 = 0,
    E2EE_ECC_P384 = 1,
    E2EE_ECC_P521 = 2,
    E2EE_X25519 = 3
} E2EE_KeyType;

typedef struct {
    E2EE_KeyType type;
    uint8_t *privKey;
    uint32_t privKeyLen;
    uint8_t *info;
    uint32_t infoLen;
} E2EE_ServerKeyExchInfo;

typedef struct E2EE_ClientCtx E2EE_ClientCtx;
typedef struct E2EE_ServerCtx E2EE_ServerCtx;

/* Memory callback */
typedef struct {
    void *(*fpMalloc)(uint32_t size);
    void (*fpFree)(void *ptr);
} E2EE_MemCallback;

typedef struct {
    uint8_t *sharedSecret;
    uint32_t sharedSecretLen;
    uint8_t *encapsulatedKey;
    uint32_t encapsulatedKeyLen;
} E2EE_KemEncapsulateResult;

typedef struct {
    uint8_t *sharedSecret;
    uint32_t sharedSecretLen;
    uint8_t *info;
    uint32_t infoLen;
} E2EE_KemDecapsulateResult;

typedef void (*E2EE_logCallbackFunc)(void *callbackArg, const char *str, uint32_t len);

/* Use kem alg to generate a shared secret.*/
typedef int32_t (*E2EE_KemEncapsulateCallbackFunc)(void *callbackArg, E2EE_KEM_AlgId kemId, uint8_t *serverPubKey,
    uint32_t serverPubKeyLen, E2EE_KemEncapsulateResult *out);

typedef int32_t (*E2EE_KemDecapsulateCallbackFunc)(void *callbackArg, E2EE_KEM_AlgId kemId, uint8_t *encapsulatedKey,
    uint32_t encapsulatedKeyLen, uint8_t *pubKeyId, uint32_t pubKeyIdLen, E2EE_KemDecapsulateResult *out);

/**********************************************************************
Function Name: E2EE_RegisterLogCallback
Description:   Register log callback, if do not register, the default log function will be used.
Input:         logCallback - log callback
Return:        void
**********************************************************************/
void E2EE_RegisterLogCallback(E2EE_logCallbackFunc logCallbackFunc);

/**********************************************************************
Function Name: E2EE_RegisterMemCallback
Description:   Register memory callback, if do not register, the default memory function will be used.
Input:         memCallback - memory callback
Return:        void
**********************************************************************/
void E2EE_RegisterMemCallback(E2EE_MemCallback *memCallback);

/**********************************************************************
Function Name: E2EE_ClientCreate
Description:   Create a client context.
Input:         algId - E2EE algorithm ID
Return:        ctx - client context
**********************************************************************/
E2EE_ClientCtx *E2EE_ClientCreate(E2EE_AlgId algId);

/**********************************************************************
Function Name: E2EE_SetClientKemCallback
Description:   Set the key derivation callback, should call before E2EE_ClientInit. 
               If do not set, the default key derivation function will be used.
Input:         ctx - client context
               keyDeriveFunc - kem encapsulate callback
               callbackArg - callback argument
Return:        void
**********************************************************************/
void E2EE_SetClientKemCallback(E2EE_ClientCtx *ctx, E2EE_KemEncapsulateCallbackFunc keyDeriveFunc, void *callbackArg);

/**********************************************************************
Function Name: E2EE_ClientInit
Description:   Init the client context.
Input:         ctx - client context
               serverPubKey - trusted server public key, for ec, the format is 04||X||Y, for x25519, the format is X.
               serverPubKeyLen - server public key length
               info - information
               infoLen - information length
Return:        Success - E2EE_SUCCESS
               Failure - other Errcode
**********************************************************************/
int32_t E2EE_ClientInit(E2EE_ClientCtx *ctx, uint8_t *serverPubKey, uint32_t serverPubKeyLen, uint8_t *info,
    uint32_t infoLen);

/**********************************************************************
Function Name: E2EE_ClientEncrypt
Description:   Encrypt data. The first cipherText will contain the E2EE_AlgId info and theephemeral public key.
Input:         ctx - client context
               plainText - plaintext
               plainTextLen - plaintext length
               aad - additional authenticated data
               aadLen - aad length
Output:        cipherText - ciphertext
               cipherTextLen - ciphertext length
Return:        Success - E2EE_SUCCESS
               Failure - other Errcode
**********************************************************************/
int32_t E2EE_ClientEncrypt(E2EE_ClientCtx *ctx, uint8_t *plainText, uint32_t plainTextLen,
    uint8_t *aad, uint32_t aadLen, uint8_t *cipherText, uint32_t *cipherTextLen);

/**********************************************************************
Function Name: E2EE_ClientDecrypt
Description:   Decrypt data
Input:         ctx - client context
               cipherText - ciphertext
               cipherTextLen - ciphertext length
               aad - additional authenticated data
               aadLen - aad length
Output:        plainText - plaintext
               plainTextLen - plaintext length
Return:        Success - E2EE_SUCCESS
               Failure - other Errcode
**********************************************************************/ 
int32_t E2EE_ClientDecrypt(E2EE_ClientCtx *ctx, uint8_t *cipherText, uint32_t cipherTextLen,
    uint8_t *aad, uint32_t aadLen, uint8_t *plainText, uint32_t *plainTextLen);

/**********************************************************************
Function Name: E2EE_ClientDestroy
Description:   Destroy client context
Input:         ctx - client context
Return:        void
**********************************************************************/
void E2EE_ClientDestroy(E2EE_ClientCtx *ctx);


/**********************************************************************
Function Name: E2EE_ServerCreate
Description:   Create a server context.
return:        ctx - server context
**********************************************************************/
E2EE_ServerCtx *E2EE_ServerCreate(void);

/**********************************************************************
Function Name: E2EE_SetServerKeyDeriveCallback
Description:   Set the key derivation callback, should call before E2EE_ServerInit.
               If do not set, the default key derivation function will be used.
Input:         ctx - server context
               keyDeriveFunc - key derivation callback
               callbackArg - callback argument
Return:        void
**********************************************************************/
void E2EE_SetServerKemCallback(E2EE_ServerCtx *ctx, E2EE_KemDecapsulateCallbackFunc keyDeriveFunc, void *callbackArg);

/**********************************************************************
Function Name: E2EE_ServerInit
Description:   Init the server context.
Input:         ctx - server context
               keyExchInfo - key exchange information
               keyExchInfoNum - key exchange information number
Return:        Success - E2EE_SUCCESS
               Failure - other Errcode
**********************************************************************/
int32_t E2EE_ServerInit(E2EE_ServerCtx *ctx, E2EE_ServerKeyExchInfo keyExchInfo[], uint32_t keyExchInfoNum);

/**********************************************************************
Function Name: E2EE_ServerDecrypt
Description:   Decrypt data. This function will get the ephemeral client public key from the first cipherText
               that from the client, and use it to derive key.
Input:         ctx - server context
               cipherText - ciphertext
               cipherTextLen - ciphertext length
               aad - additional authenticated data
               aadLen - aad length
Output:        plainText - plaintext
               plainTextLen - plaintext length
Return:        Success - E2EE_SUCCESS
               Failure - other Errcode
**********************************************************************/
int32_t E2EE_ServerDecrypt(E2EE_ServerCtx *ctx, uint8_t *cipherText, uint32_t cipherTextLen,
    uint8_t *aad, uint32_t aadLen, uint8_t *plainText, uint32_t *plainTextLen);

/**********************************************************************
Function Name: E2EE_ServerEncrypt
Description:   Encrypt data. This function will expand new symmetric key and use it to encrypt data
               when call this function first time, and the first cipherText will contain a nonce.
               Because E2EE is implemented based on HPKE, so should trust the client by other means,
               and then can call this function.
Input:         ctx - server context
               plainText - plaintext
               plainTextLen - plaintext length
               aad - additional authenticated data
               aadLen - aad length
Output:        cipherText - ciphertext
               cipherTextLen - ciphertext length
Return:        Success - E2EE_SUCCESS
               Failure - other Errcode
**********************************************************************/
int32_t E2EE_ServerEncrypt(E2EE_ServerCtx *ctx, uint8_t *plainText, uint32_t plainTextLen,
    uint8_t *aad, uint32_t aadLen, uint8_t *cipherText, uint32_t *cipherTextLen);

/**********************************************************************
Function Name: E2EE_ServerDestroy
Description:   Destroy server context
Input:         ctx - server context
Return:        void
**********************************************************************/
void E2EE_ServerDestroy(E2EE_ServerCtx *ctx);

#ifdef __cplusplus
}
#endif

#endif