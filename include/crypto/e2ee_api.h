#ifndef E2EE_APH_H
#define E2EE_APH_H

#include "stdint.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    E2EE_P256_HKDF_SHA256 = 0,
    E2EE_P384_HKDF_SHA384 = 1,
    E2EE_P521_HKDF_SHA512 = 2,
    E2EE_X25519_HKDF_SHA256 = 3
} E2EE_KEM_AlgId;

typedef enum {
    E2EE_HKDF_SHA256 = 0,
    E2EE_HKDF_SHA384 = 1,
    E2EE_HKDF_SHA512 = 2,
} E2EE_KDF_AlgId;

typedef enum {
    E2EE_AES_128_GCM = 0,
    E2EE_AES_256_GCM = 1,
    E2EE_CHACHA20_POLY1305 = 2
} E2EE_AEAD_AlgId;

typedef struct {
    E2EE_KEM_AlgId kemAlgId;
    E2EE_KDF_AlgId kdfAlgId;
    E2EE_AEAD_AlgId aeadAlgId;
} E2EE_AlgId;

typedef struct {
    uint8_t *serverPubKey;
    uint32_t serverPubKeyLen;
    uint8_t *info;
    uint32_t infoLen;
} E2EE_ClientInfo;

typedef struct {
    uint8_t *privKey;
    uint32_t privKeyLen;
    uint8_t *info;
    uint32_t infoLen;
} E2EE_ServerInfo;

typedef struct E2EE_ClientCtx E2EE_ClientCtx;
typedef struct E2EE_ServerCtx E2EE_ServerCtx;

/* Memory callback */
typedef struct {
    void *(*fpMalloc)(uint32_t size);
    void (*fpFree)(void *ptr);
} E2EE_MemCallback;

typedef void (*E2EE_logCallback)(void *callbackArg, const char *str, uint32_t len);

/* Key derivation callback, client should convert the info to E2EE_ClientInfo,
server should convert the info to E2EE_ServerInfo.*/
typedef uint32_t (*E2EE_KeyDeriveCallbackFunc)(void *callbackArg, E2EE_AlgId algId, void *info,
    uint8_t *out, uint32_t *outLen);

/**********************************************************************
Function Name: E2EE_RegisterLogCallback
Description:   Register log callback, if do not register, the default log function will be used.
Input:         logCallback - log callback
Return:        Void
**********************************************************************/
void E2EE_RegisterLogCallback(E2EE_logCallback logCallback);

/**********************************************************************
Function Name: E2EE_RegisterMemCallback
Description:   Register memory callback, if do not register, the default memory function will be used.
Input:         memCallback - memory callback
Return:        Success - E2EE_SUCCESS
               Failure - other Errcode
**********************************************************************/
uint32_t E2EE_RegisterMemCallback(E2EE_MemCallback *memCallback);

/**********************************************************************
Function Name: E2EE_ClientCreate
Description:   Create a client context. E2EE is implemented based on HPKE, so a trusted server public key is required.
Input:         algId - E2EE algorithm ID
               clientInfo - client information
               keyDeriveFunc - key derivation function, if set to NULL, the default key derivation function is used.
Output:        ctx - client context
Return:        Success - E2EE_SUCCESS
               Failure - other Errcode
**********************************************************************/
uint32_t E2EE_ClientCreate(E2EE_AlgId algId, E2EE_ClientInfo *clientInfo, E2EE_ClientCtx **ctx);

/**********************************************************************
Function Name: E2EE_SetClientKeyDeriveCallback
Description:   Set key derivation callback
Input:         ctx - client context
               keyDeriveCallback - key derivation callback
               callbackArg - callback argument
Return:        Void
**********************************************************************/
void E2EE_SetClientKeyDeriveCallback(E2EE_ClientCtx *ctx, E2EE_KeyDeriveCallbackFunc keyDeriveFunc, void *callbackArg);

/**********************************************************************
Function Name: E2EE_ClienGetKeyMaterial
Description:   Get key material
Input:         ctx - client context
               keyMaterial - key material
Output:        keyMaterialLen - key material length
Return:        Success - E2EE_SUCCESS
               Failure - other Errcode
**********************************************************************/
uint32_t E2EE_ClienGetKeyMaterial(E2EE_ClientCtx *ctx, uint8_t *keyMaterial, uint32_t *keyMaterialLen);

/**********************************************************************
Function Name: E2EE_ClienEncrypt
Description:   Encrypt data. The first cipherText will contain the E2EE_AlgId info and theephemeral public key.
Input:         ctx - client context
               plainText - plaintext
               plainTextLen - plaintext length
               aad - additional authenticated data
               aadLen - aad length
               cipherText - ciphertext
Output:        cipherTextLen - ciphertext length
Return:        Success - E2EE_SUCCESS
               Failure - other Errcode
**********************************************************************/
uint32_t E2EE_ClienEncrypt(E2EE_ClientCtx *ctx, uint8_t *plainText, uint32_t plainTextLen,
    uint8_t *aad, uint32_t aadLen, uint8_t *cipherText, uint32_t *cipherTextLen);

/**********************************************************************
Function Name: E2EE_ClienDecrypt
Description:   Decrypt data
Input:         ctx - client context
               cipherText - ciphertext
               cipherTextLen - ciphertext length
               aad - additional authenticated data
               aadLen - aad length
               plainText - plaintext
Output:        plainTextLen - plaintext length
Return:        Success - E2EE_SUCCESS
               Failure - other Errcode
**********************************************************************/ 
uint32_t E2EE_ClienDecrypt(E2EE_ClientCtx *ctx, uint8_t *cipherText, uint32_t cipherTextLen,
    uint8_t *aad, uint32_t aadLen, uint8_t *plainText, uint32_t *plainTextLen);

/**********************************************************************
Function Name: E2EE_ClientDestroy
Description:   Destroy client context
Input:         ctx - client context
Return:        Void
**********************************************************************/
void E2EE_ClientDestroy(E2EE_ClientCtx *ctx);

/**********************************************************************
Function Name: E2EE_ServerCreate
Description:   Create a server context.
Input:         algId - E2EE algorithm ID, set supported algorithms.
               algNum - number of algorithms
               serverInfo - server information
               keyDeriveFunc - key derivation function, if set to NULL, the default key derivation function is set.
Output:        ctx - server context
Return:        Success - E2EE_SUCCESS
               Failure - other Errcode
**********************************************************************/
uint32_t E2EE_ServerCreate(E2EE_AlgId algId[], uint32_t algNum, E2EE_ServerInfo *serverInfo, E2EE_ServerCtx **ctx);

/**********************************************************************
Function Name: E2EE_SetServerKeyDeriveCallback
Description:   Set key derivation callback
Input:         ctx - server context
               keyDeriveCallback - key derivation callback
               callbackArg - callback argument
Return:        Void
**********************************************************************/
void E2EE_SetServerKeyDeriveCallback(E2EE_ServerCtx *ctx, E2EE_KeyDeriveCallbackFunc keyDeriveFunc, void *callbackArg);

/**********************************************************************
Function Name: E2EE_ServerGetKeyMaterial
Description:   Get key material
Input:         ctx - server context
               keyMaterial - key material
Output:        keyMaterialLen - key material length
Return:        Success - E2EE_SUCCESS
               Failure - other Errcode
**********************************************************************/
uint32_t E2EE_ServerGetKeyMaterial(E2EE_ServerCtx *ctx, uint8_t *keyMaterial, uint32_t *keyMaterialLen);

/**********************************************************************
Function Name: E2EE_ServerDecrypt
Description:   Decrypt data. This function will get the ephemeral client public key from the first cipherText
               that from the client, and use it to derive key.
Input:         ctx - server context
               cipherText - ciphertext
               cipherTextLen - ciphertext length
               aad - additional authenticated data
               aadLen - aad length
               plainText - plaintext
Output:        plainTextLen - plaintext length
Return:        Success - E2EE_SUCCESS
               Failure - other Errcode
**********************************************************************/
uint32_t E2EE_ServerDecrypt(E2EE_ServerCtx *ctx, uint8_t *cipherText, uint32_t cipherTextLen,
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
               cipherText - ciphertext
Output:        cipherTextLen - ciphertext length
Return:        Success - E2EE_SUCCESS
               Failure - other Errcode
**********************************************************************/
uint32_t E2EE_ServerEncrypt(E2EE_ServerCtx *ctx, uint8_t *plainText, uint32_t plainTextLen,
    uint8_t *aad, uint32_t aadLen, uint8_t *cipherText, uint32_t *cipherTextLen);

/**********************************************************************
Function Name: E2EE_ServerDestroy
Description:   Destroy server context
Input:         ctx - server context
Return:        Void
**********************************************************************/
void E2EE_ServerDestroy(E2EE_ServerCtx *ctx);

#ifdef __cplusplus
}
#endif

#endif