# openHiTLS TLS Certificate Interfaces Reference

## Overview

This document provides a comprehensive reference for all certificate-related interfaces in the openHiTLS TLS library. The openHiTLS library offers a complete set of certificate management functions, supporting both standard TLS and Chinese national cryptographic standards (TLCP).

## Table of Contents

1. [Certificate Storage Management](#certificate-storage-management)
2. [Device Certificate Management](#device-certificate-management)
3. [Certificate Chain Management](#certificate-chain-management)
4. [Certificate Revocation List (CRL) Management](#certificate-revocation-list-crl-management)
5. [Certificate Verification](#certificate-verification)
6. [Password Callback Interfaces](#password-callback-interfaces)
7. [Certificate Selection Callback](#certificate-selection-callback)
8. [Key Logging Interfaces](#key-logging-interfaces)
9. [CA List Management](#ca-list-management)
10. [Certificate Resource Management](#certificate-resource-management)
11. [Client Certificate Verification Configuration](#client-certificate-verification-configuration)
12. [Certificate Initialization](#certificate-initialization)
13. [Data Formats and Algorithms](#data-formats-and-algorithms)

## Certificate Storage Management

### Verify Store (用于证书验证的CA证书存储)

| Interface | Description | Parameters |
|-----------|-------------|------------|
| `HITLS_CFG_SetVerifyStore()` | Set verify store for TLS configuration | `config`, `store`, `isClone` |
| `HITLS_SetVerifyStore()` | Set verify store for TLS context | `ctx`, `store`, `isClone` |
| `HITLS_CFG_GetVerifyStore()` | Get verify store from TLS configuration | `config` |
| `HITLS_GetVerifyStore()` | Get verify store from TLS context | `ctx` |

### Chain Store (用于构建证书链的存储)

| Interface | Description | Parameters |
|-----------|-------------|------------|
| `HITLS_CFG_SetChainStore()` | Set chain store for TLS configuration | `config`, `store`, `isClone` |
| `HITLS_SetChainStore()` | Set chain store for TLS context | `ctx`, `store`, `isClone` |
| `HITLS_CFG_GetChainStore()` | Get chain store from TLS configuration | `config` |
| `HITLS_GetChainStore()` | Get chain store from TLS context | `ctx` |

### General Certificate Store (通用证书存储)

| Interface | Description | Parameters |
|-----------|-------------|------------|
| `HITLS_CFG_SetCertStore()` | Set general certificate store for TLS configuration | `config`, `store`, `isClone` |
| `HITLS_SetCertStore()` | Set general certificate store for TLS context | `ctx`, `store`, `isClone` |
| `HITLS_CFG_GetCertStore()` | Get general certificate store from TLS configuration | `config` |
| `HITLS_GetCertStore()` | Get general certificate store from TLS context | `ctx` |

## Device Certificate Management

### Certificate Setting

| Interface | Description | Parameters |
|-----------|-------------|------------|
| `HITLS_CFG_SetCertificate()` | Set device certificate for TLS configuration | `config`, `cert`, `isClone` |
| `HITLS_SetCertificate()` | Set device certificate for TLS context | `ctx`, `cert`, `isClone` |
| `HITLS_CFG_SetTlcpCertificate()` | Set TLCP device certificate (supports encryption certificate flag) | `config`, `cert`, `isClone`, `isTlcpEncCert` |

### Certificate Loading (从文件/缓冲区加载)

| Interface | Description | Parameters |
|-----------|-------------|------------|
| `HITLS_CFG_LoadCertFile()` | Load certificate from file for TLS configuration | `config`, `file`, `format` |
| `HITLS_LoadCertFile()` | Load certificate from file for TLS context | `ctx`, `file`, `format` |
| `HITLS_CFG_LoadCertBuffer()` | Load certificate from buffer for TLS configuration | `config`, `buf`, `bufLen`, `format` |
| `HITLS_LoadCertBuffer()` | Load certificate from buffer for TLS context | `ctx`, `buf`, `bufLen`, `format` |

### Certificate Parsing (证书解析接口)

| Interface | Description | Parameters |
|-----------|-------------|------------|
| `HITLS_CFG_ParseCert()` | **Parse certificate from file or buffer to X509 object** | `config`, `buf`, `len`, `type`, `format` |

**Note**: Parse interfaces differ from Load interfaces:
- **Load interfaces**: Directly load and set to configuration
- **Parse interfaces**: Only parse to objects, not directly set, user decides how to use

### Private Key Setting

| Interface | Description | Parameters |
|-----------|-------------|------------|
| `HITLS_CFG_SetPrivateKey()` | Set certificate private key for TLS configuration | `config`, `privateKey`, `isClone` |
| `HITLS_SetPrivateKey()` | Set certificate private key for TLS context | `ctx`, `key`, `isClone` |
| `HITLS_CFG_SetTlcpPrivateKey()` | Set TLCP private key (supports encryption certificate flag) | `config`, `privateKey`, `isClone`, `isTlcpEncCertPriKey` |

### Private Key Loading (从文件/缓冲区加载私钥)

| Interface | Description | Parameters |
|-----------|-------------|------------|
| `HITLS_CFG_LoadKeyFile()` | Load private key from file for TLS configuration | `config`, `file`, `format` |
| `HITLS_LoadKeyFile()` | Load private key from file for TLS context | `ctx`, `file`, `format` |
| `HITLS_CFG_LoadKeyBuffer()` | Load private key from buffer for TLS configuration | `config`, `buf`, `bufLen`, `format` |
| `HITLS_LoadKeyBuffer()` | Load private key from buffer for TLS context | `ctx`, `buf`, `bufLen`, `format` |

### Private Key Parsing (私钥解析接口)

| Interface | Description | Parameters |
|-----------|-------------|------------|
| `HITLS_CFG_ParseKey()` | **Parse private key from file or buffer** | `config`, `buf`, `len`, `type`, `format` |

### Provider-Related Interfaces (支持自定义加密提供者)

| Interface | Description | Parameters |
|-----------|-------------|------------|
| `HITLS_CFG_ProviderLoadKeyFile()` | Load private key file using provider for TLS configuration | `config`, `file`, `format`, `type` |
| `HITLS_ProviderLoadKeyFile()` | Load private key file using provider for TLS context | `ctx`, `file`, `format`, `type` |
| `HITLS_CFG_ProviderLoadKeyBuffer()` | Load private key buffer using provider for TLS configuration | `config`, `buf`, `bufLen`, `format`, `type` |
| `HITLS_ProviderLoadKeyBuffer()` | Load private key buffer using provider for TLS context | `ctx`, `buf`, `bufLen`, `format`, `type` |
| `HITLS_CFG_ProviderParseKey()` | **Parse private key using provider** | `config`, `buf`, `len`, `type`, `format`, `encodeType` |

### Certificate Retrieval

| Interface | Description | Parameters |
|-----------|-------------|------------|
| `HITLS_CFG_GetCertificate()` | Get device certificate from TLS configuration | `config` |
| `HITLS_GetCertificate()` | Get local certificate from TLS context | `ctx` |
| `HITLS_GetPeerCertificate()` | Get peer certificate from TLS context | `ctx` |
| `HITLS_CFG_GetPrivateKey()` | Get private key from TLS configuration | `config` |
| `HITLS_GetPrivateKey()` | Get private key from TLS context | `ctx` |

## Certificate Chain Management

### Certificate Chain Operations

| Interface | Description | Parameters |
|-----------|-------------|------------|
| `HITLS_CFG_AddChainCert()` | Add certificate to current certificate chain | `config`, `cert`, `isClone` |
| `HITLS_CFG_AddCertToStore()` | Add certificate to specified certificate store | `config`, `cert`, `storeType`, `isClone` |
| `HITLS_CFG_GetChainCerts()` | Get current certificate chain | `config` |
| `HITLS_CFG_ClearChainCerts()` | Clear certificate chain in configuration | `config` |
| `HITLS_ClearChainCerts()` | Clear certificate chain in context | `ctx` |

### Extra Certificate Chain

| Interface | Description | Parameters |
|-----------|-------------|------------|
| `HITLS_CFG_AddExtraChainCert()` | Add certificate to extra certificate chain | `config`, `cert` |
| `HITLS_CFG_GetExtraChainCerts()` | Get extra certificate chain | `config` |
| `HITLS_CFG_ClearExtraChainCerts()` | Clear extra certificate chain | `config` |

### Certificate Chain Building

| Interface | Description | Parameters |
|-----------|-------------|------------|
| `HITLS_CFG_BuildCertChain()` | Build certificate chain before establishing TLS connection (config) | `config`, `flag` |
| `HITLS_BuildCertChain()` | Build certificate chain before establishing TLS connection (context) | `ctx`, `flag` |

## Certificate Revocation List (CRL) Management

### CRL Loading Interfaces

| Interface | Description | Parameters |
|-----------|-------------|------------|
| `HITLS_CFG_LoadCrlFile()` | **Load CRL from file for TLS configuration** | `config`, `file`, `format` |
| `HITLS_LoadCrlFile()` | **Load CRL from file for TLS context** | `ctx`, `file`, `format` |
| `HITLS_CFG_LoadCrlBuffer()` | **Load CRL from buffer for TLS configuration** | `config`, `buf`, `bufLen`, `format` |
| `HITLS_LoadCrlBuffer()` | **Load CRL from buffer for TLS context** | `ctx`, `buf`, `bufLen`, `format` |

### CRL Management Interfaces

| Interface | Description | Parameters |
|-----------|-------------|------------|
| `HITLS_CFG_ClearVerifyCrls()` | **Clear all CRLs from TLS configuration** | `config` |
| `HITLS_ClearVerifyCrls()` | **Clear all CRLs from TLS context** | `ctx` |

**Notes**:
- CRL (Certificate Revocation List) specifies a list of revoked certificates
- Loaded CRLs are used during certificate verification to check if certificates have been revoked
- Supports loading CRLs from both files and memory buffers
- CRLs must match corresponding CA certificates to be effective
- It is recommended to update CRLs regularly to obtain the latest revocation information

**Usage Examples**:
```c
// Load CRL from file
int32_t ret = HITLS_CFG_LoadCrlFile(config, "ca.crl", TLS_PARSE_FORMAT_PEM);
if (ret != HITLS_SUCCESS) {
    // Handle error
}

// Load CRL from buffer
ret = HITLS_CFG_LoadCrlBuffer(config, crlBuffer, crlLen, TLS_PARSE_FORMAT_ASN1);
if (ret != HITLS_SUCCESS) {
    // Handle error
}

// Clear all CRLs
HITLS_CFG_ClearVerifyCrls(config);
```

## Certificate Verification

### Verification Parameter Setting

| Interface | Description | Parameters |
|-----------|-------------|------------|
| `HITLS_CFG_SetVerifyDepth()` | Set certificate verification depth for configuration | `config`, `depth` |
| `HITLS_SetVerifyDepth()` | Set certificate verification depth for context | `ctx`, `depth` |
| `HITLS_CFG_GetVerifyDepth()` | Get certificate verification depth from configuration | `config`, `depth` |
| `HITLS_GetVerifyDepth()` | Get certificate verification depth from context | `ctx`, `depth` |
| `HITLS_CFG_CtrlSetVerifyParams()` | Set certificate verification parameters for configuration | `config`, `store`, `cmd`, `in`, `inArg` |
| `HITLS_CtrlSetVerifyParams()` | Set certificate verification parameters for context | `ctx`, `store`, `cmd`, `in`, `inArg` |
| `HITLS_CFG_CtrlGetVerifyParams()` | Get certificate verification parameters from configuration | `config`, `store`, `cmd`, `out` |
| `HITLS_CtrlGetVerifyParams()` | Get certificate verification parameters from context | `ctx`, `store`, `cmd`, `out` |

### Verification Callbacks

| Interface | Description | Parameters |
|-----------|-------------|------------|
| `HITLS_CFG_SetVerifyCb()` | Set certificate verification callback for configuration | `config`, `callback` |
| `HITLS_SetVerifyCb()` | Set certificate verification callback for context | `ctx`, `callback` |
| `HITLS_CFG_GetVerifyCb()` | Get certificate verification callback from configuration | `config` |
| `HITLS_GetVerifyCb()` | Get certificate verification callback from context | `ctx` |
| `HITLS_SetVerifyResult()` | Set peer certificate verification result | `ctx`, `verifyResult` |
| `HITLS_GetVerifyResult()` | Get peer certificate verification result | `ctx`, `verifyResult` |

### Private Key Matching Verification

| Interface | Description | Parameters |
|-----------|-------------|------------|
| `HITLS_CFG_CheckPrivateKey()` | Check if certificate matches private key in configuration | `config` |
| `HITLS_CheckPrivateKey()` | Check if certificate matches private key in context | `ctx` |

## Password Callback Interfaces

| Interface | Description | Parameters |
|-----------|-------------|------------|
| `HITLS_CFG_SetDefaultPasswordCb()` | Set default password callback for configuration | `config`, `cb` |
| `HITLS_SetDefaultPasswordCb()` | Set default password callback for context | `ctx`, `cb` |
| `HITLS_CFG_GetDefaultPasswordCb()` | Get default password callback from configuration | `config` |
| `HITLS_GetDefaultPasswordCb()` | Get default password callback from context | `ctx` |
| `HITLS_CFG_SetDefaultPasswordCbUserdata()` | Set password callback user data for configuration | `config`, `userdata` |
| `HITLS_SetDefaultPasswordCbUserdata()` | Set password callback user data for context | `ctx`, `userdata` |
| `HITLS_CFG_GetDefaultPasswordCbUserdata()` | Get password callback user data from configuration | `config` |
| `HITLS_GetDefaultPasswordCbUserdata()` | Get password callback user data from context | `ctx` |

## Certificate Selection Callback

| Interface | Description | Parameters |
|-----------|-------------|------------|
| `HITLS_CFG_SetCertCb()` | Set certificate selection callback for configuration | `config`, `certCb`, `arg` |
| `HITLS_SetCertCb()` | Set certificate selection callback for context | `ctx`, `certCb`, `arg` |

**Note**: Supports dynamic certificate selection during handshake based on SNI and other information.

## Key Logging Interfaces

| Interface | Description | Parameters |
|-----------|-------------|------------|
| `HITLS_CFG_SetKeyLogCb()` | Set TLS key logging callback for configuration | `config`, `callback` |
| `HITLS_CFG_GetKeyLogCb()` | Get TLS key logging callback from configuration | `config` |
| `HITLS_LogSecret()` | Log master key when logging is enabled | `ctx`, `label`, `secret`, `secretLen` |

## CA List Management

| Interface | Description | Parameters |
|-----------|-------------|------------|
| `HITLS_CFG_ParseCAList()` | **Parse CA file or buffer to trusted CA list** | `config`, `input`, `inputLen`, `inputType`, `format`, `caList` |
| `HITLS_GetPeerCertChain()` | Get peer certificate chain | `ctx` |
| `HITLS_GetPeerCAList()` | Get peer CA list | `ctx` |
| `HITLS_GetCAList()` | Get trusted CA list from context | `ctx` |
| `HITLS_SetCAList()` | Set trusted CA list for context | `ctx`, `list` |

## Certificate Resource Management

| Interface | Description | Parameters |
|-----------|-------------|------------|
| `HITLS_CFG_RemoveCertAndKey()` | Release all loaded certificates and private keys from configuration | `config` |
| `HITLS_RemoveCertAndKey()` | Release all loaded certificates and private keys from context | `ctx` |

## Client Certificate Verification Configuration

| Interface | Description | Parameters |
|-----------|-------------|------------|
| `HITLS_CFG_SetClientCertSupport()` | Set whether to verify client certificate in configuration | `config`, `support` |
| `HITLS_SetClientCertSupport()` | Set whether to verify client certificate in context | `ctx`, `support` |
| `HITLS_CFG_SetNoClientCertSupport()` | Set whether to allow client without certificate in configuration | `config`, `support` |
| `HITLS_SetNoClientCertSupport()` | Set whether to allow client without certificate in context | `ctx`, `support` |
| `HITLS_CFG_GetClientCertSupport()` | Get client certificate verification setting from configuration | `config`, `isSupport` |
| `HITLS_GetClientCertSupport()` | Get client certificate verification setting from context | `ctx`, `isSupport` |
| `HITLS_CFG_GetNoClientCertSupport()` | Get no client certificate support setting from configuration | `config`, `isSupport` |
| `HITLS_GetNoClientCertSupport()` | Get no client certificate support setting from context | `ctx`, `isSupport` |

## Certificate Initialization

| Interface | Description | Parameters |
|-----------|-------------|------------|
| `HITLS_CertMethodInit()` | Initialize certificate methods (default uses HITLS X509 interface) | None |
| `HITLS_CertMethodDeinit()` | Deinitialize certificate methods | None |

## Data Formats and Algorithms

### Supported Data Formats

- **PEM Format** - Most common text format
- **ASN1 Format** - Binary DER format  
- **PFX Format** - PKCS#12 format
- **PKCS12 Format** - Another PKCS#12 format

### Supported Algorithms

- **RSA** - Including RSA-PSS
- **ECDSA** - Elliptic Curve Digital Signature Algorithm
- **Ed25519** - Edwards Curve Digital Signature Algorithm
- **SM2** - Chinese National Cryptographic Elliptic Curve Algorithm

### Parse Types

```c
typedef enum {
    TLS_PARSE_TYPE_FILE,   /**< Parse file */
    TLS_PARSE_TYPE_BUFF,   /**< Parse buffer */
    TLS_PARSE_TYPE_BUTT,
} HITLS_ParseType;
```

### Parse Formats

```c
typedef enum {
    TLS_PARSE_FORMAT_PEM = BSL_FORMAT_PEM,        /**< PEM format */
    TLS_PARSE_FORMAT_ASN1 = BSL_FORMAT_ASN1,       /**< ASN1 format */
    TLS_PARSE_FORMAT_PFX_COM = BSL_FORMAT_PFX_COM,    /**< PFX COM format */
    TLS_PARSE_FORMAT_PKCS12 = BSL_FORMAT_PKCS12,     /**< PKCS12 format */
    TLS_PARSE_FORMAT_BUTT = BSL_FORMAT_UNKNOWN,
} HITLS_ParseFormat;
```

### Certificate Store Types

```c
typedef enum {
    TLS_CERT_STORE_TYPE_DEFAULT,   /**< Default CA store */
    TLS_CERT_STORE_TYPE_VERIFY,    /**< Verify store for certificate chain verification */
    TLS_CERT_STORE_TYPE_CHAIN,     /**< Certificate chain store for assembling certificate chain */
    TLS_CERT_STORE_TYPE_BUTT,
} HITLS_CERT_StoreType;
```

## Usage Examples

### Basic Certificate Loading

```c
// Load certificate from file
int32_t ret = HITLS_CFG_LoadCertFile(config, "cert.pem", TLS_PARSE_FORMAT_PEM);
if (ret != HITLS_SUCCESS) {
    // Handle error
}

// Load private key from file
ret = HITLS_CFG_LoadKeyFile(config, "key.pem", TLS_PARSE_FORMAT_PEM);
if (ret != HITLS_SUCCESS) {
    // Handle error
}
```

### Certificate Parsing

```c
// Parse certificate from buffer
HITLS_CERT_X509 *cert = HITLS_CFG_ParseCert(config, certBuffer, certLen, 
                                            TLS_PARSE_TYPE_BUFF, TLS_PARSE_FORMAT_PEM);
if (cert != NULL) {
    // Use parsed certificate
    HITLS_CFG_SetCertificate(config, cert, true);
}
```

### Certificate Chain Building

```c
// Add intermediate certificates to chain
HITLS_CFG_AddChainCert(config, intermediateCert, true);

// Build certificate chain
int32_t ret = HITLS_CFG_BuildCertChain(config, HITLS_BUILD_CHAIN_FLAG_CHECK);
if (ret != HITLS_SUCCESS) {
    // Handle error
}
```

### CRL Management

```c
// Load CA certificate for verification
int32_t ret = HITLS_CFG_LoadCertFile(config, "ca.pem", TLS_PARSE_FORMAT_PEM);
if (ret != HITLS_SUCCESS) {
    // Handle error
}

// Load corresponding CRL file
ret = HITLS_CFG_LoadCrlFile(config, "ca.crl", TLS_PARSE_FORMAT_PEM);
if (ret != HITLS_SUCCESS) {
    // Handle error
}

// Load CRL from memory buffer
uint8_t *crlBuffer = ...; // CRL data
uint32_t crlLen = ...; // CRL length
ret = HITLS_CFG_LoadCrlBuffer(config, crlBuffer, crlLen, TLS_PARSE_FORMAT_ASN1);
if (ret != HITLS_SUCCESS) {
    // Handle error
}

// Clear all loaded CRLs
HITLS_CFG_ClearVerifyCrls(config);

// Load CRL to existing connection at runtime
HITLS_Ctx *ctx = HITLS_New(config);
ret = HITLS_LoadCrlFile(ctx, "new.crl", TLS_PARSE_FORMAT_PEM);
if (ret != HITLS_SUCCESS) {
    // Handle error
}
```

## Error Handling

All certificate interfaces return `HITLS_SUCCESS` on success. For error cases, refer to `hitls_error.h` for specific error codes. Common certificate-related error codes include:

- `HITLS_CERT_ERR_BUILD_CHAIN` - Failed to construct certificate chain
- `HITLS_PARSE_CERT_ERR` - Failed to parse certificate
- `HITLS_CERT_ERR_STORE_DUP` - Failed to duplicate certificate store
- `HITLS_CFG_ERR_LOAD_CRL_FILE` - Failed to load CRL file
- `HITLS_CFG_ERR_LOAD_CRL_BUFFER` - Failed to load CRL buffer
