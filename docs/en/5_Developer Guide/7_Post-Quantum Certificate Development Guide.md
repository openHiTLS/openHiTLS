# openHiTLS Post-Quantum Certificate Development Guide

## Overview

With the rapid development of quantum computing, traditional public-key cryptosystems face the theoretical risk of being broken by quantum algorithms (e.g., Shor's algorithm). To address this challenge, Post-Quantum Cryptography (PQC) has become a major focus in cryptographic standardization and industry practice. Starting from version 0.3.0, the openHiTLS project has focused on building post-quantum cryptographic algorithms, protocols, and supporting PKI, with full support for NIST-standardized post-quantum algorithms and end-to-end deployment from the algorithm layer to the application layer. This document systematically describes how to use post-quantum certificate and key-related features in openHiTLS, including core API call flows, parameter meanings, return values, typical error scenarios, and reference pseudocode examples to help developers complete integration and verification quickly.

## Table of Contents

1. [Post-Quantum Capability Overview](#post-quantum-capability-overview)
2. [Key-Related APIs](#key-related-apis)
3. [Certificate-Related APIs](#certificate-related-apis)
4. [ML-KEM Usage Guide](#ml-kem-usage-guide)
5. [ML-DSA Usage Guide](#ml-dsa-usage-guide)
6. [SLH-DSA Usage Guide](#slh-dsa-usage-guide)
7. [XMSS Usage Guide](#xmss-usage-guide)

## Post-Quantum Capability Overview

The PQC algorithms supported by openHiTLS in the new version fall into the following categories:

### Post-Quantum Digital Signature Algorithms

+ **ML-DSA**: Supports NIST-standard ML-DSA, including ML-DSA-44, ML-DSA-65, and ML-DSA-87.
+ **SLH-DSA**: Supports the hash-based stateless signature algorithm SLH-DSA, including SHA2/SHAKE families at 128/192/256-bit security levels with Small and Fast parameter sets.
+ **XMSS**: Supports the Merkle-tree-based stateful hash signature algorithm, including XMSS and XMSSMT variants with SHA2, SHAKE, and SHAKE256, for all standardized parameter combinations across tree height, number of layers, and security parameters.

### Post-Quantum Key Encapsulation Algorithms

+ **ML-KEM**: Supports ML-KEM-512, ML-KEM-768, and ML-KEM-1024.
+ **FrodoKEM**: Supports FrodoKEM-640, FrodoKEM-976, FrodoKEM-1344, with SHAKE and AES internal PRNG variants.
+ **Classic McEliece**: Supports standard parameter sets such as mceliece348864, mceliece460896, mceliece6688128, mceliece6960119, and mceliece8192128.

### Hybrid Post-Quantum Algorithms

+ **X25519 + ML-KEM**: Hybrid key agreement combining X25519 with ML-KEM-512/768/1024, preserving classical elliptic-curve security while providing NIST Level 1/3/5 post-quantum security.
+ **ECDH + ML-KEM**: Hybrid key agreement based on traditional ECDH and ML-KEM-512/768/1024, providing both classical and post-quantum security.

openHiTLS supports the following PQC algorithms in the X.509 certificate system as certificate public-key/signature algorithms:

- **ML-DSA**
- **SLH-DSA**
- **XMSS**
- **ML-KEM**

> Note: FrodoKEM and Classic McEliece are primarily used for key encapsulation in the current implementation and are not used as mainstream certificate signature algorithms.

## Key-Related APIs

### Key Context Control

#### **`CRYPT_EAL_PkeyNewCtx`**

- **Description**: Creates and initializes an asymmetric key context structure `CRYPT_EAL_PkeyCtx` for the given algorithm ID.

- **Prototype**:

  ```c
  CRYPT_EAL_PkeyCtx *CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_AlgId id)
  ```

- **Parameters**:

  - `id`: Algorithm identifier for the asymmetric key type; the function creates the corresponding key context for this algorithm.

- **Return value**: Pointer to the newly created `CRYPT_EAL_PkeyCtx`; `NULL` on failure.

#### **`CRYPT_EAL_PkeySetParaById`**

- **Description**: Sets algorithm parameters for the given asymmetric key context according to the specified parameter ID.

- **Prototype**:

  ```c
  int32_t CRYPT_EAL_PkeySetParaById(CRYPT_EAL_PkeyCtx *pkey, CRYPT_PKEY_ParaId id)
  ```

- **Parameters**:

  - `pkey`: Pointer to the asymmetric key context to be configured.
  - `id`: Parameter identifier specifying the parameter type to set.

- **Return value**: `HITLS_PKI_SUCCESS`.

#### **`CRYPT_EAL_PkeyGen`**

- **Description**: Generates an asymmetric key pair using the current key context and stores the result in the context for subsequent encryption, signing, etc.

- **Prototype**:

  ```c
  int32_t CRYPT_EAL_PkeyGen(CRYPT_EAL_PkeyCtx *pkey)
  ```

- **Parameters**:

  - `pkey`: Pointer to the key context that receives the generated key pair.

- **Return value**: `HITLS_PKI_SUCCESS`.

#### **`CRYPT_EAL_PkeySetPub`**

- **Description**: Sets externally provided public key data into the key context for subsequent encryption and verification. The caller is responsible for allocating and freeing the public key buffer.

- **Prototype**:

  ```c
  int32_t CRYPT_EAL_PkeySetPub(CRYPT_EAL_PkeyCtx *pkey, const CRYPT_EAL_PkeyPub *key)
  ```

- **Parameters**:

  - `pkey`: Key context pointer that receives the public key.
  - `key`: Pointer to the public key data to store in `pkey`.

- **Return value**: `HITLS_PKI_SUCCESS`.

#### **`CRYPT_EAL_PkeySetPrv`**

- **Description**: Sets externally provided private key data into the key context for subsequent decryption and signing. The caller is responsible for allocating and freeing the private key buffer.

- **Prototype**:

  ```c
  int32_t CRYPT_EAL_PkeySetPrv(CRYPT_EAL_PkeyCtx *pkey, const CRYPT_EAL_PkeyPrv *key)
  ```

- **Parameters**:

  - `pkey`: Key context pointer that receives the private key.
  - `key`: Pointer to the private key data to store in `pkey`.

- **Return value**: `HITLS_PKI_SUCCESS`.

#### **`CRYPT_EAL_PkeyCtrl`**

- **Description**: Generic control interface for the asymmetric key context; the operation is selected by `opt`, and data is passed via `val`.

- **Prototype**:

  ```c
  int32_t CRYPT_EAL_PkeyCtrl(CRYPT_EAL_PkeyCtx *pkey, int32_t opt, void *val, uint32_t len)
  ```

- **Parameters**:

  - `pkey`: Key context to operate on.
  - `opt`: Option identifier for the operation.
  - `val`: Generic data pointer for input/output; type is determined by `opt`.
  - `len`: Length of the data pointed to by `val`.

- **Return value**: `HITLS_PKI_SUCCESS`.

#### **`CRYPT_EAL_PkeyEncapsInit`**

- **Description**: Initializes the asymmetric key encapsulation context and configures it with the given algorithm parameters; used for PQC key encapsulation (e.g., ML-KEM).

- **Prototype**:

  ```c
  int32_t CRYPT_EAL_PkeyEncapsInit(CRYPT_EAL_PkeyCtx *pkey, const BSL_Param *params)
  ```

- **Parameters**:

  - `pkey`: Key context pointer for encapsulation; holds key data during encapsulation.
  - `params`: PQC parameter structure (e.g., KEM scheme, mode); may be NULL for defaults.

- **Return value**: `HITLS_PKI_SUCCESS`.

#### **`CRYPT_EAL_PkeyEncaps`**

- **Description**: Performs key encapsulation: encapsulates a shared secret in ciphertext and outputs both using the given key context.

- **Prototype**:

  ```c
  int32_t CRYPT_EAL_PkeyEncaps(CRYPT_EAL_PkeyCtx *pkey, uint8_t *cipher, uint32_t *cipherLen, uint8_t *sharekey, uint32_t *shareKeyLen)
  ```

- **Parameters**:

  - `pkey`: Initialized key context (public key) for encapsulation.
  - `cipher`: Output buffer for the ciphertext.
  - `cipherLen`: Input: capacity of `cipher`; output: actual ciphertext length.
  - `sharekey`: Output buffer for the shared key.
  - `shareKeyLen`: Input: capacity of `sharekey`; output: actual shared key length.

- **Return value**: `HITLS_PKI_SUCCESS`.

#### **`CRYPT_EAL_PkeyDecapsInit`**

- **Description**: Initializes the asymmetric key decapsulation context for PQC decapsulation to recover the shared key.

- **Prototype**:

  ```c
  int32_t CRYPT_EAL_PkeyDecapsInit(CRYPT_EAL_PkeyCtx *pkey, const BSL_Param *params)
  ```

- **Parameters**:

  - `pkey`: Key context for decapsulation (private key).
  - `params`: PQC parameter structure for decapsulation; may be NULL.

- **Return value**: `HITLS_PKI_SUCCESS`.

#### **`CRYPT_EAL_PkeyDecaps`**

- **Description**: Performs key decapsulation: recovers the shared key from the ciphertext for key agreement.

- **Prototype**:

  ```c
  int32_t CRYPT_EAL_PkeyDecaps( const CRYPT_EAL_PkeyCtx *pkey, const uint8_t *cipher, uint32_t cipherLen, uint8_t *sharekey, uint32_t *shareKeyLen)
  ```

- **Parameters**:

  - `pkey`: Initialized key context (private key) for decapsulation.
  - `cipher`: Input ciphertext buffer.
  - `cipherLen`: Ciphertext length in bytes.
  - `sharekey`: Output buffer for the recovered shared key.
  - `shareKeyLen`: Input: capacity of `sharekey`; output: actual shared key length.

- **Return value**: `HITLS_PKI_SUCCESS`.

### Key Parsing and Encoding

#### **`CRYPT_EAL_DecodeBuffKey`**

- **Description**: Parses an encoded asymmetric key buffer and creates the corresponding key context; used to load PQC public or private keys for signing, verification, or key encapsulation.

- **Prototype**:

  ```c
  int32_t CRYPT_EAL_DecodeBuffKey(int32_t format, int32_t type, BSL_Buffer *encode, const uint8_t *pwd, uint32_t pwdlen, CRYPT_EAL_PkeyCtx **ealPKey)
  ```

- **Parameters**:

  - `format`: Format of the encoded key: `BSL_FORMAT_UNKNOWN` (auto-detect), `BSL_FORMAT_PEM`, or `BSL_FORMAT_ASN1` (DER). For PEM/UNKNOWN, buffer must be null-terminated.
  - `type`: Key type (e.g. `CRYPT_PRIKEY_PKCS8_UNENCRYPT`, `CRYPT_PRIKEY_PKCS8_ENCRYPT`, `CRYPT_PRIKEY_RSA`, `CRYPT_PRIKEY_ECC`, `CRYPT_PUBKEY_SUBKEY`, `CRYPT_PUBKEY_RSA`, `CRYPT_PUBKEY_SUBKEY_WITHOUT_SEQ`).
  - `encode`: Buffer containing the encoded key.
  - `pwd`: Optional password for encrypted keys; `NULL` if not encrypted.
  - `pwdlen`: Password length in bytes.
  - `ealPKey`: Output; receives the created key context pointer.

- **Return value**: `HITLS_PKI_SUCCESS`.

#### **`CRYPT_EAL_DecodeFileKey`**

- **Description**: Parses and decodes asymmetric key data from a key file in the specified format and creates the corresponding key context structure; commonly used in PQC algorithms to load post-quantum public or private key files so they can be used for signing, verification, or key encapsulation.

- **Prototype**:

  ```c
  int32_t CRYPT_EAL_DecodeFileKey(int32_t format, int32_t type, const char *path, uint8_t *pwd, uint32_t pwdlen, CRYPT_EAL_PkeyCtx **ealPKey)
  ```

- **Parameters**:

  - `format`: Input. Specifies the key file encoding format. Supports:
    - `BSL_FORMAT_UNKNOWN`: Auto-detect format
    - `BSL_FORMAT_PEM`: PEM format
    - `BSL_FORMAT_ASN1`: DER/ASN.1 format
  - `type`: Input. Specifies the key type, i.e., which asymmetric key structure to decode. The detailed values are the same as in the `type` parameter of [CRYPT_EAL_DecodeBuffKey](#crypt_eal_decodebuffkey).
  - `path`: Input. Key file path string; the function reads and decodes key data from this path.
  - `pwd`: Input. Optional password pointer for decrypting protected private or public key files; pass `NULL` if the file is not encrypted.
  - `pwdlen`: Input. Password length in bytes.
  - `ealPKey`: Output. Address of the key context pointer; on success, the function allocates and returns the created key context.

- **Return value**: Returns `HITLS_PKI_SUCCESS`.

#### **`CRYPT_EAL_EncodeBuffKey`**

- **Description**: Encodes the key from the context into the specified format; used to export PQC keys for storage, distribution, or certificate generation.

- **Prototype**:

  ```c
  int32_t CRYPT_EAL_EncodeBuffKey(CRYPT_EAL_PkeyCtx *ealPKey, const CRYPT_EncodeParam *encodeParam, int32_t format, int32_t type, BSL_Buffer *encode)
  ```

- **Parameters**:

  - `ealPKey`: Key context to encode.
  - `encodeParam`: PKCS#8 encoding parameters (encryption, protection, etc.); may be NULL.
  - `format`: Output format: `BSL_FORMAT_PEM` or `BSL_FORMAT_ASN1`.
  - `type`: Key type (same as in the `type` parameter of [CRYPT_EAL_DecodeBuffKey](#crypt_eal_decodebuffkey)).
  - `encode`: Output buffer for encoded key; must have sufficient capacity.

- **Return value**: `HITLS_PKI_SUCCESS`.

#### **`CRYPT_EAL_EncodeFileKey`**

- **Description**: Encodes the key data from the asymmetric key context into the specified format and saves it to a file; commonly used in PQC algorithms to export post-quantum public or private key files for key storage, certificate distribution, or inter-system key exchange.

- **Prototype**:

  ```c
  int32_t CRYPT_EAL_EncodeFileKey(CRYPT_EAL_PkeyCtx *ealPKey, const CRYPT_EncodeParam *encodeParam, int32_t format, int32_t type, const char *path)
  ```

- **Parameters**:

  - `ealPKey`: Input. Asymmetric key context structure pointer; the function extracts key data from this context for encoding and writing to the file.
  - `encodeParam`: Input. PKCS#8 encoding parameter structure pointer used to configure key protection, encryption algorithm, and related encoding options.
  - `format`: Input. Specifies the key encoding format of the output file. Supports:
    - `BSL_FORMAT_PEM`: PEM format
    - `BSL_FORMAT_ASN1`: DER/ASN.1 binary format
  - `type`: Input. Specifies the key type, i.e., which asymmetric key structure to encode. The detailed values are the same as in the `type` parameter of [CRYPT_EAL_DecodeBuffKey](#crypt_eal_decodebuffkey).
  - `path`: Input. Target key file path string; the function saves the encoded key data into this file.

- **Return value**: Returns `HITLS_PKI_SUCCESS`.

### Key Signing and Verification

#### **`CRYPT_EAL_PkeySign`**

- **Description**: Signs input data with the given hash algorithm and private key from the context; used for PQC signature schemes.

- **Prototype**:

  ```c
  int32_t CRYPT_EAL_PkeySign(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_MD_AlgId id, const uint8_t *data, uint32_t dataLen, uint8_t *sign, uint32_t *signLen)
  ```

- **Parameters**:

  - `pkey`: Key context (private key) for signing.
  - `id`: Hash algorithm identifier.
  - `data`, `dataLen`: Data to sign (length in [0, 0xffffffff]).
  - `sign`: Output buffer for the signature; should be at least the size returned by `CRYPT_EAL_PkeyGetSignLen`.
  - `signLen`: Input: capacity of `sign`; output: actual signature length.

- **Return value**: `HITLS_PKI_SUCCESS`.

#### **`CRYPT_EAL_PkeyGetSignLen`**

- **Description**: Obtains the signature length for the signature algorithm corresponding to the current key context; in post-quantum signature algorithms this is used to determine the signature buffer size so that the signature can be stored completely.

- **Prototype**:

  ```c
  uint32_t CRYPT_EAL_PkeyGetSignLen(const CRYPT_EAL_PkeyCtx *pkey)
  ```

- **Parameters**:

  - `pkey`: Input. Asymmetric key session structure pointer used to query the standard signature length for the signature algorithm corresponding to this key.

- **Return value**: Returns the signature length in bytes for the current key’s signature algorithm; returns 0 on failure.

#### **`CRYPT_EAL_PkeyVerify`**

- **Description**: Performs digital signature verification using the specified hash algorithm and asymmetric key context. In post-quantum algorithms it is used to verify whether signatures generated by PQC signature schemes are complete and trustworthy.

- **Prototype**:

  ```c
  int32_t CRYPT_EAL_PkeyVerify(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_MD_AlgId id, const uint8_t *data, uint32_t dataLen, const uint8_t *sign, uint32_t signLen)
  ```

- **Parameters**:

  - `pkey`: Input. Asymmetric key session structure pointer; the function uses the public key in this context to perform signature verification.
  - `id`: Input. Hash algorithm identifier used for verification.
  - `data`: Input. Pointer to the original data buffer whose signature is being verified.
  - `dataLen`: Input. Length of the data to be verified, in the range [0, 0xffffffff].
  - `sign`: Input. Pointer to the signature data buffer to verify.
  - `signLen`: Input. Signature data length.

- **Return value**: Returns `HITLS_PKI_SUCCESS`.

## Certificate-Related APIs

### Certificate Object and Encoding

#### **`HITLS_X509_CertNew`**

- **Description**: Creates and initializes an empty certificate structure for later filling with PQC algorithm information.

- **Prototype**:

  ```c
  HITLS_X509_Cert *HITLS_X509_CertNew(void);
  ```

- **Return value**: Pointer to the new `HITLS_X509_Cert`; `NULL` on failure.

#### **`HITLS_X509_CertSign`**

- **Description**: Validates the certificate TBS and signs it with the given private key and signature algorithm to complete issuance. Supports ML-DSA, SLH-DSA, XMSS, and other PQC signing keys.

- **Prototype**:

  ```c
  int32_t HITLS_X509_CertSign(int32_t mdId, const CRYPT_EAL_PkeyCtx *prvKey, const HITLS_X509_SignAlgParam *algParam, HITLS_X509_Cert *cert)
  ```

- **Parameters**:

  - `mdId`: Digest algorithm for signing.
  - `prvKey`: Private key context for signing.
  - `algParam`: Signature algorithm parameters.
  - `cert`: Certificate object with TBS already constructed.

- **Return value**: `HITLS_PKI_SUCCESS`.

#### **`HITLS_X509_CertCtrl`**

- **Description**: Generic control interface for certificates. By passing different command enums `cmd` and `void` pointer `val`, it provides unified control over certificate objects. In PQC certificate scenarios, this interface can be used to configure certificate structure content that includes post-quantum public key identifiers, extensions, and algorithm-related information, providing complete data for subsequent signing and encoding.

- **Prototype**:

  ```c
  int32_t HITLS_X509_CertCtrl(HITLS_X509_Cert *cert, int32_t cmd, void *val, uint32_t valLen)
  ```

- **Parameters**:

  - `cert`: Pointer to the certificate object to operate on. If `NULL`, `HITLS_X509_ERR_INVALID_PARAM` is returned to indicate an invalid parameter.
  - `cmd`: Control command identifier specifying the operation type for this call; the function dispatches internally based on this command. For PQC certificates, `HITLS_X509_SET_PUBKEY` and `HITLS_X509_GET_PUBKEY` write/read PQC public keys, and in extension control commands, KeyUsage restrictions for ML-KEM, ML-DSA, and SLH-DSA certificates are especially important.
  - `val`: Generic data pointer used to pass in or out specific data; the function converts the data type according to `cmd`.
  - `valLen`: Length of the data pointed to by `val`.

- **Return value**: Returns `HITLS_PKI_SUCCESS`.

#### **`HITLS_X509_CertParseBuff`**

- **Description**: Parses PEM or ASN.1-encoded certificate data from a buffer into an internal `HITLS_X509_Cert` object; entry point for loading PQC certificates (ML-DSA, SLH-DSA, XMSS, etc.) for algorithm identification, signature verification, and extension checks.

- **Prototype**:

  ```c
  int32_t HITLS_X509_CertParseBuff(int32_t format, const BSL_Buffer *encode, HITLS_X509_Cert **cert)
  ```

- **Parameters**:

  - `format`: `BSL_FORMAT_PEM`, `BSL_FORMAT_ASN1`, or `BSL_FORMAT_UNKNOWN`. For PEM/UNKNOWN, buffer must be null-terminated.
  - `encode`: Buffer containing the certificate data.
  - `cert`: Output; receives the allocated certificate object; caller must free it.

- **Return value**: `HITLS_PKI_SUCCESS`.

> Provider variant:
> ```c
> int32_t HITLS_X509_ProviderCertParseBuff(HITLS_PKI_LibCtx *libCtx, const char *attrName, const char *format, const BSL_Buffer *encode, HITLS_X509_Cert **cert)
> ```
> `libCtx` specifies the crypto library environment; `attrName` selects the Provider.
>
> Bundle (multiple certificates):
> ```c
> int32_t HITLS_X509_CertParseBundleBuff(int32_t format, const BSL_Buffer *encode, HITLS_X509_List **certlist);
> int32_t HITLS_X509_ProviderCertParseBundleBuff(HITLS_PKI_LibCtx *libCtx, const char *attrName, const char *format, const BSL_Buffer *encode, HITLS_X509_List **certlist);
> ```
> `certlist` receives the list of parsed certificates.

#### **`HITLS_X509_CertParseFile`**

- **Description**: Reads and parses PEM or ASN.1 X.509 certificate data from the specified file path into an internal `HITLS_X509_Cert` object. It is the file-level entry interface for loading and verifying post-quantum certificates, responsible for converting certificate files that contain ML-DSA, SLH-DSA, XMSS and other PQC signature algorithm identifiers and public key information into internal certificate structures for subsequent public key extraction, signature verification, extension checking, and algorithm recognition.

- **Prototype**:

  ```c
  int32_t HITLS_X509_CertParseFile(int32_t format, const char *path, HITLS_X509_Cert **cert)
  ```

- **Parameters**:

  - `format`: Specifies the certificate encoding format. Supports:
    - `BSL_FORMAT_PEM`: PEM format
    - `BSL_FORMAT_ASN1`: DER/ASN.1 binary format
    - `BSL_FORMAT_UNKNOWN`: Auto-detect format
  - `path`: Pointer to the certificate file path string; the function reads and parses the certificate file content from this path.
  - `cert`: Output parameter. Pointer used to receive the allocated certificate object; if parsing succeeds, the function allocates and returns an `HITLS_X509_Cert` instance which the caller must free after use.

- **Return value**: Returns `HITLS_PKI_SUCCESS`.

> Provider variant: `HITLS_X509_ProviderCertParseFile(...)`. Bundle: `HITLS_X509_CertParseBundleFile`, `HITLS_X509_ProviderCertParseBundleFile`; `certlist` receives the certificate list.
>
> CRL, CSR, and PKCS#12 use similar interfaces and parameters for generation, parsing, and encoding.

#### **`HITLS_X509_CertGenBuff`**

- **Description**: Encodes the internal `HITLS_X509_Cert` object to PEM or ASN.1 binary data; used for certificate storage, transfer, and distribution (including PQC signatures and extensions).

- **Prototype**:

  ```c
  int32_t HITLS_X509_CertGenBuff(int32_t format, HITLS_X509_Cert *cert, BSL_Buffer *buff)
  ```

- **Parameters**:

  - `format`: `BSL_FORMAT_PEM` or `BSL_FORMAT_ASN1`.
  - `cert`: Certificate to encode.
  - `buff`: Output buffer for encoded certificate data.

- **Return value**: `HITLS_PKI_SUCCESS`.

> Similar interface for writing to a file: `HITLS_X509_CertGenFile(int32_t format, HITLS_X509_Cert *cert, const char *path)`; `path` is the output file path.

### Certificate Chain Building and Verification

#### **`HITLS_X509_StoreCtxNew`**

- **Description**: Creates and initializes a certificate store context `HITLS_X509_StoreCtx` for loading and managing trusted certificates (including PQC) and for chain verification.

- **Prototype**:

  ```c
  HITLS_X509_StoreCtx *HITLS_X509_StoreCtxNew(void)
  ```

- **Return value**: Pointer to the new `HITLS_X509_StoreCtx`; `NULL` on failure.

#### **`HITLS_X509_StoreCtxCtrl`**

- **Description**: Configures parameters, manages certificate chains, sets verification callbacks, and queries status for the certificate store context `StoreCtx` via control commands; this is the core interface for configuring and running the post-quantum certificate chain verification environment.

- **Prototype**:

  ```c
  int32_t HITLS_X509_StoreCtxCtrl(HITLS_X509_StoreCtx *storeCtx, int32_t cmd, void *val, uint32_t valLen)
  ```

- **Parameters**:

  - `storeCtx`: Pointer to the certificate store context object, which is the target of control operations and mainly manages chain verification policies and the trusted certificate collection.
  - `cmd`: Control command identifier specifying the operation type for this call. The function dispatches internally according to the command value.
  - `val`: Generic data pointer used to pass in or out specific data; the function converts the data type according to `cmd`.
  - `valLen`: Length of the data pointed to by `val`.

- **Return value**: Returns `HITLS_PKI_SUCCESS`.

#### **`HITLS_X509_CertVerify`**

- **Description**: Verifies the validity of a certificate chain based on the specified certificate store context. By using the trusted certificate collection and verification policies configured in the store context, it performs step-by-step verification on chains that contain ML-DSA, SLH-DSA, XMSS and other PQC signature algorithms, ensuring signature validity, chain structure correctness, and algorithm compatibility, thereby supporting post-quantum secure communication authentication flows.

- **Prototype**:

  ```c
  int32_t HITLS_X509_CertVerify(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *chain)
  ```

- **Parameters**:

  - `storeCtx`: Pointer to the certificate store context object; the function uses the trusted certificate store, verification policies, and security parameters configured here to perform chain verification.
  - `chain`: Pointer to the certificate chain list structure to be verified. The list usually contains the end-entity certificate and its issuing CA certificates; the function verifies signatures and structural legality along the chain.

- **Return value**: Returns `HITLS_PKI_SUCCESS`.

#### **`HITLS_X509_CertVerifyByPubKey`**

- **Description**: Verifies the digital signature of a single certificate using an externally provided public key context. It supports using public keys of ML-DSA, SLH-DSA, XMSS and other PQC signature algorithms to verify certificate signatures, and is suitable for scenarios that do not rely on certificate chain verification.

- **Prototype**:

  ```c
  int32_t HITLS_X509_CertVerifyByPubKey(HITLS_X509_Cert *cert, CRYPT_EAL_PkeyCtx *pubKey)
  ```

- **Parameters**:

  - `cert`: Pointer to the certificate object whose signature is to be verified. The function extracts the signature data and encoded certificate content from this object; the certificate must have been parsed or generated before this call.
  - `pubKey`: Pointer to the public key context used to provide the public key for signature verification.

- **Return value**: Returns `HITLS_PKI_SUCCESS`.

#### **`HITLS_X509_CheckKey`**

- **Description**: Uses signature verification to check whether the public key in a certificate matches the given private key. It can be used to verify the public/private key consistency of ML-DSA, SLH-DSA, XMSS and other post-quantum signature algorithms, and is commonly used before certificate issuance to prevent wrong keys from being used.

- **Prototype**:

  ```c
  int32_t HITLS_X509_CheckKey(HITLS_X509_Cert *cert, CRYPT_EAL_PkeyCtx *prvKey)
  ```

- **Parameters**:

  - `cert`: Pointer to the certificate object containing the public key to be checked; the function performs signature operations on the certificate data to determine whether the public and private keys belong to the same key pair.
  - `prvKey`: Pointer to the private key context, which provides the private key used in the matching check; in PQC certificate scenarios, this private key corresponds to the post-quantum signature algorithm.

- **Return value**: Returns `HITLS_PKI_SUCCESS`.

### CMS APIs

#### **`HITLS_CMS_ProviderNew`**

- **Description**: Based on the PKI library context and Provider attributes, creates a new CMS (Cryptographic Message Syntax) handle, which can be used to create CMS contexts that support post-quantum algorithms (such as ML-DSA and SLH-DSA) for generating or parsing signed data, certificate distribution, signature encapsulation, and secure message exchange.

- **Prototype**:

  ```c
  HITLS_CMS *HITLS_CMS_ProviderNew(HITLS_PKI_LibCtx *libCtx, const char *attrName, int32_t dataType)
  ```

- **Parameters**:

  - `libCtx`: Pointer to the PKI library context object, specifying the current algorithm environment. Under the Provider mechanism, this context is used to find and load implementation modules that support specific algorithms.
  - `attrName`: Provider attribute or configuration name string used to select CMS implementation modules with specific capabilities.
  - `dataType`: Specifies the CMS content type to determine the data structure processed by the CMS handle. The current interface only supports the SignedData structure of PKCS#7, indicated by enum value `BSL_CID_PKCS7_SIGNEDDATA`.

- **Return value**: Pointer to the newly created `HITLS_CMS` object; returns `NULL` on failure.

#### **`HITLS_CMS_DataSign`**

- **Description**: Creates a SignerInfo in CMS SignedData and optionally performs one-shot signing; supports ML-DSA and other PQC private keys. Digest and SignedAttrs must comply with RFC 9882: if SignedAttrs are absent, ML-DSA must use SHA-512; if present, the following digest mapping applies:

  | ML-DSA  | Allowed digest algorithms |
  | --------|-----------------------------|
  | ML-DSA-44 | SHA256, SHA384, SHA512, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256 |
  | ML-DSA-65 | SHA384, SHA512, SHA3-384, SHA3-512, SHAKE256 |
  | ML-DSA-87 | SHA512, SHA3-512, SHAKE256 |

  Violations return `HITLS_CMS_ERR_MLDSA_INVALID_DIGEST`.

- **Prototype**:

  ```c
  int32_t HITLS_CMS_DataSign(HITLS_CMS *cms, CRYPT_EAL_PkeyCtx *prvKey, HITLS_X509_Cert *cert, BSL_Buffer *msg, const BSL_Param *optionalParam);
  ```

- **Parameters**:

  - `cms`: Pointer to CMS handle; must be of SignedData type. The function will create and add a SignerInfo structure into this CMS.
  - `prvKey`: Pointer to the signing private key context. When `msg` is not `NULL` (one-shot signing), this parameter is required; when only creating SignerInfo for streaming signing, it can be `NULL`. For PQC, ML-DSA private keys are supported.
  - `cert`: Signer’s certificate, used to construct the signer identification information in SignerInfo, such as issuer and serialNumber, and can be embedded into the CMS structure.
  - `msg`: Pointer to the message data buffer to be signed. If not `NULL`, one-shot signing is performed and a signature value is generated; if `NULL`, only SignerInfo is created and signing can be completed later via streaming interfaces.
  - `optionalParam`: Optional parameter structure pointer containing additional untrusted certificate lists, CA certificate lists or other extended configuration; it can be `NULL`.

- **Return value**: Returns `HITLS_PKI_SUCCESS`.

#### **`HITLS_CMS_DataVerify`**

- **Description**: Verifies all signatures in CMS SignedData; supports verification of PQC-signed SignedData. If SignedAttrs are absent, digest must be SHA512 (`HITLS_CMS_ERR_MLDSA_ERROR_DIGEST` otherwise); if present, ML-DSA/digest must match the table above (`HITLS_CMS_ERR_MLDSA_INVALID_DIGEST` otherwise).

- **Prototype**:

  ```c
  int32_t HITLS_CMS_DataVerify(HITLS_CMS *cms, BSL_Buffer *msg, const BSL_Param *inputParam, BSL_Buffer *output)
  ```

- **Parameters**:

  - `cms`: Pointer to the CMS structure containing signatures to verify; must be of SignedData type. The function iterates over all SignerInfo entries and performs signature verification.
  - `msg`: Pointer to the message data buffer to be verified. In detached-signature cases this must not be `NULL`; in non-detached cases it can be `NULL`, in which case the embedded CMS content is used.
  - `inputParam`: Optional input parameter structure pointer containing additional untrusted certificate lists, CA certificate lists or other auxiliary verification information; it can be `NULL`.
  - `output`: Output parameter used to return the actual message data involved in verification. In detached-signature cases it points to `msg`, and in non-detached cases it points to the CMS-embedded content. If the caller does not need the message data, this can be set to `NULL`.

- **Return value**: Returns `HITLS_PKI_SUCCESS`.

## ML-KEM Usage Guide

### Initial Setup
The first step in developing a post-quantum certificate is to complete initialization, which includes initializing error codes and random numbers, as well as registering the malloc and free functions.
```c
// Initialize error code module
BSL_ERR_Init();

// Before calling the algorithm API interface, you need to call the BSL_SAL_CallBack_Ctrl function to register the malloc and free functions. This step only needs to be performed once.
// If not registered and default capabilities are not restricted, the default Linux implementation will be used, with StdMalloc serving as a demonstration of a custom malloc function.
BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, StdMalloc);
BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE, free);

// Initialize a random number; here, we'll use the SHA256 algorithm as an example. Otherwise, you'll encounter the error CRYPT_NO_REGIST_RAND.
ret = CRYPT_EAL_ProviderRandInitCtx(NULL, CRYPT_RAND_SHA256, "provider=default", NULL, 0, NULL);
if (ret != CRYPT_SUCCESS) {
    printf("CRYPT_EAL_PkeyDecrypt: error code is %x\n", ret);
    goto EXIT;
}
```

> To ensure readability of the pseudocode, the subsequent pseudocode omits the handling logic when the return value does not meet expectations.

### Key Setup

1. **Create ML-KEM key pair**

   ```c
   // Create asymmetric key context for ML-KEM
   CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ML_KEM);
   // Set parameter id: CRYPT_KEM_TYPE_MLKEM_512 / CRYPT_KEM_TYPE_MLKEM_768 / CRYPT_KEM_TYPE_MLKEM_1024
   uint32_t id = CRYPT_KEM_TYPE_MLKEM_512;
   int32_t ret = CRYPT_EAL_PkeySetParaById(ctx, id);
   // Initialize RNG
   ret = CRYPT_EAL_ProviderRandInitCtx(NULL, CRYPT_RAND_SHA256, "provider=default", NULL, 0, NULL);
   // Generate key pair and store in context
   ret = CRYPT_EAL_PkeyGen(ctx);
   ```

   **Typical error codes**:

   | Enum | Cause | Trigger |
   |------|--------|---------|
   | `CRYPT_MLKEM_CTRL_INIT_REPEATED` | Key context initialized more than once | Calling `CRYPT_EAL_PkeySetParaById` multiple times |
   | `CRYPT_MLKEM_KEYINFO_NOT_SET` | Algorithm type not set | Performing operations without calling `CRYPT_EAL_PkeySetParaById` |

2. **Key control**

   ```c
   // Set private key encoding format
   uint32_t dkFormat = CRYPT_ALGO_MLKEM_DK_FORMAT_SEED_ONLY;
   int32_t ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_MLKEM_DK_FORMAT, &dkFormat, sizeof(dkFormat));
   
   // Get private key encoding format
   uint32_t curDkFmt = 0;
   ret = CRYPT_EAL_PkeyCtrl(ealPriKey, CRYPT_CTRL_GET_MLKEM_DK_FORMAT, &curDkFmt, sizeof(curDkFmt));
   
   // Get private key seed
   uint8_t seed[64] = {0};
   ret = CRYPT_EAL_PkeyCtrl(ealPriKey, CRYPT_CTRL_GET_MLKEM_SEED, seed, MLKEM_SEED_BYTES_LEN);
   ```

   **Typical error codes**:

   | Enum | Cause | Trigger |
   |------|--------|---------|
   | `CRYPT_MLKEM_CTRL_NOT_SUPPORT` | ML-KEM does not support this opcode | Invalid `opt` in `CRYPT_EAL_PkeyCtrl` |
   | `CRYPT_MLKEM_SEED_NOT_SET` | Seed not stored in context | `CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_MLKEM_SEED, ...)` on context that only has raw private key |

3. **Key pair encode/decode**

   **Encode**: Before encoding, set private key representation via `CRYPT_EAL_PkeyCtrl` with `CRYPT_CTRL_SET_MLKEM_DK_FORMAT`. Supported formats (`CRYPT_ALGO_MLKEM_DK_FORMAT_TYPE`): `CRYPT_ALGO_MLKEM_DK_FORMAT_BOTH` (seed + expanded key), `CRYPT_ALGO_MLKEM_DK_FORMAT_DK_ONLY` (expanded key only), `CRYPT_ALGO_MLKEM_DK_FORMAT_SEED_ONLY` (seed only).

   ```c
   // Encode to buffer
   BSL_Buffer out = {0};
   uint32_t dkFormat = CRYPT_ALGO_MLKEM_DK_FORMAT_SEED_ONLY;
   ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_MLKEM_DK_FORMAT, &dkFormat, sizeof(dkFormat));
   ret = CRYPT_EAL_EncodeBuffKey(pkey, NULL, BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &out);
   
   // Encode to file
   ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_MLKEM_DK_FORMAT, &dkFormat, sizeof(dkFormat));
   ret = CRYPT_EAL_EncodeFileKey(pkey, NULL, BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, "mlkem512_gen_seed.pem");
   ```

   **Decode**

   ```c
   // 1. Decode key pair from buffer
   CRYPT_EAL_PkeyCtx *prvKey = NULL;
   ret = CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &keyBuf, NULL, 0, &prvKey);
   
   // 2. Decode key pair from file
   prvKey = NULL;
   ret = CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, "mlkem512_prikey_seed.pem", NULL, 0, &prvKey);
   ```

   **Set public/private key**

   ```c
   // Set public key
   CRYPT_EAL_PkeyPub ek = { 0 };
   ek.id = CRYPT_PKEY_ML_KEM;
   ek.key.kemEk.data =  BSL_SAL_Malloc(encapsKeyLen);
   (void)memcpy_s(ek.key.kemEk.data, encapsKeyLen, pubkey->x, pubkey->len);
   ek.key.kemEk.len = encapsKeyLen;
   ret = CRYPT_EAL_PkeySetPub(ctx, &ek);
   
   // Set private key
   CRYPT_EAL_PkeyPrv dk = { 0 };
   dk.id = CRYPT_PKEY_ML_KEM;
   dk.key.kemDk.data =  BSL_SAL_Malloc(decapsKeyLen);
   (void)memcpy_s(dk.key.kemDk.data, decapsKeyLen, prvkey->x, prvkey->len);
   dk.key.kemDk.len = decapsKeyLen;
   ret = CRYPT_EAL_PkeySetPrv(ctx, &dk);
   ```

   **Typical error codes**:

   | Enum | Cause | Trigger |
   |------|--------|---------|
   | `CRYPT_MLKEM_KEY_NOT_SET` | Public or private key not set in context when getting | Calling `CRYPT_EAL_PkeyGetPrv` or `CRYPT_EAL_PkeyGetPub` when key is absent |
   | `CRYPT_MLKEM_KEY_REPEATED_SET` | Context already has public or private key | Calling `CRYPT_EAL_PkeySetPrv` or `CRYPT_EAL_PkeySetPub` when key already set |
   | `CRYPT_MLKEM_DECODE_KEY_OVERFLOW` | Decoded key value out of range | Malformed key in `CRYPT_EAL_PkeySetPub`/`SetPrv` |
   | `CRYPT_MLKEM_SEED_EXPANDED_KEY_INCONSISTENT` | Seed-derived key does not match provided expanded key or decoded z mismatch | `CRYPT_EAL_DecodeFileKey` key or `CRYPT_EAL_PkeySetPrv` pkey inconsistent with seed |
   | `CRYPT_MLKEM_INVALID_PRVKEY` | Private key empty, wrong length, or pairwise check failed | Invalid key in `CRYPT_EAL_DecodeFileKey` or `CRYPT_EAL_PkeyPrvCheck` with `HITLS_CRYPTO_MLKEM_CHECK` |
   | `CRYPT_MLKEM_PAIRWISE_CHECK_FAIL` | Public and private key do not match | `CRYPT_EAL_PkeyPairCheck` with `HITLS_CRYPTO_MLKEM_CHECK` |
   | `CRYPT_MLKEM_DK_FORMAT_ERROR` | Wrong private key encoding format or seed missing when seed format required | Setting format then calling `CRYPT_EAL_EncodeBuffKey`/`EncodeFileKey` to export private key |

4. **Key encapsulation**

   ```c
   ret = CRYPT_EAL_PkeyEncapsInit(pubkey_ctx, NULL);
   ret = CRYPT_EAL_PkeyEncaps(pubkey_ctx, ciphertext, &cipherLen, sharedKey, &sharedLen);
   decSharedLen = sharedLen;
   ret = CRYPT_EAL_PkeyDecapsInit(prvkey_ctx, NULL);
   ret = CRYPT_EAL_PkeyDecaps(prvkey_ctx, ciphertext, cipherLen, decSharedKey, &decSharedLen);
   ```

   **Typical errors**: `CRYPT_MLKEM_LEN_NOT_ENOUGH` (buffer too small), `CRYPT_MLKEM_INVALID_PRVKEY` (invalid private key in decaps).

### Certificate Setup

1. **Certificate creation and parsing**

   ```c
   // Create a new certificate
   HITLS_X509_Cert *cert = HITLS_X509_CertNew();
   if (cert == NULL) {
       printf("Failed to create empty certificate object\n");
       return HITLS_X509_ERR_CERT_EXIST;
   }
   
   // Read certificate from file
   HITLS_X509_Cert *cert = NULL;
   HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "mlkem_end.crt", &cert);
   if (cert == NULL) {
       printf("Failed to create empty certificate object\n");
       return HITLS_X509_ERR_CERT_EXIST;
   }
   ```

2. **Certificate control**

   ```c
   // Set certificate info and configure public key
   ret = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_VERSION, &version, sizeof(version));
   
   ret = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SERIALNUM, serialNum, sizeof(serialNum));
   ...
   ret = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_PUBKEY, pubkey, 0);
   
   // Define KeyUsage extension: ML-KEM certificates only allow keyEncipherment per draft-ietf-lamps-kyber-certificates
   HITLS_X509_ExtKeyUsage ku;
   ku.critical = true;
   ku.keyUsage = HITLS_X509_EXT_KU_KEY_ENCIPHERMENT;
   ret = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_KUSAGE, &ku, sizeof(HITLS_X509_ExtKeyUsage));
   ```

   > For ML-KEM, KeyUsage is optional; if set, it must be only `HITLS_X509_EXT_KU_KEY_ENCIPHERMENT` (key encapsulation), otherwise verification fails per draft-ietf-lamps-kyber-certificates. Per RFC 5280, if KeyUsage is absent no restriction applies and verification should succeed.

3. **Certificate signing and verification**

   ```c
   // Sign ML-KEM certificate
   ret = HITLS_X509_CertSign(CRYPT_MD_SHA256, signKey, &algParam, cert);
   
   ret = HITLS_X509_CertGenFile(BSL_FORMAT_PEM, cert, "mlkem_ee.pem");
   
   // 1. Verify with public key
   ret = HITLS_X509_CertVerifyByPubKey(cert, pubkey);
   
   // 2. Build chain and verify
   // Define storage context and certificate chain pointer
   HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
   HITLS_X509_List *chain = NULL;
   
   // Add intermediate CA certificate to context
   HITLS_X509_Cert *inter = NULL;
   ret = HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, "mlkem_inter.pem", &inter);

   ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, inter, sizeof(HITLS_X509_Cert));
   
   // Parse terminal certificates
   HITLS_X509_Cert *entity = NULL;
   ret = HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "mlkem_entity.pem", &entity);
   
   // Building the certificate chain
   ret = HITLS_X509_CertChainBuild(store, false, entity, &chain);
   
   // Add the root certificate to the context
   HITLS_X509_Cert *root = NULL;
   ret = HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "mlkem_root.pem", &root);
   
   ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, root, sizeof(HITLS_X509_Cert));
   
   // Rebuild the certificate chain
   ret = HITLS_X509_CertChainBuild(store, false, entity, &chain);
   
   // Verify the certificate chain
   ret = HITLS_X509_CertVerify(store, chain);
   ```

   **Typical error codes**:

   | Enum | Cause | Trigger |
   |------|--------|---------|
   | `HITLS_X509_ERR_EXT_KU` | KeyUsage in `HITLS_X509_ExtKeyUsage` is wrong | `HITLS_X509_CertCtrl` with `keyUsage` not equal to `keyEncipherment` for ML-KEM |

## ML-DSA Usage Guide

### Key Setup

1. **Create ML-DSA key pair**

   ```c
   // Create asymmetric key context for ML-DSA according to its algorithm ID
   CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ML_DSA);
   // Set parameter id: CRYPT_MLDSA_TYPE_MLDSA_44 / CRYPT_MLDSA_TYPE_MLDSA_65 / CRYPT_MLDSA_TYPE_MLDSA_87
   uint32_t id = CRYPT_MLDSA_TYPE_MLDSA_65;
   int32_t ret = CRYPT_EAL_PkeySetParaById(ctx, id);
   // Initialize RNG
   ret = CRYPT_EAL_ProviderRandInitCtx(NULL, CRYPT_RAND_SHA256, "provider=default", NULL, 0, NULL);
   // Generate key pair and store in context
   ret = CRYPT_EAL_PkeyGen(ctx);
   ```

   **Typical error enums**:

   | Enum                           | Cause                                 | Scenario                                                                                          |
   |--------------------------------|----------------------------------------|---------------------------------------------------------------------------------------------------|
   | `CRYPT_MLDSA_KEYINFO_NOT_SET`  | Algorithm parameters not set           | Did not call `CRYPT_EAL_PkeySetParaById` to set algorithm                                        |
   | `CRYPT_MLDSA_CTRL_INIT_REPEATED` | Key context initialized multiple times | Calling `CRYPT_EAL_PkeySetParaById` multiple times                                               |
   | `CRYPT_MLDSA_CTRL_NOT_SUPPORT` | ML-DSA algorithm does not support opcode | Invalid `opt` passed to `CRYPT_EAL_PkeyCtrl`                                                     |
   | `CRYPT_MLDSA_SEED_NOT_SET`     | Seed not recorded in context           | Calling `CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_MLDSA_SEED, ...)` on a context that only stores private key data |

2. **Key control**

   ```c
   // Set private key encoding format
   uint32_t dkFormat = CRYPT_ALGO_MLDSA_PRIV_FORMAT_PRIV_ONLY;
   int32_t ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_MLDSA_PRVKEY_FORMAT, &dkFormat, sizeof(dkFormat));
                                    
   // Set deterministic signing mode: 0 = randomized, 1 = deterministic
   uint32_t deterministic = 1;
   CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_DETERMINISTIC_FLAG, &deterministic, sizeof(deterministic));
                                    
   // Set ML-DSA context field
   const uint8_t ctx[] = "FDE19259E56C2602F3CB0DA509B912F88262A1701D4E02B513F45C97EBB100A";
   uint32_t ctx_len = (uint32_t)(sizeof(ctx) - 1U);
   ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_CTX_INFO, &ctx, ctx_len);
                                    
   // Controls whether a pre-hash version is used when signing; 0 = use no pre-hash version, 1 = use pre-hash version.
   int32_t prehash = 0;
   ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_PREHASH_MODE, &prehash, sizeof(prehash));
                                    
   // Control whether to use external μ parameter: 0 = library computes μ internally, 1 = μ provided externally
   int32_t externalMu = 0;
   ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_MLDSA_MUMSG_FLAG, &externalMu, sizeof(externalMu));
                                    
   // Get current private key encoding format
   uint32_t curFmt = 0;
   CRYPT_EAL_PkeyCtrl(pctx, CRYPT_CTRL_GET_MLDSA_PRVKEY_FORMAT, &curFmt, sizeof(curFmt));
                                    
   // Get private key seed
   uint8_t seed[MLDSA_SEED_BYTES_LEN] = {0};
   int32_t ret = CRYPT_EAL_PkeyCtrl(pctx, CRYPT_CTRL_GET_MLDSA_SEED, seed, sizeof(seed));
   ```

3. **Key pair encoding/decoding**

   **Key encoding**

   ```c
   // After creating the key pair and obtaining key context pkey, encode it
   
   // 1. Encode to buffer
   // Initialize buffer
   BSL_Buffer out = {0};
   // Set private key encoding format
   uint32_t dkFormat = CRYPT_ALGO_MLDSA_PRIV_FORMAT_PRIV_ONLY;
   int32_t ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_MLDSA_PRVKEY_FORMAT, &dkFormat, sizeof(dkFormat));
   // Call encoding API with format and type to get encoded buffer out
   ret = CRYPT_EAL_EncodeBuffKey(pkey, NULL, BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &out);
   
   // 2. Encode to file
   int32_t format = BSL_FORMAT_PEM;
   int32_t type = CRYPT_PRIKEY_PKCS8_UNENCRYPT;
   uint32_t dkFormat = CRYPT_ALGO_MLDSA_PRIV_FORMAT_PRIV_ONLY;
   int32_t ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_MLDSA_PRVKEY_FORMAT, &dkFormat, sizeof(dkFormat));
   // path specifies the file path to store encoded key
   ret = CRYPT_EAL_EncodeFileKey(pkey, NULL, format, type, "mldsa65_priv_only.pem");
   ```

   Before encoding an ML-DSA key pair, the private key representation can be configured, and the encoding format must match the key format. This is done via `CRYPT_EAL_PkeyCtrl` with command `CRYPT_CTRL_SET_MLDSA_PRVKEY_FORMAT` and the desired encoding format enum. The formats are defined by `CRYPT_ALGO_MLDSA_PRIV_KEY_FORMAT_TYPE` and include:

   + **CRYPT_ALGO_MLDSA_PRIV_FORMAT_BOTH**: Seed plus expanded private key
   + **CRYPT_ALGO_MLDSA_PRIV_FORMAT_PRIV_ONLY**: Expanded private key only
   + **CRYPT_ALGO_MLDSA_PRIV_FORMAT_SEED_ONLY**: Seed only

   **Key decoding**

   ```c
   // 1. Decode key pair from buffer
   int32_t ret = CRYPT_EAL_PkeyCtx *prvKey = NULL;
   // Set format and type; keyBuf holds encoded key pair
   ret = CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &keyBuf, NULL, 0, &prvKey);
   
   // 2. Decode key pair from file
   int32_t ret = CRYPT_EAL_PkeyCtx *prvKey = NULL;
   ret = CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, "mldsa65_priv_only.pem", NULL, 0, &prvKey);
   ```

   **Set public/private key**

   ```c
   // Set public key
   CRYPT_EAL_PkeyPub pubKey = { 0 };
   // Set algorithm type
   pubKey.id = CRYPT_PKEY_ML_DSA;
   // Set public key data
   pubKey.key.mldsaPub.len = testPubKey->len;
   pubKey.key.mldsaPub.data = testPubKey->x;
   // Store public key structure into context
   ret = CRYPT_EAL_PkeySetPub(ctx, &pubKey);
   
   // Set private key
   CRYPT_EAL_PkeyPrv prvKey = { 0 };
   // Set algorithm type
   prvKey.id = CRYPT_PKEY_ML_DSA;
   // Set private key data
   prvKey.key.mldsaPrv.data = testPrvKey->x;
   prvKey.key.mldsaPrv.len = testPrvKey->len;
   // Store private key structure into context
   ret = CRYPT_EAL_PkeySetPrv(ctx, &prvKey);
   ```

   **Typical error enums**:

   | Enum                                         | Cause                                             | Scenario                                                     |
   | -------------------------------------------- | ------------------------------------------------- | ------------------------------------------------------------ |
   | `CRYPT_MLDSA_KEY_NOT_SET`                    | Public/private key not set in context             | Calling `CRYPT_EAL_PkeyGetPrv` or `CRYPT_EAL_PkeyGetPub` when key is absent |
   | `CRYPT_MLDSA_KEYLEN_ERROR`                   | Length invalid when setting key or context info   | Calling `CRYPT_EAL_PkeySetPub/SetPrv` or `CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_CTX_INFO, ...)` |
   | `CRYPT_MLDSA_LEN_NOT_ENOUGH`                 | Buffer too short when getting public/private key  | `len` in `CRYPT_EAL_PkeyPub` or `CRYPT_EAL_PkeyPrv` too small when calling `CRYPT_EAL_PkeySetPub/SetPrv` |
   | `CRYPT_MLDSA_SET_KEY_FAILED`                 | Public/private key already set in context         | Calling `CRYPT_EAL_PkeySetPrv` or `CRYPT_EAL_PkeySetPub` when key already present |
   | `CRYPT_MLDSA_SEED_EXPANDED_KEY_INCONSISTENT` | Seed-derived key mismatches expanded key          | `pkey` in `CRYPT_EAL_DecodeFileKey` or `CRYPT_EAL_PkeySetPrv` inconsistent with seed-derived private key |
   | `CRYPT_MLDSA_INVALID_PUBKEY/PRVKEY`          | Public/private key missing or wrong length        | With `HITLS_CRYPTO_MLDSA_CHECK` enabled, calling `CRYPT_EAL_PkeyPrvCheck` or `CRYPT_EAL_PkeyPubCheck` |
   | `CRYPT_MLDSA_PAIRWISE_CHECK_FAIL`            | Public/private key pairwise check failed          | With `HITLS_CRYPTO_MLDSA_CHECK` enabled, calling `CRYPT_EAL_PkeyPairCheck` |
   | `CRYPT_MLDSA_PRVKEY_FORMAT_ERROR`            | Private key encoding format wrong or seed missing | Setting format via `CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_MLDSA_PRVKEY_FORMAT, ...)` then exporting via `CRYPT_EAL_EncodeBuffKey/EncodeFileKey` |

### Certificate Setup

1. **Certificate creation and parsing**

   ```c
   // Create a new certificate
   HITLS_X509_Cert *cert = HITLS_X509_CertNew();
   if (cert == NULL) {
       printf("Failed to create empty certificate object\n");
       return HITLS_X509_ERR_CERT_EXIST;
   }
   
   // Read certificate from file
   HITLS_X509_Cert *cert = NULL;
   HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "mldsa_end.crt", &cert);
   if (cert == NULL) {
       printf("Failed to create empty certificate object\n");
       return HITLS_X509_ERR_CERT_EXIST;
   }
   ```

2. **Certificate settings**

   ```c
   // Set certificate info and configure public key
   ret = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_VERSION, &version, sizeof(version));
   ret = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SERIALNUM, serialNum, sizeof(serialNum));
   ...
   ret = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_PUBKEY, pubkey, 0);
   
   // Define KeyUsage extension as needed
   HITLS_X509_ExtKeyUsage ku;
   ku.critical = true;
   ku.keyUsage = HITLS_X509_EXT_KU_KEY_CERT_SIGN;
   ret = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_KUSAGE, &ku, sizeof(HITLS_X509_ExtKeyUsage));
   ```

   If the post-quantum certificate public key algorithm is ML-DSA or SLH-DSA, its key usage must be restricted. The KeyUsage extension must include at least one of:

   + `HITLS_X509_EXT_KU_DIGITAL_SIGN` (digitalSignature)
   + `HITLS_X509_EXT_KU_NON_REPUDIATION` (nonRepudiation)
   + `HITLS_X509_EXT_KU_KEY_CERT_SIGN` (keyCertSign)
   + `HITLS_X509_EXT_KU_CRL_SIGN` (cRLSign)

   and must forbid all of:

   + `HITLS_X509_EXT_KU_KEY_ENCIPHERMENT` (keyEncipherment)
   + `HITLS_X509_EXT_KU_DATA_ENCIPHERMENT` (dataEncipherment)
   + `HITLS_X509_EXT_KU_KEY_AGREEMENT` (keyAgreement)
   + `HITLS_X509_EXT_KU_ENCIPHER_ONLY` (encipherOnly)
   + `HITLS_X509_EXT_KU_DECIPHER_ONLY` (decipherOnly)

3. **Certificate signing and verification**

   ```c
   // Set certificate info and configure public key
   ret = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_VERSION, &version, sizeof(version));
   
   ret = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SERIALNUM, serialNum, sizeof(serialNum));
   ...
   ret = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_PUBKEY, pubkey, 0);
   
   // Define KeyUsage extension: ML-KEM certificates only allow keyEncipherment per draft-ietf-lamps-kyber-certificates
   HITLS_X509_ExtKeyUsage ku;
   ku.critical = true;
   ku.keyUsage = HITLS_X509_EXT_KU_KEY_CERT_SIGN;
   /* For an ML-DSA end-entity signing certificate, use HITLS_X509_EXT_KU_DIGITAL_SIGN instead. */
   ret = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_KUSAGE, &ku, sizeof(HITLS_X509_ExtKeyUsage));
   ```

   > If the public key algorithm for the post-quantum certificate is ML-DSA or SLH-DSA, its key usage needs to be restricted. The KeyUsage extension must include at least one of the following uses:

   + `HITLS_X509_EXT_KU_DIGITAL_SIGN`
   + `HITLS_X509_EXT_KU_NON_REPUDIATION`
   + `HITLS_X509_EXT_KU_KEY_CERT_SIGN`
   + `HITLS_X509_EXT_KU_CRL_SIGN`

   All of the following uses are prohibited: 

   + `HITLS_X509_EXT_KU_KEY_ENCIPHERMENT`
   + `HITLS_X509_EXT_KU_DATA_ENCIPHERMENT`
   + `HITLS_X509_EXT_KU_KEY_AGREEMENT`
   + `HITLS_X509_EXT_KU_ENCIPHER_ONLY`
   + `HITLS_X509_EXT_KU_DECIPHER_ONLY`

3. **Certificate signing and verification**

   ```c
   // Sign ML-DSA certificate
   ret = HITLS_X509_CertSign(CRYPT_MD_SHA256, signKey, &algParam, cert);
   
   ret = HITLS_X509_CertGenFile(BSL_FORMAT_PEM, cert, "mldsa.pem");
   
   // 1. Verify with public key
   ret = HITLS_X509_CertVerifyByPubKey(cert, pubkey);
   
   // 2. Build chain and verify
   // Define storage context and certificate chain pointer
   HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
   HITLS_X509_List *chain = NULL;
   
   // Add intermediate CA certificate to context
   HITLS_X509_Cert *inter = NULL;
   ret = HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, "mldsa_inter.pem", &inter);

   ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, inter, sizeof(HITLS_X509_Cert));
   
   // Parse terminal certificates
   HITLS_X509_Cert *entity = NULL;
   ret = HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "mldsa_entity.pem", &entity);
   
   // Building the certificate chain
   ret = HITLS_X509_CertChainBuild(store, false, entity, &chain);
   
   // Add the root certificate to the context
   HITLS_X509_Cert *root = NULL;
   ret = HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "mldsa_root.pem", &root);
   
   ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, root, sizeof(HITLS_X509_Cert));
   
   // Rebuild the certificate chain
   ret = HITLS_X509_CertChainBuild(store, false, entity, &chain);
   
   // Verify the certificate chain
   ret = HITLS_X509_CertVerify(store, chain);
   ```

   **Typical error enums**:

   | Enum                          | Cause                                                     | Scenario                                                                                          |
   |-------------------------------|-----------------------------------------------------------|---------------------------------------------------------------------------------------------------|
   | `HITLS_X509_ERR_EXT_KU`       | Wrong `keyUsage` in `HITLS_X509_ExtKeyUsage`              | `HITLS_X509_CertCtrl` called with `keyUsage` not satisfying requirements                         |
   | `CRYPT_MLDSA_LEN_NOT_ENOUGH`  | Signature buffer too small or signature length incorrect  | Calling `HITLS_X509_CertSign` or `HITLS_X509_CertVerify`                                         |
   | `CRYPT_MLDSA_SIGN_DATA_ERROR` | Encoded signature data structure invalid or violates constraints | Calling `HITLS_X509_CertVerify`                                                                  |
   | `CRYPT_MLDSA_VERIFY_FAIL`     | Verification content does not match signature             | Calling `HITLS_X509_CertVerify`                                                                  |
   | `CRYPT_MLDSA_KEY_NOT_SET`     | Private key not set for signing                           | Calling `HITLS_X509_CertSign` without setting private key                                        |

4. **CMS signed data verification**

   ```c
   HITLS_CMS *cms = NULL;
   BSL_Buffer msgBuff = {NULL, 0};
   HITLS_X509_Cert *caCert = NULL;
   HITLS_X509_List *caCertList = NULL;
   // File paths for CMS, message, and CA cert
   char *path = "mldsa65_sha384_attached.cms";
   char *msg = "msg.txt";
   char *ca_cert = "ca_cert.pem";
   
   // Parse CMS file
   ret = HITLS_CMS_ProviderParseFile(NULL, NULL, NULL, p7path, &cms);
   // Load message data
   ret = BSL_SAL_ReadFile(msgpath, &msgBuff.data, &msgBuff.dataLen);
   // Parse CA certificate file
   ret = HITLS_X509_CertParseFile(BSL_FORMAT_PEM, caPath, &caCert);
   // Create certificate list and append CA cert
   caCertList = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
   BSL_LIST_AddElement(caCertList, caCert, BSL_LIST_POS_END);
   // Wrap CA certificate list into unified params
   BSL_Param params[2] = {
       {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, caCertList, 0, 0},
       BSL_PARAM_END
   };
   // Call CMS signed data verification API
   HITLS_CMS_DataVerify(cms, &msgBuff, params, NULL);
   ```

   In CMS verification, ML-DSA must be matched with appropriate digest algorithms; if the CMS SignedData uses a digest that does not meet ML-DSA security requirements, the verification API must reject it. See the mapping in [HITLS_CMS_DataSign](#hitls_cms_datasign).

   **Typical error enums**:

   | Enum                               | Cause                                                | Scenario                                                                                                  |
   |------------------------------------|------------------------------------------------------|-----------------------------------------------------------------------------------------------------------|
   | `HITLS_CMS_ERR_MLDSA_INVALID_DIGEST` | ML-DSA/digest mapping does not satisfy RFC 9882      | CMS parsed by `HITLS_CMS_ProviderParseFile` is invalid or algorithms in `HITLS_CMS_DataSign` (pkey/params) mismatch |
   | `HITLS_CMS_ERR_MLDSA_ERROR_DIGEST` | ML-DSA digest algorithm not allowed                  | CMS without SignedAttrs uses digest other than SHA512 during `HITLS_CMS_DataVerify`                      |
   | `HITLS_CMS_ERR_PQC_PARAMS_NOT_OMITTED` | PQC algorithm parameters not omitted in AlgorithmIdentifier | Explicit PQC parameters appear when parsing via `HITLS_CMS_ProviderParseBuff/File`                        |
   | `HITLS_CMS_ERR_NOT_SUPPORT_STREAM_PQC` | PQC algorithm does not support streaming sign/verify | Using PQC algorithm with `HITLS_CMS_DataInit`/`HITLS_CMS_DataUpdate` and failing at `HITLS_CMS_DataFinal` |

## SLH-DSA Usage Guide

### Key Setup

1. **Create SLH-DSA key pair**

   ```c
   // Create asymmetric key context for SLH-DSA according to its algorithm ID
   CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
   // Set parameter id
   uint32_t id = CRYPT_SLH_DSA_SHA2_128S;
   int32_t ret = CRYPT_EAL_PkeySetParaById(ctx, id);
   // Initialize RNG
   ret = CRYPT_EAL_ProviderRandInitCtx(NULL, CRYPT_RAND_SHA256, "provider=default", NULL, 0, NULL);
   // Generate key pair and store in context
   ret = CRYPT_EAL_PkeyGen(ctx);
   ```

   SLH-DSA supports SHA2/SHAKE parameter sets at 128/192/256-bit security with Small and Fast variants:

   | Algorithm ID                | Hash type | Security level | Parameter set |
   |----------------------------|----------|----------------|---------------|
   | `CRYPT_SLH_DSA_SHA2_128S`  | SHA-2    | 128 bit        | Small         |
   | `CRYPT_SLH_DSA_SHAKE_128S` | SHAKE    | 128 bit        | Small         |
   | `CRYPT_SLH_DSA_SHA2_128F`  | SHA-2    | 128 bit        | Fast          |
   | `CRYPT_SLH_DSA_SHAKE_128F` | SHAKE    | 128 bit        | Fast          |
   | `CRYPT_SLH_DSA_SHA2_192S`  | SHA-2    | 192 bit        | Small         |
   | `CRYPT_SLH_DSA_SHAKE_192S` | SHAKE    | 192 bit        | Small         |
   | `CRYPT_SLH_DSA_SHA2_192F`  | SHA-2    | 192 bit        | Fast          |
   | `CRYPT_SLH_DSA_SHAKE_192F` | SHAKE    | 192 bit        | Fast          |
   | `CRYPT_SLH_DSA_SHA2_256S`  | SHA-2    | 256 bit        | Small         |
   | `CRYPT_SLH_DSA_SHAKE_256S` | SHAKE    | 256 bit        | Small         |
   | `CRYPT_SLH_DSA_SHA2_256F`  | SHA-2    | 256 bit        | Fast          |
   | `CRYPT_SLH_DSA_SHAKE_256F` | SHAKE    | 256 bit        | Fast          |

   **Typical error enums**:

   | Enum                                  | Cause                                              | Scenario                                                                                      |
   |---------------------------------------|----------------------------------------------------|-----------------------------------------------------------------------------------------------|
   | `CRYPT_SLHDSA_ERR_INVALID_ALGID`      | Parameter set not set or out of supported range    | Not calling `CRYPT_EAL_PkeySetParaById` or passing invalid parameter                         |
   | `CRYPT_SLHDSA_ERR_CONTEXT_LEN_OVERFLOW` | SLH-DSA context info length exceeds 255            | Calling `CRYPT_EAL_PkeyCtrl(CRYPT_CTRL_SET_CTX_INFO, ctxInfo, ctxLen)`                       |

2. **Key control**

   ```c
   // SLH-DSA private key supports deterministic or randomized signing
   
   // Deterministic signing
   int32_t isDeterministic = 1;
   ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_DETERMINISTIC_FLAG, &isDeterministic, sizeof(isDeterministic));
   // Randomized signing: provide random seed addrand
   ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_SLH_DSA_ADDRAND, addrand->x, addrand->len);
   
   // Get key length n (seed/root length)
   uint32_t n = 0;
   int32_t ret = CRYPT_EAL_PkeyCtrl(pctx, CRYPT_CTRL_GET_SLH_DSA_KEY_LEN, &n, sizeof(n));
   ```

3. **Key pair encoding/decoding**

   **Key encoding**

   ```c
   // After creating the key pair and obtaining key context pkey, encode it
   
   // 1. Encode to buffer
   // Initialize buffer
   BSL_Buffer out = {0};
   // Call encoding API with format and type to get encoded buffer out
   ret = CRYPT_EAL_EncodeBuffKey(pkey, NULL, BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &out);
   
   // 2. Encode to file
   int32_t format = BSL_FORMAT_PEM;
   int32_t type = CRYPT_PRIKEY_PKCS8_UNENCRYPT;
   // path specifies the file path to store encoded key
   ret = CRYPT_EAL_EncodeFileKey(pkey, NULL, format, type, "slh_dsa_sha2_128s.pem");
   ```

   **Key decoding**

   ```c
   // 1. Decode key pair from buffer
   int32_t ret = CRYPT_EAL_PkeyCtx *prvKey = NULL;
   // Set format and type; keyBuf holds encoded key pair
   ret = CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &keyBuf, NULL, 0, &prvKey);
   
   // 2. Decode key pair from file
   int32_t ret = CRYPT_EAL_PkeyCtx *prvKey = NULL;
   ret = CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, "slh_dsa_sha2_128s.pem", NULL, 0, &prvKey);
   ```

   **Set public/private key**

   ```c
   // Set public key
   CRYPT_EAL_PkeyPub pub = { 0 };
   // Set algorithm type
   pub.id = CRYPT_PKEY_SLH_DSA;
   // Set public key parameters
   pub.key.slhDsaPub.seed = pubSeed;
   pub.key.slhDsaPub.root = pubRoot;
   pub.key.slhDsaPub.len = sizeof(pubSeed);
   // Store public key structure into context
   ret = CRYPT_EAL_PkeySetPub(pkey, &pub);
   
   // Set private key
   CRYPT_EAL_PkeyPrv prv = { 0 };
   // Set algorithm type
   prv.id = CRYPT_PKEY_SLH_DSA;
   // Set seed and other private key parameters; all stored in hex string key
   prv.key.slhDsaPrv.seed = key->x;
   prv.key.slhDsaPrv.prf = key->x + keyLen;
   prv.key.slhDsaPrv.pub.seed = key->x + keyLen * 2;
   prv.key.slhDsaPrv.pub.root = key->x + keyLen * 3;
   prv.key.slhDsaPrv.pub.len = keyLen;
   // Store private key structure into context
   ret = CRYPT_EAL_PkeySetPrv(pkey, &prv);
   ```

   **Typical error enums**:

   | Enum                               | Cause                                                   | Scenario                                                                                                      |
   |------------------------------------|----------------------------------------------------------|---------------------------------------------------------------------------------------------------------------|
   | `CRYPT_SLHDSA_ERR_INVALID_KEYLEN`  | Length mismatches parameter set when setting/getting key | Calling `CRYPT_EAL_PkeySetPub` / `CRYPT_EAL_PkeySetPrv` with mismatched lengths                              |
   | `CRYPT_SLHDSA_ERR_NO_PUBKEY/PRIVKEY` | Public/private key structure missing in context          | Not setting keys before `CRYPT_EAL_PkeyGetPub`/`CRYPT_EAL_PkeyGetPrv`, or with `HITLS_CRYPTO_SLH_DSA_CHECK` calling `CRYPT_EAL_PkeyPrvCheck` etc. |
   | `CRYPT_SLHDSA_PAIRWISE_CHECK_FAIL` | Root from private key and public key root differ         | With `HITLS_CRYPTO_SLH_DSA_CHECK` enabled, calling `CRYPT_EAL_PkeyPairCheck`                                  |

### Certificate Setup

1. **Certificate creation and parsing**

   ```c
   // Create a new certificate
   HITLS_X509_Cert *cert = HITLS_X509_CertNew();
   if (cert == NULL) {
       printf("Failed to create empty certificate object\n");
       return HITLS_X509_ERR_CERT_EXIST;
   }
   
   // Read certificate from file
   HITLS_X509_Cert *cert = NULL;
   HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "slhdsa_end.crt", &cert);
   if (cert == NULL) {
       printf("Failed to create empty certificate object\n");
       return HITLS_X509_ERR_CERT_EXIST;
   }
   ```
   
2. **Certificate settings**

   ```c
   // Set certificate info and configure public key
   ret = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_VERSION, &version, sizeof(version));
   ret = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SERIALNUM, serialNum, sizeof(serialNum));
   ...
   ret = HITLS_X509_CertCtrl(ert, HITLS_X509_SET_PUBKEY, pubkey, 0);
   
   // Define KeyUsage extension as needed
   HITLS_X509_ExtKeyUsage ku;
   ku.critical = true;
   ku.keyUsage = HITLS_X509_EXT_KU_KEY_ENCIPHERMENT;
   ret = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_KUSAGE, &ku, sizeof(HITLS_X509_ExtKeyUsage));
   ```

   > KeyUsage extension requirements are consistent with those for ML-DSA certificates.

3. **Certificate signing and verification**

   ```c
   // Set certificate info and configure public key
   ret = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_VERSION, &version, sizeof(version));
   
   ret = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SERIALNUM, serialNum, sizeof(serialNum));
   ...
   ret = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_PUBKEY, pubkey, 0);
   
   // Define KeyUsage extension: ML-KEM certificates only allow keyEncipherment per draft-ietf-lamps-kyber-certificates
   HITLS_X509_ExtKeyUsage ku;
   ku.critical = true;
   ku.keyUsage = HITLS_X509_EXT_KU_DIGITAL_SIGN;
   /* For a CA certificate, use HITLS_X509_EXT_KU_KEY_CERT_SIGN and/or HITLS_X509_EXT_KU_CRL_SIGN as appropriate. */
   ret = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_KUSAGE, &ku, sizeof(HITLS_X509_ExtKeyUsage));
   ```

   > For SLH-DSA, if KeyUsage is present, it follows the ML-DSA signature-key rules: include at least one signature usage and do not include key-encipherment/agreement usages.

3. **Certificate signing and verification**

   ```c
   // Sign SLH-DSA certificate
   ret = HITLS_X509_CertSign(CRYPT_MD_SHA256, signKey, &algParam, cert);
   
   ret = HITLS_X509_CertGenFile(BSL_FORMAT_PEM, cert, "slhdsa.pem");
   
   // 1. Verify with public key
   ret = HITLS_X509_CertVerifyByPubKey(cert, pubkey);
   
   // 2. Build chain and verify
   // Define storage context and certificate chain pointer
   HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
   HITLS_X509_List *chain = NULL;
   
   // Add intermediate CA certificate to context
   HITLS_X509_Cert *inter = NULL;
   ret = HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, "slhdsa_inter.pem", &inter);

   ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, inter, sizeof(HITLS_X509_Cert));
   
   // Parse terminal certificates
   HITLS_X509_Cert *entity = NULL;
   ret = HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "slhdsa_entity.pem", &entity);
   
   // Building the certificate chain
   ret = HITLS_X509_CertChainBuild(store, false, entity, &chain);
   
   // Add the root certificate to the context
   HITLS_X509_Cert *root = NULL;
   ret = HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "slhdsa_root.pem", &root);
   
   ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, root, sizeof(HITLS_X509_Cert));
   
   // Rebuild the certificate chain
   ret = HITLS_X509_CertChainBuild(store, false, entity, &chain);
   
   // Verify the certificate chain
   ret = HITLS_X509_CertVerify(store, chain);
   ```
   
   **Typical error enums**:
   
   | Enum                                      | Cause                                                             | Scenario                                                                                          |
   |-------------------------------------------|------------------------------------------------------------------|---------------------------------------------------------------------------------------------------|
   | `HITLS_X509_ERR_EXT_KU`                   | Wrong `keyUsage` in `HITLS_X509_ExtKeyUsage`                     | `HITLS_X509_CertCtrl` called with `keyUsage` not satisfying requirements                         |
   | `CRYPT_SLHDSA_ERR_INVALID_SIG_LEN`        | Signature buffer too small or signature length not fixed `sigBytes` | Calling `HITLS_X509_CertSign` or `HITLS_X509_CertVerify`                                        |
   | `CRYPT_SLHDSA_ERR_SIG_LEN_NOT_ENOUGH`     | Signature/parse needs `(a+1)*n*k` bytes but input/output too short | Calling `HITLS_X509_CertSign` or `HITLS_X509_CertVerify`                                        |
   | `CRYPT_SLHDSA_ERR_HYPERTREE_VERIFY_FAIL`  | Hypertree verification failed: root mismatch, tampered signature, or mismatched public key | Calling `HITLS_X509_CertVerify`                                                                  |
   | `CRYPT_SLHDSA_ERR_PREHASH_ID_NOT_SUPPORTED` | Prehash enabled but digest algorithm ID cannot be mapped        | Enabling prehash via `CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_PREHASH_MODE, &prehash, sizeof(prehash))` then calling `HITLS_X509_CertSign` with an unsupported digest |

## XMSS Usage Guide

### Key Setup

1. **Create XMSS key pair**

   ```c
   // Create asymmetric key context for XMSS according to its algorithm ID
   CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_XMSS);
   // Set parameter id
   uint32_t id = CRYPT_XMSS_SHA2_10_256;
   int32_t ret = CRYPT_EAL_PkeySetParaById(ctx, id);
   // Initialize RNG
   ret = CRYPT_EAL_ProviderRandInitCtx(NULL, CRYPT_RAND_SHA256, "provider=default", NULL, 0, NULL);
   // Generate key pair and store in context
   ret = CRYPT_EAL_PkeyGen(ctx);
   ```

   XMSS parameter ids cover XMSS and XMSSMT with SHA2, SHAKE, SHAKE256 variants across standardized combinations of tree height, layers, and security level. Besides hash type and security level, XMSS parameters specify tree height, while XMSSMT parameters specify number of layers and total tree height; see `CRYPT_PKEY_ParaId` entries containing `XMSS`.

   **Typical error enums**:

   | Enum                         | Cause                                      | Scenario                                                                 |
   |------------------------------|-------------------------------------------|--------------------------------------------------------------------------|
   | `CRYPT_XMSS_ERR_INVALID_ALGID` | XMSS parameter set invalid or unsupported | Not calling `CRYPT_EAL_PkeySetParaById` or passing an invalid parameter |

2. **Key control**

   ```c
   // Get XMSS XDR algorithm type
   uint8_t xdr[4] = {0};
   int32_t ret = CRYPT_EAL_PkeyCtrl(pctx, CRYPT_CTRL_GET_XMSS_XDR_ALG_TYPE, xdr, sizeof(xdr));
   
   // Set XMSS XDR algorithm type; RFC9802 defines XDR algorithm ID as 4 bytes
   int32_t ret = CRYPT_EAL_PkeyCtrl(pctx, CRYPT_CTRL_SET_XMSS_XDR_ALG_TYPE, xdr, 4);
   ```

3. **Key pair encoding/decoding**

   **Key encoding**

   ```c
   // After creating the key pair and obtaining key context pkey, encode it
   
   // 1. Encode to buffer
   // Initialize buffer
   BSL_Buffer out = {0};
   // Call encoding API with format and type to get encoded buffer out
   ret = CRYPT_EAL_EncodeBuffKey(pkey, NULL, BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &out);
   
   // 2. Encode to file
   int32_t format = BSL_FORMAT_PEM;
   int32_t type = CRYPT_PRIKEY_PKCS8_UNENCRYPT;
   // path specifies the file path to store encoded key
   ret = CRYPT_EAL_EncodeFileKey(pkey, NULL, format, type, "xmss_sha2_10_256.pem");
   ```

   **Key decoding**

   ```c
   // 1. Decode key pair from buffer
   int32_t ret = CRYPT_EAL_PkeyCtx *prvKey = NULL;
   // Set format and type; keyBuf holds encoded key pair
   ret = CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &keyBuf, NULL, 0, &prvKey);
   
   // 2. Decode key pair from file
   int32_t ret = CRYPT_EAL_PkeyCtx *prvKey = NULL;
   ret = CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, "xmss_sha2_10_256.pem", NULL, 0, &prvKey);
   ```

   **Set public/private key**

   ```c
   // Set public key
   CRYPT_EAL_PkeyPub pub = { 0 };
   // Set algorithm type
   pub.id = CRYPT_PKEY_XMSS;
   // Set public key parameters
   pub.key.xmssPub.seed = key->x;
   pub.key.xmssPub.root = key->x + keyLen;
   pub.key.xmssPub.len = keyLen;
   // Store public key structure into context
   ret = CRYPT_EAL_PkeySetPub(pkey, &pub);
   
   // Set private key
   CRYPT_EAL_PkeyPrv prv = { 0 };
   // Set algorithm type
   prv.id = CRYPT_PKEY_XMSS;
   // Set seed and other private key parameters; all stored in hex string key
   prv.key.xmssPrv.index = index;
   prv.key.xmssPrv.seed = prvSeed;
   prv.key.xmssPrv.prf = prvPrf;
   prv.key.xmssPrv.pub.seed = pubSeed;
   prv.key.xmssPrv.pub.root = pubRoot;
   prv.key.xmssPrv.pub.len = keyLen;
   // Store private key structure into context
   ret = CRYPT_EAL_PkeySetPrv(pkey, &prv);
   ```

   **Typical error enums**:

   | Enum                           | Cause                                                             | Scenario                                                                                                   |
   |--------------------------------|-------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------|
   | `CRYPT_XMSS_ERR_INVALID_KEY`   | BitString structure invalid when parsing/setting XMSS public key  | Calling `CRYPT_EAL_DecodeBuffKey()` or `CRYPT_EAL_DecodeFileKey()` to decode XMSS subkey structure        |
   | `CRYPT_XMSS_ERR_XDR_ID_UNMATCH` | XDR algorithm type in public key does not match current context   | Setting XDR via `CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_XMSS_XDR_ALG_TYPE, ...)` then calling `CRYPT_EAL_PkeySetPub()` with mismatched key |
   | `CRYPT_XMSS_ERR_INVALID_XDR_ID` | XDR algorithm type cannot be mapped to any supported XMSS params  | Calling `CRYPT_EAL_PkeyCtrl(pctx, CRYPT_CTRL_SET_XMSS_XDR_ALG_TYPE, ...)` with invalid XDR               |
   | `CRYPT_XMSS_LEN_NOT_ENOUGH`    | Output buffer too small when getting XMSS public key              | Calling `CRYPT_EAL_PkeyGetPub` with too small buffer                                                      |
   | `CRYPT_XMSS_KEYINFO_NOT_SET`   | XMSS context parameters not set before key operations             | Performing operations without `CRYPT_EAL_PkeySetParaById`                                                 |
   | `CRYPT_XMSS_ERR_INVALID_KEYLEN` | Seed or other parameter lengths do not match parameter set        | Calling `CRYPT_EAL_PkeySetPub` or `CRYPT_EAL_PkeySetPrv` with wrong lengths                              |
   | `CRYPT_XMSS_PAIRWISE_CHECK_FAIL` | Public/private keys inconsistent                                  | With `HITLS_CRYPTO_XMSS_CHECK` enabled, calling `CRYPT_EAL_PkeyPairCheck`                                 |
   | `CRYPT_XMSS_INVALID_PRVKEY`    | Private key missing fields or wrong length                        | With `HITLS_CRYPTO_XMSS_CHECK` enabled, calling `CRYPT_EAL_PkeyPrvCheck`                                  |

### Certificate Setup

1. **Certificate creation and parsing**

   ```c
   // Create a new certificate
   HITLS_X509_Cert *cert = HITLS_X509_CertNew();
   if (cert == NULL) {
       printf("Failed to create empty certificate object\n");
       return HITLS_X509_ERR_CERT_EXIST;
   }
   
   // Read certificate from file
   HITLS_X509_Cert *cert = NULL;
   HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "xmss_end.crt", &cert);
   if (cert == NULL) {
       printf("Failed to create empty certificate object\n");
       return HITLS_X509_ERR_CERT_EXIST;
   }
   ```
   
2. **Certificate settings**

   ```c
   // Set certificate info and configure public key
   ret = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_VERSION, &version, sizeof(version));
   ret = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SERIALNUM, serialNum, sizeof(serialNum));
   ...
   ret = HITLS_X509_CertCtrl(ert, HITLS_X509_SET_PUBKEY, pubkey, 0);
   ```

3. **Certificate signing and verification**

   ```c
   // Sign XMSS certificate
   ret = HITLS_X509_CertSign(CRYPT_MD_SHA256, signKey, &algParam, cert);
   // XMSS signing increments the private key index in memory, requiring persistent storage of the private key state to avoid reusing an old on-disk private key state after restart, causing one-time signature index reuse.
   if (ret == HITLS_PKI_SUCCESS) {
       ret = CRYPT_EAL_EncodeFileKey(signKey, NULL, BSL_FORMAT_PEM,
       CRYPT_PRIKEY_PKCS8_UNENCRYPT, "xmss_sign_key.pem");
   }
   
   ret = HITLS_X509_CertGenFile(BSL_FORMAT_PEM, cert, "xmss.pem");
   
   // 1. Verify with public key
   ret = HITLS_X509_CertVerifyByPubKey(cert, pubkey);
   
   // 2. Build chain and verify
   // Define storage context and certificate chain pointer
   HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
   HITLS_X509_List *chain = NULL;
   
   // Add intermediate CA certificate to context
   HITLS_X509_Cert *inter = NULL;
   ret = HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, "xmss_inter.pem", &inter);

   ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, inter, sizeof(HITLS_X509_Cert));
   
   // Parse terminal certificates
   HITLS_X509_Cert *entity = NULL;
   ret = HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "xmss_entity.pem", &entity);
   
   // Building the certificate chain
   ret = HITLS_X509_CertChainBuild(store, false, entity, &chain);
   
   // Add the root certificate to the context
   HITLS_X509_Cert *root = NULL;
   ret = HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "xmss_root.pem", &root);
   
   ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, root, sizeof(HITLS_X509_Cert));
   
   // Rebuild the certificate chain
   ret = HITLS_X509_CertChainBuild(store, false, entity, &chain);
   
   // Verify the certificate chain
   ret = HITLS_X509_CertVerify(store, chain);
   ```
   
   **Typical error enums**:
   
   | Enum                                    | Cause                                                                 | Scenario                                                                                                   |
   |-----------------------------------------|------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------|
   | `CRYPT_XMSS_ERR_INVALID_SIG_LEN`        | 1) Signature buffer too small; 2) signature length not fixed for set; 3) segment length insufficient in Hypertree/WOTS+ verification | Calling `HITLS_X509_CertSign` or `HITLS_X509_CertVerify`                                                  |
   | `CRYPT_XMSS_ERR_KEY_EXPIRED`            | Signing index `idx` exceeds available range                           | Calling `HITLS_X509_CertSign` repeatedly until indices are exhausted                                      |
   | `CRYPT_XMSS_ERR_MERKLETREE_ROOT_MISMATCH` | Reconstructed Merkle root from signature differs from pubkey root     | Calling `HITLS_X509_CertVerify` with mismatched public key / tampered signature / index-signature mismatch |

