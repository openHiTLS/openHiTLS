# Release Notes

Version: openHiTLS 0.3.0

# New Features

**openHiTLS 0.3.0 adds the following features:**

### Post-Quantum Cryptographic Algorithms
* ML-DSA algorithm support
* XMSS algorithm support
* Classic McEliece algorithm support
* FrodoKEM algorithm support
* XMSS, ML-DSA, ML-KEM, SLH-DSA certificate capabilities
* ML-DSA CMS SignedData capability

### Authentication Protocols
* SPAKE2+ protocol
* HOTP/TOTP

### PKI and Certificates
* X25519 certificate support
* Enhanced certificate verification: partial chain verification, external public key verification, hostname verification
* CMS: SignedData encoding/decoding and signature verification support
* Enhanced PKCS12: CRL-bag, key-bag, secret-bag support, provider offload support

### Cryptographic Algorithms
* AES-WRAP, RSA ISO9796-2:1997 signature
* SM4-HCTR, SM4-CCM modes
* SHA256-MB multi-buffer interface
* nistp192 curve
* Asymmetric algorithm key verification
* Random number fork reseeding capability
* Paillier algorithm homomorphic operation support
* SM9 Identity-Based Cryptography

### TLS
* Enhanced protocol certificate usability
  * Certificate loading from Buffer
  * CRL support
  * Certificate loading from directory
* Enhanced session management
* DTLS MTU transmission optimization
* Handshake buffer memory minimization
* RFC8998 cipher suite support
* Certificate Authorities extension support
* TLS_FALLBACK_SCSV support

### Command Line
New command line tools, supporting:
* Basic commands: help, list
* Random number: rand
* Encryption/decryption: enc, mac, dgst, kdf
* Key and parameter management: genpkey, pkey, param...
* Certificate and PKI: req, x509, pkcs7, pkcs12, crl...
* SSL/TLS client and server: s_client, s_server
* Password and storage: passwd

### Performance and Platform
* SM2/SM3 ARMv7 assembly optimization
* Darwin/macOS cross-platform support
* STM32F407 build configuration

### Authentication Related
* ISO19790 Provider
* SM Provider

### Bug Fixes
* Fixed cipher suite inconsistency in HRR scenario
* Fixed ticket nonceLen parsing failure
* Fixed certificate UTC time support before year 2000
* T61 string format support
* PSS certificate signature algorithm matching fix
* Fixed DRBG, ML-KEM, and atomic lock memory leaks
* Fixed DH key derivation leading zero issue
* Fixed DRBG entropy source waste issue
* Fixed BMP encoding issue
* Fixed certificate parsing address offset issue
* Fixed scrypt integer overflow issue
* Fixed initialization function order issue
* Fixed decode address offset issue
* Fixed AES-XTS assembly optimization issue
* Fixed symmetric algorithm assembly calling convention issue
* Fixed decode framework P8 key password input issue
* Fixed certificate key codec module memory issue
