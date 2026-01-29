# Overview

openHiTLS aims to provide efficient and agile cryptography suites for all scenarios. With the elastic architecture of hierarchical modules and features, features can be selected and constructed as required, supporting applications in all scenarios to meet different requirements for RAM and ROM, computing performance, and feature satisfaction. Currently, openHiTLS supports cryptographic algorithms, secure communication protocols (TLS, DTLS, and TLCP), performance optimization of commercial encryption algorithms based on ARM and x86, **and supports Hybrid Key Exchange and Post-Quantum cryptographic algorithms**. More features are to be planned and welcome to participate in co-construction.

# Feature Description

## 1. Supported Features

### 1.1 Key Functional Features

#### Post-Quantum Algorithms
- ML-KEM
- ML-DSA
- SLH-DSA
- XMSS
- Classic McEliece
- FrodoKEM

#### Protocol Support
- TLS1.3, TLS1.3-Hybrid-Key-Exchange, TLS-Provider, TLS-Multi-KeyShare, TLS-Custom-Extension
- TLCP, DTLCP
- TLS1.2, DTLS1.2

#### Symmetric Algorithms
- AES, SM4, Chacha20, and various symmetric encryption modes.

#### Traditional Asymmetric Algorithms
- RSA, RSA-Bind, DSA, ECDSA, EDDSA, ECDH, DH, SM2, SM9, Paillier, ElGamal

#### Authentication Protocols
- Privacy Pass, HOTP, TOTP, SPAKE2+

#### Others
- DRBG, GM-DRBG
- HKDF, SCRYPT, PBKDF2
- SHA1, SHA2, SHA3, SHA256-MB, MD5, SM3
- HMAC, CMAC
- HPKE

#### Certificates and PKI
- Post-Quantum certificates
- Certificate and CRL parsing and verification
- Certificate requests and generation
- Certificate chain generation, partial/full certificate chain validation
- PKCS7, PKCS8, PKCS12

#### Command Line Tools
- Basic commands, random numbers, encryption and decryption
- Key and parameter management
- Certificate and PKI management
- SSL/TLS client and server

### 1.2 Non-Functional Features

#### Elastic Architecture
- Highly modular features, support on-demand trimming
- Protocol minimization configuration
- Handshake buffer memory minimization

#### Performance Optimization
- Algorithm performance optimization based on ARMv8, ARMv7, x86_64 CPU
- ML-KEM performance optimization

#### Maintainability and Testability
- Logging and error stack functionality
- BSL_ERR module ErrorStack printing
- Enhanced sensitive data cleanup

## 2. Planned Features

- Further optimization and integration of post-quantum cryptographic algorithms
- Further performance optimization and memory footprint reduction
- Support for more platforms
