# Overview

openHiTLS aims to provide efficient and agile cryptography suites for all scenarios. With the elastic architecture of hierarchical modules and features, features can be selected and constructed as required, supporting applications in all scenarios to meet different requirements for RAM and ROM, computing performance, and feature satisfaction. Currently, openHiTLS supports cryptographic algorithms, secure communication protocols (TLS, DTLS, and TLCP), and Arm-based performance optimization of commercial encryption algorithms. More features are to be planned and welcome to participate in co-construction.

# Feature Description

1. Supported Features

1.1. Key functional features are as follows:

* TLS protocols: TLS1.2, *TLS1.3*, DTLS1.2, and *TLCP1.1*.
* Encryption and decryption cryptographic algorithms: AES, SM4, Chacha20, RSA, (EC)DSA, (EC)DH, SM2, DRBG, HKDF, SCRYPT, PBKDF2, SHA2, SHA3, MD5, SM3, and HMAC.

1.2. Non-functional features are as follows:

* Elastic architecture: Modules and features can be selected and constructed as required.
* Performance optimization: The Arm*-based performance optimization of commercial encryption algorithms is supported.
* Maintainability and testability: The log and error stack functions are supported.

2. Features to Be Planned

2.1. Key functional features: TLS protocol extension, Quick UDP Internet Connections (QUIC) protocol, X.509 certificate, post-quantum cryptographic algorithm, and security protocols.
2.2. Non-functional features: elastic architecture, usability building, x86-based performance optimization, and adaptations to different applications (Ngnix and Curl), languages (Java and Python), and hardware cryptographic modules (SDF and SKF).

Note: The asterisk (*) indicates that general standards are supported for the performance optimization.
