[简体中文](./README-zh.md) | English

# openHiTLS
Welcome to visit the openHiTLS Code Repository, which is under the openHiTLS community: <https://openhitls.net>. openHiTLS aims to provide highly efficient and agile open-source SDKs for Cryptography and Transport Layer Security in all scenarios. openHiTLS is developing and supports some common standard cryptographic algorithms, (D)TLS, (D)TLCP protocols currently. More features are to be planned.

## Overview

The architecture of openHiTLS is highly modular, and openHiTLS can be configured in modules and features. The RAM/ROM footprint depends on the features selected. It provides the optimal performance optimization for cryptographic algorithms. Currently, 5 components and cryptographic algorithms are configured, ISO19790 certified, and the performance optimization of ShangMi cryptographic algorithms on ARM, x86 is ready. More architectures and features are to be planned.

## Feature Introduction

### Functional Features

- Protocols:
   - TLS: Support TLS1.3, TLS1.3-Hybrid-Key-Exchange, TLS-Provider, TLS-Multi-KeyShare, TLS-Custom-Extension, TLCP, DTLCP, TLS1.2, DTLS1.2.
   - Authentication: Support Privacy Pass token, HOTP, TOTP, SPAKE2+.
- Algorithms:
   - Post-quantum algorithms: ML-DSA, ML-KEM, SLH-DSA, XMSS, Classic McEliece, FrodoKEM.
   - Symmetric algorithms: AES, SM4, Chacha20, and various symmetric encryption modes.
   - Traditional asymmetric algorithms: RSA, RSA-Bind, DSA, ECDSA, EDDSA, ECDH, DH, SM2, SM9, Paillier, ElGamal.
   - Random: DRBG, DRBG-GM.
   - Key derivation: HKDF, SCRYPT, PBKDF2.
   - Hash: SHA series, MD5, SM3.
   - Message authentication code: HMAC, CMAC.
   - Others: HPKE.
- PKI:
   - Post-quantum capabilities: Support XMSS, ML-DSA, ML-KEM, SLH-DSA certificate capabilities, ML-DSA CMS SignedData capability.
   - Traditional certificate capabilities: Support X509 parsing and verification, CRL parsing and verification, CSR request generation, certificate chain generation, partial/full certificate chain validation
   - PKCS7, PKCS8, PKCS12, etc.
- Command line: Support basic commands, random numbers, encryption and decryption, key and parameter management, certificates and so on.

### DFX Features

- Highly modular features, support trimming features as required.
- Algorithm performance optimization based on ARMv8, ARMv7, x86_64 CPU.
- Support for maintainability and testability based on logging and error stack functionality.

## Component Introduction

Currently, openHiTLS has 5 components. The BSL component will be used with other components.
- BSL is short for Base Support Layer, which provides the base C standard enhanced functions and OS adapter. It will be used with other modules.
- Crypto provides the full cryptographic functions with high performance. It will be used by tls, and can also be used with bsl.
- TLS is short for Transport Layer Security, which covers TLS1.3 and previous TLS versions. It will be used with crypto, bsl and other third-party cryptographic components or PKI libraries.
- PKI component provides functions such as certificate and CRL parsing, certificate and CRL validation, as well as certificate request and generation.
- Auth authentication component provides authentication functions. Currently, it provides Privacy Pass token, TOTP/HOTP, SPAKE2+.

## Development

### Dependency Preparation

openHiTLS depends on Secure C (libboundscheck), which **is now automatically managed** by the configure.py script.

**Quick Start (Automatic - Recommended)**:

```bash
# Simply clone and configure - securec will be automatically initialized and built
git clone https://gitcode.com/openhitls/openhitls.git
cd openhitls
mkdir -p build && cd build
python3 ../configure.py  # Securec is automatically handled here
cmake .. && make && make install
```

**Alternative Methods**:

1. **Clone with submodules** (if you prefer to have everything ready):
   ```bash
   git clone --recurse-submodules https://gitcode.com/openhitls/openhitls.git
   cd openhitls
   # Securec is already initialized, configure.py will build it automatically
   ```

2. **Manual dependency management** (if you need full control):
   ```bash
   git clone https://gitcode.com/openhitls/openhitls.git
   cd openhitls
   git clone https://gitee.com/openeuler/libboundscheck platform/Secure_C
   cd platform/Secure_C && make -j && cd ../..
   # Use --no-auto-deps to skip automatic dependency handling
   python3 configure.py --no-auto-deps
   ```

**Dependency Management Options**:
- `--no-auto-deps`: Disable automatic dependency initialization and build
- `--force-rebuild-deps`: Force rebuild securec even if already built

The official Secure C repository is at <https://gitee.com/openeuler/libboundscheck>.

### For Application Developers

Source code mirroring of the official releases is pending for planning.


The official source code repository is located at <https://gitcode.com/openhitls>. A local copy of the git repository can be obtained by cloning it using:
```
git clone https://gitcode.com/openhitls/openhitls.git
```
If you are going to contribute, you need to fork the openhitls repository on gitcode and clone your public fork instead:
```
git clone https://gitcode.com/"your gitcode name"/openhitls.git
```

## Document
This document is designed to improve the learning efficiency of developers and contributors on openHiTLS. Refer to the [docs](docs/index/index.md).

## Build and Installation
The major steps in Linux are as follows. Refer to [build & install](docs/en/4_User%20Guide/1_Build%20and%20Installation%20Guide.md)
The major steps in Linux:

Step 1 (Prepare the build directory):
```
cd openhitls && mkdir -p ./build && cd ./build
```
Step 2 (Generate configurations):
```
python3 ../configure.py ["option"]
```

* C Full build:
```
python3 ../configure.py --enable hitls_bsl hitls_crypto hitls_tls hitls_pki hitls_auth --lib_type static --bits=64 --system=linux
```

* x86_64 Optimize the full build:
```
python3 ../configure.py --enable hitls_bsl hitls_crypto hitls_tls hitls_pki hitls_auth --lib_type static --bits=64 --system=linux --asm_type x8664
```

* build the app:
```
python3 ../configure.py --executes hitls
```

The options are described in [Build Installation Guide](docs/en/4_User%20Guide/1_Build%20and%20Installation%20Guide.md)

Step 3 (Generate the build script):
```
cmake ..
```
Step 4 (Build and install):
```
make && make install
```

## Contribution

If you plan to contribute to the openHiTLS community, please visit the link [CLA Signing](https://cla.openhitls.net)  to complete CLA signing.
