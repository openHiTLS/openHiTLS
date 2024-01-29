# openHiTLS
Welcome to visit the openHiTLS Code Repository which is under the openHiTLS community[https://openhitls.net].
The openHiTLS aims to provide highly efficient and agile  open source SDK for Cryptography and Transport Layer Security with all-scenario.
The openHiTLS is highly modular and the RAM/ROM memory footprint grows as the configured features. It support some common standard cryptographic algrithms, TLS/DTLS/TLCP protocols. the performance optimization of ShangMi cryptographic algorithms is ready on ARM. More features is to be planned.
 
# Contents
 
## [Overview](#Overview)
## [Download](#Download)
## [Document](#Document)
## [Build](#Build)
 
## [License](#License)
## [Contribution](#Contribution)
 
 
# Overview
The openHiTLS support some common standard cryptographic algrithms, TLS/DTLS/TLCP protocols currently. It is highly modular and the RAM/ROM memory footprint grows as needed depending on the features selected currently. More features is to be planned. 
## Feature Introduction
### The supported feature currently
1 Funciton feature: TLS1.2*, TLS1.3*, DTLS1.2*. GMSSL1.1*, AES, SM4, Chacha20, RSA, DSA, ECDSA, ECDH, DH, SM2, DRBG, HKDF, SCRYPT, PBKDF2, SHA2, SHA3, MD5, SM3, HMAC.
2 DFX feature: highly modular with features configuration, Performance Optimization on ARM*, maintainability and testability with logs and errstack.
*indicate only widely part, refer the README in component for details.
### The features that is pending on planning
1 Funciton feature:  X.509,GM Certificate, PKCS, Post-quantum cryptographic algorithm and Security Protocols, QUIC and others.
2 DFX feature: Performance Optimization on x86 and others. Ngnix, Curl and others Northbound application adaptation. SDF, SKF and others Southbound hardware adaptation.
## Component Introduction
The openHiTLS include 3 components currently, the BSL component will be used with other components.
The bsl is short for base support layer, it provides the base C standand enhanced functions and OS adapter. This will used with other modules. Refer [bsl/README](bsl/README.md) for more information.
The crypto is short for cryptographic algorithms, it provides the full cryptographic functions with high Performance, Minimal. This will be used by tls, and  could also be used with bsl. Refer [crypto/README](crypto/README.md) for more information.
The tls is short for Transport Layer Security protocol, it provides all tls protocol versions up to tls1.3, This will used with crypto and bsl or other thirdparty crypto and pki library. Refer [tls/README](tls/README.md) for more information.
The demo is short for demo application, provides the application demo , performance banchmark app.  Refer [demo/README](demo/README.md) for more information.
 
# Download
## Pre-download
openHiTLS depends on Secure C which should be download to ${openHiTLS_dir}/platform/Secure_C, one of the official git repository of Secure C is localed at [gitee.com/openeuler/libboundscheck].
mkdir -p ${openHiTLS_dir}/platform && cd ${openHiTLS_dir}
git clone https://gitee.com/openeuler/libboundscheck  platform/Secure_C
 
## For Application developers
Source code mirroring of the official releases is pending on planning.
## For openHiTLS contributors
The official git repository is localed at [gitee.com/openHiTLS].
A local copy of the git repository can be obtained by cloning it using:
git clone https://gitee.com/openhitls/openhitls-dev.git
If you're going to contribute, you need to fork the openhitls repository on gitee and clone your public fork instead.
git clone https://gitee.com/"your gitee name"/openhitls-dev.git
 
# Document
This document is designed to improve the learning efficiency of developers and contributors on openHiTLS, refer the [doc](doc/README.md) for details.
 
# Build and Install
The major steps in Linux is as following. Refer [install](doc/install.md) for details in "build and install". Refer [build](build.sh) for the build script. Refer [config](config/README.md) for details in configuration.
The major steps in Linux:
Step 1(prepare build directory):              cd "directory" && mkdir -p ./build && cd ./build
Step 2(configure and gererate configuration): python3 ../configure.py ["option"]
Step 3(generate build script):                cmake ..
Step 4(build and install):                    make  && make install
 
# License
openHiTLS is Licensed under openHiTLS Software license agreement 1.0, and will be licensed under the Mulan PSL v2 once opened officially.
See the LICENSE.txt file for more details.
 
# Contribution
If you plan to contribute to the openHiTLS community, please visit the CLA Signing Guide link[https://openhitls.net/XX](pending on update) to complete CLA Signing.