# openHiTLS #

Welcome to visit the openHiTLS Code Repository, which is under the openHiTLS community\[https://openhitls.net\]. openHiTLS aims to provide highly efficient and agile open-source SDKs for Cryptography and Transport Layer Security in all scenarios. openHiTLS is developing and supports some common standard cryptographic algorithms, X.509 and (D)TLS protocols currently. Other algorithms and protocols are to be planned. openHiTLS is highly modular and the RAM/ROM footprint grows as needed depending on the features selected. It provides the optimal performance optimization for cryptographic algorithms. Currently, the performance optimization of ShangMi cryptographic algorithms is ready on Arm, and is to be planned on other architectures.

# Contents #

## [Overview](#Overview)	 ##

## [Download](#Download)	 ##

## [Document](#Document)	 ##

## [Build](#Build)	 ##

## [License](#License)	 ##

## [Contribution](#Contribution)	 ##

# Overview #

openHiTLS supports some common standard cryptographic algorithms, X.509 and (D)TLS protocols currently. It is highly modular and the RAM/ROM footprint grows as needed depending on the features selected. Other algorithms and protocols are to be planned.

## Feature Introduction ##

### The following features are supported currently: ###

1 Functional feature: TLS1.2\*, TLS1.3\*, DTLS1.2\*. GMSSL1.1\*, X.509, GM Certificate, PKCS, AES, SM4, Chacha20, RSA, (EC)DSA, (EC)DH, SM2, DRBG, HKDF, SCRYPT, PBKDF2, SHA2, SHA3, MD5, SM3, HMAC. 2 DFX feature: highly modular with features configured, performance optimization on Arm\*, maintainability and testability with logs and errstack. \* indicates only the general standard. Refer to the README in components for details.

### The following features are pending for planning: ###

1 Functional feature: Post-quantum cryptographic algorithms and security protocols, QUIC and others. 2 DFX feature: Performance optimization on x86 and other architectures. 3 Northbound application adaptation: Ngnix and others. 4 Southbound hardware adaptation: SDF, SKF and others.

## Component Introduction ##

openHiTLS includes 5 components currently, and the bsl component will be used with other components. The bsl is short for base support layer, which provides the base C standard enhanced functions and OS adapter. It will be used with other modules. Refer to [bsl/README](bsl/README.md) for more information. The crypto is short for cryptographic algorithms, which provides the full cryptographic functions with high performance. It will be used by tls, and could also be used with bsl. Refer to [crypto/README](crypto/README.md) for more information. The tls is short for Transport Layer Security, and this protocol provides all tls protocol versions up to tls1.3. It will be used with crypto and bsl or other third-party crypto and PKI libraries. Refer to [tls/README](tls/README.md) for more information. The demo is short for demo application, which provides the application demo and performance benchmark app. Refer to [demo/README](demo/README.md) for more information.

# Download #

## Pre-download ##

openHiTLS depends on Secure C which should be downloaded to $\{openHiTLS_dir\}/platform/Secure_C. One of the official git repositories of Secure C is located at \[gitee.com/openeuler/libboundscheck\]. mkdir -p $\{openHiTLS_dir\}/platform && cd $\{openHiTLS_dir\} git clone https://gitee.com/openeuler/libboundscheck platform/Secure_C

## For Application Developers ##

Source code mirroring of the official releases is pending for planning.

## For openHiTLS Contributors ##

The official git repository is located at \[gitee.com/openHiTLS\]. A local copy of the git repository can be obtained by cloning it using: git clone https://gitee.com/openhitls/openhitls.git. If you are going to contribute, you need to fork the openhitls repository on gitee and clone your public fork instead. git clone https://gitee.com/"your gitee name"/openhitls.git

# Document #

This document is designed to improve the learning efficiency of developers and contributors on openHiTLS. Refer to the [doc](doc/README.md)	for details.

# Build and Installation #

The major steps in Linux are as follows. Refer to [install](doc/install.md) for details in build and installation. Refer to [build](build.sh) for the build script. Refer to [config](config/README.md) for details in configuration. The major steps in Linux: Step 1 (Prepare the build directory): cd openHiTLS && mkdir -p ./build && cd ./build Step 2 (Generate configurations): python3 ../configure.py \["option"\] Step 3 (Generate the build script): cmake .. Step 4 (Build and install): make && make install

# License #

openHiTLS is licensed under openHiTLS software license agreement 1.0, and will be licensed under the Mulan PSL v2 once being opened officially. See the LICENSE.txt file for more details.

# Contribution #

If you plan to contribute to the openHiTLS community, please visit the link to CLA Signing Guide \[https://openhitls.net/XX\] (pending for updates) to complete CLA signing.

