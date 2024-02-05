[简体中文](./README.md) | English
# openHiTLS #

Welcome to visit the openHiTLS Code Repository, which is under the openHiTLS community: <https://openhitls.net>. openHiTLS aims to provide highly efficient and agile open-source SDKs for Cryptography and Transport Layer Security in all scenarios. openHiTLS is developing and supports some common standard cryptographic algorithms, TLS, DTLS protocols currently. More features are to be planned. 

# Contents #

## [Overview](#Overview) ##

## [Development](#Development) ##

## [Document](#Document) ##

## [Build and Installation](#Build) ##

## [License](#License) ##

## [Contribution](#Contribution) ##

## Overview <a id="Overview"></a>
The architecture of openHiTLS is highly modular, and openHiTLS can be configured in modules and features. The RAM/ROM footprint depends on the features selected. It provides the optimal performance optimization for cryptographic algorithms. Currently, 3 modulars and cryptographic algorithms are configured, and the performance optimization of ShangMi cryptographic algorithms on ARM is ready. More architectures and features are to be planned. 

## Feature Introduction ##

### The following features are supported currently: ###

1 Functional feature: TLS1.2\*, TLS1.3\*, DTLS1.2\*. GMSSL1.1\*, AES, SM4, Chacha20, RSA, (EC)DSA, (EC)DH, SM2, DRBG, HKDF, SCRYPT, PBKDF2, SHA2, SHA3, MD5, SM3, HMAC.  
2 DFX feature: highly modular with features configured, performance optimization on Arm\*, maintainability and testability with logs and error stacks.  
Declaration: \* indicates only the general standard. Refer to the "README" in components for details.

### The following features are pending for planning: ###

1 Funciton feature: X.509,GM Certificate, PKCS, Post-quantum cryptographic algorithm and Security Protocols, QUIC and others.  
2 DFX feature: Performance optimization on x86 and others. Ngnix, Curl and other northbound application adaptation. SDF, SKF and other southbound hardware adaptation.

## Component Introduction ##

openHiTLS include 4 components currently. The BSL component will be used with other components.  
The bsl is short for base support layer, which provides the base C standand enhanced functions and OS adapter. It will be used with other modules. Refer to [bsl/README](bsl/README.md) for more information.  
The crypto is short for cryptographic algorithms, which provides the full cryptographic functions with high performance. It will be used by tls, and can also be used with bsl. Refer to [crypto/README](crypto/README.md) for more information.  
The tls is short for Transport Layer Security, which provides all tls protocol versions up to tls1.3. It will be used with crypto and bsl or other third-party crypto and pki libraries. Refer to [tls/README](tls/README.md) for more information.  
The demo is short for demo application, which provides the application demo and performance banchmark app. Refer to [demo/README](demo/README.md) for more information.

## Development <a id="Development"></a>

## Dependency Preparation ##

openHiTLS depends on Secure C which should be downloaded to $\{openHiTLS_dir\}/platform/Secure_C. One of the official git repositories of Secure C is located at <https://gitee.com/openeuler/libboundscheck>.  
```
mkdir -p $\{openHiTLS_dir\}/platform
cd $\{openHiTLS_dir\}
git clone https://gitee.com/openeuler/libboundscheck platform/Secure_C
```

## For Application Developers ##

Source code mirroring of the official releases is pending for planning.

## For openHiTLS Contributors ##

The official source code repository is located at <https://gitee.com/openHiTLS>. A local copy of the git repository can be obtained by cloning it using:  
```
git clone https://gitee.com/openhitls/openhitls-dev.git
```
If you are going to contribute, you need to fork the openhitls repository on gitee and clone your public fork instead:  
```
git clone https://gitee.com/"your gitee name"/openhitls-dev.git
```

## Document <a id="Document"></a>
This document is designed to improve the learning efficiency of developers and contributors on openHiTLS. Refer to the [doc](doc/README.md)	for details.

## Build and Installation <a id="Build"></a>
The major steps in Linux are as follows. Refer to [install](doc/install.md) for details in build and installation. Refer to [build](build.sh) for the build script. Refer to [config](config/README.md) for details in configuration.  
The major steps in Linux:  
Step 1 (Prepare the build directory): 
```
cd openHiTLS && mkdir -p ./build && cd ./build
```
Step 2 (Generate configurations): 
```
python3 ../configure.py ["option"]
``` 
Step 3 (Generate the build script): 
```
cmake ..
```
Step 4 (Build and install): 
```
make && make install
```

## License <a id="License"></a>

openHiTLS is licensed under "openHiTLS Software License Agreement 1.0", and will be licensed under the Mulan PSL v2 once being opened officially. See the [LICENSE](./LICENSE) file for more details.

## Contribution <a id="Contribution"></a>

If you plan to contribute to the openHiTLS community, please visit the link [CLA Signing](https://120.46.86.252/cla)  to complete CLA signing.

