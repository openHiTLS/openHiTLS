# openHiTLS #

[English](./README-en.md) | 简体中文

欢迎访问openHiTLS代码仓！该代码仓的项目官网是openHiTLS社区https://openhitls.net，openHiTLS的目标是提供高效、敏捷的全场景开源密码学开发套件，支撑数智安全高效演进。openHiTLS已支持通用的标准密码算法、TLS、DTLS安全通信协议，正在快速发展中。

# 目录 #

## [概述](#概述)	 ##

## [下载](#下载)	 ##

## [文档](#文档)	 ##

## [构建](#构建)	 ##

## [License](#License)	 ##

## [贡献](#贡献)	 ##

# 概述 #

openHiTLS采用模块分层、特性分级的敏捷架构，实现功能特性按需选用，支撑系统内存占用最少；通过软硬算协同，实现算法性能最优，支撑系统计算性能最优。当前敏捷架构上已支持1+2模块、基于ID的算法切换可配的敏捷架构，支持ARM CPU上的算法性能优化，更多架构和特性待规划。

## 特性简介 ##

### 目前支持如下特性：

1. 功能特性：TLS1.2, TLS1.3， DTLS1.2，GMSSL1.1，AES，SM4，Chacha20，RSA，DSA，ECDSA，ECDH，DH，SM2，DRBG，HKDF，SCRYPT，PBKDF2，SHA2，SHA3，MD5，SM3，HMAC。
2. DFX特性：高度模块化特性按需配置的敏捷架构，ARM CPU上的算法性能优化，日志和错误堆栈功能的可维可测性。
说明：*仅表示通用功能，扩展功能参考各组件中的《README》文件。

### 以下特性待规划：

1. 功能特性：X.509，商密证书、PKCS、后量子密码算法、安全协议、QUIC等；
2. DFX特性：X86及其他架构上的性能优化，Ngnix、Curl等北向应用适配，SDF、SKF等南向硬件适配。

## 组件简介 ##

目前，openHiTLS有3个组件，其中BSL组件需和其他组件一起使用。
BSL是Base Support Layer的缩写，提供基础C类标准的增强功能和OS适配器，需与其他模块一起使用。更多详细信息，详情参考[bsl/README](bsl/README.md)。
密码算法组件（Crypto）提供了完整的密码功能，且性能较优。该组件既可以被TLS使用，也可与BSL一起使用。更多详细信息，请参考[crypto/README](crypto/README.md)。
TLS是Transport Layer Security的缩写，涵盖了TLS1.3及之前的所有TLS版本，会与Crypto、BSL以及其他三方密码组件或PKI库一起使用。更多详细信息，请参考[tls/README](tls/README.md)。
Demo组件提供应用demo和性能基准应用。更多详细信息，请参考[demo/README](demo/README.md)。

# 下载 ##

## 预下载 ##

openHiTLS依赖于Secure C，因此需将Secure C下载到$\{openHiTLS_dir\}/platform/Secure_C，Secure C的一个官方Git库是https://gitee.com/openeuler/libboundscheck。

```
mkdir -p $\{openHiTLS_dir\}/platform 
cd $\{openHiTLS_dir\} 
git clone https://gitee.com/openeuler/libboundscheck platform/Secure_C
```



## 致应用开发人员 ##

正式版本的源码镜像尚未正式开放、还在规划当中。

## 致openHiTLS贡献者 ##

官方Git库在https://gitee.com/openHiTLS，您可以通过如下命令将Git库克隆为一个本地副本进行使用：git clone https://gitee.com/openhitls/openhitls-dev.git。如果您想贡献自己的一份力，请在gitee上复制openhitls库，再克隆您的公共副本：

```
git clone https://gitee.com/"your gitee name"/openhitls-dev.git
```



# 文档 #

本文档旨在帮助开发者和贡献者更快地上手openHiTLS，详情参考[doc](doc/README.md) 。

# 构建与安装 #

在Linux系统中进行构建与安装时，可参考[install](doc/install.md)中的主要步骤，构建脚本请参见[build](build.sh)，详细配置参见[config](config/README.md)。Linux系统中的主要步骤有：

1. 执行 ` cd openHiTLS && mkdir -p ./build && cd ./build` 准备构建目录；
2. 执行` python3 ../configure.py \["option"\] `生成配置；
3. 执行` cmake .. `生成构建脚本；
4. 执行` make && make install` 进行构建和安装。

# License #

openHiTLS是在《openHiTLS软件许可协议1.0》下授权的，正式开放后将根据Mulan PSLv2 获得许可，详情参阅《LICENSE.txt》文件。

# 贡献 #

如果您有意为openHiTLS社区做贡献，请先按照《CLA签署指南》（待更新）\[https://openhitls.net/XX\]完成CLA签署。
