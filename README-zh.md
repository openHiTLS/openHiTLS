[English](./README.md) | 简体中文

# openHiTLS
欢迎访问openHiTLS代码仓，该代码仓的项目官网是openHiTLS社区<https://openhitls.net>，openHiTLS的目标是提供高效、敏捷的全场景开源密码学开发套件。openHiTLS已支持通用的标准密码算法、(D)TLS、(D)TLCP等安全通信协议，更多特性待规划。

## 概述

openHiTLS架构高度模块化，可通过模块和特性配置。RAM/ROM尺寸取决于所选的特性。openHiTLS为密码算法提供最佳性能优化。当前已支持5个组件和算法特性可按需配置，已经通过ISO19790认证，支持ARM、x86架构CPU上的算法性能优化，更多架构和特性待规划。

## 特性简介

### 功能特性

- 协议：
   - TLS: 支持TLS1.3，TLS1.3-Hybrid-Key-Exchange，TLS-Provider，TLS-Multi-KeyShare，TLS-Custom-Extension，TLCP，DTLCP，TLS1.2，DTLS1.2；
   - 认证：支持 Privacy Pass token，HOTP，TOTP，SPAKE2+ 等认证协议；
- 算法：
   - 后量子算法：ML-DSA，ML-KEM，SLH-DSA，XMSS，Classic McEliece，FrodoKEM；
   - 对称算法：AES，SM4，Chacha20 以及各类对称加密模式；
   - 传统非对称算法：RSA，RSA-Bind，DSA，ECDSA，EDDSA，ECDH，DH，SM2，SM9，Paillier，ElGamal；
   - 随机数：DRBG，GM-DRBG；
   - 密钥派生：HKDF，SCRYPT，PBKDF2；
   - 哈希算法：SHA系列，MD5，SM3；
   - 消息认证码：HMAC，CMAC；
   - 其他：HPKE；
- PKI：
   - 后量子能力：支持XMSS，ML-DSA，ML-KEM，SLH-DSA证书能力，ML-DSA CMS SignedData能力；
   - 传统证书能力：支持X509解析验证，CRL解析验证，CSR请求生成，证书链生成，部分/全部证书链验证
   - PKCS7，PKCS8，PKCS12等；
- 命令行：支持基础命令，随机数，加解密，密钥和参数管理，证书等；

### DFX特性

- 特性高度模块化，支持按需裁剪特性；
- 基于ARMv8、ARMv7、x86_64 CPU算法性能优化；
- 支持基于日志和错误堆栈功能维测；

## 组件简介

目前，openHiTLS有5个组件，其中BSL组件需和其他组件一起使用。
- BSL是Base Support Layer的缩写，提供基础C类标准的增强功能和OS适配器，需与其他模块一起使用；
- Crypto提供了完整的密码功能，且性能较优。该组件既可以被TLS使用，也可与BSL一起使用；
- TLS是Transport Layer Security的缩写，涵盖了TLS1.3及之前的TLS版本，会与Crypto、BSL以及其他三方密码组件或PKI库一起使用；
- PKI组件提供证书、CRL解析，证书、CRL验证以及证书请求、生成等功能；
- Auth认证组件提供了认证功能，当前提供Privacy Pass token认证功能，TOTP/HOTP，SPAKE2+等协议；

## 开发

### 依赖准备

openHiTLS依赖于Secure C（libboundscheck），**现已由 configure.py 脚本自动管理**。

**快速开始（自动化 - 推荐）**：

```bash
# 只需克隆并配置 - securec 将自动初始化和构建
git clone https://gitcode.com/openhitls/openhitls.git
cd openhitls
mkdir -p build && cd build
python3 ../configure.py  # Securec 在此自动处理
cmake .. && make && make install
```

**其他方式**：

1. **随子模块一起克隆**（如果希望一次性准备所有内容）：
   ```bash
   git clone --recurse-submodules https://gitcode.com/openhitls/openhitls.git
   cd openhitls
   # Securec 已初始化，configure.py 将自动构建
   ```

2. **手动管理依赖**（如果需要完全控制）：
   ```bash
   git clone https://gitcode.com/openhitls/openhitls.git
   cd openhitls
   git clone https://gitee.com/openeuler/libboundscheck platform/Secure_C
   cd platform/Secure_C && make -j && cd ../..
   # 使用 --no-auto-deps 跳过自动依赖处理
   python3 configure.py --no-auto-deps
   ```

**依赖管理选项**：
- `--no-auto-deps`：禁用自动依赖初始化和构建
- `--force-rebuild-deps`：强制重新构建 securec（即使已构建）

Secure C 官方仓库地址：<https://gitee.com/openeuler/libboundscheck>。

### 致应用开发人员

正式版本的源码镜像尚未正式开放，还在规划当中。


官方代码仓库托管在<https://gitcode.com/openhitls>，您可以通过如下命令将Git库克隆为一个本地副本进行使用： 
```
git clone https://gitcode.com/openhitls/openhitls.git
```
如果您有意贡献代码，请在gitcode上复制openhitls库，再克隆您的公共副本： 
```
git clone https://gitcode.com/"your gitcode name"/openhitls.git
```

## 文档

本文档旨在帮助开发者和贡献者更快地上手openHiTLS，详情参考[文档列表](docs/index/index.md) 。

## 构建与安装

在Linux系统中进行构建与安装时，可参考[构建安装指导](docs/zh/4_使用指南/1_构建及安装指导.md)
Linux系统中的主要步骤有：

1. 准备构建目录:
```
cd openhitls && mkdir -p ./build && cd ./build
```
2. 生成构建配置:
```
python3 ../configure.py ["option"]
```
* C全量构建
```
python3 ../configure.py --enable hitls_bsl hitls_crypto hitls_tls hitls_pki hitls_auth --lib_type static --bits=64 --system=linux
```

* x86_64优化全量构建：
```
python3 ../configure.py --enable hitls_bsl hitls_crypto hitls_tls hitls_pki hitls_auth --lib_type static --bits=64 --system=linux --asm_type x8664
```

* 命令行构建：
```
python3 ../configure.py --executes hitls
```

选项介绍可参考[构建安装指导](docs/zh/4_使用指南/1_构建及安装指导.md)

3. 生成构建脚本:
```
cmake ..
```
4. 执行构建和安装:
```
make && make install
```

## 贡献

如果您有意为openHiTLS社区做贡献，请先在[CLA签署](https://cla.openhitls.net)平台上完成CLA签署。
