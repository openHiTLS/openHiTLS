# openHiTLS TLS 证书接口参考

## 概述

本文档提供了 openHiTLS TLS 库中所有证书相关接口的完整参考。openHiTLS 库提供了一套完整的证书管理功能，支持标准 TLS 和中国国密标准（TLCP）。

## 目录

1. [证书存储管理](#证书存储管理)
2. [设备证书管理](#设备证书管理)
3. [证书链管理](#证书链管理)
4. [证书撤销列表(CRL)管理](#证书撤销列表crl管理)
5. [证书验证](#证书验证)
6. [密码回调接口](#密码回调接口)
7. [证书选择回调](#证书选择回调)
8. [密钥日志接口](#密钥日志接口)
9. [CA列表管理](#ca列表管理)
10. [证书资源管理](#证书资源管理)
11. [客户端证书验证配置](#客户端证书验证配置)
12. [证书初始化](#证书初始化)
13. [数据格式和算法](#数据格式和算法)

## 证书存储管理

### 验证存储 (Verify Store - 用于证书验证的CA证书存储)

| 接口 | 描述 | 参数 |
|------|------|------|
| `HITLS_CFG_SetVerifyStore()` | 为TLS配置设置验证存储 | `config`, `store`, `isClone` |
| `HITLS_SetVerifyStore()` | 为TLS上下文设置验证存储 | `ctx`, `store`, `isClone` |
| `HITLS_CFG_GetVerifyStore()` | 从TLS配置获取验证存储 | `config` |
| `HITLS_GetVerifyStore()` | 从TLS上下文获取验证存储 | `ctx` |

### 链存储 (Chain Store - 用于构建证书链的存储)

| 接口 | 描述 | 参数 |
|------|------|------|
| `HITLS_CFG_SetChainStore()` | 为TLS配置设置链存储 | `config`, `store`, `isClone` |
| `HITLS_SetChainStore()` | 为TLS上下文设置链存储 | `ctx`, `store`, `isClone` |
| `HITLS_CFG_GetChainStore()` | 从TLS配置获取链存储 | `config` |
| `HITLS_GetChainStore()` | 从TLS上下文获取链存储 | `ctx` |

### 通用证书存储 (General Certificate Store)

| 接口 | 描述 | 参数 |
|------|------|------|
| `HITLS_CFG_SetCertStore()` | 为TLS配置设置通用证书存储 | `config`, `store`, `isClone` |
| `HITLS_SetCertStore()` | 为TLS上下文设置通用证书存储 | `ctx`, `store`, `isClone` |
| `HITLS_CFG_GetCertStore()` | 从TLS配置获取通用证书存储 | `config` |
| `HITLS_GetCertStore()` | 从TLS上下文获取通用证书存储 | `ctx` |

## 设备证书管理

### 证书设置

| 接口 | 描述 | 参数 |
|------|------|------|
| `HITLS_CFG_SetCertificate()` | 为TLS配置设置设备证书 | `config`, `cert`, `isClone` |
| `HITLS_SetCertificate()` | 为TLS上下文设置设备证书 | `ctx`, `cert`, `isClone` |
| `HITLS_CFG_SetTlcpCertificate()` | 设置TLCP设备证书（支持加密证书标识） | `config`, `cert`, `isClone`, `isTlcpEncCert` |

### 证书加载（从文件/缓冲区加载）

| 接口 | 描述 | 参数 |
|------|------|------|
| `HITLS_CFG_LoadCertFile()` | 为TLS配置从文件加载证书 | `config`, `file`, `format` |
| `HITLS_LoadCertFile()` | 为TLS上下文从文件加载证书 | `ctx`, `file`, `format` |
| `HITLS_CFG_LoadCertBuffer()` | 为TLS配置从缓冲区加载证书 | `config`, `buf`, `bufLen`, `format` |
| `HITLS_LoadCertBuffer()` | 为TLS上下文从缓冲区加载证书 | `ctx`, `buf`, `bufLen`, `format` |

### 证书解析（证书解析接口）

| 接口 | 描述 | 参数 |
|------|------|------|
| `HITLS_CFG_ParseCert()` | **从文件或缓冲区解析证书为X509对象** | `config`, `buf`, `len`, `type`, `format` |

**注意**：解析接口与加载接口的区别：
- **加载接口**：直接加载并设置到配置中
- **解析接口**：仅解析为对象，不直接设置，由用户决定如何使用

### 私钥设置

| 接口 | 描述 | 参数 |
|------|------|------|
| `HITLS_CFG_SetPrivateKey()` | 为TLS配置设置证书私钥 | `config`, `privateKey`, `isClone` |
| `HITLS_SetPrivateKey()` | 为TLS上下文设置证书私钥 | `ctx`, `key`, `isClone` |
| `HITLS_CFG_SetTlcpPrivateKey()` | 设置TLCP私钥（支持加密证书标识） | `config`, `privateKey`, `isClone`, `isTlcpEncCertPriKey` |

### 私钥加载（从文件/缓冲区加载私钥）

| 接口 | 描述 | 参数 |
|------|------|------|
| `HITLS_CFG_LoadKeyFile()` | 为TLS配置从文件加载私钥 | `config`, `file`, `format` |
| `HITLS_LoadKeyFile()` | 为TLS上下文从文件加载私钥 | `ctx`, `file`, `format` |
| `HITLS_CFG_LoadKeyBuffer()` | 为TLS配置从缓冲区加载私钥 | `config`, `buf`, `bufLen`, `format` |
| `HITLS_LoadKeyBuffer()` | 为TLS上下文从缓冲区加载私钥 | `ctx`, `buf`, `bufLen`, `format` |

### 私钥解析（私钥解析接口）

| 接口 | 描述 | 参数 |
|------|------|------|
| `HITLS_CFG_ParseKey()` | **从文件或缓冲区解析私钥** | `config`, `buf`, `len`, `type`, `format` |

### Provider相关接口（支持自定义加密提供者）

| 接口 | 描述 | 参数 |
|------|------|------|
| `HITLS_CFG_ProviderLoadKeyFile()` | 使用provider为TLS配置从文件加载私钥 | `config`, `file`, `format`, `type` |
| `HITLS_ProviderLoadKeyFile()` | 使用provider为TLS上下文从文件加载私钥 | `ctx`, `file`, `format`, `type` |
| `HITLS_CFG_ProviderLoadKeyBuffer()` | 使用provider为TLS配置从缓冲区加载私钥 | `config`, `buf`, `bufLen`, `format`, `type` |
| `HITLS_ProviderLoadKeyBuffer()` | 使用provider为TLS上下文从缓冲区加载私钥 | `ctx`, `buf`, `bufLen`, `format`, `type` |
| `HITLS_CFG_ProviderParseKey()` | **使用provider解析私钥** | `config`, `buf`, `len`, `type`, `format`, `encodeType` |

### 证书获取

| 接口 | 描述 | 参数 |
|------|------|------|
| `HITLS_CFG_GetCertificate()` | 从TLS配置获取设备证书 | `config` |
| `HITLS_GetCertificate()` | 从TLS上下文获取本地证书 | `ctx` |
| `HITLS_GetPeerCertificate()` | 从TLS上下文获取对端证书 | `ctx` |
| `HITLS_CFG_GetPrivateKey()` | 从TLS配置获取私钥 | `config` |
| `HITLS_GetPrivateKey()` | 从TLS上下文获取私钥 | `ctx` |

## 证书链管理

### 证书链操作

| 接口 | 描述 | 参数 |
|------|------|------|
| `HITLS_CFG_AddChainCert()` | 添加证书到当前使用的证书链 | `config`, `cert`, `isClone` |
| `HITLS_CFG_AddCertToStore()` | 添加证书到指定的证书存储 | `config`, `cert`, `storeType`, `isClone` |
| `HITLS_CFG_GetChainCerts()` | 获取当前使用的证书链 | `config` |
| `HITLS_CFG_ClearChainCerts()` | 清除配置中的证书链 | `config` |
| `HITLS_ClearChainCerts()` | 清除上下文中的证书链 | `ctx` |

### 额外证书链

| 接口 | 描述 | 参数 |
|------|------|------|
| `HITLS_CFG_AddExtraChainCert()` | 添加证书到额外证书链 | `config`, `cert` |
| `HITLS_CFG_GetExtraChainCerts()` | 获取额外证书链 | `config` |
| `HITLS_CFG_ClearExtraChainCerts()` | 清除额外证书链 | `config` |

### 证书链构建

| 接口 | 描述 | 参数 |
|------|------|------|
| `HITLS_CFG_BuildCertChain()` | 在建立TLS连接前构建证书链（配置） | `config`, `flag` |
| `HITLS_BuildCertChain()` | 在建立TLS连接前构建证书链（上下文） | `ctx`, `flag` |

## 证书撤销列表(CRL)管理

### CRL加载接口

| 接口 | 描述 | 参数 |
|------|------|------|
| `HITLS_CFG_LoadCrlFile()` | **为TLS配置从文件加载CRL** | `config`, `file`, `format` |
| `HITLS_LoadCrlFile()` | **为TLS上下文从文件加载CRL** | `ctx`, `file`, `format` |
| `HITLS_CFG_LoadCrlBuffer()` | **为TLS配置从缓冲区加载CRL** | `config`, `buf`, `bufLen`, `format` |
| `HITLS_LoadCrlBuffer()` | **为TLS上下文从缓冲区加载CRL** | `ctx`, `buf`, `bufLen`, `format` |

### CRL管理接口

| 接口 | 描述 | 参数 |
|------|------|------|
| `HITLS_CFG_ClearVerifyCrls()` | **清除TLS配置中的所有CRL** | `config` |
| `HITLS_ClearVerifyCrls()` | **清除TLS上下文中的所有CRL** | `ctx` |

**注意**：
- CRL（Certificate Revocation List）用于指定已被撤销的证书列表
- 加载的CRL会用于证书验证过程，检查证书是否已被撤销
- 支持从文件和内存缓冲区加载CRL
- CRL必须与相应的CA证书匹配才能生效
- 建议定期更新CRL以获取最新的撤销信息

**使用示例**：
```c
// 从文件加载CRL
int32_t ret = HITLS_CFG_LoadCrlFile(config, "ca.crl", TLS_PARSE_FORMAT_PEM);
if (ret != HITLS_SUCCESS) {
    // 处理错误
}

// 从缓冲区加载CRL
ret = HITLS_CFG_LoadCrlBuffer(config, crlBuffer, crlLen, TLS_PARSE_FORMAT_ASN1);
if (ret != HITLS_SUCCESS) {
    // 处理错误
}

// 清除所有CRL
HITLS_CFG_ClearVerifyCrls(config);
```

## 证书验证

### 验证参数设置

| 接口 | 描述 | 参数 |
|------|------|------|
| `HITLS_CFG_SetVerifyDepth()` | 为配置设置证书验证深度 | `config`, `depth` |
| `HITLS_SetVerifyDepth()` | 为上下文设置证书验证深度 | `ctx`, `depth` |
| `HITLS_CFG_GetVerifyDepth()` | 从配置获取证书验证深度 | `config`, `depth` |
| `HITLS_GetVerifyDepth()` | 从上下文获取证书验证深度 | `ctx`, `depth` |
| `HITLS_CFG_CtrlSetVerifyParams()` | 为配置设置证书验证参数 | `config`, `store`, `cmd`, `in`, `inArg` |
| `HITLS_CtrlSetVerifyParams()` | 为上下文设置证书验证参数 | `ctx`, `store`, `cmd`, `in`, `inArg` |
| `HITLS_CFG_CtrlGetVerifyParams()` | 从配置获取证书验证参数 | `config`, `store`, `cmd`, `out` |
| `HITLS_CtrlGetVerifyParams()` | 从上下文获取证书验证参数 | `ctx`, `store`, `cmd`, `out` |

### 验证回调

| 接口 | 描述 | 参数 |
|------|------|------|
| `HITLS_CFG_SetVerifyCb()` | 为配置设置证书验证回调 | `config`, `callback` |
| `HITLS_SetVerifyCb()` | 为上下文设置证书验证回调 | `ctx`, `callback` |
| `HITLS_CFG_GetVerifyCb()` | 从配置获取证书验证回调 | `config` |
| `HITLS_GetVerifyCb()` | 从上下文获取证书验证回调 | `ctx` |
| `HITLS_SetVerifyResult()` | 设置对端证书验证结果 | `ctx`, `verifyResult` |
| `HITLS_GetVerifyResult()` | 获取对端证书验证结果 | `ctx`, `verifyResult` |

### 私钥匹配验证

| 接口 | 描述 | 参数 |
|------|------|------|
| `HITLS_CFG_CheckPrivateKey()` | 检查配置中证书与私钥是否匹配 | `config` |
| `HITLS_CheckPrivateKey()` | 检查上下文中证书与私钥是否匹配 | `ctx` |

## 密码回调接口

| 接口 | 描述 | 参数 |
|------|------|------|
| `HITLS_CFG_SetDefaultPasswordCb()` | 为配置设置默认密码回调 | `config`, `cb` |
| `HITLS_SetDefaultPasswordCb()` | 为上下文设置默认密码回调 | `ctx`, `cb` |
| `HITLS_CFG_GetDefaultPasswordCb()` | 从配置获取默认密码回调 | `config` |
| `HITLS_GetDefaultPasswordCb()` | 从上下文获取默认密码回调 | `ctx` |
| `HITLS_CFG_SetDefaultPasswordCbUserdata()` | 为配置设置密码回调用户数据 | `config`, `userdata` |
| `HITLS_SetDefaultPasswordCbUserdata()` | 为上下文设置密码回调用户数据 | `ctx`, `userdata` |
| `HITLS_CFG_GetDefaultPasswordCbUserdata()` | 从配置获取密码回调用户数据 | `config` |
| `HITLS_GetDefaultPasswordCbUserdata()` | 从上下文获取密码回调用户数据 | `ctx` |

## 证书选择回调

| 接口 | 描述 | 参数 |
|------|------|------|
| `HITLS_CFG_SetCertCb()` | 为配置设置证书选择回调 | `config`, `certCb`, `arg` |
| `HITLS_SetCertCb()` | 为上下文设置证书选择回调 | `ctx`, `certCb`, `arg` |

**注意**：支持在握手过程中基于SNI等信息动态选择证书。

## 密钥日志接口

| 接口 | 描述 | 参数 |
|------|------|------|
| `HITLS_CFG_SetKeyLogCb()` | 为配置设置TLS密钥日志回调 | `config`, `callback` |
| `HITLS_CFG_GetKeyLogCb()` | 从配置获取TLS密钥日志回调 | `config` |
| `HITLS_LogSecret()` | 在启用日志时记录主密钥 | `ctx`, `label`, `secret`, `secretLen` |

## CA列表管理

| 接口 | 描述 | 参数 |
|------|------|------|
| `HITLS_CFG_ParseCAList()` | **解析CA文件或缓冲区为可信CA列表** | `config`, `input`, `inputLen`, `inputType`, `format`, `caList` |
| `HITLS_GetPeerCertChain()` | 获取对端证书链 | `ctx` |
| `HITLS_GetPeerCAList()` | 获取对端CA列表 | `ctx` |
| `HITLS_GetCAList()` | 从上下文获取可信CA列表 | `ctx` |
| `HITLS_SetCAList()` | 为上下文设置可信CA列表 | `ctx`, `list` |

## 证书资源管理

| 接口 | 描述 | 参数 |
|------|------|------|
| `HITLS_CFG_RemoveCertAndKey()` | 释放配置中所有已加载的证书和私钥 | `config` |
| `HITLS_RemoveCertAndKey()` | 释放上下文中所有已加载的证书和私钥 | `ctx` |

## 客户端证书验证配置

| 接口 | 描述 | 参数 |
|------|------|------|
| `HITLS_CFG_SetClientCertSupport()` | 在配置中设置是否验证客户端证书 | `config`, `support` |
| `HITLS_SetClientCertSupport()` | 在上下文中设置是否验证客户端证书 | `ctx`, `support` |
| `HITLS_CFG_SetNoClientCertSupport()` | 在配置中设置是否允许客户端无证书 | `config`, `support` |
| `HITLS_SetNoClientCertSupport()` | 在上下文中设置是否允许客户端无证书 | `ctx`, `support` |
| `HITLS_CFG_GetClientCertSupport()` | 从配置获取客户端证书验证设置 | `config`, `isSupport` |
| `HITLS_GetClientCertSupport()` | 从上下文获取客户端证书验证设置 | `ctx`, `isSupport` |
| `HITLS_CFG_GetNoClientCertSupport()` | 从配置获取无客户端证书支持设置 | `config`, `isSupport` |
| `HITLS_GetNoClientCertSupport()` | 从上下文获取无客户端证书支持设置 | `ctx`, `isSupport` |

## 证书初始化

| 接口 | 描述 | 参数 |
|------|------|------|
| `HITLS_CertMethodInit()` | 初始化证书方法（默认使用HITLS X509接口） | 无 |
| `HITLS_CertMethodDeinit()` | 去初始化证书方法 | 无 |

## 数据格式和算法

### 支持的数据格式

- **PEM格式** - 最常用的文本格式
- **ASN1格式** - 二进制DER格式  
- **PFX格式** - PKCS#12格式
- **PKCS12格式** - 另一种PKCS#12格式

### 支持的算法

- **RSA** - 包括RSA-PSS
- **ECDSA** - 椭圆曲线数字签名算法
- **Ed25519** - Edwards曲线数字签名算法
- **SM2** - 中国国密椭圆曲线算法

### 解析类型

```c
typedef enum {
    TLS_PARSE_TYPE_FILE,   /**< 解析文件 */
    TLS_PARSE_TYPE_BUFF,   /**< 解析缓冲区 */
    TLS_PARSE_TYPE_BUTT,
} HITLS_ParseType;
```

### 解析格式

```c
typedef enum {
    TLS_PARSE_FORMAT_PEM = BSL_FORMAT_PEM,        /**< PEM格式 */
    TLS_PARSE_FORMAT_ASN1 = BSL_FORMAT_ASN1,       /**< ASN1格式 */
    TLS_PARSE_FORMAT_PFX_COM = BSL_FORMAT_PFX_COM,    /**< PFX COM格式 */
    TLS_PARSE_FORMAT_PKCS12 = BSL_FORMAT_PKCS12,     /**< PKCS12格式 */
    TLS_PARSE_FORMAT_BUTT = BSL_FORMAT_UNKNOWN,
} HITLS_ParseFormat;
```

### 证书存储类型

```c
typedef enum {
    TLS_CERT_STORE_TYPE_DEFAULT,   /**< 默认CA存储 */
    TLS_CERT_STORE_TYPE_VERIFY,    /**< 验证存储，用于证书链验证 */
    TLS_CERT_STORE_TYPE_CHAIN,     /**< 证书链存储，用于组装证书链 */
    TLS_CERT_STORE_TYPE_BUTT,
} HITLS_CERT_StoreType;
```

## 使用示例

### 基本证书加载

```c
// 从文件加载证书
int32_t ret = HITLS_CFG_LoadCertFile(config, "cert.pem", TLS_PARSE_FORMAT_PEM);
if (ret != HITLS_SUCCESS) {
    // 处理错误
}

// 从文件加载私钥
ret = HITLS_CFG_LoadKeyFile(config, "key.pem", TLS_PARSE_FORMAT_PEM);
if (ret != HITLS_SUCCESS) {
    // 处理错误
}
```

### 证书解析

```c
// 从缓冲区解析证书
HITLS_CERT_X509 *cert = HITLS_CFG_ParseCert(config, certBuffer, certLen, 
                                            TLS_PARSE_TYPE_BUFF, TLS_PARSE_FORMAT_PEM);
if (cert != NULL) {
    // 使用解析的证书
    HITLS_CFG_SetCertificate(config, cert, true);
}
```

### 证书链构建

```c
// 添加中间证书到链中
HITLS_CFG_AddChainCert(config, intermediateCert, true);

// 构建证书链
int32_t ret = HITLS_CFG_BuildCertChain(config, HITLS_BUILD_CHAIN_FLAG_CHECK);
if (ret != HITLS_SUCCESS) {
    // 处理错误
}
```

### CRL管理

```c
// 加载CA证书用于验证
int32_t ret = HITLS_CFG_LoadCertFile(config, "ca.pem", TLS_PARSE_FORMAT_PEM);
if (ret != HITLS_SUCCESS) {
    // 处理错误
}

// 加载对应的CRL文件
ret = HITLS_CFG_LoadCrlFile(config, "ca.crl", TLS_PARSE_FORMAT_PEM);
if (ret != HITLS_SUCCESS) {
    // 处理错误
}

// 从内存缓冲区加载CRL
uint8_t *crlBuffer = ...; // CRL数据
uint32_t crlLen = ...; // CRL长度
ret = HITLS_CFG_LoadCrlBuffer(config, crlBuffer, crlLen, TLS_PARSE_FORMAT_ASN1);
if (ret != HITLS_SUCCESS) {
    // 处理错误
}

// 清除所有已加载的CRL
HITLS_CFG_ClearVerifyCrls(config);

// 运行时加载CRL到现有连接
HITLS_Ctx *ctx = HITLS_New(config);
ret = HITLS_LoadCrlFile(ctx, "new.crl", TLS_PARSE_FORMAT_PEM);
if (ret != HITLS_SUCCESS) {
    // 处理错误
}
```

## 错误处理

所有证书接口在成功时返回 `HITLS_SUCCESS`。对于错误情况，请参考 `hitls_error.h` 获取具体错误码。常见的证书相关错误码包括：

- `HITLS_CERT_ERR_BUILD_CHAIN` - 构建证书链失败
- `HITLS_PARSE_CERT_ERR` - 解析证书失败
- `HITLS_CERT_ERR_STORE_DUP` - 复制证书存储失败
- `HITLS_CFG_ERR_LOAD_CRL_FILE` - 加载CRL文件失败
- `HITLS_CFG_ERR_LOAD_CRL_BUFFER` - 加载CRL缓冲区失败

