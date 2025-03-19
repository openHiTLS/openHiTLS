# Provider 开发指南

本文档是 OpenHiTLS Provider 的开发指南，为开发人员提供接口介绍、关键特性说明以及综合使用示例。

## 1. 概述

OpenHiTLS 的 Provider 管理框架支持动态加载、管理和使用加密 Provider。每个 "Provider" 封装了一组特定的加密操作，通过标准化接口向外部用户暴露。

### 核心概念：
- **库上下文（Library Context，`CRYPT_EAL_LibCtx`）**：用于管理所有加载的 Provider 的生命周期和资源。
- **Provider 管理上下文（Provider Manager Context，`CRYPT_EAL_ProvMgrCtx`）**：表示单个 Provider，包括其加载库句柄和功能实现。
- **功能接口（Functional Interfaces）**：标准化的函数，用于查询和调用 Provider 的具体操作。

---

## 2. 接口介绍

### 2.1 库上下文管理

#### **`CRYPT_EAL_LibCtxNew`**
- **描述**：创建一个新的库上下文，用于管理 Provider。
- **函数原型**：
    ```c
    CRYPT_EAL_LibCtx *CRYPT_EAL_LibCtxNew(void);
    ```
- **返回值**：指向新创建的库上下文的指针。

#### **`CRYPT_EAL_LibCtxFree`**
- **描述**：释放库上下文，并释放所有相关资源。
- **函数原型**：
    ```c
    void CRYPT_EAL_LibCtxFree(CRYPT_EAL_LibCtx *libCtx);
    ```
- **参数**：
    - `libCtx`：需要释放的库上下文。

---

### 2.2 路径配置

#### **`CRYPT_EAL_ProviderSetLoadPath`**
- **描述**：配置加载 Provider 的路径。
- **函数原型**：
    ```c
    int32_t CRYPT_EAL_ProviderSetLoadPath(
        CRYPT_EAL_LibCtx *libCtx,
        const char *searchPath
    );
    ```
- **参数**：
    - `libCtx`：库上下文。
    - `searchPath`：Provider 的搜索路径。
- **返回值**：成功返回 `CRYPT_SUCCESS`，否则返回错误代码。

---

### 2.3 Provider 加载与卸载

#### **`CRYPT_EAL_ProviderLoad`**
- **描述**：动态加载一个 Provider，并完成初始化。
- **函数原型**：
    ```c
    int32_t CRYPT_EAL_ProviderLoad(
        CRYPT_EAL_LibCtx *libCtx,
        BSL_SAL_ConverterCmd cmd,
        const char *providerName,
        BSL_Param *param,
        CRYPT_EAL_ProvMgrCtx **mgrCtx
    );
    ```
- **参数**：
    - `libCtx`：库上下文。
    - `cmd`：指定库格式的命令（例如 `.so` 或 `lib*.so`）。
    - `providerName`：要加载的 Provider 名称。
    - `param`：初始化 Provider 时的附加参数。
    - `mgrCtx`：输出的 Provider 管理上下文指针，如果不为NULL，那么将会在加载成功后返回对应provider的管理上下文（CRYPT_EAL_ProvMgrCtx）。
- **返回值**：成功返回 `CRYPT_SUCCESS`，否则返回错误代码。

#### **`CRYPT_EAL_ProviderUnload`**
- **描述**：卸载指定的 Provider，并释放相关资源。
- **函数原型**：
    ```c
    int32_t CRYPT_EAL_ProviderUnload(
        CRYPT_EAL_LibCtx *libCtx,
        BSL_SAL_ConverterCmd cmd,
        const char *providerName
    );
    ```
- **参数**：
    - `libCtx`：库上下文。
    - `cmd`：指定库格式的命令。
    - `providerName`：要卸载的 Provider 名称。
- **返回值**：成功返回 `CRYPT_SUCCESS`，否则返回错误代码。

---

### 2.4 算法查询与调用

**eal层对外包装接口**：

该部分接口会包装provider对外接口，在查询到适配的算法后自动调用算法进行初始化工作，详见各类算法的对外头文件。

- **对称接口：`CRYPT_EAL_ProviderCipherNewCtx`**
- **非对称接口：`CRYPT_EAL_ProviderPkeyNewCtx`**
- **kdf接口：`CRYPT_EAL_ProviderKdfNewCtx`**
- **mac接口：`CRYPT_EAL_ProviderMacNewCtx`**
- **md接口：`CRYPT_EAL_ProviderMdNewCtx`**
- **随机数接口：`CRYPT_EAL_ProviderRandInitCtx`、`CRYPT_EAL_ProviderDrbgNewCtx`**


**provider底层对外接口**：

#### **`CRYPT_EAL_ProviderGetFuncs`**
- **描述**：从所有加载的provider中查询符合要求的算法。
- **函数原型**：
    ```c
    int32_t CRYPT_EAL_ProviderGetFuncs(
        CRYPT_EAL_LibCtx *libCtx,
        int32_t operaId,
        int32_t algId,
        const char *attribute,
        const CRYPT_EAL_Func **funcs,
        void **provCtx
    );
    ```
- **参数**：
    - `libCtx`：库上下文。
    - `operaId`：算法类别 ID（详见”crypt_eal_implprovider.h“文件）。
    - `algId`：算法 ID （详见”crypt_eal_implprovider.h“文件）。
    - `attribute`：用于筛选 Provider 的属性字符串。
    - `funcs`：输出的算法数组指针。
    - `provCtx`：可选参数，如果不为NULL会获得该算法所在provider管理上下文中的provCtx。
- **返回值**：成功返回 `CRYPT_SUCCESS`，否则返回错误代码。

#### **`CRYPT_EAL_ProviderCtrl`**
- **描述**：控制 Provider 管理上下文中的provCtx。
- **函数原型**：
    ```c
    int32_t CRYPT_EAL_ProviderCtrl(
        CRYPT_EAL_ProvMgrCtx *ctx,
        int32_t cmd,
        void *val,
        uint32_t valLen
    );
    ```
- **参数**：
    - `ctx`：Provider 管理上下文。
    - `cmd`：控制命令。
    - `val`：与命令相关的值。
    - `valLen`：值的长度。
### 2.5 capabilities

capabilities 提供了一种机制：使得应用程序可以获取provider支持的能力集；provider通过capabilites 向使用者表明自身支持的能力

#### 2.5.1 "CRYPT_EAL_GET_GROUP_CAP"

`"CRYPT_EAL_GET_GROUP_CAP"` 用于获取`tls`握手中支持的`group` 列表。在创建`HITLS_Config`时, 会查询并收集所有`provider`支持的`group`列表，`group`会应用于握手时的密钥协商。每个`group` 必须支持`kex` 或者`kem`算法。通过这种方式，`provider`可以向`tls`握手增加新的`group`。

`provider`支持的每个`group`都可以通过传递给`CRYPT_EAL_PROVCB_GETCAPS`的回调进行声明。每个`group`可以有以下字段。

- `CRYPT_PARAM_CAP_TLS_GROUP_IANA_GROUP_NA` ：`BSL_PARAM_TYPE_OCTETS_PTR` 类型，在IANA中注册的TLS supported groups。可以参考[IANA](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8)
- `CRYPT_PARAM_CAP_TLS_GROUP_IANA_GROUP_ID` ：`BSL_PARAM_TYPE_UINT16` 类型，在IANA中注册的TLS supported groups对应的ID。
- `CRYPT_PARAM_CAP_TLS_GROUP_PARA_ID` ：`BSL_PARAM_TYPE_INT32` 类型，group对应的参数ID, 会传入`CRYPT_EAL_PkeySetParaById`接口。
- `CRYPT_PARAM_CAP_TLS_GROUP_ALG_ID` ：`BSL_PARAM_TYPE_INT32` 类型，group对应的算法ID，会传入`CRYPT_EAL_ProviderPkeyNewCtx`接口。
- `CRYPT_PARAM_CAP_TLS_GROUP_SEC_BITS` ：`BSL_PARAM_TYPE_INT32` 类型，group提供的安全强度。
- `CRYPT_PARAM_CAP_TLS_GROUP_VERSION_BITS` ：`BSL_PARAM_TYPE_UINT32` 类型，group支持的TLS版本位图。可以参考`hitls_type.h`中的`*_VERSION_BIT` 
- `CRYPT_PARAM_CAP_TLS_GROUP_IS_KEM` ：`BSL_PARAM_TYPE_BOOL` 类型，标识group是否为KEM算法。
- `CRYPT_PARAM_CAP_TLS_GROUP_PUBKEY_LEN` ：`BSL_PARAM_TYPE_INT32` 类型，group公钥长度。
- `CRYPT_PARAM_CAP_TLS_GROUP_SHAREDKEY_LEN` ：`BSL_PARAM_TYPE_INT32` 类型，group共享密钥长度。
- `CRYPT_PARAM_CAP_TLS_GROUP_CIPHERTEXT_LEN` ：`BSL_PARAM_TYPE_INT32` 类型，KEM算法的密文长度。

示例代码可参考`crypt_default_provider.c:CryptGetGroupCaps`

#### 2.5.2 “CRYPT_EAL_GET_SIGALG_CAP”

`“CRYPT_EAL_GET_SIGALG_CAP”` 用于获取`tls`握手中支持的`signature algorithms` 列表。在创建`HITLS_Config`时, 会查询并收集所有`provider`支持的`signature algorithms`列表，`signature algorithms` 会应用于握手时的身份认证。通过这种方式，`provider`可以向 `tls` 握手增加新的`signature algorithms`。

`provider`支持的每个`signature algorithms`都可以通过传递给`CRYPT_EAL_PROVCB_GETCAPS`的回调进行声明。每个`signature algorithms`可以有以下字段。

- `CRYPT_PARAM_CAP_TLS_SIGNALG_IANA_SIGN_NAME`：`BSL_PARAM_TYPE_OCTETS_PTR` 类型，在IANA中注册的TLS signature scheme名称。可以参考[IANA](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme)
- `CRYPT_PARAM_CAP_TLS_SIGNALG_IANA_SIGN_ID`：`BSL_PARAM_TYPE_UINT16` 类型，在IANA中注册的TLS signature scheme对应的ID。
- `CRYPT_PARAM_CAP_TLS_SIGNALG_KEY_TYPE`：`BSL_PARAM_TYPE_INT32` 类型，签名算法使用的密钥类型。
- `CRYPT_PARAM_CAP_TLS_SIGNALG_KEY_TYPE_OID`：`BSL_PARAM_TYPE_OCTETS_PTR` 类型，密钥类型对应的OID。
- `CRYPT_PARAM_CAP_TLS_SIGNALG_KEY_TYPE_NAME`：`BSL_PARAM_TYPE_OCTETS_PTR` 类型，密钥类型的名称。
- `CRYPT_PARAM_CAP_TLS_SIGNALG_PARA_ID`：`BSL_PARAM_TYPE_INT32` 类型，签名算法参数ID。
- `CRYPT_PARAM_CAP_TLS_SIGNALG_PARA_OID`：`BSL_PARAM_TYPE_OCTETS_PTR` 类型，签名算法参数对应的OID。
- `CRYPT_PARAM_CAP_TLS_SIGNALG_PARA_NAME`：`BSL_PARAM_TYPE_OCTETS_PTR` 类型，签名算法参数的名称。
- `CRYPT_PARAM_CAP_TLS_SIGNALG_SIGNWITHMD_ID`：`BSL_PARAM_TYPE_INT32` 类型，签名算法与摘要算法组合的ID。
- `CRYPT_PARAM_CAP_TLS_SIGNALG_SIGNWITHMD_OID`：`BSL_PARAM_TYPE_OCTETS_PTR` 类型，签名算法与摘要算法组合对应的OID。
- `CRYPT_PARAM_CAP_TLS_SIGNALG_SIGNWITHMD_NAME`：`BSL_PARAM_TYPE_OCTETS_PTR` 类型，签名算法与摘要算法组合的名称。
- `CRYPT_PARAM_CAP_TLS_SIGNALG_SIGN_ID`：`BSL_PARAM_TYPE_INT32` 类型，签名算法ID。
- `CRYPT_PARAM_CAP_TLS_SIGNALG_MD_ID`：`BSL_PARAM_TYPE_INT32` 类型，摘要算法ID。
- `CRYPT_PARAM_CAP_TLS_SIGNALG_MD_OID`：`BSL_PARAM_TYPE_OCTETS_PTR` 类型，摘要算法对应的OID。
- `CRYPT_PARAM_CAP_TLS_SIGNALG_MD_NAME`：`BSL_PARAM_TYPE_OCTETS_PTR` 类型，摘要算法的名称。
- `CRYPT_PARAM_CAP_TLS_SIGNALG_SEC_BITS`：`BSL_PARAM_TYPE_INT32` 类型，签名算法提供的安全强度。
- `CRYPT_PARAM_CAP_TLS_SIGNALG_CHAIN_VERSION_BITS`：`BSL_PARAM_TYPE_UINT32` 类型，签名算法支持的证书链版本位图，可以参考`hitls_type.h`中的`*_VERSION_BIT`
- `CRYPT_PARAM_CAP_TLS_SIGNALG_CERT_VERSION_BITS`：`BSL_PARAM_TYPE_UINT32` 类型，签名算法支持的证书版本位图，可以参考`hitls_type.h`中的`*_VERSION_BIT`

示例代码可参考`crypt_default_provider.c:CryptGetSignAlgCaps`
---

## 3. provider管理模块使用说明

### 3.1 加载与卸载

- **特性说明**：
    - provider以名称为唯一标识符，不同的provider要求具有不同的名称，不同路径相同名称的provider会被视为相同的provider。
    - 支持重复加载和卸载provider，重复加载时并不会额外创建provider管理上下文，卸载的次数需要与加载的次数相同才能将库上下文中的provider管理上下文删除。
    - 在释放库上下文时，会自动卸载所有加载的provider。
    - 加载provider的路径默认为空，如果没有设置加载路径，那么将会根据运行环境中dlopen函数的当前特性从各个位置依次检索搜索provider。
    - 目前openhitls自带的算法库会被加载进一个启动时初始化的全局库上下文中，当加载、卸载以及查找provider时，如果传入的libCtx为NULL，那么会使用该全局库上下文。
- **使用示例**：
    ```c
    ...
    // 创建库上下文
    CRYPT_EAL_LibCtx *libCtx = CRYPT_EAL_LibCtxNew();
    assert(libCtx != NULL);

    // 设置 Provider 加载路径
    int ret = CRYPT_EAL_ProviderSetLoadPath(libCtx, "/path/to/providers");
    assert(ret == CRYPT_SUCCESS);

    // 加载 Provider
    CRYPT_EAL_ProvMgrCtx *mgrCtx = NULL;
    ret = CRYPT_EAL_ProviderLoad(libCtx, BSL_SAL_CONVERTER_SO, "provider_name", NULL, &mgrCtx);
    assert(ret == CRYPT_SUCCESS);

    ...

    // 卸载 Provider
    ret = CRYPT_EAL_ProviderUnload(libCtx, BSL_SAL_CONVERTER_SO, "provider_name");
    assert(ret == CRYPT_SUCCESS);

    // 释放库上下文
    CRYPT_EAL_LibCtxFree(libCtx);
    ...
    ```

---

### 3.2 属性查询和provider打分机制

- **属性机制**：
    在查询算法时，首先会查找符合算法ID的算法数组，如果用户输入的查找字符串不为NULL，则还会根据查找字符串选择所有加载provider中最匹配的算法。
    供查找的provider算法属性值由name和value组成，name和value之间用`=`分隔，多组属性之间用`,`分隔。在provider中，每个算法可以根据实现目的定义一组或多组属性，甚至同一个算法，可以有不同实现（通过属性区分）。
- **provider打分机制**：
    查询可以由多个查询语句组成，每个语句中之间用`,`分隔，语句中的name和value之间用以下`判断字符`分隔：
    - `=`: 必须相等，属于强制条件。
    - `!=`: 必须不相等，属于强制条件。
    - `？`: 可选条件，如果value匹配，优先选择，每满足一个问号，得分会+1。

    查询时强制条件必须满足，在此基础上，根据可选条件选择最匹配的，如果最匹配实现有多个选择，随机返回一个。
    查询时允许各组语句重复，强制条件重复对结果无影响。可选条件重复，相当于满足该条件的得分由1分变为重复个数的分数。
- **使用示例**：
    ```c
    ...
    // 属性字符串可以为NILL，会根据算法ID查找
    ret = CRYPT_EAL_ProviderGetFuncs(libCtx, CRYPT_EAL_OPERAID_HASH, CRYPT_MD_MD5, NULL, &funcs, &provCtx);
    assert(ret == CRYPT_SUCCESS);
    ...
    // 属性字符串不为NULL时，根据匹配规则查找
    ret = CRYPT_EAL_ProviderGetFuncs(libCtx, CRYPT_EAL_OPERAID_HASH, CRYPT_MD_MD5, "name=md5,type=hash,version=1.0", &funcs, &provCtx);
    assert(ret == CRYPT_SUCCESS);
    ...
    // 属性字符串涉及provider打分机制
    ret = CRYPT_EAL_ProviderGetFuncs(libCtx, CRYPT_EAL_OPERAID_HASH, CRYPT_MD_MD5, "name=md5,feature?attr_good,feature?attr_good,feature?attr_bad", &funcs, &provCtx);
    assert(ret == CRYPT_SUCCESS);
    ...
    // 实际使用时推荐使用eal层各类算法对外的包装接口,会自动进行查找算法并调用算法进行初始化等工作。
    CRYPT_EAL_MdCTX *ctx = CRYPT_EAL_ProviderMdNewCtx(libCtx, CRYPT_MD_MD5, "provider=no_hitls,type=hash");
    assert(ctx != NULL);
    ...
    ```

---

## 4. provider构建说明

该部分涉及的各类命令以及函数原型的完整内容定义在`crypt_eal_implprovider.h`头文件中。

### 4.1 初始化函数

对每个provider，需要实现名为`CRYPT_EAL_ProviderInit`的初始化函数，该初始化函数会在加载provider时被调用：
- **函数原型**：
    ```c
    int32_t CRYPT_EAL_ProviderInit(
        CRYPT_EAL_ProvMgrCtx *mgrCtx,
        BSL_Param *param,
        CRYPT_EAL_Func *capFuncs,
        CRYPT_EAL_Func **outFuncs,
        void **provCtx
    );
    ```
    - **参数**：
        - `mgrCtx`：[in] Provider 管理上下文。
        - `param`：[in] 初始化 Provider 时的附加参数。
        - `capFuncs`：[in] 由管理框架输入的算法数组指针，目前支持让用户可以选择使用HITLS提供的默认熵源。
        - `outFuncs`：[out] provider对外提供的算法数组指针，详情见下文。
        - `provCtx`：[out] provider私有结构体，如需要可用于在provider管理上下文中保存一些私有数据，操作详情见下文，可选。
    - **返回值**：成功返回 `CRYPT_SUCCESS`，否则返回错误代码。

- **`outFuncs`数组说明**：
该数组用于传出provider对外提供的三种算法数组，其中**算法查询函数必须返回**，其他两个函数可选：
    - **算法查询函数**：该函数用于在查找算法时，根据传入的算法类别，获取provider对外提供的整个算法类别的方法数组:
    **`typedef int32_t (*)(void *provCtx, int32_t operaId, CRYPT_EAL_AlgInfo **algInfos);`**
        - **参数**：
            - `provCtx`：[in] provider私有结构体，可选。
            - `operaId`：[in] 算法类别ID。
            - `algInfos`：[out] 该算法类别下所有算法的数组指针，数组中当算法ID为0时表示结束。
        - **返回值**：成功返回 `CRYPT_SUCCESS`，否则返回错误代码。
    - **provCtx控制函数**：如果provider使用了provCtx,则该函数用于对其进行控制，该函数可以通过`CRYPT_EAL_ProviderCtrl`函数进行调用。
    **`typedef int32_t (*)(void *provCtx, int32_t cmd, void *val, uint32_t valLen);`**
        - **参数**：略
        - **返回值**：略
    - **provCtx释放函数**：如果provider使用了provCtx,则该函数用于释放provCtx，该函数会在释放资源时被调用。
    **`typedef void (*)(void *provCtx);`**
    - **参数**：
        - ·`provCtx`：[in] provider私有结构体。
        - **返回值**：无。

---

### 4.2 provider构建示例

- **初始化函数示例**：
```c
static CRYPT_EAL_Func defProvOutFuncs[] = {
    {CRYPT_EAL_PROVCB_QUERY, CRYPT_EAL_DefaultProvQuery},
    {CRYPT_EAL_PROVCB_FREE, NULL},
    {CRYPT_EAL_PROVCB_CTRL, NULL},
    CRYPT_EAL_FUNC_END
};

int32_t CRYPT_EAL_ProviderInit(CRYPT_EAL_ProvMgrCtx *mgrCtx,
    BSL_Param *param, CRYPT_EAL_Func *capFuncs, CRYPT_EAL_Func **outFuncs, void **provCtx)
{
    CRYPT_RandSeedMethod entroy = {0};
    CRYPT_EAL_ProvMgrCtrlCb mgrCtrl = NULL;
    int32_t index = 0;
    while (capFuncs[index].id != 0) {
        switch (capFuncs[index].id) {
            case CRYPT_EAL_CAP_GETENTROPY:
                entroy.getEntropy = capFuncs[index].func;
                break;
            case CRYPT_EAL_CAP_CLEANENTROPY:
                entroy.cleanEntropy = capFuncs[index].func;
                break;
            case CRYPT_EAL_CAP_GETNONCE:
                entroy.getNonce = capFuncs[index].func;
                break;
            case CRYPT_EAL_CAP_CLEANNONCE:
                entroy.cleanNonce = capFuncs[index].func;
                break;
            case CRYPT_EAL_CAP_MGRCTXCTRL:
                mgrCtrl = capFuncs[index].func;
                break;
            default:
                return CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL;
        }
        index++;
    }
    void *seedCtx = NULL;
    void *libCtx = NULL;
    if (entroy.getEntropy == NULL || entroy.cleanEntropy == NULL || entroy.getNonce == NULL ||
        entroy.cleanNonce == NULL || mgrCtrl == NULL) {
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = mgrCtrl(mgrCtx, CRYPT_EAL_MGR_GETSEEDCTX, &seedCtx, 0);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = mgrCtrl(mgrCtx, CRYPT_EAL_MGR_GETLIBCTX, &libCtx, 0);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    CRYPT_Data entropy = {NULL, 0};
    CRYPT_Range entropyRange = {32, 2147483632};
    ret = entroy.getEntropy(seedCtx, &entropy, 256, &entropyRange);
    if (ret != CRYPT_SUCCESS) {
        return CRYPT_DRBG_FAIL_GET_ENTROPY;
    }
    entroy.cleanEntropy(seedCtx, &entropy);
    // check libCtx
    if (param != NULL) {
        if (param[0].value != libCtx) {
            return CRYPT_INVALID_ARG;
        }
    }
    *outFuncs = defProvOutFuncs;
    return 0;
}
```
- **算法查询函数示例**：
```c
const CRYPT_EAL_Func defMdMd5[] = {
    {CRYPT_EAL_IMPLMD_NEWCTX, ...},
    {CRYPT_EAL_IMPLMD_INITCTX, ...},
    {CRYPT_EAL_IMPLMD_UPDATE, ...},
    {CRYPT_EAL_IMPLMD_FINAL, ...},
    {CRYPT_EAL_IMPLMD_DEINITCTX, ...},
    {CRYPT_EAL_IMPLMD_DUPCTX, ...},
    {CRYPT_EAL_IMPLMD_CTRL, ...},
    {CRYPT_EAL_IMPLMD_FREECTX, ...},
    CRYPT_EAL_FUNC_END,
};

static const CRYPT_EAL_AlgInfo defMds[] = {
    ...
    {CRYPT_MD_MD5, defMdMd5, "attr1=temp_attr1,attr2=temp_attr2"},
    ...
    CRYPT_EAL_ALGINFO_END
};

static int32_t CRYPT_EAL_DefaultProvQuery(void *provCtx, int32_t operaId, const CRYPT_EAL_AlgInfo **algInfos)
{
    (void) provCtx;
    int32_t ret = CRYPT_SUCCESS;
    switch (operaId) {
        ...
        case CRYPT_EAL_OPERAID_HASH:
            *algInfos = defMds;
            break;
        ...
        default:
            ret = CRYPT_NOT_SUPPORT;
            break;
    }
    return ret;
}
```

---

## 5. 综合使用示例

```c
#include "bsl_sal.h"
#include "crypt_eal_provider.h"
#include "crypt_eal_implprovider.h"
#include "crypt_eal_md.h"

/* 调用SM3 算法 */

int main() {

------------------------------------------------------------------------------------------------------

// 调用hitls自带的算法库初始化方式：
    // 步骤 1：调用eal层的md对外接口直接进行初始化
    CRYPT_EAL_MdCTX *ctx = CRYPT_EAL_ProviderMdNewCtx(NULL, CRYPT_MD_SM3, "provider=default");
    ASSERT_TRUE(ctx != NULL);

-----------------------------------------------

// 在第三方provider中寻找匹配的算法库并初始化方式：
    // 步骤 1：创建库上下文
    CRYPT_EAL_LibCtx *libCtx = CRYPT_EAL_LibCtxNew();
    ASSERT_TRUE(libCtx != NULL);

    // 步骤 2：设置 Provider 加载路径
    int ret = CRYPT_EAL_ProviderSetLoadPath(libCtx, "/path/to/providers");
    ASSERT_TRUE(ret == CRYPT_SUCCESS);

    // 步骤 3：加载 Provider
    ret = CRYPT_EAL_ProviderLoad(libCtx, BSL_SAL_LIB_FMT_SO, "provider_name", NULL, NULL);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);

    // 步骤 4：调用eal层的md对外接口直接进行初始化
    CRYPT_EAL_MdCTX *ctx = CRYPT_EAL_ProviderMdNewCtx(libCtx, CRYPT_MD_SM3, "attr1=temp_attr1,attr2=temp_attr2");
    ASSERT_TRUE(ctx != NULL);

-----------------------------------------------

// 第三方provider和hitls提供的算法库混合使用的场景，寻找匹配的算法库并初始化方式：
    // 步骤 1：设置 Provider 加载路径
    int ret = CRYPT_EAL_ProviderSetLoadPath(NULL, "/path/to/providers");
    ASSERT_TRUE(ret == CRYPT_SUCCESS);

    // 步骤 2：加载 Provider
    ret = CRYPT_EAL_ProviderLoad(NULL, BSL_SAL_LIB_FMT_SO, "provider_name", NULL, NULL);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);

    // 步骤 3：调用eal层的md对外接口直接进行初始化
    CRYPT_EAL_MdCTX *ctx = CRYPT_EAL_ProviderMdNewCtx(NULL, CRYPT_MD_SM3, "attr1=temp_attr1,attr2=temp_attr2");
    ASSERT_TRUE(ctx != NULL);

------------------------------------------------------------------------------------------------------

// 初始化后可进行一系列的算法操作:
    ASSERT_EQ(CRYPT_EAL_MdInit(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, msg->x, msg->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, output, &outLen), CRYPT_SUCCESS);

------------------------------------------------------------------------------------------------------

// 如果初始化时创建了库上下文或者加载了第三方provider,则需要进行释放
    // 卸载 Provider
    ret = CRYPT_EAL_ProviderUnload(libCtx, BSL_SAL_CONVERTER_SO, "provider_name");
    ASSERT_TRUE(ret == CRYPT_SUCCESS);

    // 释放库上下文
    CRYPT_EAL_LibCtxFree(libCtx);

    return 0;
}
```