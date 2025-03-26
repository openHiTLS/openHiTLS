# Provider Development Guide

This document serves as a development guide for OpenHiTLS providers, providing developers with interface introductions, key feature descriptions, and comprehensive usage examples.

## 1. Overview

The provider management framework in OpenHiTLS supports dynamic loading, management, and usage of cryptographic providers. Each "Provider" encapsulates a specific set of cryptographic operations and exposes them to external users through standardized interfaces.

### Core Concepts:
- **Library Context (`CRYPT_EAL_LibCtx`)**: Manages the lifecycle and resources of all loaded providers.
- **Provider Manager Context (`CRYPT_EAL_ProvMgrCtx`)**: Represents a single provider, including its loaded library handle and implemented functionalities.
- **Functional Interfaces**: Standardized functions used for querying and invoking specific operations of providers.

---

## 2. Interface Introduction

### 2.1 Library Context Management

#### **`CRYPT_EAL_LibCtxNew`**
- **Description**: Creates a new library context for managing providers.
- **Function Prototype**:
    ```c
    CRYPT_EAL_LibCtx *CRYPT_EAL_LibCtxNew(void);
    ```
- **Return Value**: A pointer to the newly created library context.

#### **`CRYPT_EAL_LibCtxFree`**
- **Description**: Frees the library context and releases all associated resources.
- **Function Prototype**:
    ```c
    void CRYPT_EAL_LibCtxFree(CRYPT_EAL_LibCtx *libCtx);
    ```
- **Parameters**:
    - `libCtx`: The library context to be freed.

---

### 2.2 Path Configuration

#### **`CRYPT_EAL_ProviderSetLoadPath`**
- **Description**: Configures the path for loading providers.
- **Function Prototype**:
    ```c
    int32_t CRYPT_EAL_ProviderSetLoadPath(
        CRYPT_EAL_LibCtx *libCtx,
        const char *searchPath
    );
    ```
- **Parameters**:
    - `libCtx`: The library context.
    - `searchPath`: The search path for providers.
- **Return Value**: Returns `CRYPT_SUCCESS` on success, otherwise an error code.

---

### 2.3 Provider Loading and Unloading

#### **`CRYPT_EAL_ProviderLoad`**
- **Description**: Dynamically loads a provider and initializes it.
- **Function Prototype**:
    ```c
    int32_t CRYPT_EAL_ProviderLoad(
        CRYPT_EAL_LibCtx *libCtx,
        BSL_SAL_ConverterCmd cmd,
        const char *providerName,
        BSL_Param *param,
        CRYPT_EAL_ProvMgrCtx **mgrCtx
    );
    ```
- **Parameters**:
    - `libCtx`: The library context.
    - `cmd`: The command specifying the library format (e.g., `.so`, `lib*.so`).
    - `providerName`: The name of the provider to load.
    - `param`: Additional parameters for provider initialization.
    - `mgrCtx`: Output pointer to the provider manager context. If not `NULL`, the manager context of the loaded provider will be returned upon successful loading.
- **Return Value**: Returns `CRYPT_SUCCESS` on success, otherwise an error code.

#### **`CRYPT_EAL_ProviderUnload`**
- **Description**: Unloads the specified provider and releases associated resources.
- **Function Prototype**:
    ```c
    int32_t CRYPT_EAL_ProviderUnload(
        CRYPT_EAL_LibCtx *libCtx,
        BSL_SAL_ConverterCmd cmd,
        const char *providerName
    );
    ```
- **Parameters**:
    - `libCtx`: The library context.
    - `cmd`: The command specifying the library format.
    - `providerName`: The name of the provider to unload.
- **Return Value**: Returns `CRYPT_SUCCESS` on success, otherwise an error code.

---

### 2.4 Algorithm Query and Invocation

**EAL Layer Wrapper Interfaces**:

These interfaces wrap the provider's exposed APIs, automatically initializing algorithms after querying suitable algorithms. See the corresponding headers for each algorithm for more details.

- **Symmetric Interface: `CRYPT_EAL_ProviderCipherNewCtx`**
- **Asymmetric Interface: `CRYPT_EAL_ProviderPkeyNewCtx`**
- **KDF Interface: `CRYPT_EAL_ProviderKdfNewCtx`**
- **MAC Interface: `CRYPT_EAL_ProviderMacNewCtx`**
- **Message Digest Interface: `CRYPT_EAL_ProviderMdNewCtx`**
- **Random Number Interfaces: `CRYPT_EAL_ProviderRandInitCtx`, `CRYPT_EAL_ProviderDrbgNewCtx`**

**Provider Layer Exposed Interfaces**:

#### **`CRYPT_EAL_ProviderGetFuncs`**
- **Description**: Queries algorithms matching the criteria from all loaded providers.
- **Function Prototype**:
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
- **Parameters**:
    - `libCtx`: The library context.
    - `operaId`: Algorithm category ID (see "crypt_eal_implprovider.h").
    - `algId`: Algorithm ID (see "crypt_eal_implprovider.h").
    - `attribute`: Attribute string for filtering providers.
    - `funcs`: Output pointer to an array of algorithms.
    - `provCtx`: Optional parameter. If not `NULL`, it retrieves the `provCtx` from the provider manager context where the algorithm resides.
- **Return Value**: Returns `CRYPT_SUCCESS` on success, otherwise an error code.

#### **`CRYPT_EAL_ProviderCtrl`**
- **Description**: Controls the `provCtx` in the provider manager context.
- **Function Prototype**:
    ```c
    int32_t CRYPT_EAL_ProviderCtrl(
        CRYPT_EAL_ProvMgrCtx *ctx,
        int32_t cmd,
        void *val,
        uint32_t valLen
    );
    ```
- **Parameters**:
    - `ctx`: Provider manager context.
    - `cmd`: Control command.
    - `val`: The value associated with the command.
    - `valLen`: The length of the value.
### 2.5 Capabilities

Capabilities provide a mechanism for applications to obtain the set of capabilities supported by a provider. Through capabilities, providers can indicate their supported capabilities to users.

#### 2.5.1 "CRYPT_EAL_GET_GROUP_CAP"

`"CRYPT_EAL_GET_GROUP_CAP"` is used to obtain the list of `groups` supported in TLS handshakes. When creating a `HITLS_Config`, it queries and collects the list of `groups` supported by all providers. These `groups` are used for key negotiation during handshakes. Each `group` must support either a `kex` or `kem` algorithm. Through this mechanism, providers can add new `groups` to TLS handshakes.

Each `group` supported by a provider can be declared through the callback passed to `CRYPT_EAL_PROVCB_GETCAPS`. Each `group` can have the following fields:

- `CRYPT_PARAM_CAP_TLS_GROUP_IANA_GROUP_NAME`: Type `BSL_PARAM_TYPE_OCTETS_PTR`, TLS supported groups registered in IANA. See [IANA](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8)
- `CRYPT_PARAM_CAP_TLS_GROUP_IANA_GROUP_ID`: Type `BSL_PARAM_TYPE_UINT16`, corresponding ID of TLS supported groups registered in IANA.
- `CRYPT_PARAM_CAP_TLS_GROUP_PARA_ID`: Type `BSL_PARAM_TYPE_INT32`, parameter ID for the group, passed to `CRYPT_EAL_PkeySetParaById` interface.
- `CRYPT_PARAM_CAP_TLS_GROUP_ALG_ID`: Type `BSL_PARAM_TYPE_INT32`, algorithm ID for the group, passed to `CRYPT_EAL_ProviderPkeyNewCtx` interface.
- `CRYPT_PARAM_CAP_TLS_GROUP_SEC_BITS`: Type `BSL_PARAM_TYPE_INT32`, security strength provided by the group.
- `CRYPT_PARAM_CAP_TLS_GROUP_VERSION_BITS`: Type `BSL_PARAM_TYPE_UINT32`, TLS version bitmap supported by the group. See `*_VERSION_BIT` in `hitls_type.h`
- `CRYPT_PARAM_CAP_TLS_GROUP_IS_KEM`: Type `BSL_PARAM_TYPE_BOOL`, indicates whether the group is a KEM algorithm.
- `CRYPT_PARAM_CAP_TLS_GROUP_PUBKEY_LEN`: Type `BSL_PARAM_TYPE_INT32`, public key length for the group.
- `CRYPT_PARAM_CAP_TLS_GROUP_SHAREDKEY_LEN`: Type `BSL_PARAM_TYPE_INT32`, shared key length for the group.
- `CRYPT_PARAM_CAP_TLS_GROUP_CIPHERTEXT_LEN`: Type `BSL_PARAM_TYPE_INT32`, ciphertext length for KEM algorithms.

For example code, refer to `crypt_default_provider.c:CryptGetGroupCaps`

#### 2.5.2 "CRYPT_EAL_GET_SIGALG_CAP"

`"CRYPT_EAL_GET_SIGALG_CAP"` is used to obtain the list of `signature algorithms` supported in TLS handshakes. When creating a `HITLS_Config`, it queries and collects the list of `signature algorithms` supported by all providers. These `signature algorithms` are used for authentication during handshakes. Through this mechanism, providers can add new `signature algorithms` to TLS handshakes.

Each `signature algorithm` supported by a provider can be declared through the callback passed to `CRYPT_EAL_PROVCB_GETCAPS`. Each `signature algorithm` can have the following fields:

- `CRYPT_PARAM_CAP_TLS_SIGNALG_IANA_SIGN_NAME`: Type `BSL_PARAM_TYPE_OCTETS_PTR`, TLS signature scheme name registered in IANA. See [IANA](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme)
- `CRYPT_PARAM_CAP_TLS_SIGNALG_IANA_SIGN_ID`: Type `BSL_PARAM_TYPE_UINT16`, corresponding ID of TLS signature scheme registered in IANA.
- `CRYPT_PARAM_CAP_TLS_SIGNALG_KEY_TYPE`: Type `BSL_PARAM_TYPE_INT32`, key type used by the signature algorithm.
- `CRYPT_PARAM_CAP_TLS_SIGNALG_KEY_TYPE_OID`: Type `BSL_PARAM_TYPE_OCTETS_PTR`, OID corresponding to the key type.
- `CRYPT_PARAM_CAP_TLS_SIGNALG_KEY_TYPE_NAME`: Type `BSL_PARAM_TYPE_OCTETS_PTR`, name of the key type.
- `CRYPT_PARAM_CAP_TLS_SIGNALG_PARA_ID`: Type `BSL_PARAM_TYPE_INT32`, parameter ID for the signature algorithm.
- `CRYPT_PARAM_CAP_TLS_SIGNALG_PARA_OID`: Type `BSL_PARAM_TYPE_OCTETS_PTR`, OID corresponding to the signature algorithm parameter.
- `CRYPT_PARAM_CAP_TLS_SIGNALG_PARA_NAME`: Type `BSL_PARAM_TYPE_OCTETS_PTR`, name of the signature algorithm parameter.
- `CRYPT_PARAM_CAP_TLS_SIGNALG_SIGNWITHMD_ID`: Type `BSL_PARAM_TYPE_INT32`, ID for the combination of signature and digest algorithms.
- `CRYPT_PARAM_CAP_TLS_SIGNALG_SIGNWITHMD_OID`: Type `BSL_PARAM_TYPE_OCTETS_PTR`, OID corresponding to the combination of signature and digest algorithms.
- `CRYPT_PARAM_CAP_TLS_SIGNALG_SIGNWITHMD_NAME`: Type `BSL_PARAM_TYPE_OCTETS_PTR`, name of the combination of signature and digest algorithms.
- `CRYPT_PARAM_CAP_TLS_SIGNALG_SIGN_ID`: Type `BSL_PARAM_TYPE_INT32`, signature algorithm ID.
- `CRYPT_PARAM_CAP_TLS_SIGNALG_MD_ID`: Type `BSL_PARAM_TYPE_INT32`, digest algorithm ID.
- `CRYPT_PARAM_CAP_TLS_SIGNALG_MD_OID`: Type `BSL_PARAM_TYPE_OCTETS_PTR`, OID corresponding to the digest algorithm.
- `CRYPT_PARAM_CAP_TLS_SIGNALG_MD_NAME`: Type `BSL_PARAM_TYPE_OCTETS_PTR`, name of the digest algorithm.
- `CRYPT_PARAM_CAP_TLS_SIGNALG_SEC_BITS`: Type `BSL_PARAM_TYPE_INT32`, security strength provided by the signature algorithm.
- `CRYPT_PARAM_CAP_TLS_SIGNALG_CHAIN_VERSION_BITS`: Type `BSL_PARAM_TYPE_UINT32`, certificate chain version bitmap supported by the signature algorithm. See `*_VERSION_BIT` in `hitls_type.h`
- `CRYPT_PARAM_CAP_TLS_SIGNALG_CERT_VERSION_BITS`: Type `BSL_PARAM_TYPE_UINT32`, certificate version bitmap supported by the signature algorithm. See `*_VERSION_BIT` in `hitls_type.h`

For example code, refer to `crypt_default_provider.c:CryptGetSignAlgCaps`

---

## 3. Provider Management Module Usage Instructions

### 3.1 Loading and Unloading

- **Feature Descriptions**:
    - Providers are uniquely identified by their names. Different providers must have unique names. Providers with the same name but located in different paths are treated as the same provider.
    - The framework supports repeated loading and unloading of providers. Repeated loading does not create additional provider manager contexts. To remove a provider manager context from the library context, the number of unloads must match the number of loads.
    - When releasing the library context, all loaded providers are automatically unloaded.
    - The default provider loading path is empty. If no path is set, the framework searches for providers in various locations based on the runtime environment and the behavior of the `dlopen` function.
    - Currently, OpenHiTLS's built-in algorithm library is loaded into a globally initialized library context during startup. If `libCtx` is `NULL` during provider loading, unloading, or searching, this global library context is used.

- **Usage Example**:
    ```c
    ...
    // Create a library context
    CRYPT_EAL_LibCtx *libCtx = CRYPT_EAL_LibCtxNew();
    assert(libCtx != NULL);

    // Set the provider loading path
    int ret = CRYPT_EAL_ProviderSetLoadPath(libCtx, "/path/to/providers");
    assert(ret == CRYPT_SUCCESS);

    // Load a provider
    CRYPT_EAL_ProvMgrCtx *mgrCtx = NULL;
    ret = CRYPT_EAL_ProviderLoad(libCtx, BSL_SAL_CONVERTER_SO, "provider_name", NULL, &mgrCtx);
    assert(ret == CRYPT_SUCCESS);

    ...

    // Unload the provider
    ret = CRYPT_EAL_ProviderUnload(libCtx, BSL_SAL_CONVERTER_SO, "provider_name");
    assert(ret == CRYPT_SUCCESS);

    // Free the library context
    CRYPT_EAL_LibCtxFree(libCtx);
    ...
    ```

---

### 3.2 Attribute Query and Provider Scoring Mechanism

- **Attribute Mechanism**:
    When querying algorithms, the framework first searches for algorithms matching the algorithm ID. If the search string is not `NULL`, it further selects the best-matching algorithm from all loaded providers based on the search string.
    Provider algorithm attributes are composed of a `name` and a `value`, separated by `=`. Multiple attributes are separated by `,`. Within a provider, each algorithm can define one or more sets of attributes based on its implementation purpose. Even the same algorithm can have different implementations distinguished by attributes.

- **Provider Scoring Mechanism**:
    Queries can consist of multiple query statements, separated by `,`. Within a statement, `name` and `value` are separated by the following **comparison characters**:
    - `=`: Must be equal (mandatory condition).
    - `!=`: Must not be equal (mandatory condition).
    - `?`: Optional condition. If `value` matches, it is prioritized. Each match adds +1 to the score.

    Mandatory conditions must be satisfied. Among providers that meet the mandatory conditions, the framework selects the best match based on optional conditions. If there are multiple best matches, one is randomly selected.
    Repeated conditions are allowed within query statements:
    - Repeated mandatory conditions have no effect.
    - Repeated optional conditions increase the score proportionally.

- **Usage Example**:
    ```c
    ...
    // Query with a NULL attribute string, searching by algorithm ID
    ret = CRYPT_EAL_ProviderGetFuncs(libCtx, CRYPT_EAL_OPERAID_HASH, CRYPT_MD_MD5, NULL, &funcs, &provCtx);
    assert(ret == CRYPT_SUCCESS);
    ...
    // Query with a non-NULL attribute string, matching based on rules
    ret = CRYPT_EAL_ProviderGetFuncs(libCtx, CRYPT_EAL_OPERAID_HASH, CRYPT_MD_MD5, "name=md5,type=hash,version=1.0", &funcs, &provCtx);
    assert(ret == CRYPT_SUCCESS);
    ...
    // Query with provider scoring mechanism
    ret = CRYPT_EAL_ProviderGetFuncs(libCtx, CRYPT_EAL_OPERAID_HASH, CRYPT_MD_MD5, "name=md5,feature?attr_good,feature?attr_good,feature?attr_bad", &funcs, &provCtx);
    assert(ret == CRYPT_SUCCESS);
    ...
    // For actual use, it is recommended to use EAL layer wrapping interfaces for each algorithm,
    // which automatically locate and initialize the algorithm.
    CRYPT_EAL_MdCTX *ctx = CRYPT_EAL_ProviderMdNewCtx(libCtx, CRYPT_MD_MD5, "provider=no_hitls,type=hash");
    assert(ctx != NULL);
    ...
    ```

---

## 4. Provider Construction Instructions

This section describes the commands and function prototypes, which are fully defined in the `crypt_eal_implprovider.h` header file.

### 4.1 Initialization Function

For each provider, an initialization function named `CRYPT_EAL_ProviderInit` must be implemented. This function is called when loading the provider:
- **Function Prototype**:
    ```c
    int32_t CRYPT_EAL_ProviderInit(
        CRYPT_EAL_ProvMgrCtx *mgrCtx,
        BSL_Param *param,
        CRYPT_EAL_Func *capFuncs,
        CRYPT_EAL_Func **outFuncs,
        void **provCtx
    );
    ```
    - **Parameters**:
        - `mgrCtx`: [in] Provider manager context.
        - `param`: [in] Additional parameters for provider initialization.
        - `capFuncs`: [in] Algorithm array pointer provided by the management framework, allowing users to optionally use HITLS's default entropy source.
        - `outFuncs`: [out] Array pointer for algorithms exposed by the provider. Details are described below.
        - `provCtx`: [out] Provider-specific structure. If needed, private data can be saved in the provider manager context. Details on its operation are below (optional).
    - **Return Value**: Returns `CRYPT_SUCCESS` on success, otherwise an error code.

- **Description of the `outFuncs` Array**:
    This array is used to pass the three types of algorithm arrays provided by the provider. **The algorithm query function must be returned**, while the other two functions are optional:
    - **Algorithm Query Function**: Used to retrieve the algorithm array provided by the provider based on the algorithm category during a search:
    **`typedef int32_t (*)(void *provCtx, int32_t operaId, CRYPT_EAL_AlgInfo **algInfos);`**
        - **Parameters**:
            - `provCtx`: [in] Provider-specific structure (optional).
            - `operaId`: [in] Algorithm category ID.
            - `algInfos`: [out] Pointer to the array of all algorithms under the category. The array ends when the algorithm ID is 0.
        - **Return Value**: Returns `CRYPT_SUCCESS` on success, otherwise an error code.
    - **`provCtx` Control Function**: If the provider uses `provCtx`, this function is used for its control. It can be invoked using the `CRYPT_EAL_ProviderCtrl` function.
    **`typedef int32_t (*)(void *provCtx, int32_t cmd, void *val, uint32_t valLen);`**
        - **Parameters**: Omitted.
        - **Return Value**: Omitted.
    - **`provCtx` Release Function**: If the provider uses `provCtx`, this function releases `provCtx`. It is called during resource release.
    **`typedef void (*)(void *provCtx);`**
    - **Parameters**:
        - `provCtx`: [in] Provider-specific structure.
        - **Return Value**: None.

---

### 4.2 Provider Construction Example

- **Initialization Function Example**:
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
- **Algorithm query function example**:
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

## 5. Comprehensive Usage Example

```c
#include "bsl_sal.h"
#include "crypt_eal_provider.h"
#include "crypt_eal_implprovider.h"
#include "crypt_eal_md.h"

/* Using the SM3 algorithm */

int main() {

------------------------------------------------------------------------------------------------------

// Using the built-in HITLS algorithm library:
    // Step 1: Directly initialize using EAL layer MD interface
    CRYPT_EAL_MdCTX *ctx = CRYPT_EAL_ProviderMdNewCtx(NULL, CRYPT_MD_SM3, "provider=default");
    ASSERT_TRUE(ctx != NULL);

-----------------------------------------------

// Searching and initializing with a matching algorithm library in a third-party provider:
    // Step 1: Create a library context
    CRYPT_EAL_LibCtx *libCtx = CRYPT_EAL_LibCtxNew();
    ASSERT_TRUE(libCtx != NULL);

    // Step 2: Set the provider loading path
    int ret = CRYPT_EAL_ProviderSetLoadPath(libCtx, "/path/to/providers");
    ASSERT_TRUE(ret == CRYPT_SUCCESS);

    // Step 3: Load the provider
    ret = CRYPT_EAL_ProviderLoad(libCtx, BSL_SAL_LIB_FMT_SO, "provider_name", NULL, NULL);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);

    // Step 4: Directly initialize using EAL layer MD interface
    CRYPT_EAL_MdCTX *ctx = CRYPT_EAL_ProviderMdNewCtx(libCtx, CRYPT_MD_SM3, "attr1=temp_attr1,attr2=temp_attr2");
    ASSERT_TRUE(ctx != NULL);

-----------------------------------------------

// Mixed usage of third-party providers and HITLS libraries:
    // Step 1: Set the provider loading path
    int ret = CRYPT_EAL_ProviderSetLoadPath(NULL, "/path/to/providers");
    ASSERT_TRUE(ret == CRYPT_SUCCESS);

    // Step 2: Load the provider
    ret = CRYPT_EAL_ProviderLoad(NULL, BSL_SAL_LIB_FMT_SO, "provider_name", NULL, NULL);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);

    // Step 3: Directly initialize using EAL layer MD interface
    CRYPT_EAL_MdCTX *ctx = CRYPT_EAL_ProviderMdNewCtx(NULL, CRYPT_MD_SM3, "attr1=temp_attr1,attr2=temp_attr2");
    ASSERT_TRUE(ctx != NULL);

------------------------------------------------------------------------------------------------------

// After initialization, a series of algorithm operations can be performed:
    ASSERT_EQ(CRYPT_EAL_MdInit(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, msg->x, msg->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, output, &outLen), CRYPT_SUCCESS);

------------------------------------------------------------------------------------------------------

// If a library context was created or a third-party provider was loaded during initialization, they need to be released:
    // Unload the provider
    ret = CRYPT_EAL_ProviderUnload(libCtx, BSL_SAL_CONVERTER_SO, "provider_name");
    ASSERT_TRUE(ret == CRYPT_SUCCESS);

    // Free the library context
    CRYPT_EAL_LibCtxFree(libCtx);

    return 0;
}
```