# CMake 构建系统开发配置指南

本文档面向 openHiTLS 的开发人员，帮助开发者在纯 CMake 构建体系下快速完成新功能的接入配置。

---

## 1. 构建系统总体架构

### 1.1 三层 CMake 文件结构（大致了解即可）

openHiTLS 的 CMake 文件分为三个层次，各层职责明确：

```
第一层：全局构建框架（cmake/ 目录）
├── CMakeLists.txt                           ← 根入口，负责加载下面所有模块（开发者通常不需要修改）
├── cmake/hitls_options.cmake                ← 所有用户可配置选项（option/set）的唯一入口
├── cmake/config.h.in                        ← 编译时宏模板，configure_file 的输入，也是所有编译时宏的唯一入口
├── cmake/hitls_define_dependencies.cmake    ← 特性间依赖/父子关系/可选依赖声明
├── cmake/hitls_config_check.cmake           ← 配置阶段的依赖合法性检查
├── cmake/hitls_generate_config_h_file.cmake ← 从 config.h.in 生成 hitls_build_config.h（开发者通常不需要修改）
├── cmake/hitls_compile_options.cmake        ← 全局编译／链接选项默认值（开发者通常不需要修改）
├── cmake/hitls_build_targets.cmake          ← 最终库目标的组装（bundle / split 模式，开发者通常不需要修改）
├── cmake/hitls_collect_feature_macros.cmake ← 收集编译时的宏列表（开发者通常不需要修改）
├── cmake/hitls_load_preset.cmake            ← 预设加载（full / iso19790 等，开发者通常不需要修改）
└── cmake/helpers/                           ← 内部辅助函数（开发者通常不需要修改）
    ├── hitls_target_helpers.cmake           ← hitls_register_objects() 注册对象库
    ├── hitls_lib_helpers.cmake              ← hitls_create_shared/static_library() 等
    └── hitls_depends_helpers.cmake          ← hitls_define_dependency() 实现

第二层：组件顶层编排（各组件根目录）
├── bsl/CMakeLists.txt      ← BSL 组件内各模块的 add_subdirectory 编排
├── crypto/CMakeLists.txt   ← Crypto 组件内各模块的 add_subdirectory 编排
├── tls/CMakeLists.txt      ← TLS 组件内各模块的 add_subdirectory 编排
├── pki/CMakeLists.txt      ← PKI 组件内各模块的 add_subdirectory 编排
└── auth/CMakeLists.txt     ← Auth 组件内各模块的 add_subdirectory 编排

第三层：模块实现（各算法/功能子目录）
├── crypto/sha2/CMakeLists.txt   ← 声明源文件列表，创建 OBJECT 库，注册到全局集合
├── crypto/aes/CMakeLists.txt
├── bsl/err/CMakeLists.txt
└── ...（每个功能模块都有自己的 CMakeLists.txt）
```

**数据流向**：第一层解析用户传入的 `-D` 选项，并决定哪些组件参与构建 → 第二层按特性开关决定哪些模块参与构建 → 第三层将符合条件的源文件注册为 OBJECT 库 → 第一层的 `hitls_build_targets.cmake` 将所有 OBJECT 库组装为最终的共享库/静态库。

### 1.2 开发者可能需要修改的文件清单

新增功能时，根据工作内容的不同，需要修改不同的文件。以下是一般需要修改的文件：

| 需要修改的场景 | 可能需要修改的文件 |
|---------------|-------------------|
| 新增特性开关供用户通过 -D 控制 | `cmake/hitls_options.cmake`和`cmake/config.h.in`，如果只在编译时需要而不希望用户配置，则只修改`config.h.in` |
| 新增特性的父子扩展关系/强依赖关系/需要检查的依赖关系 | `cmake/hitls_define_dependencies.cmake` |
| 新增业务层依赖合法性检查（可选，通常用于复杂依赖关系） | `cmake/hitls_config_check.cmake` |
| 新增三层模块目录或修改模块编排 | 二层`CMakeLists.txt`（如：`crypto/CMakeLists.txt`） |
| 新增源文件或修改模块实现 | 三层`CMakeLists.txt`（各功能模块根目录，如：`crypto/sha2/CMakeLists.txt`） |


**特别说明**：`hitls_options.cmake`中定义的是用户可配置的选项，`config.h.in`中定义的是编译时需要用到的宏。它们通常需要同时修改，以确保新特性能够被正确配置和使用。它们的差异在于：`hitls_options.cmake`定义的选项包含了构建和特性开关宏（如：构建静态库`HITLS_BUILD_STATIC`，SHA256功能开关`HITLS_CRYPTO_SHA256`），而 `config.h.in` 仅包含最终生成的编译时宏（如：`HITLS_CRYPTO_SHA256`）。

---

## 2. 分场景详细指导
### 新增一个纯C实现的算法模块（假设新增一个新的哈希算法模块 SHA3）
1. 在`cmake/hitls_options.cmake`和`cmake/config.h.in`中添加对应的选项（用于控制新特性的开启与禁用）

cmake/hitls_options.cmake:
```diff
## Md(Hash)
option(HITLS_CRYPTO_MD                      "MD" OFF)
  option(HITLS_CRYPTO_SHA2                    "SHA2" OFF)
    option(HITLS_CRYPTO_SHA256                  "SHA256" OFF)
    option(HITLS_CRYPTO_SHA512                  "SHA512" OFF)
+ option(HITLS_CRYPTO_SHA3                    "SHA3" OFF)
```

cmake/config.h.in:
```diff
// Md(Hash)
#cmakedefine HITLS_CRYPTO_MD
#cmakedefine HITLS_CRYPTO_SHA2
+#cmakedefine HITLS_CRYPTO_SHA3
```

2. 在`cmake/hitls_define_dependencies.cmake`中添加`HITLS_CRYPTO_SHA3`的依赖关系（用于声明依赖关系，进而进行依赖的推导或检查）

```diff
## Hash
hitls_define_dependency(HITLS_CRYPTO_MD
    DEPS HITLS_CRYPTO
-   CHILDREN HITLS_CRYPTO_SHA2
+   CHILDREN HITLS_CRYPTO_SHA2 HITLS_CRYPTO_SHA3
)
hitls_define_dependency(HITLS_CRYPTO_SHA2
    DEPS HITLS_CRYPTO_MD
    CHILDREN HITLS_CRYPTO_SHA256 HITLS_CRYPTO_SHA512
)
+hitls_define_dependency(HITLS_CRYPTO_SHA3      DEPS HITLS_CRYPTO_MD)
```

** 注意 **：
`HITLS_CRYPTO_MD`的`CHILDREN`中添加`HITLS_CRYPTO_SHA3`表示用户如果主动启用`HITLS_CRYPTO_MD`，`HITLS_CRYPTO_SHA3`也会被自动启用且认为是用户主动启用。

3. 在算法实现目录`crypto/sha3/`中新增模块的`CMakeLists.txt`文件（用于将当前模块编译为object库，供最终库目标组装使用）

crypto/sha3/CMakeLists.txt：
```CMAKE
set(_sha3_sources
    ${CMAKE_CURRENT_SOURCE_DIR}/src/sha3.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/noasm_sha3.c
)

add_library(_hitls_crypto_sha3 OBJECT ${_sha3_sources})

target_link_libraries(_hitls_crypto_sha3
    PUBLIC
        _hitls_crypto_common_include
)

target_include_directories(_hitls_crypto_sha3
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

hitls_register_objects(CRYPTO _hitls_crypto_sha3)
```
**注意**：`hitls_register_objects` 用于将当前模块的 OBJECT 库注册到全局集合，以便在最终库目标中进行组装，必须调用，第一个参数表示所属组件（BSL/CRYPTO/TLS/PKI/AUTH/APPS）。

4. 在对应组件的目录`crypto/`的`CMakeLists.txt`中添加对新模块的编排（用于将当前模块纳入构建体系）
crypto/CMakeLists.txt：
```diff
if(HITLS_CRYPTO_SHA2)
    add_subdirectory(sha2)
endif()

+if(HITLS_CRYPTO_SHA3)
+    add_subdirectory(sha3)
+endif()

```

### 为某个算法模块新增汇编实现（假设为SHA3新增ARMv8的汇编实现）
1. 在`cmake/hitls_options.cmake`和`cmake/config.h.in`中添加对应的汇编选项

cmake/hitls_options.cmake:
```diff
option(HITLS_CRYPTO_SHA2_ASM            "SHA2 ASM" OFF)
option(HITLS_CRYPTO_SHA2_ARMV8          "SHA2 ARMv8" OFF)
option(HITLS_CRYPTO_SHA2_X8664          "SHA2 x86_64" OFF)
+option(HITLS_CRYPTO_SHA3_ASM           "SHA3 ASM" OFF)
+option(HITLS_CRYPTO_SHA3_ARMV8         "SHA3 ARMv8" OFF)
```

cmake/config.h.in:
```diff
#cmakedefine HITLS_CRYPTO_SHA2_ASM
#cmakedefine HITLS_CRYPTO_SHA2_ARMV8
#cmakedefine HITLS_CRYPTO_SHA2_X8664
+#cmakedefine HITLS_CRYPTO_SHA3_ASM
+#cmakedefine HITLS_CRYPTO_SHA3_ARMV8
```

2. 在`cmake/hitls_define_dependencies.cmake`中添加`HITLS_CRYPTO_SHA3_ARMV8`的依赖关系

```diff
hitls_define_dependency(HITLS_CRYPTO_SHA2_ARMV8         DEPS     HITLS_CRYPTO_SHA2_ASM)
hitls_define_dependency(HITLS_CRYPTO_SHA2_X8664         DEPS     HITLS_CRYPTO_SHA2_ASM)
+hitls_define_dependency(HITLS_CRYPTO_SHA3_ARMV8         DEPS     HITLS_CRYPTO_SHA3_ASM)
```

3. 在`sha3`模块`crypto/sha3/CMakeLists.txt`文件中添加对应的源代码编译条件

crypto/sha3/CMakeLists.txt：
```diff
set(_sha3_sources
    ${CMAKE_CURRENT_SOURCE_DIR}/src/sha3.c
-    ${CMAKE_CURRENT_SOURCE_DIR}/src/noasm_sha3.c
)
+if(HITLS_CRYPTO_SHA3_ARMV8)
+    list(APPEND _sha3_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/sha3_armv8.S)
+else()
+    list(APPEND _sha3_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/noasm_sha3.c)
+endif()

add_library(_hitls_crypto_sha3 OBJECT ${_sha3_sources})
```
### 为某个特性添加可选依赖检查
1. 如果是简单的可选依赖检查，直接添加到`cmake/hitls_define_dependencies.cmake`中对应的特性依赖关系即可。
例如，`HITLS_CRYPTO_DRBG_HASH`开启时需要检查`HITLS_CRYPTO_MD`是否同时开启，直接使用`DEPS_CHECK`参数进行定义：
```diff
hitls_define_dependency(HITLS_CRYPTO_DRBG_HASH
    DEPS HITLS_CRYPTO_DRBG
+   DEPS_CHECK HITLS_CRYPTO_MD
)
```
这样在开启`HITLS_CRYPTO_DRBG_HASH`时，如果`HITLS_CRYPTO_MD`未开启，会提示用户。

**特别说明**：`DEPS`和`DEPS_CHECK`的区别，`DEPS`表示必须依赖的特性，如果未开启会自动启用；而`DEPS_CHECK`表示可选依赖，如果未开启会提示用户但不会自动启用，如果用户想忽略提示，可通过`-DHITLS_SKIP_CONFIG_CHECK=ON`跳过检查。

2. 如果是比较复杂的依赖检查（如条件依赖，可选依赖组合等），需要添加到`cmake/hitls_config_check.cmake`中(条件+提示信息)。
例如：在开启`HITLS_CRYPTO_ECDH`或`HITLS_CRYPTO_ECDSA`时，需要检查是否开启至少一种EC曲线：
```CMAKE
if(HITLS_CRYPTO_ECDH OR HITLS_CRYPTO_ECDSA)
    if(NOT HITLS_CRYPTO_CURVE_NISTP192 AND NOT HITLS_CRYPTO_CURVE_NISTP224 AND NOT HITLS_CRYPTO_CURVE_NISTP256 AND
        NOT HITLS_CRYPTO_CURVE_NISTP384 AND NOT HITLS_CRYPTO_CURVE_NISTP521 AND NOT HITLS_CRYPTO_CURVE_BP256R1 AND
        NOT HITLS_CRYPTO_CURVE_BP384R1 AND NOT HITLS_CRYPTO_CURVE_BP512R1)
        hitls_add_dependency_warning(
            "[HiTLS] The ECDH/ECDSA must work with at least one curve. "
            "(HITLS_CRYPTO_ECDH/HITLS_CRYPTO_ECDSA)"
            "(HITLS_CRYPTO_CURVE_NISTP192/HITLS_CRYPTO_CURVE_NISTP224/HITLS_CRYPTO_CURVE_NISTP256/"
            "HITLS_CRYPTO_CURVE_NISTP384/HITLS_CRYPTO_CURVE_NISTP521/HITLS_CRYPTO_CURVE_BP256R1/"
            "HITLS_CRYPTO_CURVE_BP384R1/HITLS_CRYPTO_CURVE_BP512R1)"
        )
    endif()
endif()
```

## 3. 小型化构建测试
1. 构建测试：对于新增的特性，建议只开启新增的特性进行构建测试，验证功能正确且没有引入不必要的依赖。构建测试时可添加`-DHITLS_BUILD_GEN_INFO=ON`选项生成信息文件，方便查看最终开启的宏(`build/macros.txt`)和最终库包含的源文件(`build/sources.txt`)。

2. 功能测试：在构建测试的基础上，建议编写对应的单元测试用例，验证新增功能的正确性，并且在 CI 中添加对应的测试任务，确保功能持续可用。
