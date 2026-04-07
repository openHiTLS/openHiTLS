# CMake Build System Developer Configuration Guide

This document is intended for openHiTLS developers and helps them quickly integrate new features into the pure CMake build system.

---

## 1. Overall Build System Architecture

### 1.1 Three-Layer CMake File Structure (Overview)

openHiTLS CMake files are organized in three layers, each with a clear responsibility:

```
Layer 1: Global Build Framework (cmake/ directory)
├── CMakeLists.txt                           ← Root entry, loads all modules below (developers usually don't need to modify)
├── cmake/hitls_options.cmake                ← Sole entry for all user-configurable options (option/set)
├── cmake/config.h.in                        ← Compile-time macro template, input to configure_file; sole entry for all compile-time macros
├── cmake/hitls_define_dependencies.cmake    ← Declarations of feature dependencies, parent-child relationships, and optional dependencies
├── cmake/hitls_config_check.cmake           ← Dependency validity checks at configuration time
├── cmake/hitls_generate_config_h_file.cmake ← Generates hitls_build_config.h from config.h.in (developers usually don't need to modify)
├── cmake/hitls_compile_options.cmake        ← Default global compile/link options (developers usually don't need to modify)
├── cmake/hitls_build_targets.cmake          ← Assembles final library targets (bundle / split mode, developers usually don't need to modify)
├── cmake/hitls_collect_feature_macros.cmake ← Collects compile-time macro list (developers usually don't need to modify)
├── cmake/hitls_load_preset.cmake            ← Preset loading (full / iso19790, etc., developers usually don't need to modify)
└── cmake/helpers/                           ← Internal helper functions (developers usually don't need to modify)
    ├── hitls_target_helpers.cmake           ← hitls_register_objects() registers object libraries
    ├── hitls_lib_helpers.cmake              ← hitls_create_shared/static_library(), etc.
    └── hitls_depends_helpers.cmake          ← hitls_define_dependency() implementation

Layer 2: Component Top-Level Orchestration (component root directories)
├── bsl/CMakeLists.txt      ← add_subdirectory orchestration for BSL component modules
├── crypto/CMakeLists.txt   ← add_subdirectory orchestration for Crypto component modules
├── tls/CMakeLists.txt      ← add_subdirectory orchestration for TLS component modules
├── pki/CMakeLists.txt      ← add_subdirectory orchestration for PKI component modules
└── auth/CMakeLists.txt     ← add_subdirectory orchestration for Auth component modules

Layer 3: Module Implementation (algorithm/feature subdirectories)
├── crypto/sha2/CMakeLists.txt   ← Declares source file list, creates OBJECT library, registers to global collection
├── crypto/aes/CMakeLists.txt
├── bsl/err/CMakeLists.txt
└── ... (each feature module has its own CMakeLists.txt)
```

**Data Flow**: Layer 1 parses user-supplied `-D` options and determines which components participate in the build → Layer 2 decides which modules participate based on feature switches → Layer 3 registers qualifying source files as OBJECT libraries → Layer 1's `hitls_build_targets.cmake` assembles all OBJECT libraries into the final shared/static library.

### 1.2 Files Developers May Need to Modify

When adding a new feature, different files need to be modified depending on the work involved. The following table lists the files that are generally required:

| Scenario | Files to Modify |
|----------|----------------|
| Add a feature switch controllable via `-D` | `cmake/hitls_options.cmake` and `cmake/config.h.in`; if only needed at compile time and not intended for user configuration, modify only `config.h.in` |
| Add parent-child extension / hard dependency / dependency check for a feature | `cmake/hitls_define_dependencies.cmake` |
| Add business-layer dependency validity checks (optional, usually for complex dependencies) | `cmake/hitls_config_check.cmake` |
| Add a new three-layer module directory or modify module orchestration | Layer-2 `CMakeLists.txt` (e.g., `crypto/CMakeLists.txt`) |
| Add source files or modify module implementation | Layer-3 `CMakeLists.txt` (feature module root, e.g., `crypto/sha2/CMakeLists.txt`) |


**Note**: Options defined in `hitls_options.cmake` are user-configurable, while macros in `config.h.in` are those needed at compile time. They usually need to be modified together to ensure a new feature is correctly configured and used. The difference is: `hitls_options.cmake` contains both build switches and feature macro switches (e.g., `HITLS_BUILD_STATIC` to build a static library, `HITLS_CRYPTO_SHA256` as a SHA256 feature switch), while `config.h.in` contains only the final compile-time macros (e.g., `HITLS_CRYPTO_SHA256`).

---

## 2. Scenario-Based Detailed Guide

### Adding a Pure-C Algorithm Module (Example: Adding a New SHA3 Hash Module)

1. Add the corresponding option to `cmake/hitls_options.cmake` and `cmake/config.h.in` (to control enabling and disabling of the new feature).

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

2. Add the dependency relationship for `HITLS_CRYPTO_SHA3` in `cmake/hitls_define_dependencies.cmake` (to declare dependency relationships for dependency inference or checking).

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

**Note**: Adding `HITLS_CRYPTO_SHA3` to the `CHILDREN` of `HITLS_CRYPTO_MD` means that if the user explicitly enables `HITLS_CRYPTO_MD`, `HITLS_CRYPTO_SHA3` will also be automatically enabled and treated as explicitly enabled by the user.

3. Add a `CMakeLists.txt` file in the algorithm implementation directory `crypto/sha3/` (to compile the current module as an OBJECT library for use in final library target assembly).

crypto/sha3/CMakeLists.txt:
```cmake
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

**Note**: `hitls_register_objects` registers the current module's OBJECT library into the global collection for assembly into the final library target. It must be called. The first argument indicates the owning component (BSL/CRYPTO/TLS/PKI/AUTH/APPS).

4. Add `sha3` to the component's `crypto/CMakeLists.txt` (to integrate the module into the build system).

crypto/CMakeLists.txt:
```diff
if(HITLS_CRYPTO_SHA2)
    add_subdirectory(sha2)
endif()

+if(HITLS_CRYPTO_SHA3)
+    add_subdirectory(sha3)
+endif()

```

### Adding an Assembly Implementation to an Algorithm Module (Example: Adding ARMv8 Assembly for SHA3)

1. Add the corresponding assembly options to `cmake/hitls_options.cmake` and `cmake/config.h.in`.

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

2. Add the dependency relationship for `HITLS_CRYPTO_SHA3_ARMV8` in `cmake/hitls_define_dependencies.cmake`.

```diff
hitls_define_dependency(HITLS_CRYPTO_SHA2_ARMV8         DEPS     HITLS_CRYPTO_SHA2_ASM)
hitls_define_dependency(HITLS_CRYPTO_SHA2_X8664         DEPS     HITLS_CRYPTO_SHA2_ASM)
+hitls_define_dependency(HITLS_CRYPTO_SHA3_ARMV8         DEPS     HITLS_CRYPTO_SHA3_ASM)
```

3. Add the conditional source compilation to the `sha3` module's `crypto/sha3/CMakeLists.txt`.

crypto/sha3/CMakeLists.txt:
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

### Adding an Optional Dependency Check for a Feature

1. For simple optional dependency checks, add them directly to the corresponding feature dependency entry in `cmake/hitls_define_dependencies.cmake`.
   For example, when `HITLS_CRYPTO_DRBG_HASH` is enabled, it needs to check whether `HITLS_CRYPTO_MD` is also enabled. Use the `DEPS_CHECK` parameter:

```diff
hitls_define_dependency(HITLS_CRYPTO_DRBG_HASH
    DEPS HITLS_CRYPTO_DRBG
+   DEPS_CHECK HITLS_CRYPTO_MD
)
```

This way, when `HITLS_CRYPTO_DRBG_HASH` is enabled and `HITLS_CRYPTO_MD` is not, the system will prompt the user.

**Note**: The difference between `DEPS` and `DEPS_CHECK`: `DEPS` denotes a required dependency — if it is not enabled, it will be automatically enabled; `DEPS_CHECK` denotes an optional dependency — if it is not enabled, the user will be prompted but it will not be automatically enabled. Users can suppress the warning with `-DHITLS_SKIP_CONFIG_CHECK=ON` to skip the check.

2. For more complex dependency checks (e.g., conditional dependencies, optional dependency combinations), add them to `cmake/hitls_config_check.cmake` (condition + message).
   For example, when `HITLS_CRYPTO_ECDH` or `HITLS_CRYPTO_ECDSA` is enabled, check that at least one EC curve is also enabled:

```cmake
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

## 3. Minimal Build Testing

1. **Build test**: For a newly added feature, it is recommended to enable only that feature during the build test to verify correctness and ensure no unnecessary dependencies have been introduced. You can add `-DHITLS_BUILD_GEN_INFO=ON` to generate info files for reviewing the final enabled macros (`build/macros.txt`) and the source files included in the final library (`build/sources.txt`).

2. **Functional test**: On top of the build test, it is recommended to write corresponding unit test cases to verify the correctness of the new feature, and to add the corresponding test tasks in CI to ensure the feature remains continuously available.
