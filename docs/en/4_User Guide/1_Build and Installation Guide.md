# Build and Installation Guide

## 1. Preparing the Build Environment

Check whether the build tools have been installed in the system and can be used properly.

| **Name**| **Recommended Version**| **Description**|
| -------- | ------------ | -------- |
| Gcc        | ≥ 7.3.0      | Linux    |
| CMake    | ≥ 3.16        | Linux    |
| Sctp        | No restriction on versions   | Linux    |

Note: The DTLS feature depends on sctp. sctp is disabled by default. To enable it, install the sctp dependency in advance.

## 2. Preparing the Source Code

Method 1

1. Download the openHiTLS code, including the service code, build script, and test code.

   Repository address: https://gitcode.com/openhitls/openhitls.git
2. openHiTLS depends on the libboundscheck library. Before building openHiTLS, download the library to **openHiTLS/platform/Secure\_C**.

   Repository address: https://gitee.com/openeuler/libboundscheck.git

Method 2

Run the **git submodule** command to download the source code and dependent SecureC library:

```
git clone --recurse-submodules https://gitcode.com/openhitls/openhitls.git
```

## 3. Building and Installing openHiTLS

The openHiTLS code directory structure is as follows:

```
└── openHiTLS
   ├── bsl
   ├── CMakeLists.txt
   ├── cmake
   ├── config
   ├── crypto
   ├── docs
   ├── include
   ├── LICENSE
   ├── platform
   ├── README-zh.md
   ├── README.md
   ├── testcode
   ├── tls
   ├── pki
   └── auth
```
Where:

- CMakeLists.txt: build entry file
- cmake: CMake build modules, feature option definitions, platform presets, and toolchain files
- config: stores the configuration header files used during the build
- bsl: stores the code related to basic functions
- crypto: stores the code related to cryptographic algorithm capabilities
- tls: stores the code related to secure transmission
- platform: stores other dependent codes
- testcode: stores the test project code
- pki: stores the PKI related code
- auth: stores the auth related code

**Call CMake directly to build the source code. The detailed method is as follows:**

### 3.1 CMake Build

openHiTLS uses a pure CMake build system. All build options are controlled directly via `-D` parameters. You are advised to create a **build** directory to store temporary files generated during the build process, then go to the **build** directory and run `cmake .. && make` to complete the build.

The overall CMake build procedure is as follows:

```bash
cd openHiTLS
mkdir -p ./build
cd ./build
cmake .. [options]  # Configure, see section 3.1.1 for details
make -j
```

The build result is stored in the **openHiTLS/build** directory.

Common CMake parameters are as follows:

| **CMake Parameter** | **Description** | **Example** |
| ------------- | ------------ | -------- |
| `HITLS_BUILD_PROFILE` | Use a preset configuration. Options: `full`, `iso19790` | `cmake .. -DHITLS_BUILD_PROFILE=full` |
| `HITLS_BSL` / `HITLS_CRYPTO` / `HITLS_TLS` / `HITLS_PKI` / `HITLS_AUTH` | Enable or disable the corresponding component (ON/OFF). | `cmake .. -DHITLS_TLS=OFF` |
| `HITLS_CRYPTO_<ALGO>` | Enable or disable a specific algorithm feature. Refer to [Feature Description](./4_Configuration%20guide.md#1-Feature-Description). | `cmake .. -DHITLS_CRYPTO_SHA256=ON` |
| `HITLS_BUILD_STATIC` | Build static libraries (ON by default). | `cmake .. -DHITLS_BUILD_STATIC=ON` |
| `HITLS_BUILD_SHARED` | Build shared libraries (ON by default). | `cmake .. -DHITLS_BUILD_SHARED=ON` |
| `HITLS_BUNDLE_LIB` | Bundle all modules into a single library. | `cmake .. -DHITLS_BUNDLE_LIB=ON` |
| `HITLS_BUILD_EXE` | Build the executable command line tool. | `cmake .. -DHITLS_BUILD_EXE=ON` |
| `HITLS_ASM` | Auto-detect platform and enable assembly optimizations (x86_64 / ARMv8 / ARMv7). | `cmake .. -DHITLS_ASM=ON` |
| `HITLS_ASM_X8664` | Enable x86_64 assembly optimizations. | `cmake .. -DHITLS_ASM_X8664=ON` |
| `HITLS_ASM_ARMV8` | Enable ARMv8 assembly optimizations. | `cmake .. -DHITLS_ASM_ARMV8=ON` |
| `HITLS_ASM_ARMV7` | Enable ARMv7 assembly optimizations. | `cmake .. -DHITLS_ASM_ARMV7=ON` |
| `HITLS_ASM_X8664_AVX512` | Enable x86_64 AVX512 assembly optimizations. Enabling this automatically enables `HITLS_ASM_X8664` as the fallback optimization for features where AVX512 is not yet implemented. | `cmake .. -DHITLS_ASM_X8664_AVX512=ON` |
| `HITLS_COMPILE_OPTIONS` | Override compile options completely (semicolon-separated CMake list). | `cmake .. -DHITLS_COMPILE_OPTIONS="-O0;-g"` |
| `HITLS_SHARED_LINK_FLAGS` | Override shared library link flags completely (semicolon-separated CMake list). | `cmake .. -DHITLS_SHARED_LINK_FLAGS="-shared;-Wl,-z,now"` |
| `HITLS_EXE_LINK_FLAGS` | Override executable link flags completely (semicolon-separated CMake list). | `cmake .. -DHITLS_EXE_LINK_FLAGS="-pie;-Wl,-z,now"` |
| `HITLS_BUILD_GEN_INFO` | Generate build information files (macros.txt, sources.txt, include_dirs.txt). | `cmake .. -DHITLS_BUILD_GEN_INFO=ON` |
| `HITLS_PLATFORM_ENDIAN` | Manually specify the endianness (auto-detected by default). | `cmake .. -DHITLS_PLATFORM_ENDIAN=little` |
| `HITLS_PLATFORM_BITS` | Manually specify the platform bit width (auto-detected by default). | `cmake .. -DHITLS_PLATFORM_BITS=64` |
| `HITLS_PLATFORM_INT128` | Manually specify whether 128-bit integer is supported (enabled by default). | `cmake .. -DHITLS_PLATFORM_INT128=OFF` |

#### 3.1.1 Common Configuration Commands

```bash
# Default build (all features enabled, builds static and shared libraries)
cmake ..

# Full build using preset
cmake .. -DHITLS_BUILD_PROFILE=full

# Enable a specific algorithm feature (without preset)
cmake .. -DHITLS_CRYPTO_SHA256=ON

# Disable a specific algorithm feature
cmake .. -DHITLS_CRYPTO_SHA256=OFF

# Generate static libraries only
cmake .. -DHITLS_BUILD_SHARED=OFF

# Generate shared libraries only
cmake .. -DHITLS_BUILD_STATIC=OFF

# Bundle into a single library
cmake .. -DHITLS_BUNDLE_LIB=ON

# Build the command line tool
cmake .. -DHITLS_BUILD_EXE=ON

# Enable assembly optimizations (auto-detect platform)
cmake .. -DHITLS_ASM=ON

# Enable x86_64 assembly optimizations (full build)
cmake .. -DHITLS_BUILD_PROFILE=full -DHITLS_ASM_X8664=ON

# Override compile options
cmake .. -DHITLS_COMPILE_OPTIONS="-O0;-g"

# Override shared library link flags
cmake .. -DHITLS_SHARED_LINK_FLAGS="-shared;-Wl,-z,now"

# Override executable link flags
cmake .. -DHITLS_EXE_LINK_FLAGS="-pie;-Wl,-z,now"

# Append compile flags
cmake .. -DCMAKE_C_FLAGS="-O0 -g"

# Modify the build type (CMAKE will automatically add corresponding compile options, e.g., -g for Debug mode, -O3 for Release mode, etc.)
cmake .. -DCMAKE_BUILD_TYPE=Debug/Release/RelWithDebInfo/MinSizeRel

# Load a custom feature configuration file via CMake's -C parameter
# You can set any supported CMake variables in the custom file, for example:
#     set(HITLS_CRYPTO_SHA256    ON CACHE BOOL "" FORCE)
#     set(HITLS_BUILD_EXE        ON CACHE BOOL "" FORCE)
#     set(HITLS_COMPILE_OPTIONS  "-O0;-g" CACHE STRING "" FORCE)
#     set(HITLS_PRESET_LOADED    ON CACHE BOOL "" FORCE) # must be included to mark preset as loaded
cmake .. -C ../path/to/your_feature_config.cmake
```

#### 3.1.2 Cross Compilation

To cross compile openHiTLS, use the **-DCMAKE_TOOLCHAIN_FILE** parameter of CMake to specify a toolchain file. Pre-built toolchain files for common platforms are available under `cmake/toolchain/`:

```bash
cd openHiTLS
mkdir -p ./build
cd ./build
# Use the built-in ARMv8 toolchain (see cmake/toolchain/ for other options)
cmake .. -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchain/aarch64-linux-gnu-gcc.cmake
make -j
```

For a custom toolchain, use the files in `cmake/toolchain/` as templates and pass the path via `-DCMAKE_TOOLCHAIN_FILE`.

### 3.2 Installing the Build Result

To install the build result of openHiTLS, you only need to enter the following command:

```bash
make install
```

By default, header files are installed in **/usr/local/include**, and library files are installed in **/usr/local/lib**. If you need to customize the installation path, run the following command in the CMake configuration phase:

```bash
cmake -DCMAKE_INSTALL_PREFIX=<customized path> ..
```
