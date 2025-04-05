# Build and Installation Guide

## 1. Preparing the Build Environment

Check whether the build tools have been installed in the system and can be used properly.

| **Name**| **Recommended Version**| **Description**|
| -------- | ------------ | -------- |
| Gcc        | ≥ 7.3.0      | Linux    |
| Python   | ≥ 3.5         | Linux    |
| CMake    | ≥ 3.16        | Linux    |
| Sctp        | No restriction on versions   | Linux    |

P.S. The DTLS feature depends on sctp. By default, sctp is disabled. To enable it, you need to pre-install sctp dependencies.

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
   ├── config
   ├── configure.py
   ├── crypto
   ├── docs
   ├── include
   ├── LICENSE
   ├── platform
   ├── README-en.md
   ├── README.md
   ├── script
   ├── testcode
   ├── tls
   └── pki
   └── auth
```
Where:

- configure.py: provides the command line function for build configuration
- config and script: stores build-related scripts
- bsl: stores the code related to basic functions
- crypto: stores the code related to cryptographic algorithm capabilities.
- tls: stores the code related to secure transmission
- platform: stores other dependent codes
- testcode: stores the test project code
- pki: stores the PKI related code
- auth: stores the auth related code

**Call CMake to build the source code. The detailed method is as follows:**

### 3.1 CMake Build

openHiTLS provides the CMake build mode, which can be configured using **configure.py**. You are advised to create a **build** directory to store temporary files generated during the build process, and then go to the **build** directory and run "cmake .. &&make" to build openHiTLS. You can run the `python3 ./configure.py –help` command to query the configuration of **configure.py**. The related parameters are as follows.

| **Script Parameter**| **Parameter Description**| **Execution Mode**|
| ------------- | ------------ | ---------------- |
|--help           |Displays the help information about the script.|python3 configure.py --help|
|-m                |Generates a **moudules.cmake** file.|python3 configure.py -m|
|--build_dir    |Specifies the temporary directory for compilation.|python3 configure.py --build_dir build|
|--output_dir |Specifies the output path of the compilation target.|python3 configure.py --output_dir output|
|--feature_config|Specifies the compilation feature configuration file.|python3 configure.py --feature_config path/to/xxx.json|
|--compile_config|Specifies the compilation parameter configuration file.|python3 configure.py --compile_config path/to/xxx.json|
|--enable|Specifies build features.<br>Please refer to [Feature Description](./4_Configuration%20guide.md#1-Feature%20Description) to get supported features|python3 configure.py --enable hitls_crypto hitls_tls hitls_pse|
|--disable|disable buld features|python3 configure.py --disable sal_thread |
|--enable-sctp|enable sctp which is DTLS depended on|python3 configure.py --enable-sctp|
|--asm_type|Indicates the assembly type.|python3 configure.py --lib_type  static --asm_type armv8|
|--asm|Specifes build asm features, whicht needs to be used simultaneously with parameter `asm_type`.|python3 configure.py --lib_type  static --asm_type armv8 --asm sha2|
|--endian|Indicates big-endian or little-endian build.|python3 configure.py --endian little|
|--system|Specified the system type, currently only supports `linux`, used for 'sal_xxx' related features|python3 configure.py --system linux|
|--bits|To enable feature "bn", should specify the number of OS bits, `32\|64`|python3 configure.py --bits 64|
|--lib_type|Builds a static library, a dynamic library, or an object.|python3 configure.py --lib_type  static|
|--add_options|Adds compilation options.|python3 configure.py --add_options "-O0 -g3"|
|--del_options|Removes compilation options.|python3 configure.py --del_options"-O2"|
|--add_link_flags|Adds link options.|python3 configure.py --add_link_flags="-pie"|
|--del_link_flags|Removes link options.|python3 configure.py --del_options="-O2 -Werror"|

The **configure.py** script modifies the existing configuration based on the **compile.json** and **feature.json** configuration files at the top layer.

The overall CMake build procedure is as follows:

```bash
cd openHiTLS
mkdir -p ./build
cd ./build
python3 ../configure.py # Modify the configuration. For details, see section 3.1.1.
cmake ..
make -j
```

The build result is stored in the **openHiTLS/build** directory.

#### 3.1.1 Common Configuration Commands

```bash
# Disable a feature.
python3 ../configure.py --disable [feature]::[module]

# Enable a feature.
python3 ../configure.py --enable [feature]::[module]

# Enable sctp
python3 ../configure.py --enable-sctp

# Default configuration file. If the file does not exist, a file is generated. Otherwise, no action is performed.
python3 ../configure.py -m

# Add or delete compilation options.
# Note: If a compilation option already exists and you want to update it, you must run **--del_options** and **--add_options** in sequence. In this example, O0 needs to be changed to O2.
python3 ../configure.py --del_options="-O2 -D_FORTIFY_SOURCE=2" --add_options="-O0 -g"

# Add or delete link options.
python3 ../configure.py --add_link_flags="-lxxx" --del_link_flags="-lxxx"

# Generate static libraries only.
python3 ../configure.py --lib_type static

# Generate dynamic libraries only.
python3 ../configure.py --lib_type shared

# Generate object files only.
python3 ../configure.py --lib_type object

# Generate dynamic libraries, static libraries, and object files.
python3 ../configure.py --lib_type shared static object
```

#### 3.1.2 Cross Compilation

To cross compile openHiTLS, you need to use the **-DCMAKE_TOOLCHAIN_FILE** parameter of CMake to transfer the cross compilation configuration, as follows:

```bash
cd openHiTLS
mkdir -p ./build
cd ./build
python3 ../configure.py --bits=64 --system=linux # Modify the configuration. For details, see section 3.1.1.
cmake -DCMAKE_TOOLCHAIN_FILE=usr_gcc.toolchain.cmake .. # xxx.toolchain.cmake needs to be written by the user.
make -j
```

### 3.2 Installing the Build Result

To install the build result of openHiTLS, you only need to enter the following command:

```bash
make install
```

By default, header files are installed in **/usr/local/include**, and library files are installed in **/usr/local/lib**. If you need to customize the installation path, run the following command in the CMake configuration phase:

```bash
cmake -DCMAKE_INSTALL_PREFIX=<customized path> ..
```
