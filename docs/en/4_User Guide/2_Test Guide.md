The test project depends on the source code compilation. Prepare the environment on which the compilation depends by referring to *Build and Installation Guide* to ensure that the source code can be correctly compiled.

## 1. Test Environment Preparation

| **Name**| **Recommended Version**| **Description**                                           |
| -------- | ------------ | --------------------------------------------------- |
| Gcc      | ≥ 7.3.0       | Linux                                               |
| Python   | ≥ 3.5         | Linux                                               |
| CMake    | ≥ 3.16        | Linux                                               |
| Sctp    | No restriction on versions        | Linux                                               |

## 2. Test Code Directory Structure

```
./testcode/
├── CMakeLists.txt
├── common
│   ├── execute_base.c
│   └── execute_test.c
├── demo
├── framework
│   ├── crypto
│   ├── gen_test
│   ├── include
│   ├── process
│   ├── stub
│   └── tls
├── output
├── script
│   ├── all_mini_test.sh
│   ├── build_hitls.sh
│   ├── build_sdv.sh
│   ├── execute_sdv.sh
│   └── mini_build_test.sh
├── sdv
│   ├── CMakeLists.txt
│   ├── log
│   ├── report
│   └── testcase
└── testdata
    ├── cert
    └── tls
```
Where:

- common: common test framework code
- demo: openHiTLS function test demo
- framework: framework code of the openHiTLS test case
- output: output directory of case test results and process files
- script: directory of test script code
- sdv: code of the openHiTLS test case for function scenarios
- testdata: directory of test data

## 3. Function Test Execution Guide

### 3.1 Test Framework Description

A test framework developed by the community provides public configurations and methods for community developers to compile and execute the test code. A test unit consists of a function file (.c) and a data file (.data), which store test functions and test data, respectively.

![image](../images/User%20Guide/Test%20Guide_figures/TestFrameworkDescription.png)

### 3.2 Script Parameter Description

| **Command**                   | **Description**                                                    |
| --------------------------- | ------------------------------------------------------------ |
| bash build_hitls.sh                 | Compiles all source codes.                                                |
| bash build_sdv.sh        | Compiles all test codes.                  |
| bash execute_sdv.sh | Executes test cases.|

- Parameters of the **build_hitls.sh** script

| **Script Parameter**|**Execution Mode**  |    **Parameter Description**                                       |
| -------- | ------------ | --------------------------------------------------- |
| gcov     |  bash build_hitls.sh gcov |Enables the capability of obtaining the coverage rate.        |
| debug | bash build_hitls.sh debug          |Enables the debug capability.                |
| asan    | bash build_hitls.sh asan         |Enables the memory monitoring capability.        |

- Parameters of the **build_sdv.sh** script

| **Script Parameter**|  **Execution Mode** |  **Parameter Description**                                        |
| -------- | ------------ | --------------------------------------------------- |
| --help or -h    |  bash build_sdv.sh --help |Obtains help information.       |
| no-crypto    | bash build_sdv.sh no-crypto         |Deletes the test cases of the crypto module.       |
| no-bsl    | bash build_sdv.sh no-bsl         | Deletes the test cases of the bsl module.       |
| no-tls    | bash build_sdv.sh no-tls         | Deletes the test cases of the tls module.       |
| no-pki    | bash build_sdv.sh no-pki         | Deletes the test cases of the pki module.       |
| no-auth    | bash build_sdv.sh no-auth         | Deletes the test cases of the auth module.       |
| verbose    |bash build_sdv.sh verbose          |Displays the detailed information about the build process.        |
| gcov     |  bash build_sdv.sh gcov  | Enables the capability of obtaining the coverage rate.      |
| asan    | bash build_sdv.sh asan         | Enables the memory monitoring capability.      |
| big-endian    |bash build_sdv.sh big-endian          | Implements compilation in the big-endian environment.       |
| run-tests    | bash build_sdv.sh run-tests=xxx1xxx2xxx3 |   Compiles a specified test suite.       |

- Parameters of the **execute_sdv.sh** script

| **Script Parameter**|  **Execution Mode**| **Parameter Description**                                           |
| -------- | ------------ | --------------------------------------------------- |
| \<file name\>    |  bash execute_sdv.sh test_suites_xxx ...  | Executes all test cases in a specified file.|
| \<test name\> | bash execute_sdv.sh UT_CRYPTO_xxx SDV_CRYPTO_xxx ...      |Executes a test case with a specified name. |

Remarks: Parameters can be transferred to the script in combination mode. For example:

- Build the source code in default mode: bash build_hitls.sh
- Enable ASan, debug, and coverage during source code build: bash build_hitls.sh asan gcov debug
- Enable ASan and coverage during test code build, and display build details: bash build_sdv.sh asan gcov verbose
- Build the source code in default mode: bash build_hitls.sh
- Execute all test cases in default mode: bash execute_sdv.sh
- Execute a specified test set: bash execute_sdv.sh test_suites_xxx1 test_suites_xxx2

### 3.3 Test Case Execution Process

The test project depends on the following scripts:

- **build_hitls.sh**: script for building the source code in one-click mode
- **build_sdv.sh**: script for building test cases in one-click mode
- **execute_sdv.sh**: script for executing test cases in one-click mode
  ![image](../images/User%20Guide/Test%20Guide_figures/TestCaseExecutionProcess.png)

### 3.4 Viewing Test Case Results

After the test is complete, you can go to the **output/log** directory to view the test case execution results. If a problem is found in the community repository, check whether there is a trouble ticket in the repository issue. If there is no trouble ticket, submit a trouble ticket to track the problem.

## 4. CI Pipeline Test Commands

When a CI pipeline fails, you can run the corresponding commands locally to reproduce and resolve the issue.

#### build/STM32F4

Linux x86_64, cross-compile for armv7
```bash
if [ "${codeBranch}" = "main" ];then
    mkdir build && cd build
    cmake .. -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchain/arm-none-eabi-gcc.cmake  -C ../testcode/config/cmake/STM32F4/STM32F4_feature_config.cmake
    make -j VERBOSE=1
fi
```

#### build/amd64

Linux x86_64
```bash
cd testcode/script
bash build_hitls.sh gcov
bash build_sdv.sh gcov fail-repeat
bash execute_sdv.sh
```

#### build/app

Linux x86_64
```bash
[ "${codeBranch}" != "main" ] && exit
cd testcode/script
bash build_hitls.sh exe
bash build_sdv.sh apps
script -q -e -c "bash execute_sdv.sh" /dev/null
```

#### build/arm64

Linux aarch64
```bash
cd testcode/script
bash build_hitls.sh gcov armv8_le
bash build_sdv.sh gcov fail-repeat
bash execute_sdv.sh
```

#### build/asan

Linux x86_64 (SCTP required)
```bash
sudo modprobe sctp
sudo sysctl -w net.sctp.auth_enable=1
cd testcode/script
sudo bash -x build_hitls.sh asan gcov
sudo bash -x build_sdv.sh asan gcov fail-repeat
sudo bash -x execute_sdv.sh
```

#### build/iso_arm

Linux aarch64
```bash
[ "${codeBranch}" != "main" ] && exit
cd testcode/script
bash build_hitls.sh iso armv8_le
bash build_hitls.sh add-options=-DHITLS_CRYPTO_CMVP
bash build_sdv.sh add-options=-DHITLS_CRYPTO_CMVP_ISO19790_ARMV8_LE
bash execute_sdv.sh test_suite_sdv_eal_iso19790_provider
```

#### build/iso_pure_c

Linux x86_64
```bash
[ "${codeBranch}" != "main" ] && exit
cd testcode/script
bash build_hitls.sh iso pure_c
bash build_hitls.sh add-options=-DHITLS_CRYPTO_CMVP
bash build_sdv.sh add-options=-DHITLS_CRYPTO_CMVP_ISO19790_PURE_C
bash execute_sdv.sh test_suite_sdv_eal_iso19790_provider
```

#### build/iso_x86

Linux x86_64
```bash
[ "${codeBranch}" != "main" ] && exit
cd testcode/script
bash build_hitls.sh iso x86_64
bash build_hitls.sh add-options=-DHITLS_CRYPTO_CMVP
bash build_sdv.sh add-options=-DHITLS_CRYPTO_CMVP_ISO19790_X86_64
bash execute_sdv.sh test_suite_sdv_eal_iso19790_provider
```

#### build/mini_x8664

Linux x86_64
```bash
cd testcode/script
bash all_mini_test.sh all x8664
```

#### build/no-provider

Linux x86_64
```bash
cd testcode/script
bash build_hitls.sh add-options=-fshort-enums add-options=-Wno-cast-function-type add-options=-Wno-type-limits no-provider gcov
bash build_sdv.sh add-options=-fshort-enums add-options=-Wno-cast-function-type add-options=-Wno-type-limits gcov
bash execute_sdv.sh
```

#### build/sdv_arm-app

Linux aarch64
```bash
[ "${codeBranch}" != "main" ] && exit
cd testcode/script
bash build_hitls.sh sm armv8_le
bash build_hitls.sh exe add-options=-DHITLS_APP_SM_MODE
bash build_sdv.sh apps add-options="-DHITLS_APP_SM_MODE -DHITLS_CRYPTO_CMVP_SM_ARMV8_LE"
script -q -e -c "bash execute_sdv.sh" /dev/null
```

#### build/sdv_macos

macOS aarch64
```bash
mkdir build && cd build
if [ -f "../configure.py" ]; then
    python3 ../configure.py
fi
cmake ..
make -j VERBOSE=1

cd testcode/script
if [ "${codeBranch}" = "main" ];then
    ./build_hitls.sh armv8_le
else
    ./build_hitls.sh
fi
./build_sdv.sh
./execute_sdv.sh
```

#### build/sm_arm

Linux aarch64
```bash
[ "${codeBranch}" != "main" ] && exit
cd testcode/script
bash build_hitls.sh sm armv8_le
bash build_hitls.sh add-options=-DHITLS_CRYPTO_CMVP
bash build_sdv.sh add-options=-DHITLS_CRYPTO_CMVP_SM_ARMV8_LE
bash execute_sdv.sh test_suite_sdv_eal_sm_provider
```

#### build/tls_sdv_arm

Linux aarch64
```bash
cd testcode/script
bash all_mini_test.sh tls armv8
```

