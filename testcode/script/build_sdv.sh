#!/bin/bash

# This file is part of the openHiTLS project.
#
# openHiTLS is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#
#     http://license.coscl.org.cn/MulanPSL2
#
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
set -e

usage()
{
    printf "\n"
    printf "%-05s %-30s\n" "* Script :"                                        "${BASH_SOURCE[0]}"
    printf "%-50s %-30s\n" "* Usage Option :"                                  ""
    printf "%-50s %-30s\n" "* --help|-h    : Help information."                ""
    printf "%-50s %-30s\n" "* add-options  : Add options."                    "bash ${BASH_SOURCE[0]} add-options=xxx"
    printf "%-50s %-30s\n" "* no-provider  : Disable provider."                "bash ${BASH_SOURCE[0]} no-provider"
    printf "%-50s %-30s\n" "* tls-debug    : Enable the debug mode."           "bash ${BASH_SOURCE[0]} tls-debug"
    printf "%-50s %-30s\n" "* no-crypto    : Custom crypto testcase."          "bash ${BASH_SOURCE[0]} no-crypto"
    printf "%-50s %-30s\n" "* no-bsl       : Custom bsl testcase."             "bash ${BASH_SOURCE[0]} no-bsl"
    printf "%-50s %-30s\n" "* no-tls       : Custom tls testcase."             "bash ${BASH_SOURCE[0]} no-tls"
    printf "%-50s %-30s\n" "* no-pki       : Custom pki testcase."             "bash ${BASH_SOURCE[0]} no-pki"
    printf "%-50s %-30s\n" "* no-auth      : Custom auth testcase."            "bash ${BASH_SOURCE[0]} no-auth"
    printf "%-50s %-30s\n" "* no-demos     : Not build demos."                 "bash ${BASH_SOURCE[0]} no-auth"
    printf "%-50s %-30s\n" "* verbose      : Show detailse."                   "bash ${BASH_SOURCE[0]} verbose"
    printf "%-50s %-30s\n" "* gcov         : Enable the coverage capability."  "bash ${BASH_SOURCE[0]} gcov"
    printf "%-50s %-30s\n" "* asan         : Enabling the ASAN capability."    "bash ${BASH_SOURCE[0]} asan"
    printf "%-50s %-30s\n" "* big-endian   : Specify the platform endianness." "bash ${BASH_SOURCE[0]} big-endian"
    printf "%-50s %-30s\n" "* include-path : Specify the config file path."    "bash ${BASH_SOURCE[0]} include-path=-Ixxx"
    printf "%-50s %-30s\n\n" "* run-tests  : Creating a custom test suite."    "bash ${BASH_SOURCE[0]} run-tests=xxx1|xxx2|xxx3"
    printf "%-50s %-30s\n" "* apps         : Create apps testcase."            "bash ${BASH_SOURCE[0]} apps"
}

export_env()
{
    # Force recalculate HITLS_ROOT_DIR to avoid CI environment variable pollution
    # Unset any pre-existing value to ensure clean path resolution
    unset HITLS_ROOT_DIR
    HITLS_ROOT_DIR=$(cd $(dirname ${BASH_SOURCE[0]})/../.. && pwd)
    LOCAL_ARCH=${LOCAL_ARCH:=`arch`}
    ENABLE_GCOV=${ENABLE_GCOV:=OFF}
    ENABLE_ASAN=${ENABLE_ASAN:=OFF}
    ENABLE_PRINT=${ENABLE_PRINT:=ON}
    ENABLE_FAIL_REPEAT=${ENABLE_FAIL_REPEAT:=OFF}
    CUSTOM_CFLAGS=${CUSTOM_CFLAGS:=''}
    ENABLE_APP=${ENABLE_APP:=OFF}
    ENABLE_TLS=${ENABLE_TLS:=ON}
    BIG_ENDIAN=${BIG_ENDIAN:=OFF}
    ENABLE_CRYPTO=${ENABLE_CRYPTO:=ON}
    ENABLE_BSL=${ENABLE_BSL:=ON}
    ENABLE_PKI=${ENABLE_PKI:=ON}
    ENABLE_AUTH=${ENABLE_AUTH:=ON}
    ENABLE_CMVP=${ENABLE_CMVP:=OFF}
    ENABLE_DEMOS=${ENABLE_DEMOS:=ON}
    ENABLE_UIO_SCTP=${ENABLE_UIO_SCTP:=ON}
    ENABLE_VERBOSE=${ENABLE_VERBOSE:=''}
    RUN_TESTS=${RUN_TESTS:=''}
    DEBUG=${DEBUG:=ON}

    if [ -f ${HITLS_ROOT_DIR}/build/macro.txt ];then
        CUSTOM_CFLAGS=$(cat ${HITLS_ROOT_DIR}/build/macro.txt)
        CUSTOM_CFLAGS="$CUSTOM_CFLAGS -D__FILENAME__=__FILE__"
        # Add PKI macro if PKI library exists (needed for test framework linking)
        if ls ${HITLS_ROOT_DIR}/build/libhitls_pki.* 1> /dev/null 2>&1; then
            CUSTOM_CFLAGS="$CUSTOM_CFLAGS -DHITLS_PKI"
        fi
        # Add UDP/TCP/SCTP only if main library has them (check macro.txt)
        # This ensures test framework matches the main library's UIO capabilities
        if grep -q "HITLS_BSL_UIO_UDP" ${HITLS_ROOT_DIR}/build/macro.txt 2>/dev/null; then
            CUSTOM_CFLAGS="$CUSTOM_CFLAGS -DHITLS_BSL_UIO_UDP"
        fi
        if grep -q "HITLS_BSL_UIO_TCP" ${HITLS_ROOT_DIR}/build/macro.txt 2>/dev/null; then
            CUSTOM_CFLAGS="$CUSTOM_CFLAGS -DHITLS_BSL_UIO_TCP"
        fi
        if grep -q "HITLS_BSL_UIO_SCTP" ${HITLS_ROOT_DIR}/build/macro.txt 2>/dev/null; then
            CUSTOM_CFLAGS="$CUSTOM_CFLAGS -DHITLS_BSL_UIO_SCTP"
        fi
    fi

    # Add macOS-specific flags for AppleClang (must come AFTER macro.txt)
    if [[ "$(uname)" == "Darwin" ]]; then
        CUSTOM_CFLAGS="$CUSTOM_CFLAGS -Wno-unused-command-line-argument -Wno-error=unused-command-line-argument"
        CUSTOM_CFLAGS="$CUSTOM_CFLAGS -Wno-sometimes-uninitialized -Wno-error=sometimes-uninitialized"
        CUSTOM_CFLAGS="$CUSTOM_CFLAGS -Wno-gnu-folding-constant -Wno-error=gnu-folding-constant"
        CUSTOM_CFLAGS="$CUSTOM_CFLAGS -Wno-non-literal-null-conversion -Wno-error=non-literal-null-conversion"
        CUSTOM_CFLAGS="$CUSTOM_CFLAGS -Wno-sizeof-array-div -Wno-error=sizeof-array-div"
        CUSTOM_CFLAGS="$CUSTOM_CFLAGS -Wno-format -Wno-error=format"
        CUSTOM_CFLAGS="$CUSTOM_CFLAGS -Wno-enum-conversion -Wno-error=enum-conversion"
        CUSTOM_CFLAGS="$CUSTOM_CFLAGS -Wno-int-conversion -Wno-error=int-conversion"
        CUSTOM_CFLAGS="$CUSTOM_CFLAGS -Wno-unused-function -Wno-error=unused-function"
    fi
    if [[ ! -e "${HITLS_ROOT_DIR}/testcode/output/log" ]]; then
        mkdir -p ${HITLS_ROOT_DIR}/testcode/output/log
    fi
}

down_depend_code()
{
    if [ ! -d "${HITLS_ROOT_DIR}/platform/Secure_C/lib" ]; then
        cd ${HITLS_ROOT_DIR}/platform/Secure_C
        make -j
    fi
}

find_test_suite()
{
    if [[ ${ENABLE_CRYPTO} == "ON" ]]; then
        crypto_testsuite=$(find ${HITLS_ROOT_DIR}/testcode/sdv/testcase/crypto -name "*.data" | sed -e "s/.data//" | tr -s "\n" " ")
        crypto_testsuite=${crypto_testsuite}$(find ${HITLS_ROOT_DIR}/testcode/sdv/testcase/codecs -name "*.data" | sed -e "s/.data//" | tr -s "\n" " ")
    fi
    if [[ ${ENABLE_BSL} == "ON" ]]; then
        bsl_testsuite=$(find ${HITLS_ROOT_DIR}/testcode/sdv/testcase/bsl -name "*.data" | sed -e "s/.data//" | tr -s "\n" " ")
    fi
    if [[ ${ENABLE_PKI} == "ON" ]]; then
        pki_testsuite=$(find ${HITLS_ROOT_DIR}/testcode/sdv/testcase/pki -name "*.data" | sed -e "s/.data//" | tr -s "\n" " ")
    fi
    if [[ ${ENABLE_TLS} == "ON" ]]; then
        proto_testsuite=$(find ${HITLS_ROOT_DIR}/testcode/sdv/testcase/tls  -name "*.data" | sed -e "s/.data//" | tr -s "\n" " ")
    fi
    if [[ ${ENABLE_AUTH} == "ON" ]]; then
        auth_testsuite=$(find ${HITLS_ROOT_DIR}/testcode/sdv/testcase/auth -name "*.data" | sed -e "s/.data//" | tr -s "\n" " ")
    fi
    if [[ ${ENABLE_CMVP} == "ON" ]]; then
        cmvp_testsuite=$(find ${HITLS_ROOT_DIR}/testcode/sdv/testcase/cmvp -name "*.data" | sed -e "s/.data//" | tr -s "\n" " ")
    fi
    RUN_TEST_SUITES="${crypto_testsuite}${bsl_testsuite}${pki_testsuite}${proto_testsuite}${auth_testsuite}${cmvp_testsuite}"
    if [[ ${ENABLE_APP} == "ON" ]]; then
        apps_testsuite=$(find ${HITLS_ROOT_DIR}/testcode/sdv/testcase/apps -name "*.data" | sed -e "s/.data//" | tr -s "\n" " ")
        RUN_TEST_SUITES="${apps_testsuite}"
    fi
}

build_test_suite()
{
    build_provider_so

    [[ -n ${CASES} ]] && RUN_TEST_SUITES=${CASES}
    cd ${HITLS_ROOT_DIR}/testcode && rm -rf ./build && mkdir build && cd build

    # macOS-specific flags for STUB test mechanism compatibility
    # On macOS, use flat namespace to allow test STUB wrappers to intercept library internal calls
    # This matches Linux symbol resolution behavior and is ONLY needed for test builds
    # Production builds (via top-level CMakeLists.txt) use the default two-level namespace
    if [[ "$(uname)" = "Darwin" ]]; then
        cmake -DENABLE_GCOV=${ENABLE_GCOV} -DENABLE_ASAN=${ENABLE_ASAN} \
              -DCUSTOM_CFLAGS="${CUSTOM_CFLAGS}" -DDEBUG=${DEBUG} -DENABLE_UIO_SCTP=${ENABLE_UIO_SCTP} \
              -DGEN_TEST_FILES="${RUN_TEST_SUITES}" -DENABLE_TLS=${ENABLE_TLS} \
              -DENABLE_CRYPTO=${ENABLE_CRYPTO} -DENABLE_PKI=${ENABLE_PKI} -DENABLE_AUTH=${ENABLE_AUTH} \
              -DTLS_DEBUG=${TLS_DEBUG} -DOS_BIG_ENDIAN=${BIG_ENDIAN} -DPRINT_TO_TERMINAL=${ENABLE_PRINT} \
              -DENABLE_FAIL_REPEAT=${ENABLE_FAIL_REPEAT} -DAPPS=${ENABLE_APP} \
              -DCMAKE_SHARED_LINKER_FLAGS="-flat_namespace -undefined dynamic_lookup" \
              -DCMAKE_EXE_LINKER_FLAGS="-flat_namespace -undefined dynamic_lookup" ..
    else
        cmake -DENABLE_GCOV=${ENABLE_GCOV} -DENABLE_ASAN=${ENABLE_ASAN} \
              -DCUSTOM_CFLAGS="${CUSTOM_CFLAGS}" -DDEBUG=${DEBUG} -DENABLE_UIO_SCTP=${ENABLE_UIO_SCTP} \
              -DGEN_TEST_FILES="${RUN_TEST_SUITES}" -DENABLE_TLS=${ENABLE_TLS} \
              -DENABLE_CRYPTO=${ENABLE_CRYPTO} -DENABLE_PKI=${ENABLE_PKI} -DENABLE_AUTH=${ENABLE_AUTH} \
              -DTLS_DEBUG=${TLS_DEBUG} -DOS_BIG_ENDIAN=${BIG_ENDIAN} -DPRINT_TO_TERMINAL=${ENABLE_PRINT} \
              -DENABLE_FAIL_REPEAT=${ENABLE_FAIL_REPEAT} -DAPPS=${ENABLE_APP} ..
    fi
    make -j
}

# Function: Compile provider .so file
build_provider_so()
{
    # Only build if provider support is enabled
    if [ -f ${HITLS_ROOT_DIR}/build/macro.txt ]; then
        if ! grep -q "HITLS_CRYPTO_PROVIDER" ${HITLS_ROOT_DIR}/build/macro.txt 2>/dev/null; then
            echo "[INFO] Provider support not enabled, skipping provider library build"
            return 0
        fi
    else
        echo "[WARNING] macro.txt not found, skipping provider library build"
        return 0
    fi

    echo "======================================================================"
    echo "Building provider test libraries..."
    echo "======================================================================"

    local provider_dir="${HITLS_ROOT_DIR}/testcode/testdata/provider"
    if [ ! -d "$provider_dir" ]; then
        echo "[ERROR] Provider directory not found: $provider_dir"
        return 1
    fi

    cd "$provider_dir"
    if [ $? -ne 0 ]; then
        echo "[ERROR] Failed to change directory to provider path: $provider_dir"
        return 1
    fi
    rm -rf build
    mkdir build
    cd build

    echo "[INFO] Running cmake for provider libraries..."
    if ! cmake -DENABLE_GCOV=${ENABLE_GCOV} ..; then
        echo "[ERROR] CMake configuration failed for provider libraries"
        return 1
    fi

    echo "[INFO] Building provider libraries..."
    if ! make -j; then
        echo "[ERROR] Provider library build failed"
        return 1
    fi

    echo "[SUCCESS] Provider libraries built successfully"
    echo "[INFO] Provider library location:"
    if [ -d "${HITLS_ROOT_DIR}/testcode/output/provider_test_data" ]; then
        ls -lh "${HITLS_ROOT_DIR}/testcode/output/provider_test_data/path1/" 2>/dev/null | head -5 || true
        echo "..."
        ls -lh "${HITLS_ROOT_DIR}/testcode/output/provider_test_data/path2/" 2>/dev/null | head -5 || true
        local path1_count=$(ls "${HITLS_ROOT_DIR}/testcode/output/provider_test_data/path1/" 2>/dev/null | wc -l)
        local path2_count=$(ls "${HITLS_ROOT_DIR}/testcode/output/provider_test_data/path2/" 2>/dev/null | wc -l)
        echo "[INFO] Built $path1_count provider libraries in path1/ and $path2_count in path2/"
    else
        echo "[ERROR] Provider output directory not found!"
        return 1
    fi

    return 0
}

process_custom_cases()
{
    if [[ -n "${RUN_TESTS}" ]];then
        local tmp=($(echo "${RUN_TESTS}" | tr -s "|" " "))
        for i in ${!tmp[@]}
        do
            local suite=$(find ${HITLS_ROOT_DIR}/testcode/sdv -name "${tmp[i]}.data" | sed -e "s/.data//")
            [[ -z "${suite}" ]] && echo "not found testsuite:${tmp[i]}"
            [[ -n "${suite}" ]] && CASES="${suite} ${CASES}"
        done
    fi
}

build_demos()
{
    if [[ ${ENABLE_DEMOS} == "OFF" ]]; then
        return
    fi
    pushd ${HITLS_ROOT_DIR}/testcode/demo/
    rm -rf build && mkdir build 
    pushd build
    cmake -DENABLE_GCOV=${ENABLE_GCOV} -DCUSTOM_CFLAGS="${CUSTOM_CFLAGS}" -DENABLE_ASAN=${ENABLE_ASAN} ../
    make -j
    popd
    popd
}

clean()
{
    rm -rf ${HITLS_ROOT_DIR}/testcode/output/log
    rm -rf ${HITLS_ROOT_DIR}/testcode/output/test_suite*
    rm -rf ${HITLS_ROOT_DIR}/testcode/output/asan.*
    rm -rf ${HITLS_ROOT_DIR}/testcode/output/*.log
    rm -rf ${HITLS_ROOT_DIR}/testcode/output/*.xml
    rm -rf ${HITLS_ROOT_DIR}/testcode/output/gen_testcase
    rm -rf ${HITLS_ROOT_DIR}/testcode/output/process
    rm -rf ${HITLS_ROOT_DIR}/testcode/framework/tls/build
    rm -rf ${HITLS_ROOT_DIR}/testcode/build
    rm -rf ${HITLS_ROOT_DIR}/testcode/sdv/build
    rm -rf ${HITLS_ROOT_DIR}/testcode/framework/process/build
    rm -rf ${HITLS_ROOT_DIR}/testcode/framework/gen_test/build
    rm -rf ${HITLS_ROOT_DIR}/testcode/testdata/provider/build
    rm -rf ${HITLS_ROOT_DIR}/testcode/testdata/provider/path1
    rm -rf ${HITLS_ROOT_DIR}/testcode/testdata/provider/path2
    mkdir -p ${HITLS_ROOT_DIR}/testcode/output/log
}

options()
{
    while [[ -n $1 ]]
    do
        key=${1%%=*}
        value=${1#*=}
        case ${key} in
            add-options)
                CUSTOM_CFLAGS="${CUSTOM_CFLAGS} ${value}"
                ;;
            no-provider)
                dis_options="--disable feature_provider provider codecs"
                ;;
            tls-debug)
                TLS_DEBUG=ON
                ;;
            gcov)
                ENABLE_GCOV=ON
                ;;
            asan)
                ENABLE_ASAN=ON
                ;;
            no-print)
                ENABLE_PRINT=OFF
                ;;
            no-crypto)
                ENABLE_CRYPTO=OFF
                ;;
            no-pki)
                ENABLE_PKI=OFF
                ;;
            no-auth)
                ENABLE_AUTH=OFF
                ;;
            no-bsl)
                ENABLE_BSL=OFF
                ;;
            no-tls)
                ENABLE_TLS=OFF
                ;;
            no-demos)
                ENABLE_DEMOS=OFF
                ;;
            no-sctp)
                ENABLE_UIO_SCTP=OFF
                ;;
            no-demos)
                ENABLE_DEMOS=OFF
                ;;
            verbose)
                ENABLE_VERBOSE='VERBOSE=1'
                ;;
            fail-repeat)
                ENABLE_FAIL_REPEAT=ON
                ;;
            run-tests)
                RUN_TESTS=${value}
                ;;
            big-endian)
                BIG_ENDIAN=ON
                ;;
            include-path)
                CUSTOM_CFLAGS="${CUSTOM_CFLAGS} ${value}"
                ;;
            apps)
                ENABLE_APP=ON
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                usage
                exit 1
                ;;
        esac
        shift
    done
}

export_env
options "$@"
clean
down_depend_code
find_test_suite
process_custom_cases
build_test_suite
if [[ ${ENABLE_DEMOS} == "ON" ]]; then
    build_demos
fi
