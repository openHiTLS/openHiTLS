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
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
HITLS_ROOT_DIR=$(cd "${SCRIPT_DIR}/../.." && pwd)

hitls_compile_option=()

paramList=$@
paramNum=$#
feature_options="-DHITLS_BUILD_GEN_INFO=ON"
add_options=""
del_options=""
add_link_flags=""

get_arch=`arch`
executes="OFF"

LIB_TYPE="static shared"
enable_sctp="--enable-sctp"
BITS=64

subdir="CMVP"
libname=""
build_crypto_module_provider=false

# Detect platform and set shared library extension
# Reference: https://en.wikipedia.org/wiki/Dynamic_linker
case "$(uname)" in
    Linux)
        # Linux uses ELF format with .so extension
        SHARED_LIB_EXT=".so"
        ;;
    Darwin)
        # macOS uses Mach-O format with .dylib extension
        SHARED_LIB_EXT=".dylib"
        ;;
    FreeBSD|OpenBSD|NetBSD)
        # BSD systems use ELF format with .so extension
        SHARED_LIB_EXT=".so"
        ;;
    *)
        echo "Warning: Unknown platform '$(uname)', assuming .so extension"
        SHARED_LIB_EXT=".so"
        ;;
esac

usage()
{
    printf "%-50s %-30s\n" "Build openHiTLS Code"                      "sh build_hitls.sh"
    printf "%-50s %-30s\n" "Build openHiTLS Code With Gcov"            "sh build_hitls.sh gcov"
    printf "%-50s %-30s\n" "Build openHiTLS Code With Debug"           "sh build_hitls.sh debug"
    printf "%-50s %-30s\n" "Build openHiTLS Code With Asan"            "sh build_hitls.sh asan"
    printf "%-50s %-30s\n" "Build openHiTLS Code With Pure C"           "sh build_hitls.sh pure_c"
    printf "%-50s %-30s\n" "Build openHiTLS Code With X86_64"            "sh build_hitls.sh x86_64"
    printf "%-50s %-30s\n" "Build openHiTLS Code With Armv8_be"          "sh build_hitls.sh armv8_be"
    printf "%-50s %-30s\n" "Build openHiTLS Code With Armv8_le"          "sh build_hitls.sh armv8_le"
    printf "%-50s %-30s\n" "Build openHiTLS Code With Add Options"     "sh build_hitls.sh add-options=xxx"
    printf "%-50s %-30s\n" "Build openHiTLS Code With No Provider"     "sh build_hitls.sh no-provider"
    printf "%-50s %-30s\n" "Build openHiTLS Code With No Sctp"         "sh build_hitls.sh no_sctp"
    printf "%-50s %-30s\n" "Build openHiTLS Code With Bits"            "sh build_hitls.sh bits=xxx"
    printf "%-50s %-30s\n" "Build openHiTLS Code With Lib Type"        "sh build_hitls.sh shared"
    printf "%-50s %-30s\n" "Build openHiTLS Code With Lib Fuzzer"      "sh build_hitls.sh libfuzzer"
    printf "%-50s %-30s\n" "Build openHiTLS Code With command line"    "sh build_hitls.sh exe"
    printf "%-50s %-30s\n" "Build openHiTLS Code With Iso Provider"     "sh build_hitls.sh iso"
    printf "%-50s %-30s\n" "Build openHiTLS Code With Help"            "sh build_hitls.sh help"
}

# ============================================================
# Clean Build Directory
# ============================================================
# Function: clean
# Purpose: Remove and recreate build directory for fresh build
# ============================================================
clean()
{
    rm -rf ${HITLS_ROOT_DIR}/build
    mkdir ${HITLS_ROOT_DIR}/build
}

build_hitls_code()
{
    # Compile openHiTLS
    cd ${HITLS_ROOT_DIR}/build
    feature_options="${feature_options} -DHITLS_BUILD_PROFILE=full"
    feature_options="${feature_options} -DHITLS_CRYPTO_RAND_CB=ON" # HITLS_CRYPTO_RAND_CB: add rand callback
    feature_options="${feature_options} -DHITLS_EAL_INIT_OPTS=9 -DHITLS_CRYPTO_ASM_CHECK=ON" # Get CPU capability
    feature_options="${feature_options} -DHITLS_CRYPTO_ENTROPY=ON -DHITLS_CRYPTO_ENTROPY_DEVRANDOM=ON -DHITLS_CRYPTO_ENTROPY_GETENTROPY=ON -DHITLS_CRYPTO_ENTROPY_SYS=ON -DHITLS_CRYPTO_ENTROPY_HARDWARE=ON" # add default entropy
    feature_options="${feature_options} -DHITLS_CRYPTO_DRBG_GM=ON" # enable GM DRBG
    feature_options="${feature_options} -DHITLS_CRYPTO_ACVP_TESTS=ON" # enable ACVP tests
    feature_options="${feature_options} -DHITLS_CRYPTO_DSA_GEN_PARA=ON" # enable DSA genPara tests
    feature_options="${feature_options} -DHITLS_TLS_FEATURE_SM_TLS13=ON" # enable rfc8998 tests

    if [[ $executes = "ON" ]]; then
        feature_options="${feature_options} -DHITLS_BUILD_EXE=ON -DHITLS_CRYPTO_CMVP=ON"
    fi

    # On Linux, we need -ldl for dlopen() and related functions
    # On macOS, libdl functionality is part of libSystem, so -ldl is not needed (and causes duplicate warnings)
    # On macOS, also need -fno-inline to prevent inlining (required for STUB interception to work)
    if [[ "$(uname)" != "Darwin" ]]; then
        add_link_flags="${add_link_flags} -ldl"

    else
        add_options="${add_options} -fno-inline"
    fi

    if [[ $enable_sctp = "--enable-sctp" ]]; then
        feature_options="${feature_options} -DHITLS_BSL_UIO_SCTP=ON"
    else
        feature_options="${feature_options} -DHITLS_BSL_UIO_SCTP=OFF"
    fi
    
    [[ "$LIB_TYPE" == *"static"* ]] && feature_options="${feature_options} -DHITLS_BUILD_STATIC=ON"
    [[ "$LIB_TYPE" == *"shared"* ]] && feature_options="${feature_options} -DHITLS_BUILD_SHARED=ON"

    if [[ $get_arch = "x86_64" ]]; then
        echo "Compile: env=x86_64, c, little endian, 64bits"
        feature_options="${feature_options} -DHITLS_CRYPTO_SP800_STRICT_CHECK=ON" # open the strict check in crypto.
        feature_options="${feature_options} -DHITLS_SM2_PRECOMPUTE_512K_TBL=OFF" # close the sm2 512k pre-table
        feature_options="${feature_options} -DHITLS_ASM_X8664=ON  -DHITLS_PLATFORM_ENDIAN=little"
        add_options="${add_options} -O3"
        del_options="${del_options} -O2 -D_FORTIFY_SOURCE=2"
    elif [[ $get_arch = "armv8_be" ]]; then
        echo "Compile: env=armv8, asm + c, big endian, 64bits"
        feature_options="${feature_options} -DHITLS_ASM_ARMV8=ON -DHITLS_PLATFORM_ENDIAN=big"
    elif [[ $get_arch = "armv8_le" ]]; then
        echo "Compile: env=armv8, asm + c, little endian, 64bits"
        feature_options="${feature_options} -DHITLS_ASM_ARMV8=ON -DHITLS_PLATFORM_ENDIAN=little"
        add_options="${add_options} -O3"
        del_options="${del_options} -O2 -D_FORTIFY_SOURCE=2"
    else
        echo "Compile: env=$get_arch, c, little endian, 64bits"
        feature_options="${feature_options} -DHITLS_PLATFORM_ENDIAN=little"
    fi

    # Some additional options started with -DHITLS_ are treated as feature options,
    # so need to convert them to -DXXX=ON format if they are not already in that format,
    # and remove them from add_options to avoid passing them to the compiler directly
    # For compatible with legacy calling methods (For CI)
    for option in ${add_options}; do
        if [[ $option == -DHITLS* ]]; then
            feature_option="${option#-D}"
            if [[ $feature_option == *=* ]]; then
                feature_options="${feature_options} -D${feature_option}"
            else
                feature_options="${feature_options} -D${feature_option}=ON"
            fi
            add_options="${add_options//$option/}"
        fi
    done

    # macOS-specific flags for STUB test mechanism compatibility
    # On macOS, use flat namespace + interposable to allow test STUB wrappers to intercept library internal calls
    # -flat_namespace: Changes symbol resolution order (matches Linux behavior)
    # -Wl,-interposable: Forces all function calls through PLT, even intra-module calls (prevents direct jumps)
    # This combination ensures STUB mechanism can intercept same-compilation-unit calls
    # ONLY needed for test builds - Production builds use default two-level namespace
    if [[ "$(uname)" = "Darwin" ]]; then
        cmake .. ${feature_options} \
                -DCMAKE_C_FLAGS="${add_options}" \
                -D_HITLS_COMPILE_OPTIONS_DEL="${del_options}" \
                -DCMAKE_SHARED_LINKER_FLAGS="${add_link_flags} -flat_namespace -undefined dynamic_lookup -Wl,-interposable" \
                -DCMAKE_EXE_LINKER_FLAGS="${add_link_flags} -flat_namespace -undefined dynamic_lookup"
    else
        cmake .. ${feature_options} \
                -DCMAKE_C_FLAGS="${add_options}" \
                -D_HITLS_COMPILE_OPTIONS_DEL="${del_options}" \
                -DCMAKE_SHARED_LINKER_FLAGS="${add_link_flags}" \
                -DCMAKE_EXE_LINKER_FLAGS="${add_link_flags}"
    fi
    make -j
}

build_hitls_provider()
{
    # Compile openHiTLS
    cd ${HITLS_ROOT_DIR}/build

    # Remove Cache to avoid affecting subsequent builds
    rm -f CMakeCache.txt

    if [[ $libname = "libhitls_sm${SHARED_LIB_EXT}" ]] && [[ $get_arch = "armv8_le" ]]; then
        config_file="${subdir}_sm_feature_config.cmake"
    else
        config_file="${subdir}_feature_config.cmake"
    fi

    # Remove SM TLS 1.3 feature for provider build, as it is only needed for main library to support GM suite in TLS 1.3
    feature_options="${feature_options//-DHITLS_TLS_FEATURE_SM_TLS13=ON/}"

    echo "Building provider with config: ${config_file}"
    cmake .. -DCMAKE_SKIP_RPATH=TRUE -DCMAKE_INSTALL_PREFIX=../output/${subdir}/${get_arch} \
            -C ../testcode/config/cmake/${subdir}/${get_arch}/${config_file} \
            -D_HITLS_COMPILE_OPTIONS_DEL="${del_options}" \
            -DCMAKE_C_FLAGS="${add_options}" \
            -DHITLS_BUNDLE_LIB=ON \
            ${feature_options}
    make -j
    make install

    # Verify the library was built with correct name
    cd ../output/${subdir}/${get_arch}/lib
    if [ ! -f "$libname" ]; then
        echo "Error: $libname not found in $(pwd)"
        echo "Available files:"
        ls -la
        exit 1
    fi

    echo "Successfully built $libname in $(pwd)"
}

parse_option()
{
    for i in $paramList
    do
        key=${i%%=*}
        value=${i#*=}
        case "${key}" in
            "add-options")
                add_options="${add_options} ${value}"
                ;;
            "add-feature-options")
                feature_options="${feature_options} ${value}"
                ;;
            "no-provider")
                feature_options="${feature_options} -DHITLS_TLS_FEATURE_PROVIDER=OFF -DHITLS_CRYPTO_PROVIDER=OFF -DHITLS_CRYPTO_CODECS=OFF -DHITLS_CRYPTO_KEY_DECODE_CHAIN=OFF"
                ;;
            "gcov")
                add_options="${add_options} -fno-omit-frame-pointer -fprofile-arcs -ftest-coverage -fdump-rtl-expand"
                ;;
            "debug")
                add_options="${add_options} -O0 -g3 -gdwarf-2"
                del_options="${del_options} -O2 -D_FORTIFY_SOURCE=2"
                ;;
            "asan")
                add_options="${add_options} -fsanitize=address -fsanitize-address-use-after-scope -O0 -g3 -fno-stack-protector -fno-omit-frame-pointer -fgnu89-inline"
                del_options="${del_options} -fstack-protector-strong -fomit-frame-pointer -O2 -D_FORTIFY_SOURCE=2"
                ;;
            "x86_64")
                get_arch="x86_64"
                ;;
            "armv8_be")
                get_arch="armv8_be"
                ;;
            "armv8_le")
                get_arch="armv8_le"
                ;;
            "riscv64")
                get_arch="riscv64"
                ;;
            "pure_c")
                get_arch="C"
                ;;
            "no_sctp")
                enable_sctp=""
                ;;
            "bits")
                BITS="$value"
                ;;
            "static")
                LIB_TYPE="static"
                ;;
            "shared")
                LIB_TYPE="shared"
                ;;
            "libfuzzer")
                add_options="${add_options} -fsanitize=fuzzer-no-link -fsanitize=signed-integer-overflow -fsanitize-coverage=trace-cmp"
                del_options="${del_options} -Wtrampolines -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fomit-frame-pointer -fdump-rtl-expand"
                export ASAN_OPTIONS=detect_stack_use_after_return=1:strict_string_checks=1:detect_leaks=1:log_path=asan.log
                export CC=clang
                ;;
            "exe") 
                executes="ON"
                add_options="${add_options} -fno-plt"
                ;;
            "iso")
                if [[ "$(uname)" = "Darwin" ]]; then
                    echo "Warning: ISO provider build is not supported on macOS, due to sw-entropy skipping..."
                else
                    feature_options="${feature_options} -DHITLS_CRYPTO_CMVP_ISO19790=ON"
                    libname="libhitls_iso${SHARED_LIB_EXT}"
                    build_crypto_module_provider=true
                fi
                ;;
            "fips")
                if [[ "$(uname)" = "Darwin" ]]; then
                    echo "Warning: FIPS provider build is not supported on macOS, due to sw-entropy skipping..."
                else
                    feature_options="${feature_options} -DHITLS_CRYPTO_CMVP_FIPS=ON"
                    libname="libhitls_fips${SHARED_LIB_EXT}"
                    build_crypto_module_provider=true
                fi
                ;;
            "sm")
                if [[ "$(uname)" = "Darwin" ]]; then
                    echo "Warning: SM provider build is not supported on macOS, due to sw-entropy skipping..."
                else
                    feature_options="${feature_options} -DHITLS_CRYPTO_CMVP_SM=ON"
                    libname="libhitls_sm${SHARED_LIB_EXT}"
                    build_crypto_module_provider=true
                fi
                ;;
            "help")
                usage
                exit 0
                ;;
            *)
                echo "${i} option is not recognized, Please run <sh build_hitls.sh help> get supported options."
                usage
                exit 0
                ;;
        esac
    done
}

clean
parse_option

# Always build main library
build_hitls_code

# Build CMVP provider if requested (iso/fips/sm)
if [[ $build_crypto_module_provider == true ]]; then
    build_hitls_provider
fi
