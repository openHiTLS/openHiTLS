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
cd ../../
HITLS_ROOT_DIR=`pwd`

hitls_compile_option=()

paramList=$@
paramNum=$#
add_options=""
del_options=""
dis_options=""
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

# ============================================================
# Ensure Secure_C Submodule is Ready
# ============================================================
# Function: ensure_securec_ready
# Purpose: Check and initialize Secure_C git submodule if needed
# Note: Actual build happens via CMake (platform/SecureC.cmake)
#       This function only ensures the source code is available
# ============================================================
ensure_securec_ready()
{
    local securec_src_dir="${HITLS_ROOT_DIR}/platform/Secure_C/src"
    local securec_lib_file="${HITLS_ROOT_DIR}/platform/Secure_C/lib/libboundscheck.a"

    echo "======================================================================"
    echo "Checking Secure_C dependency..."
    echo "======================================================================"

    # Initialize submodule if source not present
    if [ ! -d "${securec_src_dir}" ]; then
        echo "[INFO] Secure_C submodule not initialized, initializing..."
        cd "${HITLS_ROOT_DIR}"

        if ! git submodule update --init platform/Secure_C; then
            echo "[ERROR] Failed to initialize Secure_C submodule"
            echo "[ERROR] Please check your git configuration and network connection"
            exit 1
        fi

        echo "[SUCCESS] Secure_C submodule initialized"
    else
        echo "[INFO] Secure_C submodule already initialized"
    fi

    # Report build status
    if [ -f "${securec_lib_file}" ]; then
        echo "[INFO] Securec library already built: ${securec_lib_file}"
    else
        echo "[INFO] Securec will be built by CMake during hitls build"
    fi
    echo ""
}

build_hitls_code()
{
    # Compile openHiTLS
    cd ${HITLS_ROOT_DIR}/build
    add_options="${add_options} -DHITLS_CRYPTO_RAND_CB" # HITLS_CRYPTO_RAND_CB: add rand callback
    add_options="${add_options} -DHITLS_EAL_INIT_OPTS=9 -DHITLS_CRYPTO_ASM_CHECK" # Get CPU capability
    add_options="${add_options} -DHITLS_CRYPTO_ENTROPY -DHITLS_CRYPTO_ENTROPY_DEVRANDOM -DHITLS_CRYPTO_ENTROPY_GETENTROPY -DHITLS_CRYPTO_ENTROPY_SYS -DHITLS_CRYPTO_ENTROPY_HARDWARE" # add default entropy
    add_options="${add_options} -DHITLS_CRYPTO_DRBG_GM" # enable GM DRBG
    add_options="${add_options} -DHITLS_CRYPTO_ACVP_TESTS" # enable ACVP tests
    add_options="${add_options} -DHITLS_CRYPTO_DSA_GEN_PARA" # enable DSA genPara tests
    add_options="${add_options} -DHITLS_TLS_FEATURE_SM_TLS13" # enable rfc8998 tests
    add_options="${add_options} ${test_options}"

    build_options=""
    if [[ $executes = "ON" ]]; then
        build_options="${build_options} --executes hitls"
        add_options="${add_options} -DHITLS_CRYPTO_CMVP"
    fi

    # On Linux, we need -ldl for dlopen() and related functions
    # On macOS, libdl functionality is part of libSystem, so -ldl is not needed (and causes duplicate warnings)
    # On macOS, also need -fno-inline to prevent inlining (required for STUB interception to work)
    link_flags=""
    if [[ "$(uname)" != "Darwin" ]]; then
        link_flags="--add_link_flags=\"-ldl\""
    else
        add_options="${add_options} -fno-inline"
    fi

    if [[ $get_arch = "x86_64" ]]; then
        echo "Compile: env=x86_64, c, little endian, 64bits"
        add_options="${add_options} -DHITLS_CRYPTO_SP800_STRICT_CHECK" # open the strict check in crypto.
        del_options="${del_options} -DHITLS_CRYPTO_SM2_PRECOMPUTE_512K_TBL" # close the sm2 512k pre-table
        python3 ../configure.py ${build_options} --lib_type ${LIB_TYPE} --enable all --asm_type x8664 --add_options="$add_options" --del_options="$del_options" ${link_flags} ${enable_sctp} ${dis_options}
    elif [[ $get_arch = "armv8_be" ]]; then
        echo "Compile: env=armv8, asm + c, big endian, 64bits"
        python3 ../configure.py ${build_options} --lib_type ${LIB_TYPE} --enable all --endian big --asm_type armv8 --add_options="$add_options" --del_options="$del_options" ${link_flags} ${enable_sctp} ${dis_options}
    elif [[ $get_arch = "armv8_le" ]]; then
        echo "Compile: env=armv8, asm + c, little endian, 64bits"
        python3 ../configure.py ${build_options} --lib_type ${LIB_TYPE} --enable all --asm_type armv8 --add_options="$add_options" --del_options="$del_options" ${link_flags} ${enable_sctp} ${dis_options}
    elif [[ $get_arch = "riscv64" ]]; then
        echo "Compile: env=riscv64, asm + c, little endian, 64bits"
        python3 ../configure.py --lib_type ${LIB_TYPE} --asm_type riscv64 --add_options="$add_options" --del_options="$del_options" ${link_flags} ${enable_sctp}
    else
        echo "Compile: env=$get_arch, c, little endian, 64bits"
        python3 ../configure.py ${build_options} --lib_type ${LIB_TYPE} --enable all --add_options="$add_options" --del_options="$del_options" ${link_flags} ${enable_sctp} ${dis_options}
    fi

    # macOS-specific flags for STUB test mechanism compatibility
    # On macOS, use flat namespace + interposable to allow test STUB wrappers to intercept library internal calls
    # -flat_namespace: Changes symbol resolution order (matches Linux behavior)
    # -Wl,-interposable: Forces all function calls through PLT, even intra-module calls (prevents direct jumps)
    # This combination ensures STUB mechanism can intercept same-compilation-unit calls
    # ONLY needed for test builds - Production builds use default two-level namespace
    if [[ "$(uname)" = "Darwin" ]]; then
        cmake .. -DCMAKE_SHARED_LINKER_FLAGS="-flat_namespace -undefined dynamic_lookup -Wl,-interposable" \
                 -DCMAKE_EXE_LINKER_FLAGS="-flat_namespace -undefined dynamic_lookup"
    else
        cmake ..
    fi
    make -j
}

build_hitls_provider()
{
    # Compile openHiTLS
    cd ${HITLS_ROOT_DIR}/build

    # Remove configuration files to allow reconfiguration for provider build
    rm -f feature_config.json compile_config.json macro.txt modules.cmake

    if [[ $libname = "libhitls_sm${SHARED_LIB_EXT}" ]] && [[ $get_arch = "armv8_le" ]]; then
        config_file="${subdir}_sm_feature_config.json"
        compile_file="${subdir}_sm_compile_config.json"
    else
        config_file="${subdir}_feature_config.json"
        compile_file="${subdir}_compile_config.json"
    fi
    python3 ../configure.py --add_options="$add_options" --del_options="$del_options" \
        --feature_config=config/json/${subdir}/${get_arch}/${config_file} \
        --compile_config=config/json/${subdir}/${get_arch}/${compile_file} \
        --lib_type=shared \
        --bundle_libs
    cmake .. -DCMAKE_SKIP_RPATH=TRUE -DCMAKE_INSTALL_PREFIX=../output/${subdir}/${get_arch}
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
            "no-provider")
                dis_options="--disable feature_provider provider codecs codecsdata key_decode_chain"
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
                    add_options="${add_options} -DHITLS_CRYPTO_CMVP_ISO19790"
                    libname="libhitls_iso${SHARED_LIB_EXT}"
                    build_crypto_module_provider=true
                fi
                ;;
            "fips")
                if [[ "$(uname)" = "Darwin" ]]; then
                    echo "Warning: FIPS provider build is not supported on macOS, due to sw-entropy skipping..."
                else
                    add_options="${add_options} -DHITLS_CRYPTO_CMVP_FIPS"
                    libname="libhitls_fips${SHARED_LIB_EXT}"
                    build_crypto_module_provider=true
                fi
                ;;
            "sm")
                if [[ "$(uname)" = "Darwin" ]]; then
                    echo "Warning: SM provider build is not supported on macOS, due to sw-entropy skipping..."
                else
                    add_options="${add_options} -DHITLS_CRYPTO_CMVP_SM"
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
ensure_securec_ready

# Always build main library
build_hitls_code

# Build CMVP provider if requested (iso/fips/sm)
if [[ $build_crypto_module_provider == true ]]; then
    build_hitls_provider
fi
