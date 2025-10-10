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

clean()
{
    rm -rf ${HITLS_ROOT_DIR}/build
    mkdir ${HITLS_ROOT_DIR}/build
}

down_depend_code()
{
    if [ ! -d "${HITLS_ROOT_DIR}/platform" ]; then
        cd ${HITLS_ROOT_DIR}
        mkdir platform
    fi

    if [ ! -d "${HITLS_ROOT_DIR}/platform/Secure_C/src" ]; then
        cd ${HITLS_ROOT_DIR}/platform
        git clone https://gitee.com/openeuler/libboundscheck.git Secure_C
    fi
}

build_depend_code()
{
    if [ ! -d "${HITLS_ROOT_DIR}/platform/Secure_C/lib" ]; then
        mkdir -p ${HITLS_ROOT_DIR}/platform/Secure_C/lib
        cd ${HITLS_ROOT_DIR}/platform/Secure_C
        make -j
    fi
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

    if [[ $get_arch = "x86_64" ]]; then
        echo "Compile: env=x86_64, c, little endian, 64bits"
        add_options="${add_options} -DHITLS_CRYPTO_SP800_STRICT_CHECK" # open the strict check in crypto.
        del_options="${del_options} -DHITLS_CRYPTO_SM2_PRECOMPUTE_512K_TBL" # close the sm2 512k pre-table
        python3 ../configure.py ${build_options} --lib_type ${LIB_TYPE} --enable all --asm_type x8664 --add_options="$add_options" --del_options="$del_options" --add_link_flags="-ldl" ${enable_sctp} ${dis_options}
    elif [[ $get_arch = "armv8_be" ]]; then
        echo "Compile: env=armv8, asm + c, big endian, 64bits"
        python3 ../configure.py ${build_options} --lib_type ${LIB_TYPE} --enable all --endian big --asm_type armv8 --add_options="$add_options" --del_options="$del_options" --add_link_flags="-ldl" ${enable_sctp} ${dis_options}
    elif [[ $get_arch = "armv8_le" ]]; then
        echo "Compile: env=armv8, asm + c, little endian, 64bits"
        python3 ../configure.py ${build_options} --lib_type ${LIB_TYPE} --enable all --asm_type armv8 --add_options="$add_options" --del_options="$del_options" --add_link_flags="-ldl" ${enable_sctp} ${dis_options}
    elif [[ $get_arch = "riscv64" ]]; then
        echo "Compile: env=riscv64, asm + c, little endian, 64bits"
        python3 ../configure.py --lib_type ${LIB_TYPE} --asm_type riscv64 --add_options="$add_options" --del_options="$del_options" --add_link_flags="-ldl" ${enable_sctp}
    else
        echo "Compile: env=$get_arch, c, little endian, 64bits"
        python3 ../configure.py ${build_options} --lib_type ${LIB_TYPE} --enable all --add_options="$add_options" --del_options="$del_options" --add_link_flags="-ldl" ${enable_sctp} ${dis_options}
    fi
    cmake ..
    make -j
}

build_hitls_provider()
{
    # Compile openHiTLS
    cd ${HITLS_ROOT_DIR}/build
    if [[ $libname = "libhitls_sm.so" ]] && [[ $get_arch = "armv8_le" ]]; then
        config_file="${subdir}_sm_feature_config.json"
        compile_file="${subdir}_sm_compile_config.json"
    else
        config_file="${subdir}_feature_config.json"
        compile_file="${subdir}_compile_config.json"
    fi
    python3 ../configure.py --add_options="$add_options" --del_options="$del_options" \
        --feature_config=./config/json/${subdir}/${get_arch}/${config_file} \
        --compile=./config/json/${subdir}/${get_arch}/${compile_file} \
        --lib_type=shared
    cmake .. -DCMAKE_SKIP_RPATH=TRUE -DCMAKE_INSTALL_PREFIX=../output/${subdir}/${get_arch}
    make -j
    make install
    cd ../output/${subdir}/${get_arch}/lib
    mv libhitls.so $libname
    mv libhitls.so.hmac $libname.hmac
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
                dis_options="--disable feature_provider provider codecs"
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
                add_options="${add_options} -DHITLS_CRYPTO_CMVP_ISO19790"
                libname="libhitls_iso.so"
                ;;
            "fips")
                add_options="${add_options} -DHITLS_CRYPTO_CMVP_FIPS"
                libname="libhitls_fips.so"
                ;;
            "sm")
                add_options="${add_options} -DHITLS_CRYPTO_CMVP_SM"
                libname="libhitls_sm.so"
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
down_depend_code
build_depend_code
if [[ $libname != "" ]]; then
    build_hitls_provider
else
    build_hitls_code
fi