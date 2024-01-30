#!/bin/bash

# ---------------------------------------------------------------------------------------------
#  This file is part of the openHiTLS project.
#  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
#  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
#  for license information.
# ---------------------------------------------------------------------------------------------

set -e

usage()
{
    printf "\n"
    printf "%-05s %-30s\n" "* Script :"                                        "${BASH_SOURCE[0]}"
    printf "%-50s %-30s\n" "* Usage Option :"                                  ""
    printf "%-50s %-30s\n" "* --help|-h    : Help information."                ""
    printf "%-50s %-30s\n" "* tls-debug    : Enable the debug mode."           "bash ${BASH_SOURCE[0]} tls-debug"
    printf "%-50s %-30s\n" "* no-crypto    : Custom crypto testcase."          "bash ${BASH_SOURCE[0]} no-crypto"
    printf "%-50s %-30s\n" "* no-bsl       : Custom bsl testcase."             "bash ${BASH_SOURCE[0]} no-bsl"
    printf "%-50s %-30s\n" "* no-tls       : Custom tls testcase."             "bash ${BASH_SOURCE[0]} no-tls"
    printf "%-50s %-30s\n" "* verbose      : Show detailse."                   "bash ${BASH_SOURCE[0]} verbose"
    printf "%-50s %-30s\n" "* gcov         : Enable the coverage capability."  "bash ${BASH_SOURCE[0]} gcov"
    printf "%-50s %-30s\n" "* asan         : Enabling the ASAN capability."    "bash ${BASH_SOURCE[0]} asan"
    printf "%-50s %-30s\n" "* big-endian   : Specify the platform endianness." "bash ${BASH_SOURCE[0]} big-endian"
    printf "%-50s %-30s\n\n" "* run-tests  : Creating a custom test suite."    "bash ${BASH_SOURCE[0]} run-tests=xxx1|xxx2|xxx3"
}

export_env()
{
    HITLS_ROOT_DIR=${HITLS_ROOT_DIR:=$(cd $(dirname ${BASH_SOURCE[0]})/../..;pwd)}
    LOCAL_ARCH=${LOCAL_ARCH:=`arch`}
    ENABLE_GCOV=${ENABLE_GCOV:=OFF}
    ENABLE_ASAN=${ENABLE_ASAN:=OFF}
    ENABLE_PRINT=${ENABLE_PRINT:=ON}
    ENABLE_FAIL_REPEAT=${ENABLE_FAIL_REPEAT:=OFF}
    CUSTOM_CFLAGS=${CUSTOM_CFLAGS:=''}
    BIG_ENDIAN=${BIG_ENDIAN:=OFF}
    ENABLE_CRYPTO=${ENABLE_CRYPTO:=ON}
    ENABLE_BSL=${ENABLE_BSL:=ON}
    ENABLE_UIO_SCTP=${ENABLE_UIO_SCTP:=ON}
    ENABLE_VERBOSE=${ENABLE_VERBOSE:=''}
    RUN_TESTS=${RUN_TESTS:=''}
    DEBUG=${DEBUG:=ON}
    if [ -f ${HITLS_ROOT_DIR}/build/macro.txt ];then
        CUSTOM_CFLAGS=$(cat ${HITLS_ROOT_DIR}/build/macro.txt)
    fi
    if [[ ! -e "${HITLS_ROOT_DIR}/testcode/output/log" ]]; then
        mkdir ${HITLS_ROOT_DIR}/testcode/output/log
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
    fi
    if [[ ${ENABLE_BSL} == "ON" ]]; then
        bsl_testsuite=$(find ${HITLS_ROOT_DIR}/testcode/sdv/testcase/bsl -name "*.data" | sed -e "s/.data//" | tr -s "\n" " ")
    fi
    RUN_TEST_SUITES="${crypto_testsuite}${proto_testsuite}${bsl_testsuite}"
}

build_test_suite()
{
    procNum=$(grep -c ^processor /proc/cpuinfo)
    echo "procNum = $procNum"
    tmpPipe="$$.fifo"
    mkfifo $tmpPipe
    exec 7<>$tmpPipe
    rm -f $tmpPipe
    for((i=0; i<$procNum; i++)); do
        echo
    done >&7
    retPipe=$tmpPipe.ret
    mkfifo $retPipe
    exec 8<>$retPipe
    rm -f $retPipe
    echo "0" >&8
    [[ -n ${CASES} ]] && RUN_TEST_SUITES=${CASES}
    cd ${HITLS_ROOT_DIR}/testcode && rm -rf build && mkdir build && cd build
    for TEST_SUITE in ${RUN_TEST_SUITES}
    do
       {
            read -u7
            local tmp_dir=${TEST_SUITE##*/}
            rm -rf ./${tmp_dir} && mkdir ${tmp_dir} && cd ${tmp_dir}
            cmake -DENABLE_GCOV=${ENABLE_GCOV} -DENABLE_ASAN=${ENABLE_ASAN} \
                -DCUSTOM_CFLAGS="${CUSTOM_CFLAGS}" -DDEBUG=${DEBUG} -DENABLE_UIO_SCTP=${ENABLE_UIO_SCTP} \
                -DGEN_TEST_FILES=${TEST_SUITE} -DTESTFILE=${tmp_dir} \
                -DENABLE_CRYPTO=${ENABLE_CRYPTO} \
                -DOS_BIG_ENDIAN=${BIG_ENDIAN} -DPRINT_TO_TERMINAL=${ENABLE_PRINT} -DENABLE_FAIL_REPEAT=${ENABLE_FAIL_REPEAT} ../..
            make TESTCASE ${ENABLE_VERBOSE} -j || (read -u8 && echo "1" >&8)
            echo >&7
       } &
    done
    wait
    exec 7<&-
    read -u8 ret
    exec 8<&-
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
    mkdir ${HITLS_ROOT_DIR}/testcode/output/log
}

options()
{
    while [[ -n $1 ]]
    do
        key=${1%%=*}
        value=${1#*=}
        case ${key} in
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
            no-bsl)
                ENABLE_BSL=OFF
                ;;
            no-sctp)
                ENABLE_UIO_SCTP=OFF
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
