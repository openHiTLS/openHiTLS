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
elapsed=0

cd ../../
HITLS_ROOT_DIR=`pwd`

paramList=$@
paramNum=$#
is_concurrent=1
need_run_all=1
threadsNum=$(grep -c ^processor /proc/cpuinfo)
testsuite_array=()
testcase_array=()
export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:$(realpath ${HITLS_ROOT_DIR}/build):$(realpath ${HITLS_ROOT_DIR}/platform/Secure_C/lib)

# Check whether an ASAN alarm is generated.
generate_asan_log() {
    ASAN_LOG=$(find ../output -name "asan.log*")
    if [ ! -z "$ASAN_LOG" ]; then
        for i in $ASAN_LOG
        do
            if grep -q "ASan doesn't fully support makecontext/swapcontext" $i
            then
                line_count=$(wc -l < "$i")
                if [ "$line_count" -eq 1 ]; then
                    echo "The ASAN log contains only ucontext warning content. Ignore it."
                else
                    echo "ASAN ERROR. Exit with ucontext check failure."
                    cat ${i}
                    exit 1
                fi
                continue
            else
                echo "ASAN ERROR. Exit with failure."
                cat ${i}
                exit 1
            fi
        done
    fi
}
# Run the specified test suites or test cases in the output directory.
run_test() {
    cd ${HITLS_ROOT_DIR}/testcode/output
    export ASAN_OPTIONS=detect_stack_use_after_return=1:strict_string_checks=1:detect_leaks=1:halt_on_error=0:log_path=asan.log

    echo ""
    echo "Begin Test"
    echo ".................................................."
    start_time=$(date +%s)

    # Run the specified test suite.
    if [ ${#testsuite_array[*]} -ne 0 ] && [ ${#testcase_array[*]} -eq 0 ];then
        for i in ${testsuite_array[@]}
        do
            if [ "${i}" = "test_suite_sdv_eal_provider_load" ]; then
                # 针对特定测试套件设置 LD_LIBRARY_PATH
                echo "Running ${i} with LD_LIBRARY_PATH set to ../testdata/provider/path1"
                env LD_LIBRARY_PATH="../testdata/provider/path1:${LD_LIBRARY_PATH}" ./${i} NO_DETAIL
            else
                # 其他测试套件正常运行
                ./${i} NO_DETAIL
            fi
        done
    fi

    # Run the specified test case.
    if [ ${#testcase_array[*]} -ne 0 ];then
        num=0
        for i in ${testcase_array[@]}
        do
            ./${testsuite_array[num]} ${i}
            let num+=1
        done
    fi

    end_time=$(date +%s)
    elapsed=$((end_time - start_time))

    generate_asan_log
}

gen_test_report()
{
    cd ${HITLS_ROOT_DIR}/testcode/output
    ./gen_testcase GenReport
    testcase_num=0
    pass_num=0
    skip_num=0
    while read line
    do
        array=(${line})
        last_index=$((${#array[@]}-1))
        if [ "${array[last_index]}" = "PASS" ]; then
            let pass_num+=1
        elif [ "${array[last_index]}" = "SKIP" ]; then
            let skip_num+=1
        fi
        let testcase_num+=1
    done < result.log
    fail_num=`expr $testcase_num - $pass_num - $skip_num`
    SumTime=`echo "$elapsed 60" |awk '{printf("%.2f",$1/$2)}'`
    echo "SumTime is ${SumTime} mintues TestCase Num is ${testcase_num} Pass is ${pass_num} Skip is ${skip_num} Fail is ${fail_num}"
    if [ ${fail_num} -ne 0 ]; then
        exit 1
    fi
}

# Run all tests in the output directory.
run_all() {
    start_time=$(date +%s)
    echo "Test: $1" >> ${HITLS_ROOT_DIR}/testcode/output/time.txt
    echo "Start: $(date)" >> ${HITLS_ROOT_DIR}/testcode/output/time.txt

    cd ${HITLS_ROOT_DIR}/testcode/output
    SUITES=$(ls ./ | grep .datax | sed -e "s/.datax//")
    export ASAN_OPTIONS=detect_stack_use_after_return=1:strict_string_checks=1:detect_leaks=1:halt_on_error=0:log_path=asan.log

    echo ""
    echo "Begin Test"
    echo ".................................................."
    if [ $is_concurrent = 1 ]; then
        mkfifo tmppipe
        exec 5<>tmppipe
        rm -f tmppipe
        echo "threadsNum = $threadsNum"
        # procNum indicates the maximum number of concurrent processes.
        for ((i=1;i<=$threadsNum;i++)); do
            echo >&5
        done
        retPipe=$tmpPipe.ret
        mkfifo $retPipe
        exec 8<>$retPipe
        rm -f $retPipe
        echo "0" >&8
        for i in $SUITES
        do
            # Run tests in parallel.
            read -u5
            {
                if [ "${i}" = "test_suite_sdv_eal_provider_load" ]; then
                    echo "Running ${i} with LD_LIBRARY_PATH set to ../testdata/provider/path1"
                    env LD_LIBRARY_PATH="../testdata/provider/path1:${LD_LIBRARY_PATH}" ./${i} NO_DETAIL || (read -u8 && echo "1 $i" >&8)
                else
                    ./${i} NO_DETAIL || (read -u8 && echo "1 $i" >&8)
                fi
                echo >&5
            } &
        done
        wait

        exec 5>&-
        exec 5<&-
        read -u8 ret
        exec 8<&-
        if [ "$ret" != "0" ];then
            echo "some case failed $ret"
            gen_test_report
            generate_asan_log
            exit 1
        fi
    else
        for i in $SUITES
        do
            if [ "${i}" = "test_suite_sdv_eal_provider_load" ]; then
                echo "Running ${i} with LD_LIBRARY_PATH set to ../testdata/provider/path1"
                env LD_LIBRARY_PATH="../testdata/provider/path1:${LD_LIBRARY_PATH}" ./${i} NO_DETAIL
            else
                ./${i} NO_DETAIL
            fi
        done
    fi

    end_time=$(date +%s)
    echo "End: $(date)" >> time.txt
    elapsed=$((end_time - start_time))
    eval "echo Elapsed time: $(date -ud "@$elapsed" +'$((%s/3600/24)) days %H hr %M min %S sec') >> time.txt"

    generate_asan_log
}

parse_testsuite_testcase()
{
    cd ${HITLS_ROOT_DIR}/testcode/output
    testsuite_name="test_suite"
    if [[ "$1" == *$testsuite_name* ]]; then
        if [ -f "$1" ]; then
            testsuite_array[${#testsuite_array[*]}]=$i
            return 1
        fi
        return 0
    else
        testsuite=`grep -l $1 *.c`
        if [ "${testsuite}" = "" ]; then
            return 0
        else
            array=(${testsuite//./ })
            testsuite_array[${#testcase_array[*]}]="${array[0]}"
            testcase_array[${#testcase_array[*]}]="$1"
            return 1
        fi
    fi
}

parse_option()
{
    for i in $paramList
    do
        case "$i" in
            "help")
                printf "Note: Before Run <sh ${BASH_SOURCE[0]}>, Please Fisrt Run <sh build_hitls.sh && sh build_sdv.sh>"
                printf "%-50s %-30s\n" "Run All Testsuites Of The Output"     "sh ${BASH_SOURCE[0]}"
                printf "%-50s %-30s\n" "Run The Specified Testsuite"          "sh ${BASH_SOURCE[0]} test_suites_xxx test_suites_xxx"
                printf "%-50s %-30s\n" "Run The Specified Testcase"           "sh ${BASH_SOURCE[0]} UT_CRYPTO_xxx SDV_CRYPTO_xxx"
                printf "%-50s %-30s\n" "Set Thread Pool Size"                 "sh ${BASH_SOURCE[0]} threads=N"
                printf "%-50s %-30s\n" "Example: Run with 4 threads"          "sh ${BASH_SOURCE[0]} threads=4"
                exit 0
                ;;
            "threads"*)
                threads_num=${i#*=}
                threadsNum=$threads_num
                ;;
            *)
                parse_testsuite_testcase $i
                if [ $? -eq 0 ]; then
                    echo "Not Find This Testsuite or Testcase : ${i}"
                    exit 1
                fi
                need_run_all=0
                ;;
        esac
    done
}

run_demos()
{
    exit_code=$?
    pushd ${HITLS_ROOT_DIR}/testcode/demo/build
    executales=$(find ./ -maxdepth 1 -type f -perm -a=x )
    for e in $executales
    do
        if [[ ! "$e" == *"client"* ]] && [[ ! "$e" == *"server"* ]]; then
            echo "${e} start"
            eval "${e}"
            if [ $exit_code -ne 0 ]; then
                echo "Demo ${e} failed"
                exit 1
            fi
        fi
    done

    # run server and client in order.
    ./server &
    if [ $exit_code -ne 0 ]; then
        echo "Demo ${e} failed"
        exit 1
    fi
    sleep 1
    ./client
    if [ $exit_code -ne 0 ]; then
        echo "Demo ${e} failed"
        exit 1
    fi
    popd
}

clean()
{
    rm -rf ${HITLS_ROOT_DIR}/testcode/output/log/*
    rm -rf ${HITLS_ROOT_DIR}/testcode/output/result.log
    rm -rf ${HITLS_ROOT_DIR}/testcode/output/*.sock*
    rm -rf ${HITLS_ROOT_DIR}/testcode/output/asan*
}

clean
parse_option
if [ ${need_run_all} -eq 1 ]; then
    run_all
else
    run_test
fi
run_demos
gen_test_report
