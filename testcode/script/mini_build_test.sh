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
# Build different miniaturized targets and perform basic functional testing.

set -eu

PARAM_LIST=$@

CUR_DIR=`pwd`
HITLS_ROOT_DIR=`realpath $CUR_DIR/../../`
HITLS_BUILD_DIR=$HITLS_ROOT_DIR/build

FEATURES=()
TEST_FEATURE=""
BUILD_HITLS="on"
EXE_TEST="on"
SHOW_SIZE="off" # size libhitls_*.a
SHOW_MACRO="off"

ASM_TYPE=""

NO_LIB=""

LIB_TYPE="static"
DEBUG="off"
ADD_FEATURE_OPTIONS="-DHITLS_BUILD_GEN_INFO=ON"
ADD_OPTIONS=""
DEL_OPTIONS=""
SYSTEM=""
BITS=64
ENDIAN="little"
ASAN_OPTIONS=""
TLS_FLAG=""
FEATURE_CONFIG_FILE=""

CMAKE_BUILD_OPTIONS=""

print_usage() {
    printf "Usage: $0\n"
    printf "  %-25s %s\n" "help"                    "Print this help."
    printf "  %-25s %s\n" "macro"                   "INFO: Obtains the macro of the hitls."
    printf "  %-25s %s\n" "no-size"                 "INFO: Do not list the detail of the object files in static libraries."
    printf "  %-25s %s\n" "no-build"                "BUILD: Do not build hitls."
    printf "  %-25s %s\n" "enable=a;b;c"            "BUILD: Specify the features of the build."
    printf "  %-25s %s\n" "x8664|armv8"             "BUILD: Specify the type of assembly to build."
    printf "  %-25s %s\n" "linux|dopra"             "BUILD: Specify the type of system to build."
    printf "  %-25s %s\n" "32"                      "BUILD: Specify the number of system bits to 32, default is 64."
    printf "  %-25s %s\n" "big"                     "BUILD: Specify the endian mode of the system to big, default is little."
    printf "  %-25s %s\n" "debug"                   "BUILD: Build HiTLS with debug flags."
    printf "  %-25s %s\n" "asan"                    "BUILD: Build HiTLS with asan flags."
    printf "  %-25s %s\n" "test=a"                  "TEST: Specify the feature for which the test is to be performed."
    printf "  %-25s %s\n" "no-tls"                  "TEST: Do not link hitls_tls related libraries."
    printf "  %-25s %s\n" "no-crypto"               "TEST: Do not link hitls_crypto related libraries."
    printf "  %-25s %s\n" "no-mpa"                  "TEST: Do not link hitls_mpa related libraries."
    printf "  %-25s %s\n" "no-exe-test"             "TEST: Do not exe tests."
    printf "  %-25s %s\n" "tls-debug"               "TEST: HiTLS tls module debug log."
    printf "\nexample:\n"
    printf "  %-50s %-30s\n" "bash mini_build_test.sh enable=sha1,sha2,sha3 test=sha1,sha3" "Build sha1, sha2 and sha3, test sha1 and sha2."
    printf "  %-50s %-30s\n" "bash mini_build_test.sh enable=sha1,sm3 armv8" "Build sha1 and sm3 and enable armv8 assembly."
}

parse_option()
{
    for i in $PARAM_LIST
    do
        key=${i%%=*}
        value=${i#*=}
        case "${key}" in
            "help")
                print_usage
                exit 0;
                ;;
            "macro")
                SHOW_MACRO="on"
                LIB_TYPE="static"
                ;;
            "size")
                SHOW_SIZE="on"
                ;;
            "no-build")
                BUILD_HITLS="off"
                ;;
            "x8664"|"armv8")
                ASM_TYPE=$key
                ;;
            "linux"|"dopra")
                SYSTEM=$key
                ;;
            "32")
                BITS=32
                ;;
            "big")
                ENDIAN="big"
                ;;
            "enable")
                FEATURES=(${value//,/ })
                ;;
            "debug")
                ADD_OPTIONS="$ADD_OPTIONS -O0 -g3 -gdwarf-2"
                DEL_OPTIONS="$DEL_OPTIONS -O2 -D_FORTIFY_SOURCE=2"
                ;;
            "asan")
                ADD_OPTIONS="$ADD_OPTIONS -fsanitize=address -fsanitize-address-use-after-scope -O0 -g3 -fno-stack-protector -fno-omit-frame-pointer -fgnu89-inline"
                DEL_OPTIONS="$DEL_OPTIONS -fstack-protector-strong -fomit-frame-pointer -O2 -D_FORTIFY_SOURCE=2"
                ASAN_OPTIONS="asan"
                ;;
            "feature-config")
                # First try to find file with ASM_TYPE suffix
                if [ -n "$ASM_TYPE" ]; then
                    FEATURE_CONFIG_FILE=$(find $HITLS_ROOT_DIR -name "${value}_${ASM_TYPE}.cmake" -type f | head -n 1)
                fi
                # If not found with suffix, try the original filename
                if [ -z "$FEATURE_CONFIG_FILE" ]; then
                    FEATURE_CONFIG_FILE=$(find $HITLS_ROOT_DIR -name "${value}.cmake" -type f | head -n 1)
                fi
                if [ -z "$FEATURE_CONFIG_FILE" ]; then
                    echo "Error: Cannot find feature config file '${value}.cmake' or '${value}.cmake' under $HITLS_ROOT_DIR"
                    exit 1
                fi
                ;;
            "test")
                LIB_TYPE="static shared"
                TEST_FEATURE=$value
                if [[ $value == *cmvp* ]]; then
                    ADD_FEATURE_OPTIONS="$ADD_FEATURE_OPTIONS -DHITLS_CRYPTO_DRBG_GM=ON -DHITLS_CRYPTO_CMVP_INTEGRITY=ON"
                fi
                ;;
            "no-exe-test")
                EXE_TEST="off"
                ;;
            "no-tls")
                NO_LIB="$NO_LIB no-tls"
                ;;
            "no-crypto")
                NO_LIB="$NO_LIB no-crypto"
                ;;
            "no-mpa")
                NO_LIB="$NO_LIB no-mpa"
                ;;
            "add-options")
                ADD_OPTIONS="$ADD_OPTIONS $value"
                ;;
            "add-feature-options")
                ADD_FEATURE_OPTIONS="$ADD_FEATURE_OPTIONS $value"
                ;;
            "tls-debug")
                TLS_FLAG=$value
                ;;
            *)
                echo "Wrong parameter: $key" 
                exit 1
                ;;
        esac
    done
}

show_size()
{
    cd $HITLS_BUILD_DIR
    libs=`find -name '*.a'`
    echo "$libs"

    array=(${libs//\n/ })
    for lib in ${array[@]}
    do
        ls -lh ${lib}
        echo -e ""
        size ${lib} | grep -v "0	      0	      0	      0	      0"
    done
}

show_macro()
{
    cd ${HITLS_BUILD_DIR}
    cat macros.txt
}

build_args_to_cmake_options()
{
    local options=""

    # asm type
    if [ "$ASM_TYPE" != "" ]; then
        options="$options -DHITLS_ASM_$(echo $ASM_TYPE | tr '[:lower:]' '[:upper:]')=ON"
    fi
    # lib type
    [[ "$LIB_TYPE" == *"static"* ]] && options="${options} -DHITLS_BUILD_STATIC=ON"
    [[ "$LIB_TYPE" == *"shared"* ]] && options="${options} -DHITLS_BUILD_SHARED=ON"
    # bits
    if [ "$BITS" != "" ]; then
        options="$options -DHITLS_PLATFORM_BITS=$BITS"
    fi
    # endian
    if [ "$ENDIAN" != "" ]; then
        options="$options -DHITLS_PLATFORM_ENDIAN=$ENDIAN"
    fi
    # add feature options
    if [ "$ADD_FEATURE_OPTIONS" != "" ]; then
        options="$options $ADD_FEATURE_OPTIONS"
    fi
    # add compile options
    if [ "$ADD_OPTIONS" != "" ]; then
        ADD_OPTIONS=$(echo "$ADD_OPTIONS" | xargs)
        options="$options -DCMAKE_C_FLAGS=\"$ADD_OPTIONS\""
    fi
    # del compile options
    if [ "$DEL_OPTIONS" != "" ]; then
        DEL_OPTIONS=$(echo "$DEL_OPTIONS" | xargs)
        options="$options -D_HITLS_COMPILE_OPTIONS_DEL=\"$DEL_OPTIONS\""
    fi
    # features
    if [ ${#FEATURES[@]} -gt 0 ]; then
        FEATURE_MACRO_OPTS=$(python3 - "$HITLS_ROOT_DIR/testcode/script/feature_to_macro.json" "${FEATURES[@]}" <<'END'
import json, sys
mapping_file = sys.argv[1]
with open(mapping_file, 'r') as f:
    mapping = json.load(f)
opts = []
for feat in sys.argv[2:]:
    macro = mapping.get(feat)
    if macro:
        opts.append('-D{}=ON'.format(macro))
    else:
        print('Warning: No macro mapping found for feature: {}'.format(feat), file=sys.stderr)
print(' '.join(opts))
END
)
        options="$options $FEATURE_MACRO_OPTS"
    fi
    # feature config file
    if [ "$FEATURE_CONFIG_FILE" != "" ]; then
        options="$options -C $FEATURE_CONFIG_FILE"
    fi

    echo "================= CMake build options ================="
    echo "$options"
    echo "======================================================="

    CMAKE_BUILD_OPTIONS="$options"
}

check_cmd_res()
{
    if [ "$?" -ne "0" ]; then
        echo "Error: $1"
        exit 1
    fi
}

build_hitls()
{
    # cleanup
    cd $HITLS_ROOT_DIR
    rm -rf $HITLS_BUILD_DIR
    mkdir $HITLS_BUILD_DIR
    cd $HITLS_BUILD_DIR

    # config
    build_args_to_cmake_options

    # cmake ..
    cmake .. ${CMAKE_BUILD_OPTIONS} > cmake.txt

    # cmake ..
    check_cmd_res "cmake .."

    # make
    make -j > make.txt
    check_cmd_res "make -j"
}

get_testfiles_by_features()
{
    cd $HITLS_ROOT_DIR/testcode/test_config
    # 参数：被测试的特性列表（以逗号分隔）
    python3 - "$1" <<END
#!/usr/bin/env python
import os, sys, json
if __name__ == "__main__":
    with open('crypto_test_config.json', 'r') as f:
        test_config1 = json.loads(f.read())
    with open('tls_test_config.json', 'r') as f:
        test_config2 = json.loads(f.read())
    files = set()
    for fea in sys.argv[1].split(","):
        files.update(test_config1['testFeatures'].get(fea, ''))
        files.update(test_config2['testFeatures'].get(fea, ''))
    sys.stdout.write('%s' % '|'.join(files))
END
}

get_testcases_by_testfile()
{
    cd $HITLS_ROOT_DIR/testcode/test_config/
    # 参数：测试文件，获取需执行的测试用例
    python3 - "$1" <<END
#!/usr/bin/env python
import os, sys, json
if __name__ == "__main__":
    with open('crypto_test_config.json', 'r') as f:
        test_config1 = json.loads(f.read())
    with open('tls_test_config.json', 'r') as f:
        test_config2 = json.loads(f.read())
    if sys.argv[1] not in test_config1['testSuiteCases'] and sys.argv[1] not in test_config2['testSuiteCases']:
        raise ValueError('The test case of file %s is not configured in file crypto_test_config.json or tls_test_config.json.'% sys.argv[1])
    cases = set()
    if sys.argv[1] in test_config1['testSuiteCases']:
        cases.update(test_config1['testSuiteCases'][sys.argv[1]])
    if sys.argv[1] in test_config2['testSuiteCases']:
        cases.update(test_config2['testSuiteCases'][sys.argv[1]])
    sys.stdout.write('%s' % ' '.join(cases))
END
}

exe_file_testcases()
{
    test_file=$1
    # Get test cases according to test file.
    cd $HITLS_ROOT_DIR/testcode/script
    test_cases=`get_testcases_by_testfile $test_file`
    echo "test cases: $test_cases"

    cd $HITLS_ROOT_DIR/testcode/output
    ./$test_file ${test_cases} NO_DETAIL
    check_cmd_res "exe $test_file failed"
}

test_feature()
{
    features=$1
    cd $HITLS_ROOT_DIR/testcode/script
    files=`get_testfiles_by_features $features`
    echo "files: $files"

    if [ -z $files ]; then
        return
    fi

    bash build_sdv.sh run-tests="$files" $NO_LIB no-demos no-sctp $ASAN_OPTIONS $TLS_FLAG

    if [ $EXE_TEST == "on" ]; then
        # exe test
        file_array=(${files//|/ })
        for file in ${file_array[@]}
        do
            exe_file_testcases $file
        done
    fi
}

parse_option


if [ "${BUILD_HITLS}" = "on" ]; then
    build_hitls
fi

if [ "${SHOW_SIZE}" = "on" ]; then
    show_size
fi

if [ "${SHOW_MACRO}" = "on" ]; then
    show_macro
    exit 0
fi

if [ "$TEST_FEATURE" != "" ]; then
    test_feature $TEST_FEATURE
fi
