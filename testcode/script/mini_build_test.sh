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
ADD_OPTIONS=""
DEL_OPTIONS=""
SYSTEM=""
BITS=64
ENDIAN="little"
FEATURE_CONFIG_FILE=""

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
                ADD_OPTIONS="${ADD_OPTIONS} -E -dM"
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
                if [[ $value == *entropy* || $value == *hitls_crypto* ]]; then
                    ADD_OPTIONS="$ADD_OPTIONS -DHITLS_SEED_DRBG_INIT_RAND_ALG=CRYPT_RAND_SHA256 -DHITLS_CRYPTO_ENTROPY_DEVRANDOM"
                fi
                ;;
            "debug")
                ADD_OPTIONS="$ADD_OPTIONS -O0 -g3 -gdwarf-2"
                DEL_OPTIONS="$DEL_OPTIONS -O2 -D_FORTIFY_SOURCE=2"
                ;;
            "asan")
                ADD_OPTIONS="$ADD_OPTIONS -fsanitize=address -fsanitize-address-use-after-scope -O0 -g3 -fno-stack-protector -fno-omit-frame-pointer -fgnu89-inline"
                DEL_OPTIONS="$DEL_OPTIONS -fstack-protector-strong -fomit-frame-pointer -O2 -D_FORTIFY_SOURCE=2"
                ;;
            "feature-config")
                # First try to find file with ASM_TYPE suffix
                if [ -n "$ASM_TYPE" ]; then
                    FEATURE_CONFIG_FILE=$(find $HITLS_ROOT_DIR -name "${value}_${ASM_TYPE}.json" -type f | head -n 1)
                fi
                # If not found with suffix, try the original filename
                if [ -z "$FEATURE_CONFIG_FILE" ]; then
                    FEATURE_CONFIG_FILE=$(find $HITLS_ROOT_DIR -name "${value}.json" -type f | head -n 1)
                fi
                if [ -z "$FEATURE_CONFIG_FILE" ]; then
                    echo "Error: Cannot find feature config file '${value}.json' or '${value}.json' under $HITLS_ROOT_DIR"
                    exit 1
                fi
                ;;
            "test")
                LIB_TYPE="static shared"
                TEST_FEATURE=$value
                if [[ $value == *cmvp* ]]; then
                    ADD_OPTIONS="$ADD_OPTIONS -DHITLS_CRYPTO_DRBG_GM -DHITLS_CRYPTO_CMVP_INTEGRITY"
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
    grep "#define HITLS_" libhitls_bsl.a | grep -v HITLS_VERSION |awk '{print $2}' > macro_new.txt
    sort macro_new.txt | uniq >unique_macro.txt
    cat unique_macro.txt
}

process_feature_config()
{
    local config_file="$1"
    local endian="$2"
    local bits="$3"
    local asm_type="$4"
    local build_dir="$5"

    python3 - "$config_file" "$endian" "$bits" "$asm_type" "$build_dir" <<END
#!/usr/bin/env python
import json
import sys
import os

if __name__ == "__main__":
    config_file = sys.argv[1]
    endian = sys.argv[2]
    bits = int(sys.argv[3])
    asm_type = sys.argv[4] if len(sys.argv) > 4 and sys.argv[4] else None
    build_dir = sys.argv[5]
    # Read the current config
    with open(config_file, 'r') as f:
        config = json.load(f)
    # Update the fields
    config['endian'] = endian
    config['bits'] = bits
    if asm_type:
        config['asmType'] = asm_type
    else:
        # If no asm_type is defined, remove the "asm" field from hitls_crypto
        config['asmType'] = "no_asm"
        if 'libs' in config and 'hitls_crypto' in config['libs'] and 'asm' in config['libs']['hitls_crypto']:
            del config['libs']['hitls_crypto']['asm']

    # Create build directory if it doesn't exist
    os.makedirs(build_dir, exist_ok=True)
    # Save to build directory
    output_file = os.path.join(build_dir, 'feature_config_modified.json')
    with open(output_file, 'w') as f:
        json.dump(config, f, indent=4)
    # Print the output file path for the shell script to use
    print(output_file)
END
}

mini_config()
{
    enables="--enable"
    for feature in ${FEATURES[@]}
    do
        enables="$enables $feature"
    done

    if [ "$FEATURE_CONFIG_FILE" != "" ]; then
        MODIFIED_CONFIG_FILE=$(process_feature_config "$FEATURE_CONFIG_FILE" "$ENDIAN" "$BITS" "$ASM_TYPE" "$HITLS_ROOT_DIR/build/")
        enables="--feature_config $MODIFIED_CONFIG_FILE"
    fi

    echo "python3 configure.py --lib_type $LIB_TYPE $enables --endian=$ENDIAN --bits=$BITS"
    python3 $HITLS_ROOT_DIR/configure.py --lib_type $LIB_TYPE  $enables --endian=$ENDIAN --bits=$BITS

    if [ "$ASM_TYPE" != "" ]; then
        echo "python3 configure.py --asm_type $ASM_TYPE"
        python3 $HITLS_ROOT_DIR/configure.py --asm_type $ASM_TYPE
    fi

    if [ "$SYSTEM" != "" ]; then
        echo "python3 configure.py --system $SYSTEM"
        python3 $HITLS_ROOT_DIR/configure.py --system $SYSTEM
    fi

    if [ "$ADD_OPTIONS" != "" -o "$DEL_OPTIONS" != "" ]; then
        echo "python3 configure.py --add_options=\"$ADD_OPTIONS\" --del_options=\"$DEL_OPTIONS\""
        python3 $HITLS_ROOT_DIR/configure.py --add_options="$ADD_OPTIONS" --del_options="$DEL_OPTIONS"
    fi
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
    mini_config
    check_cmd_res "configure.py"

    # cmake ..
    cmake .. > cmake.txt

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

    bash build_sdv.sh run-tests="$files" $NO_LIB no-demos no-sctp

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

# build securec
if [ ! -d "${HITLS_ROOT_DIR}/platform/Secure_C/lib" ]; then
    cd ${HITLS_ROOT_DIR}/platform/Secure_C
    make -j
fi

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
