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
SHOW_SIZE="on" # size libhitls_*.a
SHOW_MACRO="off"

NO_CRYPTO=""
NO_TLS=""

ARMV8="off"

LIB_TYPE="static shared object"
DEBUG="off"
ADD_OPTIONS=""
DEL_OPTIONS=""

declare -A feature_testfiles
declare -A testfile_testcases
feature_testfiles=(
    # bsl
    ["init"]=""
    ["err"]="test_suite_sdv_err"
    ["list"]="test_suite_sdv_list"
    ["log"]="test_suite_sdv_log"
    ["sal"]="test_suite_sdv_sal"
    ["sal_mem"]="test_suite_sdv_sal"
    ["sal_thread"]="test_suite_sdv_sal"
    ["sal_lock"]="test_suite_sdv_sal"
    ["sal_time"]="test_suite_sdv_sal_time"
    ["sal_file"]="test_suite_sdv_sal_file"
    ["sal_net"]="test_suite_sdv_sal_socket"
    ["sal_str"]="test_suite_sdv_sal"
    ["tlv"]=""
    ["uio"]="test_suite_sdv_uio"
    ["uio_buffer"]=""
    ["uio_sctp"]=""
    ["uio_tcp"]=""
    ["usrdata"]=""
    # eal
    ["eal"]=""
    # md
    ["md5"]="test_suite_sdv_eal_md5"
    ["sm3"]="test_suite_sdv_eal_sm3"
    ["sha1"]="test_suite_sdv_eal_md_sha1"
    ["sha2"]="test_suite_sdv_eal_md_sha2"
    ["sha224"]="test_suite_sdv_eal_md_sha2"
    ["sha256"]="test_suite_sdv_eal_md_sha2"
    ["sha384"]="test_suite_sdv_eal_md_sha2"
    ["sha512"]="test_suite_sdv_eal_md_sha2"
    ["sha3"]="test_suite_sdv_eal_md_sha3"
    ["md"]="test_suite_sdv_eal_md5 test_suite_sdv_eal_sm3 test_suite_sdv_eal_md_sha1 test_suite_sdv_eal_md_sha2 test_suite_sdv_eal_md_sha3"
    # mac
    ["mac"]=""
    ["hmac"]="test_suite_sdv_eal_mac_hmac"
    # kdf
    ["scrypt"]="test_suite_sdv_eal_kdf_scrypt"
    ["hkdf"]="test_suite_sdv_eal_kdf_hkdf"
    ["pbkdf2"]="test_suite_sdv_eal_kdf_pbkdf2"
    ["kdftls12"]="test_suite_sdv_eal_kdf_tls12"
    ["kdf"]="test_suite_sdv_eal_kdf_scrypt test_suite_sdv_eal_kdf_hkdf test_suite_sdv_eal_kdf_pbkdf2 test_suite_sdv_eal_kdf_tls12"
    # bn
    ["bn"]="test_suite_sdv_bn"
    # drbg
    ["drbg_hash"]="test_suite_sdv_drbg"
    ["drbg_hmac"]="test_suite_sdv_drbg"
    ["drbg_ctr"]="test_suite_sdv_drbg"
    ["drbg"]="test_suite_sdv_drbg"
    ["entropy"]="test_suite_sdv_entropy"
    # cipher
    ["cbc"]=""
    ["ctr"]=""
    ["ccm"]=""
    ["gcm"]=""
    ["cfb"]=""
    ["ofb"]=""
    ["xts"]=""
    ["chacha20"]=""
    ["aes"]="test_suite_sdv_eal_aes_ccm test_suite_sdv_eal_aes_gcm test_suite_sdv_eal_aes"
    ["sm4"]="test_suite_sdv_eal_sm4"
    ["chacha20"]="test_suite_sdv_eal_chachapoly"
    ["cipher"]="test_suite_sdv_eal_aes_ccm test_suite_sdv_eal_aes_gcm test_suite_sdv_eal_aes test_suite_sdv_eal_sm4 test_suite_sdv_eal_chachapoly"
    # pkey
    ["rsa"]="test_suite_sdv_eal_rsa_sign_verify test_suite_sdv_eal_rsa_encrypt_decrypt"
    ["dh"]="test_suite_sdv_eal_dh"
    ["dsa"]="test_suite_sdv_eal_dsa"
    ["ecdsa"]="test_suite_sdv_eal_ecdsa"
    ["ecdh"]="test_suite_sdv_eal_ecdh"
    ["curve25519"]="test_suite_sdv_eal_curve25519"
    ["x25519"]="test_suite_sdv_eal_curve25519"
    ["ed25519"]="test_suite_sdv_eal_curve25519"
    ["sm2"]="test_suite_sdv_eal_sm2_exchange test_suite_sdv_eal_sm2_sign test_suite_sdv_eal_sm2_crypt"
    ["sm2_exch"]="test_suite_sdv_eal_sm2_exchange"
    ["sm2_sign"]="test_suite_sdv_eal_sm2_sign"
    ["sm2_crypt"]="test_suite_sdv_eal_sm2_crypt"
)

testfile_testcases=(
    # bsl
    ["test_suite_sdv_err"]=""
    ["test_suite_sdv_list"]=""
    ["test_suite_sdv_log"]=""
    ["test_suite_sdv_sal"]=""
    ["test_suite_sdv_sal_time"]=""
    ["test_suite_sdv_sal_file"]=""
    ["test_suite_sdv_sal_socket"]=""
    ["test_suite_sdv_sal"]=""
    ["test_suite_sdv_uio"]=""
    # md
    ["test_suite_sdv_eal_md_sha1"]="SDV_CRYPT_EAL_SHA1_FUN_TC001"
    ["test_suite_sdv_eal_md_sha2"]="SDV_CRYPT_EAL_MD_SHA2_FUNC_TC003"
    ["test_suite_sdv_eal_md_sha3"]="SDV_CRYPT_EAL_SHA3_FUNC_TC003"
    ["test_suite_sdv_eal_md5"]="SDV_CRYPTO_MD5_FUNC_TC002"
    ["test_suite_sdv_eal_sm3"]="SDV_CRYPT_EAL_SM3_FUNC_TC002"
    # mac
    ["test_suite_sdv_eal_mac_hmac"]="SDV_CRYPT_EAL_HMAC_FUN_TC001"
    # kdf
    ["test_suite_sdv_eal_kdf_pbkdf2"]="SDV_CRYPT_EAL_KDF_PBKDF2_FUN_TC001"
    ["test_suite_sdv_eal_kdf_hkdf"]="SDV_CRYPT_EAL_KDF_HKDF_FUN_TC001"
    ["test_suite_sdv_eal_kdf_scrypt"]="SDV_CRYPT_EAL_KDF_SCRYPT_FUN_TC001"
    ["test_suite_sdv_eal_kdf_tls12"]="SDV_CRYPT_EAL_KDF_TLS12_FUN_TC001"
    # cipher
    ["test_suite_sdv_eal_aes"]="SDV_CRYPTO_AES_ENCRYPT_FUNC_TC001 SDV_CRYPTO_AES_ENCRYPT_FUNC_TC002 SDV_CRYPTO_AES_ENCRYPT_FUNC_TC004 SDV_CRYPTO_AES_ENCRYPT_FUNC_TC006"
    ["test_suite_sdv_eal_aes_ccm"]="SDV_CRYPTO_AES_CCM_UPDATE_FUNC_TC001 SDV_CRYPTO_AES_CCM_UPDATE_FUNC_TC002"
    ["test_suite_sdv_eal_aes_gcm"]="SDV_CRYPTO_AES_GCM_UPDATE_FUNC_TC001 SDV_CRYPTO_AES_GCM_UPDATE_FUNC_TC002"
    ["test_suite_sdv_eal_sm4"]="SDV_CRYPTO_SM4_ENCRYPT_FUNC_TC003 SDV_CRYPTO_SM4_ENCRYPT_FUNC_TC004"
    ["test_suite_sdv_eal_chachapoly"]="SDV_CRYPTO_CHACHA20POLY1305_UPDATE_FUNC_TC001"
    # bn
    ["test_suite_sdv_bn"]=""
    # drbg
    ["test_suite_sdv_entropy"]=""
    ["test_suite_sdv_drbg"]="SDV_CRYPT_EAL_RAND_BYTES_FUNC_TC001 SDV_CRYPT_EAL_RAND_BYTES_FUNC_TC002 SDV_CRYPT_EAL_DRBG_BYTES_FUNC_TC001"
    # pkey
    ["test_suite_sdv_eal_rsa_sign_verify"]="SDV_CRYPTO_RSA_SIGN_PKCSV15_FUNC_TC002 SDV_CRYPTO_RSA_VERIFY_PKCSV15_FUNC_TC001 SDV_CRYPTO_RSA_SIGN_PSS_FUNC_TC001 SDV_CRYPTO_RSA_SIGN_PSS_FUNC_TC002 SDV_CRYPTO_RSA_VERIFY_PSS_FUNC_TC001 SDV_CRYPTO_RSA_GEN_SIGN_VERIFY_PKCSV15_FUNC_TC001 SDV_CRYPTO_RSA_GEN_SIGN_VERIFY_PSS_FUNC_TC001 SDV_CRYPTO_RSA_BLINDING_FUNC_TC001 SDV_CRYPTO_RSA_BLINDING_FUNC_TC002"
    ["test_suite_sdv_eal_rsa_encrypt_decrypt"]="SDV_CRYPTO_RSA_CRYPT_FUNC_TC001 SDV_CRYPTO_RSA_CRYPT_FUNC_TC003"
    ["test_suite_sdv_eal_dh"]="SDV_CRYPTO_DH_FUNC_TC001 SDV_CRYPTO_DH_FUNC_TC002 SDV_CRYPTO_DH_FUNC_TC003"
    ["test_suite_sdv_eal_dsa"]="SDV_CRYPTO_DSA_SIGN_VERIFY_FUNC_TC001"
    ["test_suite_sdv_eal_ecdsa"]="SDV_CRYPTO_ECDSA_SIGN_VERIFY_FUNC_TC001 SDV_CRYPTO_ECDSA_SIGN_VERIFY_FUNC_TC002"
    ["test_suite_sdv_eal_ecdh"]="SDV_CRYPTO_ECDH_EXCH_FUNC_TC001"
    ["test_suite_sdv_eal_curve25519"]="SDV_CRYPTO_X25519_EXCH_FUNC_TC001 SDV_CRYPTO_X25519_EXCH_FUNC_TC002 SDV_CRYPTO_ED25519_SIGN_VERIFY_FUNC_TC001"
    ["test_suite_sdv_eal_sm2_exchange"]="SDV_CRYPTO_SM2_EXCHANGE_FUNC_TC001 SDV_CRYPTO_SM2_EXCHANGE_FUNC_TC003"
    ["test_suite_sdv_eal_sm2_sign"]="SDV_CRYPTO_SM2_SIGN_FUNC_TC001 SDV_CRYPTO_SM2_VERIFY_FUNC_TC001 SDV_CRYPTO_SM2_SIGN_VERIFY_FUNC_TC001"
    ["test_suite_sdv_eal_sm2_crypt"]="SDV_CRYPTO_SM2_ENC_FUNC_TC001 SDV_CRYPTO_SM2_DEC_FUNC_TC001 SDV_CRYPTO_SM2_GEN_CRYPT_FUNC_TC001"
)

print_usage() {
    printf "Usage: $0\n"
    printf "  %-10s %s\n" "help"           "Print this help."
    printf "  %-10s %s\n" "no-build"       "Do not build openHiTLS."
    printf "  %-10s %s\n" "no-size"        "Do not list the detail of the object files in static libraries."
    printf "  %-10s %s\n" "macro"          "Obtains the macro of the openHiTLS."
    printf "  %-10s %s\n" "armv8"          "Specify the type of assembly to build."
    printf "  %-10s %s\n" "debug"          "Build openHiTLS with debug flags."
    printf "  %-10s %s\n" "asan"           "Build openHiTLS with asan flags."
    printf "  %-10s %s\n" "enable=a;b;c"   "Specify the features of the build."
    printf "  %-10s %s\n" "test=a"         "Specify the feature for which the test is to be performed."
    printf "\nexample:\n"
    printf "  %-50s %-30s\n" "sh mini_build_test.sh enable=sha1,sha2 test=sha1"  "Build sha1 and sha2 and test sha1."
    printf "  %-50s %-30s\n" "sh mini_build_test.sh enable=sha1,sm3 armv8 "      "Build sha1 and sm3 and enable armv8 assembly."
}

parse_enable_features()
{
    features=(${1//,/ })
    for i in ${features[@]}
    do
        find=0
        for feature in ${!feature_testfiles[*]}
        do
            if [ "$i" = "$feature" ]; then
                FEATURES[${#FEATURES[*]}]=$i
                find=1
                break
            fi
        done
        if [ $find -ne 1 ]; then
            echo "Wrong feature: $i"
            exit 1
        fi
    done
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
                ;;
            "no-build")
                BUILD_HITLS="off"
                ;;
            "no-size")
                SHOW_SIZE="off"
                ;;
            "no-tls")
                NO_TLS="no-tls"
                ;;
            "no-crypto")
                NO_CRYPTO="no-crypto"
                ;;
            "macro")
                SHOW_MACRO="on"
                ADD_OPTIONS="${ADD_OPTIONS} -E -dM"
                LIB_TYPE="static"
                ;;
            "armv8")
                ARMV8="on"
                ;;
            "debug")
                ADD_OPTIONS="$ADD_OPTIONS -O0 -g3 -gdwarf-2"
                DEL_OPTIONS="$DEL_OPTIONS -O2 -D_FORTIFY_SOURCE=2"
                ;;
            "asan")
                ADD_OPTIONS="$ADD_OPTIONS -fsanitize=address -fsanitize-address-use-after-scope -O0 -g3 -fno-stack-protector -fno-omit-frame-pointer -fgnu89-inline"
                DEL_OPTIONS="$DEL_OPTIONS -fstack-protector-strong -fomit-frame-pointer -O2 -D_FORTIFY_SOURCE=2"
                ;;
            "enable")
                parse_enable_features "$value"
                ;;
            "test")
                LIB_TYPE="static"
                TEST_FEATURE=$value
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

    array=(${libs//\n/ })
    for lib in ${array[@]}
    do
        ls -lh ${lib}
        size ${lib} | grep -v "0	      0	      0	      0	      0"
        echo -e ""
    done
}

show_macro()
{
    cd ${HITLS_BUILD_DIR}
    grep "#define HITLS_" libhitls_bsl.a | grep -v OPENHITLS_VERSION_S |awk '{print $2}' > macro_new.txt
    sort macro_new.txt | uniq >unique_macro.txt
    cat unique_macro.txt
}

mini_config()
{
    enables=""
    bits=0
    system=""

    for feature in ${FEATURES[@]}
    do
        enables="$enables $feature"
        case $feature in
            "sal"|"sal_mem"|"sal_thread"|"sal_lock"|"sal_time"|"sal_file"|"sal_net"|"sal_str"|\
            "uio"|"uio_tcp"|"uio_sctp")
                # uio_tcp|uio depends on sal_net. To enable sal_net, you need to specify the system.
                system="linux"
                ;;
            "bn"|\
            "rsa"|"dsa"|"dh"|"ecdsa"|"ecdh"|"curve25519"|"x25519"|\
            "ed25519"|"sm2"|"sm2_exch"|"sm2_sign"|"sm2_crypt")
                # To enable bn, you need to specify the number of platform bits.
                bits=64
                ;;
        esac
    done

    echo
    echo "python3 configure.py --lib_type $LIB_TYPE --enable $enables"
    python3 $HITLS_ROOT_DIR/configure.py --lib_type $LIB_TYPE --enable $enables

    if [ "$ARMV8" == "on" ]; then
        echo "python3 configure.py --asm_type armv8"
        python3 $HITLS_ROOT_DIR/configure.py --asm_type armv8
    fi

    if [ "$system" != "" ]; then
        echo "python3 configure.py --linux $system"
        python3 $HITLS_ROOT_DIR/configure.py --system $system
    fi

    if [ $bits -ne 0 ]; then
        echo "python3 configure.py --bits $bits"
        python3 $HITLS_ROOT_DIR/configure.py --bits $bits
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
    check_cmd_res "cmake .."

    # make
    make -j 32 > make.txt
    check_cmd_res "make -j"
}

exe_file_testcases()
{
    cd $HITLS_ROOT_DIR/testcode/output

    test_file=$1
    # Get test cases according to test file.
    test_cases=${testfile_testcases[$test_file]}

    if [ "$test_cases" = "" ]; then
        # Execute all test cases when no test case is specified.
        ./$test_file NO_DETAIL
    else
        array=(${test_cases// / })
        for case in ${array[@]}
        do
            echo "test case: $case"
            ./$test_file $case NO_DETAIL
        done
    fi
}

test_feature()
{
    feature=$1

    # Get test files according to feature.
    if [ "${feature_testfiles[$feature]}" == "" ]; then
        return 0
    fi
    files=${feature_testfiles[$feature]}

    cd $HITLS_ROOT_DIR/testcode/script
    files2=`echo ${files// /|}`  # Separate test files with vertical bars (|).
    sh build_sdv.sh run-tests=$files2 $NO_TLS $NO_CRYPTO

    file_array=(${files// / })
    for file in ${file_array[@]}
    do
        exe_file_testcases $file
    done
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
