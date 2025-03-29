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

ENABLE_C="off"
ASM_TYPE=""

parse_option()
{
    for i in $PARAM_LIST
    do
        case "${i}" in
            "c")
                ENABLE_C="on"
                ;;
            "armv8")
                ASM_TYPE=$i
                ;;
            *)
                echo "Wrong parameter: $i"
                exit 1
                ;;
        esac
    done
}

test_bsl()
{
    bash mini_build_test.sh no-crypto no-tls enable=err test=err
    bash mini_build_test.sh no-crypto no-tls enable=init
    bash mini_build_test.sh no-crypto no-tls enable=list test=list
    bash mini_build_test.sh no-crypto no-tls enable=log test=log
    bash mini_build_test.sh no-crypto no-tls enable=sal test=sal
    bash mini_build_test.sh no-crypto no-tls enable=sal_mem test=sal_mem
    bash mini_build_test.sh no-crypto no-tls enable=sal_thread test=sal_thread
    bash mini_build_test.sh no-crypto no-tls enable=sal_net test=sal_net
    bash mini_build_test.sh no-crypto no-tls enable=sal_lock test=sal_lock
    bash mini_build_test.sh no-crypto no-tls enable=sal_time test=sal_time
    bash mini_build_test.sh no-crypto no-tls enable=sal_file test=sal_file
    bash mini_build_test.sh no-crypto no-tls enable=sal_str test=sal_str
    bash mini_build_test.sh no-crypto no-tls enable=tlv test=tlv
    bash mini_build_test.sh no-crypto no-tls enable=uio_buffer
    bash mini_build_test.sh no-crypto no-tls enable=uio_sctp
    bash mini_build_test.sh no-crypto no-tls enable=uio_tcp
    bash mini_build_test.sh no-crypto no-tls enable=uio test=uio
    bash mini_build_test.sh no-crypto no-tls enable=usrdata
}

test_md()
{
    bash mini_build_test.sh no-tls enable=sha1,eal test=sha1
    bash mini_build_test.sh no-tls enable=sha2,eal test=sha2
    bash mini_build_test.sh no-tls enable=sha224,eal test=sha224
    bash mini_build_test.sh no-tls enable=sha256,eal test=sha256
    bash mini_build_test.sh no-tls enable=sha384,eal test=sha384
    bash mini_build_test.sh no-tls enable=sha512,eal test=sha512
    bash mini_build_test.sh no-tls enable=sha3,eal test=sha3
    bash mini_build_test.sh no-tls enable=sm3,eal test=sm3
    bash mini_build_test.sh no-tls enable=md5,eal test=md5
}

test_mac()
{
    bash mini_build_test.sh no-tls enable=hmac,sha1,eal test=hmac
    bash mini_build_test.sh no-tls enable=hmac,sha2,eal test=hmac
    bash mini_build_test.sh no-tls enable=hmac,sha3,eal test=hmac
    bash mini_build_test.sh no-tls enable=hmac,md5,eal test=hmac
}

test_kdf()
{
    bash mini_build_test.sh no-tls enable=scrypt,eal test=scrypt
    bash mini_build_test.sh no-tls enable=hkdf,sha2,eal test=hkdf
    bash mini_build_test.sh no-tls enable=pbkdf2,sha2,eal test=pbkdf2
    bash mini_build_test.sh no-tls enable=kdftls12,sha2,eal test=kdftls12
}

test_cipher()
{
    bash mini_build_test.sh no-tls enable=aes,cbc,eal test=aes
    bash mini_build_test.sh no-tls enable=aes,ctr,eal test=aes
    bash mini_build_test.sh no-tls enable=aes,ccm,eal test=aes
    bash mini_build_test.sh no-tls enable=aes,gcm,eal test=aes
    bash mini_build_test.sh no-tls enable=aes,cfb,eal test=aes
    bash mini_build_test.sh no-tls enable=aes,ofb,eal test=aes

    bash mini_build_test.sh no-tls enable=sm4,xts,eal test=sm4
    bash mini_build_test.sh no-tls enable=sm4,cbc,eal test=sm4
    bash mini_build_test.sh no-tls enable=sm4,ctr,eal test=sm4
    bash mini_build_test.sh no-tls enable=sm4,gcm,eal test=sm4
    bash mini_build_test.sh no-tls enable=sm4,cfb,eal test=sm4
    bash mini_build_test.sh no-tls enable=sm4,ofb,eal test=sm4

    bash mini_build_test.sh no-tls enable=chacha20,eal test=chacha20
}

test_pkey()
{
    bash mini_build_test.sh no-tls enable=rsa,sha1,sha2,eal,drbg,entropy test=rsa

    bash mini_build_test.sh no-tls enable=dsa,sha2,eal,drbg,entropy test=dsa

    bash mini_build_test.sh no-tls enable=dh,sha2,eal,drbg,entropy test=dh

    bash mini_build_test.sh no-tls enable=ecdh,sha2,eal,drbg,entropy test=ecdh

    bash mini_build_test.sh no-tls enable=ecdsa,sha2,eal,drbg,entropy test=ecdsa

    bash mini_build_test.sh no-tls enable=x25519,sha2,eal,drbg,entropy test=x25519
    bash mini_build_test.sh no-tls enable=ed25519,eal,drbg,entropy test=ed25519 # ed25519 depends on sha512 by default.

    # sm2 depends on sm3 by default.
    bash mini_build_test.sh no-tls enable=sm2_crypt,eal,drbg,entropy test=sm2_crypt
    bash mini_build_test.sh no-tls enable=sm2_exch,eal,drbg,entropy test=sm2_exch
    bash mini_build_test.sh no-tls enable=sm2_sign,eal,drbg,entropy test=sm2_sign
}

test_drbg()
{
    bash mini_build_test.sh no-tls enable=entropy,drbg_hmac,sha256,eal test=entropy
    bash mini_build_test.sh no-tls enable=drbg_ctr,eal test=drbg_ctr
    bash mini_build_test.sh no-tls enable=drbg_hash,eal,sha2 test=drbg_hash
    bash mini_build_test.sh no-tls enable=drbg_hmac,eal,sha2 test=drbg_hmac
}

test_bn()
{
    bash mini_build_test.sh no-tls enable=bn test=bn
}

test_asm_armv8()
{
    bash mini_build_test.sh no-tls enable=sm3,eal armv8 test=sm3

    bash mini_build_test.sh no-tls enable=aes,gcm,eal test=aes armv8

    bash mini_build_test.sh no-tls enable=sm4,cbc,eal test=sm4 armv8
    bash mini_build_test.sh no-tls enable=sm4,xts,eal test=sm4 armv8
    bash mini_build_test.sh no-tls enable=sm4,ctr,eal test=sm4 armv8
    bash mini_build_test.sh no-tls enable=sm4,gcm,eal test=sm4 armv8

    bash mini_build_test.sh no-tls enable=sm2_crypt,eal,drbg,entropy test=sm2_crypt armv8
    bash mini_build_test.sh no-tls enable=sm2_exch,eal,drbg,entropy test=sm2_exch armv8
    bash mini_build_test.sh no-tls enable=sm2_sign,eal,drbg,entropy test=sm2_sign armv8
}

test_pki()
{
    bash mini_build_test.sh no-tls enable=eal,encode_decode,rsa,drbg_hash,cipher,modes,sha256,hmac
    bash mini_build_test.sh no-tls enable=eal,key_encrypt,key_gen,rsa,drbg_hash,cipher,modes,sha256,hmac
    bash mini_build_test.sh no-tls enable=eal,key_gen,rsa,sha256,drbg_hash
    bash mini_build_test.sh no-tls enable=eal,key_parse,rsa,sha256,drbg_hash
    bash mini_build_test.sh no-tls enable=eal,x509,rsa,sha256,drbg_hash
    bash mini_build_test.sh no-tls enable=eal,x509_crt,rsa,sha256,drbg_hash
    bash mini_build_test.sh no-tls enable=eal,x509_crt_gen,rsa,sha256,drbg_hash
    bash mini_build_test.sh no-tls enable=eal,x509_crt_parse,rsa,sha256,drbg_hash
    bash mini_build_test.sh no-tls enable=eal,x509_csr,rsa,sha256,drbg_hash
    bash mini_build_test.sh no-tls enable=eal,x509_csr_gen,rsa,sha256,drbg_hash
    bash mini_build_test.sh no-tls enable=eal,x509_csr_parse,rsa,sha256,drbg_hash
    bash mini_build_test.sh no-tls enable=eal,x509_crl,rsa,sha256,drbg_hash
    bash mini_build_test.sh no-tls enable=eal,x509_crl_gen,rsa,sha256,drbg_hash
    bash mini_build_test.sh no-tls enable=eal,x509_crl_parse,rsa,sha256,drbg_hash
    bash mini_build_test.sh no-tls enable=eal,x509_vfy,rsa,sha256,drbg_hash
    bash mini_build_test.sh no-tls enable=eal,pkcs12,rsa,sha256,drbg_hash,md,cipher,modes,hmac
    bash mini_build_test.sh no-tls enable=eal,pkcs12_gen,rsa,sha256,drbg_hash,md,cipher,modes,hmac
    bash mini_build_test.sh no-tls enable=eal,pkcs12_parse,rsa,drbg_hash,md,cipher,modes,hmac
    bash mini_build_test.sh no-tls enable=eal,info,x509_crt,rsa,drbg_hash,md,cipher,modes,hmac

    #### key gen ####
    bash mini_build_test.sh no-tls enable=eal,key_gen,sal_file,pem,rsa,sha256,drbg_hash         test=key_gen
    bash mini_build_test.sh no-tls enable=eal,key_gen,pem,ed25519,drbg_hash                     test=key_gen
    bash mini_build_test.sh no-tls enable=eal,key_gen,sal_file,sm2,sha256,drbg_hash             test=key_gen
    bash mini_build_test.sh no-tls enable=eal,key_gen,pem,ecdsa,sha256,drbg_hash                test=key_gen

    #### key parse ####
    bash mini_build_test.sh no-tls enable=eal,key_parse,sal_file,pem,rsa,sha256                 test=key_parse
    bash mini_build_test.sh no-tls enable=eal,key_parse,sal_file,pem,ed25519                    test=key_parse
    bash mini_build_test.sh no-tls enable=eal,key_parse,sal_file,sm2,sha256                     test=key_parse
    bash mini_build_test.sh no-tls enable=eal,key_parse,sal_file,pem,ecdsa,sha256               test=key_parse

    #### crl gen ####
    bash mini_build_test.sh no-tls enable=eal,x509_crl_gen,rsa,sal_file,pem,sha256,drbg_hash             test=x509_crl_gen
    bash mini_build_test.sh no-tls enable=eal,x509_crl_gen,pem,ed25519,drbg_hash                test=x509_crl_gen
    bash mini_build_test.sh no-tls enable=eal,x509_crl_gen,sm2,sha256,drbg_hash             test=x509_crl_gen
    bash mini_build_test.sh no-tls enable=eal,x509_crl_gen,sal_file,ecdsa,sha256,drbg_hash  test=x509_crl_gen

    #### crl parse ####
    bash mini_build_test.sh no-tls enable=eal,x509_crl_parse,pem,sal_file,rsa,sha256                test=x509_crl_parse
    bash mini_build_test.sh no-tls enable=eal,x509_crl_parse,sal_file,ed25519,sha256            test=x509_crl_parse
    bash mini_build_test.sh no-tls enable=eal,x509_crl_parse,pem,sal_file,sm2,sha256                test=x509_crl_parse
    bash mini_build_test.sh no-tls enable=eal,x509_crl_parse,sal_file,ecdsa,sha256              test=x509_crl_parse

    #### csr gen ####
    bash mini_build_test.sh no-tls enable=eal,x509_csr_gen,pem,rsa,sha256,drbg_hash             test=x509_csr_gen
    bash mini_build_test.sh no-tls enable=eal,x509_csr_gen,sal_file,ed25519,drbg_hash                test=x509_csr_gen
    bash mini_build_test.sh no-tls enable=eal,x509_csr_gen,sm2,sha256,drbg_hash             test=x509_csr_gen
    bash mini_build_test.sh no-tls enable=eal,x509_csr_gen,sal_file,pem,ecdsa,sha256,drbg_hash           test=x509_csr_gen

    #### csr parse ####
    bash mini_build_test.sh no-tls enable=eal,x509_csr_parse,sal_file,rsa,sha256,drbg_hash             test=x509_csr_parse
    bash mini_build_test.sh no-tls enable=eal,x509_csr_parse,sal_file,pem,ed25519,drbg_hash                test=x509_csr_parse
    bash mini_build_test.sh no-tls enable=eal,x509_csr_parse,sal_file,pem,sm2,sha256,drbg_hash             test=x509_csr_parse
    bash mini_build_test.sh no-tls enable=eal,x509_csr_parse,sal_file,ecdsa,sha256,drbg_hash           test=x509_csr_parse

    #### cert gen ####
    bash mini_build_test.sh no-tls enable=eal,x509_crt_gen,pem,rsa,sha256,drbg_hash             test=x509_crt_gen
    bash mini_build_test.sh no-tls enable=eal,x509_crt_gen,sal_file,pem,ed25519,drbg_hash                test=x509_crt_gen
    bash mini_build_test.sh no-tls enable=eal,x509_crt_gen,sal_file,sm2,sha256,drbg_hash             test=x509_crt_gen
    bash mini_build_test.sh no-tls enable=eal,x509_crt_gen,ecdsa,sha256,drbg_hash           test=x509_crt_gen

    #### cert parse ####hitls_x509_verify.c:699
    bash mini_build_test.sh no-tls enable=eal,x509_crt_parse,sal_file,pem,rsa,sha256,drbg_hash             test=x509_crt_parse
    bash mini_build_test.sh no-tls enable=eal,x509_crt_parse,sal_file,ed25519,drbg_hash                test=x509_crt_parse
    bash mini_build_test.sh no-tls enable=eal,x509_crt_parse,sal_file,sm2,sha256,drbg_hash             test=x509_crt_parse
    bash mini_build_test.sh no-tls enable=eal,x509_crt_parse,sal_file,pem,ecdsa,sha256,drbg_hash           test=x509_crt_parse

    #### cert chain ####
    bash mini_build_test.sh no-tls enable=eal,x509_vfy,sal_file,pem,rsa,ecdsa,ed25519,sm2,sha2,drbg_hash test=x509_vfy debug

    #### pkcs12 gen ####
    bash mini_build_test.sh no-tls enable=eal,pkcs12_gen,key_parse,sal_file,pem,rsa,ecdsa,ed25519,sm2,drbg_hash,cipher,modes,md,hmac test=pkcs12_gen debug
    bash mini_build_test.sh no-tls enable=eal,pkcs12_parse,sal_file,pem,rsa,ecdsa,ed25519,sm2,cipher,modes,md,drbg_hash,hmac test=pkcs12_parse debug
}

parse_option

test_pki

# if [ "${ENABLE_C}" = "on" ]; then
#     test_bsl
#     test_md
#     test_mac
#     test_kdf
#     test_cipher
#     test_pkey
#     test_drbg
#     test_bn
# fi

# case "${ASM_TYPE}" in
#     "armv8")
#         test_asm_armv8
#         ;;
#     *)
#         ;;
# esac
