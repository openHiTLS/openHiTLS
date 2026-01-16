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

COMMON_PARAM=""
TEST=""
ASM_TYPE=""

parse_option()
{
    for i in $PARAM_LIST
    do
        case "${i}" in
            "bsl"|"md"|"mac"|"kdf"|"cipher"|"bn"|"ecc"|"pkey"|"pki"|"all"|"tls")
                TEST=$i
                ;;
            "x8664"|"armv8")
                ASM_TYPE=$i
                COMMON_PARAM="$COMMON_PARAM $i"
                ;;
            "linux")
                COMMON_PARAM="$COMMON_PARAM $i"
                ;;
            "32")
                COMMON_PARAM="$COMMON_PARAM $i"
                ;;
            "big")
                COMMON_PARAM="$COMMON_PARAM $i"
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
    if [ "$ASM_TYPE" != "" ]; then
        echo "bsl does not support assembly."
        return
    fi
    NO_LIB="no-crypto no-tls linux"
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=asn1 test=asn1
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=base64 test=base64
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=buffer test=buffer
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=err test=err
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=hash test=hash
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=init test=init
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=list test=list
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=log test=log
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=obj test=obj
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=obj,hash,sal_thread test=obj # depends on thread to init hash
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=params test=params
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=pem test=pem

    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=sal test=sal
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=sal_mem test=sal_mem
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=sal_thread test=sal_thread
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=sal_lock test=sal_lock
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=sal_time test=sal_time
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=sal_file test=sal_file
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=sal_net test=sal_net
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=sal_str test=sal_str
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=sal_dl test=sal_dl

    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=tlv test=tlv

    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=uio test=uio
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=uio_buffer
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=uio_mem
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=uio_sctp
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=uio_tcp
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=uio_udp

    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=usrdata test=usrdata
}

test_md()
{
    NO_LIB="no-tls"
    if [ "$ASM_TYPE" = "armv8" ]; then
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,sm3 test=sm3
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,ealinit,sha1 test=sha1
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,ealinit,sha2 test=sha2
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,ealinit,sha224 test=sha224
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,ealinit,sha256 test=sha256
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,sha384 test=sha384
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,sha512 test=sha512
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,sha3 test=sha3
    elif [ "$ASM_TYPE" = "x8664" ]; then
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,sm3 test=sm3
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,md5 test=md5
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,sha1 test=sha1
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,sha2 test=sha2
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,sha224 test=sha224
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,sha256 test=sha256
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,sha384 test=sha384
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,sha512 test=sha512
    else
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,md5 test=md5
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,sm3 test=sm3
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,sha1 test=sha1
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,sha2 test=sha2
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,sha224 test=sha224
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,sha256 test=sha256
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,sha384 test=sha384
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,sha512 test=sha512
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,sha3 test=sha3
    fi
}

test_mac()
{
    if [ "$ASM_TYPE" != "" ]; then
        echo "mac does not support assembly."
        return
    fi
    NO_LIB="no-tls"
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,hmac,md5 test=hmac
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,hmac,sha1 test=hmac
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,hmac,sha2 test=hmac
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,hmac,sha224 test=hmac
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,hmac,sha256 test=hmac
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,hmac,sha384 test=hmac
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,hmac,sha512 test=hmac
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,hmac,sha3 test=hmac
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,hmac,sm3 test=hmac

    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,gmac test=gmac

    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,cmac_aes test=cmac_aes
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,cmac_sm4 test=cmac_sm4
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,cbc_mac test=cbc_mac

    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,siphash test=siphash
}

test_kdf()
{
    if [ "$ASM_TYPE" != "" ]; then
        echo "kdf does not support assembly."
        return
    fi
    NO_LIB="no-tls"
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,scrypt test=scrypt

    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,hkdf,md5 test=hkdf
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,hkdf,sha1 test=hkdf
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,hkdf,sha2 test=hkdf

    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,pbkdf2,md5 test=pbkdf2
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,pbkdf2,sha1 test=pbkdf2
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,pbkdf2,sha2 test=pbkdf2
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,pbkdf2,sha3 test=pbkdf2
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,pbkdf2,sm3 test=pbkdf2

    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,kdftls12,sha256 test=kdftls12
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,kdftls12,sha384 test=kdftls12
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,kdftls12,sha512 test=kdftls12
}

test_cipher()
{
    NO_LIB="no-tls"
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,aes,modes test=aes
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,aes,cbc test=aes
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,aes,ctr test=aes
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,aes,ecb test=aes # SDV_CRYPTO_AES_ENCRYPT_FUNC_TC001
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,aes,xts test=aes # SDV_CRYPTO_EAL_AES_FUNC_TC001
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,aes,ccm test=aes
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,aes,gcm test=aes
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,aes,cfb test=aes
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,aes,ofb test=aes

    if [ "$ASM_TYPE" = "x8664" ]; then
        # depends on ealinit
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,ealinit,sm4,modes test=sm4
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,ealinit,sm4,xts test=sm4
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,ealinit,sm4,cbc test=sm4
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,ealinit,sm4,ecb test=sm4
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,ealinit,sm4,ctr test=sm4
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,ealinit,sm4,gcm test=sm4
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,ealinit,sm4,cfb test=sm4
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,ealinit,sm4,ofb test=sm4
    else
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,sm4,modes test=sm4
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,sm4,xts test=sm4
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,sm4,cbc test=sm4
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,sm4,ecb test=sm4
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,sm4,ctr test=sm4
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,sm4,gcm test=sm4
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,sm4,cfb test=sm4
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,sm4,ofb test=sm4
    fi

    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,chacha20 test=chacha20
}

test_bn()
{
    NO_LIB="no-tls"
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=bn
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=bn_basic
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal_bn
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=bn_rand
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=bn_prime
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=bn_str_conv
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=bn_cb
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=bn_prime_rfc3526
}

test_ecc()
{
    NO_LIB="no-tls"
    if [ "$ASM_TYPE" = "armv8" -o "$ASM_TYPE" = "x8664" ]; then
        # The curves that support assembly are: curve_sm2, curve_nistp256
        # all curves.
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,eal_bn,ecdh,ecdsa,sm2,drbg_hash,entropy,sha2,ecc,ealinit test=curve_nistp224
        # sm2, depends on sm3
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,eal_bn,sm2,drbg_hash,entropy,ealinit test=sm2
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,eal_bn,sm2_crypt,drbg_hash,entropy,ealinit test=sm2_crypt
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,eal_bn,sm2_exch,drbg_hash,entropy,ealinit test=sm2_exch
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,eal_bn,sm2_sign,drbg_hash,entropy,ealinit test=sm2_sign
        # nistp256
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,eal_bn,ecdh,ecdsa,drbg_hash,entropy,sha2,curve_nistp256,ealinit test=curve_nistp256

        return
    fi

    # Test all curves.
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,eal_bn,ecdh,ecdsa,sm2,drbg_hash,entropy,sha2,ecc test=curve_nistp224

    # nist192/224/256/384/521
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,eal_bn,ecdh,ecdsa,drbg_hash,entropy,sha2,curve_nistp192 test=curve_nistp192
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,eal_bn,ecdh,ecdsa,drbg_hash,entropy,sha2,curve_nistp224 test=curve_nistp224
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,eal_bn,ecdh,ecdsa,drbg_hash,entropy,sha2,curve_nistp256 test=curve_nistp256
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,eal_bn,ecdh,ecdsa,drbg_hash,entropy,sha2,curve_nistp384 test=curve_nistp384
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,eal_bn,ecdh,ecdsa,drbg_hash,entropy,sha2,curve_nistp521 test=curve_nistp521

    # br256/384/512
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,eal_bn,ecdh,ecdsa,drbg_hash,entropy,sha2,curve_bp256r1 test=curve_bp256r1
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,eal_bn,ecdh,ecdsa,drbg_hash,entropy,sha2,curve_bp384r1 test=curve_bp384r1
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,eal_bn,ecdh,ecdsa,drbg_hash,entropy,sha2,curve_bp512r1 test=curve_bp512r1

    # sm2 depends on sm3 by default.
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,eal_bn,sm2,drbg_hash,entropy test=sm2
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,eal_bn,sm2_crypt,drbg_hash,entropy test=sm2_crypt
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,eal_bn,sm2_exch,drbg_hash,entropy test=sm2_exch
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,eal_bn,sm2_sign,drbg_hash,entropy test=sm2_sign
}

test_pkey()
{
    NO_LIB="no-tls"
    if [ "$ASM_TYPE" = "x8664" -o "$ASM_TYPE" = "armv8" ]; then
        # The pkey that support assembly is: x25519.
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=x25519,sha2,ealinit
        bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,x25519,drbg_hash,sha2,ealinit test=x25519
        return
    fi
    # rsa
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,rsa,rsa_bssa,drbg_hash,sha1,sha2 test=rsa
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,rsa,drbg_hash,sha1,sha2 test=rsa

    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,rsa_gen,drbg_hash,sha1,sha2 test=rsa_gen

    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,rsa_sign,rsa_emsa_pss,sha1,sha2,drbg_hash test=rsa_sign
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,rsa_sign,rsa_emsa_pss,drbg_hash,sha1,sha2 test=rsa_sign
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,rsa_sign,rsa_emsa_pkcsv15,sha1,sha2 test=rsa_sign # not need drbg
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,rsa_verify,rsa_emsa_pss,sha1,sha2 test=rsa_verify # not need drbg
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,rsa_verify,rsa_emsa_pkcsv15,sha1,sha2 test=rsa_verify # not need drbg

    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,rsa_encrypt,rsa_no_pad,sha1,sha2 test=rsa_encrypt # not need drbg
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,rsa_encrypt,rsaes_oaep,drbg_hash,sha1,sha2 test=rsa_encrypt
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,rsa_encrypt,rsaes_pkcsv15,drbg_hash,sha1,sha2 test=rsa_encrypt
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,rsa_encrypt,rsaes_pkcsv15_tls,drbg_hash,sha1,sha2 test=rsa_encrypt

    # rsa_decrypt: not need drbg
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,rsa_decrypt,rsa_no_pad,sha1,sha2 test=rsa_decrypt
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,rsa_decrypt,rsaes_oaep,sha1,sha2 test=rsa_decrypt
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,rsa_decrypt,rsaes_pkcsv15,sha1,sha2 test=rsa_decrypt
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,rsa_decrypt,rsaes_pkcsv15_tls,sha1,sha2 test=rsa_decrypt

    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,rsa_sign,rsa_blinding,rsa_emsa_pkcsv15,drbg_hash,sha1,sha2 test=rsa_sign
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,rsa_decrypt,rsa_blinding,rsaes_oaep,drbg_hash,sha1,sha2 test=rsa_decrypt
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,rsa_sign,rsa_bssa,rsa_blinding,rsa_emsa_pss,drbg_hash,sha1,sha2 test=rsa_sign
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,rsa_sign,rsa_verify,rsa_bssa,rsa_emsa_pss,drbg_hash,sha1,sha2 test=rsa_sign

    # dsa
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,eal_bn,dsa,drbg_hash,sha2 test=dsa

    # dh
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,dh,drbg_hash,sha2 test=dh

    # curve25519: ed25519 depends on sha512 by default.
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,x25519,drbg_hash,sha2 test=x25519
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,ed25519,drbg_hash,sha2 test=ed25519

    # mldsa
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,mldsa,drbg_hash,sha2 test=mldsa

    # paillier
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,paillier,drbg_hash,sha2 test=paillier

    # mlkem
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,mlkem,drbg_hash,sha2 test=mlkem

    # hybridkem
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,hybridkem,x25519,ecdh,ecc,drbg_hash,sha2 test=hybridkem

    # elgamal
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,elgamal,drbg_hash,sha2 test=elgamal

    # slh_dsa
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB enable=eal,slh_dsa,drbg_hash,sha2 test=slh_dsa
}

test_tls()
{
    NO_LIB=""
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB feature-config=tlcp_feature test=base,asn1,base64,buffer,err,hash,init,list,log,obj,params,pem,tlv,usrdata,sal,sal_mem,sal_lock,sal_str,sal_file,sal_thread,sal_net,sal_time,aes,bn,chacha20,cmac_aes,drbg_ctr,drbg_hash,ecc,ecdh,ecdsa,entropy,gcm,hkdf,hpke,mlkem,mldsa,sha256,sha384,sha512,slh_dsa,sm2,sm3,sm4,x25519,curve_nistp256,curve_nistp384,curve_nistp521,x509_crl_gen,x509_crl_parse,x509_csr_gen,x509_csr_parse,x509_crt_gen,x509_crt_parse,x509_vfy,tlcp linux
    bash mini_build_test.sh $COMMON_PARAM $NO_LIB feature-config=nokem_feature test=base linux
}

test_pki()
{
    if [ "$ASM_TYPE" != "" ]; then
        return
    fi
    bash mini_build_test.sh no-tls enable=eal,codecskey,rsa,drbg_hash,cipher,modes,sha256,hmac
    bash mini_build_test.sh no-tls enable=eal,key_epki,key_encode,rsa,drbg_hash,cipher,modes,sha256,hmac
    bash mini_build_test.sh no-tls enable=eal,key_encode,rsa,sha256,drbg_hash
    bash mini_build_test.sh no-tls enable=eal,key_decode,rsa,sha256,drbg_hash
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

    ### key gen ####
    bash mini_build_test.sh no-tls enable=eal,key_encode,sal_file,pem,rsa,sha256,drbg_hash test=key_encode linux
    bash mini_build_test.sh no-tls enable=eal,key_encode,pem,ed25519,drbg_hash test=key_encode
    bash mini_build_test.sh no-tls enable=eal,key_encode,key_epki,pem,x25519,drbg_hash,cipher,modes,sha256,hmac test=key_encode
    bash mini_build_test.sh no-tls enable=eal,key_encode,sal_file,sm2,sha256,drbg_hash test=key_encode linux
    bash mini_build_test.sh no-tls enable=eal,key_encode,pem,ecdsa,curve_nistp256,sha256,drbg_hash test=key_encode

    #### key parse ####
    bash mini_build_test.sh no-tls enable=eal,key_decode,sal_file,pem,rsa,sha256,drbg_hash test=key_decode linux
    bash mini_build_test.sh no-tls enable=eal,key_decode,sal_file,pem,ed25519 test=key_decode linux
    bash mini_build_test.sh no-tls enable=eal,key_decode,key_epki,sal_file,pem,x25519,cipher,modes,sha256,hmac test=key_decode linux
    bash mini_build_test.sh no-tls enable=eal,key_decode,sal_file,sm2,sha256 test=key_decode linux
    bash mini_build_test.sh no-tls enable=eal,key_decode,sal_file,pem,ecdsa,curve_nistp256,sha256 test=key_decode linux

    #### crl gen ####
    bash mini_build_test.sh no-tls enable=eal,x509_crl_gen,rsa,sal_file,pem,sha256,drbg_hash test=x509_crl_gen linux
    bash mini_build_test.sh no-tls enable=eal,x509_crl_gen,pem,ed25519,drbg_hash test=x509_crl_gen
    bash mini_build_test.sh no-tls enable=eal,x509_crl_gen,sm2,sha256,drbg_hash test=x509_crl_gen
    bash mini_build_test.sh no-tls enable=eal,x509_crl_gen,sal_file,ecdsa,curve_nistp256,sha256,drbg_hash test=x509_crl_gen linux

    #### crl parse ####
    bash mini_build_test.sh no-tls enable=eal,x509_crl_parse,pem,sal_file,rsa,sha256,drbg_hash test=x509_crl_parse linux
    bash mini_build_test.sh no-tls enable=eal,x509_crl_parse,sal_file,ed25519,sha256 test=x509_crl_parse linux
    bash mini_build_test.sh no-tls enable=eal,x509_crl_parse,pem,sal_file,sm2,sha256 test=x509_crl_parse linux
    bash mini_build_test.sh no-tls enable=eal,x509_crl_parse,sal_file,ecdsa,curve_nistp256,sha256 test=x509_crl_parse linux

    #### csr gen ####
    bash mini_build_test.sh no-tls enable=eal,x509_csr_gen,pem,rsa,sha256,drbg_hash test=x509_csr_gen
    bash mini_build_test.sh no-tls enable=eal,x509_csr_gen,sal_file,ed25519,drbg_hash test=x509_csr_gen linux
    bash mini_build_test.sh no-tls enable=eal,x509_csr_gen,sm2,sha256,drbg_hash test=x509_csr_gen
    bash mini_build_test.sh no-tls enable=eal,x509_csr_gen,sal_file,pem,ecdsa,curve_nistp256,sha256,drbg_hash test=x509_csr_gen linux

    #### csr parse ####
    bash mini_build_test.sh no-tls enable=eal,x509_csr_parse,sal_file,rsa,sha256,drbg_hash test=x509_csr_parse linux
    bash mini_build_test.sh no-tls enable=eal,x509_csr_parse,sal_file,pem,ed25519,drbg_hash test=x509_csr_parse linux
    bash mini_build_test.sh no-tls enable=eal,x509_csr_parse,sal_file,pem,sm2,sha256,drbg_hash test=x509_csr_parse linux
    bash mini_build_test.sh no-tls enable=eal,x509_csr_parse,sal_file,ecdsa,curve_nistp256,sha256,drbg_hash test=x509_csr_parse linux

    #### cert gen ####
    bash mini_build_test.sh no-tls enable=eal,x509_crt_gen,pem,rsa,sha256,drbg_hash test=x509_crt_gen
    bash mini_build_test.sh no-tls enable=eal,x509_crt_gen,sal_file,pem,ed25519,drbg_hash test=x509_crt_gen linux
    bash mini_build_test.sh no-tls enable=eal,x509_crt_gen,sal_file,sm2,sha256,drbg_hash test=x509_crt_gen linux
    bash mini_build_test.sh no-tls enable=eal,x509_crt_gen,ecdsa,curve_nistp256,sha256,drbg_hash test=x509_crt_gen

    ### cert parse ####hitls_x509_verify.c:699
    bash mini_build_test.sh no-tls enable=eal,x509_crt_parse,sal_file,pem,rsa,sha256,drbg_hash test=x509_crt_parse linux
    bash mini_build_test.sh no-tls enable=eal,x509_crt_parse,sal_file,ed25519,drbg_hash test=x509_crt_parse linux
    bash mini_build_test.sh no-tls enable=eal,x509_crt_parse,sal_file,sm2,sha256,drbg_hash test=x509_crt_parse linux
    bash mini_build_test.sh no-tls enable=eal,x509_crt_parse,sal_file,pem,ecdsa,curve_nistp256,curve_nistp384,sha256,drbg_hash test=x509_crt_parse linux

    ### cert chain ####
    bash mini_build_test.sh no-tls enable=eal,x509_vfy,sal_file,pem,rsa,ecdsa,curve_nistp256,curve_nistp384,ed25519,sm2,sha2,drbg_hash test=x509_vfy linux

    ### pkcs12 gen ####
    bash mini_build_test.sh no-tls enable=eal,pkcs12_gen,key_decode,sal_file,pem,rsa,ecdsa,curve_nistp256,ed25519,sm2,drbg_hash,cipher,modes,md,hmac test=pkcs12_gen linux
    bash mini_build_test.sh no-tls enable=eal,pkcs12_parse,sal_file,pem,rsa,ecdsa,curve_nistp256,curve_nistp384,curve_nistp521,ed25519,sm2,cipher,modes,md,drbg_hash,hmac test=pkcs12_parse linux debug
}

parse_option

case $TEST in
    "all")
        test_bsl
        test_md
        test_mac
        test_kdf
        test_cipher
        test_bn
        test_ecc
        test_pkey
        test_tls
        ;;
    "bsl")
        test_bsl
        ;;
    "md")
        test_md
        ;;
    "mac")
        test_mac
        ;;
    "kdf")
        test_kdf
        ;;
    "cipher")
        test_cipher
        ;;
    "bn")
        test_bn
        ;;
    "ecc")
        test_ecc
        ;;
    "pkey")
        test_pkey
        ;;
    "pki")
        test_pki
        ;;
    "tls")
        test_tls
        ;;
    *)
        ;;
esac
