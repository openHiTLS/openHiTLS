/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_CMVP_ISO19790) || defined(HITLS_CRYPTO_CMVP_SM) || defined(HITLS_CRYPTO_CMVP_FIPS)

#include <stdio.h>
#include <string.h>
#include "crypt_cmvp_selftest.h"
#include "cmvp_common.h"
#include "err.h"
#include "crypt_errno.h"
#include "crypt_eal_cipher.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "crypt_local_types.h"
#include "bsl_sal.h"
#include <securec.h>

typedef struct {
    uint32_t id;
    const char *key;
    const char *aad;
    const char *iv;
    const char *plaintext;
    const char *ciphertext;
    const char *tag;
    uint32_t mode;
} CMVP_CIPHER_VECTOR;

// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
static const CMVP_CIPHER_VECTOR CIPHER_VECTOR[] = {
    // CRYPT_CIPHER_AES128_CBC
    {
        .id = CRYPT_CIPHER_AES128_CBC,
        .key = "2b7e151628aed2a6abf7158809cf4f3c",
        .aad = NULL,
        .iv = "000102030405060708090a0b0c0d0e0f",
        .plaintext = "6bc1bee22e409f96e93d7e117393172a",
        .ciphertext = "7649abac8119b246cee98e9b12e9197d",
        .tag = NULL,
        .mode = HCRYPT_MODE_CBC
    },
    // CRYPT_CIPHER_AES192_CBC
    {
        .id = CRYPT_CIPHER_AES192_CBC,
        .key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        .aad = NULL,
        .iv = "000102030405060708090a0b0c0d0e0f",
        .plaintext = "6bc1bee22e409f96e93d7e117393172a",
        .ciphertext = "4f021db243bc633d7178183a9fa071e8",
        .tag = NULL,
        .mode = HCRYPT_MODE_CBC
    },
    // CRYPT_CIPHER_AES256_CBC
    {
        .id = CRYPT_CIPHER_AES256_CBC,
        .key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        .aad = NULL,
        .iv = "000102030405060708090a0b0c0d0e0f",
        .plaintext = "6bc1bee22e409f96e93d7e117393172a",
        .ciphertext = "f58c4c04d6e5f1ba779eabfb5f7bfbd6",
        .tag = NULL,
        .mode = HCRYPT_MODE_CBC
    },
    // CRYPT_CIPHER_AES128_CTR
    {
        .id = CRYPT_CIPHER_AES128_CTR,
        .key = "2b7e151628aed2a6abf7158809cf4f3c",
        .aad = NULL,
        .iv = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        .plaintext = "6bc1bee22e409f96e93d7e117393172a",
        .ciphertext = "874d6191b620e3261bef6864990db6ce",
        .tag = NULL,
        .mode = HCRYPT_MODE_CTR
    },
    // CRYPT_CIPHER_AES192_CTR
    {
        .id = CRYPT_CIPHER_AES192_CTR,
        .key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        .aad = NULL,
        .iv = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        .plaintext = "6bc1bee22e409f96e93d7e117393172a",
        .ciphertext = "1abc932417521ca24f2b0459fe7e6e0b",
        .tag = NULL,
        .mode = HCRYPT_MODE_CTR
    },
    // CRYPT_CIPHER_AES256_CTR
    {
        .id = CRYPT_CIPHER_AES256_CTR,
        .key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        .aad = NULL,
        .iv = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        .plaintext = "6bc1bee22e409f96e93d7e117393172a",
        .ciphertext = "601ec313775789a5b7a7f504bbf3d228",
        .tag = NULL,
        .mode = HCRYPT_MODE_CTR
    },
    // CRYPT_CIPHER_AES128_ECB
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/
    // aes/XTSTestVectors.zip
    {
        .id = CRYPT_CIPHER_AES128_ECB,
        .key = "2b7e151628aed2a6abf7158809cf4f3c",
        .aad = NULL,
        .iv = NULL,
        .plaintext = "6bc1bee22e409f96e93d7e117393172a",
        .ciphertext = "3ad77bb40d7a3660a89ecaf32466ef97",
        .tag = NULL,
        .mode = HCRYPT_MODE_ECB
    },
    // CRYPT_CIPHER_AES192_ECB
    {
        .id = CRYPT_CIPHER_AES192_ECB,
        .key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        .aad = NULL,
        .iv = NULL,
        .plaintext = "6bc1bee22e409f96e93d7e117393172a",
        .ciphertext = "bd334f1d6e45f25ff712a214571fa5cc",
        .tag = NULL,
        .mode = HCRYPT_MODE_ECB
    },
    // CRYPT_CIPHER_AES256_ECB
    {
        .id = CRYPT_CIPHER_AES256_ECB,
        .key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        .aad = NULL,
        .iv = NULL,
        .plaintext = "6bc1bee22e409f96e93d7e117393172a",
        .ciphertext = "f3eed1bdb5d2a03c064b5a7e3db181f8",
        .tag = NULL,
        .mode = HCRYPT_MODE_ECB
    },
    // CRYPT_CIPHER_AES128_XTS
    {
        .id = CRYPT_CIPHER_AES128_XTS,
        .key = "a1b90cba3f06ac353b2c343876081762090923026e91771815f29dab01932f2f",
        .aad = NULL,
        .iv = "4faef7117cda59c66e4b92013e768ad5",
        .plaintext = "ebabce95b14d3c8d6fb350390790311c",
        .ciphertext = "778ae8b43cb98d5a825081d5be471c63",
        .tag = NULL,
        .mode = HCRYPT_MODE_XTS
    },
    // CRYPT_CIPHER_AES256_XTS
    {
        .id = CRYPT_CIPHER_AES256_XTS,
        .key = "e149be00177d76b7c1d85bcbb6b5054ee10b9f51cd73f59e0840628b9e7d854e2e1c0a"
            "b0537186a2a7c314bbc5eb23b6876a26bcdbf9e6b758d1cae053c2f278",
        .aad = NULL,
        .iv = "0ea18818fab95289b1caab4e61349501",
        .plaintext = "f5f101d8e3a7681b1ddb21bd2826b24e32990bca49b39291b5369a9bca277d75",
        .ciphertext = "5bf2479393cc673306fbb15e72600598e33d4d8a470727ce098730fd80afa959",
        .tag = NULL,
        .mode = HCRYPT_MODE_XTS
    },
    // CRYPT_CIPHER_AES128_CCM
    // http://csrc.nist.gov/groups/STM/cavp/documents/mac/ccmtestvectors.zip
    {
        .id = CRYPT_CIPHER_AES128_CCM,
        .key = "f149e41d848f59276cfddd743bafa9a9",
        .aad = "f5827e",
        .iv = "14b756d66fc51134e203d1c6f9",
        .plaintext = "9759e6f21f5a588010f57e6d6eae178d8b20ab59cda66f42",
        .ciphertext = "f634bf00f1f9f1f93f41049d7f3797b05e805f0b14850f4e78e2a23411147a6187da6818506232ee",
        .tag = NULL,
        .mode = HCRYPT_MODE_CCM
    },
    // CRYPT_CIPHER_AES192_CCM
    {
        .id = CRYPT_CIPHER_AES192_CCM,
        .key = "393dcac5a28d77297946d7ab471ae03bd303ba3499e2ce26",
        .aad = "1c8b",
        .iv = "fe7329f343f6e726a90b11ae37",
        .plaintext = "262f4ac988812500cb437f52f0c182148e85a0bec67a2736",
        .ciphertext = "e6d43f822ad168aa9c2e29c07f4592d7bbeb0203f418f3020ecdbc200be353112faf20e2be711908",
        .tag = NULL,
        .mode = HCRYPT_MODE_CCM
    },
    // CRYPT_CIPHER_AES256_CCM
    {
        .id = CRYPT_CIPHER_AES256_CCM,
        .key = "c5a850167a5bfdf56636ce9e56e2952855504e35cc4f5d24ee5e168853be82d8",
        .aad = "4759557e9bab",
        .iv = "c45b165477e8bfa9ca3a1cd3ca",
        .plaintext = "e758796d7db73bccb1697c42df691ac57974b40ca9186a43",
        .ciphertext = "93ad58bd5f4f77ac4f92b0ae16c62489e4074c7f152e2ed8a88179e0d32f4928eff13b4ce2873338",
        .tag = NULL,
        .mode = HCRYPT_MODE_CCM
    },
    // CRYPT_CIPHER_AES128_GCM
    // http://csrc.nist.gov/groups/STM/cavp/documents/mac/gcmtestvectors.zip
    {
        .id = CRYPT_CIPHER_AES128_GCM,
        .key = "07a6be880a58f572dbc2ad74a56db8b6",
        .aad = "de4269feea1a439d6e8990fd6f9f9d5bc67935294425255ea89b6f6772d680fd656b06"
            "581a5d8bc5c017ab532b4a9b83a55fde58cdfb3d2a8fef3aa426bc59d3e32f09d3cc20"
            "b1ceb9a9e349d1068a0aa3d39617fae0582ccef0",
        .iv = "95fc6654e6dc3a8adf5e7a69",
        .plaintext = "7680b48b5d28f38cdeab2d5851769394a3e141b990ec4bdf79a33e5315ac0338",
        .ciphertext = "095635c7e0eac0fc1059e67e1a936b6f72671121f96699fed520e5f8aff777f0",
        .tag = "b2235f6d4bdd7b9c0901711048859d47",
        .mode = HCRYPT_MODE_GCM
    },
    // CRYPT_CIPHER_AES192_GCM
    {
        .id = CRYPT_CIPHER_AES192_GCM,
        .key = "4e2d3d59e95884dc3aab32afdb96938cc6e9016d7f21e95f",
        .aad = "bd0dbced527c4df9e76c67405cfd0536ef45d6a392b789370356d71a12ee0cacbca6d8a8caa96d4c89923ddb6ba96622",
        .iv = "48fd791bf49a798a54fcdc60",
        .plaintext = "8e36651ba5bf9a6f903e01080083feeb",
        .ciphertext = "f96e2cc58714fd512b1fdbeba770b460",
        .tag = "63dfe1bbd756237a43150c82341486",
        .mode = HCRYPT_MODE_GCM
    },
    // CRYPT_CIPHER_AES256_GCM
    {
        .id = CRYPT_CIPHER_AES256_GCM,
        .key = "4c8cacccd8a55ec4222f3ec3996b23c4e86f9ab9c1312d53a7eb9b8891085ad9",
        .aad = "7dc38ba88808f3e0c7c08111e3f305b7f26ebb0f8915ab1d06b6eaa09ec9258fef04f4"
            "0c174d7cf4161653582058e611d667077""cbf0a974b632ed8d486dd807e2d9e8d8ef3"
            "749d2b2105e2a3161fe0b42b09fae30db42958aa94",
        .iv = "d9e80f9ab45c186c846b3605",
        .plaintext = "24ed8a0023a9e11d127488234c285956",
        .ciphertext = "4df94bd82b1b284e2dda6dccbbe5076f",
        .tag = "241e6c864aabc4a99e344a5d",
        .mode = HCRYPT_MODE_GCM
    },
    // CRYPT_CIPHER_CHACHA20_POLY1305
    {
        .id = CRYPT_CIPHER_CHACHA20_POLY1305,
        .key = NULL,
        .aad = NULL,
        .iv = NULL,
        .plaintext = NULL,
        .ciphertext = NULL,
        .tag = NULL,
        .mode = HCRYPT_MODE_CHACHA20_POLY1305
    },
    // CRYPT_CIPHER_SM4_CBC
    // http://c.gb688.cn/bzgk/gb/showGb?type=online&hcno=4F89D833626340B1F71068D25EAC737D
    // GB/T 17964-2021
    {
        .id = CRYPT_CIPHER_SM4_CBC,
        .key = "2b7e151628aed2a6abf7158809cf4f3c",
        .aad = NULL,
        .iv = "000102030405060708090A0b0C0D0E0F",
        .plaintext = "6BC1BEE22E409F96E93D7E117393172A",
        .ciphertext = "AC529AF989A62FCE9CDDC5FFB84125CA",
        .tag = NULL,
        .mode = HCRYPT_MODE_CBC
    },
    // CRYPT_CIPHER_SM4_CBC
    {
        .id = CRYPT_CIPHER_SM4_CBC,
        .key = "2b7e151628aed2a6abf7158809cf4f3c",
        .aad = NULL,
        .iv = "000102030405060708090A0b0C0D0E0F",
        .plaintext = "6BC1BEE22E409F96E93D7E117393172A73F3D6557DC1BA9BF9DD717E53AAF9AC",
        .ciphertext = "AC529AF989A62FCE9CDDC5FFB84125CA2FB185F512E505453C6456C3E81BF507",
        .tag = NULL,
        .mode = HCRYPT_MODE_CBC
    },
    // CRYPT_CIPHER_SM4_XTS
    // GB/T 17964-2021
    {
        .id = CRYPT_CIPHER_SM4_XTS,
        .key = "2b7e151628aed2a6abf7158809cf4f3c000102030405060708090a0b0c0d0e0f",
        .aad = NULL,
        .iv = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        .plaintext = "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17",
        .ciphertext = "E9538251C71D7B80BBE4483FEF497BD12C5C581BD6242FC51E08964FB4F60FDB0BA42F63499279213D318D2C11F6886E903BE7F93A1B3479",
        .tag = NULL,
        .mode = HCRYPT_MODE_XTS
    },
    // CRYPT_CIPHER_SM4_ECB
    // GB/T 17964-2021
    {
        .id = CRYPT_CIPHER_SM4_ECB,
        .key = "2b7e151628aed2a6abf7158809cf4f3c",
        .aad = NULL,
        .iv = NULL,
        .plaintext = "6BC1BEE22E409F96E93D7E117393172A",
        .ciphertext = "A51411ff04a711443891fce7ab842a29",
        .tag = NULL,
        .mode = HCRYPT_MODE_ECB
    },
    // CRYPT_CIPHER_SM4_ECB
    {
        .id = CRYPT_CIPHER_SM4_ECB,
        .key = "2b7e151628aed2a6abf7158809cf4f3c",
        .aad = NULL,
        .iv = NULL,
        .plaintext = "6BC1BEE22E409F96E93D7E117393172ABF570C705E9A8CD9A3268884B47E99C5",
        .ciphertext = "A51411FF04A711443891FCE7AB842A29FA4CF0EB1747BC376CCF06C002BFABC3",
        .tag = NULL,
        .mode = HCRYPT_MODE_ECB
    },
    // CRYPT_CIPHER_SM4_CTR
    // GB/T 17964-2021
    {
        .id = CRYPT_CIPHER_SM4_CTR,
        .key = "2b7e151628aed2a6abf7158809cf4f3c",
        .aad = NULL,
        .iv = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        .plaintext = "6BC1BEE22E409F96E93D7E117393172A",
        .ciphertext = "14AE4A72B97A93CE1216CCD998E371C1",
        .tag = NULL,
        .mode = HCRYPT_MODE_CTR
    },
    // CRYPT_CIPHER_SM4_CTR
    {
        .id = CRYPT_CIPHER_SM4_CTR,
        .key = "2b7e151628aed2a6abf7158809cf4f3c",
        .aad = NULL,
        .iv = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        .plaintext = "6BC1BEE22E409F96E93D7E117393172AF16AC4741C7E907EDB41E3D61976132E",
        .ciphertext = "14AE4A72B97A93CE1216CCD998E371C13FB0A1A86139818FE46FA97FB925BCE4",
        .tag = NULL,
        .mode = HCRYPT_MODE_CTR
    },
    // CRYPT_CIPHER_SM4_GCM
    // https://www.rfc-editor.org/rfc/rfc8998.html
    {
        .id = CRYPT_CIPHER_SM4_GCM,
        .key = "0123456789ABCDEFFEDCBA9876543210",
        .aad = "FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2",
        .iv = "00001234567800000000ABCD",
        .plaintext = "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDEEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFFEEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA",
        .ciphertext = "17F399F08C67D5EE19D0DC9969C4BB7D5FD46FD3756489069157B282BB200735D82710CA5C22F0CCFA7CBF93D496AC15A56834CBCF98C397B4024A2691233B8D",
        .tag = "83DE3541E4C2B58177E065A9BF7B62EC",
        .mode = HCRYPT_MODE_GCM
    },
    // CRYPT_CIPHER_SM4_CFB
    // GB/T 17964-2021
    {
        .id = CRYPT_CIPHER_SM4_CFB,
        .key = "2b7e151628aed2a6abf7158809cf4f3c",
        .aad = NULL,
        .iv = "000102030405060708090A0B0C0D0E0F",
        .plaintext = "6BC1BEE22E409F96E93D7E117393172A",
        .ciphertext = "bc710d762d070b26361da82b54565e46",
        .tag = NULL,
        .mode = HCRYPT_MODE_CFB
    },
    // CRYPT_CIPHER_SM4_CFB
    {
        .id = CRYPT_CIPHER_SM4_CFB,
        .key = "2b7e151628aed2a6abf7158809cf4f3c",
        .aad = NULL,
        .iv = "000102030405060708090A0B0C0D0E0F",
        .plaintext = "6BC1BEE22E409F96E93D7E117393172A790297389526FF2D9312B724753A8416",
        .ciphertext = "BC710D762D070B26361DA82B54565E4673E25F17E11F0122AE6313491365B913",
        .tag = NULL,
        .mode = HCRYPT_MODE_CFB
    },
    // CRYPT_CIPHER_SM4_OFB
    // GB/T 17964-2021
    {
        .id = CRYPT_CIPHER_SM4_OFB,
        .key = "2b7e151628aed2a6abf7158809cf4f3c",
        .aad = NULL,
        .iv = "000102030405060708090A0B0C0D0E0F",
        .plaintext = "6BC1BEE22E409F96E93D7E117393172A",
        .ciphertext = "BC710D762D070B26361DA82B54565E46",
        .tag = NULL,
        .mode = HCRYPT_MODE_OFB
    },
    // CRYPT_CIPHER_SM4_OFB
    {
        .id = CRYPT_CIPHER_SM4_OFB,
        .key = "2b7e151628aed2a6abf7158809cf4f3c",
        .aad = NULL,
        .iv = "000102030405060708090A0B0C0D0E0F",
        .plaintext = "6BC1BEE22E409F96E93D7E117393172AFD21572934B59ABB3E10F3ABB92E6587",
        .ciphertext = "BC710D762D070B26361DA82B54565E4654AC1B561EC23CF484AABF96D960FDF7",
        .tag = NULL,
        .mode = HCRYPT_MODE_OFB
    },
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    // CRYPT_CIPHER_AES128_CFB
    {
        .id = CRYPT_CIPHER_AES128_CFB,
        .key = "2b7e151628aed2a6abf7158809cf4f3c",
        .aad = NULL,
        .iv = "000102030405060708090a0b0c0d0e0f",
        .plaintext = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c8"
                "1c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        .ciphertext = "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b2675"
                "1f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6",
        .tag = NULL,
        .mode = HCRYPT_MODE_CFB
    },
    // CRYPT_CIPHER_AES192_CFB
    {
        .id = CRYPT_CIPHER_AES192_CFB,
        .key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        .aad = NULL,
        .iv = "000102030405060708090a0b0c0d0e0f",
        .plaintext = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c8"
                "1c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        .ciphertext = "cdc80d6fddf18cab34c25909c99a417467ce7f7f81173621961a2b70171d3d7a2e1e"
                "8a1dd59b88b1c8e60fed1efac4c9c05f9f9ca9834fa042ae8fba584b09ff",
        .tag = NULL,
        .mode = HCRYPT_MODE_CFB
    },
    // CRYPT_CIPHER_AES256_CFB
    {
        .id = CRYPT_CIPHER_AES256_CFB,
        .key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        .aad = NULL,
        .iv = "000102030405060708090a0b0c0d0e0f",
        .plaintext = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c8"
                "1c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        .ciphertext = "dc7e84bfda79164b7ecd8486985d386039ffed143b28b1c832113c6331e5407bdf10"
                "132415e54b92a13ed0a8267ae2f975a385741ab9cef82031623d55b1e471",
        .tag = NULL,
        .mode = HCRYPT_MODE_CFB
    },
    // CRYPT_CIPHER_AES128_OFB
    {
        .id = CRYPT_CIPHER_AES128_OFB,
        .key = "2b7e151628aed2a6abf7158809cf4f3c",
        .aad = NULL,
        .iv = "000102030405060708090a0b0c0d0e0f",
        .plaintext = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c8"
                "1c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        .ciphertext = "3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed8259740"
                "051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e",
        .tag = NULL,
        .mode = HCRYPT_MODE_OFB
    },
    // CRYPT_CIPHER_AES192_OFB
    {
        .id = CRYPT_CIPHER_AES192_OFB,
        .key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        .aad = NULL,
        .iv = "000102030405060708090a0b0c0d0e0f",
        .plaintext = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c8"
                "1c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        .ciphertext = "cdc80d6fddf18cab34c25909c99a4174fcc28b8d4c63837c09e81700c11004018d9a"
                "9aeac0f6596f559c6d4daf59a5f26d9f200857ca6c3e9cac524bd9acc92a",
        .tag = NULL,
        .mode = HCRYPT_MODE_OFB
    },
    // CRYPT_CIPHER_AES256_OFB
    {
        .id = CRYPT_CIPHER_AES256_OFB,
        .key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        .aad = NULL,
        .iv = "000102030405060708090a0b0c0d0e0f",
        .plaintext = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c8"
                "1c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        .ciphertext = "dc7e84bfda79164b7ecd8486985d38604febdc6740d20b3ac88f6ad82a4fb08d71ab"
                "47a086e86eedf39d1c5bba97c4080126141d67f37be8538f5a8be740e484",
        .tag = NULL,
        .mode = HCRYPT_MODE_OFB
    }
};

typedef struct {
    CRYPT_Data key;
    CRYPT_Data iv;
    CRYPT_Data aad;
    CRYPT_Data plainText;
    CRYPT_Data cipherText;
    CRYPT_Data tag;
} CIPHER_SELFTEST_DATA;

bool CipherEnc(void *libCtx, const char *attrName, CRYPT_CIPHER_AlgId id, CIPHER_SELFTEST_DATA data)
{
    bool ret = false;
    CRYPT_EAL_CipherCtx *ctx = NULL;
    uint32_t finLen;
    uint32_t len = data.cipherText.len;
    uint8_t *out = BSL_SAL_Malloc(len);
    GOTO_ERR_IF_TRUE(out == NULL, CRYPT_MEM_ALLOC_FAIL);
    memset_s(out, len, 0, len);
    ctx = CRYPT_EAL_ProviderCipherNewCtx(libCtx, id, attrName);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_CipherInit(ctx, data.key.data, data.key.len, data.iv.data, data.iv.len, true) !=
        CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_CipherUpdate(ctx, data.plainText.data, data.plainText.len, out, &len) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(data.cipherText.len < len, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    finLen = data.cipherText.len - len;
    CRYPT_EAL_CipherFinal(ctx, out + len, &finLen);
    GOTO_ERR_IF_TRUE(memcmp(out, data.cipherText.data, data.cipherText.len) != 0, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    ret = true;
ERR:
    BSL_SAL_Free(out);
    CRYPT_EAL_CipherFreeCtx(ctx);
    return ret;
}

bool CipherDec(void *libCtx, const char *attrName, CRYPT_CIPHER_AlgId id, CIPHER_SELFTEST_DATA data)
{
    bool ret = false;
    CRYPT_EAL_CipherCtx *ctx = NULL;
    uint32_t finLen;
    uint32_t len = data.plainText.len;
    uint8_t *out = BSL_SAL_Malloc(len);
    GOTO_ERR_IF_TRUE(out == NULL, CRYPT_MEM_ALLOC_FAIL);
    ctx = CRYPT_EAL_ProviderCipherNewCtx(libCtx, id, attrName);
    GOTO_ERR_IF_TRUE(ctx == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_CipherInit(ctx, data.key.data, data.key.len, data.iv.data, data.iv.len, false) !=
        CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_CipherUpdate(ctx, data.cipherText.data, data.cipherText.len, out, &len) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(data.plainText.len < len, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    finLen = data.plainText.len - len;
    CRYPT_EAL_CipherFinal(ctx, out + len, &finLen);
    GOTO_ERR_IF_TRUE(memcmp(out, data.plainText.data, data.plainText.len) != 0, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    ret = true;
ERR:
    BSL_SAL_Free(out);
    CRYPT_EAL_CipherFreeCtx(ctx);
    return ret;
}

bool AesAeadEnc(void *libCtx, const char *attrName, const CMVP_CIPHER_VECTOR *cipherVec, CIPHER_SELFTEST_DATA data)
{
    bool ret = false;
    uint64_t msgLen = data.plainText.len;
    uint32_t cipherLen = data.cipherText.len;
    uint8_t *cipher = NULL;
    uint32_t tagLen;
    uint8_t *tag = NULL;
    uint32_t finLen;
    CRYPT_EAL_CipherCtx *ctx = NULL;

    cipher = BSL_SAL_Malloc(cipherLen);
    GOTO_ERR_IF_TRUE(cipher == NULL, CRYPT_MEM_ALLOC_FAIL);
    if (cipherVec->mode == HCRYPT_MODE_GCM) {
        tagLen = data.tag.len;
        tag = BSL_SAL_Malloc(tagLen);
        GOTO_ERR_IF_TRUE(tag == NULL, CRYPT_ERR_ALGID);
    } else {
        tagLen = data.cipherText.len - data.plainText.len;
    }

    ctx = CRYPT_EAL_ProviderCipherNewCtx(libCtx, cipherVec->id, attrName);
    GOTO_ERR_IF_TRUE(ctx == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_CipherInit(ctx, data.key.data, data.key.len, data.iv.data, data.iv.len, true) !=
        CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    if (cipherVec->mode == HCRYPT_MODE_CCM) {
        GOTO_ERR_IF_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN, &msgLen, sizeof(msgLen)) != CRYPT_SUCCESS,
            CRYPT_CMVP_ERR_ALGO_SELFTEST);
    }
    GOTO_ERR_IF_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, data.aad.data, data.aad.len) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    cipherLen = data.plainText.len;
    GOTO_ERR_IF_TRUE(CRYPT_EAL_CipherUpdate(ctx, data.plainText.data, data.plainText.len, cipher, &cipherLen) !=
        CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(data.cipherText.len < cipherLen, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    finLen = data.cipherText.len - cipherLen;
    if (cipherVec->mode != HCRYPT_MODE_CCM && cipherVec->mode != HCRYPT_MODE_GCM) {
        GOTO_ERR_IF_TRUE(CRYPT_EAL_CipherFinal(ctx, cipher + cipherLen, &finLen) != CRYPT_SUCCESS,
            CRYPT_CMVP_ERR_ALGO_SELFTEST);
    }
    if (cipherVec->mode == HCRYPT_MODE_CCM) {
        GOTO_ERR_IF_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, cipher + msgLen, tagLen) != CRYPT_SUCCESS,
            CRYPT_CMVP_ERR_ALGO_SELFTEST);
        GOTO_ERR_IF_TRUE(memcmp(cipher, data.cipherText.data, data.cipherText.len) != 0, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    } else {
        GOTO_ERR_IF_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag, tagLen) != CRYPT_SUCCESS,
            CRYPT_CMVP_ERR_ALGO_SELFTEST);
        GOTO_ERR_IF_TRUE(memcmp(cipher, data.cipherText.data, data.cipherText.len) != 0, CRYPT_CMVP_ERR_ALGO_SELFTEST);
        GOTO_ERR_IF_TRUE(memcmp(tag, data.tag.data, data.tag.len) != 0, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    }

    ret = true;
ERR:
    BSL_SAL_Free(tag);
    BSL_SAL_Free(cipher);
    CRYPT_EAL_CipherFreeCtx(ctx);
    return ret;
}

bool AesAeadDec(void *libCtx, const char *attrName, const CMVP_CIPHER_VECTOR *cipherVec, CIPHER_SELFTEST_DATA data)
{
    bool ret = false;
    uint32_t tagLen;
    uint8_t *tag = NULL;
    uint64_t msgLen = data.plainText.len;
    uint32_t plainLen = data.plainText.len;
    uint8_t *plain = NULL;
    CRYPT_EAL_CipherCtx *ctx = NULL;

    plain = BSL_SAL_Malloc(plainLen);
    GOTO_ERR_IF_TRUE(plain == NULL, CRYPT_MEM_ALLOC_FAIL);
    if (cipherVec->mode == HCRYPT_MODE_CCM) {
        tagLen = data.cipherText.len - data.plainText.len;
    } else {
        tagLen = data.tag.len;
    }
    tag = BSL_SAL_Malloc(tagLen);
    GOTO_ERR_IF_TRUE(tag == NULL, CRYPT_MEM_ALLOC_FAIL);

    ctx = CRYPT_EAL_ProviderCipherNewCtx(libCtx, cipherVec->id, attrName);
    GOTO_ERR_IF_TRUE(ctx == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_CipherInit(ctx, data.key.data, data.key.len, data.iv.data, data.iv.len, false) !=
        CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    if (cipherVec->mode == HCRYPT_MODE_CCM) {
        GOTO_ERR_IF_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN, &msgLen, sizeof(msgLen)) != CRYPT_SUCCESS,
            CRYPT_CMVP_ERR_ALGO_SELFTEST);
    }
    GOTO_ERR_IF_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, data.aad.data, data.aad.len) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_CipherUpdate(ctx, data.cipherText.data, data.plainText.len, plain, &plainLen) !=
        CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(data.plainText.len != plainLen, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(memcmp(plain, data.plainText.data, data.plainText.len) != 0, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag, tagLen) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    if (cipherVec->mode == HCRYPT_MODE_CCM) {
        GOTO_ERR_IF_TRUE(memcmp(tag, data.cipherText.data + msgLen, tagLen) != 0, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    } else {
        GOTO_ERR_IF_TRUE(memcmp(tag, data.tag.data, tagLen) != 0, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    }
    ret = true;
ERR:
    BSL_SAL_Free(tag);
    BSL_SAL_Free(plain);
    CRYPT_EAL_CipherFreeCtx(ctx);
    return ret;
}

const CMVP_CIPHER_VECTOR *FindCipherVectorById(CRYPT_CIPHER_AlgId id)
{
    uint32_t num = sizeof(CIPHER_VECTOR) / sizeof(CIPHER_VECTOR[0]);
    const CMVP_CIPHER_VECTOR *cipherVec = NULL;

    for (uint32_t i = 0; i < num; i++) {
        if (CIPHER_VECTOR[i].id == id) {
            cipherVec = &CIPHER_VECTOR[i];
            return cipherVec;
        }
    }

    return NULL;
}
static bool CRYPT_CMVP_SelftestCipherInternal(void *libCtx, const char *attrName, CRYPT_CIPHER_AlgId id)
{
    const CMVP_CIPHER_VECTOR *cipherVec = FindCipherVectorById(id);
    if (cipherVec == NULL || cipherVec->key == NULL) {
        return false;
    }

    bool ret = false;
    CIPHER_SELFTEST_DATA data = {
        { NULL, 0 }, { NULL, 0 }, { NULL, 0 }, { NULL, 0 }, { NULL, 0 }, { NULL, 0 },
    };
    data.key.data = CMVP_StringsToBins(cipherVec->key, &(data.key.len));
    GOTO_ERR_IF_TRUE(data.key.data == NULL, CRYPT_CMVP_COMMON_ERR);
    if (cipherVec->iv != NULL) {
        data.iv.data = CMVP_StringsToBins(cipherVec->iv, &(data.iv.len));
        GOTO_ERR_IF_TRUE(data.iv.data == NULL, CRYPT_CMVP_COMMON_ERR);
    }
    data.plainText.data = CMVP_StringsToBins(cipherVec->plaintext, &(data.plainText.len));
    GOTO_ERR_IF_TRUE(data.plainText.data == NULL, CRYPT_CMVP_COMMON_ERR);
    data.cipherText.data = CMVP_StringsToBins(cipherVec->ciphertext, &(data.cipherText.len));
    GOTO_ERR_IF_TRUE(data.cipherText.data == NULL, CRYPT_CMVP_COMMON_ERR);
    if (cipherVec->aad != NULL) {
        data.aad.data = CMVP_StringsToBins(cipherVec->aad, &(data.aad.len));
        GOTO_ERR_IF_TRUE(data.aad.data == NULL, CRYPT_CMVP_COMMON_ERR);
    }
    if (cipherVec->tag != NULL) {
        data.tag.data = CMVP_StringsToBins(cipherVec->tag, &(data.tag.len));
        GOTO_ERR_IF_TRUE(data.tag.data == NULL, CRYPT_CMVP_COMMON_ERR);
    }

    if (cipherVec->mode == HCRYPT_MODE_CCM || cipherVec->mode == HCRYPT_MODE_GCM) {
        GOTO_ERR_IF_TRUE(AesAeadEnc(libCtx, attrName, cipherVec, data) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
        GOTO_ERR_IF_TRUE(AesAeadDec(libCtx, attrName, cipherVec, data) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    } else {
        GOTO_ERR_IF_TRUE(CipherEnc(libCtx, attrName, id, data) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
        GOTO_ERR_IF_TRUE(CipherDec(libCtx, attrName, id, data) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    }

    ret = true;
ERR:
    BSL_SAL_Free(data.key.data);
    BSL_SAL_Free(data.iv.data);
    BSL_SAL_Free(data.cipherText.data);
    BSL_SAL_Free(data.plainText.data);
    BSL_SAL_Free(data.aad.data);
    BSL_SAL_Free(data.tag.data);
    return ret;
}

bool CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AlgId id)
{
    return CRYPT_CMVP_SelftestCipherInternal(NULL, NULL, id);
}

bool CRYPT_CMVP_SelftestProviderCipher(void *libCtx, const char *attrName, CRYPT_CIPHER_AlgId id)
{
    return CRYPT_CMVP_SelftestCipherInternal(libCtx, attrName, id);
}

#endif /* HITLS_CRYPTO_CMVP_ISO19790 || HITLS_CRYPTO_CMVP_SM || HITLS_CRYPTO_CMVP_FIPS */
