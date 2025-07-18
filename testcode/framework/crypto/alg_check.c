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

#include <stdbool.h>
#include "helper.h"

#include "crypt_algid.h"
#include "hitls_build.h"
#include "crypto_test_util.h"

#define ERR_ID (-1)

typedef struct {
    int id;
    int offset;
} MdAlgMap;

static MdAlgMap g_mdAlgMap[] = {
    { CRYPT_MD_MD5, 0 },
    { CRYPT_MD_SHA1, 1 },
    { CRYPT_MD_SHA224, 2 },
    { CRYPT_MD_SHA256, 3 },
    { CRYPT_MD_SHA384, 4 },
    { CRYPT_MD_SHA512, 5 },
    { CRYPT_MD_SHA3_224, 6 },
    { CRYPT_MD_SHA3_256, 7 },
    { CRYPT_MD_SHA3_384, 8 },
    { CRYPT_MD_SHA3_512, 9 },
    { CRYPT_MD_SHAKE128, 10 },
    { CRYPT_MD_SHAKE256, 11 },
    { CRYPT_MD_SM3, 12 },
};

#define MD_ALG_MAP_CNT ((int)(sizeof(g_mdAlgMap) / sizeof(MdAlgMap)))

// All MD algorithms are available by default.
static int g_mdDisableTable[MD_ALG_MAP_CNT] = { 0 };
static bool g_isInitMd = false;

static int g_avlRandAlg = -1;
static bool g_isInitRandAlg = false;

static void InitMdTable(void)
{
    if (g_isInitMd) {
        return;
    }
#ifndef HITLS_CRYPTO_MD5
    g_mdDisableTable[0] = 1;
#endif
#ifndef HITLS_CRYPTO_SHA1
    g_mdDisableTable[1] = 1;
#endif
#ifndef HITLS_CRYPTO_SHA224
    g_mdDisableTable[2] = 1;
#endif
#ifndef HITLS_CRYPTO_SHA256
    g_mdDisableTable[3] = 1;
#endif
#ifndef HITLS_CRYPTO_SHA384
    g_mdDisableTable[4] = 1;
#endif
#ifndef HITLS_CRYPTO_SHA512
    g_mdDisableTable[5] = 1;
#endif
#ifndef HITLS_CRYPTO_SHA3
    g_mdDisableTable[6] = 1;
    g_mdDisableTable[7] = 1;
    g_mdDisableTable[8] = 1;
    g_mdDisableTable[9] = 1;
    g_mdDisableTable[10] = 1;
    g_mdDisableTable[11] = 1;
#endif
#ifndef HITLS_CRYPTO_SM3
    g_mdDisableTable[12] = 1;
#endif
    g_isInitMd = true;
}

static bool IsDrbgHashDisabled(void)
{
#ifdef HITLS_CRYPTO_DRBG_HASH
    return false;
#else
    return true;
#endif
}

static bool IsDrbgHmacDisabled(void)
{
#ifdef HITLS_CRYPTO_DRBG_HMAC
    return false;
#else
    return true;
#endif
}

static bool IsDrbgCtrDisabled(void)
{
#ifdef HITLS_CRYPTO_DRBG_CTR
    return false;
#else
    return true;
#endif
}

static bool IsDrbgCtrSm4Disabled()
{
#if defined(HITLS_CRYPTO_DRBG_CTR) && defined(HITLS_CRYPTO_DRBG_GM) && defined(HITLS_CRYPTO_SM4)
    return false;
#else
    return true;
#endif
}


static int GetDrbgHashAlgId(void)
{
    InitMdTable();
    // CRYPT_RAND_SHA256 is preferred (224 depends on 256).
    if (g_mdDisableTable[3] == 0) {
        return CRYPT_RAND_SHA256;
    }

    if (g_mdDisableTable[5] == 0) {
        return CRYPT_RAND_SHA512;
    }

    if (g_mdDisableTable[1] == 0) {
        return CRYPT_RAND_SHA1;
    }
    if (g_mdDisableTable[12] == 0) {
        return CRYPT_RAND_SM3;
    }
    return ERR_ID;
}

static int GetDrbgHmacAlgId(void)
{
    InitMdTable();
    if (g_mdDisableTable[3] == 0) {
        return CRYPT_RAND_HMAC_SHA256;
    }

    if (g_mdDisableTable[5] == 0) {
        return CRYPT_RAND_HMAC_SHA512;
    }

    if (g_mdDisableTable[1] == 0) {
        return CRYPT_RAND_HMAC_SHA1;
    }
    return ERR_ID;
}

bool IsMdAlgDisabled(int id)
{
    InitMdTable();
    bool res = false;  // By default, this algorithm is not disabled.

    for (int i = 0; i < MD_ALG_MAP_CNT; i++) {
        if (id == g_mdAlgMap[i].id) {
            res = g_mdDisableTable[g_mdAlgMap[i].offset] == 1;
            break;
        }
    }
    return res;
}

bool IsHmacAlgDisabled(int id)
{
#ifdef HITLS_CRYPTO_HMAC
    InitMdTable();
    switch (id) {
        case CRYPT_MAC_HMAC_MD5:
            return g_mdDisableTable[0] == 1;
        case CRYPT_MAC_HMAC_SHA1:
            return g_mdDisableTable[1] == 1;
        case CRYPT_MAC_HMAC_SHA224:
            return g_mdDisableTable[2] == 1;
        case CRYPT_MAC_HMAC_SHA256:
            return g_mdDisableTable[3] == 1;
        case CRYPT_MAC_HMAC_SHA384:
            return g_mdDisableTable[4] == 1;
        case CRYPT_MAC_HMAC_SHA512:
            return g_mdDisableTable[5] == 1;
        case CRYPT_MAC_HMAC_SHA3_224:
            return g_mdDisableTable[6] == 1;
        case CRYPT_MAC_HMAC_SHA3_256:
            return g_mdDisableTable[7] == 1;
        case CRYPT_MAC_HMAC_SHA3_384:
            return g_mdDisableTable[8] == 1;
        case CRYPT_MAC_HMAC_SHA3_512:
            return g_mdDisableTable[9] == 1;
        case CRYPT_MAC_HMAC_SM3:
            return g_mdDisableTable[12] == 1;
        default:
            return false;
    }
#else
    (void)id;
    return false;
#endif
}

bool IsMacAlgDisabled(int id)
{
    switch (id) {
        case CRYPT_MAC_HMAC_MD5:
        case CRYPT_MAC_HMAC_SHA1:
        case CRYPT_MAC_HMAC_SHA224:
        case CRYPT_MAC_HMAC_SHA256:
        case CRYPT_MAC_HMAC_SHA384:
        case CRYPT_MAC_HMAC_SHA512:
        case CRYPT_MAC_HMAC_SM3:
            return IsHmacAlgDisabled(id);
        case CRYPT_MAC_CBC_MAC_SM4:
#ifdef HITLS_CRYPTO_CBC_MAC
            return false;
#else
            return true;
#endif
        default:
            return false;
    }
}

bool IsDrbgHashAlgDisabled(int id)
{
    if (IsDrbgHashDisabled()) {
        return true;
    }
    InitMdTable();
    switch (id) {
        case CRYPT_RAND_SHA1:
            return g_mdDisableTable[1] == 1;
        case CRYPT_RAND_SHA224:
            return g_mdDisableTable[2] == 1;
        case CRYPT_RAND_SHA256:
            return g_mdDisableTable[3] == 1;
        case CRYPT_RAND_SHA384:
            return g_mdDisableTable[4] == 1;
        case CRYPT_RAND_SHA512:
            return g_mdDisableTable[5] == 1;
        case CRYPT_RAND_SM3:
#ifdef HITLS_CRYPTO_DRBG_GM
            return g_mdDisableTable[12] == 1;
#else
            return true;
#endif
        default:
            return false;
    }
}

bool IsDrbgHmacAlgDisabled(int id)
{
    if (IsDrbgHmacDisabled()) {
        return true;
    }
    InitMdTable();
    switch (id) {
        case CRYPT_RAND_HMAC_SHA1:
            return g_mdDisableTable[1] == 1;
        case CRYPT_RAND_HMAC_SHA224:
            return g_mdDisableTable[2] == 1;
        case CRYPT_RAND_HMAC_SHA256:
            return g_mdDisableTable[3] == 1;
        case CRYPT_RAND_HMAC_SHA384:
            return g_mdDisableTable[4] == 1;
        case CRYPT_RAND_HMAC_SHA512:
            return g_mdDisableTable[5] == 1;
        default:
            return false;
    }
}

int GetAvailableRandAlgId(void)
{
    if (g_isInitRandAlg) {
        return g_avlRandAlg;
    }
    g_isInitRandAlg = true;

    if (!IsDrbgHashDisabled()) {
        g_avlRandAlg = GetDrbgHashAlgId();
        if (g_avlRandAlg != ERR_ID) {
            return g_avlRandAlg;
        }
    }

    if (!IsDrbgHmacDisabled()) {
        g_avlRandAlg = GetDrbgHmacAlgId();
        if (g_avlRandAlg != ERR_ID) {
            return g_avlRandAlg;
        }
    }

    if (!IsDrbgCtrDisabled()) {
        g_avlRandAlg = CRYPT_RAND_AES256_CTR;
        return g_avlRandAlg;
    }

    return g_avlRandAlg;
}

bool IsRandAlgDisabled(int id)
{
    switch (id) {
        case CRYPT_RAND_SHA1:
        case CRYPT_RAND_SHA224:
        case CRYPT_RAND_SHA256:
        case CRYPT_RAND_SHA384:
        case CRYPT_RAND_SHA512:
        case CRYPT_RAND_SM3:
            return IsDrbgHashAlgDisabled(id);
        case CRYPT_RAND_HMAC_SHA1:
        case CRYPT_RAND_HMAC_SHA224:
        case CRYPT_RAND_HMAC_SHA256:
        case CRYPT_RAND_HMAC_SHA384:
        case CRYPT_RAND_HMAC_SHA512:
            return IsDrbgHmacAlgDisabled(id);
        case CRYPT_RAND_AES128_CTR:
        case CRYPT_RAND_AES192_CTR:
        case CRYPT_RAND_AES256_CTR:
        case CRYPT_RAND_AES128_CTR_DF:
        case CRYPT_RAND_AES192_CTR_DF:
        case CRYPT_RAND_AES256_CTR_DF:
            return IsDrbgCtrDisabled();
        case CRYPT_RAND_SM4_CTR_DF:
            return IsDrbgCtrSm4Disabled();
        default:
            return false;
    }
    return false;
}

bool IsAesAlgDisabled(int id)
{
#ifdef HITLS_CRYPTO_AES
    switch (id) {
#ifndef HITLS_CRYPTO_CBC
        case CRYPT_CIPHER_AES128_CBC:
        case CRYPT_CIPHER_AES192_CBC:
        case CRYPT_CIPHER_AES256_CBC:
            return true;
#endif
#ifndef HITLS_CRYPTO_ECB
        case CRYPT_CIPHER_AES128_ECB:
        case CRYPT_CIPHER_AES192_ECB:
        case CRYPT_CIPHER_AES256_ECB:
            return true;
#endif
#ifndef HITLS_CRYPTO_CTR
        case CRYPT_CIPHER_AES128_CTR:
        case CRYPT_CIPHER_AES192_CTR:
        case CRYPT_CIPHER_AES256_CTR:
            return true;
#endif
#ifndef HITLS_CRYPTO_CCM
        case CRYPT_CIPHER_AES128_CCM:
        case CRYPT_CIPHER_AES192_CCM:
        case CRYPT_CIPHER_AES256_CCM:
            return true;
#endif
#ifndef HITLS_CRYPTO_GCM
        case CRYPT_CIPHER_AES128_GCM:
        case CRYPT_CIPHER_AES192_GCM:
        case CRYPT_CIPHER_AES256_GCM:
            return true;
#endif
#ifndef HITLS_CRYPTO_CFB
        case CRYPT_CIPHER_AES128_CFB:
        case CRYPT_CIPHER_AES192_CFB:
        case CRYPT_CIPHER_AES256_CFB:
            return true;
#endif
#ifndef HITLS_CRYPTO_OFB
        case CRYPT_CIPHER_AES128_OFB:
        case CRYPT_CIPHER_AES192_OFB:
        case CRYPT_CIPHER_AES256_OFB:
            return true;
#endif
#ifndef HITLS_CRYPTO_XTS
        case CRYPT_CIPHER_AES128_XTS:
        case CRYPT_CIPHER_AES256_XTS:
            return true;
#endif
        default:
            return false;  // Unsupported algorithm ID
    }
#else
    (void)id;
    return true;
#endif
}

bool IsSm4AlgDisabled(int id)
{
#ifdef HITLS_CRYPTO_SM4
    switch (id) {
#ifndef HITLS_CRYPTO_XTS
        case CRYPT_CIPHER_SM4_XTS:
            return true;
#endif
#ifndef HITLS_CRYPTO_CBC
        case CRYPT_CIPHER_SM4_CBC:
            return true;
#endif
#ifndef HITLS_CRYPTO_ECB
        case CRYPT_CIPHER_SM4_ECB:
            return true;
#endif
#ifndef HITLS_CRYPTO_CTR
        case CRYPT_CIPHER_SM4_CTR:
            return true;
#endif
#ifndef HITLS_CRYPTO_GCM
        case CRYPT_CIPHER_SM4_GCM:
            return true;
#endif
#ifndef HITLS_CRYPTO_CFB
        case CRYPT_CIPHER_SM4_CFB:
            return true;
#endif
#ifndef HITLS_CRYPTO_OFB
        case CRYPT_CIPHER_SM4_OFB:
            return true;
#endif
#ifndef HITLS_CRYPTO_HCTR
        case CRYPT_CIPHER_SM4_HCTR:
            return true;
#endif
        default:
            return false;  // Unsupported algorithm ID
    }
#else
    (void)id;
    return true;
#endif
}

bool IsCipherAlgDisabled(int id)
{
    switch (id) {
        case CRYPT_CIPHER_AES128_CBC:
        case CRYPT_CIPHER_AES192_CBC:
        case CRYPT_CIPHER_AES256_CBC:
        case CRYPT_CIPHER_AES128_CTR:
        case CRYPT_CIPHER_AES192_CTR:
        case CRYPT_CIPHER_AES256_CTR:
        case CRYPT_CIPHER_AES128_CCM:
        case CRYPT_CIPHER_AES192_CCM:
        case CRYPT_CIPHER_AES256_CCM:
        case CRYPT_CIPHER_AES128_GCM:
        case CRYPT_CIPHER_AES192_GCM:
        case CRYPT_CIPHER_AES256_GCM:
        case CRYPT_CIPHER_AES128_CFB:
        case CRYPT_CIPHER_AES192_CFB:
        case CRYPT_CIPHER_AES256_CFB:
        case CRYPT_CIPHER_AES128_OFB:
        case CRYPT_CIPHER_AES192_OFB:
        case CRYPT_CIPHER_AES256_OFB:
            return IsAesAlgDisabled(id);
        case CRYPT_CIPHER_CHACHA20_POLY1305:
#if !defined(HITLS_CRYPTO_CHACHA20) && !defined(HITLS_CRYPTO_CHACHA20POLY1305)
            return true;
#else
            return false;
#endif
        case CRYPT_CIPHER_SM4_XTS:
        case CRYPT_CIPHER_SM4_CBC:
        case CRYPT_CIPHER_SM4_CTR:
        case CRYPT_CIPHER_SM4_GCM:
        case CRYPT_CIPHER_SM4_CFB:
        case CRYPT_CIPHER_SM4_OFB:
        case CRYPT_CIPHER_SM4_HCTR:
            return IsSm4AlgDisabled(id);
        default:
            return false;
    }
}

bool IsCmacAlgDisabled(int id)
{
#ifdef HITLS_CRYPTO_CMAC
    switch (id) {
#ifndef HITLS_CRYPTO_CMAC_AES
        case CRYPT_MAC_CMAC_AES128:
        case CRYPT_MAC_CMAC_AES192:
        case CRYPT_MAC_CMAC_AES256:
            return true;
#endif
#ifndef HITLS_CRYPTO_CMAC_SM4
        case CRYPT_MAC_CMAC_SM4:
            return true;
#endif
        default:
            return false;  // Unsupported algorithm ID
    }
#else
    (void)id;
    return true;
#endif
}

bool IsCurveDisabled(int eccId)
{
    switch (eccId) {
#ifdef HITLS_CRYPTO_CURVE_NISTP224
        case CRYPT_ECC_NISTP224:
            return false;
#endif
#ifdef HITLS_CRYPTO_CURVE_NISTP256
        case CRYPT_ECC_NISTP256:
            return false;
#endif
#ifdef HITLS_CRYPTO_CURVE_NISTP384
        case CRYPT_ECC_NISTP384:
            return false;
#endif
#ifdef HITLS_CRYPTO_CURVE_NISTP521
        case CRYPT_ECC_NISTP521:
            return false;
#endif
#ifdef HITLS_CRYPTO_CURVE_BP256R1
        case CRYPT_ECC_BRAINPOOLP256R1:
            return false;
#endif
#ifdef HITLS_CRYPTO_CURVE_BP384R1
        case CRYPT_ECC_BRAINPOOLP384R1:
            return false;
#endif
#ifdef HITLS_CRYPTO_CURVE_BP512R1
        case CRYPT_ECC_BRAINPOOLP512R1:
            return false;
#endif
#ifdef HITLS_CRYPTO_CURVE_192WAPI
        case CRYPT_ECC_192WAPI:
            return false;
#endif
        default:
            return true;
    }
}

bool IsCurve25519AlgDisabled(int id)
{
    if (id == CRYPT_PKEY_ED25519) {
#ifndef HITLS_CRYPTO_ED25519
        return true;
#else
        return false;
#endif
    }
    if (id == CRYPT_PKEY_X25519) {
#ifndef HITLS_CRYPTO_X25519
        return true;
#else
        return false;
#endif
    }
    return false;  // Unsupported algorithm ID
}