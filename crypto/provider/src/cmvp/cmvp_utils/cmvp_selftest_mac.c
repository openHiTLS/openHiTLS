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

#include <string.h>
#include "crypt_cmvp_selftest.h"
#include "cmvp_common.h"
#include "err.h"
#include "crypt_errno.h"
#include "crypt_eal_mac.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "bsl_sal.h"
#include "crypt_local_types.h"

#define MAC_TYPE_HMAC_CMAC 1
#define MAC_TYPE_GMAC 2
#define MAC_TYPE_CBC_MAC 3

typedef struct {
    uint32_t id;
    const char *key;
    const char *msg;
    const char *mac;
    const char *iv;
    uint32_t type;
} CMVP_MAC_VECTOR;

static const CMVP_MAC_VECTOR MAC_VECTOR[] = {
    // CRYPT_MAC_HMAC_MD5
    // https://datatracker.ietf.org/doc/html/rfc2202
    {
        .id = CRYPT_MAC_HMAC_MD5,
        .key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        .msg = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
        .mac = "56be34521d144c88dbb8c733f0e8b3f6",
        .iv = NULL,
        .type = MAC_TYPE_HMAC_CMAC
    },
    // CRYPT_MAC_HMAC_SHA1
    // https://datatracker.ietf.org/doc/html/rfc2202
    {
        .id = CRYPT_MAC_HMAC_SHA1,
        .key = "0102030405060708090a0b0c0d0e0f10111213141516171819",
        .msg = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        .mac = "4c9007f4026250c6bc8414f9bf50c86c2d7235da",
        .iv = NULL,
        .type = MAC_TYPE_HMAC_CMAC
    },
    // CRYPT_MAC_HMAC_SHA224
    // https://datatracker.ietf.org/doc/html/rfc4231.html#page-4
    {
        .id = CRYPT_MAC_HMAC_SHA224,
        .key = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        .msg = "4869205468657265",
        .mac = "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22",
        .iv = NULL,
        .type = MAC_TYPE_HMAC_CMAC
    },
    // CRYPT_MAC_HMAC_SHA256
    // https://datatracker.ietf.org/doc/html/rfc4231.html#page-4
    {
        .id = CRYPT_MAC_HMAC_SHA256,
        .key = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        .msg = "4869205468657265",
        .mac = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        .iv = NULL,
        .type = MAC_TYPE_HMAC_CMAC
    },
    // CRYPT_MAC_HMAC_SHA384
    // https://datatracker.ietf.org/doc/html/rfc4231.html#page-4
    {
        .id = CRYPT_MAC_HMAC_SHA384,
        .key = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        .msg = "4869205468657265",
        .mac = "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
        .iv = NULL,
        .type = MAC_TYPE_HMAC_CMAC
    },
    // CRYPT_MAC_HMAC_SHA512
    // https://datatracker.ietf.org/doc/html/rfc4231.html#page-4
    {
        .id = CRYPT_MAC_HMAC_SHA512,
        .key = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        .msg = "4869205468657265",
        .mac = "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833"
            "b7d6b8a702038b274eaea3f4e4be9d914""eeb61f1702e696c203a126854",
        .iv = NULL,
        .type = MAC_TYPE_HMAC_CMAC
    },
    // CRYPT_MAC_HMAC_SM3
    {
        .id = CRYPT_MAC_HMAC_SM3,
        .key = "00112233445566778899aabbccddeeff",
        .msg = "6162636465666768696A6B6C6D6E6F707172737475767778797A", // abcdefghijklmnopqrstuvwxyz
        .mac = "a51ce58c52ae29edd66a53e6aaf0745bf4fedbde899973b2d817290e646df87e",
        .iv = NULL,
        .type = MAC_TYPE_HMAC_CMAC
    },
    // CRYPT_MAC_CMAC_AES128
    // https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes#CMAC
    {
        .id = CRYPT_MAC_CMAC_AES128,
        .key = "5fcad38ae778394912f8f1b8413cf773",
        .msg = "07185502bf6d275c84e3ac4f5f77c3d4",
        .mac = "fd44fbc0dd9719e8b569ff10421df4",
        .iv = NULL,
        .type = MAC_TYPE_HMAC_CMAC
    },
    // CRYPT_MAC_CMAC_AES192
    // https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes#CMAC
    {
        .id = CRYPT_MAC_CMAC_AES192,
        .key = "7fea563a866571822472dade8a0bec4b98202d47a3443129",
        .msg = "a206a1eb70a9d24bb5e72f314e7d91de074f59055653bdd24aab5f2bbe112436",
        .mac = "3bfe96f05e9cf96a98bd",
        .iv = NULL,
        .type = MAC_TYPE_HMAC_CMAC
    },
    // CRYPT_MAC_CMAC_AES256
    // https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes#CMAC
    {
        .id = CRYPT_MAC_CMAC_AES256,
        .key = "7bef8d35616108922aab78936967204980b8a4945b31602f5ef2feec9b144841",
        .msg = "40affd355416200191ba64edec8d7d27ead235a7b2e01a12662273deb36379b8a748c422c31e046152d6f196f94e852b",
        .mac = "b2d078071e318ec88de9",
        .iv = NULL,
        .type = MAC_TYPE_HMAC_CMAC
    },
    // CRYPT_MAC_CMAC_SM4
    // GB/T 15852.1-2020 B.6
    {
        .id = CRYPT_MAC_CMAC_SM4,
        .key = "0123456789ABCDEFFEDCBA9876543210",
        .msg = "54686973206973207468652074657374206d65737361676520666f72206d6163", // "This is the test message for mac"
        .mac = "692c437100f3b5ee2b8abcef373d990c",
        .iv = NULL,
        .type = MAC_TYPE_HMAC_CMAC
    },
    // CRYPT_MAC_GMAC_AES128
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip
    {
        .id = CRYPT_MAC_GMAC_AES128,
        .key = "bea48ae4980d27f357611014d4486625",
        .msg = "8a50b0b8c7654bced884f7f3afda2ead",
        .mac = "8e0f6d8bf05ffebe6f500eb1",
        .iv = "32bddb5c3aa998a08556454c",
        .type = MAC_TYPE_GMAC
    },
    // CRYPT_MAC_GMAC_AES192
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip
    {
        .id = CRYPT_MAC_GMAC_AES192,
        .key = "41c5da8667ef725220ffe39ae0ac590ac9fca729ab60ada0",
        .msg = "8b5c124bef6e2f0fe4d8c95cd5fa4cf1",
        .mac = "204bdb1bd62154bf08922aaa54eed705",
        .iv = "05ad13a5e2c2ab667e1a6fbc",
        .type = MAC_TYPE_GMAC
    },
    // CRYPT_MAC_GMAC_AES256
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip
    {
        .id = CRYPT_MAC_GMAC_AES256,
        .key = "78dc4e0aaf52d935c3c01eea57428f00ca1fd475f5da86a49c8dd73d68c8e223",
        .msg = "b96baa8c1c75a671bfb2d08d06be5f36",
        .mac = "3e5d486aa2e30b22e040b85723a06e76",
        .iv = "d79cf22d504cc793c3fb6c8a",
        .type = MAC_TYPE_GMAC
    },
    // CRYPT_MAC_CBC_MAC_SM4
    // GB/T 15852.1-2020 B.2
    {
        .id = CRYPT_MAC_CBC_MAC_SM4,
        .key = "0123456789ABCDEFFEDCBA9876543210",
        .msg = "54686973206973207468652074657374206d65737361676520666f72206d6163", // "This is the test message for mac"
        .mac = "16e02904efb765b706459c9edabdb519",
        .iv = NULL,
        .type = MAC_TYPE_CBC_MAC
    },
    {
        .id = CRYPT_MAC_MAX,
        .key = NULL,
        .msg = NULL,
        .mac = NULL,
        .iv = NULL,
        .type = 0
    }
};

static void FreeData(uint8_t *key, uint8_t *msg, uint8_t *mac, uint8_t *expectMac, uint8_t *iv)
{
    BSL_SAL_Free(key);
    BSL_SAL_Free(msg);
    BSL_SAL_Free(mac);
    BSL_SAL_Free(expectMac);
    BSL_SAL_Free(iv);
}

static bool GetData(const CMVP_MAC_VECTOR *macVec, CRYPT_Data *key, CRYPT_Data *msg,
    CRYPT_Data *expectMac, CRYPT_Data *iv)
{
    key->data = CMVP_StringsToBins(macVec->key, &(key->len));
    GOTO_ERR_IF_TRUE(key->data == NULL, CRYPT_CMVP_COMMON_ERR);
    msg->data = CMVP_StringsToBins(macVec->msg, &(msg->len));
    GOTO_ERR_IF_TRUE(msg->data == NULL, CRYPT_CMVP_COMMON_ERR);
    expectMac->data = CMVP_StringsToBins(macVec->mac, &(expectMac->len));
    GOTO_ERR_IF_TRUE(expectMac->data == NULL, CRYPT_CMVP_COMMON_ERR);
    if (macVec->iv != NULL) {
        iv->data = CMVP_StringsToBins(macVec->iv, &(iv->len));
        GOTO_ERR_IF_TRUE(iv->data == NULL, CRYPT_CMVP_COMMON_ERR);
    }
    return true;
ERR:
    return false;
}

const CMVP_MAC_VECTOR *FindMacVectorById(CRYPT_MAC_AlgId id)
{
    uint32_t num = sizeof(MAC_VECTOR) / sizeof(MAC_VECTOR[0]);
    const CMVP_MAC_VECTOR *macVec = NULL;

    for (uint32_t i = 0; i < num; i++) {
        if (MAC_VECTOR[i].id == id) {
            macVec = &MAC_VECTOR[i];
            return macVec;
        }
    }

    return NULL;
}

static bool CRYPT_CMVP_SelftestMacInternal(void *libCtx, const char *attrName, CRYPT_MAC_AlgId id)
{
    bool ret = false;
    CRYPT_EAL_MacCtx *ctx = NULL;
    CRYPT_Data key = { NULL, 0 };
    CRYPT_Data msg = { NULL, 0 };
    CRYPT_Data iv = { NULL, 0 };
    uint8_t *mac = NULL;
    uint32_t macLen = 0;
    CRYPT_Data expectMac = { NULL, 0 };

    const CMVP_MAC_VECTOR *macVec = FindMacVectorById(id);
    // HMAC-MD5 is a non-approved algorithm and does not provide self-test.
    if (macVec == NULL || macVec->msg == NULL || macVec->id == CRYPT_MAC_HMAC_MD5) {
        return false;
    }

    GOTO_ERR_IF_TRUE(!GetData(macVec, &key, &msg, &expectMac, &iv), CRYPT_CMVP_ERR_ALGO_SELFTEST);
    ctx = CRYPT_EAL_ProviderMacNewCtx(libCtx, id, attrName);
    GOTO_ERR_IF_TRUE(ctx == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    if (macVec->type == MAC_TYPE_GMAC) {
        macLen = expectMac.len;
    } else {
        macLen = CRYPT_EAL_GetMacLen(ctx);
    }
    mac = BSL_SAL_Malloc(macLen);
    GOTO_ERR_IF_TRUE(mac == NULL, CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_MacInit(ctx, key.data, key.len) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    if (macVec->type == MAC_TYPE_GMAC) {
        GOTO_ERR_IF_TRUE(CRYPT_EAL_MacCtrl(ctx, CRYPT_CTRL_SET_IV, iv.data, iv.len) != CRYPT_SUCCESS,
            CRYPT_CMVP_ERR_ALGO_SELFTEST);
        GOTO_ERR_IF_TRUE(CRYPT_EAL_MacCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &macLen, sizeof(uint32_t)) != CRYPT_SUCCESS,
            CRYPT_CMVP_ERR_ALGO_SELFTEST);
    }
    if (macVec->type == MAC_TYPE_CBC_MAC) {
        int32_t padType = CRYPT_PADDING_ZEROS;
        GOTO_ERR_IF_TRUE(CRYPT_EAL_MacCtrl(ctx, CRYPT_CTRL_SET_CBC_MAC_PADDING, &padType, sizeof(padType)) !=
            CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    }
    GOTO_ERR_IF_TRUE(CRYPT_EAL_MacUpdate(ctx, msg.data, msg.len) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(memcmp(mac, expectMac.data, expectMac.len) != 0, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    ret = true;
ERR:
    FreeData(key.data, msg.data, mac, expectMac.data, iv.data);
    CRYPT_EAL_MacDeinit(ctx);
    CRYPT_EAL_MacFreeCtx(ctx);
    return ret;
}

bool CRYPT_CMVP_SelftestMac(CRYPT_MAC_AlgId id)
{
    return CRYPT_CMVP_SelftestMacInternal(NULL, NULL, id);
}

bool CRYPT_CMVP_SelftestProviderMac(void *libCtx, const char *attrName, CRYPT_MAC_AlgId id)
{
    return CRYPT_CMVP_SelftestMacInternal(libCtx, attrName, id);
}

#endif /* HITLS_CRYPTO_CMVP_ISO19790 || HITLS_CRYPTO_CMVP_SM || HITLS_CRYPTO_CMVP_FIPS */
