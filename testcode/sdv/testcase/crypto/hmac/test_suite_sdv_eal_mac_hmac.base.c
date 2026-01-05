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

#include <pthread.h>
#include "securec.h"
#include "crypt_eal_mac.h"
#include "eal_mac_local.h"
#include "crypt_errno.h"
#include "bsl_sal.h"
#include "crypt_sha1.h"
#include "crypt_sha2.h"
#include "crypt_sha3.h"
#include "crypt_sm3.h"
#include "crypt_md5.h"
#include "stub_replace.h"

#define TEST_FAIL (-1)
#define TEST_SUCCESS (0)
#define DATA_MAX_LEN (65538)

uint32_t GetMacLen(int algId)
{
    switch (algId) {
#ifdef HITLS_CRYPTO_MD5
        case CRYPT_MAC_HMAC_MD5:
            return CRYPT_MD5_DIGESTSIZE;
#endif
#ifdef HITLS_CRYPTO_SHA1
        case CRYPT_MAC_HMAC_SHA1:
            return CRYPT_SHA1_DIGESTSIZE;
#endif
#ifdef HITLS_CRYPTO_SHA224
        case CRYPT_MAC_HMAC_SHA224:
            return CRYPT_SHA2_224_DIGESTSIZE;
#endif
#ifdef HITLS_CRYPTO_SHA256
        case CRYPT_MAC_HMAC_SHA256:
            return CRYPT_SHA2_256_DIGESTSIZE;
#endif
#ifdef HITLS_CRYPTO_SHA384
        case CRYPT_MAC_HMAC_SHA384:
            return CRYPT_SHA2_384_DIGESTSIZE;
#endif
#ifdef HITLS_CRYPTO_SHA512
        case CRYPT_MAC_HMAC_SHA512:
            return CRYPT_SHA2_512_DIGESTSIZE;
#endif
#ifdef HITLS_CRYPTO_SM3
        case CRYPT_MAC_HMAC_SM3:
            return CRYPT_SM3_DIGESTSIZE;
#endif
#ifdef HITLS_CRYPTO_SHA3
        case CRYPT_MAC_HMAC_SHA3_224:
            return CRYPT_SHA3_224_DIGESTSIZE;
        case CRYPT_MAC_HMAC_SHA3_256:
            return CRYPT_SHA3_256_DIGESTSIZE;
        case CRYPT_MAC_HMAC_SHA3_384:
            return CRYPT_SHA3_384_DIGESTSIZE;
        case CRYPT_MAC_HMAC_SHA3_512:
            return CRYPT_SHA3_512_DIGESTSIZE;
#endif
        default:
            return 0;
    }
}

typedef struct {
    uint8_t *data;
    uint8_t *mac;
    uint8_t *key;
    uint32_t dataLen;
    uint32_t macLen;
    uint32_t keyLen;
    int algId;
} ThreadParameter;

void MultiThreadTest(void *arg)
{
    ThreadParameter *threadParameter = (ThreadParameter *)arg;
    uint32_t outLen = GetMacLen(threadParameter->algId);
    uint8_t out[outLen];
    CRYPT_EAL_MacCtx *ctx = NULL;
    ctx = CRYPT_EAL_MacNewCtx(threadParameter->algId);
    ASSERT_TRUE(ctx != NULL);
    for (uint32_t i = 0; i < 10; i++) {
        ASSERT_EQ(CRYPT_EAL_MacInit(ctx, threadParameter->key, threadParameter->keyLen), CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_MacUpdate(ctx, threadParameter->data, threadParameter->dataLen), CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_MacFinal(ctx, out, &outLen), CRYPT_SUCCESS);
        ASSERT_COMPARE("hash result cmp", out, outLen, threadParameter->mac, threadParameter->macLen);
    }

EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
