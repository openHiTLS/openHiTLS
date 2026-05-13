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

/* BEGIN_HEADER */

#include "crypt.h"
#include "hitls_crypt_type.h"
#include "hitls_crypt_init.h"
#include "stub_utils.h"
#include "crypt_eal_mac.h"
#include "crypt_errno.h"
#include "hitls_crypt.h"

#define PRF_OUT_LEN 48

STUB_DEFINE_RET2(int32_t, CRYPT_EAL_MacSetParam, CRYPT_EAL_MacCtx *, const BSL_Param *);

/* END_HEADER */

/* BEGIN_CASE */
void SDV_TLS_CRYPT_PRF_TC001(int hashAlgo, Hex *secret, Hex *label, Hex *seed, Hex *expect)
{
    CRYPT_KeyDeriveParameters input = {0};
    input.hashAlgo = hashAlgo;
    input.secret = (uint8_t *)secret->x;
    input.secretLen = secret->len;
    input.label = (uint8_t *)label->x;
    input.labelLen = label->len;
    input.seed = (uint8_t *)seed->x;
    input.seedLen = seed->len;
    input.libCtx = NULL;
    input.attrName = NULL;
    uint8_t out[PRF_OUT_LEN] = {0};

    HITLS_CryptMethodInit();
    ASSERT_TRUE(PRF_OUT_LEN <= expect->len);
    ASSERT_EQ(SAL_CRYPT_PRF(&input, out, PRF_OUT_LEN), HITLS_SUCCESS);
    ASSERT_COMPARE("result cmp", out, PRF_OUT_LEN, expect->x, PRF_OUT_LEN);

EXIT:
    return;
}
/* END_CASE */

#ifdef HITLS_CRYPTO_PROVIDER
int32_t STUB_CRYPT_EAL_MacSetParam(CRYPT_EAL_MacCtx *ctx, const BSL_Param *param)
{
    (void)ctx;
    (void)param;
    return CRYPT_NULL_INPUT;
}
#endif

/**
 * @test SDV_CRYPTO_HMAC_STUB_TC001
 * title 1. Test the mac with stub SetHmacMdAttr fail
 *
 */
/* BEGIN_CASE */
void SDV_TLS_CRYPTO_HMAC_STUB_TC001(int algId, Hex *key, Hex *data)
{
#ifndef HITLS_TLS_FEATURE_PROVIDER
    (void)algId;
    (void)key;
    (void)data;
    SKIP_TEST();
#else
    uint32_t macLen = 64;
    uint8_t mac[64];
    int ret = HITLS_CRYPT_HMAC(NULL, "provider?=default", algId, key->x, key->len, data->x, data->len, mac, &macLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    STUB_REPLACE(CRYPT_EAL_MacSetParam, STUB_CRYPT_EAL_MacSetParam);
    ret = HITLS_CRYPT_HMAC(NULL, "provider?=default", algId, key->x, key->len, data->x, data->len, mac, &macLen);
    ASSERT_NE(ret, CRYPT_SUCCESS);

EXIT:
    STUB_RESTORE(CRYPT_EAL_MacSetParam);
#endif
}
/* END_CASE */