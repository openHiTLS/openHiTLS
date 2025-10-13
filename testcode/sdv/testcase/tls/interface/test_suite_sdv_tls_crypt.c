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

#define PRF_OUT_LEN 48

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
