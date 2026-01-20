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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "securec.h"
#include "bsl_err.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_eal_pkey.h"
#include "crypt_util_rand.h"
#include "crypt_bn.h"
#include "eal_pkey_local.h"
#include "test.h"
/* END_HEADER */

/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_VERIFY_KAT_TC001(int id, Hex *key, Hex *addrand, Hex *msg, Hex *context, Hex *sig, int result)
{
    TestMemInit();

    CRYPT_EAL_PkeyCtx *pkey = NULL;
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    ASSERT_TRUE(pkey != NULL);
    int32_t algId = id;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, algId), CRYPT_SUCCESS);
    uint32_t keyLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_SLH_DSA_KEY_LEN, (void *)&keyLen, sizeof(keyLen)), CRYPT_SUCCESS);
    if (addrand->len == 0) {
        int32_t isDeterministic = 1;
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_DETERMINISTIC_FLAG, (void *)&isDeterministic,
                                     sizeof(isDeterministic)),
                  CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_SLH_DSA_ADDRAND, (void *)addrand->x, addrand->len),
                  CRYPT_SUCCESS);
    }

    CRYPT_EAL_PkeyPrv prv;
    (void)memset_s(&prv, sizeof(CRYPT_EAL_PkeyPrv), 0, sizeof(CRYPT_EAL_PkeyPrv));
    prv.id = CRYPT_PKEY_SLH_DSA;
    prv.key.slhDsaPrv.seed = key->x;
    prv.key.slhDsaPrv.prf = key->x + keyLen;
    prv.key.slhDsaPrv.pub.seed = key->x + keyLen * 2;
    prv.key.slhDsaPrv.pub.root = key->x + keyLen * 3;
    prv.key.slhDsaPrv.pub.len = keyLen;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, &prv), CRYPT_SUCCESS);
    if (context->len != 0) {
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_CTX_INFO, context->x, context->len), CRYPT_SUCCESS);
    }
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA256, msg->x, msg->len, sig->x, sig->len), result);
    if (result == CRYPT_SUCCESS) {
        ASSERT_TRUE(TestIsErrStackEmpty());
    }
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_SLH_DSA_VERIFY_PREHASHED_KAT_TC001(int id, Hex *key, Hex *addrand, Hex *msg, Hex *context, int hashId, Hex *sig, int result)
{
    TestMemInit();

    CRYPT_EAL_PkeyCtx *pkey = NULL;
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
    ASSERT_TRUE(pkey != NULL);
    int32_t algId = id;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, algId), CRYPT_SUCCESS);
    uint32_t keyLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_SLH_DSA_KEY_LEN, (void *)&keyLen, sizeof(keyLen)), CRYPT_SUCCESS);
    if (addrand->len == 0) {
        int32_t isDeterministic = 1;
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_DETERMINISTIC_FLAG, (void *)&isDeterministic,
                                     sizeof(isDeterministic)),
                  CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_SLH_DSA_ADDRAND, (void *)addrand->x, addrand->len),
                  CRYPT_SUCCESS);
    }
    int32_t prehash = 1;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_PREHASH_FLAG, (void *)&prehash, sizeof(prehash)),
              CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPrv prv;
    (void)memset_s(&prv, sizeof(CRYPT_EAL_PkeyPrv), 0, sizeof(CRYPT_EAL_PkeyPrv));
    prv.id = CRYPT_PKEY_SLH_DSA;
    prv.key.slhDsaPrv.seed = key->x;
    prv.key.slhDsaPrv.prf = key->x + keyLen;
    prv.key.slhDsaPrv.pub.seed = key->x + keyLen * 2;
    prv.key.slhDsaPrv.pub.root = key->x + keyLen * 3;
    prv.key.slhDsaPrv.pub.len = keyLen;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, &prv), CRYPT_SUCCESS);
    if (context->len != 0) {
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_CTX_INFO, context->x, context->len), CRYPT_SUCCESS);
    }
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, hashId, msg->x, msg->len, sig->x, sig->len), result);
    if (result == CRYPT_SUCCESS) {
        ASSERT_TRUE(TestIsErrStackEmpty());
    }
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return;
}
/* END_CASE */
