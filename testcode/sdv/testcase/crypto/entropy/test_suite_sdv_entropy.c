/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

/* BEGIN_HEADER */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "entropy.h"
#include "eal_entropy.h"
#include "crypt_algid.h"

/* END_HEADER */

/**
 * @test   UT_CRYPTO_ENTROPY_GetCtx
 * @title  Get the seedCtx of the corresponding algorithm.
 * @precon nan
 * @brief
 *    1.Call ENTROPY_GetCtx get seedCtx, expected result 1.
 *    2.Call ENTROPY_GetCtx get seedCtx,conFunc is NULL or algid is 0, expected result 2.
 * @expect
 *    1.Return seedCtx.
 *    2.Return NULL.
 */
/* BEGIN_CASE */
void UT_CRYPTO_ENTROPY_GetCtx(void)
{
    ASSERT_TRUE(ENTROPY_GetCtx(EAL_EntropyGetECF(CRYPT_MAC_HMAC_SHA256), CRYPT_MAC_HMAC_SHA256) != NULL);
    ASSERT_TRUE(ENTROPY_GetCtx(NULL, CRYPT_MAC_HMAC_SHA256) == NULL);
    ASSERT_TRUE(ENTROPY_GetCtx(EAL_EntropyGetECF(CRYPT_MAC_HMAC_SHA256), 0) == NULL);
exit:
    return;
}
/* END_CASE */

/**
 * @test   UT_CRYPTO_ENTROPY_GetFei
 * @title  Get the seedCtx of the corresponding algorithm.
 * @precon nan
 * @brief
 *    1.Call ENTROPY_GetCtx get seedCtx, expected result 1.
 *    2.Call ENTROPY_GetFullEntropyInput get entropy, expected result 2.
 * @expect
 *    1.Return seedCtx.
 *    2.Get entropy successful.
 */
/* BEGIN_CASE */
void UT_CRYPTO_ENTROPY_GetFei(void)
{
    TestMemInit();
    void *seedCtx = ENTROPY_GetCtx(EAL_EntropyGetECF(CRYPT_MAC_HMAC_SHA256), CRYPT_MAC_HMAC_SHA256);
    ASSERT_TRUE(seedCtx != NULL);
    uint8_t data[32] = {0};
    ASSERT_EQ(ENTROPY_GetFullEntropyInput(seedCtx, data, 32), CRYPT_SUCCESS);

exit:
    return;
}
/* END_CASE */

