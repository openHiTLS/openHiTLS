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

#include "bsl_user_data.h"
#include "bsl_sal.h"
#include "bsl_errno.h"

/* END_HEADER */

void Stub_BSL_USER_ExDataFree(void *parent, void *ptr, BSL_USER_ExData *ad, int idx, long argl, void *argp)
{
    (void)parent;
    (void)idx;
    (void)argl;
    (void)argp;
    for (int32_t i = 0; i < BSL_MAX_EX_DATA; i++) {
        if (ad->sk[i] == ptr) {
            BSL_SAL_FREE(ad->sk[i]);
        }
    }
    return;
}

/**
 * @test  SDV_BSL_USERDATA_API_TC001
 * @title  Find tlv value pos test
 * @precon  nan
 * @brief
 *    1. Invoke BSL_USER_GetExDataNewIndex to new a index. Expected result 1 is obtained.
 *    2. Invoke BSL_USER_SetExData to set a userdata. Expected result 2 is obtained.
 *    3. Invoke BSL_USER_FreeExDataIndex to free userdata, and invoke to get userdata. Expected result 3 is obtained.
 * @expect
 *    1. Expected -1
 *    2. Expected success
 *    3. Expected NULL
 */
/* BEGIN_CASE */
void SDV_BSL_USERDATA_API_TC001(void)
{
    int ret;
    void *ctx = NULL;
    void *newCtx = NULL;
    BSL_USER_ExData exdata = { 0 };
    int idx = BSL_USER_GetExDataNewIndex(BSL_USER_DATA_EX_INDEX_SSL, 0, NULL, NULL, NULL, Stub_BSL_USER_ExDataFree);
    ASSERT_TRUE(idx != -1);

    ctx = BSL_SAL_Calloc(1u, 1024);
    ret = BSL_USER_SetExData(&exdata, idx, ctx);
    ASSERT_TRUE(ret == BSL_SUCCESS);

    BSL_USER_FreeExDataIndex(BSL_USER_DATA_EX_INDEX_SSL, NULL, &exdata);
    newCtx = BSL_USER_GetExData(&exdata, idx);
    ASSERT_TRUE(newCtx == NULL);
EXIT:
    return;
}
/* END_CASE */
