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
#include "app_opt.h"
#include "app_errno.h"
#include "bsl_uio.h"
#include "bsl_errno.h"
#include "app_print.h"
#include "stub_utils.h"
/* END_HEADER */

/* INCLUDE_SOURCE  ${HITLS_ROOT_PATH}/apps/src/app_print.c */

STUB_DEFINE_RET1(BSL_UIO *, BSL_UIO_New, const BSL_UIO_Method *);
STUB_DEFINE_RET4(int32_t, BSL_UIO_Ctrl, BSL_UIO *, int32_t, int32_t, void *);
STUB_DEFINE_VOID1(BSL_UIO_Free, BSL_UIO *);

static int32_t g_fakeUio;
static uint32_t g_uioFreeCount;

static BSL_UIO *StubUioNewFailure(const BSL_UIO_Method *method)
{
    (void)method;
    return NULL;
}

static BSL_UIO *StubUioNewSuccess(const BSL_UIO_Method *method)
{
    (void)method;
    return (BSL_UIO *)&g_fakeUio;
}

static int32_t StubUioCtrlFailure(BSL_UIO *uio, int32_t cmd, int32_t larg, void *parg)
{
    (void)uio;
    (void)cmd;
    (void)larg;
    (void)parg;
    return BSL_UIO_FAIL;
}

static void StubUioFree(BSL_UIO *uio)
{
    (void)uio;
    g_uioFreeCount++;
}


/**
 * @test UT_HITLS_APP_PrintStderr_TC001
 * @spec  -
 * @title   测试UT_HITLS_APP_PrintStderr_TC001函数
 */
/* BEGIN_CASE */
void UT_HITLS_APPPrint_TC001(void)
{
    AppPrintErrorUioInit(stderr);
    AppPrintError("\n%d %x\n", BSL_UIO_FILE_PTR, BSL_UIO_FILE_PTR + 1);
    AppPrintErrorUioUnInit();
}
/* END_CASE */

BSL_UIO *g_stderrUio = NULL;
static int32_t InitStderrUIO(void)
{
    if (g_stderrUio != NULL)
        return HITLS_APP_SUCCESS;
    g_stderrUio = BSL_UIO_New(BSL_UIO_FileMethod());
    if (g_stderrUio == NULL)
        return HITLS_APP_MEM_ALLOC_FAIL;

    return BSL_UIO_Ctrl(g_stderrUio, BSL_UIO_FILE_PTR, 0, (void *)stderr);
}


/**
 * @test UT_HITLS_APP_Print_TC001
 * @spec  -
 * @title   测试UT_HITLS_APP_Print_TC001函数
 */
/* BEGIN_CASE */
void UT_HITLS_APPPrint_TC002(void)
{
    InitStderrUIO();
    ASSERT_EQ(AppPrint(g_stderrUio, "\n%d %x\n", HITLS_APP_SUCCESS, HITLS_APP_SUCCESS + 1), HITLS_APP_SUCCESS);
EXIT:
    BSL_UIO_Free(g_stderrUio);
    g_stderrUio = NULL;
}
/* END_CASE */

/* BEGIN_CASE */
void UT_HITLS_APPPrint_InitFailure_TC001(void)
{
    AppPrintErrorUioUnInit();
    STUB_REPLACE(BSL_UIO_New, StubUioNewFailure);
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_MEM_ALLOC_FAIL);
EXIT:
    STUB_RESTORE(BSL_UIO_New);
    AppPrintErrorUioUnInit();
}
/* END_CASE */

/* BEGIN_CASE */
void UT_HITLS_APPPrint_InitFailure_TC002(void)
{
    AppPrintErrorUioUnInit();
    g_uioFreeCount = 0;
    STUB_REPLACE(BSL_UIO_New, StubUioNewSuccess);
    STUB_REPLACE(BSL_UIO_Ctrl, StubUioCtrlFailure);
    STUB_REPLACE(BSL_UIO_Free, StubUioFree);
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_UIO_FAIL);
    ASSERT_EQ(g_uioFreeCount, 1);
EXIT:
    AppPrintErrorUioUnInit();
    STUB_RESTORE(BSL_UIO_New);
    STUB_RESTORE(BSL_UIO_Ctrl);
    STUB_RESTORE(BSL_UIO_Free);
}
/* END_CASE */
