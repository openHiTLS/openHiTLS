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
#include <stdio.h>
#include "app_opt.h"
#include "app_print.h"
#include "bsl_uio.h"
#include "uio_abstraction.h"
#include "app_errno.h"
#include "crypt_errno.h"
#include "app_req.h"
#include "app_function.h"
#include "securec.h"
#include "bsl_errno.h"
#include "bsl_sal.h"

/* END_HEADER */

static void RestoreStdoutByFd(int savedStdoutFd)
{
    if (savedStdoutFd < 0) {
        return;
    }
    /*
     * req may print directly to process stdout when no output file is given.
     * Restore stdout between iterations so later command cases and test logs do
     * not reuse redirected state, and keep the recovery independent of /dev/tty.
     */
    fflush(stdout);
    (void)dup2(savedStdoutFd, STDOUT_FILENO);
    clearerr(stdout);
}

static void SplitArgs(char *str, char **result, int *count) {
    char *token;
    token = strtok(str, " ");
    while (token != NULL) {
        result[*count] = token;
        (*count)++;
        token = strtok(NULL, " ");
    }
}

/**
 * @test UT_HITLS_APP_REQ_TC001
 * @spec  -
 * @title   测试UT_HITLS_APP_REQ_TC001函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_REQ_TC001(char *arg, int expect)
{
    int savedStdoutFd = dup(STDOUT_FILENO);
    char *argv[20] = {};
    int argc = 0;
    SplitArgs(arg, argv, &argc);
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    int ret = HITLS_ReqMain(argc, argv);
    RestoreStdoutByFd(savedStdoutFd);
    ASSERT_EQ(ret, expect);
EXIT:
    if (savedStdoutFd >= 0) {
        close(savedStdoutFd);
    }
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */
