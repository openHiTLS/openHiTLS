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

#include <stdio.h>
#include "securec.h"
#include "app_errno.h"
#include "bsl_sal.h"
#include "bsl_errno.h"
#include "app_function.h"
#include "app_print.h"
#include "app_help.h"

static int AppInit(void)
{
    int32_t ret = AppPrintErrorUioInit(stderr);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    return HITLS_APP_SUCCESS;
}

static void AppUninit(void)
{
    AppPrintErrorUioUnInit();
    return;
}

static void FreeNewArgv(char **newargv, int argc)
{
    if (newargv != NULL) {
        for (int i = 0; i < argc; i++) {
            BSL_SAL_FREE(newargv[i]);
        }
    }
    BSL_SAL_FREE(newargv);
}

static char **CopyArgs(int argc, char **argv, int *newArgc)
{
    char **newargv = BSL_SAL_Calloc(argc + 1, sizeof(*newargv));
    if (newargv == NULL) {
        AppPrintError("SAL malloc failed.\n");
        return NULL;
    }
    int i = 0;
    for (i = 0; i < argc; i++) {
        newargv[i] = (char *)BSL_SAL_Calloc(strlen(argv[i]) + 1, sizeof(char));
        if (newargv[i] == NULL) {
            AppPrintError("SAL malloc failed.\n");
            goto EXIT;
        }
        if (strcpy_s(newargv[i], strlen(argv[i]) + 1, argv[i]) != EOK) {
            AppPrintError("Failed to copy argv.\n");
            goto EXIT;
        }
    }
    newargv[i] = NULL;
    *newArgc = i;
    return newargv;
EXIT:
    FreeNewArgv(newargv, i);
    return NULL;
}

int main(int argc, char *argv[])
{
    int ret = AppInit();
    if (ret != HITLS_APP_SUCCESS) {
        return HITLS_APP_INIT_FAILED;
    }
    if (argc == 1) {
        AppPrintError("There is only one input parameter. Please enter help to obtain the support list.\n");
        return HITLS_APP_INVALID_ARG;
    }
    int paramNum = argc;
    char** paramVal = argv;
    --paramNum;
    ++paramVal;
    int newArgc = 0;
    char **newArgv = CopyArgs(paramNum, paramVal, &newArgc);
    if (newArgv == NULL) {
        AppPrintError("Copy args failed.\n");
        ret = HITLS_APP_COPY_ARGS_FAILED;
        goto end;
    }

    HITLS_CmdFunc func = { 0 };
    char *proName = newArgv[0];
    ret = AppGetProgFunc(proName, &func);
    if (ret != 0) {
        AppPrintError("Please enter help to obtain the support list.\n");
        FreeNewArgv(newArgv, newArgc);
        goto end;
    }

    ret = func.main(newArgc, newArgv);
    FreeNewArgv(newArgv, newArgc);
end:
    AppUninit();
    return ret;
}
