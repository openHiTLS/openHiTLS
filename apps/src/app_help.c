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

#include "app_help.h"
#include "app_errno.h"
#include "app_print.h"
#include "app_opt.h"
#include "app_function.h"

HITLS_CmdOption g_helpOptions[] = {
    {"help", HITLS_APP_OPT_HELP, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Usage: help [options]"},
    {NULL, 0, 0, NULL}
};

int HITLS_HelpMain(int argc, char *argv[])
{
    if (argc == 1) {
        AppPrintFuncList();
        return HITLS_APP_SUCCESS;
    }

    HITLS_OptChoice oc;
    int32_t ret = HITLS_APP_OptBegin(argc, argv, g_helpOptions);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("error in opt begin.\n");
        HITLS_APP_OptEnd();
        return ret;
    }
    while ((oc = HITLS_APP_OptNext()) != HITLS_APP_OPT_EOF) {
        switch (oc) {
            case HITLS_APP_OPT_ERR:
                AppPrintError("help: Use -help for summary.\n");
                HITLS_APP_OptEnd();
                return HITLS_APP_OPT_UNKOWN;
            case HITLS_APP_OPT_HELP:
                HITLS_APP_OptHelpPrint(g_helpOptions);
                HITLS_APP_OptEnd();
                return HITLS_APP_SUCCESS;
            default:
                AppPrintError("help: Use -help for summary.\n");
                HITLS_APP_OptEnd();
                return HITLS_APP_OPT_UNKOWN;
        }
    }

    if (HITLS_APP_GetRestOptNum() != 1) {
        AppPrintError("Please enter help to obtain the support list.\n");
        HITLS_APP_OptEnd();
        return HITLS_APP_OPT_VALUE_INVALID;
    }

    HITLS_CmdFunc func = { 0 };
    char *proName = HITLS_APP_GetRestOpt()[0];
    HITLS_APP_OptEnd();
    ret = AppGetProgFunc(proName, &func);
    if (ret != 0) {
        AppPrintError("Please enter help to obtain the support list.\n");
        return ret;
    }
    char *newArgv[3] = {proName, "--help", NULL};
    int newArgc = 2;
    return func.main(newArgc, newArgv);
}