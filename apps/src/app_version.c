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

#include "app_version.h"
#include "app_errno.h"
#include "app_opt.h"
#include "app_print.h"
#include "bsl_uio.h"
#include "bsl_version.h"

static const HITLS_CmdOption g_versionOpts[] = {
    {"help", HITLS_APP_OPT_HELP, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Display this function summary"},
    {NULL, 0, 0, NULL}
};

static int32_t PrintVersion(void)
{
    BSL_UIO *out = HITLS_APP_UioOpenPrivate(NULL, 'w');
    if (out == NULL) {
        AppPrintError("version: Failed to open stdout.\n");
        return HITLS_APP_UIO_FAIL;
    }

    int32_t ret = AppPrint(out, "%s\n", HITLS_Version());
    BSL_UIO_Free(out);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("version: Failed to print version.\n");
        return HITLS_APP_UIO_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t OptParse(void)
{
    int32_t optType;
    while ((optType = HITLS_APP_OptNext()) != HITLS_APP_OPT_EOF) {
        switch (optType) {
            case HITLS_APP_OPT_ERR:
                AppPrintError("version: Use -help for summary.\n");
                return HITLS_APP_OPT_UNKOWN;
            case HITLS_APP_OPT_HELP:
                HITLS_APP_OptHelpPrint(g_versionOpts);
                return HITLS_APP_HELP;
            default:
                return HITLS_APP_OPT_UNKOWN;
        }
    }

    if (HITLS_APP_GetRestOptNum() != 0) {
        AppPrintError("version: Extra arguments given.\n");
        AppPrintError("version: Use -help for summary.\n");
        return HITLS_APP_OPT_UNKOWN;
    }

    return HITLS_APP_SUCCESS;
}

int32_t HITLS_VersionMain(int argc, char *argv[])
{
    int32_t mainRet = HITLS_APP_OptBegin(argc, argv, g_versionOpts);
    if (mainRet != HITLS_APP_SUCCESS) {
        goto end;
    }

    mainRet = OptParse();
    if (mainRet != HITLS_APP_SUCCESS) {
        goto end;
    }
    mainRet = PrintVersion();

end:
    HITLS_APP_OptEnd();
    return mainRet;
}
