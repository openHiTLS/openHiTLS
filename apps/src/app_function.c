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
#include "app_function.h"
#include <string.h>
#include <stddef.h>
#include "app_errno.h"
#include "app_help.h"
#include "app_print.h"
#include "app_rand.h"
#include "app_enc.h"
#include "app_pkcs12.h"
#include "app_x509.h"
#include "app_list.h"
#include "app_rsa.h"
#include "app_dgst.h"
#include "app_crl.h"
#include "app_genrsa.h"
#include "app_verify.h"
#include "app_passwd.h"
#include "app_pkey.h"
#include "app_genpkey.h"
#include "app_req.h"

HITLS_CmdFunc g_cmdFunc[] = {
    {"help",     FUNC_TYPE_GENERAL,   HITLS_HelpMain},
    {"rand",     FUNC_TYPE_GENERAL,   HITLS_RandMain},
    {"enc",      FUNC_TYPE_GENERAL,   HITLS_EncMain},
    {"pkcs12",   FUNC_TYPE_GENERAL,   HITLS_PKCS12Main},
    {"rsa",      FUNC_TYPE_GENERAL,   HITLS_RsaMain},
    {"x509",     FUNC_TYPE_GENERAL,   HITLS_X509Main},
    {"list",     FUNC_TYPE_GENERAL,   HITLS_ListMain},
    {"dgst",     FUNC_TYPE_GENERAL,   HITLS_DgstMain},
    {"crl",      FUNC_TYPE_GENERAL,   HITLS_CrlMain},
    {"genrsa",   FUNC_TYPE_GENERAL,   HITLS_GenRSAMain},
    {"verify",   FUNC_TYPE_GENERAL,   HITLS_VerifyMain},
    {"passwd",   FUNC_TYPE_GENERAL,   HITLS_PasswdMain},
    {"pkey",     FUNC_TYPE_GENERAL,   HITLS_PkeyMain},
    {"genpkey",  FUNC_TYPE_GENERAL,   HITLS_GenPkeyMain},
    {"req",      FUNC_TYPE_GENERAL,   HITLS_ReqMain},
    {NULL,      FUNC_TYPE_NONE, NULL}
};
static void AppGetFuncPrintfLen(size_t *maxLen)
{
    size_t len = 0;
    for (size_t i = 0; g_cmdFunc[i].name != NULL; i++) {
        len = (len > strlen(g_cmdFunc[i].name)) ? len : strlen(g_cmdFunc[i].name);
    }
    *maxLen = len + 5; // The relative maximum length is filled with 5 spaces.
}

void AppPrintFuncList(void)
{
    AppPrintError("HiTLS supports the following commands:\n");
    size_t maxLen = 0;
    AppGetFuncPrintfLen(&maxLen);
    for (size_t i = 0; g_cmdFunc[i].name != NULL; i++) {
        if (((i % 4) == 0) && (i != 0)) { // Print 4 functions in one line
            AppPrintError("\n");
        }
        AppPrintError("%-*s", maxLen, g_cmdFunc[i].name);
    }
    AppPrintError("\n");
}

int AppGetProgFunc(const char *proName, HITLS_CmdFunc *func)
{
    for (size_t i = 0; g_cmdFunc[i].name != NULL; i++) {
        if (strcmp(proName, g_cmdFunc[i].name) == 0) {
            func->type = g_cmdFunc[i].type;
            func->main = g_cmdFunc[i].main;
            break;
        }
    }

    if (func->main == NULL) {
        AppPrintError("Can not find the function : %s. ", proName);
        return HITLS_APP_OPT_NAME_INVALID;
    }

    return HITLS_APP_SUCCESS;
}
