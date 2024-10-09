/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_EAL)

#include <stddef.h>
#include "crypt_types.h"
#include "crypt_eal_md.h"
#include "crypt_eal_mac.h"
#include "crypt_method.h"
#include "eal_cipher_local.h"
#include "eal_pkey_local.h"
#include "eal_md_local.h"
#include "eal_mac_local.h"
#include "bsl_err_internal.h"
#include "eal_common.h"

EventReport g_eventReportFunc = NULL;
void CRYPT_EAL_RegEventReport(EventReport func)
{
    g_eventReportFunc = func;
}

void EAL_EventReport(CRYPT_EVENT_TYPE oper, CRYPT_ALGO_TYPE type, int32_t id, int32_t err)
{
    if (g_eventReportFunc == NULL) {
        return;
    }
    g_eventReportFunc(oper, type, id, err);
}
#endif
