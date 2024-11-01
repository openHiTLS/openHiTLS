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

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_EAL)

#include <stddef.h>
#include "crypt_types.h"
#include "crypt_eal_md.h"
#include "crypt_eal_mac.h"
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
