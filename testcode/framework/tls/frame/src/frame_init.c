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

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "cert_callback.h"
#include "bsl_sal.h"
#include "bsl_log.h"
#include "bsl_err.h"
#include "crypt_algid.h"
#include "hitls_crypt_init.h"
#include "crypt_eal_rand.h"
#include "hitls_cert_init.h"

static void *StdMalloc(uint32_t len)
{
    return malloc((uint32_t)len);
}

static void StdFree(void *addr)
{
    free(addr);
}

static void *StdMallocFail(uint32_t len)
{
    (void)len;
    return NULL;
}

void FRAME_Init(void)
{
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC_CB_FUNC, StdMalloc);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE_CB_FUNC, StdFree);
    BSL_ERR_Init();
    HITLS_CertMethodInit();
    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);
    HITLS_CryptMethodInit();
    return;
}

void FRAME_DeInit(void)
{
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC_CB_FUNC, StdMallocFail);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE_CB_FUNC, StdFree);

    BSL_ERR_DeInit();
    return;
}