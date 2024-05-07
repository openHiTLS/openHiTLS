/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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
    BSL_SAL_MemCallback memMthod = {StdMalloc, StdFree};
    BSL_SAL_RegMemCallback(&memMthod);
    BSL_ERR_Init();
    HITLS_CertMethodInit();
    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);
    HITLS_CryptMethodInit();
    return;
}

void FRAME_DeInit(void)
{
    BSL_SAL_MemCallback memMthod = {StdMallocFail, StdFree};
    BSL_SAL_RegMemCallback(&memMthod);

    BSL_ERR_DeInit();
    return;
}