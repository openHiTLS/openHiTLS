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
#include "hitls_build.h"
#include "cert_callback.h"
#include "bsl_sal.h"
#include "bsl_log.h"
#include "bsl_err.h"
#include "bsl_err_internal.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "hitls_crypt_init.h"
#include "crypt_eal_rand.h"
#include "hitls_cert_init.h"
#include "bsl_log.h"

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

void BinLogFixLenFunc(uint32_t logId, uint32_t logLevel, uint32_t logType,
    void *format, void *para1, void *para2, void *para3, void *para4);

void BinLogVarLenFunc(uint32_t logId, uint32_t logLevel, uint32_t logType, void *format, void *para);
void FRAME_Init(void)
{
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, StdMalloc);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE, StdFree);
    BSL_ERR_Init();
#ifdef TLS_DEBUG
    BSL_LOG_SetBinLogLevel(BSL_LOG_LEVEL_DEBUG);
    BSL_LOG_BinLogFuncs logFunc = { BinLogFixLenFunc, BinLogVarLenFunc };
    BSL_LOG_RegBinLogFunc(&logFunc);
#endif
    BSL_ERR_SET_MARK();
#ifdef HITLS_TLS_FEATURE_PROVIDER
    if (CRYPT_EAL_ProviderRandInitCtx(NULL, CRYPT_RAND_SHA256, "provider=default", NULL, 0, NULL) == CRYPT_EAL_ERR_DRBG_REPEAT_INIT) {
        BSL_ERR_POP_TO_MARK();
    }
#else
    if (CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_EAL_ERR_DRBG_REPEAT_INIT) {
        BSL_ERR_POP_TO_MARK();
    }
    HITLS_CertMethodInit();
    HITLS_CryptMethodInit();
#endif
    return;
}

void FRAME_DeInit(void)
{
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, StdMallocFail);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE, StdFree);

    BSL_ERR_DeInit();
    return;
}