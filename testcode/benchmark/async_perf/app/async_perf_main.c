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

#include "async_perf_opt.h"
#include "bench_handshake.h"
#include "affinity.h"
#include "bsl_sal.h"
#include "bsl_err.h"
#include "bsl_async.h"
#include "hitls.h"
#include "crypt_eal_provider.h"
#include "crypt_errno.h"
#include "crypt_eal_rand.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#ifndef HITLS_ASYNC_SIM_PROVIDER_DIR
#define HITLS_ASYNC_SIM_PROVIDER_DIR "testcode/output/async_sim_provider"
#endif

int main(int argc, char **argv)
{
    PerfOptions opt;
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_ProvMgrCtx *mgr = NULL;
    PerfScenario scenarios[PERF_FORM_BUTT * PERF_PROFILE_BUTT];
    bool globalRand = false;
    bool localRand = false;
    int ret = 2;

    if (PerfOptParse(argc, argv, &opt) != 0) {
        return 2;
    }
    if (opt.listOnly) {
        PerfOptPrintList(&opt);
        return 0;
    }
    (void)signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);
    int n = PerfOptExpand(&opt, scenarios);
    if (n != 1) {
        fprintf(stderr, "select exactly one server scenario with -a\n");
        goto EXIT;
    }
    const char *provPath = opt.providerPath;
    if (provPath == NULL) {
        provPath = getenv("HITLS_ASYNC_SIM_PROVIDER_PATH");
        if (provPath == NULL || provPath[0] == '\0') {
            provPath = HITLS_ASYNC_SIM_PROVIDER_DIR;
        }
    }
    libCtx = CRYPT_EAL_LibCtxNew();
    if (libCtx == NULL || CRYPT_EAL_ProviderSetLoadPath(libCtx, provPath) != CRYPT_SUCCESS ||
        CRYPT_EAL_ProviderLoad(libCtx, BSL_SAL_LIB_FMT_LIBSO, PERF_PROVIDER_NAME, NULL, &mgr) != CRYPT_SUCCESS ||
        mgr == NULL || CRYPT_EAL_ProviderLoad(libCtx, BSL_SAL_LIB_FMT_OFF, "default", NULL, NULL) != CRYPT_SUCCESS) {
        fprintf(stderr, "provider load failed: %s/%s\n", provPath, PERF_PROVIDER_NAME);
        goto EXIT;
    }
    if (CRYPT_EAL_ProviderRandInitCtx(NULL, CRYPT_RAND_SHA256, "provider=default", NULL, 0, NULL) != CRYPT_SUCCESS) {
        fprintf(stderr, "global DRBG init failed\n");
        goto EXIT;
    }
    globalRand = true;
    if (CRYPT_EAL_ProviderRandInitCtx(libCtx, CRYPT_RAND_SHA256, "provider=default", NULL, 0, NULL) != CRYPT_SUCCESS) {
        fprintf(stderr, "DRBG init failed\n");
        goto EXIT;
    }
    localRand = true;
#ifdef HITLS_BSL_ASYNC
    if (BSL_ASYNC_IsSupported() && BSL_ASYNC_InitThread(0, 0, 0) != BSL_SUCCESS) {
        fprintf(stderr, "BSL async init failed\n");
        goto EXIT;
    }
#endif
    if (PerfAffinityInit(opt.pinCpu, opt.execMode == PERF_EXEC_WORKER ? opt.workers : 0) != 0) {
        goto EXIT;
    }
    ret = PerfBenchHandshake(&opt, &scenarios[0], libCtx, mgr) == 0 ? 0 : 1;
EXIT:
    if (localRand) {
        CRYPT_EAL_RandDeinitEx(libCtx);
    }
    CRYPT_EAL_LibCtxFree(libCtx);
    if (globalRand) {
        CRYPT_EAL_RandDeinitEx(NULL);
    }
#ifdef HITLS_BSL_ASYNC
    BSL_ASYNC_CleanupThread();
#endif
    PerfAffinityRestore();
    return ret;
}
