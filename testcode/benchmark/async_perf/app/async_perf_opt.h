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

#ifndef ASYNC_PERF_OPT_H
#define ASYNC_PERF_OPT_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Form: runtime mode + completion-notify path */
typedef enum {
    PERF_FORM_SYNC = 0,
    PERF_FORM_ON_FD = 1,
    PERF_FORM_ON_CB = 2,
    PERF_FORM_BUTT,
} PerfForm;

/* Device execution mode */
typedef enum {
    PERF_EXEC_INLINE = 1,
    PERF_EXEC_WORKER = 2,
} PerfExecMode;

/* Profile: protocol + suite composition */
typedef enum {
    PERF_PROFILE_TLS13_ECDHE_ECDSA = 0,
    PERF_PROFILE_TLS13_ECDHE_RSA,
    PERF_PROFILE_TLS12_ECDHE_ECDSA,
    PERF_PROFILE_TLS12_ECDHE_RSA,
    PERF_PROFILE_BUTT,
} PerfProfile;

/* TLS profile and server mode. */
typedef struct {
    PerfForm form;
    PerfProfile profile;
} PerfScenario;

/* Parsed command line */
typedef struct {
    const char *pattern; /* -a glob, default '*' */
    uint32_t concurrency;
    uint32_t port;
    PerfExecMode execMode;
    uint32_t workers;
    const char *providerPath;
    const char *certDir;
    int pinCpu;
    bool listOnly;
} PerfOptions;

#define PERF_PROVIDER_NAME "async_sim_provider"
#define PERF_PROVIDER_ATTR "provider=async_sim_async"

/* Parse argv; returns 0 on success, nonzero on usage error (message printed). */
int PerfOptParse(int argc, char **argv, PerfOptions *opt);

int PerfOptExpand(const PerfOptions *opt, PerfScenario *scenarios);

/* Form name ("sync"/"on-fd"/"on-cb") */
const char *PerfFormName(PerfForm f);
/* Profile name ("tls13-ecdhe-ecdsa" ...) */
const char *PerfProfileName(PerfProfile p);
/* Full scenario name "hs-<form>-<profile>" */
void PerfScenarioName(const PerfScenario *s, char *buf, uint32_t bufLen);

/* Print the --list table. */
void PerfOptPrintList(const PerfOptions *opt);

#ifdef __cplusplus
}
#endif

#endif /* ASYNC_PERF_OPT_H */
