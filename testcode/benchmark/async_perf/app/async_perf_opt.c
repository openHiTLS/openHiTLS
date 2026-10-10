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

/* Async perf benchmark: command line parsing and scenario expansion */

#include "async_perf_opt.h"
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <fnmatch.h>

#define FORM_PREFIX "hs-"

static const char *g_formNames[PERF_FORM_BUTT] = {"sync", "on-fd", "on-cb"};
static const char *g_profileNames[PERF_PROFILE_BUTT] = {
    "tls13-ecdhe-ecdsa",
    "tls13-ecdhe-rsa",
    "tls12-ecdhe-ecdsa",
    "tls12-ecdhe-rsa",
};

const char *PerfFormName(PerfForm f)
{
    return (f >= 0 && f < PERF_FORM_BUTT) ? g_formNames[f] : "?";
}

const char *PerfProfileName(PerfProfile p)
{
    return (p >= 0 && p < PERF_PROFILE_BUTT) ? g_profileNames[p] : "?";
}

void PerfScenarioName(const PerfScenario *s, char *buf, uint32_t bufLen)
{
    (void)snprintf(buf, bufLen, "%s%s-%s", FORM_PREFIX, PerfFormName(s->form), PerfProfileName(s->profile));
}

static void PerfOptDefault(PerfOptions *opt)
{
    (void)memset(opt, 0, sizeof(*opt));
    opt->pattern = "*";
    opt->concurrency = 1;
    opt->port = 44330;
    opt->execMode = PERF_EXEC_INLINE;
    opt->workers = 4;
    opt->pinCpu = -1;
    opt->certDir = HITLS_ASYNC_PERF_CERT_DIR;
}

static void PerfOptUsage(void)
{
    printf("openhitls_async_benchmark [options]\n");
    printf("  -a <glob>             scenario name glob ('*' default; forms select via 'hs-on-*')\n");
    printf("  --list                list all scenarios and exit\n");
    printf("  -c, --concurrency N   clients per batch (default 1; bounded by memory and file descriptors)\n");
    printf("  --port PORT          server loopback TCP port (default 44330)\n");
    printf("  --device-mode MODE    inline / worker (default inline)\n");
    printf("  -w, --workers P       worker threads in worker mode (default 4)\n");
    printf("  --provider-path DIR   provider .so directory\n");
    printf("  --pin-cpu CPU         auto or dispatcher CPU; bind idle physical cores\n");
    printf("  --cert-dir PATH       certificate directory\n");
}

static int PerfOptMatchInt(const char *s, uint32_t *out)
{
    char *end = NULL;
    errno = 0;
    unsigned long v = strtoul(s, &end, 10);
    if (*s == '-' || errno != 0 || v > UINT32_MAX || end == s || *end != '\0') {
        return -1;
    }
    *out = (uint32_t)v;
    return 0;
}

int PerfOptParse(int argc, char **argv, PerfOptions *opt)
{
    PerfOptDefault(opt);
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "-a") == 0 && i + 1 < argc) {
            opt->pattern = argv[++i];
        } else if (strcmp(a, "--list") == 0) {
            opt->listOnly = true;
        } else if ((strcmp(a, "-c") == 0 || strcmp(a, "--concurrency") == 0) && i + 1 < argc) {
            if (PerfOptMatchInt(argv[++i], &opt->concurrency) != 0 || opt->concurrency == 0) {
                printf("invalid concurrency: %s\n", argv[i]);
                return -1;
            }
        } else if (strcmp(a, "--port") == 0 && i + 1 < argc) {
            if (PerfOptMatchInt(argv[++i], &opt->port) != 0 || opt->port == 0 || opt->port > UINT16_MAX) {
                printf("invalid port: %s\n", argv[i]);
                return -1;
            }
        } else if (strcmp(a, "--device-mode") == 0 && i + 1 < argc) {
            const char *m = argv[++i];
            if (strcmp(m, "inline") == 0) {
                opt->execMode = PERF_EXEC_INLINE;
            } else if (strcmp(m, "worker") == 0) {
                opt->execMode = PERF_EXEC_WORKER;
            } else {
                printf("invalid device-mode: %s (inline|worker)\n", m);
                return -1;
            }
        } else if ((strcmp(a, "-w") == 0 || strcmp(a, "--workers") == 0) && i + 1 < argc) {
            if (PerfOptMatchInt(argv[++i], &opt->workers) != 0 || opt->workers == 0) {
                printf("invalid workers: %s\n", argv[i]);
                return -1;
            }
        } else if (strcmp(a, "--provider-path") == 0 && i + 1 < argc) {
            opt->providerPath = argv[++i];
        } else if (strcmp(a, "--pin-cpu") == 0 && i + 1 < argc) {
            if (strcmp(argv[i + 1], "auto") == 0) {
                opt->pinCpu = -2;
                i++;
                continue;
            }
            uint32_t cpu;
            if (PerfOptMatchInt(argv[++i], &cpu) != 0 || cpu > INT_MAX) {
                return -1;
            }
            opt->pinCpu = (int)cpu;
        } else if (strcmp(a, "--cert-dir") == 0 && i + 1 < argc) {
            opt->certDir = argv[++i];
        } else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            PerfOptUsage();
            return -1;
        } else {
            printf("unknown option: %s\n", a);
            PerfOptUsage();
            return -1;
        }
    }
    if (opt->workers > 1024) {
        printf("option out of range\n");
        return -1;
    }
    return 0;
}

int PerfOptExpand(const PerfOptions *opt, PerfScenario *scenarios)
{
    int count = 0;
    for (PerfForm f = PERF_FORM_SYNC; f < PERF_FORM_BUTT; f++) {
        for (PerfProfile p = 0; p < PERF_PROFILE_BUTT; p++) {
            PerfScenario scenario = {.form = f, .profile = p};
            char name[64];
            PerfScenarioName(&scenario, name, sizeof(name));
            if (fnmatch(opt->pattern, name, 0) == 0) {
                scenarios[count++] = scenario;
            }
        }
    }
    return count;
}

void PerfOptPrintList(const PerfOptions *opt)
{
    PerfScenario list[PERF_FORM_BUTT * PERF_PROFILE_BUTT];
    int n = PerfOptExpand(opt, list);
    printf("%-36s %-10s %-8s %s\n", "scenario", "concurr.", "exec", "workers");
    for (int i = 0; i < n; i++) {
        char name[128];
        PerfScenarioName(&list[i], name, sizeof(name));
        printf("%-36s %-10u %-8s %u\n", name, opt->concurrency, opt->execMode == PERF_EXEC_INLINE ? "inline" : "worker",
               opt->execMode == PERF_EXEC_INLINE ? 0 : opt->workers);
    }
}
