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

#include "affinity.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include <sched.h>

typedef struct {
    uint64_t total;
    uint64_t idle;
    int package;
    int core;
    double busy;
    bool present;
} PerfCpu;

static cpu_set_t g_original;
static PerfCpu g_cpus[CPU_SETSIZE];
static int32_t g_selected[CPU_SETSIZE];
static uint32_t g_selectedCount;
static bool g_pinned;

static bool PerfReadCpuTimes(PerfCpu *cpus)
{
    FILE *f = fopen("/proc/stat", "r");
    if (f == NULL) {
        return false;
    }
    char line[512];
    while (fgets(line, sizeof(line), f) != NULL) {
        unsigned cpu;
        unsigned long long user, nice, system, idle, wait, irq, softirq, steal;
        if (sscanf(line, "cpu%u %llu %llu %llu %llu %llu %llu %llu %llu", &cpu, &user, &nice, &system, &idle, &wait,
                   &irq, &softirq, &steal) != 9 ||
            cpu >= CPU_SETSIZE) {
            continue;
        }
        cpus[cpu].total = user + nice + system + idle + wait + irq + softirq + steal;
        cpus[cpu].idle = idle;
        cpus[cpu].present = true;
    }
    fclose(f);
    return true;
}

static int PerfTopology(int cpu, const char *field)
{
    char path[160];
    snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/topology/%s", cpu, field);
    FILE *f = fopen(path, "r");
    int value = -1;
    if (f != NULL) {
        if (fscanf(f, "%d", &value) != 1) {
            value = -1;
        }
        fclose(f);
    }
    return value;
}

static bool PerfSameCore(int a, int b)
{
    return g_cpus[a].package == g_cpus[b].package && g_cpus[a].core == g_cpus[b].core;
}

static double PerfCoreBusy(int cpu)
{
    double busy = g_cpus[cpu].busy;
    for (int i = 0; i < CPU_SETSIZE; i++) {
        if (g_cpus[i].present && PerfSameCore(cpu, i) && g_cpus[i].busy > busy) {
            busy = g_cpus[i].busy;
        }
    }
    return busy;
}

static bool PerfCpuAvailable(int cpu)
{
    if (!CPU_ISSET(cpu, &g_original) || !g_cpus[cpu].present || g_cpus[cpu].package < 0 || g_cpus[cpu].core < 0 ||
        PerfCoreBusy(cpu) > 10.0) {
        return false;
    }
    for (uint32_t i = 0; i < g_selectedCount; i++) {
        if (PerfSameCore(cpu, g_selected[i])) {
            return false;
        }
    }
    return true;
}

int PerfAffinityInit(int cpu, uint32_t workers)
{
    if (cpu == -1) {
        return 0;
    }
    PerfCpu before[CPU_SETSIZE] = {0};
    if (workers >= CPU_SETSIZE - 1 || sched_getaffinity(0, sizeof(g_original), &g_original) != 0 ||
        !PerfReadCpuTimes(before)) {
        goto FAIL;
    }
    struct timespec delay = {0, 500000000};
    while (nanosleep(&delay, &delay) != 0) {
        if (errno != EINTR) {
            goto FAIL;
        }
    }
    if (!PerfReadCpuTimes(g_cpus)) {
        goto FAIL;
    }
    for (int i = 0; i < CPU_SETSIZE; i++) {
        if (!g_cpus[i].present) {
            continue;
        }
        g_cpus[i].package = PerfTopology(i, "physical_package_id");
        g_cpus[i].core = PerfTopology(i, "core_id");
        uint64_t total = g_cpus[i].total - before[i].total;
        uint64_t idle = g_cpus[i].idle - before[i].idle;
        g_cpus[i].busy =
            before[i].present && total > 0 && idle <= total ? 100.0 * (double)(total - idle) / (double)total : 100.0;
    }
    g_selectedCount = 0;
    for (uint32_t slot = 0; slot < workers + 2; slot++) {
        int best = -1;
        for (int i = 0; i < CPU_SETSIZE; i++) {
            if (slot == 0 && cpu >= 0 && cpu != i) {
                continue;
            }
            if (PerfCpuAvailable(i) && (best < 0 || PerfCoreBusy(i) < PerfCoreBusy(best))) {
                best = i;
            }
        }
        if (best < 0) {
            goto FAIL;
        }
        g_selected[g_selectedCount++] = best;
    }
    for (int i = 0; i < CPU_SETSIZE; i++) {
        if (PerfCpuAvailable(i)) {
            g_selected[g_selectedCount++] = i;
        }
    }
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(g_selected[0], &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        goto FAIL;
    }
    g_pinned = true;
    printf("CPU binding: dispatcher=%d workers=", g_selected[0]);
    for (uint32_t i = 1; i <= workers; i++) {
        printf("%s%d", i == 1 ? "" : ",", g_selected[i]);
    }
    printf(" clients=");
    for (uint32_t i = workers + 1; i < g_selectedCount; i++) {
        printf("%s%d", i == workers + 1 ? "" : ",", g_selected[i]);
    }
    printf(" (distinct physical cores, sampled busy <= 10%%)\n");
    return 0;
FAIL:
    fprintf(stderr, "cannot bind idle physical cores: need dispatcher + %u workers + client (Linux, busy <= 10%%)\n",
            workers);
    return -1;
}

void PerfAffinityConfigure(SIM_PROV_CTRL_REQ *req)
{
    if (g_pinned && req->execMode == SIM_PROV_EXEC_WORKER) {
        req->workerCpus = &g_selected[1];
        req->workerCpuCount = req->workers;
    }
}

void PerfAffinityRestore(void)
{
    if (g_pinned) {
        if (sched_setaffinity(0, sizeof(g_original), &g_original) != 0) {
            fprintf(stderr, "WARNING: cannot restore CPU affinity\n");
        }
        g_pinned = false;
    }
}
