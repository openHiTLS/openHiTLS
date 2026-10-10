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

#ifndef ASYNC_PERF_AFFINITY_H
#define ASYNC_PERF_AFFINITY_H
#include <stdio.h>
#include "sim_prov_ctrl.h"

int PerfAffinityInit(int cpu, uint32_t workers);
void PerfAffinityConfigure(SIM_PROV_CTRL_REQ *req);
void PerfAffinityRestore(void);
#endif
