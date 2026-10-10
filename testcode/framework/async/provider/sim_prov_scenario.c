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

/* Simulation provider: scenario matching engine */

#include "sim_prov_internal.h"

#ifdef HITLS_CRYPTO_PROVIDER

static uint32_t SimOperaSlot(uint32_t operaId)
{
    /* CRYPT_EAL_OPERAID_* values are 1..12; anything else folds into slot 15 */
    if (operaId >= 1 && operaId <= 12) {
        return operaId;
    }
    return 15;
}

void SimScenarioMatch(SimEngine *e, uint32_t operaId, SimScenarioSnap *snap)
{
    /* Default action: COMPLETE with no extra pauses */
    snap->action = SIM_PROV_ACTION_COMPLETE;
    snap->resumeCount = 0;
    snap->notifyRepeat = 0;
    snap->waitNs = SIM_PROV_WAIT_INHERIT;
    snap->errCode = 0;

    uint32_t slot = SimOperaSlot(operaId);
    uint64_t hit = ++e->hits[slot];

    if (e->scenarios == NULL || e->scenarioCount == 0) {
        return;
    }
    for (uint32_t i = 0; i < e->scenarioCount; i++) {
        const SIM_PROV_SCENARIO *s = &e->scenarios[i];
        if (e->disarmed[i]) {
            continue;
        }
        if (s->operaId != SIM_PROV_OPERA_ANY && s->operaId != operaId) {
            continue;
        }
        if (s->hitIndex != 0 && s->hitIndex != hit) {
            continue;
        }
        /* first match wins */
        if (s->once == 1) {
            e->disarmed[i] = true;
        }
        snap->action = s->action;
        snap->resumeCount = s->resumeCount == 0 ? 1 : s->resumeCount;
        snap->notifyRepeat = s->notifyRepeat;
        snap->waitNs = s->waitNs;
        snap->errCode = s->errCode;
        return;
    }
}

#endif /* HITLS_CRYPTO_PROVIDER */
