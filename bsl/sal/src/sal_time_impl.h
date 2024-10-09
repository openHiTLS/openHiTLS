/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef SAL_TIMEIMPL_H
#define SAL_TIMEIMPL_H

#include "hitls_build.h"
#ifdef HITLS_BSL_SAL_TIME

#include <stdint.h>
#include "bsl_sal.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef struct {
    BslSalGetSysTime pfGetSysTime;
    BslSalDateToStrConvert pfDateToStrConvert;
    BslSalSysTimeGet pfSysTimeGet;
    BslSalUtcTimeToDateConvert pfUtcTimeToDateConvert;
    BslSalSleep pfSleep;
    BslSalTick pfTick;
    BslSalTicksPerSec pfTicksPerSec;
} BSL_SAL_TimeCallback;

int32_t SAL_TimeCallback_Ctrl(BSL_SAL_CB_FUNC_TYPE type, void *funcCb);

#ifdef HITLS_BSL_SAL_LINUX
int64_t TIME_GetSysTime(void);
uint32_t TIME_DateToStrConvert(const BSL_TIME *dateTime, char *timeStr, size_t len);
uint32_t TIME_SysTimeGet(BSL_TIME *sysTime);
uint32_t TIME_UtcTimeToDateConvert(int64_t utcTime, BSL_TIME *sysTime);
void SAL_Sleep(uint32_t time);
long SAL_Tick(void);
long SAL_TicksPerSec(void);
#endif

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_BSL_SAL_TIME
#endif // SAL_TIMEIMPL_H

