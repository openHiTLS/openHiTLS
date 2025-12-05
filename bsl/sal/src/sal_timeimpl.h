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
    BslGetUtcTime pfGetUtcTime;
    BslGetBslTime pfGetBslTime;
    BslUtcTimeToBslTime pfUtcTimeToBslTime;
    BslSleep pfSleep;
    BslTick pfTick;
    BslTicksPerSec pfTicksPerSec;
    BslGetTimeInNS pfBslGetTimeInNS;
} BSL_SAL_TimeCallback;

/**
 * @brief Register the time-related callback function.
 * @param type [IN] Callback function type.
 * @param funcCb [IN] Pointer to the callback function.
 * @return BSL_SUCCESS is successfully executed.
 *         BSL_SAL_ERR_BAD_PARAM The parameter is incorrect.
 */
int32_t SAL_TimeCallBack_Ctrl(BSL_SAL_CB_FUNC_TYPE type, void *funcCb);

#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
int64_t SAL_TIME_GetSysTime(void);
uint32_t TIME_DateToStrConvert(const BSL_TIME *dateTime, char *timeStr, size_t len);
int32_t SAL_TIME_SysTimeGet(BSL_TIME *sysTime);
int32_t SAL_TIME_UtcTimeToDateConvert(int64_t utcTime, BSL_TIME *sysTime);
long SAL_TIME_Tick(void);
long SAL_TIME_TicksPerSec(void);
uint64_t SAL_TIME_GetNSec(void);

void SAL_TIME_Sleep(uint32_t time);
#endif
#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_BSL_SAL_TIME
#endif // SAL_TIMEIMPL_H

