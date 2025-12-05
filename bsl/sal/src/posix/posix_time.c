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

#include "hitls_build.h"
#if (defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)) && defined(HITLS_BSL_SAL_TIME)

#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/times.h>
#include "bsl_sal.h"
#include "sal_time.h"
#include "bsl_errno.h"

int64_t SAL_TIME_GetSysTime(void)
{
    return (int64_t)time(NULL);
}

uint32_t TIME_DateToStrConvert(const BSL_TIME *dateTime, char *timeStr, size_t len)
{
    struct tm timeStruct = {0};
    timeStruct.tm_year = (int32_t)dateTime->year - (int32_t)BSL_TIME_YEAR_START;
    timeStruct.tm_mon  = (int32_t)dateTime->month - 1;
    timeStruct.tm_mday = (int32_t)dateTime->day;
    timeStruct.tm_hour = (int32_t)dateTime->hour;
    timeStruct.tm_min  = (int32_t)dateTime->minute;
    timeStruct.tm_sec  = (int32_t)dateTime->second;
    if (asctime_r(&timeStruct, timeStr) != NULL) {
        return BSL_SUCCESS;
    }
    (void)len;
    return BSL_INTERNAL_EXCEPTION;
}

int32_t SAL_TIME_SysTimeGet(BSL_TIME *sysTime)
{
    struct timeval tv = {0};
    int timeRet = gettimeofday(&tv, NULL);
    if (timeRet != 0) {
        return BSL_SAL_TIME_SYS_ERROR;
    }

    tzset();
    int32_t ret = BSL_SAL_UtcTimeToDateConvert((int64_t)tv.tv_sec, sysTime);
    if (ret == BSL_SUCCESS) {
        /* milliseconds : non-thread safe */
        sysTime->millSec = (uint16_t)(tv.tv_usec / 1000U);  /* 1000 is multiple */
        sysTime->microSec = (uint16_t)(tv.tv_usec % 1000U); /* 1000 is multiple */
    }

    return ret;
}

int32_t SAL_TIME_UtcTimeToDateConvert(int64_t utcTime, BSL_TIME *sysTime)
{
    struct tm tempTime;
    time_t utcTimeTmp = (time_t)utcTime;
    if (gmtime_r(&utcTimeTmp, &tempTime) == NULL) {
        return BSL_SAL_TIME_BAD_PARAM;
    }

    sysTime->year = (uint16_t)((uint16_t)tempTime.tm_year + BSL_TIME_YEAR_START); /* 1900 is base year */
    sysTime->month = (uint8_t)((uint8_t)tempTime.tm_mon + 1U);
    sysTime->day = (uint8_t)tempTime.tm_mday;
    sysTime->hour = (uint8_t)tempTime.tm_hour;
    sysTime->minute = (uint8_t)tempTime.tm_min;
    sysTime->second = (uint8_t)tempTime.tm_sec;
    sysTime->millSec = 0U;
    sysTime->microSec = 0U;
    return BSL_SUCCESS;
}

void SAL_TIME_Sleep(uint32_t time)
{
    sleep(time);
}

long SAL_TIME_Tick(void)
{
    struct tms buf = {0};
    clock_t tickCount = times(&buf);
    return (long)tickCount;
}

long SAL_TIME_TicksPerSec(void)
{
    return sysconf(_SC_CLK_TCK);
}

// Get time in nanoseconds.
uint64_t SAL_TIME_GetNSec(void)
{
#if defined(HITLS_BSL_SAL_DARWIN)
    /* macOS/Darwin: Use clock_gettime_nsec_np for nanosecond precision */
    return clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
#elif defined(HITLS_BSL_SAL_LINUX)
    /* Linux: Use CLOCK_MONOTONIC (sufficient precision on Linux) */
    uint64_t ticks = 0;
    struct timespec time;
    if (clock_gettime(CLOCK_REALTIME, &time) == 0) {
        ticks = ((uint64_t)time.tv_sec & 0xFFFFFFFF) * 1000000000UL;
        ticks = ticks + (uint64_t)time.tv_nsec;
    }
    return ticks;
#else
    #error "SAL_TIME_GetNSec not implemented for this platform"
#endif
}
#endif
