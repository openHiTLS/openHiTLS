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
#ifdef HITLS_BSL_SAL_TIME

#ifdef HITLS_BSL_ERR
#include "bsl_err_internal.h"
#endif
#include "bsl_sal.h"
#include "sal_timeimpl.h"
#include "bsl_errno.h"
#include "sal_time.h"

static BSL_SAL_TimeCallback g_timeCallback = {0};

int32_t SAL_TimeCallback_Ctrl(BSL_SAL_CB_FUNC_TYPE type, void *funcCb)
{
    if (type > BSL_SAL_TIME_GET_TIME_IN_NS || type < BSL_SAL_TIME_GET_UTC_TIME_CB_FUNC) {
        return BSL_SAL_TIME_NO_REG_FUNC;
    }
    uint32_t offset = (uint32_t)(type - BSL_SAL_TIME_GET_UTC_TIME_CB_FUNC);
    ((void **)&g_timeCallback)[offset] = funcCb;
    return BSL_SUCCESS;
}

void BSL_SAL_SysTimeFuncReg(BslTimeFunc func)
{
    if (func != NULL) {
        g_timeCallback.pfGetSysTime = func;
    }
    return;
}

void BSL_SysTimeFuncUnReg(void)
{
    g_timeCallback.pfGetSysTime = NULL;
    return;
}

bool BSL_IsLeapYear(uint32_t year)
{
    return ((((year % 4U) == 0U) && ((year % 100U) != 0U)) || ((year % 400U) == 0U));
}

static int64_t BslMkTime64Get(const BSL_TIME *inputTime)
{
    int64_t result;
    uint32_t i;
    int32_t unixYear;
    int32_t unixDay;
    int32_t extraDay = 0;
    int32_t year   = inputTime->year;
    int32_t month  = inputTime->month - 1;
    int32_t day    = inputTime->day;
    int32_t hour   = inputTime->hour;
    int32_t minute = inputTime->minute;
    int32_t second = inputTime->second;
    int32_t monthTable[13] = {0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365};

    for (i = BSL_TIME_SYSTEM_EPOCH_YEAR; (int32_t)i < year; i++) {
        if (BSL_IsLeapYear(i) == true) {
            extraDay++;
        }
    }

    unixYear = year - (int32_t)BSL_TIME_SYSTEM_EPOCH_YEAR;
    if (BSL_IsLeapYear((uint32_t)year) == true) {
        for (i = BSL_MONTH_FEB; i < BSL_MONTH_DEC; i++) {
            monthTable[i] = monthTable[i] + 1;
        }
    }

    unixDay = (unixYear * (int32_t)BSL_TIME_DAY_PER_NONLEAP_YEAR) + monthTable[month] + (day - 1) + extraDay;
    result = unixDay * (int64_t)86400; /* 86400 is the number of seconds in a day */
    result = (hour * (int64_t)3600) + result;  /* 3600 is the number of seconds in a hour */
    result = (minute * (int64_t)60) + second + result;  /* 60 is the number of seconds in a minute */

    return result;
}

/**
 * @brief Convert the given date structure to the number of seconds since January 1,1970
 * @param inputTime [IN] Pointer to the date to be converted.
 * @param utcTime [OUT] Pointer to the storage of the conversion result
 * @return BSL_SUCCESS              successfully executed.
 *         BSL_INTERNAL_EXCEPTION   Execution Failure
 */
static uint32_t BslUtcTimeGet(const BSL_TIME *inputTime, int64_t *utcTime)
{
    int64_t result;

    if (inputTime == NULL || utcTime == NULL) {
        return BSL_INTERNAL_EXCEPTION;
    }
    if (BSL_DateTimeCheck(inputTime) == false) {
        return BSL_INTERNAL_EXCEPTION;
    }
    result = BslMkTime64Get(inputTime);
    if (result < 0) {
        *utcTime = -1;
        return BSL_INTERNAL_EXCEPTION;
    } else {
        *utcTime = result;
        return BSL_SUCCESS;
    }
}

#define BSL_TIMESTR_MINLEN 26

uint32_t BSL_DateToStrConvert(const BSL_TIME *dateTime, char *timeStr, size_t len)
{
    if (dateTime == NULL || timeStr == NULL || len < BSL_TIMESTR_MINLEN) {
        return BSL_INTERNAL_EXCEPTION;
    }
    if (BSL_DateTimeCheck(dateTime) != true) {
        return BSL_INTERNAL_EXCEPTION;
    }

    if (g_timeCallback.pfDateToStrConvert != NULL && g_timeCallback.pfDateToStrConvert != BSL_DateToStrConvert) {
        return g_timeCallback.pfDateToStrConvert(dateTime, timeStr, len);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return TIME_DateToStrConvert(dateTime, timeStr, len);
#else
    return BSL_SAL_TIME_NO_REG_FUNC;
#endif
}

int64_t BSL_SAL_CurrentSysTimeGet(void)
{
    if (g_timeCallback.pfGetSysTime != NULL && g_timeCallback.pfGetSysTime != BSL_SAL_CurrentSysTimeGet) {
        return g_timeCallback.pfGetSysTime();
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return TIME_GetSysTime();
#else
    BSL_ERR_PUSH_ERROR(BSL_SAL_TIME_NO_REG_FUNC);
    return 0;
#endif
}

static uint32_t BslDateTimeCmpCheck(const BSL_TIME *dateA, int64_t *utcTimeA,
                                    const BSL_TIME *dateB, int64_t *utcTimeB)
{
    if ((dateA == NULL) || (dateB == NULL)) {
        return BSL_INTERNAL_EXCEPTION;
    }

    if (BslUtcTimeGet(dateA, utcTimeA) != BSL_SUCCESS) {
        return BSL_INTERNAL_EXCEPTION;
    }
    if (BslUtcTimeGet(dateB, utcTimeB) != BSL_SUCCESS) {
        return BSL_INTERNAL_EXCEPTION;
    }

    return BSL_SUCCESS;
}

int32_t BSL_SAL_DateTimeCompare(const BSL_TIME *dateA, const BSL_TIME *dateB, int64_t *diffSec)
{
    int64_t utcTimeA = 0;
    int64_t utcTimeB = 0;
    int64_t dTimeDiff;
    uint32_t ret;

    if (BslDateTimeCmpCheck(dateA, &utcTimeA, dateB, &utcTimeB) == BSL_SUCCESS) {
        dTimeDiff = utcTimeA - utcTimeB;
        if (diffSec != NULL) {
            *diffSec = dTimeDiff;
        }

        if (dTimeDiff < 0) {
            ret = (uint32_t)BSL_TIME_DATE_BEFORE;
        } else if (dTimeDiff > 0) {
            ret = (uint32_t)BSL_TIME_DATE_AFTER;
        } else {
            ret = (uint32_t)BSL_TIME_CMP_EQUAL;
        }
    } else {
        ret = (uint32_t)BSL_TIME_CMP_ERROR;
    }

    return ret;
}

static uint32_t TimeCmp(uint32_t a, uint32_t b)
{
    if (a > b) {
        return BSL_TIME_DATE_AFTER;
    }
    if (a < b) {
        return BSL_TIME_DATE_BEFORE;
    }
    return BSL_TIME_CMP_EQUAL;
}

int32_t BSL_SAL_DateTimeCompareByUs(const BSL_TIME *dateA, const BSL_TIME *dateB)
{
    int64_t diffSec = 0;
    uint32_t ret;

    ret = BSL_SAL_DateTimeCompare(dateA, dateB, &diffSec);
    if (ret != BSL_TIME_CMP_EQUAL) {
        return ret;
    }

    ret = TimeCmp(dateA->millSec, dateB->millSec);
    if (ret != BSL_TIME_CMP_EQUAL) {
        return ret;
    }

    return TimeCmp(dateA->microSec, dateB->microSec);
}

uint32_t BSL_DateTimeAddUs(BSL_TIME *dateR, const BSL_TIME *dateA, uint32_t us)
{
    uint32_t ret;
    int64_t utcTime = 0;

    /* Convert the date into seconds. */
    ret = BSL_SAL_DateToUtcTimeConvert(dateA, &utcTime);
    if (ret != BSL_SUCCESS) {
        return ret;
    }

    /* Convert the increased time to seconds */
    uint32_t microSec = us + dateA->microSec;
    uint32_t millSec = (microSec / BSL_SECOND_TRANSFER_RATIO) + dateA->millSec;
    microSec %= BSL_SECOND_TRANSFER_RATIO;
    uint32_t second = millSec / BSL_SECOND_TRANSFER_RATIO;
    millSec %= BSL_SECOND_TRANSFER_RATIO;

    /* Convert to the date after the number of seconds is added */
    utcTime += (int64_t)second;
    ret = BSL_SAL_UtcTimeToDateConvert(utcTime, dateR);
    if (ret != BSL_SUCCESS) {
        return ret;
    }

    /* Complete milliseconds and microseconds. */
    dateR->millSec = (uint16_t)millSec;
    dateR->microSec = microSec;
    return BSL_SUCCESS;
}

int32_t BSL_SAL_DateToUtcTimeConvert(const BSL_TIME *dateTime, int64_t *utcTime)
{
    uint32_t ret = BSL_INTERNAL_EXCEPTION;

    if ((dateTime != NULL) && (utcTime != NULL)) {
        if (BSL_DateTimeCheck(dateTime) == true) {
            ret = BslUtcTimeGet(dateTime, utcTime);
        }
    }

    return ret;
}

static bool BslFebDayValidCheck(uint16_t year, uint8_t day)
{
    bool ret;

    if ((BSL_IsLeapYear(year) == true) && (day <= BSL_TIME_LEAP_FEBRUARY_DAY)) {
        ret = true;
    } else if ((BSL_IsLeapYear(year) == false) && (day <= BSL_TIME_NOLEAP_FEBRUARY_DAY)) {
        ret = true;
    } else {
        ret = false;
    }
    return ret;
}

static bool BslDayValidCheck(uint16_t year, uint8_t month, uint8_t day)
{
    bool ret = true;

    switch (month) {
        case BSL_MONTH_JAN:
        case BSL_MONTH_MAR:
        case BSL_MONTH_MAY:
        case BSL_MONTH_JUL:
        case BSL_MONTH_AUG:
        case BSL_MONTH_OCT:
        case BSL_MONTH_DEC:
            if (day > BSL_TIME_BIG_MONTH_DAY) {
                ret = false;
            }
            break;

        case BSL_MONTH_APR:
        case BSL_MONTH_JUN:
        case BSL_MONTH_SEM:
        case BSL_MONTH_NOV:
            if (day > BSL_TIME_SMALL_MONTH_DAY) {
                ret = false;
            }
            break;

        case BSL_MONTH_FEB:
            ret = BslFebDayValidCheck(year, day);
            break;

        default:
            ret = false;
            break;
    }
    return ret;
}

static bool BslYearMonthDayCheck(const BSL_TIME *dateTime)
{
    if (dateTime->year < BSL_TIME_SYSTEM_EPOCH_YEAR) {
        return false;
    } else if ((dateTime->month < BSL_MONTH_JAN) || (dateTime->month > BSL_MONTH_DEC)) {
        return false;
    } else if (dateTime->day < BSL_MONTH_JAN) {
        return false;
    } else {
        return BslDayValidCheck(dateTime->year, dateTime->month, dateTime->day);
    }
}

static bool BslHourMinSecCheck(const BSL_TIME *dateTime)
{
    bool ret;

    if (dateTime->hour > 23U) {
        ret = false;
    } else if (dateTime->minute > 59U) {
        ret = false;
    } else if (dateTime->second > 59U) {
        ret = false;
    } else if (dateTime->millSec > 999U) {
        ret = false;
    } else if (dateTime->microSec > 999U) { /* microseconds does not exceed the maximum value 1000 */
        ret = false;
    } else {
        ret = true;
    }

    return ret;
}

bool BSL_DateTimeCheck(const BSL_TIME *dateTime)
{
    bool ret = true;

    if ((BslYearMonthDayCheck(dateTime) == false) ||
        (BslHourMinSecCheck(dateTime) == false)) {
        ret = false;
    }

    return ret;
}

int32_t BSL_SAL_UtcTimeToDateConvert(int64_t utcTime, BSL_TIME *sysTime)
{
    if (sysTime == NULL || utcTime > BSL_UTCTIME_MAX) {
        return BSL_SAL_ERR_BAD_PARAM;
    }
    if (g_timeCallback.pfUtcTimeToDateConvert != NULL &&
        g_timeCallback.pfUtcTimeToDateConvert != (BslSalUtcTimeToDateConvert)BSL_SAL_UtcTimeToDateConvert) {
        return g_timeCallback.pfUtcTimeToDateConvert(utcTime, sysTime);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return TIME_UtcTimeToDateConvert(utcTime, sysTime);
#else
    return BSL_SAL_TIME_NO_REG_FUNC;
#endif
}

int32_t BSL_SAL_SysTimeGet(BSL_TIME *sysTime)
{
    if (sysTime == NULL) {
        return BSL_SAL_ERR_BAD_PARAM;
    }
    if (g_timeCallback.pfSysTimeGet != NULL && g_timeCallback.pfSysTimeGet != (BslSalSysTimeGet)BSL_SAL_SysTimeGet) {
        return g_timeCallback.pfSysTimeGet(sysTime);
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return TIME_SysTimeGet(sysTime);
#else
    return BSL_SAL_TIME_NO_REG_FUNC;
#endif
}

void BSL_SAL_Sleep(uint32_t time)
{
    if (g_timeCallback.pfSleep != NULL && g_timeCallback.pfSleep != BSL_SAL_Sleep) {
        g_timeCallback.pfSleep(time);
        return;
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    SAL_Sleep(time);
#endif
}

long BSL_SAL_Tick(void)
{
    if (g_timeCallback.pfTick != NULL && g_timeCallback.pfTick != BSL_SAL_Tick) {
        return g_timeCallback.pfTick();
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_Tick();
#else
    return BSL_SAL_TIME_NO_REG_FUNC;
#endif
}

long BSL_SAL_TicksPerSec(void)
{
    if (g_timeCallback.pfTicksPerSec != NULL && g_timeCallback.pfTicksPerSec != BSL_SAL_TicksPerSec) {
        return g_timeCallback.pfTicksPerSec();
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_TicksPerSec();
#else
    return BSL_SAL_TIME_NO_REG_FUNC;
#endif
}

uint64_t BSL_SAL_TIME_GetNSec(void)
{
    if (g_timeCallback.pfBslGetTimeInNS != NULL && g_timeCallback.pfBslGetTimeInNS != BSL_SAL_TIME_GetNSec) {
        return g_timeCallback.pfBslGetTimeInNS();
    }
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    return SAL_TIME_GetNSec();
#else
    BSL_ERR_PUSH_ERROR(BSL_SAL_TIME_NO_REG_FUNC);
    return 0;
#endif
}
#endif /* HITLS_BSL_SAL_TIME */
