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

/* BEGIN_HEADER */

#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <sys/times.h>
#include "bsl_sal.h"
#include "sal_time.h"
#include "bsl_errno.h"

static int64_t TestBslSysTimeFunc(void)
{
    return (time_t)1;
}

static int64_t TestBslSysTimeFunc1(void)
{
    return time(NULL);
}

static void TestBslSysTimeInit(BSL_TIME *dateTime)
{
    dateTime->year = 1990;
    dateTime->month = 6;
    dateTime->day = 12;
    dateTime->hour = 10;
    dateTime->minute = 3;
    dateTime->microSec = 1;
    dateTime->millSec = 1;
}

static void TestBslSysTimeAndTmCompare(BSL_TIME *dateTime, struct tm *tempTime)
{
    ASSERT_EQ(dateTime->year, tempTime->tm_year + 1900); /* 1900 is base year */
    ASSERT_EQ(dateTime->month, tempTime->tm_mon + 1U);
    ASSERT_EQ(dateTime->day, tempTime->tm_mday);
    ASSERT_EQ(dateTime->hour, tempTime->tm_hour);
    ASSERT_EQ(dateTime->minute, tempTime->tm_min);
    ASSERT_EQ(dateTime->second, tempTime->tm_sec);
EXIT:
    return;
}
/* END_HEADER */

/**
 * @test SDV_BSL_TIME_FUNC_GET_DATETIME_TC001
 * @title Function test of obtaining the date as a character string.
 * @precon
 * @brief    1.The input parameter dateTime, timeStr, or len is invalid (less than the storage length).
 *           2.Invalid time.
 *           3.The time is legal.
 * @expect   1.Fail, return BSL_ERR
 *           2.Fail, return BSL_ERR
 *           3.Success, return BSL_SUCCESS
 */
/* BEGIN_CASE */
void SDV_BSL_TIME_FUNC_GET_DATETIME_TC001(void)
{
    BSL_TIME dateTime = {0};
    char timeStr[26];

    timeStr[0] = '\0';
    dateTime.year = BSL_TIME_SYSTEM_EPOCH_YEAR;
    dateTime.month = 1;
    dateTime.day = 1;
    dateTime.hour = 0;
    dateTime.minute = 0;
    dateTime.second = 0;

    /* 1.The input parameter dateaTime or timeStr is invalid. */
    ASSERT_EQ(BSL_DateToStrConvert(NULL, timeStr, 26), (uint32_t)BSL_INTERNAL_EXCEPTION);
    ASSERT_EQ(BSL_DateToStrConvert(&dateTime, NULL, 26), (uint32_t)BSL_INTERNAL_EXCEPTION);

    /* 2.Invalid time. */
    dateTime.month = 13;
    ASSERT_EQ(BSL_DateToStrConvert(&dateTime, timeStr, 26), (uint32_t)BSL_INTERNAL_EXCEPTION);
    dateTime.month = 1;

    /* 3.The time is legal. */
    ASSERT_EQ(BSL_DateToStrConvert(&dateTime, timeStr, 26), (uint32_t)BSL_SUCCESS);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_TIME_FUNC_REGISTER_TC001
 * @title Obtaining the current system time
 * @precon
 * @brief
 *    1. Registering System Time Hooks, obtain the Unix time. Expected result 1 is obtained.
 *    2. Unregistered system time hook, Obtain the Unix time. Expected result 2 is obtained.
 *    3. Unregister System Time Hook, Obtain the Unix time. Expected result 3 is obtained.
 * @expect
 *    1. The operation is successful, 0 is returned.
 *    2. The operation is successful, 0 is returned. The hook has not changed
 *    3. The operation is successful, a non-zero value is returned.
 */
/* BEGIN_CASE */
void SDV_BSL_TIME_FUNC_REGISTER_TC001(void)
{
    /* 1.Registering System Time Hooks */
    BSL_SAL_SysTimeFuncReg(TestBslSysTimeFunc);
    ASSERT_EQ(BSL_SAL_CurrentSysTimeGet(), 1);

    /* 2.Unregistered system time hook */
    BSL_SAL_SysTimeFuncReg(NULL);
    ASSERT_EQ(BSL_SAL_CurrentSysTimeGet(), 1);

    BSL_SysTimeFuncUnReg();

    ASSERT_NE(BSL_SAL_CurrentSysTimeGet(), 1);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_SAL_TIME_CMP_TIME_API_TC001
 * @title Time comparison function test
 * @precon
 * @brief
 *    1. The existence time is invalid. Expected result 1 is obtained.
 *    2. The two dates are consistent. Expected result 2 is obtained.
 *    3. The first date is before the second date. Expected result 3 is obtained.
 *    4. The first date is after the second. Expected result 3 is obtained.
 * @expect
 *    1. Fail, return BSL_TIME_CMP_ERROR
 *    2. Success, return BSL_TIME_CMP_EQUAL
 *    3. Success, return BSL_TIME_DATE_BEFORE
 *    4. Success, return BSL_TIME_DATE_AFTER
 */
/* BEGIN_CASE */
void SDV_BSL_SAL_TIME_CMP_TIME_API_TC001(void)
{
    int64_t diffSec;
    BSL_TIME dateA = {0};
    BSL_TIME dateB = {0};

    dateA.year = BSL_TIME_SYSTEM_EPOCH_YEAR;
    dateA.month = 1;
    dateA.day = 1;

    dateB.year = BSL_TIME_SYSTEM_EPOCH_YEAR;
    dateB.month = 1;
    dateB.day = 1;

    /* 1.The existence time is invalid */
    ASSERT_EQ(BSL_SAL_DateTimeCompare(NULL, &dateB, &diffSec), BSL_TIME_CMP_ERROR);

    /* 2.The two dates are consistent */
    ASSERT_EQ(BSL_SAL_DateTimeCompare(&dateA, &dateB, &diffSec), BSL_TIME_CMP_EQUAL);
    ASSERT_EQ(diffSec, 0);

    /* 3.The first date is before the second date */
    dateB.second = 1;
    ASSERT_EQ(BSL_SAL_DateTimeCompare(&dateA, &dateB, &diffSec), BSL_TIME_DATE_BEFORE);
    ASSERT_EQ(diffSec, -1);
    dateB.second = 0;

    /* 4.The first date is after the second */
    dateA.second = 1;
    ASSERT_EQ(BSL_SAL_DateTimeCompare(&dateA, &dateB, &diffSec), BSL_TIME_DATE_AFTER);
    ASSERT_EQ(diffSec, 1);
    dateA.second = 0;
EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_SAL_TIME_CMP_TIME_API_TC002
 * @title Time comparison function test
 * @precon
 * @brief
 *    1. The existence time is invalid. Expected result 1 is obtained.
 *    2. The two dates are consistent. Expected result 2 is obtained.
 *    3. The first date is before the second date. Expected result 3 is obtained.
 *    4. The first date is after the second. Expected result 3 is obtained.
 * @expect
 *    1. Fail, return BSL_TIME_CMP_ERROR
 *    2. Success, return BSL_TIME_CMP_EQUAL
 *    3. Success, return BSL_TIME_DATE_BEFORE
 *    4. Success, return BSL_TIME_DATE_AFTER
 */
/* BEGIN_CASE */
void SDV_BSL_SAL_TIME_CMP_TIME_API_TC002(void)
{
    BSL_TIME dateA = {0};
    BSL_TIME dateB = {0};

    dateA.year = BSL_TIME_SYSTEM_EPOCH_YEAR;
    dateA.month = 1;
    dateA.day = 1;
    dateA.millSec = 2;
    dateA.microSec = 3;

    dateB.year = BSL_TIME_SYSTEM_EPOCH_YEAR;
    dateB.month = 1;
    dateB.day = 1;
    dateB.millSec = 2;
    dateB.microSec = 3;

    /* 1.The existence time is invalid. */
    ASSERT_EQ(BSL_SAL_DateTimeCompareByUs(NULL, &dateB), BSL_TIME_CMP_ERROR);

    /* 2.The two dates are consistent. */
    ASSERT_EQ(BSL_SAL_DateTimeCompareByUs(&dateA, &dateB), BSL_TIME_CMP_EQUAL);

    /* 3.The first date is before the second date. */
    dateB.millSec = 1;
    ASSERT_EQ(BSL_SAL_DateTimeCompareByUs(&dateA, &dateB), BSL_TIME_DATE_AFTER);
    dateB.millSec = 2;

    /* 4.The first date is after the second */
    dateA.microSec = 1;
    ASSERT_EQ(BSL_SAL_DateTimeCompareByUs(&dateA, &dateB), BSL_TIME_DATE_BEFORE);
    dateA.microSec = 0;
EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_TIME_SYSTIME_API_TC001
 * @title Obtaining the System Time
 * @precon
 * @brief
 *    1. Call BSL_SAL_SysTimeGet to transfer the NULL parameter. Expected result 1 is obtained.
 *    2. Call BSL_SAL_SysTimeGet to transfer the normal parameter. Expected result 2 is obtained.
 * @expect
 *    1. Return BSL_SAL_ERR_BAD_PARAM.
 *    2. The obtained time is the same as the expected value. Return BSL_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_BSL_TIME_SYSTIME_API_TC001(void)
{
    BSL_TIME systime;
    uint32_t ret;

    /* The time obtaining interface is registered as time. */
    BSL_SAL_SysTimeFuncReg(TestBslSysTimeFunc1);

    ret = BSL_SAL_SysTimeGet(NULL);
    ASSERT_EQ(ret, BSL_SAL_ERR_BAD_PARAM);

    ret = BSL_SAL_SysTimeGet(&systime);
    ASSERT_TRUE(ret == BSL_SUCCESS);

    /* Get the current time. */
    int64_t curtime = time(NULL);

    int64_t timestamp = 0;
    ret = BSL_SAL_DateToUtcTimeConvert(&systime, &timestamp);
    ASSERT_LT(abs((int)(curtime - timestamp)), 5);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_TIME_CONVERT_TIME_FUNC_TC001
 * @title UTC time conversion
 * @precon
 * @brief
 *    1. Call BSL_SAL_DateToUtcTimeConvert to transfer the NULL parameter. Expected result 1 is obtained.
 *    2. Call BSL_SAL_DateToUtcTimeConvert to transfer an exception parameter. Expected result 1 is obtained.
 *    3. Call BSL_SAL_DateToUtcTimeConvert to transfer normal parameters. Expected result 2 is obtained.
 * @expect
 *    1. Fail, return BSL_ERR
 *    2. Fail, return BSL_ERR
 *    3. Success, return BSL_SUCCESS
 */
/* BEGIN_CASE */
void SDV_BSL_TIME_CONVERT_TIME_FUNC_TC001(void)
{
    int64_t utcTime;
    BSL_TIME dateTime = {0};

    /* 1.The input parameter dateTime or utcTime is empty. */
    ASSERT_TRUE(BSL_SAL_DateToUtcTimeConvert(NULL, &utcTime) == BSL_INTERNAL_EXCEPTION);
    ASSERT_TRUE(BSL_SAL_DateToUtcTimeConvert(&dateTime, NULL) == BSL_INTERNAL_EXCEPTION);

    /* 2.Failed to convert the time. */
    ASSERT_TRUE(BSL_SAL_DateToUtcTimeConvert(&dateTime, &utcTime) != BSL_SUCCESS);

    /* 3.Time conversion succeeded. */
    dateTime.year = BSL_TIME_SYSTEM_EPOCH_YEAR;
    dateTime.month = 1;
    dateTime.day = 1;
    dateTime.hour = 0;
    dateTime.minute = 0;
    dateTime.second = 0;
    ASSERT_TRUE(BSL_SAL_DateToUtcTimeConvert(&dateTime, &utcTime) == (uint32_t)BSL_SUCCESS);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_SAL_CONVERT_TIME_API_TC002
 * @title Converting BslSysTime to BslUnixTime
 * @precon
 * @brief
 *    1. The value of utcTime is 0. Expected result 1 is obtained.
 *    2. The value of utcTime is a negative number. Expected result 2 is obtained.
 *    3. The value of utcTime is INT32_MAX - 1. Expected result 3 is obtained.
 *    4. The value of utcTime is INT32_MAX. Expected result 4 is obtained.
 *    5. The value of utcTime is INT32_MAX + 1. Expected result 5 is obtained.
 *    6. The value of utcTime is BSL_UTCTIME_MAX. Expected result 6 is obtained.
 * @expect
 *    1. Success, return BSL_SUCCESS
 *    2. Success, return BSL_SUCCESS
 *    3. Success, return BSL_SUCCESS
 *    4. Success, return BSL_SUCCESS
 *    5. Success, return BSL_SUCCESS
 *    6. Success, return BSL_SUCCESS
 */
/* BEGIN_CASE */
void SDV_BSL_SAL_CONVERT_TIME_API_TC001(void)
{
    int64_t utcTime;
    BSL_TIME dateTime = {0};
    struct tm tempTime;

    utcTime = 0;
    ASSERT_TRUE(BSL_SAL_UtcTimeToDateConvert(utcTime, &dateTime) == BSL_SUCCESS);
    ASSERT_TRUE(gmtime_r((const time_t *)&utcTime, &tempTime) != NULL);
    TestBslSysTimeAndTmCompare(&dateTime, &tempTime);

    utcTime = -1;
    ASSERT_TRUE(BSL_SAL_UtcTimeToDateConvert(utcTime, &dateTime) == BSL_SUCCESS);
    ASSERT_TRUE(gmtime_r((const time_t *)&utcTime, &tempTime) != NULL);
    TestBslSysTimeAndTmCompare(&dateTime, &tempTime);

    utcTime = INT32_MAX;
    ASSERT_TRUE(BSL_SAL_UtcTimeToDateConvert(utcTime, &dateTime) == BSL_SUCCESS);
    ASSERT_TRUE(gmtime_r((const time_t *)&utcTime, &tempTime) != NULL);
    TestBslSysTimeAndTmCompare(&dateTime, &tempTime);

    utcTime = INT32_MAX - 1;
    ASSERT_TRUE(BSL_SAL_UtcTimeToDateConvert(utcTime, &dateTime) == BSL_SUCCESS);
    ASSERT_TRUE(gmtime_r((const time_t *)&utcTime, &tempTime) != NULL);
    TestBslSysTimeAndTmCompare(&dateTime, &tempTime);

    utcTime = (int64_t)INT32_MAX + 1;
    ASSERT_TRUE(BSL_SAL_UtcTimeToDateConvert(utcTime, &dateTime) == BSL_SUCCESS);
    ASSERT_TRUE(gmtime_r((const time_t *)&utcTime, &tempTime) != NULL);
    TestBslSysTimeAndTmCompare(&dateTime, &tempTime);

    utcTime = BSL_UTCTIME_MAX;
    ASSERT_TRUE(BSL_SAL_UtcTimeToDateConvert(utcTime, &dateTime) == BSL_SUCCESS);
    ASSERT_TRUE(gmtime_r((const time_t *)&utcTime, &tempTime) != NULL);
    TestBslSysTimeAndTmCompare(&dateTime, &tempTime);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_TIME_FUNC_DATETIME_CHECK_TC001
 * @title BSL_DateTimeCheck the test of the year
 * @precon nan
 * @brief
 *    1.Year illegal (<1970). Expected result 1 is obtained.
 *    2.Year legal (1990). Expected result 2 is obtained.
 * @expect
 *    1.Return false
 *    2.Return true
 */
/* BEGIN_CASE */
void SDV_BSL_TIME_DATETIME_CHECK_FUNC_TC001(void)
{
    bool ret;
    BSL_TIME dateTime = {0};

    TestBslSysTimeInit(&dateTime);

    /* 1.Year illegal (<1970) */
    dateTime.year = 1969;
    ret = BSL_DateTimeCheck(&dateTime);
    ASSERT_EQ(ret, false);

    /* 2.Year legal (=1970) */
    dateTime.year = 1970;
    ret = BSL_DateTimeCheck(&dateTime);
    ASSERT_EQ(ret, true);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_TIME_FUNC_DATETIME_CHECK_TC002
 * @title   BSL_DateTimeCheck the test of the month
 * @precon nan
 * @brief
 *    1.Month illegal (== 0 or > 12). Expected result 1 is obtained.
 *    2.Month legal (== 1 or == 12). Expected result 2 is obtained.
 * @expect
 *    1.Return false
 *    2.Return true
 */
/* BEGIN_CASE */
void SDV_BSL_TIME_DATETIME_CHECK_FUNC_TC002(void)
{
    bool ret;
    BSL_TIME dateTime = {0};

    TestBslSysTimeInit(&dateTime);

    /* 1.Month illegal (== 0 or > 12) */
    dateTime.month = 0;
    ret = BSL_DateTimeCheck(&dateTime);
    ASSERT_EQ(ret, false);
    dateTime.month = 13;
    ret = BSL_DateTimeCheck(&dateTime);
    ASSERT_EQ(ret, false);

    /* 2.Month legal (== 1 or == 12) */
    dateTime.month = 1;
    ret = BSL_DateTimeCheck(&dateTime);
    ASSERT_EQ(ret, true);
    dateTime.month = 12;
    ret = BSL_DateTimeCheck(&dateTime);
    ASSERT_EQ(ret, true);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_TIME_FUNC_DATETIME_CHECK_TC003
 * @title   BSL_DateTimeCheck the test of the day
 * @precon
 * @brief
 *    1.Day illegal (== 0). Expected result 1 is obtained.
 *    2.Day legal (== 1). Expected result 2 is obtained.
 *    3.Day illegal (More than 28 days in February). Expected result 3 is obtained.
 *    4.Day legal (February equals 28 days). Expected result 4 is obtained.
 *    5.Day illegal (More than 31 days in January). Expected result 5 is obtained.
 *    6.Day legal (January equals 31 days). Expected result 6 is obtained.
 *    7.Day illegal (More than 30 in April). Expected result 7 is obtained.
 *    8.Day legal (April equals 30 days). Expected result 8 is obtained.
 *    9.Day illegal (Leap year February greater than 29 days). Expected result 9 is obtained.
 *    10.Day legal (Leap year February equals 29 days). Expected result 10 is obtained.
 * @expect
 *    1.Return false
 *    2.Return true
 *    3.Return false
 *    4.Return true
 *    5.Return false
 *    6.Return true
 *    7.Return false
 *    8.Return true
 *    9.Return false
 *    10.Return true
 */
/* BEGIN_CASE */
void SDV_BSL_TIME_DATETIME_CHECK_FUNC_TC003(void)
{
    bool ret;
    BSL_TIME dateTime = {0};

    TestBslSysTimeInit(&dateTime);

    /* 1.Day illegal (== 0) */
    dateTime.day = 0;
    ret = BSL_DateTimeCheck(&dateTime);
    ASSERT_EQ(ret, false);

    /* 2.Day legal (== 1) */
    dateTime.day = 1;
    ret = BSL_DateTimeCheck(&dateTime);
    ASSERT_EQ(ret, true);

    /* 3.Day illegal (More than 28 days in February) */
    dateTime.month = 2;
    dateTime.day = 29;
    ret = BSL_DateTimeCheck(&dateTime);
    ASSERT_EQ(ret, false);

    /* 4.Day legal (February equals 28 days) */
    dateTime.month = 2;
    dateTime.day = 28;
    ret = BSL_DateTimeCheck(&dateTime);
    ASSERT_EQ(ret, true);

    /* 5.Day illegal (More than 31 days in January) */
    dateTime.month = 1;
    dateTime.day = 32;
    ret = BSL_DateTimeCheck(&dateTime);
    ASSERT_EQ(ret, false);

    /* 6.Day legal (January equals 31 days) */
    dateTime.month = 1;
    dateTime.day = 31;
    ret = BSL_DateTimeCheck(&dateTime);
    ASSERT_EQ(ret, true);

    /* 7.Day illegal (More than 30 days in April) */
    dateTime.month = 4;
    dateTime.day = 31;
    ret = BSL_DateTimeCheck(&dateTime);
    ASSERT_EQ(ret, false);

    /* 8.Day legal (April equals 30 days) */
    dateTime.month = 4;
    dateTime.day = 30;
    ret = BSL_DateTimeCheck(&dateTime);
    ASSERT_EQ(ret, true);

    /* 9.Day illegal (Leap year February greater than 29) */
    dateTime.year = 2020;
    dateTime.month = 2;
    dateTime.day = 30;
    ret = BSL_DateTimeCheck(&dateTime);
    ASSERT_EQ(ret, false);

    /* 10.Day legal (Leap year February equals 29) */
    dateTime.year = 2020;
    dateTime.month = 2;
    dateTime.day = 29;
    ret = BSL_DateTimeCheck(&dateTime);
    ASSERT_EQ(ret, true);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_TIME_FUNC_DATETIME_CHECK_TC004
 * @title BSL_DateTimeCheck hour minute second test
 * @precon nan
 * @brief
 *    1. hour is illegal ( > 23). Expected result 1 is obtained.
 *    2. hour is legal ( == 23). Expected result 2 is obtained.
 *    3. minute is illegal ( > 59). Expected result 3 is obtained.
 *    4. minute is legal ( == 59). Expected result 4 is obtained.
 *    5. second is illegal( > 59). Expected result 5 is obtained.
 *    6. second is legal ( == 59). Expected result 6 is obtained.
 *    7. millisecond is illegal ( > 999). Expected result 7 is obtained.
 *    8. millisecond is legal ( == 999). Expected result 8 is obtained.
 *    9. call BSL_DateToStrConvert to convert legal time. Expected result 9 is obtained.
 * @expect
 *    1. Return false
 *    2. Return true
 *    3. Return false
 *    4. Return true
 *    5. Return false
 *    6. Return true
 *    7. Return false
 *    8. Return true
 *    9. Return BSL_SUCCESS
 */
/* BEGIN_CASE */
void SDV_BSL_TIME_DATETIME_CHECK_FUNC_TC004(void)
{
    bool ret;
    BSL_TIME dateTime = {0};

    TestBslSysTimeInit(&dateTime);

    /* 1.hour is illegal ( > 23) */
    dateTime.hour = 24;
    ret = BSL_DateTimeCheck(&dateTime);
    ASSERT_EQ(ret, false);

    /* 2.hour is legal ( == 23) */
    dateTime.hour = 23;
    ret = BSL_DateTimeCheck(&dateTime);
    ASSERT_EQ(ret, true);

    /* 3.minute is illegal ( > 59) */
    dateTime.minute = 60;
    ret = BSL_DateTimeCheck(&dateTime);
    ASSERT_EQ(ret, false);

    /* 4.minute is legal ( == 59) */
    dateTime.minute = 59;
    ret = BSL_DateTimeCheck(&dateTime);
    ASSERT_EQ(ret, true);

    /* 5.second is illegal ( > 59) */
    dateTime.second = 60;
    ret = BSL_DateTimeCheck(&dateTime);
    ASSERT_EQ(ret, false);

    /* 6.second is legal ( == 59) */
    dateTime.second = 59;
    ret = BSL_DateTimeCheck(&dateTime);
    ASSERT_EQ(ret, true);

    /* 7.millisecond is illegal ( > 999) */
    dateTime.millSec = 1000;
    ret = BSL_DateTimeCheck(&dateTime);
    ASSERT_EQ(ret, false);

    /* 8.millisecond is legal ( == 999) */
    dateTime.millSec = 59;
    ret = BSL_DateTimeCheck(&dateTime);
    ASSERT_EQ(ret, true);
    char buf[256] = {0};
    ASSERT_EQ(BSL_DateToStrConvert(&dateTime, buf, 256), BSL_SUCCESS);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_TIME_FUNC_TICK_TC001
 * @title Test of functions related to the number of ticks in the system
 * @precon
 * @brief
 *    1. Call BSL_SAL_Tick to obtain the number of ticks that the system has experienced since startup.
 *       Expected result 1 is obtained.
 *    2. Call BSL_SAL_TicksPerSec to obtain the number of system ticks per second. Expected result 2 is obtained.
 * @expect
 *    1. Succeeded in obtaining the number of ticks that have been experienced since the system is started.
 *    2. Succeeded in obtaining the number of system ticks per second.
 */
/* BEGIN_CASE */
void SDV_BSL_TIME_FUNC_TICK_TC001(void)
{
    long res = BSL_SAL_Tick();
    ASSERT_TRUE(res != 0);
    res = BSL_SAL_TicksPerSec();
    ASSERT_EQ(res, sysconf(_SC_CLK_TCK));
    BSL_SAL_Sleep(1);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_TIME_ADD_TIME_TC001
 * @title   Time comparison function test.
 * @tprecon
 * @brief    1.Adding succeeded.
 *           2.The two dates are consistent.
 *           3.One of them is empty. Adding failed.
 * @texpect  1.Sucessful, return BSL_SUCCESS
 *           2.Sucessful, return BSL_TIME_CMP_EQUAL
 *           3.Fail, return BSL_ERR
 */
/* BEGIN_CASE */
void SDV_BSL_TIME_ADD_TIME_TC001(void)
{
    BSL_TIME dateA = {0};
    BSL_TIME dateB = {0};
    BSL_TIME dateC = {0};

    dateA.year = BSL_TIME_SYSTEM_EPOCH_YEAR;
    dateA.month = 1;
    dateA.day = 1;
    dateA.millSec = 1;

    dateB.year = BSL_TIME_SYSTEM_EPOCH_YEAR;
    dateB.month = 2;
    dateB.day = 1;
    dateB.millSec = 2;

    dateC.year = BSL_TIME_SYSTEM_EPOCH_YEAR;
    dateC.month = 1;
    dateC.day = 1;
    dateC.millSec = 3;

    /* Dates add up */
    ASSERT_TRUE(BSL_DateTimeAddUs(&dateA, &dateC, 0) == BSL_SUCCESS);

    /* 2.Comparison of two dates */
    ASSERT_NE(BSL_SAL_DateTimeCompareByUs(&dateA, &dateB), BSL_TIME_CMP_EQUAL);
    ASSERT_EQ(BSL_SAL_DateTimeCompareByUs(&dateA, &dateC), BSL_TIME_CMP_EQUAL);

    /* Exceptions */
    ASSERT_TRUE(BSL_DateTimeAddUs(&dateA, NULL, 0) == BSL_INTERNAL_EXCEPTION);
EXIT:
    return;
}
/* END_CASE */

static uint64_t TestTimeGetNSec(void)
{
    return 0x1122334455667788;
}

/**
 * @test   SDV_BSL_TIME_GET_NSEC_FUNC_TC001
 * @title  Test of BSL_SAL_TIME_GetNSec.
 * @precon nan
 */
/* BEGIN_CASE */
void SDV_BSL_TIME_GET_NSEC_FUNC_TC001(void)
{
#ifdef HITLS_BSL_SAL_LINUX
    ASSERT_TRUE(BSL_SAL_TIME_GetNSec() > 0);
#else
    ASSERT_EQ(BSL_SAL_TIME_GetNSec(), 0);
#endif

    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_TIME_GET_TIME_IN_NS, TestTimeGetNSec), BSL_SUCCESS);
    ASSERT_EQ(BSL_SAL_TIME_GetNSec(), TestTimeGetNSec());
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_TIME_GET_TIME_IN_NS, NULL), BSL_SUCCESS);
EXIT:
    return;
}
/* END_CASE */
