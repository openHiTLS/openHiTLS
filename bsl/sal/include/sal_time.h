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

#ifndef SAL_TIME_H
#define SAL_TIME_H

#include "hitls_build.h"
#ifdef HITLS_BSL_SAL_TIME

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "bsl_sal.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BSL_TIME_YEAR_START 1900U
#define BSL_TIME_SYSTEM_EPOCH_YEAR 1970U
#define BSL_TIME_DAY_PER_NONLEAP_YEAR 365U

#define BSL_TIME_BIG_MONTH_DAY 31U
#define BSL_TIME_SMALL_MONTH_DAY 30U
#define BSL_TIME_LEAP_FEBRUARY_DAY 29U
#define BSL_TIME_NOLEAP_FEBRUARY_DAY 28U

#define BSL_MONTH_JAN 1U     /* January */
#define BSL_MONTH_FEB 2U     /* February */
#define BSL_MONTH_MAR 3U     /* March */
#define BSL_MONTH_APR 4U     /* April */
#define BSL_MONTH_MAY 5U     /* May */
#define BSL_MONTH_JUN 6U     /* June */
#define BSL_MONTH_JUL 7U     /* July */
#define BSL_MONTH_AUG 8U     /* August */
#define BSL_MONTH_SEM 9U     /* September */
#define BSL_MONTH_OCT 10U    /* October */
#define BSL_MONTH_NOV 11U    /* November */
#define BSL_MONTH_DEC 12U    /* December */

#define BSL_TIME_TICKS_PER_SECOND_DEFAULT 100U
#define BSL_SECOND_TRANSFER_RATIO         1000U        /* conversion ratio of microseconds -> milliseconds -> seconds */

#define BSL_UTCTIME_MAX 2005949145599L /* UTC time corresponding to December 31, 65535 23:59:59 */

#define BSL_TIME_SECS_PER_DAY 86400L /* seconds per day */

bool BSL_IsLeapYear(uint32_t year);

/**
 * @brief Add the time.
 * @param date [IN]
 * @param us [IN]
 * @return BSL_SUCCESS is successfully executed.
 * For other failures, see BSL_SAL_DateToUtcTimeConvert and BSL_SAL_UtcTimeToDateConvert.
 */
int32_t BSL_DateTimeAddUs(BSL_TIME *dateR, const BSL_TIME *dateA, uint32_t us);

/**
 * @brief Add day and second to the given time
 * @param dateR [OUT] Destination time
 * @param dateA [IN]  Base time to start from.
 * @param offDay [IN] Number of days to add (can be negative).
 * @param offsetSecond [IN] Number of seconds to add (can be negative).
 * @return BSL_SUCCESS is successfully executed.
 * BSL_SUCCESS on success, otherwise BSL_INTERNAL_EXCEPTION.
 */
int32_t BSL_DateTimeAddDaySecond(BSL_TIME *dateR, const BSL_TIME *dateA, int32_t offsetDay, int64_t offsetSecond);

/**
 * @brief Check whether the time format is correct.
 * @param dateTime [IN] Time to be checked
 * @return true  The time format is correct.
 *         false incorrect
 */
bool BSL_DateTimeCheck(const BSL_TIME *dateTime);

void BSL_SysTimeFuncUnReg(void);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_BSL_SAL_TIME */

#endif // SAL_TIME_H
