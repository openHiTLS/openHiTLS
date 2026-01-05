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

#ifndef TEST_H
#define TEST_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/wait.h>
#include <time.h>

#include "helper.h"
#include "crypto_test_util.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TEST_RESULT_SUCCEED 0
#define TEST_RESULT_FAILED 1
#define TEST_RESULT_SKIPPED 2

typedef struct {
    int result;
    char test[512];
    char filename[256];
} TestInfo;

#define TRUE_OR_EXIT(TEST)                  \
    do {                                    \
        if (!(TEST)) {                      \
            goto EXIT;                      \
        }                                   \
    } while (0)

#define TRUE_OR_ABRT(TEST)                  \
    do {                                    \
        if (!(TEST)) {                      \
            raise(SIGABRT);                 \
        }                                   \
    } while (0)

#define PRINT_ABRT(TEST)                    \
    do {                                    \
        if (!(TEST)) {                      \
            goto ABORT;                      \
        }                                   \
    } while (0)

#define ASSERT_TRUE(TEST)                   \
    do {                                    \
        if (!(TEST)) {                      \
            RecordFailure(#TEST, __FILE__); \
            goto EXIT;                      \
        }                                   \
    } while (0)

#define ASSERT_EQ(VALUE1, VALUE2)                       \
    do {                                                \
        int64_t value1__ = (int64_t)(VALUE1);           \
        int64_t value2__ = (int64_t)(VALUE2);           \
        if (value1__ != value2__) {                     \
            RecordFailure(#VALUE1 #VALUE2, __FILE__);   \
            Print("\nvalue is %d (0x%x).\nexpect %d (0x%x).\n", value1__, value1__, value2__, value2__); \
            goto EXIT;                                  \
        }                                               \
    } while (0)


#define ASSERT_EQ_LOG(LOG, VALUE1, VALUE2)              \
    do {                                                \
        int64_t value1__ = (int64_t)(VALUE1);           \
        int64_t value2__ = (int64_t)(VALUE2);           \
        if (value1__ != value2__) {                     \
            RecordFailure(LOG, __FILE__);   \
            Print("\nvalue is %d (0x%x).\nexpect %d (0x%x).\n", value1__, value1__, value2__, value2__); \
            goto EXIT;                                  \
        }                                               \
    } while (0)

#define ASSERT_NE(VALUE1, VALUE2)                       \
    do {                                                \
        int64_t value1__ = (int64_t)(VALUE1);           \
        int64_t value2__ = (int64_t)(VALUE2);           \
        if (value1__ == value2__) {                     \
            RecordFailure(#VALUE1#VALUE2, __FILE__);    \
            Print("\nvalue is the same: %d (0x%x).\n", value1__, value2__); \
            goto EXIT;                                  \
        }                                               \
    } while (0)

#define ASSERT_TRUE_AND_LOG(LOG, TEST)    \
    do {                                  \
        if (!(TEST)) {                    \
            RecordFailure(LOG, __FILE__); \
            goto EXIT;                    \
        }                                 \
    } while (0)

#define ASSERT_COMPARE(LOG, STR1, SIZE1, STR2, SIZE2)                                              \
    do {                                                                                           \
        ASSERT_TRUE_AND_LOG(LOG, (SIZE1) == (SIZE2));                                              \
        if (memcmp((STR1), (STR2), (SIZE1)) != 0) {                                                \
            RecordFailure((LOG), __FILE__);                                                        \
            PrintDiff((uint8_t *)(STR1), (uint32_t)(SIZE1), (uint8_t *)(STR2), (uint32_t)(SIZE2)); \
            goto EXIT;                                                                             \
        }                                                                                          \
    } while (0)

#define SKIP_TEST()         \
    do {\
        SkipTest(__FILE__); \
        return;             \
    } while (0)

extern int *GetJmpAddress(void);
#ifndef TEST_NO_SUBPROC
#define SUB_PROC 1
#define SUB_PROC_BEGIN(parentAction)   if (fork() > 0) parentAction
#define SUB_PROC_END() *GetJmpAddress() = SUB_PROC; return
#define SUB_PROC_WAIT(times) for (uint16_t i = 0; i < times; i++) wait(NULL)
#else
#define SUB_PROC 0
#define SUB_PROC_BEGIN(parentAction)
#define SUB_PROC_END()
#define SUB_PROC_WAIT(times)
#endif

extern TestInfo g_testResult;

int ConvertInt(const char *intStr, int *outNum);

int ConvertString(char **str);

int ConvertHex(const char *str, Hex *output);

void RecordFailure(const char *test, const char *filename);

void SkipTest(const char *filename);

void PrintResult(bool showDetail, char *vectorName, uint64_t useTime);

void PrintLog(FILE *logFile);

void PrintDiff(const uint8_t *str1, uint32_t size1, const uint8_t *str2, uint32_t size2);

/**
 * @brief Stub function for BSL_SAL_Malloc to simulate malloc failures
 *
 * This function is used in memory leak tests to trigger malloc failures at specific points.
 * It tracks the number of malloc calls and returns NULL when the call count matches
 * the configured failure index.
 *
 * @param size Size to allocate
 * @return Allocated memory pointer, or NULL if simulating a failure
 */
void *STUB_BSL_SAL_Malloc(uint32_t size);

/**
 * @brief Reset malloc stub counters
 *
 * Resets the internal counters used by STUB_BSL_SAL_Malloc. Should be called
 * before each test case to ensure clean state.
 */
void STUB_ResetMallocCount(void);

/**
 * @brief Set which malloc call should fail
 *
 * Configures STUB_BSL_SAL_Malloc to fail on a specific call number.
 * For example, SetMallocFailIndex(3) will cause the 3rd malloc call to return NULL.
 *
 * @param failIdx The index (0-based) of the malloc call that should fail
 */
void STUB_SetMallocFailIndex(uint32_t failIdx);

/**
 * @brief Get current malloc call count
 *
 * Returns the number of malloc calls made since the last reset.
 *
 * @return Current call count
 */
uint32_t STUB_GetMallocCallCount(void);

/**
 * @brief Enable or disable malloc failure injection
 *
 * When disabled, STUB_BSL_SAL_Malloc will never return NULL (acts like normal malloc).
 * This is useful for the "probe" phase to count total malloc calls.
 *
 * @param enable true to enable failure injection, false to disable
 */
void STUB_EnableMallocFail(bool enable);

#ifdef __cplusplus
}
#endif

#endif // TEST_H