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

#include "bsl_sal.h"
#include "crypt_types.h"
#include "crypt_errno.h"
#include "securec.h"
#include "crypt_sm9.h"
#include "crypt_util_rand.h"

#define RAND_BUF_LEN 2048
#define UINT8_MAX_NUM 255

uint8_t g_RandOutput[RAND_BUF_LEN];
uint32_t g_RandBufLen = 0;

int32_t RandFunc(uint8_t *randNum, uint32_t randLen)
{
    for (uint32_t i = 0; i < randLen; i++) {
        randNum[i] = (uint8_t)(rand() % UINT8_MAX_NUM);
    }
    return 0;
}

int32_t SetFakeRandOutput(uint8_t *in, uint32_t inLen)
{
    g_RandBufLen = inLen;
    return memcpy_s(g_RandOutput, sizeof(g_RandOutput), in, inLen);
}

int32_t FakeRandFunc(uint8_t *randNum, uint32_t randLen)
{
    if (randLen > RAND_BUF_LEN) {
        return -1;
    }
    return memcpy_s(randNum, randLen, g_RandOutput, randLen);
}

void PrintHex(const char *name, const uint8_t *data, uint32_t len)
{
    printf("%s (%u bytes): ", name, len);
    for (uint32_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

// Initialize random number generator for SM9 tests
__attribute__((constructor))
static void InitSM9Tests(void)
{
    // Register random number generator for SM9
    CRYPT_RandRegist(RandFunc);
}
