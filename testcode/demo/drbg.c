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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "crypt_types.h"
#include "bsl_sal.h"
#include "bsl_err.h"
#include "crypt_algid.h"
#include "crypt_eal_init.h"
#include "crypt_errno.h"
#include "crypt_eal_rand.h"

void PrintLastError(void) {
    const char *file = NULL;
    uint32_t line = 0;
    BSL_ERR_GetLastErrorFileLine(&file, &line);
    printf("failed at file %s at line %d\n", file, line);
}

int main(void)
{
    int ret;
    uint8_t output[100] = {0};
    uint32_t len = 100;
    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Init: error code is %x\n", ret);
        return ret;
    }

    // Obtain the random number sequence of the **len** value.
    ret = CRYPT_EAL_RandbytesEx(NULL, output, len);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Randbytes: error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    printf("random value is: ");  // Output the random number.
    for (uint32_t i = 0; i < len; i++) {
        printf("%02x", output[i]);
    }
    printf("\n");

    // Reseeding
    ret = CRYPT_EAL_RandSeedEx(NULL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_RandSeed: error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    // Obtain the random number sequence of the **len** value.
    ret = CRYPT_EAL_RandbytesEx(NULL, output, len);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Randbytes: error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    printf("random value is: "); // Output the random number.
    for (uint32_t i = 0; i < len; i++) {
        printf("%02x", output[i]);
    }
    printf("\n");

EXIT:
    // Release the context memory.
    CRYPT_EAL_RandDeinit();
    BSL_ERR_DeInit();
    return ret;
}