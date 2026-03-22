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
#include <stdint.h>

#include "bsl_err.h"
#include "crypt_eal_init.h"
#include "crypt_eal_rand.h"
#include "crypt_errno.h"


static void DrbgPrintHex(const char *label, const uint8_t *data, uint32_t len)
{
    uint32_t i;

    printf("%s: ", label);
    for (i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main(void)
{
    uint8_t random1[32] = {0};
    uint8_t random2[32] = {0};
    int32_t ret;

    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Init failed: 0x%x\n", ret);
        return -1;
    }

    ret = CRYPT_EAL_RandbytesEx(NULL, random1, sizeof(random1));
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_RandbytesEx failed: 0x%x\n", ret);
        goto cleanup;
    }

    /* Force a reseed so the demo shows both initial output and explicit state refresh. */
    ret = CRYPT_EAL_RandSeedEx(NULL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_RandSeedEx failed: 0x%x\n", ret);
        goto cleanup;
    }

    ret = CRYPT_EAL_RandbytesEx(NULL, random2, sizeof(random2));
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_RandbytesEx after reseed failed: 0x%x\n", ret);
        goto cleanup;
    }

    /* Print both samples so developers can see the reseed changed the stream. */
    DrbgPrintHex("Random bytes", random1, sizeof(random1));
    DrbgPrintHex("Random bytes after reseed", random2, sizeof(random2));
    ret = 0;

cleanup:
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return ret;
}
