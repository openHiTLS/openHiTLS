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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypt_errno.h"
#include "bsl_sal.h"
#include "bsl_err.h"
#include "crypt_algid.h"
#include "crypt_eal_md.h"

#define PBKDF2_PARAM_LEN (4)

void *StdMalloc(uint32_t len) {
    return malloc((size_t)len);
}

void PrintLastError(void) {
    const char *file = NULL;
    uint32_t line = 0;
    BSL_ERR_GetErrorFileLine(&file, &line);
    printf("failed at file %s at line %d\n", file, line);
}

int main(void)
{
    int ret = 0;
    CRYPT_EAL_MdCTX *ctx = NULL;
    uint8_t digest[32] = {0};
    unsigned int digestLen = 32;
    uint8_t data[] = {0x1b, 0x50, 0x3f, 0xb9, 0xa7, 0x3b, 0x16, 0xad, 0xa3,
        0xfc, 0xf1, 0x04, 0x26, 0x23, 0xae, 0x76, 0x10};
    uint8_t expResult[] = {0xd5, 0xc3, 0x03, 0x15, 0xf7, 0x2e, 0xd0, 0x5f, 0xe5, 0x19, 0xa1, 0xbf, 0x75,
        0xab, 0x5f, 0xd0, 0xff, 0xec, 0x5a, 0xc1, 0xac, 0xb0, 0xda, 0xf6, 0x6b, 0x6b, 0x76, 0x95, 0x98,
        0x59, 0x45, 0x09};

    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, StdMalloc);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE, free);

    // Initialize the error code module.
    BSL_ERR_Init();

    /**
     * Before calling the algorithm APIs,
     * call the BSL_SAL_CallBack_Ctrl function to register the malloc and free functions.
     * Execute this step only once. If the memory allocation ability of Linux is available,
     * the two functions can be registered using Linux by default.
    */
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, StdMalloc);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE, free);

    ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA256);
    if (ctx == NULL) {
        PrintLastError();
        goto EXIT;
    }

    ret = CRYPT_EAL_MdInit(ctx);
    if (ret != 0) {
        PrintLastError();
        goto EXIT;
    }

    ret = CRYPT_EAL_MdUpdate(ctx, data, sizeof(data));
    if (ret != 0) {
        PrintLastError();
        goto EXIT;
    }

    ret = CRYPT_EAL_MdFinal(ctx, digest, &digestLen);
    if (ret != 0) {
        PrintLastError();
        goto EXIT;
    }
    printf("hash result: ");
    for (uint32_t i = 0; i < digestLen; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
    // result compare
    if (digestLen != sizeof(expResult) || memcmp(expResult, digest, digestLen) != 0) {
        printf("hash result comparison failed\n");
        goto EXIT;
    }
    printf("pass \n");

EXIT:
    BSL_ERR_DeInit();
    CRYPT_EAL_MdFreeCtx(ctx);
    return ret;
}