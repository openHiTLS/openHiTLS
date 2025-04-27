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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "crypt_errno.h"
#include "bsl_sal.h"
#include "bsl_err.h"
#include "crypt_algid.h"
#include "crypt_eal_kdf.h"
#include "bsl_params.h"
#include "crypt_params_key.h"

#define PBKDF2_PARAM_LEN (4)

void *StdMalloc(uint32_t len) {
    return malloc((size_t)len);
}

void PrintLastError(void) {
    const char *file = NULL;
    uint32_t line = 0;
    BSL_ERR_GetLastErrorFileLine(&file, &line);
    printf("failed at file %s at line %d\n", file, line);
}

int main(void)
{
    int32_t ret;
    uint8_t key[] = {0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64};
    uint8_t salt[] = {0x4e, 0x61, 0x43, 0x6c};
    uint32_t iterations = 80000;
    uint8_t result[] = {
        0x4d, 0xdc, 0xd8, 0xf6, 0x0b, 0x98, 0xbe, 0x21,
        0x83, 0x0c, 0xee, 0x5e, 0xf2, 0x27, 0x01, 0xf9,
        0x64, 0x1a, 0x44, 0x18, 0xd0, 0x4c, 0x04, 0x14,
        0xae, 0xff, 0x08, 0x87, 0x6b, 0x34, 0xab, 0x56,
        0xa1, 0xd4, 0x25, 0xa1, 0x22, 0x58, 0x33, 0x54,
        0x9a, 0xdb, 0x84, 0x1b, 0x51, 0xc9, 0xb3, 0x17,
        0x6a, 0x27, 0x2b, 0xde, 0xbb, 0xa1, 0xd0, 0x78,
        0x47, 0x8f, 0x62, 0xb3, 0x97, 0xf3, 0x3c, 0x8d};

    uint8_t out[sizeof(result)] = {0};
    uint32_t outLen = sizeof(result);

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

    CRYPT_EAL_KdfCTX *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_PBKDF2);
    if (ctx == NULL) {
        PrintLastError();
        goto EXIT;
    }
    CRYPT_MAC_AlgId id = CRYPT_MAC_HMAC_SHA256;
    BSL_Param params[5] = {{0}, {0}, {0}, {0}, BSL_PARAM_END};
    (void)BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, &id, sizeof(id));
    (void)BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_PASSWORD, BSL_PARAM_TYPE_OCTETS, key, sizeof(key));
    (void)BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS, salt, sizeof(salt));
    (void)BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_ITER, BSL_PARAM_TYPE_UINT32, &iterations, sizeof(iterations));
    ret = CRYPT_EAL_KdfSetParam(ctx, params);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    ret = CRYPT_EAL_KdfDerive(ctx, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    if (memcmp(out, result, sizeof(result)) != 0) {
        printf("failed to compare test results\n");
        ret = -1;
        goto EXIT;
    }
    printf("pass \n");

EXIT:
    BSL_ERR_DeInit();
    CRYPT_EAL_KdfFreeCtx(ctx);
    return ret;
}