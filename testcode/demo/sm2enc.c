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
#include "crypt_eal_pkey.h" // Header file of the interfaces for asymmetric encryption and decryption.
#include "bsl_sal.h"
#include "bsl_err.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_init.h"
#include "crypt_types.h"

void *StdMalloc(uint32_t len) {
    return malloc((uint32_t)len);
}
void PrintLastError(void) {
    const char *file = NULL;
    uint32_t line = 0;
    BSL_ERR_GetLastErrorFileLine(&file, &line);
    printf("failed at file %s at line %d\n", file, line);
}

int main(void) {
    int32_t ret;
    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
    if (pkey == NULL) {
        PrintLastError();
        goto EXIT;
    }

    // Generate a key pair.
    ret = CRYPT_EAL_PkeyGen(pkey);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_PkeyGen: error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    // Data to be encrypted.
    char *data = "test enc data";
    uint32_t dataLen = 12;
    uint8_t ecrypt[125] = {0};
    uint32_t ecryptLen = 125;
    uint8_t dcrypt[125] = {0};
    uint32_t dcryptLen = 125;
    // Encrypt data.
    ret = CRYPT_EAL_PkeyEncrypt(pkey, (const uint8_t *)data, dataLen, ecrypt, &ecryptLen);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_PkeyEncrypt: error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    // Decrypt data.
    ret = CRYPT_EAL_PkeyDecrypt(pkey, ecrypt, ecryptLen, dcrypt, &dcryptLen);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_PkeyDecrypt: error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    if (memcmp(dcrypt, data, dataLen) == 0) {
        printf("encrypt and decrypt success\n");
    } else {
        ret = -1;
    }
EXIT:
    // Release the context memory.
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_RandDeinit();
    BSL_ERR_DeInit();
    return ret;
}