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
#include "crypt_eal_pkey.h" // Header file for key exchange.
#include "bsl_sal.h"
#include "bsl_err.h"
#include "crypt_eal_init.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_eal_rand.h"

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
    int ret;

    uint8_t prikey[] =
        {0x7d, 0x7d, 0xc5, 0xf7, 0x1e, 0xb2, 0x9d, 0xda, 0xf8, 0x0d, 0x62, 0x14, 0x63, 0x2e, 0xea, 0xe0,
         0x3d, 0x90, 0x58, 0xaf, 0x1f, 0xb6, 0xd2, 0x2e, 0xd8, 0x0b, 0xad, 0xb6, 0x2b, 0xc1, 0xa5, 0x34};
    uint8_t pubkey[] =
        {0x04, 0x70, 0x0c, 0x48, 0xf7, 0x7f, 0x56, 0x58, 0x4c, 0x5c, 0xc6, 0x32, 0xca, 0x65, 0x64, 0x0d, 0xb9,
         0x1b, 0x6b, 0xac, 0xce, 0x3a, 0x4d, 0xf6, 0xb4, 0x2c, 0xe7, 0xcc, 0x83, 0x88, 0x33, 0xd2, 0x87,
         0xdb, 0x71, 0xe5, 0x09, 0xe3, 0xfd, 0x9b, 0x06, 0x0d, 0xdb, 0x20, 0xba, 0x5c, 0x51, 0xdc, 0xc5,
         0x94, 0x8d, 0x46, 0xfb, 0xf6, 0x40, 0xdf, 0xe0, 0x44, 0x17, 0x82, 0xca, 0xb8, 0x5f, 0xa4, 0xac};
    uint8_t resSharekey[] =
        {0x46, 0xfc, 0x62, 0x10, 0x64, 0x20, 0xff, 0x01, 0x2e, 0x54, 0xa4, 0x34, 0xfb, 0xdd, 0x2d, 0x25,
         0xcc, 0xc5, 0x85, 0x20, 0x60, 0x56, 0x1e, 0x68, 0x04, 0x0d, 0xd7, 0x77, 0x89, 0x97, 0xbd, 0x7b};

    CRYPT_EAL_PkeyPrv prvKey = {0};
    CRYPT_EAL_PkeyPub pubKey = {0};
    uint32_t shareLen;
    uint8_t *shareKey;
    CRYPT_EAL_PkeyCtx *prvCtx = NULL;
    CRYPT_EAL_PkeyCtx *pubCtx = NULL;
    CRYPT_PKEY_ParaId id = CRYPT_ECC_NISTP256;

    BSL_ERR_Init(); // Initialize the error code module.
    /**
     * Before calling the algorithm APIs,
     * call the BSL_SAL_CallBack_Ctrl function to register the malloc and free functions.
     * Execute this step only once. If the memory allocation ability of Linux is available,
     * the two functions can be registered using Linux by default.
    */
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, StdMalloc);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE, free);
    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_PROVIDER);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Init: error code is %x\n", ret);
        goto EXIT;
    }

    prvCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDH);
    pubCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDH);
    if (prvCtx == NULL || pubCtx == NULL) {
        goto EXIT;
    }

    // Set the curve parameters.
    ret = CRYPT_EAL_PkeySetParaById(prvCtx, id);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    // Set the private key of one end.
    prvKey.id = CRYPT_PKEY_ECDH;
    prvKey.key.eccPrv.len = sizeof(prikey);
    prvKey.key.eccPrv.data = prikey;
    ret = CRYPT_EAL_PkeySetPrv(prvCtx, &prvKey);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    // Set the curve parameters.
    ret = CRYPT_EAL_PkeySetParaById(pubCtx, id);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    // Set the public key of the other end.
    pubKey.id = CRYPT_PKEY_ECDH;
    pubKey.key.eccPub.len = sizeof(pubkey);
    pubKey.key.eccPub.data = pubkey;
    ret = CRYPT_EAL_PkeySetPub(pubCtx, &pubKey);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    // The shared key involves only the X axis. The length of the public key is not compressed in the returned results.
    shareLen = CRYPT_EAL_PkeyGetKeyLen(prvCtx) / 2;
    shareKey = (uint8_t *)BSL_SAL_Malloc(shareLen);
    if (shareKey == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        PrintLastError();
        goto EXIT;
    }
    // Initialize the random number.
    ret = CRYPT_EAL_ProviderRandInitCtx(NULL, CRYPT_RAND_SHA256, "provider=default", NULL, 0, NULL);
    if (ret != CRYPT_SUCCESS) {
        printf("RandInit: error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }   

    // Calculate the shared key.
    ret = CRYPT_EAL_PkeyComputeShareKey(prvCtx, pubCtx, shareKey, &shareLen);
    if (ret != CRYPT_SUCCESS) {
        printf("error code is %x\n", ret);
        PrintLastError();
        goto EXIT;
    }

    // Compare the calculation result with the expected one.
    if (shareLen != sizeof(resSharekey) || memcmp(shareKey, resSharekey, shareLen) != 0) {
        printf("failed to compare test results\n");
        ret = -1;
        goto EXIT;
    }

    printf("pass \n");

EXIT:
    // Release the context memory.
    CRYPT_EAL_RandDeinit();
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
    CRYPT_EAL_PkeyFreeCtx(pubCtx);
    BSL_SAL_Free(shareKey);
    BSL_ERR_DeInit();
    return 0;
}