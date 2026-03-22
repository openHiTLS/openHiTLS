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


int main(void)
{
    static const char data[] = "test enc data";
    int32_t ret = -1;
    CRYPT_EAL_PkeyCtx *pkey = NULL;

    printf("=== SM2 Encryption Demo ===\n\n");

    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Init failed: 0x%x\n", ret);
        goto EXIT;
    }
    pkey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_SM2, CRYPT_EAL_PKEY_CIPHER_OPERATE, NULL);
    if (pkey == NULL) {
        printf("CRYPT_EAL_ProviderPkeyNewCtx failed.\n");
        goto EXIT;
    }

    /* Generate one SM2 key pair and use it for the encrypt/decrypt round-trip. */
    ret = CRYPT_EAL_PkeyGen(pkey);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_PkeyGen: error code is %x\n", ret);
        goto EXIT;
    }

    /* Keep the sample payload short so the focus stays on the API sequence. */
    uint32_t dataLen = (uint32_t)(sizeof(data) - 1);
    uint8_t ecrypt[125] = {0};
    uint32_t ecryptLen = 125;
    uint8_t dcrypt[125] = {0};
    uint32_t dcryptLen = 125;

    ret = CRYPT_EAL_PkeyEncrypt(pkey, (const uint8_t *)data, dataLen, ecrypt, &ecryptLen);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_PkeyEncrypt: error code is %x\n", ret);
        goto EXIT;
    }

    /* Decrypt with the same private key to verify the generated key pair is usable. */
    ret = CRYPT_EAL_PkeyDecrypt(pkey, ecrypt, ecryptLen, dcrypt, &dcryptLen);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_PkeyDecrypt: error code is %x\n", ret);
        goto EXIT;
    }

    if (memcmp(dcrypt, data, dataLen) == 0) {
        printf("encrypt and decrypt success\n");
        ret = 0;
    } else {
        ret = -1;
    }
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return ret;
}
