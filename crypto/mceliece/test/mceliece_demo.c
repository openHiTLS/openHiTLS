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
#include <time.h>
#include <linux/limits.h>
#include <unistd.h>
#include <libgen.h>
#include "pqcp_types.h"
#include "pqcp_provider.h"
#include "crypt_eal_provider.h"
#include "crypt_eal_implprovider.h"
#include "crypt_eal_pkey.h"
#include "crypt_errno.h"
#include "crypt_eal_rand.h"

#include "pqcp_test.h"
#include "internal/mceliece_params.h"
#include "mceliece_types.h"

static void PrintHex(const char *label, const unsigned char *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0 && i < len - 1) {
            printf("\n");
        }
    }
    printf("\n");
}

static int32_t McelieceDemo(void)
{
    int32_t val = PQC_ALG_ID_MCELIECE_6688128_F;
    int32_t ret = -1;
    CRYPT_EAL_PkeyCtx *deCtx = NULL;
    int32_t cipherLen = 208;
    uint8_t cipher[208] = {0};
    int32_t sharekeyLen = 32;
    uint8_t sharekey[32] = {0};
    int32_t sharekey2Len = 32;
    uint8_t sharekey2[32] = {0};
    uint8_t pubdata[1044992];
    uint8_t prvdata[13932];

    BSL_Param pub[2] = {
        {CRYPT_PARAM_MCELIECE_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubdata, sizeof(pubdata), 0},
        BSL_PARAM_END
    };

    BSL_Param prv[2] = {
        {CRYPT_PARAM_MCELIECE_PRVKEY, BSL_PARAM_TYPE_OCTETS, prvdata, sizeof(prvdata), 0},
        BSL_PARAM_END
    };

    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_MCELIECE, CRYPT_EAL_PKEY_KEM_OPERATE,
        "provider=pqcp");
    if (ctx == NULL) {
        printf("create ctx failed.\n");
        goto EXIT;
    }
    deCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_MCELIECE, CRYPT_EAL_PKEY_KEM_OPERATE,
        "provider=pqcp");
    if (deCtx == NULL) {
        printf("create ctx failed.\n");
        goto EXIT;
    }

    ret = CRYPT_EAL_PkeyCtrl(ctx, PQCP_MCELIECE_ALG_PARAMS, &val, sizeof(val));
    if (ret != CRYPT_SUCCESS) {
        printf("ctrl param failed.\n");
        goto EXIT;
    }

    ret = CRYPT_EAL_PkeyCtrl(deCtx, PQCP_MCELIECE_ALG_PARAMS, &val, sizeof(val));
    if (ret != CRYPT_SUCCESS) {
        printf("ctrl param failed.\n");
        goto EXIT;
    }

    ret = CRYPT_EAL_PkeyGen(ctx);
    if (ret != CRYPT_SUCCESS) {
        printf("gen key failed.\n");
        goto EXIT;
    }

    ret = CRYPT_EAL_PkeyGen(deCtx);
    if (ret != CRYPT_SUCCESS) {
        printf("gen key failed.\n");
        goto EXIT;
    }

    ret = CRYPT_EAL_PkeyGetPubEx(ctx, &pub);
    if (ret != CRYPT_SUCCESS) {
        printf("get public key failed.\n");
        goto EXIT;
    }

    ret = CRYPT_EAL_PkeySetPubEx(deCtx, &pub);
    if (ret != CRYPT_SUCCESS) {
        printf("set public key failed: %d.\n", ret);
        goto EXIT;
    }

    ret = CRYPT_EAL_PkeyGetPrvEx(ctx, &prv);
    if (ret != CRYPT_SUCCESS) {
        printf("get private key failed.\n");
        goto EXIT;
    }

    ret = CRYPT_EAL_PkeySetPrvEx(deCtx, &prv);
    if (ret != CRYPT_SUCCESS) {
        printf("set private key failed: %d.\n", ret);
        goto EXIT;
    }

    ret = CRYPT_EAL_PkeyCmp(ctx, deCtx);
    if (ret != CRYPT_SUCCESS) {
        printf("ctx comparison failed: %d.\n", ret);
        goto EXIT;
    }

    ret = CRYPT_EAL_PkeyEncapsInit(ctx, NULL);
    if (ret != CRYPT_SUCCESS) {
        printf("encaps init failed.\n");
        goto EXIT;
    }

    ret = CRYPT_EAL_PkeyEncaps(ctx, cipher, &cipherLen, sharekey, &sharekeyLen);
    if (ret != CRYPT_SUCCESS) {
        printf("encaps failed.\n");
        goto EXIT;
    }

    ret = CRYPT_EAL_PkeyDecapsInit(ctx, NULL);
    if (ret != CRYPT_SUCCESS) {
        printf("decaps init failed.\n");
        goto EXIT;
    }

    ret = CRYPT_EAL_PkeyDecaps(ctx, cipher, cipherLen, sharekey2, &sharekeyLen);
    if (ret != CRYPT_SUCCESS) {
        printf("decaps failed.\n");
        goto EXIT;
    }

    if (sharekeyLen == sharekey2Len && memcmp(sharekey, sharekey2, sharekeyLen) == 0) {
        printf("\nClassic McEliece encaps and decaps finished; sharedkey matching succeeded.\n");
    } else {
        printf("\nError: encaps or decaps failed; sharekey mismatch.\n");
        ret = -1;
    }

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(deCtx);
    return ret;
}

static int32_t PQCP_TestLoadProvider(void)
{
    char basePath[PATH_MAX] = {0};
    char fullPath[PATH_MAX] = {0};

    if (readlink("/proc/self/exe", basePath, sizeof(basePath)-1) == -1) {
        perror("get realpath failed.\n");
        return PQCP_TEST_FAILURE;
    }
    printf("basePath: %s\n", basePath);

    dirname(basePath);
    snprintf(fullPath, sizeof(fullPath), "%s/../../../build", basePath);
    printf("fullPath: %s\n", fullPath);

    int32_t ret = CRYPT_EAL_ProviderSetLoadPath(NULL, fullPath);
    if (ret != 0) {
        printf("set provider path failed.\n");
        return PQCP_TEST_FAILURE;
    }

    ret = CRYPT_EAL_ProviderLoad(NULL, BSL_SAL_LIB_FMT_LIBSO, "pqcp_provider", NULL, NULL);
    if (ret != 0) {
        printf("load provider failed: 0x%x.\n", ret);
        return PQCP_TEST_FAILURE;
    }

    return PQCP_TEST_SUCCESS;
}

int32_t main(void)
{
    printf("PQCP_Classic_McEliece\n");
    printf("====================================\n");

    int32_t result = 0;
    if (PQCP_TestLoadProvider() != CRYPT_SUCCESS) {
        printf("\nLoad provider failed!\n");
    } else {
        printf("\nLoad provider successfully.\n");
    }

    if (McelieceDemo() != 0) {
        result = -1;
    }

    if (result == 0) {
        printf("\nClassic McEliece success\n");
    } else {
        printf("\nClassic McEliece error\n");
    }

    (void)CRYPT_EAL_ProviderUnload(NULL, BSL_SAL_LIB_FMT_LIBSO, "pqcp_provider");
    return result;
}