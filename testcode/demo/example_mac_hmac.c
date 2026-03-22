/*
 * HMAC-SHA256 example.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "crypt_algid.h"
#include "crypt_eal_init.h"
#include "crypt_eal_mac.h"
#include "crypt_errno.h"

static void PrintHex(const char *label, const uint8_t *data, uint32_t len)
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
    static const uint8_t key[] = "openHiTLS-mac-key";
    static const uint8_t msg[] = "message for HMAC-SHA256";
    CRYPT_EAL_MacCtx *ctx = NULL;
    uint8_t mac[32];
    uint32_t macLen = sizeof(mac);
    int32_t ret;

    printf("=== HMAC-SHA256 Example ===\n\n");

    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Init failed: 0x%x\n", ret);
        return -1;
    }

    ctx = CRYPT_EAL_ProviderMacNewCtx(NULL, CRYPT_MAC_HMAC_SHA256, NULL);
    if (ctx == NULL) {
        printf("CRYPT_EAL_MacNewCtx failed\n");
        CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
        return -1;
    }
    ret = CRYPT_EAL_MacInit(ctx, key, sizeof(key) - 1);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_MacInit failed: 0x%x\n", ret);
        goto cleanup;
    }
    ret = CRYPT_EAL_MacUpdate(ctx, msg, sizeof(msg) - 1);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_MacUpdate failed: 0x%x\n", ret);
        goto cleanup;
    }
    ret = CRYPT_EAL_MacFinal(ctx, mac, &macLen);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_MacFinal failed: 0x%x\n", ret);
        goto cleanup;
    }

    PrintHex("HMAC-SHA256", mac, macLen);
    ret = 0;

cleanup:
    CRYPT_EAL_MacFreeCtx(ctx);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return ret;
}
