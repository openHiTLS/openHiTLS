/*
 * SHA-256 hash example.
 */

#include <stdio.h>
#include <stdint.h>

#include "crypt_algid.h"
#include "crypt_eal_init.h"
#include "crypt_eal_md.h"
#include "crypt_errno.h"

static void PrintHex(const uint8_t *data, uint32_t len)
{
    uint32_t i;

    for (i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main(void)
{
    const uint8_t message[] = "openHiTLS SHA-256 example";
    uint8_t digest[32];
    uint32_t digestLen = sizeof(digest);
    int32_t ret;

    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Init failed: 0x%x\n", ret);
        return -1;
    }

    ret = CRYPT_EAL_ProviderMd(NULL, CRYPT_MD_SHA256, NULL, message, sizeof(message) - 1, digest, &digestLen);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_ProviderMd failed: 0x%x\n", ret);
        CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
        return -1;
    }

    printf("Message: %s\n", message);
    printf("SHA-256: ");
    PrintHex(digest, digestLen);

    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return 0;
}
