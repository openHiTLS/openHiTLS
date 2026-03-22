/*
 * Random generation example.
 */

#include <stdio.h>
#include <stdint.h>

#include "crypt_eal_rand.h"
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
    uint8_t rnd[16];
    uint8_t rndWithAdin[16];
    uint8_t adin[] = {'g', 'u', 'i', 'd', 'e'};
    int32_t ret;

    printf("=== Random Generation Example ===\n\n");

    ret = CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_RandInit failed: 0x%x\n", ret);
        return -1;
    }
    ret = CRYPT_EAL_Randbytes(rnd, sizeof(rnd));
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Randbytes failed: 0x%x\n", ret);
        goto cleanup;
    }
    ret = CRYPT_EAL_RandbytesWithAdin(rndWithAdin, sizeof(rndWithAdin), adin, sizeof(adin));
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_RandbytesWithAdin failed: 0x%x\n", ret);
        goto cleanup;
    }
    ret = CRYPT_EAL_RandSeed();
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_RandSeed failed: 0x%x\n", ret);
        goto cleanup;
    }

    PrintHex("Random bytes", rnd, sizeof(rnd));
    PrintHex("Random bytes with adin", rndWithAdin, sizeof(rndWithAdin));
    ret = 0;

cleanup:
    CRYPT_EAL_RandDeinit();
    return ret;
}
