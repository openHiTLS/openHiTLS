/*
 * PBKDF2 Key Derivation Example
 * This example demonstrates how to derive a cryptographic key from a password using PBKDF2
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "crypt_eal_kdf.h"
#include "crypt_eal_init.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_params_key.h"
#include "bsl_sal.h"
#include "bsl_err.h"
#include "bsl_params.h"

void PrintHex(const char *label, uint8_t *data, uint32_t len)
{
    printf("%s: ", label);
    for (uint32_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main(void)
{
    int32_t ret;
    CRYPT_EAL_KdfCTX *ctx = NULL;

    /* Password to derive key from */
    uint8_t password[] = "MySecurePassword123!";
    uint32_t passwordLen = sizeof(password) - 1;

    /* Salt for key derivation (should be random in real applications) */
    uint8_t salt[] = {
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
    };
    uint32_t saltLen = sizeof(salt);

    /* PBKDF2 parameters */
    uint32_t iterations = 10000;  /* Number of iterations (higher = more secure but slower) */
    uint32_t keyLen = 32;         /* Desired key length in bytes (256 bits) */

    /* Output buffer for derived key */
    uint8_t derivedKey[32];
    printf("=== PBKDF2 Key Derivation Example ===\n\n");

    /* Initialize cryptographic library */
    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Init failed, error code: 0x%x\n", ret);
        return -1;
    }

    printf("Password: %s\n", password);
    printf("Password length: %u bytes\n", passwordLen);
    printf("Salt: ");
    PrintHex("", salt, saltLen);
    printf("Iterations: %u\n", iterations);
    printf("Desired key length: %u bytes (%u bits)\n\n", keyLen, keyLen * 8);

    /* Create PBKDF2 context */
    ctx = CRYPT_EAL_ProviderKdfNewCtx(NULL, CRYPT_KDF_PBKDF2, NULL);
    if (ctx == NULL) {
        printf("CRYPT_EAL_KdfNewCtx failed\n");
        ret = -1;
        goto cleanup;
    }

    /* Set PBKDF2 parameters using BSL_Param */
    BSL_Param params[5];
    uint32_t paramCount = 0;

    /* Set HMAC algorithm ID (using SHA-256) */
    int32_t macId = CRYPT_MAC_HMAC_SHA256;
    BSL_PARAM_InitValue(&params[paramCount], CRYPT_PARAM_KDF_MAC_ID,
                        BSL_PARAM_TYPE_UINT32, &macId, sizeof(macId));
    paramCount++;

    /* Set password */
    BSL_PARAM_InitValue(&params[paramCount], CRYPT_PARAM_KDF_PASSWORD,
                        BSL_PARAM_TYPE_OCTETS, password, passwordLen);
    paramCount++;

    /* Set salt */
    BSL_PARAM_InitValue(&params[paramCount], CRYPT_PARAM_KDF_SALT,
                        BSL_PARAM_TYPE_OCTETS, salt, saltLen);
    paramCount++;

    /* Set iteration count */
    BSL_PARAM_InitValue(&params[paramCount], CRYPT_PARAM_KDF_ITER,
                        BSL_PARAM_TYPE_UINT32, &iterations, sizeof(iterations));
    paramCount++;

    params[paramCount] = (BSL_Param)BSL_PARAM_END;

    /* Set parameters to KDF context */
    ret = CRYPT_EAL_KdfSetParam(ctx, params);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_KdfSetParam failed, error code: 0x%x\n", ret);
        goto cleanup;
    }

    printf("PBKDF2 parameters set successfully\n\n");

    /* Derive key */
    printf("Deriving key (this may take a few seconds due to %u iterations)...\n", iterations);
    ret = CRYPT_EAL_KdfDerive(ctx, derivedKey, keyLen);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_KdfDerive failed, error code: 0x%x\n", ret);
        goto cleanup;
    }

    printf("\nKey derivation successful!\n");
    printf("Derived key length: %u bytes (%u bits)\n", keyLen, keyLen * 8);
    PrintHex("Derived key", derivedKey, keyLen);
    printf("\n");

    /* Verification: Derive key again with same parameters */
    printf("Verifying: Deriving key again with same parameters...\n");
    uint8_t verifyKey[32];
    ret = CRYPT_EAL_KdfDerive(ctx, verifyKey, keyLen);
    if (ret != CRYPT_SUCCESS) {
        printf("Verification derivation failed, error code: 0x%x\n", ret);
        goto cleanup;
    }

    /* Compare the two derived keys */
    if (memcmp(derivedKey, verifyKey, keyLen) == 0) {
        printf("✓ Verification successful: Same key derived!\n");
        ret = 0;
    } else {
        printf("✗ Verification failed: Keys don't match!\n");
        ret = -1;
    }

cleanup:
    if (ctx != NULL) {
        CRYPT_EAL_KdfFreeCtx(ctx);
    }
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);

    return ret;
}
