#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "auth/totp/include/auth_totp.h"
#include "crypto/crypt_algid.h" // For CRYPT_MAC_AlgId

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <secret> [totp_to_validate]\n", argv[0]);
        return 1;
    }

    const uint8_t *secret = (const uint8_t *)argv[1];
    uint32_t secret_len = strlen(argv[1]);
    
    // TOTP parameters
    CRYPT_MAC_AlgId hmac_alg = CRYPT_MAC_HMAC_SHA1; // Or CRYPT_MAC_HMAC_SHA256
    uint32_t time_step = 30;
    uint32_t t0 = 0;
    uint32_t digits = 6;
    char totp_code_buffer[10]; // Buffer for 6-8 digits + null

    printf("Using secret: %s\n", argv[1]);
    printf("Algorithm: %s\n", (hmac_alg == CRYPT_MAC_HMAC_SHA1) ? "HMAC-SHA1" : "HMAC-SHA256 (or other)");
    printf("Time step: %u seconds\n", time_step);
    printf("Digits: %u\n", digits);

    int32_t gen_result = TOTP_Generate(secret, secret_len, hmac_alg, time_step, t0, digits, 
                                       totp_code_buffer, sizeof(totp_code_buffer));

    if (gen_result == TOTP_SUCCESS) {
        printf("Generated TOTP: %s\n", totp_code_buffer);
    } else {
        fprintf(stderr, "Error generating TOTP: %d\n", gen_result);
        return 1;
    }

    if (argc >= 3) {
        const char *code_to_validate = argv[2];
        printf("Attempting to validate provided code: %s\n", code_to_validate);
        
        // Allow a window of 1 time step (e.g., current, previous, next) for validation
        int32_t validation_window = 1; 
        int32_t val_result = TOTP_Validate(code_to_validate, secret, secret_len, hmac_alg, 
                                           time_step, t0, digits, validation_window);

        if (val_result == TOTP_SUCCESS) {
            printf("Validation successful! The code is valid.\n");
        } else if (val_result == TOTP_ERROR_VALIDATION_FAILED) {
            printf("Validation failed. The code is NOT valid.\n");
        } else {
            fprintf(stderr, "Error during validation: %d\n", val_result);
        }
    }
    return 0;
}
