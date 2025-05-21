#include <stdio.h>
#include <string.h>
#include <stdint.h> // For uint8_t etc.

#include "auth/totp/include/auth_totp.h"
#include "crypto/crypt_algid.h" // For CRYPT_MAC_AlgId
// #include "bsl/sal/include/sal_time.h" // For BSL_SAL_CurrentSysTimeGet - not needed for these tests

// For RFC tests, we use the exposed generate_totp_for_counter
// For self-consistency, TOTP_Generate uses the system time.

int run_rfc_sha1_tests() {
    int failures = 0;
    const uint8_t secret[] = "Geheimnis"; // ASCII: 47 65 68 65 69 6d 6e 69 73
    uint32_t secret_len = strlen((const char*)secret);
    char totp_code_buffer[10]; // Buffer for TOTP code + null terminator
    CRYPT_MAC_AlgId hmac_alg = CRYPT_MAC_HMAC_SHA1;
    uint32_t digits = 6;

    printf("Starting RFC 6238 SHA1 Direct Counter Tests (6-digits)...\n");

    // Test Case 1: Counter = 1 (from Time = 59s, step=30, T0=0)
    // Expected TOTP for 6 digits (SHA1): 287082
    const char* expected_rfc_totp_1 = "287082";
    uint64_t counter1 = 1;
    printf("RFC Test Vector 1 (Counter %llu, SHA1, %u-digit)\n", (unsigned long long)counter1, digits);
    if (generate_totp_for_counter(secret, secret_len, hmac_alg, counter1, digits, totp_code_buffer, sizeof(totp_code_buffer)) == TOTP_SUCCESS) {
        if (strncmp(totp_code_buffer, expected_rfc_totp_1, digits) == 0) {
            printf("  PASSED: Expected %s, Got %s\n", expected_rfc_totp_1, totp_code_buffer);
        } else {
            printf("  FAILED: Expected %s, Got %s\n", expected_rfc_totp_1, totp_code_buffer);
            failures++;
        }
    } else {
        printf("  FAILED: Generation error for counter %llu\n", (unsigned long long)counter1);
        failures++;
    }

    // Test Case 2: Counter = 37037036 (from Time = 1111111109s, step=30, T0=0)
    // Expected TOTP for 6 digits (SHA1): 081805
    const char* expected_rfc_totp_2 = "081805";
    uint64_t counter2 = 37037036;
    printf("RFC Test Vector 2 (Counter %llu, SHA1, %u-digit)\n", (unsigned long long)counter2, digits);
    if (generate_totp_for_counter(secret, secret_len, hmac_alg, counter2, digits, totp_code_buffer, sizeof(totp_code_buffer)) == TOTP_SUCCESS) {
        if (strncmp(totp_code_buffer, expected_rfc_totp_2, digits) == 0) {
            printf("  PASSED: Expected %s, Got %s\n", expected_rfc_totp_2, totp_code_buffer);
        } else {
            printf("  FAILED: Expected %s, Got %s\n", expected_rfc_totp_2, totp_code_buffer);
            failures++;
        }
    } else {
        printf("  FAILED: Generation error for counter %llu\n", (unsigned long long)counter2);
        failures++;
    }
    
    // Test Case 3: Counter = 37037037 (from Time = 1111111111s -> RFC uses 1111111111, step=30, T0=0)
    // RFC Expected for 8 digits (SHA1, T=1111111111): 14050471. For 6 digits: 050471
    const char* expected_rfc_totp_3 = "050471";
    uint64_t counter3 = 37037037; 
    printf("RFC Test Vector 3 (Counter %llu, SHA1, %u-digit)\n", (unsigned long long)counter3, digits);
    if (generate_totp_for_counter(secret, secret_len, hmac_alg, counter3, digits, totp_code_buffer, sizeof(totp_code_buffer)) == TOTP_SUCCESS) {
        if (strncmp(totp_code_buffer, expected_rfc_totp_3, digits) == 0) {
            printf("  PASSED: Expected %s, Got %s\n", expected_rfc_totp_3, totp_code_buffer);
        } else {
            printf("  FAILED: Expected %s, Got %s\n", expected_rfc_totp_3, totp_code_buffer);
            failures++;
        }
    } else {
        printf("  FAILED: Generation error for counter %llu\n", (unsigned long long)counter3);
        failures++;
    }

    // Test Case 4: Counter = 41666666 (from Time = 1234567890s, step=30, T0=0)
    // RFC Expected for 8 digits (SHA1, T=1234567890): 89005924. For 6 digits: 005924
    const char* expected_rfc_totp_4 = "005924";
    uint64_t counter4 = 41666666;
    printf("RFC Test Vector 4 (Counter %llu, SHA1, %u-digit)\n", (unsigned long long)counter4, digits);
    if (generate_totp_for_counter(secret, secret_len, hmac_alg, counter4, digits, totp_code_buffer, sizeof(totp_code_buffer)) == TOTP_SUCCESS) {
        if (strncmp(totp_code_buffer, expected_rfc_totp_4, digits) == 0) {
            printf("  PASSED: Expected %s, Got %s\n", expected_rfc_totp_4, totp_code_buffer);
        } else {
            printf("  FAILED: Expected %s, Got %s\n", expected_rfc_totp_4, totp_code_buffer);
            failures++;
        }
    } else {
        printf("  FAILED: Generation error for counter %llu\n", (unsigned long long)counter4);
        failures++;
    }

    // Test Case 5: Counter = 66666666 (from Time = 2000000000s, step=30, T0=0)
    // RFC Expected for 8 digits (SHA1, T=2000000000): 69279037. For 6 digits: 279037
    const char* expected_rfc_totp_5 = "279037";
    uint64_t counter5 = 66666666;
    printf("RFC Test Vector 5 (Counter %llu, SHA1, %u-digit)\n", (unsigned long long)counter5, digits);
    if (generate_totp_for_counter(secret, secret_len, hmac_alg, counter5, digits, totp_code_buffer, sizeof(totp_code_buffer)) == TOTP_SUCCESS) {
        if (strncmp(totp_code_buffer, expected_rfc_totp_5, digits) == 0) {
            printf("  PASSED: Expected %s, Got %s\n", expected_rfc_totp_5, totp_code_buffer);
        } else {
            printf("  FAILED: Expected %s, Got %s\n", expected_rfc_totp_5, totp_code_buffer);
            failures++;
        }
    } else {
        printf("  FAILED: Generation error for counter %llu\n", (unsigned long long)counter5);
        failures++;
    }

    printf("RFC SHA1 Direct Counter Tests Complete. Failures: %d\n\n", failures);
    return failures;
}

int run_self_consistency_tests() {
    int failures = 0;
    const uint8_t secret[] = "TestSecret123!@#";
    uint32_t secret_len = strlen((const char*)secret);
    char totp_code[10];
    uint32_t time_step = 30;
    uint32_t t0 = 0;
    uint32_t digits = 6;
    int32_t window = 1; // Check current, T-1, T+1

    printf("Starting Self-Consistency Tests (Generate then Validate)...\n");

    // Test with SHA1
    printf("Self-Consistency Test (SHA1, %u-digits, window %d)\n", digits, window);
    int32_t gen_result_sha1 = TOTP_Generate(secret, secret_len, CRYPT_MAC_HMAC_SHA1, time_step, t0, digits, totp_code, sizeof(totp_code));
    if (gen_result_sha1 == TOTP_SUCCESS) {
        printf("  Generated SHA1 TOTP: %s (using current time)\n", totp_code);
        int32_t val_result_sha1 = TOTP_Validate(totp_code, secret, secret_len, CRYPT_MAC_HMAC_SHA1, time_step, t0, digits, window);
        if (val_result_sha1 == TOTP_SUCCESS) {
            printf("  PASSED: Validation successful.\n");
        } else {
            printf("  FAILED: Validation failed with code %d for generated TOTP %s\n", val_result_sha1, totp_code);
            failures++;
        }
    } else {
        printf("  FAILED: Generation failed with code %d\n", gen_result_sha1);
        failures++;
    }

    // Test with SHA256
    printf("Self-Consistency Test (SHA256, %u-digits, window %d)\n", digits, window);
    int32_t gen_result_sha256 = TOTP_Generate(secret, secret_len, CRYPT_MAC_HMAC_SHA256, time_step, t0, digits, totp_code, sizeof(totp_code));
    if (gen_result_sha256 == TOTP_SUCCESS) {
        printf("  Generated SHA256 TOTP: %s (using current time)\n", totp_code);
        int32_t val_result_sha256 = TOTP_Validate(totp_code, secret, secret_len, CRYPT_MAC_HMAC_SHA256, time_step, t0, digits, window);
        if (val_result_sha256 == TOTP_SUCCESS) {
            printf("  PASSED: Validation successful.\n");
        } else {
            printf("  FAILED: Validation failed with code %d for generated TOTP %s\n", val_result_sha256, totp_code);
            failures++;
        }
    } else {
        printf("  FAILED: Generation failed with code %d\n", gen_result_sha256);
        failures++;
    }
    
    // Test with SHA512
    digits = 8; // RFC examples for SHA512 often use 8 digits
    window = 0; // Test with a tighter window
    printf("Self-Consistency Test (SHA512, %u-digits, window %d)\n", digits, window);
    int32_t gen_result_sha512 = TOTP_Generate(secret, secret_len, CRYPT_MAC_HMAC_SHA512, time_step, t0, digits, totp_code, sizeof(totp_code));
    if (gen_result_sha512 == TOTP_SUCCESS) {
        printf("  Generated SHA512 TOTP: %s (using current time)\n", totp_code);
        int32_t val_result_sha512 = TOTP_Validate(totp_code, secret, secret_len, CRYPT_MAC_HMAC_SHA512, time_step, t0, digits, window);
        if (val_result_sha512 == TOTP_SUCCESS) {
            printf("  PASSED: Validation successful.\n");
        } else {
            printf("  FAILED: Validation failed with code %d for generated TOTP %s\n", val_result_sha512, totp_code);
            failures++;
        }
    } else {
        printf("  FAILED: Generation failed with code %d\n", gen_result_sha512);
        failures++;
    }

    printf("Self-Consistency Tests Complete. Failures: %d\n\n", failures);
    return failures;
}


int main() {
    int total_failures = 0;
    
    printf("===== Starting TOTP Unit Tests =====\n");

    total_failures += run_rfc_sha1_tests();
    total_failures += run_self_consistency_tests();

    printf("===== TOTP Unit Tests Complete =====\n");
    if (total_failures == 0) {
        printf("All TOTP tests PASSED.\n");
        return 0; // Success
    } else {
        printf("Some TOTP tests FAILED. Total failures: %d\n", total_failures);
        return 1; // Failure
    }
}
