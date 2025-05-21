#include "auth/totp/include/auth_totp.h"
#include "crypto/crypt_eal_mac.h"
#include "crypto/crypt_algid.h" // Already included by auth_totp.h, but good for clarity
#include "crypto/hmac/include/crypt_hmac.h" // For HMAC_MAXOUTSIZE
#include "bsl/sal/include/sal_time.h"
#include "bsl/bsl_types.h"      // Already included by auth_totp.h
#include "bsl/bsl_errno.h"      // For BSL_SUCCESS if needed, though CRYPT_SUCCESS is more likely

#include <string.h> // For memcpy, strlen
#include <stdio.h>  // For snprintf
#include <math.h>   // For floor

// Helper function to convert uint64_t to big-endian byte array
// Exposed for testing if needed, though typically static
void uint64_to_be_bytes(uint64_t value, uint8_t *bytes) {
    bytes[0] = (value >> 56) & 0xFF;
    bytes[1] = (value >> 48) & 0xFF;
    bytes[2] = (value >> 40) & 0xFF;
    bytes[3] = (value >> 32) & 0xFF;
    bytes[4] = (value >> 24) & 0xFF;
    bytes[5] = (value >> 16) & 0xFF;
    bytes[6] = (value >> 8) & 0xFF;
    bytes[7] = value & 0xFF;
}

// Internal function to generate TOTP for a given counter value
// Made non-static for testing RFC vectors directly.
// Consider if this should be in a private/internal header if not for testing.
int32_t generate_totp_for_counter(const uint8_t *secret,
                                         uint32_t secret_len,
                                         CRYPT_MAC_AlgId hmac_alg,
                                         uint64_t counter,
                                         uint32_t digits,
                                         char *totp_code,
                                         uint32_t totp_code_buffer_len) {
    CRYPT_EAL_MacCtx *mac_ctx = NULL;
    // Using HMAC_MAXOUTSIZE (64) as CRYPT_MAC_MAX_LEN was not found.
    uint8_t hmac_result[HMAC_MAXOUTSIZE]; 
    uint32_t hmac_len = sizeof(hmac_result);
    uint8_t counter_bytes[8];
    int32_t ret_val = TOTP_ERROR_HMAC_FAILURE;

    if (digits > 9 || digits == 0) { // Max 9 digits for uint32_t, typical 6 or 8
        return TOTP_ERROR_INVALID_INPUT;
    }
    if (totp_code_buffer_len < digits + 1) { // +1 for null terminator
        return TOTP_ERROR_BUFFER_TOO_SMALL;
    }

    uint64_to_be_bytes(counter, counter_bytes);

    mac_ctx = CRYPT_EAL_MacNewCtx(hmac_alg);
    if (mac_ctx == NULL) {
        return TOTP_ERROR_HMAC_FAILURE;
    }

    // Assuming CRYPT_EAL_MacInit signature is (CRYPT_EAL_MacCtx*, const uint8_t*, uint32_t)
    if (CRYPT_EAL_MacInit(mac_ctx, secret, secret_len) != CRYPT_SUCCESS) {
        goto cleanup;
    }

    if (CRYPT_EAL_MacUpdate(mac_ctx, counter_bytes, sizeof(counter_bytes)) != CRYPT_SUCCESS) {
        goto cleanup;
    }

    if (CRYPT_EAL_MacFinal(mac_ctx, hmac_result, &hmac_len) != CRYPT_SUCCESS) {
        goto cleanup;
    }

    // Dynamic truncation (RFC 6238 Section 5.3)
    uint8_t offset = hmac_result[hmac_len - 1] & 0x0F;
    if (offset + 4 > hmac_len) { // Check boundary
         ret_val = TOTP_ERROR_HMAC_FAILURE; 
         goto cleanup;
    }

    uint32_t binary_code = ((hmac_result[offset] & 0x7F) << 24) |
                           ((hmac_result[offset + 1] & 0xFF) << 16) |
                           ((hmac_result[offset + 2] & 0xFF) << 8) |
                           (hmac_result[offset + 3] & 0xFF);

    uint32_t divisor = 1;
    for (uint32_t i = 0; i < digits; ++i) {
        divisor *= 10;
    }
    
    uint32_t otp_value = binary_code % divisor;

    // Format as string, ensuring leading zeros
    char format_string[8]; // Max "%09u"
    snprintf(format_string, sizeof(format_string), "%%0%uu", digits);
    snprintf(totp_code, totp_code_buffer_len, format_string, otp_value);
    
    ret_val = TOTP_SUCCESS;

cleanup:
    if (mac_ctx != NULL) {
        CRYPT_EAL_MacFreeCtx(mac_ctx);
    }
    return ret_val;
}

int32_t TOTP_Generate(const uint8_t *secret,
                      uint32_t secret_len,
                      CRYPT_MAC_AlgId hmac_alg,
                      uint32_t time_step,
                      uint32_t t0,
                      uint32_t digits,
                      char *totp_code,
                      uint32_t totp_code_buffer_len) {

    if (secret == NULL || totp_code == NULL || secret_len == 0 || time_step == 0) {
        return TOTP_ERROR_INVALID_INPUT;
    }

    int64_t current_unix_time = BSL_SAL_CurrentSysTimeGet();
    if (current_unix_time < 0) { // Error from BSL_SAL_CurrentSysTimeGet
        return TOTP_ERROR_TIME_FAILURE;
    }
    
    if ((uint64_t)current_unix_time < t0) {
         return TOTP_ERROR_INVALID_INPUT; // Current time before T0
    }

    uint64_t time_counter = (uint64_t)floor(((double)current_unix_time - t0) / time_step);

    return generate_totp_for_counter(secret, secret_len, hmac_alg, time_counter, digits, totp_code, totp_code_buffer_len);
}

int32_t TOTP_Validate(const char *totp_code,
                      const uint8_t *secret,
                      uint32_t secret_len,
                      CRYPT_MAC_AlgId hmac_alg,
                      uint32_t time_step,
                      uint32_t t0,
                      uint32_t digits,
                      int32_t window) {

    if (totp_code == NULL || secret == NULL || secret_len == 0 || time_step == 0) {
        return TOTP_ERROR_INVALID_INPUT;
    }
    if (digits == 0 || digits > 9) {
        return TOTP_ERROR_INVALID_INPUT;
    }
    if (strlen(totp_code) != digits) {
        return TOTP_ERROR_INVALID_INPUT; // Code length mismatch
    }

    int64_t current_unix_time = BSL_SAL_CurrentSysTimeGet();
    if (current_unix_time < 0) {
        return TOTP_ERROR_TIME_FAILURE;
    }
    
    // If current time is before t0 and even the furthest future window slot (current_time + window * time_step) is still before t0,
    // then validation is impossible.
    if ((uint64_t)current_unix_time < t0 && (current_unix_time + (int64_t)window * time_step) < (int64_t)t0 ) {
         return TOTP_ERROR_INVALID_INPUT;
    }

    uint64_t current_time_counter = (uint64_t)floor(((double)current_unix_time - t0) / time_step);
    char generated_code_buffer[10]; // Max 9 digits + null

    // Check current time step
    // Ensure the time for current_time_counter is effectively >= t0
    if (current_unix_time >= (int64_t)t0) {
        if (generate_totp_for_counter(secret, secret_len, hmac_alg, current_time_counter, digits, generated_code_buffer, sizeof(generated_code_buffer)) == TOTP_SUCCESS) {
            if (strncmp(generated_code_buffer, totp_code, digits) == 0) {
                return TOTP_SUCCESS;
            }
        }
    }

    // Check window (if any)
    for (int32_t i = 1; i <= window; ++i) {
        // Check previous time steps: current_time_counter - i
        // Effective time for this check: current_unix_time - i * time_step
        double past_check_time_sec = (double)current_unix_time - (double)i * time_step;
        if (past_check_time_sec >= (double)t0) {
            uint64_t past_counter = (uint64_t)floor((past_check_time_sec - t0) / time_step);
            if (generate_totp_for_counter(secret, secret_len, hmac_alg, past_counter, digits, generated_code_buffer, sizeof(generated_code_buffer)) == TOTP_SUCCESS) {
                if (strncmp(generated_code_buffer, totp_code, digits) == 0) {
                    return TOTP_SUCCESS;
                }
            }
        }

        // Check future time steps: current_time_counter + i
        // Effective time for this check: current_unix_time + i * time_step
        double future_check_time_sec = (double)current_unix_time + (double)i * time_step;
        if (future_check_time_sec >= (double)t0) { // Ensure this time point is not before t0
            uint64_t future_counter = (uint64_t)floor((future_check_time_sec - t0) / time_step);
            if (generate_totp_for_counter(secret, secret_len, hmac_alg, future_counter, digits, generated_code_buffer, sizeof(generated_code_buffer)) == TOTP_SUCCESS) {
                if (strncmp(generated_code_buffer, totp_code, digits) == 0) {
                    return TOTP_SUCCESS;
                }
            }
        }
    }

    return TOTP_ERROR_VALIDATION_FAILED;
}
