#ifndef AUTH_TOTP_H
#define AUTH_TOTP_H

#include <stdint.h>
#include "crypto/crypt_algid.h" // For CRYPT_MAC_AlgId
#include "bsl/bsl_types.h"      // For int32_t, uint32_t

#ifdef __cplusplus
extern "C" {
#endif

// Error Codes
#define TOTP_SUCCESS 0
#define TOTP_ERROR_INVALID_INPUT -1
#define TOTP_ERROR_BUFFER_TOO_SMALL -2
#define TOTP_ERROR_HMAC_FAILURE -3
#define TOTP_ERROR_VALIDATION_FAILED -4
#define TOTP_ERROR_TIME_FAILURE -5

/**
 * @brief Generates a Time-based One-Time Password (TOTP).
 *
 * @param secret Pointer to the shared secret key.
 * @param secret_len Length of the shared secret key in bytes.
 * @param hmac_alg HMAC algorithm to use (e.g., CRYPT_MAC_HMAC_SHA1, CRYPT_MAC_HMAC_SHA256).
 * @param time_step Time step in seconds (e.g., 30).
 * @param t0 Unix time to start counting time steps from (e.g., 0 for standard Unix epoch).
 * @param digits Number of digits in the TOTP code (typically 6 or 8).
 * @param totp_code Output buffer to store the generated TOTP string (null-terminated).
 * @param totp_code_buffer_len Size of the totp_code buffer.
 * @return TOTP_SUCCESS on success, or an error code on failure.
 */
int32_t TOTP_Generate(const uint8_t *secret,
                      uint32_t secret_len,
                      CRYPT_MAC_AlgId hmac_alg,
                      uint32_t time_step,
                      uint32_t t0,
                      uint32_t digits,
                      char *totp_code,
                      uint32_t totp_code_buffer_len);

/**
 * @brief Validates a given Time-based One-Time Password (TOTP).
 *
 * @param totp_code The TOTP code string to validate.
 * @param secret Pointer to the shared secret key.
 * @param secret_len Length of the shared secret key in bytes.
 * @param hmac_alg HMAC algorithm to use.
 * @param time_step Time step in seconds.
 * @param t0 Unix time to start counting time steps from.
 * @param digits Number of digits in the TOTP code.
 * @param window The number of previous and next time steps to check to account for clock skew
 *               (e.g., a window of 1 checks T-1, T, and T+1). Use 0 for no window.
 * @return TOTP_SUCCESS if the code is valid, TOTP_ERROR_VALIDATION_FAILED if invalid,
 *         or another error code on other failures.
 */
int32_t TOTP_Validate(const char *totp_code,
                      const uint8_t *secret,
                      uint32_t secret_len,
                      CRYPT_MAC_AlgId hmac_alg,
                      uint32_t time_step,
                      uint32_t t0,
                      uint32_t digits,
                      int32_t window);

// --- Internal functions exposed for testing/advanced use ---
// WARNING: These are not typically part of the public API. Use with caution.

/**
 * @brief Converts a uint64_t value to a big-endian byte array.
 * Exposed for testing purposes.
 */
void uint64_to_be_bytes(uint64_t value, uint8_t *bytes);

/**
 * @brief Generates a TOTP code for a specific counter value.
 * Exposed for testing RFC vectors directly.
 * This function is normally static within auth_totp.c.
 */
int32_t generate_totp_for_counter(const uint8_t *secret,
                                  uint32_t secret_len,
                                  CRYPT_MAC_AlgId hmac_alg,
                                  uint64_t counter,
                                  uint32_t digits,
                                  char *totp_code,
                                  uint32_t totp_code_buffer_len);

#ifdef __cplusplus
}
#endif

#endif // AUTH_TOTP_H
