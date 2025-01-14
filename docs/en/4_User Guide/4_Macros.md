# Macros
## Feature Macros
If using the build method provided by openHiTLS, there's no need to manually set macros. Refer to [1_Build and Installation Guide](1_Build and Installation Guide.md), use `--enable` to enable a feature, or `--disable` to disable it.

For the complete list of feature macros, refer to feature.json: libs/hitls_/features/\*/
## Key Generation Related Macros
- `CRYPT_DH_TRY_CNT_MAX`
    - Default value: 100
    - Description: Maximum number of attempts for DH key pair generation. When the generated key does not meet requirements, it will be regenerated until reaching this limit.
    - Recommendation: Keep the default value of 100 unless there are special performance requirements.

- `CRYPT_DSA_TRY_MAX_CNT`
    - Default value: 100
    - Description: Maximum number of attempts for DSA key pair generation. When the generated key does not meet requirements, it will be regenerated until reaching this limit.
    - Recommendation: Keep the default value of 100 unless there are special performance requirements.

- `CRYPT_ECC_TRY_MAX_CNT`
    - Default value: 100
    - Description: Maximum number of attempts for ECC key pair generation. When the generated key does not meet requirements, it will be regenerated until reaching this limit.
    - Recommendation: Keep the default value of 100 unless there are special performance requirements.

## Random Number Generation Related Macros
- `DRBG_MAX_RESEED_INTERVAL`
    - Default value: 10000
    - Description: Maximum interval for DRBG (Deterministic Random Bit Generator) reseeding. After generating 10000 random numbers, entropy source must be reacquired for reseeding.
    - Recommendation: Keep the default value of 10000. Larger values reduce random number security, smaller values affect performance.

- `ENTROPY_USE_DEVRANDOM`
    - Description: Use operating system device random number as entropy source. On Linux systems, typically uses /dev/random or /dev/urandom.

## System Related Macros
- `HITLS_BIG_ENDIAN`
    - Description: Indicates system uses big-endian byte order. Affects data storage and transmission format.
    - Note: If not specified, little-endian byte order is used by default.

- `HITLS_BSL_LOG_NO_FORMAT_STRING`
    - Description: Log output without format strings, directly outputs raw strings. Can improve logging performance. This feature is mainly used in the protocol module.
    - Note: If not specified, format strings are used by default.
    - Recommendation: Enable this macro in scenarios where log performance needs to be improved.

- `HITLS_BSL_SAL_LINUX`
    - Description: Use Linux system abstraction layer. Used to adapt Linux system calls.
    - Note: If not specified, users need to register SAL interfaces themselves.
    - Related features: sal_mem, sal_thread, sal_lock, sal_file, sal_net, sal_time, sal_dl

- `HITLS_CRYPTO_NO_AUXVAL`
    - Description: Do not use auxiliary vector to get CPU features. Requires alternative methods for CPU feature detection.

- `HITLS_CRYPTO_ASM_CHECK`
    - Description: Enable assembly code checking. Checks at runtime if CPU supports corresponding instruction set extensions. Currently supported algorithm checks include:
        - aes: x8664/armv8
        - sm4: x8664/armv8
        - gcm: x8664/armv8
        - md5: x8664
        - sha1: x8664
        - sha2: x8664
        - sm3: x8664
        - ecc: x8664
    - Note: Only effective when the ealinit feature is enabled.

- `HITLS_EAL_INIT_OPTS`
    - Description: EAL (Encryption Adaptation Layer) initialization options. Used to configure encryption module initialization parameters.
    - Used for CRYPT_EAL_Init function, can replace this function's input parameters. Values refer to header file include/crypto/crypt_eal_init.h, can combine the following values:
        - CRYPT_EAL_INIT_CPU
        - CRYPT_EAL_INIT_BSL
        - CRYPT_EAL_INIT_RAND
        - CRYPT_EAL_INIT_PROVIDER

## Big Number Related Macros
- `HITLS_SIXTY_FOUR_BITS`, `HITLS_THIRTY_TWO_BITS`
    - Description: Indicates whether the current system is 64-bit or 32-bit platform.
    - Default value: HITLS_SIXTY_FOUR_BITS, i.e., 64-bit mode.
    - Recommendation: Keep consistent with current system bit width.

## Algorithm Related Macros
- `HITLS_CRYPTO_INIT_RAND_ALG`
    - Description: Initialize random number algorithm, used for DRBG initialization.
    - Default value: CRYPT_RAND_SHA256
    - Optional values: Refer to CRYPT_RAND_AlgId in header file include/crypto/crypt_algid.h

- `HITLS_CRYPTO_NIST_ECC_ACCELERATE`
    - Description: Use hardware acceleration for NIST curves. This macro is enabled by default, configured in config/json/compile.json.
    - Recommendation: Enable this macro on platforms supporting hardware acceleration to improve ECC computation performance.

## Setting Macros
Refer to [1_Build and Installation Guide](1_Build and Installation Guide.md), use `--add_options` to add macros or `--del_options` to delete macros.

Example:
```bash
python3 ../configure.py --add_options="-DHITLS_CRYPTO_NIST_ECC_ACCELERATE"
```
