# Feature and Optimization Configuration Guide

openHiTLS has a highly modular architecture, with RAM/ROM size depending on the selected features and optimization configurations.

## 1. Feature Configuration

openHiTLS uses CMake `option()` variables to control which features to build. You can select a built-in preset or configure individual feature flags with `-D` options.

### Presets

Use `-DHITLS_BUILD_PROFILE=<preset>` to load a built-in preset:

| Preset | Description |
|---|---|
| `full` | All features enabled |
| `iso19790` | Cryptographic algorithm library compliant with ISO/IEC 19790 |

You can also load a preset file directly via CMake's `-C` parameter:

```bash
cmake .. -C cmake/presets/full.cmake
```

> **Note:** A custom preset file loaded via `-C` must contain `set(HITLS_PRESET_LOADED ON CACHE BOOL "" FORCE)`.

### Component and Algorithm Flags

After selecting a preset, use `-D` flags to enable or disable specific components and algorithms:

- **Component-level**: `-DHITLS_CRYPTO=ON/OFF`, `-DHITLS_TLS=ON/OFF`, `-DHITLS_PKI=ON/OFF`, `-DHITLS_BSL=ON/OFF`
- **Algorithm-level**: `-DHITLS_CRYPTO_<ALGO>=ON/OFF` (e.g., `-DHITLS_CRYPTO_AES=ON`, `-DHITLS_CRYPTO_SHA256=ON`)

The build system automatically enables required dependencies when a feature is enabled.

> **Tip:** All available feature switches are defined in [`cmake/hitls_options.cmake`](../../../cmake/hitls_options.cmake). Refer to that file for the complete list of configurable options.

> **Note:** If you find that a feature you explicitly disabled is still enabled when rerunning cmake, it may be due to one of the following reasons:
> 1. The last time the feature switch was enabled, it also enabled all of its sub-features. For example, using `cmake .. -DHITLS_CRYPTO_MD=ON` enables all hash algorithm sub-features (such as SHA256, SHA512, etc.). Even if you try to disable `HITLS_CRYPTO_MD` on a subsequent cmake run, because its sub-features are still enabled, CMake will automatically re-enable it based on dependency relationships, causing the feature to appear enabled. This behavior is expected because using `-DHITLS_CRYPTO_MD=ON` is assumed to mean you want all its sub-features enabled. To disable its sub-features, you need to explicitly turn off each sub-feature on the command line, e.g., `-DHITLS_CRYPTO_SHA256=OFF -DHITLS_CRYPTO_SHA512=OFF`.
> 2. The feature you explicitly disabled is strongly depended on by another feature. For example, if you disable `HITLS_CRYPTO_SHA256` but enable `HITLS_CRYPTO_SCRYPT`, and `HITLS_CRYPTO_SCRYPT` depends on `HITLS_CRYPTO_SHA256`, CMake will automatically re-enable `HITLS_CRYPTO_SHA256` to satisfy the dependency, causing it to appear enabled. This behavior is also expected because the build system ensures all dependencies are satisfied.

### Feature Configuration Examples

1. Enable the HPKE algorithm:

   ```bash
   cmake .. -DHITLS_CRYPTO_HPKE=ON \
            -DHITLS_CRYPTO_HKDF=ON \
            -DHITLS_CRYPTO_SHA256=ON \
            -DHITLS_CRYPTO_AES=ON \
            -DHITLS_CRYPTO_GCM=ON \
            -DHITLS_CRYPTO_X25519=ON
   ```

2. Use TLS 1.3 protocol with AES-128-GCM-SHA256 cipher suite:

   ```bash
   cmake .. -DHITLS_TLS_PROTO_TLS13=ON \
            -DHITLS_TLS_SUITE_AES_128_GCM_SHA256=ON \
            -DHITLS_CRYPTO_CURVE_NISTP256=ON \
            -DHITLS_TLS_SUITE_AUTH_ECDSA=ON
   ```

## 2. Optimization Configuration

### Configuration Categories

#### System-Related Configuration
|Configuration|Description|Recommendation|
|---|---|---|
|HITLS_BSL_SAL_LINUX|Use Linux system abstraction layer. Used to adapt Linux system calls. Auto-detected from the build host OS.|Auto-detected; specify explicitly for cross-compilation|
|HITLS_CRYPTO_AUXVAL|Use auxiliary vector to get CPU features. Requires alternative methods for CPU feature detection. Enabled by default, will be automatically selected based on platform support.|Enable if supported, otherwise disable|
|HITLS_CRYPTO_ASM_CHECK|Enable assembly code checking. Checks at runtime if CPU supports corresponding instruction set extensions. Automatically enabled when assembly features are enabled.|Auto-detected; enable or disable as needed|

#### Key Generation Optimization Configuration
|Configuration|Description|Recommendation|
|---|---|---|
|CRYPT_DH_TRY_CNT_MAX|Maximum number of attempts for DH key pair generation, default 100. When the generated key does not meet requirements, it will be regenerated until reaching this limit.|Keep default value of 100 unless there are special performance requirements|
|CRYPT_DSA_TRY_MAX_CNT|Maximum number of attempts for DSA key pair generation, default 100. When the generated key does not meet requirements, it will be regenerated until reaching this limit.|Keep default value of 100 unless there are special performance requirements|
|CRYPT_ECC_TRY_MAX_CNT|Maximum number of attempts for ECC key pair generation, default 100. When the generated key does not meet requirements, it will be regenerated until reaching this limit.|Keep default value of 100 unless there are special performance requirements|

#### ECC Optimization Configuration
|Configuration|Description|Recommendation|
|---|---|---|
|HITLS_CRYPTO_NIST_ECC_ACCELERATE|Use hardware acceleration for NIST curves. Enabled by default. Can be disabled via `-DHITLS_CRYPTO_NIST_ECC_ACCELERATE=OFF`. This acceleration depends on INT128; if system doesn't support it, this configuration is ignored.|Enabled by default|

#### Random Number Generation Configuration
|Configuration|Description|Recommendation|
|---|---|---|
|DRBG_MAX_RESEED_INTERVAL|Maximum interval for DRBG (Deterministic Random Bit Generator) reseeding, default 10000. After generating 10000 random numbers, entropy source must be reacquired for reseeding.|Keep default value of 10000. Larger values reduce random number security, smaller values affect performance|
|HITLS_CRYPTO_ENTROPY_DEVRANDOM|Use operating system device random number as entropy source. On Linux systems, typically uses /dev/random or /dev/urandom.|Enable if supported|
|HITLS_CRYPTO_INIT_RAND_ALG|Initialization random number algorithm for DRBG.|Default value is CRYPT_RAND_SHA256, optional values refer to CRYPT_RAND_AlgId in header file include/crypto/crypt_algid.h|

#### Other Configuration
|Configuration|Description|Recommendation|
|---|---|---|
|HITLS_BSL_LOG_NO_FORMAT_STRING|Log output without format strings, directly outputs raw strings. Can improve logging performance. This feature is mainly used in the protocol module.|Enable if log viewing is not needed|
|HITLS_EAL_INIT_OPTS=n|EAL initialization options. Default value is 0, indicating EAL initialization is disabled.<br>When HITLS_EAL_INIT_OPTS is defined, CRYPT_EAL_Init and CRYPT_EAL_Cleanup will be marked as constructor and destructor functions, and will override the parameters of these two functions.<br>Different values can be set to enable different EAL initializations:<br>- CPU feature detection: CRYPT_EAL_INIT_CPU       0x01<br>- Error code module initialization: CRYPT_EAL_INIT_BSL       0x02<br>- Random number initialization: CRYPT_EAL_INIT_RAND      0x04<br>- Provider initialization: CRYPT_EAL_INIT_PROVIDER  0x08<br>The value of n is the sum of the above values|Enable based on requirements|

### Configuration Method

Refer to [1_Build and Installation Guide](1_Build%20and%20Installation%20Guide.md). Pass configuration macros directly as CMake `-D` flags:

```bash
# Enable assembly check, disable NIST ECC hardware acceleration
cmake .. -DHITLS_CRYPTO_ASM_CHECK=ON -DHITLS_CRYPTO_NIST_ECC_ACCELERATE=OFF

# Enable specific EAL initialization options (9 = CRYPT_EAL_INIT_CPU + CRYPT_EAL_INIT_PROVIDER)
cmake .. -DHITLS_EAL_INIT_OPTS=9
```
