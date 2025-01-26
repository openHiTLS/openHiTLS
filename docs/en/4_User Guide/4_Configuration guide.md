# Feature and Optimization Configuration Guide

openHiTLS has a highly modular architecture, with RAM/ROM size depending on the selected features and optimization configurations.

## 1. Feature Configuration
The feature.json file defines the features of openHiTLS. It serves both as a comprehensive, full-featured configuration file and as a feature dictionary for user reference. It contains two parts: libs and modules, where the libs section defines the components and features of openHiTLS.

`libs.hitls_xxx.features.c/asm` defines the c/asm features of component hitls_xxx. 

Example:
Feature configuration examples:
1. To enable `feature_C`, you need to enable:
- `feature_C`: main feature
- `feature_A`: required by `feature_Ca`. This feature doesn't need to be explicitly enabled; the build framework will automatically enable dependent features when enabling the main feature.
- `feature_Ba`: required by `feature_C`. This feature doesn't need to be explicitly enabled; the build framework will automatically enable dependent features when enabling the main feature.
- `feature_Da` or `feature_Db`: required by `feature_C`, and at least one must be enabled. This feature needs to be explicitly enabled since it's unclear which specific feature the user needs.
- **Configuration command**:` python3 configure.py --enable feature_C feature_Da`

2. To enable `feature_Da` and `feature_Db`:
- `feature_D`: since it only contains these two sub-features, you only need to enable `feature_D`.
- **Configuration command**: `python3 configure.py --enable feature_D`

## 2. Optimization Configuration

### Configuration Categories

#### System-Related Configuration
|Configuration|Description|Recommendation|
|---|---|---|
|HITLS_BIG_ENDIAN|Indicates system uses big-endian byte order. Affects data storage and transmission format. If not specified, little-endian is used by default.|Enable if system is big-endian|
|HITLS_BSL_SAL_LINUX|Use Linux system abstraction layer. Used to adapt Linux system calls.|Enable if supported, otherwise disable|
|HITLS_CRYPTO_NO_AUXVAL|Do not use auxiliary vector to get CPU features. Requires alternative methods for CPU feature detection.|Enable if supported, otherwise disable|
|HITLS_CRYPTO_ASM_CHECK|Enable assembly code checking. Checks at runtime if CPU supports corresponding instruction set extensions. Currently supported algorithm checks include: aes, sm4, gcm, md5, sha1, sha2, sm3, ecc.|Only effective when ealinit feature is enabled|

#### Big Number Configuration
|Configuration|Description|Recommendation|
|---|---|---|
|HITLS_SIXTY_FOUR_BITS|Indicates system is 64-bit platform.|Enable if system is 64-bit|
|HITLS_THIRTY_TWO_BITS|Indicates system is 32-bit platform.|Enable if system is 32-bit|

#### Key Generation Optimization Configuration
|Configuration|Description|Recommendation|
|---|---|---|
|CRYPT_DH_TRY_CNT_MAX|Maximum number of attempts for DH key pair generation, default 100. When the generated key does not meet requirements, it will be regenerated until reaching this limit.|Keep default value of 100 unless there are special performance requirements|
|CRYPT_DSA_TRY_MAX_CNT|Maximum number of attempts for DSA key pair generation, default 100. When the generated key does not meet requirements, it will be regenerated until reaching this limit.|Keep default value of 100 unless there are special performance requirements|
|CRYPT_ECC_TRY_MAX_CNT|Maximum number of attempts for ECC key pair generation, default 100. When the generated key does not meet requirements, it will be regenerated until reaching this limit.|Keep default value of 100 unless there are special performance requirements|

#### ECC Optimization Configuration
|Configuration|Description|Recommendation|
|---|---|---|
|HITLS_CRYPTO_NIST_ECC_ACCELERATE|Use hardware acceleration for NIST curves. Enabled by default, configured in config/json/compile.json. This acceleration depends on INT128; if system doesn't support it, this configuration is ignored.|Enabled by default|

#### Random Number Generation Configuration
|Configuration|Description|Recommendation|
|---|---|---|
|DRBG_MAX_RESEED_INTERVAL|Maximum interval for DRBG (Deterministic Random Bit Generator) reseeding, default 10000. After generating 10000 random numbers, entropy source must be reacquired for reseeding.|Keep default value of 10000. Larger values reduce random number security, smaller values affect performance|
|ENTROPY_USE_DEVRANDOM|Use operating system device random number as entropy source. On Linux systems, typically uses /dev/random or /dev/urandom.|Enable if supported|
|HITLS_CRYPTO_INIT_RAND_ALG|Initialization random number algorithm for DRBG.|Default value is CRYPT_RAND_SHA256, optional values refer to CRYPT_RAND_AlgId in header file include/crypto/crypt_algid.h|

#### Other Configuration
|Configuration|Description|Recommendation|
|---|---|---|
|HITLS_BSL_LOG_NO_FORMAT_STRING|Log output without format strings, directly outputs raw strings. Can improve logging performance. This feature is mainly used in the protocol module.|Enable if log viewing is not needed|
|HITLS_EAL_INIT_OPTS=n|EAL initialization options. Default value is 0, indicating EAL initialization is disabled.<br>When HITLS_EAL_INIT_OPTS is defined, CRYPT_EAL_Init and CRYPT_EAL_Cleanup will be marked as constructor and destructor functions, and will override the parameters of these two functions.<br>Different values can be set to enable different EAL initializations:<br>- CPU feature detection: CRYPT_EAL_INIT_CPU       0x01<br>- Error code module initialization: CRYPT_EAL_INIT_BSL       0x02<br>- Random number initialization: CRYPT_EAL_INIT_RAND      0x04<br>- Provider initialization: CRYPT_EAL_INIT_PROVIDER  0x08<br>The value of n is the sum of the above values|Enable based on requirements|

### Configuration Method

Refer to 1_Build and Installation Guide, use --add_options to add configurations or --del_options to delete default configurations.

Example:
```bash
python3 ../configure.py --add_options="-DHITLS_CRYPTO_ASM_CHECK" --del_options="-DHITLS_CRYPTO_NIST_ECC_ACCELERATE"

python3 ../configure.py --add_options="-DHITLS_BSL_SAL_LINUX" # Same as python3 ../configure.py --system linux

python3 ../configure.py --add_options="-DHITLS_THIRTY_TWO_BITS" # Same as python3 ../configure.py --bits 32

python3 ../configure.py --add_options="-DHITLS_EAL_INIT_OPTS=9" # 9 = CRYPT_EAL_INIT_CPU + CRYPT_EAL_INIT_PROVIDER
```
