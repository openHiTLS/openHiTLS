# This file is part of the openHiTLS project.
#
# openHiTLS is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#
#     http://license.coscl.org.cn/MulanPSL2
#
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.


message(STATUS "Loading preset: ISO 19790")

# Mark preset as loaded (prevents profile system from overriding)
set(HITLS_PRESET_LOADED ON CACHE BOOL "" FORCE)

# ---------------------------------------------------------------
# Crypto - Base Features
# ---------------------------------------------------------------
set(HITLS_CRYPTO_EAL                ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_PROVIDER           ON CACHE BOOL "" FORCE)

# ---------------------------------------------------------------
# CMVP - ISO 19790 Compliance Mode
# ---------------------------------------------------------------
set(HITLS_CRYPTO_CMVP_ISO19790      ON CACHE BOOL "" FORCE)

# ---------------------------------------------------------------
# Crypto - Symmetric Cipher
# ---------------------------------------------------------------
set(HITLS_CRYPTO_AES                ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_CHACHA20           ON CACHE BOOL "" FORCE)

# ---------------------------------------------------------------
# Crypto - AES Cipher Modes
# ---------------------------------------------------------------
set(HITLS_CRYPTO_MODES              ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_HCTR               OFF CACHE BOOL "" FORCE)

# ---------------------------------------------------------------
# Crypto - Hash: SHA-1 / SHA-2 / SHA-3 (ISO 19790 / FIPS 180-4, 202)
# SHA-1 is approved for legacy/limited use only
# SM3 is included as a dependency of SM2
# ---------------------------------------------------------------
set(HITLS_CRYPTO_SHA1               ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_SHA2               ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_SHA3               ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_SM3                ON CACHE BOOL "" FORCE)

# ---------------------------------------------------------------
# Crypto - MAC (ISO 19790 / NIST SP 800-38B, SP 800-185)
# ---------------------------------------------------------------
set(HITLS_CRYPTO_HMAC               ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_CMAC_AES           ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_GMAC               ON CACHE BOOL "" FORCE)

# ---------------------------------------------------------------
# Crypto - KDF (ISO 19790 / NIST SP 800-56C, SP 800-132)
# ---------------------------------------------------------------
set(HITLS_CRYPTO_HKDF               ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_PBKDF2             ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_KDFTLS12           ON CACHE BOOL "" FORCE)

# ---------------------------------------------------------------
# Crypto - DRBG (ISO 19790 / NIST SP 800-90A Rev 1)
# ---------------------------------------------------------------
set(HITLS_CRYPTO_DRBG_CTR           ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_DRBG_HASH          ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_DRBG_HMAC          ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_ENTROPY            ON CACHE BOOL "" FORCE)

# ---------------------------------------------------------------
# Crypto - Pkey Algorithms
# ---------------------------------------------------------------
set(HITLS_CRYPTO_PKEY_CMP          ON CACHE BOOL "" FORCE)

# DSA (FIPS 186)
set(HITLS_CRYPTO_DSA                ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_DSA_CHECK          ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_DSA_GEN_PARA       ON CACHE BOOL "" FORCE)

# CURVE25519 - Ed25519 (FIPS 186-5) / X25519
set(HITLS_CRYPTO_CURVE25519         ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_ED25519            ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_ED25519_CHECK      ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_X25519             ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_X25519_CHECK       ON CACHE BOOL "" FORCE)

# RSA (NIST SP 800-131A, FIPS 186)
set(HITLS_CRYPTO_RSA                ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_RSA_BSSA           ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_SP800_STRICT_CHECK ON CACHE BOOL "" FORCE)

# DH (NIST SP 800-56A)
set(HITLS_CRYPTO_DH                 ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_DH_CHECK           ON CACHE BOOL "" FORCE)

# ECC base (FIPS 186, SP 800-56A) - shared by ECDSA, ECDH, SM2
set(HITLS_CRYPTO_CURVE_NISTP192     ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_CURVE_NISTP224     ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_CURVE_NISTP256     ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_CURVE_NISTP384     ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_CURVE_NISTP521     ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_CURVE_SM2          ON CACHE BOOL "" FORCE)

# ECDSA (FIPS 186)
set(HITLS_CRYPTO_ECDSA              ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_ECDSA_CHECK        ON CACHE BOOL "" FORCE)

# ECDH (NIST SP 800-56A)
set(HITLS_CRYPTO_ECDH               ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_ECDH_CHECK         ON CACHE BOOL "" FORCE)

# SM2 (Chinese national standard, optional in ISO 19790 module)
set(HITLS_CRYPTO_SM2                ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_SM2_SIGN           ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_SM2_CRYPT          ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_SM2_EXCH           ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_SM2_CHECK          ON CACHE BOOL "" FORCE)

# SLH-DSA (FIPS 205)
set(HITLS_CRYPTO_SLH_DSA            ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_SLH_DSA_CHECK      ON CACHE BOOL "" FORCE)

# ML-KEM (FIPS 203)
set(HITLS_CRYPTO_MLKEM              ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_MLKEM_CHECK        ON CACHE BOOL "" FORCE)

# ML-DSA (FIPS 204)
set(HITLS_CRYPTO_MLDSA              ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_MLDSA_CHECK        ON CACHE BOOL "" FORCE)

# ---------------------------------------------------------------
# Crypto - Key Encoding/Decoding (PKCS#8, SubjectPublicKeyInfo)
# ---------------------------------------------------------------
set(HITLS_CRYPTO_CODECSKEY          ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_KEY_ENCODE         ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_KEY_DECODE         ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_KEY_EPKI           ON CACHE BOOL "" FORCE)

