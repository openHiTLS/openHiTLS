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


# Mark preset as loaded (prevents profile system from overriding)
set(HITLS_PRESET_LOADED                                ON CACHE BOOL "" FORCE)

# Build type options
set(HITLS_BUILD_STATIC                                 ON CACHE BOOL "" FORCE)
set(HITLS_BUILD_SHARED                                 ON CACHE BOOL "" FORCE)

# BSL modules
set(HITLS_BSL_ASN1                                     ON CACHE BOOL "" FORCE)
set(HITLS_BSL_BASE64                                   ON CACHE BOOL "" FORCE)
set(HITLS_BSL_BUFFER                                   ON CACHE BOOL "" FORCE)
set(HITLS_BSL_ERR                                      ON CACHE BOOL "" FORCE)
set(HITLS_BSL_HASH                                     ON CACHE BOOL "" FORCE)
set(HITLS_BSL_INIT                                     ON CACHE BOOL "" FORCE)
set(HITLS_BSL_LIST                                     ON CACHE BOOL "" FORCE)
set(HITLS_BSL_LOG                                      ON CACHE BOOL "" FORCE)
set(HITLS_BSL_OBJ                                      ON CACHE BOOL "" FORCE)
set(HITLS_BSL_PARAMS                                   ON CACHE BOOL "" FORCE)
set(HITLS_BSL_PEM                                      ON CACHE BOOL "" FORCE)
set(HITLS_BSL_SAL                                      ON CACHE BOOL "" FORCE)
set(HITLS_BSL_SAL_DL                                   ON CACHE BOOL "" FORCE)
set(HITLS_BSL_SAL_FILE                                 ON CACHE BOOL "" FORCE)
set(HITLS_BSL_SAL_LOCK                                 ON CACHE BOOL "" FORCE)
set(HITLS_BSL_SAL_MEM                                  ON CACHE BOOL "" FORCE)
set(HITLS_BSL_SAL_NET                                  ON CACHE BOOL "" FORCE)
set(HITLS_BSL_SAL_STR                                  ON CACHE BOOL "" FORCE)
set(HITLS_BSL_SAL_THREAD                               ON CACHE BOOL "" FORCE)
set(HITLS_BSL_SAL_TIME                                 ON CACHE BOOL "" FORCE)
set(HITLS_BSL_TLV                                      ON CACHE BOOL "" FORCE)
set(HITLS_BSL_UIO                                      ON CACHE BOOL "" FORCE)

# Crypto modules
set(HITLS_CRYPTO_BN                                    ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_CIPHER                                ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_CODECSKEY                             ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_DRBG                                  ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_EAL                                   ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_EALINIT                               ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_ENTROPY                               ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_HPKE                                  ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_KDF                                   ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_MAC                                   ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_MD                                    ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_MODES                                 ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO_PKEY                                  ON CACHE BOOL "" FORCE)

# TLS modules
set(HITLS_TLS_FEATURE_SESSION                          ON CACHE BOOL "" FORCE)
set(HITLS_TLS_CALLBACK_CERT                            ON CACHE BOOL "" FORCE)
set(HITLS_TLS_CALLBACK_CRYPT                           ON CACHE BOOL "" FORCE)
set(HITLS_TLS_CONFIG                                   ON CACHE BOOL "" FORCE)
set(HITLS_TLS_HOST                                     ON CACHE BOOL "" FORCE)
set(HITLS_TLS_MAINTAIN                                 ON CACHE BOOL "" FORCE)
set(HITLS_TLS_PROTO                                    ON CACHE BOOL "" FORCE)
set(HITLS_TLS_PROTO_VERSION                            ON CACHE BOOL "" FORCE)
set(HITLS_TLS_SUITE                                    ON CACHE BOOL "" FORCE)
set(HITLS_TLS_SUITE_AUTH                               ON CACHE BOOL "" FORCE)
set(HITLS_TLS_SUITE_CIPHER                             ON CACHE BOOL "" FORCE)
set(HITLS_TLS_SUITE_KX                                 ON CACHE BOOL "" FORCE)

# PKI modules
set(HITLS_PKI_INFO                                     ON CACHE BOOL "" FORCE)
set(HITLS_PKI_PKCS12                                   ON CACHE BOOL "" FORCE)
set(HITLS_PKI_X509                                     ON CACHE BOOL "" FORCE)
