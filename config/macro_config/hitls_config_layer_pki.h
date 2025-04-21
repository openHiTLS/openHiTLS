/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef HITLS_CONFIG_LAYER_PKI_H
#define HITLS_CONFIG_LAYER_PKI_H

#ifdef HITLS_PKI_PKCS12
    #ifndef HITLS_PKI_PKCS12_GEN
        #define HITLS_PKI_PKCS12_GEN
    #endif
    #ifndef HITLS_PKI_PKCS12_PARSE
        #define HITLS_PKI_PKCS12_PARSE
    #endif
#endif

#ifdef HITLS_PKI_PKCS12_GEN
    #ifndef HITLS_PKI_X509_CRT_GEN
        #define HITLS_PKI_X509_CRT_GEN
    #endif
    #ifndef HITLS_PKI_X509_CRT_PARSE
        #define HITLS_PKI_X509_CRT_PARSE
    #endif
    #ifndef HITLS_CRYPTO_KEY_ENCODE
        #define HITLS_CRYPTO_KEY_ENCODE
    #endif
#endif

#ifdef HITLS_PKI_PKCS12_PARSE
    #ifndef HITLS_PKI_X509_CRT_PARSE
        #define HITLS_PKI_X509_CRT_PARSE
    #endif
    #ifndef HITLS_CRYPTO_KEY_DECODE
        #define HITLS_CRYPTO_KEY_DECODE
    #endif
#endif

#if defined(HITLS_PKI_PKCS12_GEN) || defined(HITLS_PKI_PKCS12_PARSE)
    #ifndef HITLS_PKI_PKCS12
        #define HITLS_PKI_PKCS12
    #endif
    #ifndef HITLS_CRYPTO_KEY_EPKI
        #define HITLS_CRYPTO_KEY_EPKI
    #endif
#endif

#ifdef HITLS_PKI_X509
    #ifndef HITLS_PKI_X509_CRT
        #define HITLS_PKI_X509_CRT
    #endif
    #ifndef HITLS_PKI_X509_CSR
        #define HITLS_PKI_X509_CSR
    #endif
    #ifndef HITLS_PKI_X509_CRL
        #define HITLS_PKI_X509_CRL
    #endif
    #ifndef HITLS_PKI_X509_VFY
        #define HITLS_PKI_X509_VFY
    #endif
#endif

#ifdef HITLS_PKI_X509_VFY
    #ifndef HITLS_PKI_X509_CRT_PARSE
        #define HITLS_PKI_X509_CRT_PARSE
    #endif
    #ifndef HITLS_PKI_X509_CRL_PARSE
        #define HITLS_PKI_X509_CRL_PARSE
    #endif
#endif

#ifdef HITLS_PKI_X509_CRT
    #ifndef HITLS_PKI_X509_CRT_GEN
        #define HITLS_PKI_X509_CRT_GEN
    #endif
    #ifndef HITLS_PKI_X509_CRT_PARSE
        #define HITLS_PKI_X509_CRT_PARSE
    #endif
#endif

#if defined(HITLS_PKI_X509_CRT_GEN) || defined(HITLS_PKI_X509_CRT_PARSE)
    #ifndef HITLS_PKI_X509_CRT
        #define HITLS_PKI_X509_CRT
    #endif
#endif

#ifdef HITLS_PKI_X509_CSR
    #ifndef HITLS_PKI_X509_CSR_GEN
        #define HITLS_PKI_X509_CSR_GEN
    #endif
    #ifndef HITLS_PKI_X509_CSR_PARSE
        #define HITLS_PKI_X509_CSR_PARSE
    #endif
#endif

#if defined(HITLS_PKI_X509_CSR_GEN) || defined(HITLS_PKI_X509_CSR_PARSE)
    #ifndef HITLS_PKI_X509_CSR
        #define HITLS_PKI_X509_CSR
    #endif
#endif

#ifdef HITLS_PKI_X509_CRL
    #ifndef HITLS_PKI_X509_CRL_GEN
        #define HITLS_PKI_X509_CRL_GEN
    #endif
    #ifndef HITLS_PKI_X509_CRL_PARSE
        #define HITLS_PKI_X509_CRL_PARSE
    #endif
#endif

#if defined(HITLS_PKI_X509_CRL_GEN) || defined(HITLS_PKI_X509_CRL_PARSE)
    #ifndef HITLS_PKI_X509_CRL
        #define HITLS_PKI_X509_CRL
    #endif
#endif

#if defined(HITLS_PKI_X509_CRT) || defined(HITLS_PKI_X509_CSR) || defined(HITLS_PKI_X509_CRL) || \
    defined(HITLS_PKI_X509_VFY)
    #ifndef HITLS_PKI_X509
        #define HITLS_PKI_X509
    #endif
#endif

#if defined(HITLS_PKI_X509_CRT_GEN) || defined(HITLS_PKI_X509_CSR_GEN) || defined(HITLS_PKI_X509_CRL_GEN) || \
    defined(HITLS_PKI_PKCS12_GEN)
    #ifndef HITLS_CRYPTO_KEY_ENCODE
        #define HITLS_CRYPTO_KEY_ENCODE
    #endif
#endif

#if defined(HITLS_PKI_X509_CRT_PARSE) || defined(HITLS_PKI_X509_CSR_PARSE) || defined(HITLS_PKI_X509_CRL_PARSE) || \
    defined(HITLS_PKI_PKCS12_PARSE)
    #ifndef HITLS_CRYPTO_KEY_DECODE
        #define HITLS_CRYPTO_KEY_DECODE
    #endif
#endif

#ifdef HITLS_PKI_INFO
    #ifndef HITLS_BSL_UIO_PLT
        #define HITLS_BSL_UIO_PLT
    #endif
#endif

// Common dependencies
#ifndef HITLS_BSL_LIST
    #define HITLS_BSL_LIST
#endif
#ifndef HITLS_BSL_OBJ
    #define HITLS_BSL_OBJ
#endif
#ifndef HITLS_BSL_ASN1
    #define HITLS_BSL_ASN1
#endif

#endif /* HITLS_CONFIG_LAYER_PKI_H */
