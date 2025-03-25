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
#endif

#ifdef HITLS_PKI_X509_CRT
    #ifndef HITLS_PKI_X509_CRT_GEN
        #define HITLS_PKI_X509_CRT_GEN
    #endif
    #ifndef HITLS_PKI_X509_CRT_PARSE
        #define HITLS_PKI_X509_CRT_PARSE
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

#ifdef HITLS_PKI_X509_CRL
    #ifndef HITLS_PKI_X509_CRL_GEN
        #define HITLS_PKI_X509_CRL_GEN
    #endif
    #ifndef HITLS_PKI_X509_CRL_PARSE
        #define HITLS_PKI_X509_CRL_PARSE
    #endif
#endif

#ifdef HITLS_PKI_PKCS12
    #ifndef HITLS_PKI_PKCS12_GEN
        #define HITLS_PKI_PKCS12_GEN
    #endif
    #ifndef HITLS_PKI_PKCS12_PARSE
        #define HITLS_PKI_PKCS12_PARSE
    #endif
#endif

#endif /* HITLS_CONFIG_LAYER_PKI_H */
