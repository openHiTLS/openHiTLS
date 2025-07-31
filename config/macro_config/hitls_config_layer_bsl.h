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
/* Derivation of configuration features.
 * The derivation type (rule) and sequence are as follows:
 * 1. Parent features derive child features.
 * 2. Derive the features of dependencies.
 *    For example, if feature a depends on features b and c, you need to derive features b and c.
 * 3. Child features derive parent features.
 *    The high-level interfaces of the crypto module is controlled by the parent feature macro,
 *    if there is no parent feature, such interfaces will be unavailable.
 */

#ifndef HITLS_CONFIG_LAYER_BSL_H
#define HITLS_CONFIG_LAYER_BSL_H

/* BSL_INIT */
#if defined(HITLS_CRYPTO_EAL) && !defined(HITLS_BSL_INIT)
    #define HITLS_BSL_INIT
#endif

#if defined(HITLS_BSL_INIT) && !defined(HITLS_BSL_ERR)
    #define HITLS_BSL_ERR
#endif

#if defined(HITLS_BSL_UI) && !defined(HITLS_BSL_SAL_FILE)
    #define HITLS_BSL_SAL_FILE
#endif

#ifdef HITLS_BSL_CONF
    #ifndef HITLS_BSL_LIST
        #define HITLS_BSL_LIST
    #endif
    #ifndef HITLS_BSL_UIO_FILE
        #define HITLS_BSL_UIO_FILE
    #endif
#endif

/* BSL_UIO */
/* Derive the child-features of uio. */
#ifdef HITLS_BSL_UIO
    #ifndef HITLS_BSL_UIO_PLT
        #define HITLS_BSL_UIO_PLT
    #endif
    #ifndef HITLS_BSL_UIO_BUFFER
        #define HITLS_BSL_UIO_BUFFER
    #endif
    #ifndef HITLS_BSL_UIO_SCTP
        #define HITLS_BSL_UIO_SCTP
    #endif
    #ifndef HITLS_BSL_UIO_UDP
        #define HITLS_BSL_UIO_UDP
    #endif
    #ifndef HITLS_BSL_UIO_TCP
        #define HITLS_BSL_UIO_TCP
    #endif
    #ifndef HITLS_BSL_UIO_MEM
        #define HITLS_BSL_UIO_MEM
    #endif
    #ifndef HITLS_BSL_UIO_FILE
        #define HITLS_BSL_UIO_FILE
    #endif
#endif

#if defined(HITLS_BSL_UIO_FILE) && !defined(HITLS_BSL_SAL_FILE)
    #define HITLS_BSL_SAL_FILE
#endif

/* Derive the child-features of uio mem. */
#if defined(HITLS_BSL_UIO_MEM)
    #ifndef HITLS_BSL_SAL_MEM
        #define HITLS_BSL_SAL_MEM
    #endif
    #ifndef HITLS_BSL_BUFFER
        #define HITLS_BSL_BUFFER
    #endif
#endif

/* Derive the dependency features of uio_tcp and uio_sctp. */
#if defined(HITLS_BSL_UIO_TCP) || defined(HITLS_BSL_UIO_SCTP)
    #ifndef HITLS_BSL_SAL_NET
        #define HITLS_BSL_SAL_NET
    #endif
#endif

/* Derive parent feature from child features. */
#if defined(HITLS_BSL_UIO_BUFFER) || defined(HITLS_BSL_UIO_SCTP) || defined(HITLS_BSL_UIO_TCP) || \
    defined(HITLS_BSL_UIO_MEM) || defined(HITLS_BSL_UIO_FILE)
    #ifndef HITLS_BSL_UIO_PLT
        #define HITLS_BSL_UIO_PLT
    #endif
#endif

#ifdef HITLS_BSL_PEM
    #ifndef HITLS_BSL_BASE64
        #define HITLS_BSL_BASE64
    #endif
#endif

#ifdef HITLS_BSL_ASN1
    #ifndef HITLS_BSL_SAL_TIME
        #define HITLS_BSL_SAL_TIME
    #endif
#endif

#endif /* HITLS_CONFIG_LAYER_BSL_H */