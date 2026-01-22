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

#ifndef NODFX_CONFIG_H
#define NODFX_CONFIG_H

#ifdef HITLS_TLS_FEATURE_EXTENDED_MASTER_SECRET
    #undef HITLS_TLS_FEATURE_EXTENDED_MASTER_SECRET
#endif

#ifdef HITLS_TLS_PROTO_CLOSE_STATE
    #undef HITLS_TLS_PROTO_CLOSE_STATE
#endif

#ifdef HITLS_TLS_PROTO_DFX
    #undef HITLS_TLS_PROTO_DFX
#endif

#ifdef HITLS_TLS_PROTO_DFX_CHECK
    #undef HITLS_TLS_PROTO_DFX_CHECK
#endif

#ifdef HITLS_TLS_PROTO_DFX_INFO
    #undef HITLS_TLS_PROTO_DFX_INFO
#endif

#ifdef HITLS_TLS_PROTO_DFX_ALERT_NUMBER
    #undef HITLS_TLS_PROTO_DFX_ALERT_NUMBER
#endif

#ifdef HITLS_TLS_PROTO_DFX_SERVER_PREFER
    #undef HITLS_TLS_PROTO_DFX_SERVER_PREFER
#endif
#endif /* NODFX_CONFIG_H */