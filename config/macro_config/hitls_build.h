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

#ifndef HITLS_BUILD_H
#define HITLS_BUILD_H

#ifdef HITLS_TLS
#include "hitls_config_layer_tls.h"
#endif

#ifdef HITLS_PKI
#include "hitls_config_layer_pki.h"
#endif

#ifdef HITLS_CRYPTO
#include "hitls_config_layer_crypto.h"
#endif

#include "hitls_config_layer_bsl.h"

#include "hitls_config_check.h"

#endif /* HITLS_BUILD_H */
