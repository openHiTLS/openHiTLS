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

#ifndef CMVP_INTEGRITY_HMAC_H
#define CMVP_INTEGRITY_HMAC_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_CMVP_ISO19790) || defined(HITLS_CRYPTO_CMVP_SM) || defined(HITLS_CRYPTO_CMVP_FIPS)

#include <stdbool.h>
#include "crypt_algid.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// When the HMAC is used to perform integrity verification, a failure message is returned,
// and the module does not enter the error state.
bool CMVP_IntegrityHmac(void *libCtx, const char *attrName, const char *libPath, CRYPT_MAC_AlgId id);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif /* HITLS_CRYPTO_CMVP_ISO19790 || HITLS_CRYPTO_CMVP_SM || HITLS_CRYPTO_CMVP_FIPS */
#endif /* CMVP_INTEGRITY_HMAC_H */
