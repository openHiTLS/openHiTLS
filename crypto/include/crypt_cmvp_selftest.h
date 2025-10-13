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

#ifndef CRYPT_CMVP_SELFTEST_H
#define CRYPT_CMVP_SELFTEST_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_CMVP_ISO19790) || defined(HITLS_CRYPTO_CMVP_SM) || defined(HITLS_CRYPTO_CMVP_FIPS)

#include <stdint.h>
#include "crypt_cmvp.h"
#include "crypt_types.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_md.h"
#include "crypt_eal_mac.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_kdf.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

bool CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_AlgId id);

bool CRYPT_CMVP_SelftestProviderDrbg(void *libCtx, const char *attrName, CRYPT_RAND_AlgId id);

bool CRYPT_CMVP_SelftestMd(CRYPT_MD_AlgId id);

bool CRYPT_CMVP_SelftestProviderMd(void *libCtx, const char *attrName, CRYPT_MD_AlgId id);

bool CRYPT_CMVP_SelftestRsa(void);

bool CRYPT_CMVP_SelftestProviderRsa(void *libCtx, const char *attrName);

bool CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AlgId id);

bool CRYPT_CMVP_SelftestProviderCipher(void *libCtx, const char *attrName, CRYPT_CIPHER_AlgId id);

bool CRYPT_CMVP_SelftestChacha20poly1305(void);

bool CRYPT_CMVP_SelftestProviderChacha20poly1305(void *libCtx, const char *attrName);

bool CRYPT_CMVP_SelftestDh(void);

bool CRYPT_CMVP_SelftestProviderDh(void *libCtx, const char *attrName);

bool CRYPT_CMVP_SelftestDsa(void);

bool CRYPT_CMVP_SelftestProviderDsa(void *libCtx, const char *attrName);

bool CRYPT_CMVP_SelftestEd25519(void);

bool CRYPT_CMVP_SelftestProviderEd25519(void *libCtx, const char *attrName);

bool CRYPT_CMVP_SelftestHkdf(void);

bool CRYPT_CMVP_SelftestProviderHkdf(void *libCtx, const char *attrName);

bool CRYPT_CMVP_SelftestMac(CRYPT_MAC_AlgId id);

bool CRYPT_CMVP_SelftestProviderMac(void *libCtx, const char *attrName, CRYPT_MAC_AlgId id);

bool CRYPT_CMVP_SelftestPbkdf2(CRYPT_MAC_AlgId id);

bool CRYPT_CMVP_SelftestProviderPbkdf2(void *libCtx, const char *attrName, CRYPT_MAC_AlgId id);

bool CRYPT_CMVP_SelftestScrypt(void);

bool CRYPT_CMVP_SelftestProviderScrypt(void *libCtx, const char *attrName);

bool CRYPT_CMVP_SelftestKdfTls12(void);

bool CRYPT_CMVP_SelftestProviderKdfTls12(void *libCtx, const char *attrName);

bool CRYPT_CMVP_SelftestX25519(void);

bool CRYPT_CMVP_SelftestProviderX25519(void *libCtx, const char *attrName);

bool CRYPT_CMVP_SelftestEcdsa(void);

bool CRYPT_CMVP_SelftestProviderEcdsa(void *libCtx, const char *attrName);

bool CRYPT_CMVP_SelftestEcdh(void);

bool CRYPT_CMVP_SelftestProviderEcdh(void *libCtx, const char *attrName);

bool CRYPT_CMVP_SelftestSM2(void);

bool CRYPT_CMVP_SelftestProviderSM2(void *libCtx, const char *attrName);

bool CRYPT_CMVP_SelftestMlkemEncapsDecaps(void);

bool CRYPT_CMVP_SelftestProviderMlkemEncapsDecaps(void *libCtx, const char *attrName);

bool CRYPT_CMVP_SelftestMldsaSignVerify(void);

bool CRYPT_CMVP_SelftestProviderMldsaSignVerify(void *libCtx, const char *attrName);

bool CRYPT_CMVP_SelftestSlhdsaSignVerify(void);

bool CRYPT_CMVP_SelftestProviderSlhdsaSignVerify(void *libCtx, const char *attrName);

bool CRYPT_CMVP_SelftestPkeyPct(void *ctx, int32_t algId);

int32_t CRYPT_CMVP_RandomnessTest(const uint8_t *data, const uint32_t len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* HITLS_CRYPTO_CMVP_ISO19790 || HITLS_CRYPTO_CMVP_SM || HITLS_CRYPTO_CMVP_FIPS */
#endif /* CRYPT_CMVP_SELFTEST_H */
