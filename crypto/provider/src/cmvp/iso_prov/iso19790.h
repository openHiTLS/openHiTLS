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

#ifndef ISO19790_H
#define ISO19790_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CMVP_ISO19790

#include <stdint.h>
#include "crypt_cmvp.h"
#include "crypt_types.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_md.h"
#include "crypt_eal_mac.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_kdf.h"

// asym alg param check
bool ISO19790_AsymParamCheck(CRYPT_PKEY_AlgId id, const CRYPT_EAL_PkeyC2Data *data);

// mac alg param check
bool ISO19790_MacParamCheck(CRYPT_MAC_AlgId id, uint32_t keyLen);

// kdfTls12 alg param check
bool ISO19790_KdfTls12ParamCheck(CRYPT_MAC_AlgId id, uint32_t keyLen);

// pbkdf alg param check
bool ISO19790_PbkdfParamCheck(const CRYPT_EAL_Pbkdf2Param *param);

// hkdf alg param check
bool ISO19790_HkdfParamCheck(CRYPT_MAC_AlgId id, uint32_t keyLen);

bool ISO19790_CipherKat(void *libCtx, const char *attrName);

bool ISO19790_MdKat(void *libCtx, const char *attrName);

bool ISO19790_MacKat(void *libCtx, const char *attrName);

bool ISO19790_DrbgKat(void *libCtx, const char *attrName);

bool ISO19790_KdfKat(void *libCtx, const char *attrName);

bool ISO19790_PkeyKat(void *libCtx, const char *attrName);

#endif /* HITLS_CRYPTO_CMVP_ISO19790 */
#endif /* ISO19790_H */
