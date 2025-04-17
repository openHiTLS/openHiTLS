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

/**
 * @defgroup crypt_eal_provider
 * @ingroup crypt
 * @brief default provider impl
 */

#ifndef CRYPT_EAL_DEFAULT_PROVIDERIMPL_H
#define CRYPT_EAL_DEFAULT_PROVIDERIMPL_H

#ifdef HITLS_CRYPTO_PROVIDER

#include "crypt_eal_implprovider.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

extern const CRYPT_EAL_Func g_defMdMd5[];
extern const CRYPT_EAL_Func g_defMdSha1[];
extern const CRYPT_EAL_Func g_defMdSha224[];
extern const CRYPT_EAL_Func g_defMdSha256[];
extern const CRYPT_EAL_Func g_defMdSha384[];
extern const CRYPT_EAL_Func g_defMdSha512[];
extern const CRYPT_EAL_Func g_defMdSha3224[];
extern const CRYPT_EAL_Func g_defMdSha3256[];
extern const CRYPT_EAL_Func g_defMdSha3384[];
extern const CRYPT_EAL_Func g_defMdSha3512[];
extern const CRYPT_EAL_Func g_defMdShake512[];
extern const CRYPT_EAL_Func g_defMdShake128[];
extern const CRYPT_EAL_Func g_defMdShake256[];
extern const CRYPT_EAL_Func g_defMdSm3[];

extern const CRYPT_EAL_Func g_defKdfScrypt[];
extern const CRYPT_EAL_Func g_defKdfPBKdf2[];
extern const CRYPT_EAL_Func g_defKdfKdfTLS12[];
extern const CRYPT_EAL_Func g_defKdfHkdf[];

extern const CRYPT_EAL_Func g_defKeyMgmtDsa[];
extern const CRYPT_EAL_Func g_defKeyMgmtEd25519[];
extern const CRYPT_EAL_Func g_defKeyMgmtX25519[];
extern const CRYPT_EAL_Func g_defKeyMgmtRsa[];
extern const CRYPT_EAL_Func g_defKeyMgmtDh[];
extern const CRYPT_EAL_Func g_defKeyMgmtEcdsa[];
extern const CRYPT_EAL_Func g_defKeyMgmtEcdh[];
extern const CRYPT_EAL_Func g_defKeyMgmtSm2[];
extern const CRYPT_EAL_Func g_defKeyMgmtPaillier[];
extern const CRYPT_EAL_Func g_defKeyMgmtSlhDsa[];
extern const CRYPT_EAL_Func g_defKeyMgmtElGamal[];
extern const CRYPT_EAL_Func g_defKeyMgmtMlKem[];
extern const CRYPT_EAL_Func g_defKeyMgmtMlDsa[];
extern const CRYPT_EAL_Func g_defKeyMgmtHybridKem[];

extern const CRYPT_EAL_Func g_defExchX25519[];
extern const CRYPT_EAL_Func g_defExchDh[];
extern const CRYPT_EAL_Func g_defExchEcdh[];
extern const CRYPT_EAL_Func g_defExchSm2[];


extern const CRYPT_EAL_Func g_defAsymCipherRsa[];
extern const CRYPT_EAL_Func g_defAsymCipherSm2[];
extern const CRYPT_EAL_Func g_defAsymCipherPaillier[];
extern const CRYPT_EAL_Func g_defAsymCipherElGamal[];

extern const CRYPT_EAL_Func g_defSignDsa[];
extern const CRYPT_EAL_Func g_defSignEd25519[];
extern const CRYPT_EAL_Func g_defSignRsa[];
extern const CRYPT_EAL_Func g_defSignEcdsa[];
extern const CRYPT_EAL_Func g_defSignSm2[];
extern const CRYPT_EAL_Func g_defSignMlDsa[];
extern const CRYPT_EAL_Func g_defMacHmac[];
extern const CRYPT_EAL_Func g_defSignSlhDsa[];
extern const CRYPT_EAL_Func g_defMacCmac[];
extern const CRYPT_EAL_Func g_defMacCbcMac[];
extern const CRYPT_EAL_Func g_defMacGmac[];
extern const CRYPT_EAL_Func g_defMacSiphash[];

extern const CRYPT_EAL_Func g_defRand[];

extern const CRYPT_EAL_Func g_defCbc[];
extern const CRYPT_EAL_Func g_defCcm[];
extern const CRYPT_EAL_Func g_defCfb[];
extern const CRYPT_EAL_Func g_defChaCha[];
extern const CRYPT_EAL_Func g_defCtr[];
extern const CRYPT_EAL_Func g_defEcb[];
extern const CRYPT_EAL_Func g_defGcm[];
extern const CRYPT_EAL_Func g_defOfb[];
extern const CRYPT_EAL_Func g_defXts[];
extern const CRYPT_EAL_Func g_defMlKem[];
extern const CRYPT_EAL_Func g_defHybridKeyKem[];

#ifdef __cplusplus
}
#endif // __cplusplus

#endif /* HITLS_CRYPTO_PROVIDER */
#endif // CRYPT_EAL_DEFAULT_PROVIDERIMPL_H