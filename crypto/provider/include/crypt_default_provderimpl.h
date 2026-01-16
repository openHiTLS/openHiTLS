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

extern const CRYPT_EAL_Func g_defEalMdMd5[];
extern const CRYPT_EAL_Func g_defEalMdSha1[];
extern const CRYPT_EAL_Func g_defEalMdSha224[];
extern const CRYPT_EAL_Func g_defEalMdSha256[];
extern const CRYPT_EAL_Func g_defEalMdSha384[];
extern const CRYPT_EAL_Func g_defEalMdSha512[];
extern const CRYPT_EAL_Func g_defEalMdSha3224[];
extern const CRYPT_EAL_Func g_defEalMdSha3256[];
extern const CRYPT_EAL_Func g_defEalMdSha3384[];
extern const CRYPT_EAL_Func g_defEalMdSha3512[];
extern const CRYPT_EAL_Func g_defEalMdShake512[];
extern const CRYPT_EAL_Func g_defEalMdShake128[];
extern const CRYPT_EAL_Func g_defEalMdShake256[];
extern const CRYPT_EAL_Func g_defEalMdSm3[];

extern const CRYPT_EAL_Func g_defEalKdfScrypt[];
extern const CRYPT_EAL_Func g_defEalKdfPBKdf2[];
extern const CRYPT_EAL_Func g_defEalKdfKdfTLS12[];
extern const CRYPT_EAL_Func g_defEalKdfHkdf[];

extern const CRYPT_EAL_Func g_defEalKeyMgmtDsa[];
extern const CRYPT_EAL_Func g_defEalKeyMgmtEd25519[];
extern const CRYPT_EAL_Func g_defEalKeyMgmtX25519[];
extern const CRYPT_EAL_Func g_defEalKeyMgmtRsa[];
extern const CRYPT_EAL_Func g_defEalKeyMgmtDh[];
extern const CRYPT_EAL_Func g_defEalKeyMgmtEcdsa[];
extern const CRYPT_EAL_Func g_defEalKeyMgmtEcdh[];
extern const CRYPT_EAL_Func g_defEalKeyMgmtSm2[];
extern const CRYPT_EAL_Func g_defEalKeyMgmtPaillier[];
extern const CRYPT_EAL_Func g_defEalKeyMgmtSlhDsa[];
extern const CRYPT_EAL_Func g_defEalKeyMgmtElGamal[];
extern const CRYPT_EAL_Func g_defEalKeyMgmtMlKem[];
extern const CRYPT_EAL_Func g_defEalKeyMgmtMlDsa[];
extern const CRYPT_EAL_Func g_defEalKeyMgmtHybridKem[];

extern const CRYPT_EAL_Func g_defEalExchX25519[];
extern const CRYPT_EAL_Func g_defEalExchDh[];
extern const CRYPT_EAL_Func g_defEalExchEcdh[];
extern const CRYPT_EAL_Func g_defEalExchSm2[];


extern const CRYPT_EAL_Func g_defEalAsymCipherRsa[];
extern const CRYPT_EAL_Func g_defEalAsymCipherSm2[];
extern const CRYPT_EAL_Func g_defEalAsymCipherPaillier[];
extern const CRYPT_EAL_Func g_defEalAsymCipherElGamal[];

extern const CRYPT_EAL_Func g_defEalSignDsa[];
extern const CRYPT_EAL_Func g_defEalSignEd25519[];
extern const CRYPT_EAL_Func g_defEalSignRsa[];
extern const CRYPT_EAL_Func g_defEalSignEcdsa[];
extern const CRYPT_EAL_Func g_defEalSignSm2[];
extern const CRYPT_EAL_Func g_defEalSignMlDsa[];
extern const CRYPT_EAL_Func g_defEalMacHmac[];
extern const CRYPT_EAL_Func g_defEalSignSlhDsa[];
extern const CRYPT_EAL_Func g_defEalMacCmac[];
extern const CRYPT_EAL_Func g_defEalMacCbcMac[];
extern const CRYPT_EAL_Func g_defEalMacGmac[];
extern const CRYPT_EAL_Func g_defEalMacSiphash[];

extern const CRYPT_EAL_Func g_defEalRand[];

extern const CRYPT_EAL_Func g_defEalCbc[];
extern const CRYPT_EAL_Func g_defEalCcm[];
extern const CRYPT_EAL_Func g_defEalCfb[];
extern const CRYPT_EAL_Func g_defEalChaCha[];
extern const CRYPT_EAL_Func g_defEalCtr[];
extern const CRYPT_EAL_Func g_defEalEcb[];
extern const CRYPT_EAL_Func g_defEalGcm[];
extern const CRYPT_EAL_Func g_defEalOfb[];
extern const CRYPT_EAL_Func g_defEalXts[];
extern const CRYPT_EAL_Func g_defEalWrap[];
extern const CRYPT_EAL_Func g_defEalMlKem[];
extern const CRYPT_EAL_Func g_defEalHybridKeyKem[];

extern const CRYPT_EAL_Func g_defEalPrvP8Enc2P8[];
extern const CRYPT_EAL_Func g_defEalPem2Der[];
extern const CRYPT_EAL_Func g_defEalRsaPrvDer2Key[];
extern const CRYPT_EAL_Func g_defEalEcdsaPrvDer2Key[];
extern const CRYPT_EAL_Func g_defEalSm2PrvDer2Key[];
extern const CRYPT_EAL_Func g_defEalP8Der2RsaKey[];
extern const CRYPT_EAL_Func g_defEalP8Der2EcdsaKey[];
extern const CRYPT_EAL_Func g_defEalP8Der2Sm2Key[];
extern const CRYPT_EAL_Func g_defEalP8Der2Ed25519Key[];
extern const CRYPT_EAL_Func g_defEalP8Der2X25519Key[];
extern const CRYPT_EAL_Func g_defEalSubPubKeyDer2RsaKey[];
extern const CRYPT_EAL_Func g_defEalSubPubKeyDer2EcdsaKey[];
extern const CRYPT_EAL_Func g_defEalSubPubKeyDer2Sm2Key[];
extern const CRYPT_EAL_Func g_defEalSubPubKeyDer2Ed25519Key[];
extern const CRYPT_EAL_Func g_defEalSubPubKeyDer2X25519Key[];
extern const CRYPT_EAL_Func g_defEalSubPubKeyWithoutSeqDer2RsaKey[];
extern const CRYPT_EAL_Func g_defEalSubPubKeyWithoutSeqDer2EcdsaKey[];
extern const CRYPT_EAL_Func g_defEalSubPubKeyWithoutSeqDer2Sm2Key[];
extern const CRYPT_EAL_Func g_defEalSubPubKeyWithoutSeqDer2Ed25519Key[];
extern const CRYPT_EAL_Func g_defEalSubPubKeyWithoutSeqDer2X25519Key[];
extern const CRYPT_EAL_Func g_defEalLowKeyObject2PkeyObject[];
extern const CRYPT_EAL_Func g_defEalRsaPubDer2Key[];
#ifdef __cplusplus
}
#endif // __cplusplus

#endif /* HITLS_CRYPTO_PROVIDER */
#endif // CRYPT_EAL_DEFAULT_PROVIDERIMPL_H