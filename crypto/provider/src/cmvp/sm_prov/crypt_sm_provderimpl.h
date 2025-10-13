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
 * @brief sm provider impl
 */

#ifndef CRYPT_EAL_SM_PROVIDERIMPL_H
#define CRYPT_EAL_SM_PROVIDERIMPL_H

#ifdef HITLS_CRYPTO_CMVP_SM

#include "crypt_eal_implprovider.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct {
    int32_t algId;
    void *ctx;
    void *provCtx;
} CRYPT_Sm_Pkey_Ctx;


extern const CRYPT_EAL_Func g_smMdSm3[];

extern const CRYPT_EAL_Func g_smKdfPBKdf2[];
extern const CRYPT_EAL_Func g_smKdfKdfTLS12[];

extern const CRYPT_EAL_Func g_smKeyMgmtSm2[];

extern const CRYPT_EAL_Func g_smExchSm2[];

extern const CRYPT_EAL_Func g_smAsymCipherSm2[];

extern const CRYPT_EAL_Func g_smSignSm2[];

extern const CRYPT_EAL_Func g_smMacHmac[];
extern const CRYPT_EAL_Func g_smMacCbcMac[];

extern const CRYPT_EAL_Func g_smRand[];

extern const CRYPT_EAL_Func g_smCbc[];
extern const CRYPT_EAL_Func g_smCfb[];
extern const CRYPT_EAL_Func g_smCtr[];
extern const CRYPT_EAL_Func g_smEcb[];
extern const CRYPT_EAL_Func g_smGcm[];
extern const CRYPT_EAL_Func g_smOfb[];
extern const CRYPT_EAL_Func g_smXts[];

extern const CRYPT_EAL_Func g_smSelftest[];

#ifdef HITLS_CRYPTO_KEY_DECODE_CHAIN
extern const CRYPT_EAL_Func g_smEalPrvP8Enc2P8[];
extern const CRYPT_EAL_Func g_smEalPem2Der[];
extern const CRYPT_EAL_Func g_smEalSm2PrvDer2Key[];
extern const CRYPT_EAL_Func g_smEalP8Der2Sm2Key[];
extern const CRYPT_EAL_Func g_smEalSubPubKeyDer2Sm2Key[];
extern const CRYPT_EAL_Func g_smEalSubPubKeyWithoutSeqDer2Sm2Key[];
extern const CRYPT_EAL_Func g_smEalLowKeyObject2PkeyObject[];
#endif // HITLS_CRYPTO_KEY_DECODE_CHAIN

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* HITLS_CRYPTO_CMVP_SM */
#endif /* CRYPT_EAL_SM_PROVIDERIMPL_H */