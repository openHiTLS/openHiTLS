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
 * @brief iso19790 provider impl
 */

#ifndef CRYPT_EAL_ISO_PROVIDERIMPL_H
#define CRYPT_EAL_ISO_PROVIDERIMPL_H

#ifdef HITLS_CRYPTO_CMVP_ISO19790

#include "crypt_eal_implprovider.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct {
    int32_t algId;
    void *ctx;
    void *provCtx;
} CRYPT_Iso_Pkey_Ctx;

extern const CRYPT_EAL_Func g_isoMdSha1[];
extern const CRYPT_EAL_Func g_isoMdSha224[];
extern const CRYPT_EAL_Func g_isoMdSha256[];
extern const CRYPT_EAL_Func g_isoMdSha384[];
extern const CRYPT_EAL_Func g_isoMdSha512[];
extern const CRYPT_EAL_Func g_isoMdSha3224[];
extern const CRYPT_EAL_Func g_isoMdSha3256[];
extern const CRYPT_EAL_Func g_isoMdSha3384[];
extern const CRYPT_EAL_Func g_isoMdSha3512[];
extern const CRYPT_EAL_Func g_isoMdShake128[];
extern const CRYPT_EAL_Func g_isoMdShake256[];
extern const CRYPT_EAL_Func g_isoMdSm3[];

extern const CRYPT_EAL_Func g_isoKdfScrypt[];
extern const CRYPT_EAL_Func g_isoKdfPBKdf2[];
extern const CRYPT_EAL_Func g_isoKdfKdfTLS12[];
extern const CRYPT_EAL_Func g_isoKdfHkdf[];

extern const CRYPT_EAL_Func g_isoKeyMgmtDsa[];
extern const CRYPT_EAL_Func g_isoKeyMgmtEd25519[];
extern const CRYPT_EAL_Func g_isoKeyMgmtX25519[];
extern const CRYPT_EAL_Func g_isoKeyMgmtRsa[];
extern const CRYPT_EAL_Func g_isoKeyMgmtDh[];
extern const CRYPT_EAL_Func g_isoKeyMgmtEcdsa[];
extern const CRYPT_EAL_Func g_isoKeyMgmtEcdh[];
extern const CRYPT_EAL_Func g_isoKeyMgmtSm2[];

extern const CRYPT_EAL_Func g_isoExchX25519[];
extern const CRYPT_EAL_Func g_isoExchDh[];
extern const CRYPT_EAL_Func g_isoExchEcdh[];
extern const CRYPT_EAL_Func g_isoExchSm2[];


extern const CRYPT_EAL_Func g_isoAsymCipherRsa[];
extern const CRYPT_EAL_Func g_isoAsymCipherSm2[];

extern const CRYPT_EAL_Func g_isoSignDsa[];
extern const CRYPT_EAL_Func g_isoSignEd25519[];
extern const CRYPT_EAL_Func g_isoSignRsa[];
extern const CRYPT_EAL_Func g_isoSignEcdsa[];
extern const CRYPT_EAL_Func g_isoSignSm2[];
extern const CRYPT_EAL_Func g_isoMacHmac[];
extern const CRYPT_EAL_Func g_isoMacCmac[];
extern const CRYPT_EAL_Func g_isoMacGmac[];

extern const CRYPT_EAL_Func g_isoRand[];

extern const CRYPT_EAL_Func g_isoCbc[];
extern const CRYPT_EAL_Func g_isoCcm[];
extern const CRYPT_EAL_Func g_isoCfb[];
extern const CRYPT_EAL_Func g_isoChaCha[];
extern const CRYPT_EAL_Func g_isoCtr[];
extern const CRYPT_EAL_Func g_isoEcb[];
extern const CRYPT_EAL_Func g_isoGcm[];
extern const CRYPT_EAL_Func g_isoOfb[];
extern const CRYPT_EAL_Func g_isoXts[];

extern const CRYPT_EAL_Func g_isoSelftest[];

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* HITLS_CRYPTO_CMVP_ISO19790 */
#endif /* CRYPT_EAL_ISO_PROVIDERIMPL_H */