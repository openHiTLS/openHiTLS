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

#ifndef MODES_LOCAL_H
#define MODES_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_MODES

#include <stdint.h>
#include <stdbool.h>
#include "crypt_local_types.h"
#include "crypt_modes_xts.h"
#include "crypt_modes_cbc.h"

#include "crypt_modes_ccm.h"
#include "crypt_modes_cfb.h"
#include "crypt_modes_chacha20poly1305.h"
#include "crypt_modes_ctr.h"
#include "crypt_modes_ecb.h"
#include "crypt_modes_gcm.h"
#include "crypt_modes_ofb.h"
#include "crypt_modes.h"
#include "eal_cipher_local.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus


#define UPDATE_VALUES(l, i, o, len) \
    do { \
        (l) -= (len); \
        (i) += (len); \
        (o) += (len); \
    } while (false)

int32_t MODES_CipherInitCommonCtx(MODES_CipherCommonCtx *modeCtx, void *setSymKey, void *keyCtx,
    const uint8_t *key, uint32_t keyLen, const uint8_t *iv, uint32_t ivLen);
int32_t MODES_CipherInitCtx(MODES_CipherCtx *ctx, void *setSymKey, void *keyCtx, const uint8_t *key,
    uint32_t keyLen, const uint8_t *iv, uint32_t ivLen, bool enc);

int32_t MODE_CheckUpdateParam(uint8_t blockSize, uint32_t cacheLen, uint32_t inLen, uint32_t *outLen);
/* Block cipher processing */
int32_t MODES_CipherUpdate(MODES_CipherCtx *modeCtx, void *blockUpdate, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen);

int32_t MODES_BlockPadding(int32_t algId, int32_t padding, uint8_t blockSize, uint8_t *data, uint8_t *dataLen);
int32_t MODES_BlockUnPadding(int32_t padding, const uint8_t *pad, uint32_t padLen, uint32_t *dataLen);
/* Block cipher processing */
int32_t MODES_CipherFinal(MODES_CipherCtx *modeCtx, void *blockUpdate, uint8_t *out, uint32_t *outLen);

int32_t MODES_CipherDeInitCtx(MODES_CipherCtx *modeCtx);

void MODES_CipherFreeCtx(MODES_CipherCtx *modeCtx);

int32_t MODES_CipherCtrl(MODES_CipherCtx *ctx, int32_t opt, void *val, uint32_t len);


int32_t MODES_CipherStreamProcess(void *processFuncs, void *ctx, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen);

static inline void MODE_IncCounter(uint8_t *counter, uint32_t counterLen)
{
    uint32_t i = counterLen;
    uint16_t carry = 1;

    while (i > 0) {
        i--;
        carry += counter[i];
        counter[i] = carry & (0xFFu);
        carry >>= 8;  // Take the upper 8 bits.
    }
}

int32_t MODES_SetEncryptKey(MODES_CipherCommonCtx *ctx, const uint8_t *key, uint32_t len);
int32_t MODES_SetDecryptKey(MODES_CipherCommonCtx *ctx, const uint8_t *key, uint32_t len);
int32_t MODES_SetPaddingCheck(int32_t pad);

#ifdef HITLS_CRYPTO_SM4

int32_t MODES_SM4_SetEncryptKey(MODES_CipherCommonCtx *ctx, const uint8_t *key, uint32_t len);

int32_t MODES_SM4_SetDecryptKey(MODES_CipherCommonCtx *ctx, const uint8_t *key, uint32_t len);
#endif

// cfb
#ifdef HITLS_CRYPTO_CFB
int32_t MODES_CFB_Encrypt(MODES_CipherCFBCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

int32_t MODES_CFB_Decrypt(MODES_CipherCFBCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
#endif

// ctr
#ifdef HITLS_CRYPTO_CTR
uint32_t MODES_CTR_LastHandle(MODES_CipherCommonCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

void MODES_CTR_RemHandle(MODES_CipherCommonCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
#endif

// gcm
#ifdef HITLS_CRYPTO_GCM
void GcmTableGen4bit(uint8_t key[GCM_BLOCKSIZE], MODES_GCM_GF128 hTable[16]);

void GcmHashMultiBlock(uint8_t t[GCM_BLOCKSIZE], const MODES_GCM_GF128 hTable[16], const uint8_t *in, uint32_t inLen);

uint32_t MODES_GCM_LastHandle(MODES_CipherGCMCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, bool enc);

int32_t MODES_GCM_SetIv(MODES_CipherGCMCtx *ctx, const uint8_t *iv, uint32_t ivLen);
int32_t CryptLenCheckAndRefresh(MODES_CipherGCMCtx *ctx, uint32_t len);
#endif

// xts
#ifdef HITLS_CRYPTO_XTS
int32_t MODES_XTS_CheckPara(const uint8_t *key, uint32_t len, const uint8_t *iv);
int32_t MODES_XTS_SetIv(MODES_CipherXTSCtx *ctx, const uint8_t *val, uint32_t len);

int32_t MODES_XTS_SetEncryptKey(MODES_CipherXTSCtx *ctx, const uint8_t *key, uint32_t len);
int32_t MODES_XTS_SetDecryptKey(MODES_CipherXTSCtx *ctx, const uint8_t *key, uint32_t len);

#endif

#ifdef HITLS_CRYPTO_CBC
int32_t AES_CBC_EncryptBlock(MODES_CipherCommonCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
int32_t AES_CBC_DecryptBlock(MODES_CipherCommonCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
int32_t MODES_CBC_Encrypt(MODES_CipherCommonCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
int32_t MODES_CBC_Decrypt(MODES_CipherCommonCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
int32_t MODE_SM4_CBC_Encrypt(MODES_CipherCommonCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
int32_t MODE_SM4_CBC_Decrypt(MODES_CipherCommonCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
#endif
#ifdef HITLS_CRYPTO_CCM
int32_t MODES_CCM_Encrypt(MODES_CipherCCMCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
int32_t MODES_CCM_Decrypt(MODES_CipherCCMCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
int32_t MODES_AES_CCM_Encrypt(MODES_CipherCCMCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
int32_t MODES_AES_CCM_Decrypt(MODES_CipherCCMCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
#endif
#ifdef HITLS_CRYPTO_CFB
int32_t MODES_CFB_BitCrypt(MODES_CipherCFBCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, bool enc);
int32_t MODE_AES_CFB_Decrypt(MODES_CipherCFBCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
int32_t MODE_SM4_CFB_Encrypt(MODES_CipherCFBCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
int32_t MODE_SM4_CFB_Decrypt(MODES_CipherCFBCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
#endif
#if defined(HITLS_CRYPTO_CHACHA20) && defined(HITLS_CRYPTO_CHACHA20POLY1305)
int32_t MODES_CHACHA20POLY1305_Encrypt(MODES_CipherChaChaPolyCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
int32_t MODES_CHACHA20POLY1305_Decrypt(MODES_CipherChaChaPolyCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
int32_t MODES_CHACHA20POLY1305_SetEncryptKey(MODES_CipherChaChaPolyCtx *ctx, const uint8_t *key, uint32_t len);
int32_t MODES_CHACHA20POLY1305_SetDecryptKey(MODES_CipherChaChaPolyCtx *ctx, const uint8_t *key, uint32_t len);
#endif
#ifdef HITLS_CRYPTO_CTR
int32_t MODES_CTR_Crypt(MODES_CipherCommonCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
int32_t AES_CTR_EncryptBlock(MODES_CipherCommonCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
int32_t MODE_SM4_CTR_Encrypt(MODES_CipherCommonCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
#endif
#ifdef HITLS_CRYPTO_ECB
int32_t MODES_ECB_Encrypt(MODES_CipherCommonCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
int32_t MODES_ECB_Decrypt(MODES_CipherCommonCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
int32_t AES_ECB_EncryptBlock(MODES_CipherCommonCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
int32_t AES_ECB_DecryptBlock(MODES_CipherCommonCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
int32_t MODE_SM4_ECB_Encrypt(MODES_CipherCommonCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
int32_t MODE_SM4_ECB_Decrypt(MODES_CipherCommonCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
#endif
#ifdef HITLS_CRYPTO_GCM
int32_t MODES_GCM_Encrypt(MODES_CipherGCMCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
int32_t MODES_GCM_Decrypt(MODES_CipherGCMCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
int32_t AES_GCM_EncryptBlock(MODES_CipherGCMCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
int32_t AES_GCM_DecryptBlock(MODES_CipherGCMCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
int32_t MODES_SM4_GCM_DecryptBlock(MODES_CipherGCMCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
#endif
#ifdef HITLS_CRYPTO_OFB
int32_t MODES_OFB_Crypt(MODES_CipherCommonCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
#endif
#ifdef HITLS_CRYPTO_XTS
int32_t MODES_XTS_Encrypt(MODES_CipherXTSCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
int32_t MODES_XTS_Decrypt(MODES_CipherXTSCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
int32_t MODES_AES_XTS_Encrypt(MODES_CipherXTSCtx *xtsCtx, const uint8_t *in, uint8_t *out, uint32_t len);
int32_t MODES_AES_XTS_Decrypt(MODES_CipherXTSCtx *xtsCtx, const uint8_t *in, uint8_t *out, uint32_t len);
int32_t MODES_SM4_XTS_Encrypt(MODES_CipherXTSCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
int32_t MODES_SM4_XTS_Decrypt(MODES_CipherXTSCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);
#endif
#ifdef __cplusplus
}
#endif  // __cplusplus

#endif
#endif
