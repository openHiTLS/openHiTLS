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
#ifdef HITLS_CRYPTO_GCM

#include <stdint.h>
#include <stdbool.h>
#include "crypt_local_types.h"
#include "crypt_modes_xts.h"
#include "crypt_modes_cbc.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#define MODES_MAX_IV_LENGTH 24
#define MODES_MAX_BUF_LENGTH 24
#define DES_BLOCK_BYTE_NUM 8
#define MODES_IV_LENGTH 16

#define UPDATE_VALUES(l, i, o, len) \
    do { \
        (l) -= (len); \
        (i) += (len); \
        (o) += (len); \
    } while (false)

#define EAL_MAX_BLOCK_LENGTH 32

typedef struct {
    void *ciphCtx;  /* Context defined by each algorithm  */
    const EAL_SymMethod *ciphMeth; /* Corresponding to the related methods for each symmetric algorithm */
    uint8_t iv[MODES_MAX_IV_LENGTH];   /* IV information */
    uint8_t buf[MODES_MAX_BUF_LENGTH]; /* Cache the information of the previous block. */
    uint8_t blockSize;                 /* Save the block size. */
    /* Used in CTR and OFB modes. If offset > 0, [0, offset-1] of iv indicates the used data,
       [offset, blockSize-1] indicates unused data. */
    uint8_t offset;
} MODES_CipherCommonCtx;

/**
 * @ingroup crypt_mode_cipherctx
 *   mode handle
 */
struct ModesCipherCtx {
    MODES_CipherCommonCtx commonCtx;
    int32_t algId;
    uint8_t data[EAL_MAX_BLOCK_LENGTH];             /**< last data block that may not be processed */
    uint8_t dataLen;                                /**< size of the last data block that may not be processed. */
    CRYPT_PaddingType pad;                          /**< padding type */
    bool enc;
};

typedef struct {
    void *ciphCtx;                    /* Key defined by each algorithm  */
    const EAL_SymMethod *ciphMeth; /* corresponding to the encrypt and decrypt in the bottom layer, operate keyctx */
    uint8_t iv[MODES_MAX_IV_LENGTH];  /* The length is blocksize */
    uint8_t tweak[MODES_MAX_IV_LENGTH]; /* The length is blocksize */
    uint8_t blockSize;                  /* Save the block size. */
} MODES_CipherXTSCtx;

struct ModesXTSCtx {
    int32_t algId;
    MODES_CipherXTSCtx xtsCtx;
    bool enc;
};

#define CCM_BLOCKSIZE 16

typedef struct {
    void *ciphCtx;  /* Context defined by each algorithm  */
    const EAL_SymMethod *ciphMeth;  /* Corresponding to the related methods for each symmetric algorithm */

    uint8_t nonce[CCM_BLOCKSIZE];  /* Data nonce, ctr encrypted data */
    uint8_t tag[CCM_BLOCKSIZE];    /* Data tag, intermediate data encrypted by the CBC */
    uint8_t last[CCM_BLOCKSIZE];   /* Previous data block in ctr mode */
    uint64_t msgLen;    /* The message length */
    uint8_t lastLen;    /* Unused data length of the previous data block in ctr mode. */
    uint8_t tagLen;     /* The length of the tag is 16 by default. The tag is reset each time the key is set. */
    uint8_t tagInit;    /* Indicate whether the tag is initialized. */
} MODES_CipherCCMCtx;

struct ModesCcmCtx {
    int32_t algId;
    MODES_CipherCCMCtx ccmCtx;
    bool enc;
};

typedef struct {
    uint32_t acc[6];    // The intermediate data of the acc, must be greater than 130 bits.
    uint32_t r[4];      // Key information r, 16 bytes, that is, 4 * sizeof(uint32_t)
    uint32_t s[4];      // Key information s, 16 bytes, that is, 4 * sizeof(uint32_t)
    uint32_t table[36]; // Indicates the table used to accelerate the assembly calculation.
    uint8_t last[16];   // A block 16 bytes are cached for the last unprocessed data.
    uint32_t lastLen;   // Indicates the remaining length of the last data.
    uint32_t flag;      // Used to save the assembly status information.
} Poly1305Ctx;

typedef struct {
    void *key; // Handle for the method.
    const EAL_SymMethod *method; // algorithm method
    Poly1305Ctx polyCtx;
    uint64_t aadLen; // Status, indicating whether identification data is set.
    uint64_t cipherTextLen; // status, indicating whether the identification data is set.
} MODES_CipherChaChaPolyCtx;

struct ModesChaChaCtx {
    int32_t algId;
    MODES_CipherChaChaPolyCtx chachaCtx;
    bool enc;
};

typedef struct {
    uint64_t h;
    uint64_t l;
} MODES_GCM_GF128;

#define GCM_BLOCKSIZE 16

typedef struct {
    // The information can be set once and used multiple times.
    uint8_t iv[GCM_BLOCKSIZE];      // Processed IV information. The length is 16 bytes.
    uint8_t ghash[GCM_BLOCKSIZE];   // Intermediate data for tag calculation.
    MODES_GCM_GF128 hTable[16]; // The window uses 4 bits, 2 ^ 4 = 16 entries need to be pre-calculated.
    void *ciphCtx; // Context defined by each symmetric algorithm.
    const EAL_SymMethod *ciphMeth; // algorithm method
    /**
     * tagLen may be any one of the following five values: 16, 15, 14, 13, or 12 bytes
     * For certain applications, tagLen may be 8 or 4 bytes
     */
    uint8_t tagLen;
    uint32_t cryptCnt; // Indicate the number of encryption times that the key can be used.

    // Intermediate encryption/decryption information. The lifecycle is one encryption/decryption operation,
    // and needs to be reset during each encryption/decryption operation.
    uint8_t last[GCM_BLOCKSIZE];    // ctr mode last
    uint8_t remCt[GCM_BLOCKSIZE];     // Remaining ciphertext
    uint8_t ek0[GCM_BLOCKSIZE];     // ek0
    uint64_t plaintextLen;  // use for calc tag
    uint32_t aadLen;        // use for calc tag
    uint32_t lastLen;       // ctr mode lastLen
} MODES_CipherGCMCtx;

struct ModesGcmCtx {
    int32_t algId;
    MODES_CipherGCMCtx gcmCtx;
    bool enc;
};

typedef struct {
    MODES_CipherCommonCtx modeCtx;
    uint8_t feedbackBits;  /* Save the FeedBack length. */
} MODES_CipherCFBCtx;

struct ModesCFBCtx {
    int32_t algId;
    MODES_CipherCFBCtx cfbCtx;
    bool enc;
};

typedef struct {
    const uint8_t *in;
    uint8_t *out;
    const uint8_t *ctr;
    uint8_t *tag;
} XorCryptData;

MODES_CipherCtx *MODES_CipherNewCtx(int32_t algId);

int32_t MODES_CipherInitCtx(MODES_CipherCtx *modeCtx, void *setSymKey, void *keyCtx, const uint8_t *key,
    uint32_t keyLen, const uint8_t *iv, uint32_t ivLen, bool enc);

/* Block cipher processing */
int32_t MODES_CipherUpdate(MODES_CipherCtx *modeCtx, void *blockUpdate, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen);

/* Block cipher processing */
int32_t MODES_CipherFinal(MODES_CipherCtx *modeCtx, void *blockUpdate, uint8_t *out, uint32_t *outLen);

int32_t MODES_CipherDeInitCtx(MODES_CipherCtx *modeCtx);

void MODES_CipherFreeCtx(MODES_CipherCtx *modeCtx);

int32_t MODES_CipherCtrl(MODES_CipherCtx *ctx, int32_t opt, void *val, uint32_t len);

void MODES_Clean(MODES_CipherCommonCtx *ctx);
int32_t MODES_SetIv(MODES_CipherCommonCtx *ctx, uint8_t *val, uint32_t len);
int32_t MODES_GetIv(MODES_CipherCommonCtx *ctx, uint8_t *val, uint32_t len);

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

#ifdef HITLS_CRYPTO_SM4

int32_t MODES_SM4_SetEncryptKey(MODES_CipherCommonCtx *ctx, const uint8_t *key, uint32_t len);

int32_t MODES_SM4_SetDecryptKey(MODES_CipherCommonCtx *ctx, const uint8_t *key, uint32_t len);
#endif

// cfb
int32_t MODES_CFB_Encrypt(MODES_CipherCFBCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

int32_t MODES_CFB_Decrypt(MODES_CipherCFBCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

// ctr
uint32_t MODES_CTR_LastHandle(MODES_CipherCommonCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

void MODES_CTR_RemHandle(MODES_CipherCommonCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

// gcm
void GcmTableGen4bit(uint8_t key[GCM_BLOCKSIZE], MODES_GCM_GF128 hTable[16]);

void GcmHashMultiBlock(uint8_t t[GCM_BLOCKSIZE], const MODES_GCM_GF128 hTable[16], const uint8_t *in, uint32_t inLen);

uint32_t MODES_GCM_LastHandle(MODES_CipherGCMCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, bool enc);

int32_t MODES_GCM_InitHashTable(MODES_CipherGCMCtx *ctx);
int32_t MODES_GCM_SetIv(MODES_CipherGCMCtx *ctx, const uint8_t *iv, uint32_t ivLen);

// xts
int32_t MODES_XTS_CheckPara(const uint8_t *key, uint32_t len, const uint8_t *iv);
int32_t MODES_XTS_SetIv(MODES_CipherXTSCtx *ctx, const uint8_t *val, uint32_t len);

int32_t MODES_SetPaddingCheck(int32_t pad);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif
#endif
