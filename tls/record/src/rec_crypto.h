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
#ifndef REC_CRYPT_H
#define REC_CRYPT_H
#include "hitls_build.h"
#include "hitls_error.h"
#include "record.h"
#include "rec_conn.h"

#ifdef HITLS_TLS_PROTO_TLS
typedef struct {
    REC_Type recordType; /* Protocol type */
    uint32_t plainLen;   /* message length */
    uint8_t *plainData;  /* message data */
#ifdef HITLS_TLS_PROTO_TLS13
    /* Length of the tls1.3 padding content. Currently, the value is 0. The value can be used as required */
    uint64_t recPaddingLength;
#endif
    bool isTlsInnerPlaintext; /* Whether it is a TLSInnerPlaintext message for tls1.3 */
} RecordPlaintext;            /* Record protocol data before encryption */
#else
typedef struct DtlsRecordPlaintext RecordPlaintext;
#endif

typedef uint32_t (*CalCiphertextLenFunc)(const TLS_Ctx *ctx, RecConnSuitInfo *suitInfo,
    uint32_t plantextLen, bool isRead);
typedef int32_t (*CalPlantextBufLenFunc)(TLS_Ctx *ctx, RecConnSuitInfo *suitInfo,
    uint32_t ciphertextLen, uint32_t *offset, uint32_t *plaintextLen);
typedef int32_t (*DecryptFunc)(TLS_Ctx *ctx, RecConnState *state, const REC_TextInput *cryptMsg,
    uint8_t *data, uint32_t *dataLen);
typedef int32_t (*EncryptFunc)(TLS_Ctx *ctx, RecConnState *state, const REC_TextInput *plainMsg,
    uint8_t *cipherText, uint32_t cipherTextLen);
typedef int32_t (*DecryptPostProcess)(TLS_Ctx *ctx, RecConnSuitInfo *suitInfo, REC_TextInput *cryptMsg,
    uint8_t *data, uint32_t *dataLen);
typedef int32_t (*EncryptPreProcess)(TLS_Ctx *ctx, uint8_t recordType, const uint8_t *data, uint32_t plainLen,
    RecordPlaintext *recPlaintext);

typedef struct {
    CalCiphertextLenFunc calCiphertextLen;
    CalPlantextBufLenFunc calPlantextBufLen;
    DecryptFunc decrypt;
    DecryptPostProcess decryptPostProcess;
    EncryptFunc encryt;
    EncryptPreProcess encryptPreProcess;
} RecCryptoFunc;

const RecCryptoFunc *RecGetCryptoFuncs(const RecConnSuitInfo *suiteInfo);
#endif