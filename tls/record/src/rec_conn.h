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

#ifndef REC_CONN_H
#define REC_CONN_H

#include <stdint.h>
#include "rec.h"

#ifdef __cplusplus
extern "C" {
#endif

#define REC_MAX_MAC_KEY_LEN            64
#define REC_MAX_KEY_LENGTH             64
#define REC_MAX_IV_LENGTH              16
#define REC_MAX_KEY_BLOCK_LEN          (REC_MAX_MAC_KEY_LEN * 2 + REC_MAX_KEY_LENGTH * 2 + REC_MAX_IV_LENGTH * 2)
#define MAX_SHA1_SIZE 20
#define MAX_MD5_SIZE 16

#define REC_CONN_SEQ_SIZE 8u            /* Sequence number size */

/**
 * Cipher suite information, which is required for local encryption and decryption
 * For details, see RFC5246 6.1
 */
typedef struct {
    HITLS_MacAlgo macAlg;               /* MAC algorithm */
    HITLS_CipherAlgo cipherAlg;         /* symmetric encryption algorithm */
    HITLS_CipherType cipherType;        /* encryption algorithm type */

    uint8_t macKey[REC_MAX_MAC_KEY_LEN];
    uint8_t key[REC_MAX_KEY_LENGTH];
    uint8_t iv[REC_MAX_IV_LENGTH];
    bool isExportIV;                /* Used by the TTO feature. The IV does not need to be randomly
                                    generated during CBC encryption If it is set by user */
    /* key length */
    uint8_t macKeyLen;              /* Length of the MAC key. The length of the MAC key is 0 in AEAD algorithm */
    uint8_t encKeyLen;              /* Length of the symmetric key */
    uint8_t fixedIvLength;          /* iv length. It is the implicit IV length in AEAD algorithm */

    /* result length */
    uint8_t blockLength;            /* If the block length is not zero, the alignment should be handled */
    uint8_t recordIvLength;         /* The explicit IV needs to be sent to the peer */
    uint8_t macLen;                 /* Add the length of the MAC. Or the tag length in AEAD */
} RecConnSuitInfo;

/* connection state */
typedef struct {
    RecConnSuitInfo *suiteInfo;             /* Cipher suite information */
    uint64_t seq;                           /* tls: 8 byte sequence number or dtls: 6 byte seq */

#ifndef HITLS_NO_DTLS12
    uint16_t epoch;                         /* dtls: 2 byte epoch */
    uint16_t reserve;                       /* Four-byte alignment is reserved */
#endif
} RecConnState;

/* see TLSPlaintext structure definition in rfc */
typedef struct {
    uint8_t type;  // ccs(20), alert(21), hs(22), app data(23), (255)
    bool isEncryptThenMac;
    uint8_t reverse[2];

    uint16_t version;
    uint16_t negotiatedVersion;

    uint8_t seq[REC_CONN_SEQ_SIZE];     /* 1. tls: sequence number 2.dtls: epoch + sequence */

    uint32_t textLen;
    const uint8_t *text;  // fragment
} REC_TextInput;

/**
 * @brief   Initialize RecConnState
 */
RecConnState *RecConnStateNew(void);

/**
 * @brief   Release RecConnState
 */
void RecConnStateFree(RecConnState *state);

/**
 * @brief   Obtain the Sequence number
 *
 * @param   state [IN] Connection state
 *
 * @retval  Sequence number
 */
uint64_t RecConnGetSeqNum(const RecConnState *state);

/**
 * @brief   Set the Sequence number
 *
 * @param   state [IN] Connection state
 * @param   seq [IN] Sequence number
 *
 * @retval  Sequence number
 */
void RecConnSetSeqNum(RecConnState *state, uint64_t seq);

#ifndef HITLS_NO_DTLS12
/**
 * @brief   Obtain the epoch
 *
 * @attention state can not be null pointer
 *
 * @param   state [IN] Connection state
 *
 * @retval  epoch
 */
uint16_t RecConnGetEpoch(const RecConnState *state);

/**
 * @brief   Set epoch
 *
 * @attention state can not be null pointer
 * @param   state [IN] Connection state
 * @param   epoch [IN] epoch
 *
 */
void RecConnSetEpoch(RecConnState *state, uint16_t epoch);

#endif

/**
 * @brief   Set the key information
 *
 * @param   state [IN] Connection state
 * @param   suitInfo [IN] Ciphersuite information
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_INTERNAL_EXCEPTION Invalid null pointer
 * @retval  HITLS_MEMALLOC_FAIL Memory allocated failed
 */
int32_t RecConnStateSetCipherInfo(RecConnState *state, RecConnSuitInfo *suitInfo);

/**
 * @brief   Calculate the ciphertext length based on the plaintext length
 * @attention The ciphertext length is accurate
 * @param   state [IN] RecState context, including cipher suite information
 * @param   plainLen [IN] Plaintext length
 * @param   isEncThenMac [IN] Indicates whether the Encrypt-Then-Mac mode is used
 *
 * @return  ciphertext length
 */
uint32_t RecConnCalcCiphertextLen(const RecConnState *state, uint32_t plainLen, bool isEncThenMac);

/**
 * @brief   Encrypt the record payload
 *
 * @param   state  RecState context
 * @param   plainMsg [IN] Input data before encryption
 * @param   cipherText [OUT] Encrypted content
 * @param   cipherTextLen [IN] Length after encryption
 * @param   isEncryptThenMac [IN] Indicates whether the Encrypt-Then-Mac mode is used
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_MEMCPY_FAIL Memory copy failed
 * @retval  HITLS_REC_ERR_NOT_SUPPORT_CIPHER The key algorithm is not supported
 * @retval  HITLS_REC_ERR_ENCRYPT Encryption failed
 * @see     SAL_CRYPT_Encrypt
 */
int32_t RecConnEncrypt(RecConnState *state, const REC_TextInput *plainMsg, uint8_t *cipherText, uint32_t cipherTextLen);

/**
 * @brief   Decrypt the record payload
 *
 * @param   ctx [IN] tls Context
 * @param   state  RecState context
 * @param   cryptMsg [IN] Content to be decrypted
 * @param   data [OUT] Decrypted data
 * @param   dataLen [IN/OUT] IN: length of data OUT: length after decryption
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_REC_ERR_NOT_SUPPORT_CIPHER The key algorithm is not supported
 * @retval  HITLS_MEMCPY_FAIL Memory copy failed
 */
int32_t RecConnDecrypt(TLS_Ctx *ctx, RecConnState *state,
    const REC_TextInput *cryptMsg, uint8_t *data, uint32_t *dataLen);

/**
 * @brief   Key generation
 *
 * @param   param [IN] Security parameter
 * @param   client [OUT] Client key material
 * @param   server [OUT] Server key material
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_INTERNAL_EXCEPTION Invalid null pointer
 * @retval  Reference SAL_CRYPT_PRF
 */
int32_t RecConnKeyBlockGen(const REC_SecParameters *param, RecConnSuitInfo *client, RecConnSuitInfo *server);

/**
 * @brief   TLS1.3 Key generation
 *
 * @param   param [IN] Security parameter
 * @param   suitInfo [OUT] key material
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_UNREGISTERED_CALLBACK Unregistered callback
 * @retval  HITLS_CRYPT_ERR_DIGEST hash calculation failed
 * @retval  HITLS_CRYPT_ERR_HKDF_EXPAND HKDF-Expand calculation fails
 *
 */
int32_t RecTLS13ConnKeyBlockGen(const REC_SecParameters *param, RecConnSuitInfo *suitInfo);

#ifdef __cplusplus
}
#endif

#endif /* REC_CONN_H */
