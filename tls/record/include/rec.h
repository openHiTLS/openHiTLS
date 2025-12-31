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

#ifndef REC_H
#define REC_H

#include <stdbool.h>
#include <stdint.h>
#include "hitls_build.h"
#include "hitls_crypt_type.h"
#include "tls.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DTLS_MIN_MTU 256    /* Minimum MTU setting size */
#define REC_MAX_PLAIN_LENGTH 16384          /* Maximum plain length */
/* TLS13 Maximum MAC address padding */
#define REC_MAX_TLS13_ENCRYPTED_OVERHEAD  256u
/* TLS13 Maximum ciphertext length */
#define REC_MAX_TLS13_ENCRYPTED_LEN (REC_MAX_PLAIN_LENGTH + REC_MAX_TLS13_ENCRYPTED_OVERHEAD)

#define REC_MASTER_SECRET_LEN 48
#define REC_RANDOM_LEN  32

#define RECORD_HEADER 0x100
#define RECORD_INNER_CONTENT_TYPE 0x101
/*
 * record type
 */
typedef enum {
    REC_TYPE_CHANGE_CIPHER_SPEC = 20,
    REC_TYPE_ALERT = 21,
    REC_TYPE_HANDSHAKE = 22,
    REC_TYPE_APP = 23,
    REC_TYPE_UNKNOWN = 255
} REC_Type;

/*
 * SecurityParameters, used to generate keys and initialize the connect state
 */
typedef struct {
    bool isClient;                  /* Connection Endpoint */
    bool isClientTrafficSecret;     /* TrafficSecret type */
    HITLS_HashAlgo prfAlg;          /* prf_algorithm */
    HITLS_MacAlgo macAlg;           /* mac algorithm */
    HITLS_CipherAlgo cipherAlg;     /* symmetric encryption algorithm */
    HITLS_CipherType cipherType;    /* encryption algorithm type */

    /* key length */
    uint8_t fixedIvLength;          /* iv length. In TLS1.2 AEAD algorithm is the implicit IV length */
    uint8_t encKeyLen;              /* Length of the symmetric key */
    uint8_t macKeyLen;              /* MAC key length: If the AEAD algorithm is used, the MAC key length is 0 */

    uint8_t blockLength;            /* If the block length is not zero, the alignment should be handled. */
    uint8_t recordIvLength;         /* The explicit IV needs to be sent to the peer */
    uint8_t macLen;                 /*  MAC length. For AEAD, it is the mark length */

    uint8_t masterSecret[MAX_DIGEST_SIZE];             /* tls1.2 master key. TLS1.3 carries the TrafficSecret */
    uint8_t clientRandom[REC_RANDOM_LEN];              /* Client random number */
    uint8_t serverRandom[REC_RANDOM_LEN];              /* service random number */
} REC_SecParameters;

/**
 * @ingroup record
 * @brief   Record initialization
 *
 * @param   ctx [IN] TLS object
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_INTERNAL_EXCEPTION Invalid null pointer
 * @retval  HITLS_MEMALLOC_FAIL Memory allocated failed
 *
 */
int32_t REC_Init(TLS_Ctx *ctx);

/**
 * @ingroup record
 * @brief   record deinitialize
 *
 * @param   ctx [IN] TLS object
 */
void REC_DeInit(TLS_Ctx *ctx);

/**
 * @ingroup record
 * @brief   Check whether data exists in the read buffer of the reocrd
 *
 * @param   ctx [IN] TLS object
 * @return  whether data exists in the read buffer
 */
bool REC_ReadHasPending(const TLS_Ctx *ctx);

/**
 * @ingroup record
 * @brief   Reads a message in the unit of a record. Data is read from the uio of the CTX to the data pointer
 *
 * @attention recordType indicates the expected record type (app or handshake)
 *            readLen indicates the length of read data. The maximum length is REC_MAX_PLAIN_LENGTH (16384)
 * @param   ctx [IN] TLS object
 * @param   recordType [IN] Expected record type(app or handshake)
 * @param   data [OUT] Read buffer
 * @param   readLen [OUT] Length of the read data
 * @param   num [IN] The size of read buffer, which must be greater than or equal to the maximum size of the record
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_INTERNAL_EXCEPTION,Invalid null pointer
 * @retval  HITLS_REC_ERR_BUFFER_NOT_ENOUGH The buffer space is insufficient
 * @retval  HITLS_MEMCPY_FAIL Memory copy failed
 * @retval  HITLS_REC_NORMAL_RECV_BUF_EMPTY indicates that the buffer is empty and needs to be read again
 * @retval  HITLS_REC_ERR_IO_EXCEPTION I/O error
 * @retval  HITLS_REC_NORMAL_RECV_UNEXPECT_MSG An unexpected message is received and needs to be processed
 * @retval  HITLS_REC_ERR_SN_WRAPPING Sequence number wrap
 */
int32_t REC_Read(TLS_Ctx *ctx, REC_Type recordType, uint8_t *data, uint32_t *readLen, uint32_t num);

/**
 * @ingroup record
 * @brief   Write a record in the unit of record
 *
 * @attention If the value of num exceeds the maximum length of the record, return error
 *
 * @param   ctx [IN] TLS object
 * @param   recordType [IN] record type
 * @param   data [IN] Write data
 * @param   num [IN] Attempt to write num bytes of plaintext data
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_INTERNAL_EXCEPTION Invalid null pointer
 * @retval  HITLS_REC_ERR_BUFFER_NOT_ENOUGH The buffer space is insufficient
 * @retval  HITLS_MEMCPY_FAIL Memory copy failed
 * @retval  HITLS_REC_PMTU_TOO_SMALL The PMTU is too small
 * @retval  HITLS_REC_ERR_IO_EXCEPTION I/O error
 * @retval  HITLS_REC_NORMAL_IO_BUSY I/O busy
 * @retval  HITLS_REC_ERR_TOO_BIG_LENGTH The length of the plaintext data written by the upper layer exceeds the
* maximum length of the plaintext data that can be written by a single record
 * @retval  HITLS_REC_ERR_NOT_SUPPORT_CIPHER The key algorithm is not supported
 * @retval  HITLS_REC_ERR_SN_WRAPPING Sequence number wrap
 */
int32_t REC_Write(TLS_Ctx *ctx, REC_Type recordType, const uint8_t *data, uint32_t num);

/**
 * @ingroup record
 * @brief   Activate the expired write state. This API is invoked in the retransmission scenario
 *
 * @attention Reservation Interface
 * @param   ctx [IN] TLS object
 *
 */
void REC_ActiveOutdatedWriteState(TLS_Ctx *ctx);

/**
 * @ingroup record
 * @brief   Disable the expired write status. This API is invoked in the retransmission scenario
 *
 * @attention Reservation Interface
 * @param   ctx [IN] TLS object
 *
 */
void REC_DeActiveOutdatedWriteState(TLS_Ctx *ctx);

/**
 * @ingroup record
 * @brief   Initialize the pending state
 *
 * @param   ctx [IN] TLS object
 * @param   param [IN] Security parameter
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_MEMALLOC_FAIL Memory allocated failed
 * @retval  HITLS_INTERNAL_EXCEPTION Invalid null pointer
 *
 */
int32_t REC_InitPendingState(const TLS_Ctx *ctx, const REC_SecParameters *param);

/**
 * @ingroup record
 * @brief    Activate the pending state, switch the pending state to the current state
 *
 * @attention ctx cannot be empty
 * @param   ctx [IN] TLS object
 * @param   isOut [IN] Indicates whether is the output type
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_INTERNAL_EXCEPTION Invalid null pointer
 *
 */
int32_t REC_ActivePendingState(TLS_Ctx *ctx, bool isOut);

/**
 * @brief   Calculate the mtu
 *
 * @param   ctx [IN] TLS_Ctx context
 *
 * @retval  HITLS_SUCCESS
 * @retval  ITLS_UIO_FAIL The uio ctrl failed
 */
int32_t REC_QueryMtu(TLS_Ctx *ctx);

/**
 * @brief   Obtain the maximum writable plaintext length of a single record
 *
 * @param   ctx [IN] TLS_Ctx context
 * @param   len [OUT] Maximum length of the plaintext
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_INTERNAL_EXCEPTION Invalid null pointer
 * @retval  HITLS_REC_PMTU_TOO_SMALL The PMTU is too small
 */
int32_t REC_GetMaxWriteSize(const TLS_Ctx *ctx, uint32_t *len);

/**
 * @brief   Obtain the maximum writable plaintext according to mtu
 *
 * @param   ctx [IN] TLS_Ctx context
 * @param   len [OUT] Maximum length of the plaintext
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_UIO_IO_TYPE_ERROR Not UDP uio
 * @retval  HITLS_REC_PMTU_TOO_SMALL The PMTU is too small
 */
int32_t REC_GetMaxDataMtu(const TLS_Ctx *ctx, uint32_t *len);

/**
 * @ingroup record
 * @brief   TLS13 Initialize the pending state
 *
 * @param   ctx [IN] TLS object
 * @param   param [IN] Security parameter
 * @param   isOut [IN] Indicates whether is the output type
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_MEMALLOC_FAIL Memory allocated failed
 * @retval  HITLS_INTERNAL_EXCEPTION Invalid null pointer
 *
 */
int32_t REC_TLS13InitPendingState(const TLS_Ctx *ctx, const REC_SecParameters *param, bool isOut);

/**
 * @brief   Add the message to the retransmission queue
 *
 * @param   recCtx [OUT] RecCtx Structure
 * @param   type [IN] Message type
 * @param   msg [IN] Message content
 * @param   len [IN] Message length
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_MEMALLOC_FAIL Memory allocation failed
 */
int32_t REC_RetransmitListAppend(REC_Ctx *recCtx, REC_Type type, const uint8_t *msg, uint32_t len);

/**
 * @brief   Clear the retransmission queue
 *
 * @param   recCtx [OUT] RecCtx Structure
 */
void REC_RetransmitListClean(REC_Ctx *recCtx);

/**
 * @brief   Send a message in the retransmission queue
 *          UDP sending will not fail. Therefore, the sending failure scenario does not need to be considered
 *
 * @param   ctx [OUT] tls Context
 * @retval  HITLS_SUCCESS
 * @retval  For other error codes, see hitls_error.h
 */
int32_t REC_RetransmitListFlush(TLS_Ctx *ctx);

REC_Type REC_GetUnexpectedMsgType(TLS_Ctx *ctx);

bool REC_HaveReadSuiteInfo(const TLS_Ctx *ctx);

/**
 * @ingroup app
 * @brief Obtain the length of the remaining readable app messages in the current record.
 *
 * @param ctx [IN] TLS object
 * @return Length of the remaining readable app message
 */
uint32_t APP_GetReadPendingBytes(const TLS_Ctx *ctx);

int32_t REC_RecOutBufReSet(TLS_Ctx *ctx);

/**
 * @brief   Flush the buffer uio
 *
 * @param   ctx [IN] ssl context
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_REC_NORMAL_IO_BUSY uio busy
 * @retval  HITLS_REC_ERR_IO_EXCEPTION uio error
 */
int32_t REC_FlightTransmit(TLS_Ctx *ctx);

/**
 * @brief   Obtain the out buffer remaining size
 *
 * @param   ctx [IN] TLS_Ctx context
 *
 * @retval  the out buffer remaining size
 */
uint32_t REC_GetOutBufPendingSize(const TLS_Ctx *ctx);

/**
 * @brief   Flush the record out buffer
 *
 * @param   ctx [IN] TLS_Ctx context
 *
 * @retval  HITLS_SUCCESS Out buffer is empty or flush success
 * @retval  HITLS_REC_NORMAL_IO_BUSY Out buffer is not empty, but the IO operation is busy
 */
int32_t REC_OutBufFlush(TLS_Ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* REC_H */
