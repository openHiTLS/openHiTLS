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
 * @defgroup bsl_uio
 * @ingroup bsl
 * @brief uio module
 */

#ifndef BSL_UIO_H
#define BSL_UIO_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup bsl_uio
 * @brief   UIO module control structure
 */
typedef struct UIO_ControlBlock BSL_UIO;

typedef int32_t BSL_UIO_InfoCb(BSL_UIO *, int32_t, int32_t);


typedef int32_t (*BslUioWriteCb)(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen);
typedef int32_t (*BslUioReadCb)(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen);
typedef int32_t (*BslUioCtrlCb)(BSL_UIO *uio, int32_t cmd, int32_t larg, void *parg);
typedef int32_t (*BslUioCreateCb)(BSL_UIO *uio);
typedef int32_t (*BslUioDestroyCb)(BSL_UIO *uio);
typedef int32_t (*BslUioPutsCb)(BSL_UIO *uio, const char *buf, uint32_t *writeLen);
typedef int32_t (*BslUioGetsCb)(BSL_UIO *uio, char *buf, uint32_t *readLen);
typedef int32_t (*BslUioCbCtrlCb)(BSL_UIO *uio, int cmd, BSL_UIO_InfoCb *callback);

typedef struct BSL_UIO_MethodStruct BSL_UIO_Method;

/**
 * @ingroup bsl_uio
 *
 * @brief   UIO_Addr structure
 */
typedef union UIO_Address BSL_UIO_Addr;

/**
 * @ingroup bsl_uio
 * @brief   Transmission protocol enumeration
 */
typedef enum {
    BSL_UIO_TCP,
    BSL_UIO_UDP,
    BSL_UIO_SCTP,
    BSL_UIO_MEM,
    BSL_UIO_FILE,
    BSL_UIO_BUFFER,
    BSL_UIO_UNKNOWN, /* Unknown protocol should not appear */

    BSL_UIO_EXTEND = 10000, /* extension value */
} BSL_UIO_TransportType;

#define IS_TRANSTYPE_DATAGRAM(transportType) ((transportType) == BSL_UIO_SCTP || (transportType) == BSL_UIO_UDP)

/**
 * @ingroup bsl_uio
 * @brief   Sctp auth key, hitls Use the BSL_UIO_Method.ctrl method to transfer the BSL_UIO_SCTP_ADD_AUTH_SHARED_KEY
 *          instruction to notify the user that the auth key needs to be set.
 */
typedef struct {
    uint16_t shareKeyId;
    uint16_t authKeySize;
    const uint8_t *authKey;
} BSL_UIO_SctpAuthKey;

/**
 * @ingroup bsl_uio
 * @brief   userData release function
 */
typedef void (*BSL_UIO_USERDATA_FREE_FUNC)(void *);

/**
 * @ingroup bsl_uio
 * @brief   BSL_UIO_CtrlParameter controls the I/O callback function. Hitls notifies the
 *          user of the function to be implemented
 */
typedef enum {
    /* The cmd(0-0x99) used by the abstraction layer and the uio
     * implemented by the user cannot reuse these values. */

    /* Public use 0x000 */
    /* larg equals the length of array, parg is a pointer type array */
    BSL_UIO_SET_PEER_IP_ADDR = 0x000,
    /* larg equals the length of BSL_UIO_CtrlGetPeerIpAddrParam structure,
     * parg is a pointer type BSL_UIO_CtrlGetPeerIpAddrParam
     */
    BSL_UIO_GET_PEER_IP_ADDR,
    /* larg equals the length of 32-bit integer, parg is a pointer type 32-bit integer */
    BSL_UIO_SET_FD,
    /* larg equals the length of 32-bit integer, parg is a pointer type 32-bit integer */
    BSL_UIO_GET_FD,
    /* larg equals the length of 64-bit integer, parg is a pointer type 64-bit integer */
    BSL_UIO_PENDING,
    /* not need to set larg and parg. the default values are 0 and null */
    BSL_UIO_FLUSH,
    /* larg equals the length of 64-bit integer, parg is a pointer type 64-bit integer */
    BSL_UIO_WPENDING,
    /* larg equals the length of 64-bit integer,  parg is a pointer type 64-bit integer */
    BSL_UIO_SEEK,
    /* not need to set larg and parg. the default values are 0 and null */
    BSL_UIO_RESET,
    /* larg equals the length of bool,  parg is a pointer type bool */
    BSL_UIO_GET_INIT,
    /* larg equals the length of 64-bit integer, parg is a pointer type 64-bit integer */
    BSL_UIO_GET_WRITE_NUM,
    /* larg equals the length of 64-bit integer, parg is a pointer type 64-bit integer */
    BSL_UIO_GET_READ_NUM,
    /* larg equals the length of 32-bit integer, parg is a pointer type 32-bit integer */
    BSL_UIO_GET_PTO_LEN,
    BSL_UIO_INFO,
    BIO_UIO_SET_CALLBACK,
    BSL_UIO_SET_CONNECT,
    BSL_UIO_GET_CONNECT,
    BSL_UIO_SET_NOBLOCK,
    BSL_UIO_DO_HANDSHAKE,
    BSL_UIO_SET_CTX,
    BSL_UIO_GET_CTX,
    BSL_UIO_SET_SSL_RENEGOTIATE_TIMEOUT,
    BSL_UIO_SET_SSL_RENEGOTIATE_BYTES,
    BSL_UIO_UDP_SET_CONNECTED,
    BSL_UIO_SET_BUFFER_SIZE,
    BSL_UIO_UDP_GET_MTU_OVERHEAD,
    BSL_UIO_UDP_QUERY_MTU,
    BSL_UIO_UDP_MTU_EXCEEDED,
    BSL_UIO_CIPHER_IS_FINISHED,
    BSL_UIO_SET_CONNECT_MODE,
    BSL_UIO_SET_ACCEPT,
    BSL_UIO_GET_ACCEPT,
    BSL_UIO_SET_BIND_MODE,
    BSL_UIO_GET_BIND_MODE,
    BSL_UIO_APPEND,

    /* SCTP uses 0x3XX */
    BSL_UIO_SCTP_CHECK_PEER_AUTH = 0x300,     /**< SCTP Check whether the peer supports authentication */
    BSL_UIO_SCTP_ADD_AUTH_SHARED_KEY,         /**< Add a new sctp auth key. The sctp can use the new
                                                   key to receive data */
    BSL_UIO_SCTP_ACTIVE_AUTH_SHARED_KEY,      /**< activates the new sctp auth key. The sctp needs to
                                                   use the new key to send data */
    BSL_UIO_SCTP_DEL_PRE_AUTH_SHARED_KEY,     /**< SCTP Delete the previous shared key */
    BSL_UIO_SCTP_SND_BUFF_IS_EMPTY,           /**< Whether the SCTP send queue is NULL. ctrl.param is the
                                                   pointer of uint8_t *. If the value of ctrl.param is greater than 0,
                                                   it indicates that the queue is NULL.
                                                   Otherwise, it indicates that the queue is not NULL */
    BSL_UIO_SCTP_RECV_BUFF_IS_EMPTY,          /**< check whether the SCTP receive queue is NULL.
                                                   ctrl.param is the pointer of uint8_t *.
                                                   If the value of ctrl.param is greater than 0,
                                                   it indicates that the queue is NULL.
                                                   Otherwise, it indicates that the queue is not NULL */
    BSL_UIO_SCTP_GET_SEND_STREAM_ID,
    /* larg equals the length of unsigned 16-bit integer, parg is a pointer type unsigned 16-bit integer */
    BSL_UIO_SCTP_SET_APP_STREAM_ID,
    /* larg equals the length of bool, parg is a pointer type bool */
    BSL_UIO_SCTP_MASK_APP_MESSAGE,
    /* larg is a func callback type BSL_UIO_METHOD_TYPE,  parg is a pointer type func callback */
    BSL_UIO_SCTP_SET_CALLBACK,

    /* MEMÊ¹ÓÃ0x4XX */
    /* larg equals the length of array, parg is a pointer type array */
    BSL_UIO_MEM_NEW_BUF = 0x400,
    /* larg equals the length of pointer, parg is a pointer's pointer type BSL_BufMem */
    BSL_UIO_MEM_GET_PTR,
    /* larg equals the length of 32-bit integer, parg is a pointer type 32-bit integer */
    BSL_UIO_MEM_SET_EOF,
    /* larg equals the length of 32-bit integer, parg is a pointer type 32-bit integer */
    BSL_UIO_MEM_GET_EOF,
    /* larg equals the length of BSL_UIO_CtrlGetInfoParam,  parg is a pointer type BSL_UIO_CtrlGetInfoParam */
    BSL_UIO_MEM_GET_INFO,

    /* FILEÊ¹ÓÃ0x5xx */
    /* larg is the mode for opening a file, parg is a pointer type string */
    BSL_UIO_FILE_OPEN = 0x500,
    /* larg is of the Boolean type and is used to indicate whether the handle is closed with the release of uio,
     * parg is a pointer type file */
    BSL_UIO_FILE_PTR,
    BSL_UIO_FILE_GET_EOF,
    BSL_UIO_FILE_SEEK,
    BSL_UIO_FILE_TELL,
    BSL_UIO_FILE_GET_PTR,

    /* FDÊ¹ÓÃ0x6xx */
    /* larg equals the length of 64-bit integer, parg is a pointer type 64-bit integer */

    BSL_UIO_FD_GET_INFO = 0x600,

    /* Pair uses 0x7xx */
    BSL_UIO_PAIR_MAKE = 0x700,
    BSL_UIO_PAIR_SET_BUFFER_SIZE,
    BSL_UIO_PAIR_GET_BUFFER_SIZE,

    /* TTO uses 0x8xx */
    BSL_UIO_TTO_SET_READ_CB = 0x800,
    BSL_UIO_TTO_SET_WRITE_CB,
    BSL_UIO_TTO_SET_READ_APP_DATA,
    BSL_UIO_TTO_SET_WRITE_APP_DATA,

    /* DTO uses 0x10xx */
    BSL_UIO_DTO_SET_KEY = 0x1001,
    BSL_UIO_DTO_SET_EPOCH_SEQUENCE,
} BSL_UIO_CtrlParameter;

typedef enum {
    BSL_UIO_CREATE_CB,
    BSL_UIO_DESTROY_CB,
    BSL_UIO_WRITE_CB,
    BSL_UIO_READ_CB,
    BSL_UIO_CTRL_CB,
    BSL_UIO_PUTS_CB,
    BSL_UIO_GETS_CB,
} BSL_UIO_METHOD_TYPE;

typedef struct {
    uint8_t *addr;
    uint32_t size;
} BSL_UIO_CtrlGetPeerIpAddrParam;

#define BSL_UIO_FILE_READ             0x02
#define BSL_UIO_FILE_WRITE            0x04
#define BSL_UIO_FILE_APPEND           0x08
#define BSL_UIO_FILE_TEXT             0x10

#define BSL_UIO_FLAGS_READ          0x01
#define BSL_UIO_FLAGS_WRITE         0x02
#define BSL_UIO_FLAGS_IO_SPECIAL    0x04
#define BSL_UIO_FLAGS_RWS (BSL_UIO_FLAGS_READ | BSL_UIO_FLAGS_WRITE | BSL_UIO_FLAGS_IO_SPECIAL)
#define BSL_UIO_FLAGS_SHOULD_RETRY  0x08

#define BSL_UIO_FLAGS_MEM_READ_ONLY      0x10 /* This flag can be set only by uio_mem */

#define BSL_UIO_FLAGS_BASE64_NO_NEWLINE  0x20
#define BSL_UIO_FLAGS_BASE64_PEM         0x40



/**
 * @ingroup bsl_uio
 * @brief   Creating uio method structure
 *
 * @retval  uio method structure pointer
 */
BSL_UIO_Method *BSL_UIO_NewMethod(void);

/**
 * @ingroup bsl_uio
 * @brief   set uio method type
 *
 * @param   meth  [IN] uio method structure
 * @param   type  [IN] type
 * @retval #BSL_SUCCESS
 * @retval #BSL_NULL_INPUT
 */
int32_t BSL_UIO_SetMethodType(BSL_UIO_Method *meth, BSL_UIO_TransportType type);

/**
 * @ingroup bsl_uio
 * @brief   set uio method callback
 *
 * @param   meth  [IN] uio method structure
 * @param   type  [IN] callback type
 * @param   func  [IN] callback pointer
 * @retval #BSL_SUCCESS
 * @retval #BSL_INVALID_ARG
 */
int32_t BSL_UIO_SetMethod(BSL_UIO_Method *meth, int32_t type, void *func);

/**
 * @ingroup bsl_uio
 * @brief   free uio Method
 *
 * @param   meth  [IN] uio method structure
 * @retval  void
 */
void BSL_UIO_FreeMethod(BSL_UIO_Method *meth);

/**
 * @ingroup bsl_uio
 * @brief   obtain the default MEM UIO
 *
 * @retval  pointer to the MEM UIO method
 */
const BSL_UIO_Method *BSL_UIO_MemMethod(void);

/**
 * @ingroup bsl_uio
 *
 * @brief   obtain the default FILE UIO method
 * @return  pointer to the FILE UIO method
 */
const BSL_UIO_Method *BSL_UIO_FileMethod(void);

/**
 * @ingroup bsl_uio
 * @brief   obtain the default SCTP UIO
 *
 * @retval  pointer to the SCTP UIO method
 */
const BSL_UIO_Method *BSL_UIO_SctpMethod(void);

/**
 * @ingroup bsl_uio
 * @brief   obtain the default TCP UIO method
 *
 * @retval  pointer to the TCP UIO method
 */
const BSL_UIO_Method *BSL_UIO_TcpMethod(void);

/**
 * @ingroup bsl_uio
 * @brief   obtain the default UDP UIO method
 *
 * @retval  pointer to the UDP UIO method
 */
const BSL_UIO_Method *BSL_UIO_UdpMethod(void);

/**
 * @ingroup bsl_uio
 * @brief   obtain the default buffer UIO
 *
 * @retval  pointer to the Buffer UIO method
 */
const BSL_UIO_Method *BSL_UIO_BufferMethod(void);

/**
 * @ingroup bsl_uio
 * @brief   Create a UIO object
 *
 * @param   method  [IN] UIO method structure
 * @retval  UIO, created successfully
 * @retval  NULL UIO, creation failure
 */
BSL_UIO *BSL_UIO_New(const BSL_UIO_Method *method);

/**
 * @ingroup bsl_uio
 * @brief   Release the UIO object.
 *
 * @param   uio  [IN] UIO object.
 */
void BSL_UIO_Free(BSL_UIO *uio);

/**
 * @ingroup bsl_uio
 * @brief Write data to the UIO object
 *
 * @param uio  [IN] uio object.
 * @param data  [IN] Data to be written.
 * @param len  [IN] Data length.
 * @param writeLen [OUT] Length of the data that is successfully written.
 * @retval #BSL_SUCCESS, indicating that the data is successfully written.
 * @retval #BSL_INTERNAL_EXCEPTION, an unexpected internal error occurs.
 * @retval #BSL_UIO_IO_BUSY, indicating that the underlying I/O is busy.
 * @retval #BSL_UIO_IO_EXCEPTION, The I/O is abnormal.
 * @retval #BSL_UIO_FAIL,invalid parameter.
 */
int32_t BSL_UIO_Write(BSL_UIO *uio, const void *data, uint32_t len, uint32_t *writeLen);

/**
 * @ingroup bsl_uio
 * @brief   Read data from the UIO object.
 *
 * @param uio  [IN] uio object.
 * @param data  [IN] Buffer for receiving data
 * @param len  [IN] Length of the received data buffer.
 * @param readLen [OUT] Length of the received data.
 * @retval #BSL_SUCCESS, The data is read successfully(Determined based on the actual receive length,
 * if the length is 0 means no data is read.)
 * @retval #BSL_INTERNAL_EXCEPTION, an unexpected internal error occurs.
 * @retval #BSL_UIO_FAIL, invalid parameter.
 * @retval #BSL_UIO_IO_EXCEPTION, IO is abnormal.
 */
int32_t BSL_UIO_Read(BSL_UIO *uio, void *data, uint32_t len, uint32_t *readLen);

/**
 * @ingroup bsl_uio
 * @brief Process specific UIO implementations by cmd
 *
 * @param uio [IN] UIO object
 * @param cmd [IN] Different cmd processes perform different operations on UIO objects.
 * @param larg [IN] Determined by cmd. For details, see the following
 * @param parg [IN/OUT] Determined by cmd. For details, see the following
 * @retval #BSL_SUCCESS
 * @retval Non-BSL_SUCCESS, for details, see bsl_errno.h.
 *
 * @brief set the peer IP address in the UIO object
 *
 * The address format is a binary address in network byte order, with a length of 4 or 16 bytes.
 *           A generated cookie will be provided for use by the HelloVerifyRequest for dtls.
 *
 * @param uio [IN] UIO object
 * @param cmd [IN] BSL_UIO_SET_PEER_IP_ADDR
 * @param larg [IN] Size of the peer address: The length must be 4 or 16
 * @param parg [IN] Peer address
 *
 * @brief Obtain the peer IP address from the UIO object
 *
 * The obtained address is in the network byte order binary address format.
 * The input length must be greater than the configured size.
 * The purpose is to provide a generated cookie for use by the HelloVerifyRequest of the dtls.
 *
 * @param uio [IN] UIO object
 * @param cmd [IN] BSL_UIO_GET_PEER_IP_ADDR
 * @param larg [IN] 0
 * @param parg [IN] BSL_UIO_CtrlGetPeerIpAddrParam *, include:
 *             addr [IN/OUT] Peer address,
 *             size [IN/OUT] IN: size of the input buffer OUT: size of the output peer address
 *
 * @brief Obtain the stream ID sent by the SCTP from the UIO object.
 *
 * This API needs to be called by users in BSL_UIO_Method.write
 * and send SCTP messages based on the obtained stream ID
 *
 * @param uio [IN] UIO object
 * @param cmd [IN] BSL_UIO_SCTP_GET_SEND_STREAM_ID
 * @param larg [IN] 0
 * @param parg [IN/OUT] ID of the sent stream, uint16_t* Type
 *
 * @brief Set the stream ID of the app message sent by the SCTP in the UIO object.
 *
 * If a service message needs to be processed by a specific stream ID, this interface can be called.
 *
 * @param uio [IN] UIO object
 * @param cmd [IN] BSL_UIO_SCTP_SET_APP_STREAM_ID
 * @param larg [IN] App stream ID. The value ranges from 0 to 65535
 * @param parg [IN] NULL
 */
int32_t BSL_UIO_Ctrl(BSL_UIO *uio, int32_t cmd, int32_t larg, void *parg);

/**
 * @ingroup bsl_uio
 * @brief   Write a string to the UIO object.
 *
 * @param uio  [IN] uio object.
 * @param buf  [IN] A null-terminated string to be written.
 * @param writeLen [OUT] Length of the data that is successfully written.
 * @retval #BSL_SUCCESS, Writing succeeded.
 * @retval #BSL_INTERNAL_EXCEPTION, an unexpected internal error occurs.
 * @retval #BSL_UIO_IO_BUSY, indicating that the underlying I/O is busy.
 * @retval #BSL_UIO_IO_EXCEPTION, IO abnormal.
 * @retval #BSL_UIO_FAIL, invalid parameter.
 */
int32_t BSL_UIO_Puts(BSL_UIO *uio, const char *buf, uint32_t *writeLen);

/**
 * @ingroup bsl_uio
 * @brief   Reads a string from the UIO object
 *
 * @param uio  [IN] uio object.
 * @param buf  [IN] Buffer that accepts a line of strings
 * @param readLen [IN/OUT] Length of the buffer for receiving data/Length of the data that is successfully read
 * @retval #BSL_SUCCESS (Determine the value based on the actual receive length.
 * if the length is 0 means no data is read.)
 * @retval #BSL_INTERNAL_EXCEPTION, an unexpected internal error occurs.
 * @retval #BSL_UIO_FAIL, invalid parameter.
 * @retval #BSL_UIO_IO_EXCEPTION, IO abnormal.
 */
int32_t BSL_UIO_Gets(BSL_UIO *uio, char *buf, uint32_t *readLen);

/**
 * @ingroup bsl_uio
 * @brief Set the UIO init.
 *
 * @param uio [IN] UIO object
 * @param init [IN] init value
 */
void BSL_UIO_SetInit(BSL_UIO *uio, bool init);

/**
 * @ingroup bsl_uio
 * @brief   Obtain the UIO transmission protocol type
 *
 * @param   uio  [IN] UIO object.
 * @retval  protocol type
 */
BSL_UIO_TransportType BSL_UIO_GetTransportType(const BSL_UIO *uio);

/**
 * @ingroup bsl_uio
 *
 * @brief   Obtain the UIO transmission protocol type
 * @param   uio  [IN] UIO object.
 * @param   uioType [IN] Type of the protocol to be obtained.
 * @return  TRUE, Succeeded in obtaining the UIO type.
 * @return  FALSE, Failed to obtain the UIO type.
 */
bool BSL_UIO_GetUioChainTransportType(BSL_UIO *uio, const BSL_UIO_TransportType uioType);

/**
 * @ingroup bsl_uio
 * @brief   Set the user data in the UIO object
 *
 * UIO will not modify the user data, user can add some information
 * for the UIO, and get the information by use BSL_UIO_GetUserData function; After you set user data by calling
 * BSL_UIO_SetUserData, you need to call BSL_UIO_SetUserData again before calling BSL_UIO_Free to set
 * user data to null to ensure that all memory is released.
 *
 * @param   uio   [IN] UIO object.
 * @param   data  [IN] User data pointer
 * @retval  #BSL_SUCCESS, success.
 * @retval  #BSL_NULL_INPUT, invalid null pointer.
 */
int32_t BSL_UIO_SetUserData(BSL_UIO *uio, void *data);

/**
 * @ingroup bsl_uio
 * @brief   Release the user data set in the UIO object.
 *
 * Free uio->userData at BSL_UIO_Free.
 *
 * @param   uio   [IN] UIO object
 * @param   data  [IN] Pointer to the function for releasing user data
 * @retval  #BSL_SUCCESS, success.
 * @retval  #BSL_NULL_INPUT, invalid null pointer.
 */
int32_t BSL_UIO_SetUserDataFreeFunc(BSL_UIO *uio, BSL_UIO_USERDATA_FREE_FUNC userDataFreeFunc);

/**
 * @ingroup bsl_uio
 * @brief   Obtain the user data in the UIO object.
 *
 * The user data comes from users, and tls will not change any thing
 * for user data, user can add some customize information.
 *
 * @param   uio   [IN] UIO object.
 * @retval  Succeeded in obtaining the data structure pointer stored by the user.
 * @retval  NULL, the obtained data does not exist.
 */
void *BSL_UIO_GetUserData(const BSL_UIO *uio);

/**
 * @ingroup bsl_uio
 * @brief Obtains whether resources associated with the UIO are closed by the UIO.
 *
 * @param uio [OUT] UIO object
 * @retval ture The resources associated with the UIO are closed by the UIO.
 * @retval false The resources associated with the UIO are not closed by the UIO.
 */
bool BSL_UIO_GetIsUnderlyingClosedByUio(const BSL_UIO *uio);

/**
 * @ingroup bsl_uio
 * @brief Set whether resources associated with the UIO are closed by the UIO.
 *
 * @param uio [IN/OUT] UIO object
 * @param close [IN] true UIO-associated resources are closed by the UIO.
 *                   false The resources associated with the UIO are not closed by the UIO.
 */
void BSL_UIO_SetIsUnderlyingClosedByUio(BSL_UIO *uio, bool close);

/**
 * @ingroup bsl_uio
 * @brief Method for obtaining the UIO
 *
 * @param uio [IN/OUT] UIO object
 * @retval UIO method
 */
const BSL_UIO_Method *BSL_UIO_GetMethod(const BSL_UIO *uio);

/**
 * @ingroup bsl_uio
 * @brief Obtain the implementation-related context.
 *
 * @param uio [IN] UIO object
 * @retval Implementation-related context pointer
 */
void *BSL_UIO_GetCtx(const BSL_UIO *uio);

/**
 * @ingroup bsl_uio
 * @brief Set the implementation-related context.
 *
 * @param uio [IN] UIO object
 * @param ctx [IN] Implement the relevant context pointer.
 */
void BSL_UIO_SetCtx(BSL_UIO *uio, void *ctx);

/**
 * @ingroup bsl_uio
 * @brief   Set the fd of the UIO object
 *
 * @param   uio [IN] UIO object
 * @param   fd [IN] File Descriptor fd
 */
void BSL_UIO_SetFD(BSL_UIO *uio, int fd);

/**
 * @ingroup bsl_uio
 * @brief Set the UIO object flag.
 *
 * @param uio [IN] UIO object
 * @param flags [IN] flag
 * @retval #BSL_SUCCESS, succeeded.
 * @retval Other reference: bsl_errno.h.
 */
int32_t BSL_UIO_SetFlags(BSL_UIO *uio, uint32_t flags);

/**
 * @ingroup bsl_uio
 * @brief Clear the UIO object flag
 *
 * @param uio [IN] UIO object
 * @param flags [IN] flag
 * @retval #BSL_SUCCESS, succeeded.
 * @retval Other reference: bsl_errno.h.
 */
int32_t BSL_UIO_ClearFlags(BSL_UIO *uio, uint32_t flags);

/**
 * @ingroup bsl_uio
 * @brief Check the UIO object flag
 *
 * @param uio [IN] UIO object
 * @param flags [IN] To-be-checked flag
 * @param out [OUT] Mark the detection result
 * @retval #BSL_SUCCESS, succeeded.
 * @retval Other reference: bsl_errno.h
 */
uint32_t BSL_UIO_TestFlags(const BSL_UIO *uio, uint32_t flags, uint32_t *out);

/**
 * @ingroup bsl_uio
 * @brief    Set the value of uio reference counting to 1
 *
 * @attention Call BSL_UIO_Free to decrease the value of reference counting by 1
 * @param   uio [IN] uio object
 * @retval #BSL_SUCCESS, the setting is successful.
 * @retval #BSL_INTERNAL_EXCEPTION, an unexpected internal error occurs.
 * @retval #BSL_UIO_REF_MAX, The number of UIO objects has reached the maximum.
 */
int32_t BSL_UIO_UpRef(BSL_UIO *uio);

/**
 * @ingroup bsl_uio
 * @brief   Add a UIO object to the tail of the chain.
 *
 * @attention The reference counting of the added UIO object will not increase by 1.
 * @param   uio [IN] uio object
 * @param   tail [IN] UIO object added to the tail
 * @retval #BSL_SUCCESS, success.
 * @retval Non-BSL_SUCCESS, failure. For details, see bsl_errno.h.
 */
int32_t BSL_UIO_Append(BSL_UIO *uio, BSL_UIO *tail);

/**
 * @ingroup bsl_uio
 * @brief   Pop UIO object from the chain.
 *
 * @attention The reference counting of the added UIO object does not decrease by 1.
 * @param   uio [IN] UIO object of the pop-up link.
 * @retval The next UIO object in the chain.
 */
BSL_UIO *BSL_UIO_PopCurrent(BSL_UIO *uio);

/**
 * @ingroup bsl_uio
 * @brief   Release UIO object b and its subsequent chains.
 *
 * @attention: The release starts from b.
 * If the reference counting of a UIO object in the chain is greater than or equal to 1, the release stops
 * @param   uio [IN] First UIO object in the UIO object chain to be released
 */
void BSL_UIO_FreeChain(BSL_UIO *uio);

/**
 * @ingroup bsl_uio
 * @brief   Obtain the next UIO object in the chain.
 *
 * @param   uio [IN] UIO object
 * @retval Next UIO object in the chain.
 */
BSL_UIO *BSL_UIO_Next(BSL_UIO *uio);

#ifdef __cplusplus
}
#endif

#endif // BSL_UIO_H
