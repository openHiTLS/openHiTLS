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
 * @defgroup bsl_sal
 * @ingroup bsl
 * @brief System Abstraction Layer
 */

#ifndef BSL_SAL_H
#define BSL_SAL_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup bsl_sal
 *
 * Thread lock handle, the corresponding structure is provided by the user during registration.
 */
typedef void *BSL_SAL_ThreadLockHandle;

/**
 * @ingroup bsl_sal
 *
 * Thread handle, the corresponding structure is provided by the user during registration.
 */
typedef void *BSL_SAL_ThreadId;

/**
 * @ingroup bsl_sal
 *
 * mutex
 */
typedef void *BSL_SAL_Mutex;

/**
 * @ingroup bsl_sal
 *
 * Condition handle, the corresponding structure is provided by the user during registration.
 */
typedef void *BSL_SAL_CondVar;

/**
 * @ingroup bsl_sal
 * @brief Allocate memory space.
 *
 * Allocate memory space.
 *
 * @attention None
 * @param size [IN] Size of the allocated memory
 * @retval If the application is successful, returned the pointer pointing to the memory.
 * @retval If the application failed, return NULL.
 */
void *BSL_SAL_Malloc(uint32_t size);

/**
 * @ingroup bsl_sal
 * @brief Allocate and clear the memory space.
 *
 * Allocate and clear the memory space. The maximum size of UINT32_MAX is allocated.
 *
 * @attention num*size should not have overflow wrap.
 * @param num [IN] Number of allocated memory.
 * @param size [IN] Size of each memory.
 * @retval If the application is successful, returned the pointer pointing to the memory.
 * @retval If the application failed, return NULL.
 */
void *BSL_SAL_Calloc(uint32_t num, uint32_t size);

/**
 * @ingroup bsl_sal
 * @brief   Duplicate the memory space.
 *
 * @param   src Source memory address
 * @param   size Total memory size
 * @retval  If the allocation is successful, returned the pointer pointing to the memory.
 * @retval  If the allocation failed, return NULL.
 */
void *BSL_SAL_Dump(const void *src, uint32_t size);

/**
 * @ingroup bsl_sal
 * @brief Release the specified memory.
 *
 * Release the specified memory.
 *
 * @attention NONE.
 * @param value [IN] Pointer to the memory space to be released.
 */
void BSL_SAL_Free(void *value);

/**
 * @ingroup bsl_sal
 * @brief Memory expansion
 *
 * Memory expansion function.
 *
 * @attention None.
 * @param addr    [IN] Original memory address.
 * @param newSize [IN] Extended memory size.
 * @param oldSize [IN] Memory size before expansion.
 * @retval void*   indicates successful, the extended memory address is returned.
 * @retval NULL    indicates failed, return NULL.
 */
void *BSL_SAL_Realloc(void *addr, uint32_t newSize, uint32_t oldSize);

/**
 * @ingroup bsl_sal
 * @brief Set sensitive information to zero.
 *
 * @param ptr [IN] Memory to be zeroed
 * @param size [IN] Length of the memory to be zeroed out
 */
void BSL_SAL_CleanseData(void *ptr, uint32_t size);

/**
 * @ingroup bsl_sal
 * @brief Clear sensitive information and release memory.
 *
 * @param ptr [IN] Pointer to the memory to be released
 * @param size [IN] Length of the memory to be zeroed out
 */
void BSL_SAL_ClearFree(void *ptr, uint32_t size);

#define BSL_SAL_FREE(value_)                        \
    do {                                        \
        if ((value_) != NULL) {                 \
            BSL_SAL_Free((void *)(value_));         \
            (value_) = NULL;                    \
        }                                       \
    } while (0)

#define BSL_SAL_ONCE_INIT 0 // equal to PTHREAD_ONCE_INIT, the pthread symbol is masked.

/**
 * @ingroup bsl_sal
 * @brief Create a thread lock.
 *
 * Create a thread lock.
 *
 * @attention none
 * @param lock [IN/OUT] Lock handle
 * @retval #BSL_SUCCESS, created successfully.
 * @retval #BSL_MALLOC_FAIL, memory space is insufficient and failed to apply for process lock space.
 * @retval #BSL_SAL_ERR_UNKNOWN, thread lock initialization failed.
 * @retval #BSL_SAL_ERR_BAD_PARAM, parameter error, the value of lock is NULL.
 */
int32_t BSL_SAL_ThreadLockNew(BSL_SAL_ThreadLockHandle *lock);

/**
 * @ingroup bsl_sal
 * @brief Lock the read operation.
 *
 * Lock the read operation.
 *
 * @attention none
 * @param lock [IN] Lock handle
 * @retval #BSL_SUCCESS, succeeded.
 * @retval #BSL_SAL_ERR_UNKNOWN, operation failed.
 * @retval #BSL_SAL_ERR_BAD_PARAM, parameter error. The value of lock is NULL.
 */
int32_t BSL_SAL_ThreadReadLock(BSL_SAL_ThreadLockHandle lock);

/**
 * @ingroup bsl_sal
 * @brief Lock the write operation.
 *
 * Lock the write operation.
 *
 * @attention none
 * @param lock [IN] Lock handle
 * @retval #BSL_SUCCESS, succeeded.
 * @retval #BSL_SAL_ERR_UNKNOWN, operation failed.
 * @retval #BSL_SAL_ERR_BAD_PARAM, parameter error. The value of lock is NULL.
 */
int32_t BSL_SAL_ThreadWriteLock(BSL_SAL_ThreadLockHandle lock);

/**
 * @ingroup bsl_sal
 * @brief Unlock
 *
 * Unlock
 *
 * @attention unlock: Locks that have been unlocked are undefined behavior and are not allowed by default.
 * @param lock [IN] Lock handle
 * @retval #BSL_SUCCESS, succeeded.
 * @retval #BSL_SAL_ERR_UNKNOWN operation failed.
 * @retval #BSL_SAL_ERR_BAD_PARAM parameter error. The value of lock is NULL.
 */
int32_t BSL_SAL_ThreadUnlock(BSL_SAL_ThreadLockHandle lock);

/**
 * @ingroup bsl_sal
 * @brief Release the thread lock.
 *
 * Release the thread lock.
 *
 * @attention By default, repeated release is prohibited.
 * @param lock [IN] Lock handle.
 */
void BSL_SAL_ThreadLockFree(BSL_SAL_ThreadLockHandle lock);

/**
 * @ingroup bsl_sal
 * @brief Obtain the thread ID.
 *
 * Obtain the thread ID.
 *
 * @attention none
 * @retval Thread ID
 */
uint64_t BSL_SAL_ThreadGetId(void);

/**
 * @ingroup bsl_sal
 * @brief Obtain the process ID.
 *
 * Obtain the process ID.
 *
 * @attention none
 * @retval Process ID
 */
int32_t BSL_SAL_GetPid(void);

/**
 * @ingroup bsl_sal
 * @brief run once: Use the initialization callback.
 *
 * @attention This function should not be a cancel, otherwise the default implementation of run
 * once seems to have never been called.
 */
typedef void (*BSL_SAL_ThreadInitRoutine)(void);

/**
 * @ingroup bsl_sal
 * @brief Execute only once.
 *
 * Run the init Func command only once.
 *
 * @attention The current version does not support registration.
 * @param onceControl [IN] Record the execution status.
 * @param initFunc [IN] Initialization function.
 * @retval #BSL_SUCCESS, succeeded.
 * @retval #BSL_SAL_ERR_BAD_PARAM, input parameter is abnormal.
 * @retval #BSL_SAL_ERR_UNKNOWN, the default run once failed.
 */
int32_t BSL_SAL_ThreadRunOnce(uint32_t *onceControl, BSL_SAL_ThreadInitRoutine initFunc);

/**
 * @ingroup bsl_sal
 * @brief Create a thread.
 *
 * Create a thread.
 *
 * @attention none
 * @param thread [IN/OUT] Thread ID
 * @param startFunc [IN] Thread function
 * @param arg [IN] Thread function parameters
 * @retval #BSL_SUCCESS, created successfully.
 * @retval #BSL_SAL_ERR_UNKNOWN, Failed to create a thread.
 * @retval #BSL_SAL_ERR_BAD_PARAM, parameter error.
 */
int32_t BSL_SAL_ThreadCreate(BSL_SAL_ThreadId *thread, void *(*startFunc)(void *), void *arg);

/**
 * @ingroup bsl_sal
 * @brief Close the thread.
 *
 * Close the thread.
 *
 * @attention none
 * @param thread [IN] Thread ID
 */
void BSL_SAL_ThreadClose(BSL_SAL_ThreadId thread);

/**
 * @ingroup bsl_sal
 * @brief Create a condition variable.
 *
 * Create a condition variable.
 *
 * @attention none
 * @param condVar [IN] Condition variable
 * @retval #BSL_SUCCESS, created successfully.
 * @retval #BSL_SAL_ERR_UNKNOWN, failed to create a condition variable.
 * @retval #BSL_SAL_ERR_BAD_PARAM, parameter error. The value of condVar is NULL.
 */
int32_t BSL_SAL_CreateCondVar(BSL_SAL_CondVar *condVar);

/**
 * @ingroup bsl_sal
 * @brief The waiting time ends or the signal is obtained.
 *
 * The waiting time ends or the signal is obtained.
 *
 * @attention None
 * @param condVar [IN] Condition variable
 * @retval #BSL_SUCCESS, succeeded.
 * @retval #BSL_SAL_ERR_UNKNOWN, function failure
 * @retval #BSL_SAL_ERR_BAD_PARAM, parameter error. The value of condVar is NULL.
 */
int32_t BSL_SAL_CondSignal(BSL_SAL_CondVar condVar);

/**
 * @ingroup bsl_sal
 * @brief The waiting time ends or the signal is obtained.
 *
 * The waiting time ends or the signal is obtained.
 *
 * @attention None
 * @param condMutex [IN] Mutex
 * @param condVar [IN] Condition variable
 * @param timeout [IN] Time
 * @retval #BSL_SUCCESS, succeeded.
 * @retval #BSL_SAL_ERR_UNKNOWN, fails.
 * @retval #BSL_SAL_ERR_BAD_PARAM, parameter error. The value of condMutex or condVar is null.
 */
int32_t BSL_SAL_CondTimedwaitMs(BSL_SAL_Mutex condMutex, BSL_SAL_CondVar condVar, int32_t timeout);

/**
 * @ingroup bsl_sal
 * @brief Delete a condition variable.
 *
 * Delete a condition variable.
 *
 * @attention none
 * @param condVar [IN] Condition variable
 * @retval #BSL_SUCCESS, Succeeded in deleting the condition variable.
 * @retval #BSL_SAL_ERR_UNKNOWN, Failed to delete the condition variable.
 * @retval #BSL_SAL_ERR_BAD_PARAM, parameter error. The value of condVar is NULL.
 */
int32_t BSL_SAL_DeleteCondVar(BSL_SAL_CondVar condVar);

typedef void *bsl_sal_file_handle; // Pointer to file handle

/**
 * @ingroup bsl_sal
 * @brief Open a file.
 *
 * Open the file and ensure that the entered path is standardized.
 *
 * @attention None
 * @param stream [OUT] File handle
 * @param path [IN] File path
 * @param mode [IN] Reading mode
 * @retval #BSL_SUCCESS, succeeded.
 * @retval #BSL_SAL_ERR_FILE_OPEN, failed to be opened.
 * @retval #BSL_NULL_INPUT, parameter error.
 */
int32_t BSL_SAL_FileOpen(bsl_sal_file_handle *stream, const char *path, const char *mode);

/**
 * @ingroup bsl_sal
 * @brief Close the file.
 *
 * Close the file.
 *
 * @attention none
 * @param stream [IN] File handle
 * @retval NA
 */
void BSL_SAL_FileClose(bsl_sal_file_handle stream);

/**
 * @ingroup bsl_sal
 * @brief   Read the file.
 *
 * Read the file.
 * The actual memory of the interface is 1 more than the real length of the read file,
 * which is used to add '\0' after the end of the read file content, and the outgoing parameter len is the real
 * data length, excluding '\0'.
 *
 * @attention none
 * @param stream [IN] File handle
 * @param buffer [IN] Buffer for reading data
 * @param size [IN] The unit of reading.
 * @param num [IN] Number of data records to be read
 * @param len [OUT] Read the data length.
 * @retval #BSL_SUCCESS, succeeded.
 * @retval #BSL_SAL_ERR_UNKNOWN, fails.
 * @retval #BSL_NULL_INPUT, Incorrect parameter
 */
int32_t BSL_SAL_FileRead(bsl_sal_file_handle stream, void *buffer, size_t size, size_t num, size_t *len);

/**
 * @ingroup bsl_sal
 * @brief Write a file
 *
 * Write File
 *
 * @attention none
 * @param stream [IN] File handle
 * @param buffer [IN] Data to be written
 * @param size [IN] Write the unit
 * @param num [IN] Number of written data
 * @retval #BSL_SUCCESS, succeeded
 * @retval #BSL_SAL_ERR_UNKNOWN, fails
 * @retval #BSL_NULL_INPUT, parameter error
 */
int32_t BSL_SAL_FileWrite(bsl_sal_file_handle stream, const void *buffer, size_t size, size_t num);

/**
 * @ingroup bsl_sal
 * @brief Obtain the file length.
 *
 * Obtain the file length.
 *
 * @attention none
 * @param path [IN] File path
 * @param len [OUT] File length
 * @retval #BSL_SUCCESS, succeeded
 * @retval #BSL_SAL_ERR_UNKNOWN, fails
 * @retval #BSL_NULL_INPUT, parameter error
 */
int32_t BSL_SAL_FileLength(const char *path, size_t *len);

/**
 * @ingroup bsl_sal
 * @brief Basic time data structure definition.
 */
typedef struct {
    uint16_t year;      /**< Year. the value range is [0, 65535]. */
    uint8_t  month;     /**< Month. the value range is [1, 12]. */
    uint8_t  day;       /**< Day, the value range is [1, 31]. */
    uint8_t  hour;      /**< Hour, the value range is [0, 23]. */
    uint8_t  minute;    /**< Minute, the value range is [0, 59]. */
    uint16_t millSec;   /**< Millisecond, the value range is [0, 999]. */
    uint8_t  second;    /**< Second, the value range is [0, 59]. */
    uint16_t microSec;  /**< Microseconds, the value range is [0, 999]. */
} BSL_TIME;

/**
 * @ingroup bsl_sal
 * @brief Unix Time structure definition.
 */
typedef int64_t BslUnixTime;

/**
 * @ingroup bsl_sal
 * @brief Prototype of the callback function for obtaining the time
 *
 * Prototype definition of the callback function for obtaining the time.
 */
typedef BslUnixTime (*BslTimeFunc)(void);

/**
 * @ingroup bsl_sal
 * @brief Interface for registering the function for obtaining the system time
 * You can use this API to register the system time obtaining function.
 *
 * This interface can be registered for multiple times. After the registration is
 * successful, the registration cannot be NULL again.
 * Description of the time range:
 * Users can use the Linux system at most 2038 per year.
 * The lower limit of the time is 1970 - 1 - 1 0: 0: 0.
 * It is recommended that users use this minimum intersection, i.e., the bounds of
 * years are 1970-1-1 0:0:0 ~ 2038-01-19 03:14:08.
 *
 * @param func [IN] Register the function for obtaining the system time
 */
void BSL_SAL_SysTimeFuncReg(BslTimeFunc func);

/**
 * @ingroup bsl_sal
 * @brief   Compare Two Dates
 *
 * @param   dateA [IN] The first date
 * @param   dateB [IN] The second date
 * @param   diffSeconds [OUT] Number of seconds between two dates
 * @retval  BslTimeCmpResult Comparison result of two dates
 * @retval  #BSL_TIME_CMP_ERROR - Error in comparison
 * @retval  #BSL_TIME_CMP_EQUAL - The two dates are consistent.
 * @retval  #BSL_TIME_DATE_BEFORE - The first date is before the second date.
 * @retval  #BSL_TIME_DATE_AFTER - The first date is after the second
 */
int32_t BSL_SAL_DateTimeCompare(const BSL_TIME *dateA, const BSL_TIME *dateB, int64_t *diffSec);

/**
 * @ingroup bsl_sal
 * @brief Obtain the system time.
 *
 * Obtain the system time.
 *
 * @attention none
 * @param sysTime [out] Time
 * @retval #BSL_SUCCESS, obtained the time successfully.
 * @retval #BSL_SAL_ERR_BAD_PARAM, the value of cb is null.
 * @retval #BSL_INTERNAL_EXCEPTION, an exception occurred when obtaining the time.
 */
int32_t BSL_SAL_SysTimeGet(BSL_TIME *sysTime);

/**
 * @ingroup bsl_sal
 * @brief Obtain the Unix time.
 *
 * Obtain the Unix time.
 *
 * @retval Return the Unix time.
 */
BslUnixTime BSL_SAL_CurrentSysTimeGet(void);

/**
 * @ingroup bsl_sal
 * @brief Convert the date in the BslSysTime format to the UTC time format.
 *
 * Convert the date in the BslSysTime format to the UTC time format.
 *
 * @attention None
 * @param dateTime [IN] Date and time
 * @param utcTime [OUT] UTC time
 * @retval #BSL_SUCCESS, time is successfully converted.
 * @retval #BSL_INTERNAL_EXCEPTION, an exception occurred when obtaining the time.
 */
int32_t BSL_SAL_DateToUtcTimeConvert(const BSL_TIME *dateTime, int64_t *utcTime);

/**
 * @ingroup bsl_sal
 * @brief Convert the date in the BslUnixTime format to the BslSysTime format.
 *
 * Convert the date in the BslUnixTime format to the BslSysTime format.
 *
 * @attention none
 * @param utcTime [IN] UTC time
 * @param sysTime [OUT] BslSysTime Time
 * @retval #BSL_SUCCESS, time is converted successfully
 * @retval #BSL_SAL_ERR_BAD_PARAM, the value of utcTime exceeds the upper limit or the value of sysTime is null.
 */
int32_t BSL_SAL_UtcTimeToDateConvert(int64_t utcTime, BSL_TIME *sysTime);

/**
 * @ingroup bsl_sal
 * @brief Compare two dates, accurate to microseconds.
 *
 * Compare two dates, accurate to microseconds
 *
 * @attention None
 * @param dateA [IN] Time
 * @param dateB [IN] Time
 * @retval #BslTimeCmpResult Comparison result of two dates
 * @retval #BSL_TIME_CMP_ERROR - An error occurred in the comparison.
 * @retval #BSL_TIME_CMP_EQUAL - The two dates are consistent.
 * @retval #BSL_TIME_DATE_BEFORE - The first date is on the second
 * @retval #BSL_TIME_DATE_ AFTER - The first date is after the second
 */
int32_t BSL_SAL_DateTimeCompareByUs(const BSL_TIME *dateA, const BSL_TIME *dateB);

/**
 * @ingroup bsl_sal
 * @brief   Sleep the current thread
 *
 * Sleep the current thread
 *
 * @attention none
 * @param time [IN] Sleep time
 */
void BSL_SAL_Sleep(uint32_t time);

/**
 * @ingroup bsl_sal
 * @brief   Obtain the number of ticks that the system has experienced since startup.
 *
 * Obtain the system time.
*
 * @attention none
 * @retval Number of ticks
 */
long BSL_SAL_Tick(void);

/**
 * @ingroup bsl_sal
 * @brief   Obtain the number of system ticks per second.
 *
 * Obtain the system time.
 *
 * @attention none
 * @retval Number of ticks per second
 */
long BSL_SAL_TicksPerSec(void);

/**
 * @ingroup  bsl_sal_net
 * @brief socket address.
 * 
 * It should be defined like following union in linux, to cover various socket addresses.
 *     union SockAddr {
 *         struct sockaddr addr;
 *         struct sockaddr_in6 addrIn6;
 *         struct sockaddr_in addrIn;
 *         struct sockaddr_un addrUn;
 *     };
 *
 */
typedef void *BSL_SAL_SockAddr;

/**
 * @ingroup bsl_sal
 * @brief   Socket address information
 * 
 * It should be defined like 'struct addinfo' in linux,
 *        struct addrinfo {
 *            int              ai_flags;
 *            int              ai_family;
 *            int              ai_socktype;
 *            int              ai_protocol;
 *            socklen_t        ai_addrlen;
 *            struct sockaddr *ai_addr;
 *            char            *ai_canonname;
 *            struct addrinfo *ai_next;
 *        };
 */
typedef void *BSL_SAL_SockAddrInfo;

/**
 * @ingroup bsl_sal
 * @brief   Create a BSL_SAL_SockAddr
 *
 * @return New BSL_SAL_SockAddr object
 */
typedef int32_t (*BslSalSockAddrNew)(BSL_SAL_SockAddr *sockAddr);

/**
 * @ingroup bsl_sal
 * @brief   Release the UIO_Addr object.
 *
 * @param   uioAddr [IN] UIO_Addr object
 */
typedef void (*BslSalSockAddrFree)(BSL_SAL_SockAddr sockAddr);

/**
 * @ingroup bsl_sal
 * @brief   Obtain the size of the BSL_SAL_SockAddr address.
 * @details Only for internal use
 *
 * @param   sockAddr   [IN] UIO object
 * @retval  Address size, if the address is not valid, return 0
 */
typedef uint32_t (*BslSalSockAddrSize)(const BSL_SAL_SockAddr sockAddr);

/**
 * @ingroup bsl_sal
 * @brief   Copy the BSL_SAL_SockAddr address.
 *
 * @param   src [IN] Source address
 * @param   dst [OUT] Destination address
 */
typedef void (*BslSalSockAddrCopy)(BSL_SAL_SockAddr dst, const BSL_SAL_SockAddr src);

/**
 * @ingroup bsl_sal
 * @brief   Socket creation interface
 *
 * Socket creation interface.
 *
 * @attention none
 * @param af [IN] Socket specifies the protocol set.
 * @param type [IN] Socket type
 * @param protocol [IN] Protocol type
 * @retval If the creation is successful, a non-negative value is returned.
 * @retval Otherwise, a negative value is returned.
 */
int32_t BSL_SAL_Socket(int32_t af, int32_t type, int32_t protocol);

/**
 * @ingroup bsl_sal
 * @brief Close the socket
 *
 * Close the socket
 *
 * @attention none
 * @param sockId [IN] Socket file descriptor ID
 * @retval If the operation succeeds, BSL_SUCCESS is returned.
 * @retval If the operation fails, BSL_SAL_ERR_NET_SOCKCLOSE is returned.
 */
int32_t BSL_SAL_SockClose(int32_t sockId);

/**
 * @ingroup bsl_sal
 * @brief   Set the socket
 *
 * Set the socket
 *
 * @attention none
 * @param sockId [IN] Socket file descriptor ID
 * @param level [IN] Level of the option to be set.
 * @param name [IN] Options to be set
 * @param val [IN] Value of the option.
 * @param len [IN] val Length
 * @retval If the operation succeeds, BSL_SUCCESS is returned
 * @retval If the operation fails, BSL_SAL_ERR_NET_SETSOCKOPT is returned.
 */
int32_t BSL_SAL_SetSockopt(int32_t sockId, int32_t level, int32_t name, const void *val, int32_t len);

/**
 * @ingroup bsl_sal
 * @brief   Get the socket
 *
 * Get the socket
 *
 * @attention none
 * @param sockId [IN] Socket file descriptor ID
 * @param level [IN] Level of the option to be set.
 * @param name [IN] Options to be set
 * @param val [OUT] Value of the option.
 * @param len [OUT] val Length
 * @retval If the operation succeeds, BSL_SUCCESS is returned
 */
int32_t BSL_SAL_GetSockopt(int32_t sockId, int32_t level, int32_t name, void *val, int32_t *len);

/**
 * @ingroup bsl_sal
 * @brief Listening socket
 *
 * Listen socket
 *
 * @attention none
 * @param sockId [IN] Socket file descriptor ID
 * @param backlog [IN] Length of the receiving queue
 * @retval If the operation succeeds, BSL_SUCCESS is returned.
 * @retval If the operation fails, BSL_SAL_ERR_NET_LISTEN is returned.
 */
int32_t BSL_SAL_SockListen(int32_t sockId, int32_t backlog);

/**
 * @ingroup bsl_sal
 * @brief Binding a socket
 *
 * Binding Socket
 *
 * @attention None
 * @param sockId [IN] Socket file descriptor ID
 * @param addr [IN] Specify the address.
 * @param len [IN] Address length
 * @retval If the operation succeeds, BSL_SUCCESS is returned.
 * @retval If the operation fails, BSL_SAL_ERR_NET_BIND is returned.
 */
int32_t BSL_SAL_SockBind(int32_t sockId, BSL_SAL_SockAddr addr, size_t len);

/**
 * @ingroup bsl_sal
 * @brief Initiate a connection.
 *
 * Initiate a connection.
 *
 * @attention none
 * @param sockId [IN] Socket file descriptor ID
 * @param addr [IN] Address to be connected
 * @param len [IN] Address length
 * @retval If the operation succeeds, BSL_SUCCESS is returned
 * @retval If the operation fails, BSL_SAL_ERR_NET_CONNECT is returned.
 */
int32_t BSL_SAL_SockConnect(int32_t sockId, BSL_SAL_SockAddr addr, size_t len);

/**
 * @ingroup bsl_sal
 * @brief   Send a message.
 *
 * Send messages
 *
 * @attention none
 * @param sockId [IN] Socket file descriptor ID
 * @param msg [IN] Message sent
 * @param len [IN] Information length
 * @param flags [IN] is generally set to 0.
 * @retval If the operation succeeds, the length of the sent data is returned.
 * @retval If the operation fails, a negative value is returned.
 * @retval If the operation times out or the peer end disables the function, the value 0 is returned.
 */
int32_t BSL_SAL_SockSend(int32_t sockId, const void *msg, size_t len, int32_t flags);

/**
 * @ingroup bsl_sal
 * @brief Receive the message.
 *
 * Receive information
 *
 * @attention none
 * @param sockfd [IN] Socket file descriptor ID
 * @param buff [IN] Buffer for receiving information
 * @param len [IN] Length of the buffer
 * @param flags [IN] is generally set to 0.
 * @retval If the operation succeeds, the received data length is returned.
 * @retval If the operation fails, a negative value is returned.
 * @retval If the operation times out or the peer end disables the function, the value 0 is returned.
 */
int32_t BSL_SAL_SockRecv(int32_t sockfd, void *buff, size_t len, int32_t flags);

/**
 * @ingroup bsl_sal
 * @brief   Check the socket descriptor.
 *
 * Check the socket descriptor.
 *
 * @attention None
 * @param nfds [IN] Total number of file descriptors that are listened on
 * @param readfds [IN] Readable file descriptor (optional)
 * @param writefds [IN] Descriptor of a writable file. This parameter is optional.
 * @param exceptfds [IN] Exception file descriptor (optional)
 * @param timeout [IN] Set the timeout interval.
 * @retval If the operation succeeds, Number of ready descriptors are returned;
 * @retval If the operation fails, a negative value is returned;
 * @retval If the operation times out, 0 is returned
 */
int32_t BSL_SAL_Select(int32_t nfds, void *readfds, void *writefds, void *exceptfds, void *timeout);

/**
 * @ingroup bsl_sal
 * @brief   Device control interface function
 *
 * Device control interface function
 *
 * @attention None
 * @param sockId [IN] Socket file descriptor ID
 * @param cmd [IN] Interaction protocol
 * @param arg [IN] Parameter
 * @retval If the operation succeeds, BSL_SUCCESS is returned.
 * @retval If the operation fails, BSL_SAL_ERR_NET_IOCTL is returned.
 */
int32_t BSL_SAL_Ioctlsocket(int32_t sockId, long cmd, unsigned long *arg);

/**
 * @ingroup bsl_sal
 * @brief   Obtain the last error corresponding to the socket.
 *
 * Obtain the last error corresponding to the socket.
 *
 * @attention none
 * @retval Return the corresponding error.
 */
int32_t BSL_SAL_SockGetLastSocketError(void);

/**
 * @ingroup bsl_sal
 * @brief String comparison
 *
 * String comparison
 *
 * @attention None.
 * @param str1 [IN] First string to be compared.
 * @param str2 [IN] Second string to be compared.
 * @retval If the parameter is abnormal, BSL_NULL_INPUT is returned.
 * @retval If the strings are the same, 0 is returned;
 * Otherwise, the difference between different characters is returned.
 */
int32_t BSL_SAL_StrcaseCmp(const char *str1, const char *str2);

/**
 * @ingroup bsl_sal
 * @brief Search for the corresponding character position in a string.
 *
 * Search for the corresponding character position in a string.
 *
 * @attention None.
 * @param str [IN] String
 * @param character [IN] Character to be searched for
 * @param count [IN] Range to be found
 * @retval If a character is found, the position of the character is returned;
 * Otherwise, NULL is returned.
 */
void *BSL_SAL_Memchr(const char *str, int32_t character, size_t count);

/**
 * @ingroup bsl_sal
 * @brief Convert string to number
 *
 * Convert string to number
 *
 * @attention None.
 * @param str [IN] String to be converted.
 * @retval If the conversion is successful, the corresponding number is returned;
 * Otherwise, the value 0 is returned.
 */
int32_t BSL_SAL_Atoi(const char *str);

/**
 * @ingroup bsl_sal
 * @brief Obtain the length of a given string.
 *
 * Obtain the length of a given string.
 *
 * @attention None.
 * @param string [IN] String to obtain the length.
 * @param count [IN] Maximum length
 * @retval If the parameter is abnormal, return 0.
 * @retval If the length of a string is greater than the count, return count.
 * Otherwise, the actual length of the string is returned.
 */
uint32_t BSL_SAL_Strnlen(const char *string, uint32_t count);

typedef enum {
    BSL_SAL_MEM_MALLOC = 0X0100,
    BSL_SAL_MEM_FREE,

    BSL_SAL_THREAD_LOCK_NEW_CB_FUNC = 0X0200,
    BSL_SAL_THREAD_LOCK_FREE_CB_FUNC,
    BSL_SAL_THREAD_LOCK_READ_LOCK_CB_FUNC,
    BSL_SAL_THREAD_LOCK_WRITE_LOCK_CB_FUNC,
    BSL_SAL_THREAD_LOCK_UNLOCK_CB_FUNC,
    BSL_SAL_THREAD_GET_ID_CB_FUNC,

    BSL_SAL_NET_WRITE_CB_FUNC = 0x0300,
    BSL_SAL_NET_READ_CB_FUNC,
    BSL_SAL_NET_SOCK_CB_FUNC,
    BSL_SAL_NET_SOCK_CLOSE_CB_FUNC,
    BSL_SAL_NET_SET_SOCK_OPT_CB_FUNC,
    BSL_SAL_NET_GET_SOCK_OPT_CB_FUNC,
    BSL_SAL_NET_SOCK_LISTEN_CB_FUNC,
    BSL_SAL_NET_SOCK_BIND_CB_FUNC,
    BSL_SAL_NET_SOCK_CONNECT_CB_FUNC,
    BSL_SAL_NET_SOCK_SEND_CB_FUNC,
    BSL_SAL_NET_SOCK_RECV_CB_FUNC,
    BSL_SAL_NET_SELECT_CB_FUNC,
    BSL_SAL_NET_IOCTL_CB_FUNC,
    BSL_SAL_NET_SOCKGETLASTSOCKETERROR_CB_FUNC,
    BSL_SAL_NET_SOCKADDR_NEW_CB_FUNC,
    BSL_SAL_NET_SOCKADDR_FREE_CB_FUNC,
    BSL_SAL_NET_SOCKADDR_SIZE_CB_FUNC,
    BSL_SAL_NET_SENDTO_CB_FUNC,
    BSL_SAL_NET_RECVFROM_CB_FUNC,

    BSL_SAL_TIME_GET_UTC_TIME_CB_FUNC = 0x0400,
    BSL_SAL_TIME_DATE_TO_STR_CONVERT_CB_FUNC,
    BSL_SAL_TIME_SYS_TIME_GET_CB_FUNC,
    BSL_SAL_TIME_UTC_TIME_TO_DATE_CONVERT_CB_FUNC,
    BSL_SAL_TIME_SLEEP_CB_FUNC,
    BSL_SAL_TIME_TICK_CB_FUNC,
    BSL_SAL_TIME_TICK_PER_SEC_CB_FUNC,

    BSL_SAL_FILE_OPEN_CB_FUNC = 0X0500,
    BSL_SAL_FILE_READ_CB_FUNC,
    BSL_SAL_FILE_WRITE_CB_FUNC,
    BSL_SAL_FILE_CLOSE_CB_FUNC,
    BSL_SAL_FILE_LENGTH_CB_FUNC,

    BSL_SAL_DL_OPEN_CB_FUNC = 0x0700,
    BSL_SAL_DL_CLOSE_CB_FUNC,
    BSL_SAL_DL_SYM_CB_FUNC,

    BSL_SAL_PID_GET_ID_CB_FUNC = 0x0800,

    BSL_SAL_MAX_FUNC_CB = 0xffff
} BSL_SAL_CB_FUNC_TYPE;

/**
 * @ingroup bsl_sal
 * @brief Allocate a memory block.
 *
 * Allocate a memory block.
 *
 * @param size [IN] Size of the allocated memory.
 * @retval: Not NULL, The start address of the allocated memory when memory is allocated successfully.
 * @retval  NULL, Memory allocation failure.
 */
typedef void *(*BslSalMalloc)(uint32_t size);

/**
 * @ingroup bsl_sal
 * @brief Reclaim a memory block allocated by pfMalloc.
 *
 * Reclaim a block of memory allocated by pfMalloc.
 *
 * @param addr [IN] Start address of the memory allocated by pfMalloc.
 */
typedef void (*BslSalFree)(void *addr);

/**
 * @ingroup bsl_sal
 * @brief Create a thread lock.
 *
 * Create a thread lock.
 *
 * @param lock [IN/OUT] Lock handle
 * @retval #BSL_SUCCESS, created successfully.
 * @retval #BSL_MALLOC_FAIL, memory space is insufficient and thread lock space cannot be applied for.
 * @retval #BSL_SAL_ERR_UNKNOWN, thread lock initialization failed.
 * @retval #BSL_SAL_ERR_BAD_PARAM, parameter error. The value of lock is NULL.
 */
typedef int32_t (*BslSalThreadLockNew)(BSL_SAL_ThreadLockHandle *lock);

/**
 * @ingroup bsl_sal
 * @brief Release the thread lock.
 *
 * Release the thread lock. Ensure that the lock can be released when other threads obtain the lock.
 *
 * @param lock [IN] Lock handle
 */
typedef void (*BslSalThreadLockFree)(BSL_SAL_ThreadLockHandle lock);

/**
 * @ingroup bsl_sal
 * @brief Lock the read operation.
 *
 * Lock the read operation.
 *
 * @param lock [IN] Lock handle
 * @retval #BSL_SUCCESS, succeeded.
 * @retval #BSL_SAL_ERR_UNKNOWN, operation failed.
 * @retval #BSL_SAL_ERR_BAD_PARAM, parameter error. The value of lock is NULL.
 */
typedef int32_t (*BslSalThreadReadLock)(BSL_SAL_ThreadLockHandle lock);

/**
 * @ingroup bsl_sal
 * @brief Lock the write operation.
 *
 * Lock the write operation.
 *
 * @param lock [IN] Lock handle
 * @retval #BSL_SUCCESS, succeeded.
 * @retval #BSL_SAL_ERR_UNKNOWN, operation failed.
 * @retval #BSL_SAL_ERR_BAD_PARAM, parameter error. The value of lock is NULL.
 */
typedef int32_t (*BslSalThreadWriteLock)(BSL_SAL_ThreadLockHandle lock);

/**
 * @ingroup bsl_sal
 * @brief Unlock
 *
 * Unlock
 *
 * @param lock [IN] Lock handle
 * @retval #BSL_SUCCESS, succeeded.
 * @retval #BSL_SAL_ERR_UNKNOWN, operation failed.
 * @retval #BSL_SAL_ERR_BAD_PARAM, parameter error. The value of lock is NULL.
 */
typedef int32_t (*BslSalThreadUnlock)(BSL_SAL_ThreadLockHandle lock);

/**
 * @ingroup bsl_sal
 * @brief Obtain the thread ID.
 *
 * Obtain the thread ID.
 *
 * @retval Thread ID
 */
typedef uint64_t (*BslSalThreadGetId)(void);

/**
 * @ingroup bsl_sal
 * @brief Open the file.
 *
 * @retval #BSL_SUCCESS: succeeded.
 * @retval #BSL_SAL_ERR_FILE_OPEN: file open fails.
 * @retval #BSL_NULL_INPUT: parameter error.
 */
typedef int32_t (*BslSalFileOpen)(bsl_sal_file_handle *stream, const char *path, const char *mode);

/**
 * @ingroup bsl_sal
 * @brief Read from the file.
 *
 * @retval #BSL_SUCCESS: succeeded.
 * @retval #BSL_SAL_ERR_FILE_READ: file read fails.
 * @retval #BSL_NULL_INPUT: parameter error.
 */
typedef int32_t (*BslSalFileRead)(bsl_sal_file_handle stream, void *buffer, size_t size, size_t num, size_t *len);

/**
 * @ingroup bsl_sal
 * @brief Write to the file.
 *
 * @retval #BSL_SUCCESS: succeeded.
 * @retval #BSL_SAL_ERR_FILE_WRITE: file write fails.
 * @retval #BSL_NULL_INPUT: parameter error.
 */
typedef int32_t (*BslSalFileWrite)(bsl_sal_file_handle stream, const void *buffer, size_t size, size_t num);

/**
 * @ingroup bsl_sal
 * @brief Close the file.
 */
typedef void (*BslSalFileClose)(bsl_sal_file_handle stream);

/**
 * @ingroup bsl_sal
 * @brief Get the length of the file.
 *
 * @retval #BSL_SUCCESS: succeeded.
 * @retval #BSL_SAL_ERR_FILE_LENGTH: get file length fails.
 * @retval #BSL_NULL_INPUT: parameter error.
 */
typedef int32_t (*BslSalFileLength)(const char *path, size_t *len);

/**
 * @ingroup bsl_sal
 * @brief Get the system time.
 *
 * @retval System time in int64_t format.
 */
typedef int64_t (*BslSalGetSysTime)(void);

/**
 * @ingroup bsl_sal
 * @brief Convert date to string.
 *
 * @retval #BSL_SUCCESS: succeeded.
 * @retval #BSL_INTERNAL_EXCEPTION: conversion fails.
 */
typedef uint32_t (*BslSalDateToStrConvert)(const BSL_TIME *dateTime, char *timeStr, size_t len);

/**
 * @ingroup bsl_sal
 * @brief Get the system time.
 *
 * @retval #BSL_SUCCESS: succeeded.
 * @retval #BSL_SAL_ERR_BAD_PARAM: parameter error.
 * @retval #BSL_INTERNAL_EXCEPTION: an exception occurred when obtaining the time.
 */
typedef uint32_t (*BslSalSysTimeGet)(BSL_TIME *sysTime);

/**
 * @ingroup bsl_sal
 * @brief Convert UTC time to date.
 *
 * @retval #BSL_SUCCESS: succeeded.
 * @retval #BSL_SAL_ERR_BAD_PARAM: parameter error.
 */
typedef uint32_t (*BslSalUtcTimeToDateConvert)(int64_t utcTime, BSL_TIME *sysTime);

/**
 * @ingroup bsl_sal
 * @brief Sleep for a specified time.
 */
typedef void (*BslSalSleep)(uint32_t time);

/**
 * @ingroup bsl_sal
 * @brief Get the system tick count.
 *
 * @retval System tick count.
 */
typedef long (*BslSalTick)(void);

/**
 * @ingroup bsl_sal
 * @brief Get the number of ticks per second.
 *
 * @retval Number of ticks per second.
 */
typedef long (*BslSalTicksPerSec)(void);

/**
 * @ingroup bsl_sal
 * @brief Write data.
 *
 * @retval Positive integer: number of bytes written.
 * @retval Negative integer: write operation failed.
 */
typedef int32_t (*BslSalWrite)(int32_t fd, const void *buf, uint32_t len, int32_t *err);

/**
 * @ingroup bsl_sal
 * @brief Read data.
 *
 * @retval Positive integer: number of bytes read.
 * @retval Negative integer: read operation failed.
 */
typedef int32_t (*BslSalRead)(int32_t fd, void *buf, uint32_t len, int32_t *err);

/**
 * @ingroup bsl_sal
 * @brief Create a socket.
 *
 * @retval Non-negative integer: socket file descriptor.
 * @retval Negative integer: socket creation failed.
 */
typedef int32_t (*BslSalSocket)(int32_t af, int32_t type, int32_t protocol);

/**
 * @ingroup bsl_sal
 * @brief Close a socket.
 *
 * @retval #BSL_SUCCESS: succeeded.
 * @retval #BSL_SAL_ERR_NET_SOCKCLOSE: socket close fails.
 */
typedef int32_t (*BslSalSockClose)(int32_t sockId);

/**
 * @ingroup bsl_sal
 * @brief Set socket options.
 *
 * @retval #BSL_SUCCESS: succeeded.
 * @retval #BSL_SAL_ERR_NET_SETSOCKOPT: set socket option fails.
 */
typedef int32_t (*BslSalSetSockopt)(int32_t sockId, int32_t level, int32_t name, const void *val, int32_t len);

/**
 * @ingroup bsl_sal
 * @brief Get socket options.
 *
 * @retval #BSL_SUCCESS: succeeded.
 * @retval #BSL_SAL_ERR_NET_GETSOCKOPT: get socket option fails.
 */
typedef int32_t (*BslSalGetSockopt)(int32_t sockId, int32_t level, int32_t name, void *val, int32_t *len);

/**
 * @ingroup bsl_sal
 * @brief Listen for socket connections.
 *
 * @retval #BSL_SUCCESS: succeeded.
 * @retval #BSL_SAL_ERR_NET_LISTEN: socket listen fails.
 */
typedef int32_t (*BslSalSockListen)(int32_t sockId, int32_t backlog);

/**
 * @ingroup bsl_sal
 * @brief Bind a socket to an address.
 *
 * @retval #BSL_SUCCESS: succeeded.
 * @retval #BSL_SAL_ERR_NET_BIND: socket bind fails.
 */
typedef int32_t (*BslSalSockBind)(int32_t sockId, BSL_SAL_SockAddr addr, size_t len);

/**
 * @ingroup bsl_sal
 * @brief Connect a socket to a remote address.
 *
 * @retval #BSL_SUCCESS: succeeded.
 * @retval #BSL_SAL_ERR_NET_CONNECT: socket connect fails.
 */
typedef int32_t (*BslSalSockConnect)(int32_t sockId, BSL_SAL_SockAddr addr, size_t len);

/**
 * @ingroup bsl_sal
 * @brief Send data through a socket.
 *
 * @retval Positive integer: number of bytes sent.
 * @retval Negative integer: send operation failed.
 */
typedef int32_t (*BslSalSockSend)(int32_t sockId, const void *msg, size_t len, int32_t flags);

/**
 * @ingroup bsl_sal
 * @brief Receive data from a socket.
 *
 * @retval Positive integer: number of bytes received.
 * @retval Negative integer: receive operation failed.
 */
typedef int32_t (*BslSalSockRecv)(int32_t sockfd, void *buff, size_t len, int32_t flags);

/**
 * @ingroup bsl_sal
 * @brief Same as linux funciton "sendto"
 *
 * @param sock [IN] Socket descriptor.
 * @param buf [IN] The buffer containing the data to be sent.
 * @param len [IN] Length of the buffer.
 * @param flags [IN] The type of message transmission.
 * @param address [IN] Points to a sockaddr structure containing the destination address.
 * @param addrLen [IN] Length of the sockaddr structure.
 * @param err [OUT] The error code if "sendto" failed.
 * @return BSL_SUCCESS, success.
 *         Otherwise, failure.
 */
typedef int32_t (*BslSalNetSendTo)(int32_t sock, const void *buf, size_t len, int32_t flags, void *address, int32_t addrLen, int32_t *err);

/**
 * @ingroup bsl_salZ
 * @brief Same as linux funciton "recvfrom"
 * @param sock [IN] Socket descriptor.
 * @param buf [IN] The buffer where the message should be stored.
 * @param len [IN] Length of the buffer.
 * @param flags [IN] The type of message transmission.
 * @param address [IN] A null pointer, or points to a sockaddr structure in
                   which the sending address is to be stored.
 * @param addrLen [IN] Either a null pointer, if address is a null pointer,
                   or a pointer to a socklen_t object which on input
                   specifies the length of the supplied sockaddr
                   structure, and on output specifies the length of the
                   stored address.

 * @param err [OUT] The error code if "recvfrom" failed.
 * @return BSL_SUCCESS, success.
 *         Otherwise, failure.
 */
typedef int32_t (*BslSalNetRecvFrom)(int32_t sock, void *buf, size_t len, int32_t flags, void *address, int32_t *addrLen, int32_t *err);

/**
 * @ingroup bsl_sal
 * @brief Monitor multiple file descriptors for readiness.
 *
 * @retval Positive integer: number of ready descriptors.
 * @retval 0: timeout occurred.
 * @retval Negative integer: select operation failed.
 */
typedef int32_t (*BslSalSelect)(int32_t nfds, void *readfds, void *writefds, void *exceptfds, void *timeout);

/**
 * @ingroup bsl_sal
 * @brief Perform I/O control on a socket.
 *
 * @retval #BSL_SUCCESS: succeeded.
 * @retval #BSL_SAL_ERR_NET_IOCTL: ioctl operation fails.
 */
typedef int32_t (*BslSalIoctlsocket)(int32_t sockId, long cmd, unsigned long *arg);

/**
 * @ingroup bsl_sal
 * @brief Get the last socket error.
 *
 * @retval Error code of the last socket operation.
 */
typedef int32_t (*BslSalSockGetLastSocketError)(void);

/**
 * @ingroup bsl_sal
 * @brief Control callback functions for SAL (System Abstraction Layer).
 *
 * This function is used to control and register callback functions for different SAL modules
 * such as network, time, and file operations.
 *
 * @attention None
 * @param funcType [IN] Type of the callback function to be controlled
 * @param funcCb [IN] Pointer to the callback function
 * @retval #BSL_SUCCESS Callback function controlled successfully
 * @retval #BSL_SAL_ERR_BAD_PARAM Invalid function type or callback pointer
 * @retval Other error codes specific to the SAL module
 */
int32_t BSL_SAL_CallBack_Ctrl(BSL_SAL_CB_FUNC_TYPE funcType, void *funcCb);
/**
 * @ingroup bsl_sal
 * @brief Load a dynamic library for dl.
 *
 * Load a dynamic library for dl.
 *
 * @attention None.
 * @param fileName [IN] Name of the file to be loaded.
 * @param handle [OUT] Pointer to store the handle of the loaded library.
 * @retval If the operation is successful, BSL_SUCCESS is returned;
 * Otherwise, an error code is returned.
 */
int32_t BSL_SAL_LoadLib(const char *fileName, void **handle);

/**
 * @ingroup bsl_sal
 * @brief Unload a dynamic library for dl.
 *
 * Unload a dynamic library for dl.
 *
 * @attention None.
 * @param handle [IN] Handle of the library to be unloaded.
 * @retval If the operation is successful, BSL_SUCCESS is returned;
 * Otherwise, an error code is returned.
 */
int32_t BSL_SAL_UnLoadLib(void *handle);

/**
 * @ingroup bsl_sal
 * @brief Get the address of the initialization function for dl.
 *
 * Get the address of the initialization function for dl.
 *
 * @attention None.
 * @param handle [IN] Handle of the loaded library.
 * @param funcName [IN] Name of the function.
 * @param func [OUT] Pointer to store the address of the function.
 * @retval If the operation is successful, BSL_SUCCESS is returned;
 * Otherwise, an error code is returned.
 */
int32_t BSL_SAL_GetFuncAddress(void *handle, const char *funcName, void **func);

// Define command enumeration
typedef enum {
    BSL_SAL_LIB_FMT_OFF = 0, /* Do not enable named conversion */
    BSL_SAL_LIB_FMT_SO = 1,
    BSL_SAL_LIB_FMT_LIBSO = 2,
    BSL_SAL_LIB_FMT_LIBDLL = 3,
    BSL_SAL_LIB_FMT_DLL = 4
} BSL_SAL_LibFmtCmd;

/**
 * @ingroup bsl_sal
 * @brief Convert filename to full library path for dl.
 *
 * Convert filename to full library name for dl according to the specified format and directory.
 *
 * @attention None.
 * @param cmd [IN] Command specifying the conversion format.
 * @param fileName [IN] Original filename.
 * @param name [OUT] Pointer to store the converted full name.
 * @retval If the operation is successful, BSL_OK is returned;
 * Otherwise, an error code is returned.
 */
int32_t BSL_SAL_LibNameFormat(BSL_SAL_LibFmtCmd cmd, const char *fileName, char **name);

/**
 * @ingroup bsl_sal
 * @brief Loading dynamic libraries.
 *
 * Loading dynamic libraries.
 *
 * @param fileName [IN] Path of dl
 * @param handle [OUT] Dynamic library handle
 * @retval #BSL_SUCCESS Succeeded.
 * @retval #BSL_SAL_ERR_DL_NOT_FOUND Library file not found.
 * @retval #BSL_SAL_ERR_DL_LOAD_FAIL Failed to load the library.
 */
typedef int32_t (*BslSalLoadLib)(const char *fileName, void **handle);

/**
 * @ingroup bsl_sal
 * @brief Close dynamic library.
 *
 * Close dynamic library.
 *
 * @param handle [IN] Dynamic library handle
 * @retval #BSL_SUCCESS Succeeded.
 * @retval #BSL_SAL_ERR_DL_UNLOAAD_FAIL Failed to unload the library.
 */
typedef int32_t (*BslSalUnLoadLib)(void *handle);

/**
 * @ingroup bsl_sal
 * @brief Get function symbol from dynamic library.
 *
 * Get function symbol from dynamic library.
 *
 * @param handle [IN] Dynamic library handle
 * @param funcName [IN] Function name
 * @param func [OUT] Function pointer
 * @retval #BSL_SUCCESS Succeeded.
 * @retval #BSL_SAL_ERR_DL_NON_FUNCTION Symbol found but is not a function.
 * @retval #BSL_SAL_ERR_DL_LOOKUP_METHOD Failed to lookup the function.
 */
typedef int32_t (*BslSalGetFunc)(void *handle, const char *funcName, void **func);

#ifdef __cplusplus
}
#endif

#endif // BSL_SAL_H