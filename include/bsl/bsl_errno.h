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
 * @defgroup bsl_errno
 * @ingroup bsl
 * @brief error number module
 */

#ifndef BSL_ERRNO_H
#define BSL_ERRNO_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup bsl_errno
 * @brief   Return success
 */
#define BSL_SUCCESS 0

/**
 * @ingroup bsl_errno
 *
 * Return values of the BSL module range from 0x03000001 to 0x03ffffff.
 */
enum BSL_ERROR {
    /* Common return value start from 0x03000001. */
    BSL_NULL_INPUT = 0x03000000,            /**< NULL input. */
    BSL_INTERNAL_EXCEPTION,                 /**< Error occurs when calling internal BSL functions */
    BSL_MALLOC_FAIL,                        /**< Error occurs when allocating memory */
    BSL_MEMCPY_FAIL,                        /**< Error occurs when calling memcpy_s. */
    BSL_MEMMOVE_FAIL,                       /**< Error occurs when calling memmove. */
    BSL_INVALID_ARG,                        /**< Invalid arguments. */
    BSL_DUMP_FAIL,                          /**< Error occurs when duplicating memory */

    /* The return value of the SAL submodule starts from 0x03010001. */
    /* The return value of the SAL submodule starts from 0x03010001. */
    BSL_SAL_ERR_UNKNOWN = 0x03010001,        /**< Unknown error. */
    BSL_SAL_ERR_BAD_PARAM,                   /**< Parameter incorrect. */
    BSL_SAL_ERR_FILE_OPEN,                   /**< Open file error. */
    BSL_SAL_ERR_FILE_READ,                   /**< File reading error. */
    BSL_SAL_ERR_FILE_WRITE,                  /**< File writing error. */
    BSL_SAL_ERR_FILE_LENGTH,                 /**< Obtaining the file length error. */
    BSL_SAL_ERR_FILE_TELL,                   /**< Error in obtaining the file pointer offset. */
    BSL_SAL_ERR_FILE_SEEK,                   /**< Failed to set pointer position of file. */
    BSL_SAL_ERR_FILE_SET_ATTR,               /**< Setting file attribute is incorrect. */
    BSL_SAL_ERR_FILE_GET_ATTR,               /**< Error in obtaining file attributes. */
    BSL_SAL_FILE_NO_REG_FUNC,
    BSL_SAL_ERR_DL_NOT_FOUND,                  /**< dl not found. */
    BSL_SAL_ERR_DL_LOAD_FAIL,                  /**< Error occured when loading dynamic library. */
    BSL_SAL_ERR_DL_UNLOAAD_FAIL,               /**< Error occured when unloading dynamic library. */
    BSL_SAL_ERR_DL_NON_FUNCTION,               /**< dl doesn't find function. */
    BSL_SAL_ERR_DL_LOOKUP_METHOD,              /**< Error occurred when looking up dl method. */
    BSL_SAL_ERR_DL_PATH_EXCEED,                /**< Path exceeds the maximum length. */
    BSL_SAL_DL_NO_REG_FUNC,                    /**< The dl-related function is not registered. */
    BSL_SAL_NOT_FILE_EOF,
    BSL_SAL_THREAD_LOCK_NO_REG_FUNC,
    BSL_SAL_ERR_NO_MEMORY,

    /* The return value of the LOG submodule starts from 0x03020001. */
    BSL_LOG_ERR_BAD_PARAM = 0x03020001,      /**< Bad parameter. */
    BSL_LOG_ERR_MEMCPY_FAIL,                 /**< Memory Copy Failure. */

    /* The return value of the TLV submodule starts from 0x03030001. */
    BSL_TLV_ERR_BAD_PARAM = 0x03030001,      /**< Bad parameter. */
    BSL_TLV_ERR_NO_WANT_TYPE,                /**< No TLV found. */
    BSL_TLV_ERR_MEMCPY_FAIL,                 /**< Memory Copy Failure. */

    /* The return value of the ERR submodule starts from 0x03040001. */
    BSL_ERR_ERR_ACQUIRE_READ_LOCK_FAIL = 0x03040001,  /**< Failed to obtain the read lock. */
    BSL_ERR_ERR_ACQUIRE_WRITE_LOCK_FAIL,              /**< Failed to obtain the write lock. */
    BSL_ERR_ERR_NO_STACK,                             /**< Error stack is empty. */
    BSL_ERR_ERR_NO_ERROR,                             /**< Error stack is NULL.  */
    BSL_ERR_ERR_NO_MARK,                              /**< Error stack has no mark. */

    BSL_SAL_TIME_BAD_PARAM = 0x03050001,
    BSL_SAL_TIME_NO_REG_FUNC,                /** The time-related function is not registered. */
    BSL_SAL_TIME_SYS_ERROR,                  /** Function gettimeofday failed */

    /* The return value of the UIO submodule starts from 0x03060001. */
    BSL_UIO_FAIL = 0x03060001,
    BSL_UIO_IO_EXCEPTION,
    BSL_UIO_IO_BUSY,
    BSL_UIO_MEM_GROW_FAIL,
    BSL_UIO_REF_MAX,
    BSL_UIO_MEM_ALLOC_FAIL,
    BSL_UIO_IO_EOF,
    BSL_UIO_WRITE_NOT_ALLOWED,
    BSL_UIO_UNINITIALIZED,
    BSL_UIO_MEM_NOT_NULL,
    BSL_UIO_CB_NOT_SET,
    BSL_UIO_CTRL_INVALID_PARAM,
    BSL_UIO_FILE_OPEN_FAIL,
    BSL_UIO_EXIST_CONTEXT_NOT_RELEASED,
    BSL_UIO_BUF_TOO_LONG,
    BSL_UIO_CIPHER_UPDATE_FAIL,
    BSL_UIO_CIPHER_FINAL_FAIL,
    BSL_UIO_CIPHER_GET_BLOCK_SIZE_FAIL,
    BSL_UIO_CIPHER_SET_PADDING_FAIL,
    BSL_UIO_CIPHER_SHOULD_NOT_WRITE,
    BSL_UIO_CIPHER_SHOULD_NOT_READ,
    BSL_UIO_CIPHER_SHOULD_NOT_FLUSH,
    BSL_UIO_NEXT_IS_NULL,
    BSL_UIO_SET_CIPHER_CTX_AGAIN,

    /* The return value of the LIST submodule starts from 0x03070001. */
    BSL_LIST_INVALID_LIST_CURRENT = 0x03070001, /**< Current node pointer is NULL */
    BSL_LIST_MALLOC_FAIL,
    BSL_LIST_DATA_NOT_AVAILABLE,                /**< Data of current node is NULL */
    BSL_LIST_FULL,                              /**< Number of nodes has reached its limit */
    
    /* The return value of the UI submodule starts from 0x03080001. */
    BSL_UI_WRITE_ERROR = 0x03080001,
    BSL_UI_FGETS_ERROR,
    BSL_UI_STDIN_END_ERROR,
    BSL_UI_OPERATION_ERROR,
    BSL_UI_READ_LEN_TOO_SHORT,
    BSL_UI_READ_BUFF_TOO_LONG,
    BSL_UI_METHOD_INVALID_TYPE,
    BSL_UI_CONSTRUCT_PROMPT_ERROR,
    BSL_UI_CREATE_OBJECT_ERROR,
    BSL_UI_OUTPUT_BUFF_TOO_SHORT,
    BSL_UI_INVALID_DATA_TYPE,
    BSL_UI_INVALID_DATA_ARG,
    BSL_UI_INVALID_DATA_RESULT,
    BSL_UI_VERIFY_BUFF_FAILED,
    BSL_UI_MEM_ALLOC_FAIL,

    /* The return value of the OID submodule starts from 0x03090001. */
    BSL_OID_INVALID = 0x03090001,
    BSL_OID_TYPE_CODE_INVALID,
    BSL_OID_NAME_LENGTH_INVALID,
    BSL_OID_DUPLICATE,
    BSL_OID_OBJ_INTERNAL_USE,

    /* The return value of the BASE64 submodule starts from 0x030a0001. */
    BSL_BASE64_INVALID = 0x030a0001,
    BSL_BASE64_BUF_NOT_ENOUGH,
    BSL_BASE64_DATA_NOT_ENOUGH,
    BSL_BASE64_WRITE_FAILED,
    BSL_BASE64_READ_FAILED,
    BSL_BASE64_DATA_AFTER_PADDING,
    BSL_BASE64_ILLEGALLY_MODIFIED,
    BSL_BASE64_ENCODE_FAILED,
    BSL_BASE64_DECODE_FAILED,
    BSL_BASE64_HEADER,
    BSL_BASE64_INVALID_CHARACTER,
    BSL_BASE64_INVALID_ENCODE,

    BSL_SAL_ERR_NET_NOBLOCK = 0x030b0001,
    BSL_SAL_ERR_NET_SOCKCLOSE,               /**< Error occured when closing a socket. */
    BSL_SAL_ERR_NET_SETSOCKOPT,              /**< Error occured when setting a socket option. */
    BSL_SAL_ERR_NET_GETSOCKOPT,              /**< Error occured when getting a socket option. */
    BSL_SAL_ERR_NET_LISTEN,                  /**< Error occured when listening a socket. */
    BSL_SAL_ERR_NET_BIND,                    /**< Error occured when binding a socket */
    BSL_SAL_ERR_NET_CONNECT,                 /**< Error occured when building a connection. */
    BSL_SAL_ERR_NET_IOCTL,                   /**< Error occured when calling ioctl. */
    BSL_SAL_NET_NO_REG_FUNC,
    BSL_SAL_ERR_NET_ACCEPT,
    BSL_SAL_ERR_NET_GETSOCKNAME,

    BSL_CONF_FAIL = 0x030c0001,
    BSL_CONF_INIT_FAIL,
    BSL_CONF_LOAD_FAIL,
    BSL_CONF_MEM_ALLOC_FAIL,
    BSL_CONF_FREE_FAIL,
    BSL_CONF_NOT_NUM,
    BSL_CONF_PARSE_FAIL,
    BSL_CONF_COPY_ARGS_FAILED,
    BSL_CONF_CONTEXT_ERR,
    BSL_CONF_GET_FAIL,
    BSL_CONF_VALUE_NOT_FOUND,
    BSL_CONF_DUMP_FAIL,
    BSL_CONF_BUFF_OVERFLOW,
    BSL_CONF_INVALID_NAME,

    BSL_PARAMS_INVALID_KEY = 0x030f0001,
    BSL_PARAMS_INVALID_TYPE,
    BSL_PARAMS_LEN_NOT_ENOUGH,
    BSL_PARAMS_MISMATCH,
    BSL_PARAMS_OUT_LIMIT,

    BSL_ASN1_FAIL = 0x03100001,
    BSL_ASN1_ERR_DECODE_BOOL,
    BSL_ASN1_ERR_NO_CALLBACK,
    BSL_ASN1_ERR_MAX_DEPTH,
    BSL_ASN1_ERR_OVERFLOW,
    BSL_ASN1_ERR_TAG_EXPECTED,
    BSL_ASN1_ERR_DECODE_LEN,
    BSL_ASN1_ERR_MAX_LEN_NUM,
    BSL_ASN1_ERR_DECODE_INT,
    BSL_ASN1_ERR_DECODE_BIT_STRING,
    BSL_ASN1_ERR_DECODE_UTC_TIME,
    BSL_ASN1_ERR_DECODE_TIME,
    BSL_ASN1_ERR_DECODE_GENERAL_TIME,
    BSL_ASN1_ERR_CHECK_TIME,
    BSL_ASN1_ERR_EXCEED_LIST_DEPTH,
    BSL_ASN1_ERR_MISMATCH_TAG,
    BSL_ASN1_ERR_BUFF_NOT_ENOUGH,
    BSL_ASN1_ERR_ENCODE_FAIL,
    BSL_ASN1_ERR_ENCODE_ASN_LACK,
    BSL_ASN1_ERR_ENCODE_ASN_TOO_MUCH,
    BSL_ASN1_ERR_ENCODE_BOOL,
    BSL_ASN1_ERR_ENCODE_INT,
    BSL_ASN1_ERR_ENCODE_BIT_STRING,
    BSL_ASN1_ERR_ENCODE_UTC_TIME,
    BSL_ASN1_ERR_ENCODE_GENERALIZED_TIME,
    BSL_ASN1_ERR_LEN_OVERFLOW,
    BSL_ASN1_ERR_PRINTF,
    BSL_ASN1_ERR_PRINTF_IO_ERR,
    BSL_ASN1_ERR_DECODE_T61_STRING,
    BSL_ASN1_ERR_ENCODE_T61_STRING,

    BSL_PEM_INVALID = 0x03110001,
    BSL_PEM_DATA_NOT_ENOUGH,
    BSL_PEM_SYMBOL_NOT_FOUND,
    BSL_PEM_NO_PWD,

    BSL_PRINT_ERR_FMT = 0x03120001,
    BSL_PRINT_ERR_BUF,
    BSL_PRINT_ERR_NUMBER,

    BSL_OBJ_ERR_INSERT_HASH_TABLE = 0x03130001,
    BSL_OBJ_ERR_FIND_HASH_TABLE,
    BSL_OBJ_INVALID_HASH_TABLE,
};

#ifdef __cplusplus
}
#endif

#endif // BSL_ERRNO_H
