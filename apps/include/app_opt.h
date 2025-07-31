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
 
#ifndef HITLS_APP_OPT_H
#define HITLS_APP_OPT_H

#include <stdint.h>
#include "bsl_uio.h"
#include "bsl_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HILTS_APP_FORMAT_UNDEF 0
#define HITLS_APP_FORMAT_PEM BSL_FORMAT_PEM    // 1
#define HITLS_APP_FORMAT_ASN1 BSL_FORMAT_ASN1  // 2
#define HITLS_APP_FORMAT_TEXT 3
#define HITLS_APP_FORMAT_BASE64 4
#define HITLS_APP_FORMAT_HEX 5
#define HITLS_APP_FORMAT_BINARY 6

typedef enum {
    HITLS_APP_OPT_VALUETYPE_NONE = 0,
    HITLS_APP_OPT_VALUETYPE_NO_VALUE = 1,
    HITLS_APP_OPT_VALUETYPE_IN_FILE,
    HITLS_APP_OPT_VALUETYPE_OUT_FILE,
    HITLS_APP_OPT_VALUETYPE_STRING,
    HITLS_APP_OPT_VALUETYPE_PARAMTERS,
    HITLS_APP_OPT_VALUETYPE_DIR,
    HITLS_APP_OPT_VALUETYPE_INT,
    HITLS_APP_OPT_VALUETYPE_UINT,
    HITLS_APP_OPT_VALUETYPE_POSITIVE_INT,
    HITLS_APP_OPT_VALUETYPE_LONG,
    HITLS_APP_OPT_VALUETYPE_ULONG,
    HITLS_APP_OPT_VALUETYPE_FMT_PEMDER,
    HITLS_APP_OPT_VALUETYPE_FMT_ANY,
    HITLS_APP_OPT_VALUETYPE_MAX,
} HITLS_ValueType;

typedef enum {
    HITLS_APP_OPT_VALUECLASS_NONE = 0,
    HITLS_APP_OPT_VALUECLASS_NO_VALUE = 1,
    HITLS_APP_OPT_VALUECLASS_STR,
    HITLS_APP_OPT_VALUECLASS_DIR,
    HITLS_APP_OPT_VALUECLASS_INT,
    HITLS_APP_OPT_VALUECLASS_LONG,
    HITLS_APP_OPT_VALUECLASS_FMT,
    HITLS_APP_OPT_VALUECLASS_MAX,
} HITLS_ValueClass;

typedef enum {
    HITLS_APP_OPT_ERR = -1,
    HITLS_APP_OPT_EOF = 0,
    HITLS_APP_OPT_PARAM = HITLS_APP_OPT_EOF,
    HITLS_APP_OPT_HELP = 1,
} HITLS_OptChoice;

typedef struct {
    const char *name;  // option name
    const int optType; // option type
    int valueType;     // options with parameters(type)
    const char *help;  // description of this option
} HITLS_CmdOption;

/**
 * @ingroup HITLS_APP
 * @brief   Initialization of command-line argument parsing (internal function)
 *
 * @param   argc [IN] number of options
 * @param   argv [IN] pointer to an array of options
 * @param   opts [IN] command option table
 *
 * @retval  command name of command-line argument
 */
int32_t HITLS_APP_OptBegin(int32_t argc, char **argv, const HITLS_CmdOption *opts);

/**
 * @ingroup HITLS_APP
 * @brief   Parse next command-line argument (internal function)
 *
 * @param   void
 *
 * @retval  int32 option type
 */
int32_t HITLS_APP_OptNext(void);


/**
 * @ingroup HITLS_APP
 * @brief   Finish parsing options
 *
 * @param   void
 *
 * @retval  void
 */
void HITLS_APP_OptEnd(void);

/**
 * @ingroup HITLS_APP
 * @brief   Print command line parsing
 *
 * @param   opts command option table
 *
 * @retval  void
 */
void HITLS_APP_OptHelpPrint(const HITLS_CmdOption *opts);

/**
 * @ingroup HITLS_APP
 * @brief   Get the number of remaining options
 *
 * @param   void
 *
 * @retval  int32 number of remaining options
 */
int32_t HITLS_APP_GetRestOptNum(void);

/**
 * @ingroup HITLS_APP
 * @brief   Get the remaining options
 *
 * @param   void
 *
 * @retval  char** the address of remaining options
 */
char **HITLS_APP_GetRestOpt(void);

/**
 * @ingroup HITLS_APP
 * @brief  Get command option
 * @param  void
 * @retval char* command option
 */
char *HITLS_APP_OptGetValueStr(void);

/**
 * @ingroup HITLS_APP
 * @brief option string to int
 * @param valueS [IN] string value
 * @param valueL [OUT] int value
 * @retval int32_t success or not
 */
int32_t HITLS_APP_OptGetInt(const char *valueS, int32_t *valueI);

/**
 * @ingroup HITLS_APP
 * @brief option string to uint32_t
 * @param valueS [IN] string value
 * @param valueL [OUT] uint32_t value
 * @retval int32_t success or not
 */
int32_t HITLS_APP_OptGetUint32(const char *valueS, uint32_t *valueU);

/**
 * @ingroup HITLS_APP
 * @brief   Get the name of the current second-class command
 *
 * @param   void
 *
 * @retval  char* command name
 */
char *HITLS_APP_GetProgName(void);

/**
 * @ingroup HITLS_APP
 * @brief   option string to long
 *
 * @param   valueS [IN] string value
 * @param   valueL [OUT] long value
 *
 * @retval  int32_t success or not
 */
int32_t HITLS_APP_OptGetLong(const char *valueS, long *valueL);

/**
 * @ingroup HITLS_APP
 * @brief   Get the format type from the option value
 *
 * @param   valueS [IN] string of value
 * @param   type   [IN] value type
 * @param   formatType [OUT] format type
 *
 * @retval  int32_t success or not
 */
int32_t HITLS_APP_OptGetFormatType(const char *valueS, HITLS_ValueType type, BSL_ParseFormat *formatType);

/**
 * @ingroup HITLS_APP
 * @brief   Get UIO type from option value
 *
 * @param   filename [IN] name of input file
 * @param   mode     [IN] method of opening a file
 * @param   flag     [OUT] whether the closing of the standard input/output window is bound to the UIO
 *
 * @retval  BSL_UIO * when succeeded, NULL when failed
*/
BSL_UIO* HITLS_APP_UioOpen(const char* filename, char mode, int32_t flag);

/**
 * @ingroup HITLS_APP
 * @brief   Converts a character string to a character string in Base64 format and output the buf to UIO
 *
 * @param   buf     [IN]  content to be encoded
 * @param   outLen  [IN]  the length of content to be encoded
 * @param   outBuf  [IN]  Encoded content
 * @param   outBufLen  [IN] the length of encoded content
 *
 * @retval  int32_t success or not
*/
int32_t HITLS_APP_OptToBase64(uint8_t *buf, uint32_t outLen, char *outBuf, uint32_t outBufLen);

/**
 * @ingroup HITLS_APP
 * @brief   Converts a character string to a hexadecimal character string and output the buf to UIO
 *
 * @param   buf     [IN]  content to be encoded
 * @param   outLen  [IN]  the length of content to be encoded
 * @param   outBuf  [IN]  Encoded content
 * @param   outBufLen  [IN] the length of encoded content
 *
 * @retval  int32_t success or not
*/
int32_t HITLS_APP_OptToHex(uint8_t *buf, uint32_t outLen, char *outBuf, uint32_t outBufLen);

/**
 * @ingroup HITLS_APP
 * @brief   Output the buf to UIO
 *
 * @param   uio     [IN] output UIO
 * @param   buf     [IN] output buf
 * @param   outLen  [IN] the length of output buf
 * @param   format  [IN] output format
 *
 * @retval  int32_t success or not
*/
int32_t HITLS_APP_OptWriteUio(BSL_UIO* uio, uint8_t* buf, uint32_t outLen, int32_t format);

/**
 * @ingroup HITLS_APP
 * @brief   Read the content in the UIO to the readBuf
 *
 * @param   uio         [IN] input UIO
 * @param   readBuf     [IN] buf which uio read
 * @param   readBufLen  [IN] the length of readBuf
 * @param   maxBufLen   [IN] the maximum length to be read.
 *
 * @retval  int32_t success or not
 */
int32_t HITLS_APP_OptReadUio(BSL_UIO *uio, uint8_t **readBuf, uint64_t *readBufLen, uint64_t maxBufLen);

/**
 * @ingroup HITLS_APP
 * @brief   Get unknown option name
 *
 * @retval  char*
 */
const char *HITLS_APP_OptGetUnKownOptName();
#ifdef __cplusplus
}
#endif
#endif
