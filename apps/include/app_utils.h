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

#ifndef HITLS_APP_UTILS_H
#define HITLS_APP_UTILS_H
#include <stddef.h>
#include <stdint.h>
#include "bsl_ui.h"
#include "bsl_types.h"
#include "crypt_eal_pkey.h"
#include "app_conf.h"
#include "app_provider.h"
#include "app_sm.h"
#include "hitls_csr_local.h"
#include "bsl_pem_internal.h"
#ifdef __cplusplus
extern "C" {
#endif

#define APP_MAX_PASS_LENGTH 1024
#define APP_MIN_PASS_LENGTH 1
#define APP_FILE_MAX_SIZE_KB 256
#define APP_FILE_MAX_SIZE (APP_FILE_MAX_SIZE_KB * 1024) // 256KB
#define APP_HEX_TO_BYTE 2

#define APP_MAX_PATH_LEN PATH_MAX

#define DEFAULT_SALTLEN 16
#define DEFAULT_ITCNT 2048

#define MAX_DIGEST_SIZE (1024 * 8)  // Indicates the length of a single digest during digest calculation.

/**
 * @ingroup apps
 *
 * @brief Apps Function for Checking the Validity of Key Characters
 *
 * @attention If the key length needs to be limited, the caller needs to limit the key length outside the function.
 *
 * @param password      [IN] Key entered by the user
 * @param passwordLen   [IN] Length of the key entered by the user
 *
 * @retval The key is valid：HITLS_APP_SUCCESS
 * @retval The key is invalid：HITLS_APP_PASSWD_FAIL
 */
int32_t HITLS_APP_CheckPasswd(const uint8_t *password, const uint32_t passwordLen);

/**
 * @ingroup apps
 *
 * @brief Apps Function for Verifying Passwd Received by the BSL_UI_ReadPwdUtil()
 *
 * @attention callBackData is the default callback structure APP_DefaultPassCBData.
 *
 * @param ui             [IN] Input/Output Stream
 * @param buff           [IN] Buffer for receiving passwd
 * @param buffLen        [IN] Length of the buffer for receiving passwd
 * @param callBackData   [IN] Key verification information.
 *
 * @retval The key is valid：HITLS_APP_SUCCESS
 * @retval The key is invalid：HITLS_APP_PASSWD_FAIL
 */
int32_t HITLS_APP_DefaultPassCB(BSL_UI *ui, char *buff, uint32_t buffLen, void *callBackData);

int32_t HITLS_APP_Passwd(char *buf, int32_t bufMaxLen, int32_t flag);

void HITLS_APP_PrintPassErrlog(void);
/**
 * @ingroup apps
 *
 * @brief Obtain the password from the command line argument.
 *
 * @attention pass: The memory needs to be released automatically.
 *
 * @param passArg        [IN] Command line password parameters
 * @param pass           [OUT] Parsed password
 *
 * @retval The key is valid：HITLS_APP_SUCCESS
 * @retval The key is invalid：HITLS_APP_PASSWD_FAIL
 */
int32_t HITLS_APP_ParsePasswd(const char *passArg, char **pass);

/**
 * @ingroup apps
 *
 * @brief Get the password from the command line argument.
 *
 * @param param            [IN] Password parameter
 * @param passin           [OUT] Parsed password
 * @param passLen          [OUT] Length of the password
 * @return HITLS_APP_SUCCESS on success, error code otherwise
 */
int32_t HITLS_APP_GetPasswd(BSL_UI_ReadPwdParam *param, char **passin, uint32_t *passLen);

/**
 * @ingroup apps
 *
 * @brief Load the public key.
 *
 * @attention If inFilePath is empty, it is read from the standard input.
 *
 * @param inFilePath        [IN] file name
 * @param informat          [IN] Public Key Format
 *
 * @retval CRYPT_EAL_PkeyCtx
 */
CRYPT_EAL_PkeyCtx *HITLS_APP_LoadPubKey(const char *inFilePath, BSL_ParseFormat informat);

/**
 * @ingroup apps
 *
 * @brief Load the private key using provider attributes.
 *
 * @attention If inFilePath or passin is empty, it is read from the standard input.
 *            The provider attribute (attrName) is used to specify the provider for key loading.
 *
 * @param libCtx            [IN] Library context
 * @param attrName          [IN] Provider attribute name
 * @param inFilePath        [IN] File name
 * @param informat          [IN] Private Key Format
 * @param passin            [IN/OUT] Parsed password
 *
 * @retval CRYPT_EAL_PkeyCtx
 */
CRYPT_EAL_PkeyCtx *HITLS_APP_ProviderLoadPrvKey(CRYPT_EAL_LibCtx *libCtx, const char *attrName,
    const char *inFilePath, BSL_ParseFormat informat, char **passin);

/**
 * @ingroup apps
 *
 * @brief Load the private key.
 *
 * @attention If inFilePath or passin is empty, it is read from the standard input.
 *
 * @param inFilePath        [IN] file name
 * @param informat          [IN] Private Key Format
 * @param passin            [IN/OUT] Parsed password
 *
 * @retval CRYPT_EAL_PkeyCtx
 */
CRYPT_EAL_PkeyCtx *HITLS_APP_LoadPrvKey(const char *inFilePath, BSL_ParseFormat informat, char **passin);

/**
 * @ingroup apps
 *
 * @brief Print the public key.
 *
 * @attention If outFilePath is empty, the standard output is displayed.
 *
 * @param pkey              [IN] key
 * @param outFilePath       [IN] file name
 * @param outformat         [IN] Public Key Format
 *
 * @retval HITLS_APP_SUCCESS
 * @retval HITLS_APP_INVALID_ARG
 * @retval HITLS_APP_ENCODE_KEY_FAIL
 * @retval HITLS_APP_UIO_FAIL
 */
int32_t HITLS_APP_PrintPubKey(CRYPT_EAL_PkeyCtx *pkey, const char *outFilePath, BSL_ParseFormat outformat);

/**
 * @ingroup apps
 *
 * @brief Print the private key.
 *
 * @attention If outFilePath is empty, the standard output is displayed, If passout is empty, it is read
 * from the standard input.
 *
 * @param pkey              [IN] key
 * @param outFilePath       [IN] file name
 * @param outformat         [IN] Private Key Format
 * @param cipherAlgCid      [IN] Encryption algorithm cid
 * @param passout           [IN/OUT] encryption password
 *
 * @retval HITLS_APP_SUCCESS
 * @retval HITLS_APP_INVALID_ARG
 * @retval HITLS_APP_ENCODE_KEY_FAIL
 * @retval HITLS_APP_UIO_FAIL
 */
int32_t HITLS_APP_PrintPrvKey(CRYPT_EAL_PkeyCtx *pkey, const char *outFilePath, BSL_ParseFormat outformat,
    int32_t cipherAlgCid, char **passout);

typedef struct {
    const char *name;
    BSL_ParseFormat outformat;
    int32_t cipherAlgCid;
    bool text;
    bool noout;
} AppKeyPrintParam;

int32_t HITLS_APP_PrintPrvKeyByUio(BSL_UIO *uio, CRYPT_EAL_PkeyCtx *pkey, AppKeyPrintParam *printKeyParam,
    char **passout);

/**
 * @ingroup apps
 *
 * @brief Obtain and check the encryption algorithm.
 *
 * @param name            [IN] encryption name
 * @param symId           [IN/OUT] encryption algorithm cid
 *
 * @retval HITLS_APP_SUCCESS
 * @retval HITLS_APP_INVALID_ARG
 */
int32_t HITLS_APP_GetAndCheckCipherOpt(const char *name, int32_t *symId);

/**
 * @ingroup apps
 *
 * @brief Load the cert.
 *
 * @param inPath           [IN] cert path
 * @param inform           [IN] cert format
 *
 * @retval HITLS_X509_Cert
 */
HITLS_X509_Cert *HITLS_APP_LoadCert(const char *inPath, BSL_ParseFormat inform);

/**
 * @ingroup apps
 *
 * @brief Load the csr.
 *
 * @param inPath           [IN] csr path
 * @param inform           [IN] csr format
 *
 * @retval HITLS_X509_Csr
 */
HITLS_X509_Csr *HITLS_APP_LoadCsr(const char *inPath, BSL_ParseFormat inform);

/**
 * @ingroup apps
 *
 * @brief Load the crl.
 *
 * @param inPath           [IN] crl path
 * @param inform           [IN] crl format
 *
 * @retval HITLS_X509_Crl
 */
HITLS_X509_Crl *HITLS_APP_LoadCrl(const char *inPath, BSL_ParseFormat inform);

int32_t HITLS_APP_GetAndCheckHashOpt(const char *name, int32_t *hashId);

int32_t HITLS_APP_PrintText(const BSL_Buffer *csrBuf, const char *outFileName);

/**
 * @ingroup apps
 * @brief Parse hexadecimal string to byte array (with optional "0x" prefix support)
 *
 * @param hexStr        [IN] Hexadecimal string (e.g., "0x1a2b" or "1a2b")
 * @param expectPrefix  [IN] Whether to expect "0x" prefix (true: must have "0x", false: no prefix)
 * @param bytes         [OUT] Allocated byte array (caller must free)
 * @param bytesLen      [OUT] Length of byte array
 *
 * @retval HITLS_APP_SUCCESS on success
 * @retval HITLS_APP_OPT_VALUE_INVALID if format is invalid
 * @retval HITLS_APP_MEM_ALLOC_FAIL if memory allocation fails
 *
 * @note This function allocates memory internally. Caller must free the returned bytes.
 * @note Leading zeros are automatically skipped.
 * @note Odd-length hex strings are handled by prepending '0'.
 */
int32_t HITLS_APP_ParseHex(const char *hexStr, bool expectPrefix, uint8_t **bytes, uint32_t *bytesLen);

CRYPT_EAL_PkeyCtx *HITLS_APP_GenRsaPkeyCtx(uint32_t bits);

/**
 * @ingroup apps
 * @brief Convert hexadecimal string to byte array
 *
 * @param hexStr        [IN] Hexadecimal string (e.g., "1a2b3c")
 * @param bytes         [OUT] Output byte array (caller provides buffer)
 * @param bytesLen      [IN/OUT] Input: buffer size, Output: actual bytes written
 *
 * @retval HITLS_APP_SUCCESS on success
 * @retval HITLS_APP_INVALID_ARG if parameters are invalid
 * @retval HITLS_APP_OPT_VALUE_INVALID if hex string format is invalid
 *
 * @note Hex string must have even length and contain only [0-9a-fA-F].
 * @note Caller must provide buffer with sufficient size (hexLen/2 bytes).
 */
int32_t HITLS_APP_HexToBytes(const char *hexStr, uint8_t *bytes, uint32_t *bytesLen);

int32_t HITLS_APP_ReadData(const char *path, BSL_PEM_Symbol *symbol, char *fileName, BSL_Buffer *data);

/**
 * @ingroup apps
 * @brief Read data from file or stdin into buffer
 *
 * @param buf      [OUT] Allocated buffer pointer (caller must free)
 * @param bufLen   [IN/OUT] Input: buffer capacity, Output: actual bytes read
 * @param inFile   [IN] File path to read from (NULL for stdin)
 * @param maxSize  [IN] Maximum allowed read size in bytes
 * @param module   [IN] Module name for error messages (e.g., "dgst", "pkeyutl")
 *
 * @retval HITLS_APP_SUCCESS on success
 * @retval HITLS_APP_INVALID_ARG if parameters are invalid
 * @retval HITLS_APP_UIO_FAIL if file open or read fails
 * @retval HITLS_APP_STDIN_FAIL if stdin read fails
 *
 * @note This function allocates memory for the buffer. Caller must free it.
 * @note When inFile is NULL, reads from stdin using HITLS_APP_ReadData
 * @note When inFile is provided, uses HITLS_APP_OptReadUio for reading
 */
int32_t HITLS_APP_ReadFileOrStdin(uint8_t **buf, uint64_t *bufLen, const char *inFile,
                                   uint32_t maxSize, const char *module);

typedef struct {
    int32_t randAlgId;
    AppProvider *provider;
#ifdef HITLS_APP_SM_MODE
    HITLS_APP_SM_Param *smParam;
#endif
} AppInitParam;

int32_t HITLS_APP_Init(AppInitParam *param);

void HITLS_APP_Deinit(AppInitParam *param, int32_t ret);

int32_t HITLS_APP_GetTime(int64_t *time);

#ifdef __cplusplus
}
#endif
#endif // HITLS_APP_UTILS_H