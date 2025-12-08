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

#ifndef APP_UTILS_H
#define APP_UTILS_H
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

#define APP_MAX_PATH_LEN PATH_MAX

#define DEFAULT_SALTLEN 16
#define DEFAULT_ITCNT 2048

#define MAX_DIGEST_SIZE (1024 * 8)  // Indicates the length of a single digest during digest calculation.

void *ExpandingMem(void *oldPtr, size_t newSize, size_t oldSize);

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

int32_t HITLS_APP_Passwd(char *buf, int32_t bufMaxLen, int32_t flag, void *userdata);

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

int32_t HITLS_APP_GetPasswd(BSL_UI_ReadPwdParam *param, char **passin, uint8_t **pass, uint32_t *passLen);
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

int32_t HITLS_APP_GetAndCheckHashOpt(const char *name, int32_t *hashId);

int32_t HITLS_APP_PrintText(const BSL_Buffer *csrBuf, const char *outFileName);

int32_t HITLS_APP_HexToByte(const char *hex, uint8_t **bin, uint32_t *len);

CRYPT_EAL_PkeyCtx *HITLS_APP_GenRsaPkeyCtx(uint32_t bits);

int32_t HITLS_APP_StrToHex(const char *str, uint8_t *hex, uint32_t *hexLen);

int32_t HITLS_APP_ReadData(const char *path, BSL_PEM_Symbol *symbol, char *fileName, BSL_Buffer *data);

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
#endif // APP_UTILS_H