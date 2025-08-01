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
#include "app_utils.h"
#include <stdio.h>
#include <securec.h>
#include <string.h>
#include <linux/limits.h>
#include "bsl_sal.h"
#include "bsl_buffer.h"
#include "bsl_ui.h"
#include "bsl_errno.h"
#include "bsl_buffer.h"
#include "bsl_pem_internal.h"
#include "sal_file.h"
#include "crypt_errno.h"
#include "crypt_eal_codecs.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_md.h"
#include "crypt_encode_decode_key.h"
#include "app_print.h"
#include "app_errno.h"
#include "app_opt.h"
#include "app_list.h"
#include "hitls_pki_errno.h"

#define DEFAULT_PEM_FILE_SIZE 1024U
#define RSA_PRV_CTX_LEN 8

#define APP_LINESIZE 255
#define PEM_BEGIN_STR "-----BEGIN "
#define PEM_END_STR "-----END "
#define PEM_TAIL_STR "-----\n"
#define PEM_TAIL_KEY_STR "KEY-----\n"

#define PEM_BEGIN_STR_LEN ((int)(sizeof(PEM_BEGIN_STR) - 1))
#define PEM_END_STR_LEN ((int)(sizeof(PEM_END_STR) - 1))
#define PEM_TAIL_STR_LEN ((int)(sizeof(PEM_TAIL_STR) - 1))
#define PEM_TAIL_KEY_STR_LEN ((int)(sizeof(PEM_TAIL_KEY_STR) - 1))

#define PEM_RSA_PRIVATEKEY_STR "RSA PRIVATE KEY"
#define PEM_RSA_PUBLIC_STR "RSA PUBLIC KEY"
#define PEM_EC_PRIVATEKEY_STR "EC PRIVATE KEY"
#define PEM_PKCS8_PRIVATEKEY_STR "PRIVATE KEY"
#define PEM_PKCS8_PUBLIC_STR "PUBLIC KEY"
#define PEM_ENCRYPTED_PKCS8_PRIVATEKEY_STR "ENCRYPTED PRIVATE KEY"

#define PEM_PROC_TYPE_STR "Proc-Type:"
#define PEM_PROC_TYPE_NUM_STR "4,"
#define PEM_ENCRYPTED_STR "ENCRYPTED"

#define APP_PASS_ARG_STR "pass:"
#define APP_PASS_ARG_STR_LEN ((int)(sizeof(APP_PASS_ARG_STR) - 1))

#define APP_PASS_STDIN_STR "stdin"
#define APP_PASS_STDIN_STR_LEN ((int)(sizeof(APP_PASS_STDIN_STR) - 1))

#define APP_PASS_FILE_STR "file:"
#define APP_PASS_FILE_STR_LEN ((int)(sizeof(APP_PASS_FILE_STR) - 1))

typedef struct defaultPassCBData {
    uint32_t maxLen;
    uint32_t minLen;
} APP_DefaultPassCBData;

void *ExpandingMem(void *oldPtr, size_t newSize, size_t oldSize)
{
    if (newSize <= 0) {
        return oldPtr;
    }
    void *newPtr = BSL_SAL_Calloc(newSize, sizeof(uint8_t));
    if (newPtr == NULL) {
        return oldPtr;
    }
    if (oldPtr != NULL) {
        if (memcpy_s(newPtr, newSize, oldPtr, oldSize) != 0) {
            BSL_SAL_FREE(newPtr);
            return oldPtr;
        }
        BSL_SAL_FREE(oldPtr);
    }
    return newPtr;
}

int32_t HITLS_APP_CheckPasswd(const uint8_t *password, const uint32_t passwordLen)
{
    for (uint32_t i = 0; i < passwordLen; ++i) {
        if (password[i] < '!' || password[i] > '~') {
            AppPrintError("The password can contain only the following characters:\n");
            AppPrintError("a~z A~Z 0~9 ! \" # $ %% & ' ( ) * + , - . / : ; < = > ? @ [ \\ ] ^ _ ` { | } ~\n");
            return HITLS_APP_PASSWD_FAIL;
        }
    }
    return HITLS_APP_SUCCESS;
}

int32_t HITLS_APP_DefaultPassCB(BSL_UI *ui, char *buff, uint32_t buffLen, void *callBackData)
{
    if (ui == NULL || buff == NULL || buffLen == 1) {
        (void)AppPrintError("You have not entered a password.\n");
        return BSL_UI_INVALID_DATA_ARG;
    }
    uint32_t passLen = buffLen - 1;
    uint32_t maxLength = 0;
    if (callBackData == NULL) {
        maxLength = APP_MAX_PASS_LENGTH;
    } else {
        APP_DefaultPassCBData *data = callBackData;
        maxLength = data->maxLen;
    }
    if (passLen > maxLength) {
        HITLS_APP_PrintPassErrlog();
        return BSL_UI_INVALID_DATA_RESULT;
    }
    return BSL_SUCCESS;
}

static int32_t CopyBufToData(const char *buf, size_t readLen, uint8_t **data, size_t *dataSize, size_t *dataCapacity)
{
    if ((*dataSize + readLen) > APP_FILE_MAX_SIZE) {
        AppPrintError("The supports a maximum of %zukb.\n", APP_FILE_MAX_SIZE_KB);
        return HITLS_APP_STDIN_FAIL;
    }
    if ((*dataSize + readLen) > *dataCapacity) {
        size_t newdataCapacity = *dataCapacity << 1; // space is insufficient, expand the capacity by twice
        // If the space is insufficient for twice the capacity expansion,
        // expand the capacity based on the actual length.
        if ((*dataSize + readLen) > newdataCapacity) {
            newdataCapacity = *dataSize + readLen;
        }
        *data = ExpandingMem(*data, newdataCapacity, *dataCapacity);
        *dataCapacity = newdataCapacity;
    }
    if (memcpy_s(*data + *dataSize, *dataCapacity - *dataSize, buf, readLen) != 0) {
        return HITLS_APP_SECUREC_FAIL;
    }
    *dataSize += readLen;
    return HITLS_APP_SUCCESS;
}

static char *GetPemKeyFileName(const char *buf, size_t readLen)
{
    // -----BEGIN *** KEY-----
    if ((strncmp(buf, PEM_BEGIN_STR, PEM_BEGIN_STR_LEN) != 0) || (readLen < PEM_TAIL_KEY_STR_LEN) ||
        (strncmp(buf + readLen - PEM_TAIL_KEY_STR_LEN, PEM_TAIL_KEY_STR, PEM_TAIL_KEY_STR_LEN) != 0)) {
        return NULL;
    }

    int32_t len = readLen - PEM_BEGIN_STR_LEN - PEM_TAIL_STR_LEN;
    char *name = BSL_SAL_Calloc(len + 1, sizeof(char));
    if (name == NULL) {
        return name;
    }
    memcpy_s(name, len, buf + PEM_BEGIN_STR_LEN, len);
    name[len] = '\0';
    return name;
}

static bool IsNeedEncryped(const char *name, const char *header, uint32_t headerLen)
{
    // PKCS8
    if (strcmp(name, PEM_ENCRYPTED_PKCS8_PRIVATEKEY_STR) == 0) {
        return true;
    }
    // PKCS1
    // Proc-Type: 4, ENCRYPTED
    uint32_t offset = 0;
    uint32_t len = strlen(PEM_PROC_TYPE_STR);
    if (strncmp(header + offset, PEM_PROC_TYPE_STR, len) != 0) {
        return false;
    }
    offset += len + strspn(header + offset + len, " \t");
    len = strlen(PEM_PROC_TYPE_NUM_STR);
    if ((offset >= headerLen) || (strncmp(header + offset, PEM_PROC_TYPE_NUM_STR, len) != 0)) {
        return false;
    }
    offset += len + strspn(header + offset + len, " \t");
    len = strlen(PEM_ENCRYPTED_STR);
    if ((offset >= headerLen) || (strncmp(header + offset, PEM_ENCRYPTED_STR, len) != 0)) {
        return false;
    }
    offset += len + strspn(header + offset + len, " \t");
    if ((offset >= headerLen) || header[offset] != '\n') {
        return false;
    }
    return true;
}

static void PrintFileOrStdinError(const char *filePath, const char *errStr)
{
    if (filePath == NULL) {
        AppPrintError("%s.\n", errStr);
    } else {
        AppPrintError("%s from \"%s\".\n", errStr, filePath);
    }
}

static int32_t ReadPemKeyFile(const char *inFilePath, uint8_t **inData, uint32_t *inDataSize, char **name,
    bool *isEncrypted)
{
    if ((inData == NULL) || (inDataSize == NULL) || (name == NULL)) {
        return HITLS_APP_INVALID_ARG;
    }
    BSL_UIO *rUio = HITLS_APP_UioOpen(inFilePath, 'r', 1);
    if (rUio == NULL) {
        return HITLS_APP_UIO_FAIL;
    }
    BSL_UIO_SetIsUnderlyingClosedByUio(rUio, true);
    // The system automatically ends when the following words are read:
    // -----BEGIN XXX-----
    // -----END XXX-----
    bool isParseHeader = false;
    size_t dataCapacity = DEFAULT_PEM_FILE_SIZE;
    uint8_t *data = (uint8_t *)BSL_SAL_Calloc(dataCapacity, sizeof(uint8_t));
    if (data == NULL) {
        BSL_UIO_Free(rUio);
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    size_t dataSize = 0;
    char buf[APP_LINESIZE + 1] = {};
    uint32_t readLen = APP_LINESIZE + 1;
    while (true) {
        readLen = APP_LINESIZE + 1;
        (void)memset_s(buf, readLen, 0, readLen);
        if ((BSL_UIO_Gets(rUio, buf, &readLen) != BSL_SUCCESS) || (readLen == 0)) {
            break;
        }
        if (CopyBufToData(buf, readLen, &data, &dataSize, &dataCapacity) != HITLS_APP_SUCCESS) {
            BSL_SAL_FREE(data);
            break;
        }

        if (*name == NULL) {
            *name = GetPemKeyFileName(buf, readLen);
        } else if ((strncmp(buf, PEM_END_STR, PEM_END_STR_LEN) == 0)) {
            break;
        } else if (!isParseHeader) {
            *isEncrypted = IsNeedEncryped(*name, buf, readLen);
            isParseHeader = true;
        }
    }
    BSL_UIO_Free(rUio);
    if (dataSize == 0 || *name == NULL || data[dataCapacity - 1] != '\0') {
        BSL_SAL_FREE(data);
        BSL_SAL_FREE(*name);
        return HITLS_APP_STDIN_FAIL;
    }
    *inData = data;
    *inDataSize = dataSize;
    return HITLS_APP_SUCCESS;
}

static int32_t GetPasswdByFile(const char *passwdArg, size_t passwdArgLen, char **pass)
{
    if (passwdArgLen <= APP_PASS_FILE_STR_LEN) {
        AppPrintError("Failed to read passwd from file.\n");
        return HITLS_APP_INVALID_ARG;
    }
    // Apply for a new memory and copy the unprocessed character string.
    char filePath[PATH_MAX] = {0};
    if (strcpy_s(filePath, PATH_MAX - 1, passwdArg + APP_PASS_FILE_STR_LEN) != EOK) {
        AppPrintError("Failed to read passwd from file.\n");
        return HITLS_APP_SECUREC_FAIL;
    }
    // Binding the password file UIO.
    BSL_UIO *passUio = BSL_UIO_New(BSL_UIO_FileMethod());
    if (passUio == NULL) {
        AppPrintError("Failed to read passwd from file.\n");
        return HITLS_APP_UIO_FAIL;
    }
    BSL_UIO_SetIsUnderlyingClosedByUio(passUio, true);
    if (BSL_UIO_Ctrl(passUio, BSL_UIO_FILE_OPEN, BSL_UIO_FILE_READ, filePath) != BSL_SUCCESS) {
        AppPrintError("Failed to set infile mode for passwd.\n");
        BSL_UIO_Free(passUio);
        return HITLS_APP_UIO_FAIL;
    }
    char *passBuf = (char *)BSL_SAL_Calloc(APP_MAX_PASS_LENGTH + 1 + 1, sizeof(char));
    if (passBuf == NULL) {
        BSL_UIO_Free(passUio);
        AppPrintError("Failed to read passwd from file.\n");
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    // When the number of bytes exceeds 1024 bytes, only one more bit is read.
    uint32_t passLen = APP_MAX_PASS_LENGTH + 1 + 1;
    if (BSL_UIO_Gets(passUio, passBuf, &passLen) != BSL_SUCCESS) {
        AppPrintError("Failed to read passwd from file.\n");
        BSL_UIO_Free(passUio);
        BSL_SAL_FREE(passBuf);
        return HITLS_APP_UIO_FAIL;
    }
    BSL_UIO_Free(passUio);

    if (passLen <= 0) {
        passBuf[0] = '\0';
    } else if (passBuf[passLen - 1] == '\n') {
        passBuf[passLen - 1] = '\0';
    }
    *pass = passBuf;
    return HITLS_APP_SUCCESS;
}

static char *GetPasswdByStdin(BSL_UI_ReadPwdParam *param)
{
    char *pass = (char *)BSL_SAL_Calloc(APP_MAX_PASS_LENGTH + 1, sizeof(char));
    if (pass == NULL) {
        return NULL;
    }
    uint32_t passLen = APP_MAX_PASS_LENGTH + 1;
    int32_t ret = BSL_UI_ReadPwdUtil(param, pass, &passLen, NULL, NULL);
    if (ret != BSL_SUCCESS) {
        pass[0] = '\0';
        return pass;
    }
    pass[passLen - 1] = '\0';
    return pass;
}

static char *GetStrAfterPreFix(const char *inputArg, uint32_t inputArgLen, uint32_t prefixLen)
{
    if (prefixLen > inputArgLen) {
        return NULL;
    }
    uint32_t len = inputArgLen - prefixLen;
    char *str = (char *)BSL_SAL_Calloc(len + 1, sizeof(char));
    if (str == NULL) {
        return NULL;
    }
    memcpy_s(str, len, inputArg + prefixLen, len);
    str[len] = '\0';
    return str;
}

int32_t HITLS_APP_ParsePasswd(const char *passArg, char **pass)
{
    if (passArg == NULL) {
        return HITLS_APP_SUCCESS;
    }
    if (strncmp(passArg, APP_PASS_ARG_STR, APP_PASS_ARG_STR_LEN) == 0) {
        *pass = GetStrAfterPreFix(passArg, strlen(passArg), APP_PASS_ARG_STR_LEN);
    } else if (strncmp(passArg, APP_PASS_STDIN_STR, APP_PASS_STDIN_STR_LEN) == 0) {
        BSL_UI_ReadPwdParam passParam = { "passwd", NULL, false };
        *pass = GetPasswdByStdin(&passParam);
    } else if (strncmp(passArg, APP_PASS_FILE_STR, APP_PASS_FILE_STR_LEN) == 0) {
        return GetPasswdByFile(passArg, strlen(passArg), pass);
    } else {
        AppPrintError("The %s password parameter is not supported.\n", passArg);
        return HITLS_APP_PASSWD_FAIL;
    }

    return HITLS_APP_SUCCESS;
}

static CRYPT_EAL_PkeyCtx *ReadPemPrvKey(BSL_Buffer *encode, const char *name, uint8_t *pass, uint32_t passLen)
{
    int32_t type = CRYPT_ENCDEC_UNKNOW;

    if (strcmp(name, PEM_RSA_PRIVATEKEY_STR) == 0) {
        type = CRYPT_PRIKEY_RSA;
    } else if (strcmp(name, PEM_EC_PRIVATEKEY_STR) == 0) {
        type = CRYPT_PRIKEY_ECC;
    } else if (strcmp(name, PEM_PKCS8_PRIVATEKEY_STR) == 0) {
        type = CRYPT_PRIKEY_PKCS8_UNENCRYPT;
    } else if (strcmp(name, PEM_ENCRYPTED_PKCS8_PRIVATEKEY_STR) == 0) {
        type = CRYPT_PRIKEY_PKCS8_ENCRYPT;
    }

    CRYPT_EAL_PkeyCtx *pkey = NULL;
    if (CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_PEM, type, encode, pass, passLen, &pkey) != CRYPT_SUCCESS) {
        return NULL;
    }
    return pkey;
}

static CRYPT_EAL_PkeyCtx *ReadPemPubKey(BSL_Buffer *encode, const char *name)
{
    int32_t type = CRYPT_ENCDEC_UNKNOW;

    if (strcmp(name, PEM_RSA_PUBLIC_STR)) {
        type = CRYPT_PUBKEY_RSA;
    } else if (strcmp(name, PEM_PKCS8_PUBLIC_STR)) {
        type = CRYPT_PUBKEY_SUBKEY;
    }

    CRYPT_EAL_PkeyCtx *pkey = NULL;
    if (CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_PEM, type, encode, NULL, 0, &pkey) != CRYPT_SUCCESS) {
        return NULL;
    }
    return pkey;
}

int32_t HITLS_APP_GetPasswd(BSL_UI_ReadPwdParam *param, char **passin, uint8_t **pass, uint32_t *passLen)
{
    if (*passin == NULL) {
        *passin = GetPasswdByStdin(param);
    }
    if ((*passin == NULL) || (strlen(*passin) > APP_MAX_PASS_LENGTH) || (strlen(*passin) < APP_MIN_PASS_LENGTH)) {
        HITLS_APP_PrintPassErrlog();
        return HITLS_APP_PASSWD_FAIL;
    }
    *pass = (uint8_t *)*passin;
    *passLen = strlen(*passin);
    return HITLS_APP_SUCCESS;
}

static bool CheckFilePath(const char *filePath)
{
    if (filePath == NULL) {
        return true;
    }
    if (strlen(filePath) > PATH_MAX) {
        AppPrintError("The maximum length of the file path is %d.\n", PATH_MAX);
        return false;
    }
    return true;
}

static CRYPT_EAL_PkeyCtx *LoadPrvDerKey(const char *inFilePath)
{
    static CRYPT_ENCDEC_TYPE encodeType[] = {CRYPT_PRIKEY_ECC, CRYPT_PRIKEY_RSA, CRYPT_PRIKEY_PKCS8_UNENCRYPT};

    CRYPT_EAL_PkeyCtx *pkey = NULL;
    for (uint32_t i = 0; i < sizeof(encodeType) / sizeof(CRYPT_ENCDEC_TYPE); ++i) {
        if (CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, encodeType[i], inFilePath, NULL, 0, &pkey) == CRYPT_SUCCESS) {
            break;
        }
    }

    if (pkey == NULL) {
        AppPrintError("Failed to read the private key from \"%s\".\n", inFilePath);
        return NULL;
    }

    return pkey;
}

CRYPT_EAL_PkeyCtx *HITLS_APP_LoadPrvKey(const char *inFilePath, BSL_ParseFormat informat, char **passin)
{
    if (inFilePath == NULL && informat == BSL_FORMAT_ASN1) {
        AppPrintError("The \"-inform DER or -keyform DER\" requires using the \"-in\" option.\n");
        return NULL;
    }
    if (!CheckFilePath(inFilePath)) {
        return NULL;
    }
    if (informat == BSL_FORMAT_ASN1) {
        return LoadPrvDerKey(inFilePath);
    }
    char *prvkeyName = NULL;
    bool isEncrypted = false;
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    if (ReadPemKeyFile(inFilePath, &data, &dataLen, &prvkeyName, &isEncrypted) != HITLS_APP_SUCCESS) {
        PrintFileOrStdinError(inFilePath, "Failed to read the private key");
        return NULL;
    }

    uint8_t *pass = NULL;
    uint32_t passLen = 0;
    BSL_UI_ReadPwdParam passParam = { "passwd", inFilePath, false };
    if (isEncrypted && (HITLS_APP_GetPasswd(&passParam, passin, &pass, &passLen) != HITLS_APP_SUCCESS)) {
        BSL_SAL_FREE(data);
        BSL_SAL_FREE(prvkeyName);
        return NULL;
    }
    BSL_Buffer encode = { data, dataLen };
    CRYPT_EAL_PkeyCtx *pkey = ReadPemPrvKey(&encode, prvkeyName, pass, passLen);
    if (pkey == NULL) {
        PrintFileOrStdinError(inFilePath, "Failed to read the private key");
    }
    BSL_SAL_FREE(data);
    BSL_SAL_FREE(prvkeyName);
    return pkey;
}

CRYPT_EAL_PkeyCtx *HITLS_APP_LoadPubKey(const char *inFilePath, BSL_ParseFormat informat)
{
    if (informat != BSL_FORMAT_PEM) {
        return NULL;
    }
    char *pubKeyName = NULL;
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    bool isEncrypted = false;
    if (!CheckFilePath(inFilePath) ||
        (ReadPemKeyFile(inFilePath, &data, &dataLen, &pubKeyName, &isEncrypted) != HITLS_APP_SUCCESS)) {
        PrintFileOrStdinError(inFilePath, "Failed to read the public key");
        return NULL;
    }
    BSL_Buffer encode = { data, dataLen };
    CRYPT_EAL_PkeyCtx *pkey = ReadPemPubKey(&encode, pubKeyName);
    if (pkey == NULL) {
        PrintFileOrStdinError(inFilePath, "Failed to read the public key");
    }
    BSL_SAL_FREE(data);
    BSL_SAL_FREE(pubKeyName);
    return pkey;
}

int32_t HITLS_APP_PrintPubKey(CRYPT_EAL_PkeyCtx *pkey, const char *outFilePath, BSL_ParseFormat outformat)
{
    if (!CheckFilePath(outFilePath)) {
        return HITLS_APP_INVALID_ARG;
    }

    BSL_Buffer pubKeyBuf = { 0 };
    if (CRYPT_EAL_EncodeBuffKey(pkey, NULL, outformat, CRYPT_PUBKEY_SUBKEY, &pubKeyBuf) != CRYPT_SUCCESS) {
        AppPrintError("Failed to export the public key.\n");
        return HITLS_APP_ENCODE_KEY_FAIL;
    }
    BSL_UIO *wPubKeyUio = HITLS_APP_UioOpen(outFilePath, 'w', 0);
    if (wPubKeyUio == NULL) {
        BSL_SAL_FREE(pubKeyBuf.data);
        return HITLS_APP_UIO_FAIL;
    }
    int32_t ret = HITLS_APP_OptWriteUio(wPubKeyUio, pubKeyBuf.data, pubKeyBuf.dataLen, HITLS_APP_FORMAT_PEM);
    BSL_SAL_FREE(pubKeyBuf.data);
    BSL_UIO_SetIsUnderlyingClosedByUio(wPubKeyUio, true);
    BSL_UIO_Free(wPubKeyUio);
    return ret;
}

int32_t HITLS_APP_PrintPrvKey(CRYPT_EAL_PkeyCtx *pkey, const char *outFilePath, BSL_ParseFormat outformat,
    int32_t cipherAlgCid, char **passout)
{
    if (!CheckFilePath(outFilePath)) {
        return HITLS_APP_INVALID_ARG;
    }

    BSL_UIO *wPrvUio = HITLS_APP_UioOpen(outFilePath, 'w', 0);
    if (wPrvUio == NULL) {
        return HITLS_APP_UIO_FAIL;
    }
    AppKeyPrintParam param = { outFilePath, outformat, cipherAlgCid, false, false};
    int32_t ret = HITLS_APP_PrintPrvKeyByUio(wPrvUio, pkey, &param, passout);
    BSL_UIO_SetIsUnderlyingClosedByUio(wPrvUio, true);
    BSL_UIO_Free(wPrvUio);
    return ret;
}

int32_t HITLS_APP_PrintPrvKeyByUio(BSL_UIO *uio, CRYPT_EAL_PkeyCtx *pkey, AppKeyPrintParam *printKeyParam,
    char **passout)
{
    int32_t ret = printKeyParam->text ? CRYPT_EAL_PrintPrikey(0, pkey, uio) : HITLS_APP_SUCCESS;
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("Failed to print the private key text, errCode = 0x%x.\n", ret);
        return HITLS_APP_CRYPTO_FAIL;
    }
    if (printKeyParam->noout) {
        return HITLS_APP_SUCCESS;
    }
    int32_t type =
        printKeyParam->cipherAlgCid != CRYPT_CIPHER_MAX ? CRYPT_PRIKEY_PKCS8_ENCRYPT : CRYPT_PRIKEY_PKCS8_UNENCRYPT;
    uint8_t *pass = NULL;
    uint32_t passLen = 0;
    BSL_UI_ReadPwdParam passParam = { "passwd", printKeyParam->name, true };
    if ((type == CRYPT_PRIKEY_PKCS8_ENCRYPT) &&
        (HITLS_APP_GetPasswd(&passParam, passout, &pass, &passLen) != HITLS_APP_SUCCESS)) {
        return HITLS_APP_PASSWD_FAIL;
    }
    CRYPT_Pbkdf2Param param = { 0 };
    param.pbesId = BSL_CID_PBES2;
    param.pbkdfId = BSL_CID_PBKDF2;
    param.hmacId = CRYPT_MAC_HMAC_SHA256;
    param.symId = printKeyParam->cipherAlgCid;
    param.pwd = pass;
    param.saltLen = DEFAULT_SALTLEN;
    param.pwdLen = passLen;
    param.itCnt = DEFAULT_ITCNT;
    CRYPT_EncodeParam paramEx = { CRYPT_DERIVE_PBKDF2, &param };
    BSL_Buffer prvKeyBuf = { 0 };
    if (CRYPT_EAL_EncodeBuffKey(pkey, &paramEx, printKeyParam->outformat, type, &prvKeyBuf) != CRYPT_SUCCESS) {
        AppPrintError("Failed to export the private key.\n");
        return HITLS_APP_ENCODE_KEY_FAIL;
    }
    ret = HITLS_APP_OptWriteUio(uio, prvKeyBuf.data, prvKeyBuf.dataLen, HITLS_APP_FORMAT_PEM);
    BSL_SAL_FREE(prvKeyBuf.data);
    return ret;
}

int32_t HITLS_APP_GetAndCheckCipherOpt(const char *name, int32_t *symId)
{
    if (symId == NULL) {
        return HITLS_APP_INVALID_ARG;
    }
    uint32_t cid = (uint32_t)HITLS_APP_GetCidByName(name, HITLS_APP_LIST_OPT_CIPHER_ALG);
    if (cid == CRYPT_CIPHER_MAX) {
        (void)AppPrintError("%s: Use the [list -cipher-algorithms] command to view supported encryption algorithms.\n",
            HITLS_APP_GetProgName());
        return HITLS_APP_OPT_UNKOWN;
    }
    if (!CRYPT_EAL_CipherIsValidAlgId(cid)) {
        AppPrintError("%s: %s ciphers not supported.\n", HITLS_APP_GetProgName(), name);
        return HITLS_APP_OPT_UNKOWN;
    }
    uint32_t isAeadId = 1;

    if (CRYPT_EAL_CipherGetInfo((CRYPT_CIPHER_AlgId)cid, CRYPT_INFO_IS_AEAD, &isAeadId) != CRYPT_SUCCESS) {
        AppPrintError("%s: The encryption algorithm is not supported\n", HITLS_APP_GetProgName());
        return HITLS_APP_INVALID_ARG;
    }

    if (isAeadId == 1) {
        AppPrintError("%s: The AEAD encryption algorithm is not supported\n", HITLS_APP_GetProgName());
        return HITLS_APP_INVALID_ARG;
    }
    *symId = cid;
    return HITLS_APP_SUCCESS;
}

static int32_t ReadPemByUioSymbol(BSL_UIO *memUio, BSL_UIO *rUio, BSL_PEM_Symbol *symbol)
{
    int32_t ret = HITLS_APP_UIO_FAIL;
    char buf[APP_LINESIZE + 1];
    uint32_t lineLen;
    bool hasHead = false;
    uint32_t writeMemLen;
    int64_t dataLen = 0;

    while (true) {
        lineLen = APP_LINESIZE + 1;
        (void)memset_s(buf, lineLen, 0, lineLen);

        // Reads a row of data.
        if ((BSL_UIO_Gets(rUio, buf, &lineLen) != BSL_SUCCESS) || (lineLen == 0)) {
            break;
        }
        ret = BSL_UIO_Ctrl(rUio, BSL_UIO_GET_READ_NUM, sizeof(int64_t), &dataLen);
        if (ret != BSL_SUCCESS || dataLen > APP_FILE_MAX_SIZE) {
            AppPrintError("The maximum file size is %zukb.\n", APP_FILE_MAX_SIZE_KB);
            ret = HITLS_APP_UIO_FAIL;
            break;
        }
        if (!hasHead) {
            // Check whether it is the head.
            if (strncmp(buf, symbol->head, strlen(symbol->head)) != 0) {
                continue;
            }
            if (BSL_UIO_Puts(memUio, (const char *)buf, &writeMemLen) != BSL_SUCCESS || writeMemLen != lineLen) {
                break;
            }
            hasHead = true;
            continue;
        }
        // Copy the intermediate content.
        if (BSL_UIO_Puts(memUio, (const char *)buf, &writeMemLen) != BSL_SUCCESS || writeMemLen != lineLen) {
            break;
        }
        // Check whether it is the tail.
        if (strncmp(buf, symbol->tail, strlen(symbol->tail)) == 0) {
            ret = HITLS_APP_SUCCESS;
            break;
        }
    }
    return ret;
}

static int32_t ReadPemFromStdin(BSL_BufMem **data, BSL_PEM_Symbol *symbol)
{
    int32_t ret = HITLS_APP_UIO_FAIL;
    BSL_UIO *memUio = BSL_UIO_New(BSL_UIO_MemMethod());
    if (memUio == NULL) {
        return ret;
    }

    // Read from stdin or file.
    BSL_UIO *rUio = HITLS_APP_UioOpen(NULL, 'r', 1);
    if (rUio == NULL) {
        BSL_UIO_Free(memUio);
        return ret;
    }
    BSL_UIO_SetIsUnderlyingClosedByUio(rUio, true);

    ret = ReadPemByUioSymbol(memUio, rUio, symbol);
    BSL_UIO_Free(rUio);
    if (ret == HITLS_APP_SUCCESS) {
        if (BSL_UIO_Ctrl(memUio, BSL_UIO_MEM_GET_PTR, sizeof(BSL_BufMem *), data) == BSL_SUCCESS) {
            BSL_UIO_SetIsUnderlyingClosedByUio(memUio, false);
            BSL_SAL_Free(BSL_UIO_GetCtx(memUio));
            BSL_UIO_SetCtx(memUio, NULL);
        } else {
            ret = HITLS_APP_UIO_FAIL;
        }
    }
    BSL_UIO_Free(memUio);
    return ret;
}

static int32_t ReadFileData(const char *path, BSL_Buffer *data)
{
    size_t fileLen = 0;
    int32_t ret = BSL_SAL_FileLength(path, &fileLen);
    if (ret != BSL_SUCCESS) {
        AppPrintError("Failed to get file size: %s.\n", path);
        return ret;
    }
    if (fileLen > APP_FILE_MAX_SIZE) {
        AppPrintError("File size exceed limit %zukb: %s.\n", APP_FILE_MAX_SIZE_KB, path);
        return HITLS_APP_UIO_FAIL;
    }
    ret = BSL_SAL_ReadFile(path, &data->data, &data->dataLen);
    if (ret != BSL_SUCCESS) {
        AppPrintError("Read file failed: %s.\n", path);
    }
    return ret;
}

static int32_t ReadData(const char *path, BSL_PEM_Symbol *symbol, char *fileName, BSL_Buffer *data)
{
    if (path == NULL) {
        BSL_BufMem *buf = NULL;
        if (ReadPemFromStdin(&buf, symbol) != HITLS_APP_SUCCESS) {
            AppPrintError("Failed to read %s from stdin.\n", fileName);
            return HITLS_APP_UIO_FAIL;
        }
        data->data = (uint8_t *)buf->data;
        data->dataLen = buf->length;
        BSL_SAL_Free(buf);
        return HITLS_APP_SUCCESS;
    } else {
        return ReadFileData(path, data);
    }
}

HITLS_X509_Cert *HITLS_APP_LoadCert(const char *inPath, BSL_ParseFormat inform)
{
    if (inPath == NULL && inform == BSL_FORMAT_ASN1) {
        AppPrintError("Reading DER files from stdin is not supported.\n");
        return NULL;
    }
    if (!CheckFilePath(inPath)) {
        AppPrintError("Invalid cert path: \"%s\".", inPath == NULL ? "" : inPath);
        return NULL;
    }
    BSL_Buffer data = { 0 };
    BSL_PEM_Symbol symbol = { BSL_PEM_CERT_BEGIN_STR, BSL_PEM_CERT_END_STR };
    int32_t ret = ReadData(inPath, &symbol, "cert", &data);
    if (ret != HITLS_APP_SUCCESS) {
        return NULL;
    }

    HITLS_X509_Cert *cert = NULL;
    if (HITLS_X509_CertParseBuff(inform, &data, &cert) != 0) {
        AppPrintError("Failed to parse cert: \"%s\".\n", inPath == NULL ? "stdin" : inPath);
        BSL_SAL_Free(data.data);
        return NULL;
    }
    BSL_SAL_Free(data.data);
    return cert;
}

HITLS_X509_Csr *HITLS_APP_LoadCsr(const char *inPath, BSL_ParseFormat inform)
{
    if (inPath == NULL && inform == BSL_FORMAT_ASN1) {
        AppPrintError("Reading DER files from stdin is not supported.\n");
        return NULL;
    }
    if (!CheckFilePath(inPath)) {
        AppPrintError("Invalid csr path: \"%s\".", inPath == NULL ? "" : inPath);
        return NULL;
    }

    BSL_Buffer data = { 0 };
    BSL_PEM_Symbol symbol = { BSL_PEM_CERT_REQ_BEGIN_STR, BSL_PEM_CERT_REQ_END_STR };
    int32_t ret = ReadData(inPath, &symbol, "csr", &data);
    if (ret != HITLS_APP_SUCCESS) {
        return NULL;
    }

    HITLS_X509_Csr *csr = NULL;
    if (HITLS_X509_CsrParseBuff(inform, &data, &csr) != 0) {
        AppPrintError("Failed to parse csr: \"%s\".\n", inPath == NULL ? "stdin" : inPath);
        BSL_SAL_Free(data.data);
        return NULL;
    }
    BSL_SAL_Free(data.data);
    return csr;
}

int32_t HITLS_APP_GetAndCheckHashOpt(const char *name, int32_t *hashId)
{
    if (hashId == NULL) {
        return HITLS_APP_INVALID_ARG;
    }
    uint32_t cid = (uint32_t)HITLS_APP_GetCidByName(name, HITLS_APP_LIST_OPT_DGST_ALG);
    if (cid == BSL_CID_UNKNOWN) {
        (void)AppPrintError("%s: Use the [list -digest-algorithms] command to view supported digest algorithms.\n",
            HITLS_APP_GetProgName());
        return HITLS_APP_OPT_UNKOWN;
    }
    if (!CRYPT_EAL_MdIsValidAlgId(cid)) {
        AppPrintError("%s: %s digest not supported.\n", HITLS_APP_GetProgName(), name);
        return HITLS_APP_OPT_UNKOWN;
    }
    *hashId = cid;
    return HITLS_APP_SUCCESS;
}

int32_t HITLS_APP_PrintText(const BSL_Buffer *csrBuf, const char *outFileName)
{
    BSL_UIO *wCsrUio = HITLS_APP_UioOpen(outFileName, 'w', 0);
    if (wCsrUio == NULL) {
        return HITLS_APP_UIO_FAIL;
    }
    int32_t ret = HITLS_APP_OptWriteUio(wCsrUio, csrBuf->data, csrBuf->dataLen, HITLS_APP_FORMAT_TEXT);
    BSL_UIO_SetIsUnderlyingClosedByUio(wCsrUio, true);
    BSL_UIO_Free(wCsrUio);
    return ret;
}

CRYPT_EAL_PkeyCtx *HITLS_APP_GenRsaPkeyCtx(uint32_t bits)
{
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_RSA,
        CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default");
    if (pkey == NULL) {
        AppPrintError("%s: Failed to initialize the RSA private key.\n", HITLS_APP_GetProgName());
        return NULL;
    }
    CRYPT_EAL_PkeyPara *para = BSL_SAL_Calloc(sizeof(CRYPT_EAL_PkeyPara), 1);
    if (para == NULL) {
        CRYPT_EAL_PkeyFreeCtx(pkey);
        return NULL;
    }
    static uint8_t e[] = {0x01, 0x00, 0x01}; // Default E value
    para->id = CRYPT_PKEY_RSA;
    para->para.rsaPara.bits = bits;
    para->para.rsaPara.e = e;
    para->para.rsaPara.eLen = sizeof(e);
    if (CRYPT_EAL_PkeySetPara(pkey, para) != CRYPT_SUCCESS) {
        AppPrintError("%s: Failed to set RSA parameters.\n", HITLS_APP_GetProgName());
        BSL_SAL_FREE(para);
        CRYPT_EAL_PkeyFreeCtx(pkey);
        return NULL;
    }
    BSL_SAL_FREE(para);
    if (CRYPT_EAL_PkeyGen(pkey) != CRYPT_SUCCESS) {
        AppPrintError("%s: Failed to generate the RSA private key.\n", HITLS_APP_GetProgName());
        CRYPT_EAL_PkeyFreeCtx(pkey);
        return NULL;
    }

    int32_t padType = CRYPT_EMSA_PKCSV15;
    if (CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_PADDING, &padType, sizeof(padType)) != CRYPT_SUCCESS) {
        AppPrintError("%s: Failed to set rsa padding.\n", HITLS_APP_GetProgName());
        CRYPT_EAL_PkeyFreeCtx(pkey);
        return NULL;
    }
    return pkey;
}

void HITLS_APP_PrintPassErrlog(void)
{
    AppPrintError("The password length is incorrect. It should be in the range of %d to %d.\n", APP_MIN_PASS_LENGTH,
        APP_MAX_PASS_LENGTH);
}