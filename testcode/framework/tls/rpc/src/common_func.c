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

#include <stdlib.h>
#include <stdatomic.h>
#include "securec.h"
#include "hitls_crypt_type.h"
#include "hitls_session.h"
#include "logger.h"
#include "bsl_sal.h"
#include "hitls_error.h"
#include "hitls_sni.h"
#include "sni.h"
#include "hitls_alpn.h"
#include "hitls_type.h"
#include "common_func.h"

#define SUCCESS 0
#define ERROR (-1)
#define MAX_CERT_PATH_LENGTH (128)
#define SINGLE_CERT_LEN (120)

#define KEY_NAME_SIZE 16
#define IV_SIZE 16
#define KEY_SIZE 32
#define RENEGOTIATE_FAIL 1

static uint8_t g_keyName[KEY_NAME_SIZE] = {
    0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A
};

static uint8_t g_key[KEY_SIZE] = {
    0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A,
    0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A
};

static uint8_t g_iv[IV_SIZE] = {
    0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A
};

typedef struct {
    char *name;
    void *cb;
} ExampleCb;

typedef struct {
    char *name;
    void *(*data)(void);
} ExampleData;

#define ASSERT_RETURN(condition, log) \
    do {                              \
        if (!(condition)) {           \
            LOG_ERROR(log);           \
            return ERROR;             \
        }                             \
    } while (0)

static char g_localIdentity[PSK_MAX_LEN] = "Client_identity";
static char g_localPsk[PSK_MAX_LEN] = "1A1A1A1A1A";

int32_t ExampleSetPsk(char *psk)
{
    if (psk == NULL) {
        LOG_DEBUG("input error.");
        return -1;
    }
    (void)memset_s(g_localPsk, PSK_MAX_LEN, 0, PSK_MAX_LEN);
    if (strcpy_s(g_localPsk, PSK_MAX_LEN, psk) != EOK) {
        LOG_DEBUG("ExampleSetPsk failed.");
        return -1;
    }
    return 0;
}

int32_t ExampleHexStr2BufHelper(const uint8_t *input, uint32_t inLen, uint8_t *out, uint32_t outLen, uint32_t *usedLen)
{
    (void)inLen;
    (void)outLen;
    char indexH[2] = {0};
    char indexL[2] = {0};
    const uint8_t *curr = NULL;
    uint8_t *outIndex = NULL;
    int32_t high, low;

    if ((input == NULL) || (out == NULL) || (usedLen == NULL)) {
        return -1;
    }

    for (curr = input, outIndex = out; *curr;) {
        indexH[0] = *curr++;
        indexL[0] = *curr++;
        if (indexL[0] == '\0') {
            return -1;
        }

        high = (int32_t)strtol(indexH, NULL, 16); // Converting char to Hexadecimal numbers
        low = (int32_t)strtol(indexL, NULL, 16);  // Converting char to Hexadecimal numbers

        if (high < 0 || low < 0) {
            return -1;
        }
        *outIndex++ = (uint8_t)((high << 4) | low); // The upper four bits of the  are shifted to the left
    }

    *usedLen = outIndex - out;

    return 0;
}

uint32_t ExampleClientCb(HITLS_Ctx *ctx, const uint8_t *hint, uint8_t *identity, uint32_t maxIdentityLen, uint8_t *psk,
    uint32_t maxPskLen)
{
    (void)ctx;
    (void)hint;
    int32_t ret;
    uint8_t pskTrans[PSK_MAX_LEN] = {0};
    uint32_t pskTransUsedLen = 0u;

    ret = ExampleHexStr2BufHelper((uint8_t *)g_localPsk, sizeof(g_localPsk), pskTrans, PSK_MAX_LEN, &pskTransUsedLen);
    if (ret != 0) {
        return 0;
    }

    /* strlen(g_localIdentity) + 1 copy terminator */
    if (memcpy_s(identity, maxIdentityLen, g_localIdentity, strlen(g_localIdentity) + 1) != EOK) {
        return 0;
    }
    if (memcpy_s(psk, maxPskLen, pskTrans, pskTransUsedLen) != EOK) {
        return 0;
    }
    return pskTransUsedLen;
}

uint32_t ExampleServerCb(HITLS_Ctx *ctx, const uint8_t *identity, uint8_t *psk, uint32_t maxPskLen)
{
    (void)ctx;

    if (identity == NULL || strcmp((const char *)identity, g_localIdentity) != 0) {
        return 0;
    }

    int32_t ret;
    uint8_t pskTrans[PSK_MAX_LEN] = {0};
    uint32_t pskTransUsedLen = 0u;

    ret = ExampleHexStr2BufHelper((uint8_t *)g_localPsk, sizeof(g_localPsk), pskTrans, PSK_MAX_LEN, &pskTransUsedLen);
    if (ret != 0) {
        return 0;
    }

    if (memcpy_s(psk, maxPskLen, pskTrans, pskTransUsedLen) != EOK) {
        return 0;
    }

    return pskTransUsedLen;
}

static void SetCipherInfo(void *cipher)
{
    HITLS_CipherParameters *cipherPara = cipher;
    cipherPara->type = HITLS_CBC_CIPHER;
    cipherPara->algo = HITLS_CIPHER_AES_256_CBC;
    cipherPara->key = g_key;
    cipherPara->keyLen = sizeof(g_key);
    cipherPara->hmacKey = g_key;
    cipherPara->hmacKeyLen = sizeof(g_key);
    cipherPara->iv = g_iv;
    cipherPara->ivLen = sizeof(g_iv);
    return;
}

int32_t ExampleTicketKeySuccessCb(uint8_t *keyName, uint32_t keyNameSize, void *cipher, uint8_t isEncrypt)
{
    if (isEncrypt) {
        if (memcpy_s(keyName, keyNameSize, g_keyName, KEY_NAME_SIZE) != EOK) {
            return HITLS_TICKET_KEY_RET_FAIL;
        }
        SetCipherInfo(cipher);
        return HITLS_TICKET_KEY_RET_SUCCESS;
    }

    if (memcmp(keyName, g_keyName, KEY_NAME_SIZE) != 0) {
        return HITLS_TICKET_KEY_RET_FAIL;
    }
    SetCipherInfo(cipher);
    return HITLS_TICKET_KEY_RET_SUCCESS;
}

int32_t ExampleTicketKeyRenewCb(uint8_t *keyName, uint32_t keyNameSize, void *cipher, uint8_t isEncrypt)
{
    if (isEncrypt) {
        if (memcpy_s(keyName, keyNameSize, g_keyName, KEY_NAME_SIZE) != EOK) {
            return HITLS_TICKET_KEY_RET_FAIL;
        }
        SetCipherInfo(cipher);
        return HITLS_TICKET_KEY_RET_SUCCESS_RENEW;
    }

    if (memcmp(keyName, g_keyName, KEY_NAME_SIZE) != 0) {
        return HITLS_TICKET_KEY_RET_FAIL;
    }
    SetCipherInfo(cipher);
    return HITLS_TICKET_KEY_RET_SUCCESS_RENEW;
}

int32_t ExampleTicketKeyAlertCb(uint8_t *keyName, uint32_t keyNameSize, HITLS_CipherParameters *cipher,
    uint8_t isEncrypt)
{
    if (isEncrypt) {
        (void)memcpy_s(keyName, keyNameSize, g_keyName, KEY_NAME_SIZE);
        SetCipherInfo(cipher);
        return HITLS_TICKET_KEY_RET_SUCCESS_RENEW;
    } else {
        return HITLS_TICKET_KEY_RET_NEED_ALERT;
    }
}

int32_t ExampleTicketKeyFailCb(uint8_t *keyName, uint32_t keyNameSize, HITLS_CipherParameters *cipher,
    uint8_t isEncrypt)
{
    if (isEncrypt) {
        (void)memcpy_s(keyName, keyNameSize, g_keyName, KEY_NAME_SIZE);
        SetCipherInfo(cipher);
        return HITLS_TICKET_KEY_RET_SUCCESS_RENEW;
    }

    SetCipherInfo(cipher);
    return HITLS_TICKET_KEY_RET_FAIL;
}

int32_t ExampleServerNameCb(HITLS_Ctx *ctx, int *alert, void *arg)
{
    (void)ctx;
    (void)arg;
    *alert = HITLS_ACCEPT_SNI_ERR_OK;
    return HITLS_ACCEPT_SNI_ERR_OK;
}

int32_t ExampleServerNameCbNOACK(HITLS_Ctx *ctx, int *alert, void *arg)
{
    (void)ctx;
    (void)alert;
    (void)arg;
    return HITLS_ACCEPT_SNI_ERR_NOACK;
}

int32_t ExampleServerNameCbALERT(HITLS_Ctx *ctx, int *alert, void *arg)
{
    (void)ctx;
    (void)alert;
    (void)arg;
    return HITLS_ACCEPT_SNI_ERR_ALERT_FATAL;
}

SNI_Arg *g_sniArg;
void *ExampleServerNameArg(void)
{
    return g_sniArg;
}

static char *g_alpnhttp = "http";

int32_t ExampleAlpnParseProtocolList1(uint8_t *out, uint8_t *outLen, uint8_t *in, uint8_t inLen)
{
    if (out == NULL || outLen == NULL || in == NULL) {
        return HITLS_NULL_INPUT;
    }

    if (inLen == 0) {
        return HITLS_CONFIG_INVALID_LENGTH;
    }

    uint8_t i = 0u;
    uint8_t commaNum = 0u;
    uint8_t startPos = 0u;

    for (i = 0u; i <= inLen; ++i) {
        if (i == inLen || in[i] == ',') {
            if (i == startPos) {
                ++startPos;
                ++commaNum;
                continue;
            }
            out[startPos - commaNum] = (uint8_t)(i - startPos);
            startPos = i + 1;
        } else {
            out[i + 1 - commaNum] = in[i];
        }
    }

    *outLen = inLen + 1 - commaNum;

    return HITLS_SUCCESS;
}

int32_t ExampleAlpnCb(HITLS_Ctx *ctx, char **selectedProto, uint8_t *selectedProtoSize, char *clientAlpnList,
    uint32_t clientAlpnListSize, void *userData)
{
    (void)ctx;
    (void)userData;
    if (clientAlpnListSize >= 5 && memcmp(clientAlpnList + 1, "http", 4) == 0) {
        *selectedProto = clientAlpnList + 1;
        *selectedProtoSize = 4;
        return HITLS_ALPN_ERR_OK;
    } else if (clientAlpnListSize >= 4 && memcmp(clientAlpnList + 1, "ftp", 3) == 0) {
        *selectedProto = g_alpnhttp;
        *selectedProtoSize = 4;
        return HITLS_ALPN_ERR_OK;
    } else if (clientAlpnListSize >= 4 && memcmp(clientAlpnList + 1, "mml", 3) == 0) {
        *selectedProto = g_alpnhttp;
        *selectedProtoSize = 4;
        return HITLS_ALPN_ERR_ALERT_FATAL;
    } else if (clientAlpnListSize >= 4 && memcmp(clientAlpnList + 1, "www", 3) == 0) {
        *selectedProto = g_alpnhttp;
        *selectedProtoSize = 4;
        return HITLS_ALPN_ERR_OK;
    } else {
        return HITLS_ALPN_ERR_NOACK;
    }
}

int32_t AlpnCbWARN1(HITLS_Ctx *ctx, uint8_t **selectedProto, uint8_t *selectedProtoSize, uint8_t *clientAlpnList,
    uint32_t clientAlpnListSize, void *userData)
{
    (void)ctx;
    (void)selectedProto;
    (void)selectedProtoSize;
    (void)clientAlpnList;
    (void)clientAlpnListSize;
    (void)userData;

    return HITLS_ALPN_ERR_ALERT_WARNING;
}

int32_t AlpnCbALERT1(HITLS_Ctx *ctx, uint8_t **selectedProto, uint8_t *selectedProtoSize, uint8_t *clientAlpnList,
    uint32_t clientAlpnListSize, void *userData)
{
    (void)ctx;
    (void)selectedProto;
    (void)selectedProtoSize;
    (void)clientAlpnList;
    (void)clientAlpnListSize;
    (void)userData;

    return HITLS_ALPN_ERR_ALERT_FATAL;
}

void *ExampleAlpnData(void)
{
    // Return the alpnData address.
    return "audata";
}

void *GetTicketKeyCb(char *str)
{
    const ExampleCb cbList[] = {
        {"ExampleTicketKeySuccessCb", ExampleTicketKeySuccessCb},
        {"ExampleTicketKeyRenewCb", ExampleTicketKeyRenewCb},
        {"ExampleTicketKeyAlertCb", ExampleTicketKeyAlertCb},
        {"ExampleTicketKeyFailCb", ExampleTicketKeyFailCb},
    };

    int len = sizeof(cbList) / sizeof(cbList[0]);
    for (int i = 0; i < len; i++) {
        if (strcmp(str, cbList[i].name) == 0) {
            return cbList[i].cb;
        }
    }
    return NULL;
}

static void ExampleKeyLogCb(HITLS_Ctx *ctx, const char *out)
{
    (void)ctx; // Unused parameter
    char *fileName = "FileKeyLog.txt";
    char *fileEndStr = "\n";
    FILE *fp = fopen(fileName, "a+");
    if (fp == NULL) {
        return;
    }
    fwrite(out, sizeof(char), strlen(out), fp);
    fwrite((char*)fileEndStr, sizeof(char), strlen(fileEndStr), fp);
    fclose(fp);
}

void *GetExtensionCb(const char *str)
{
    const ExampleCb cbList[] = {
        {"ExampleSNICb", ExampleServerNameCb},
        {"ExampleAlpnCb", ExampleAlpnCb},
        {"ExampleAlpnWarnCb", AlpnCbWARN1},
        {"ExampleAlpAlertCb", AlpnCbALERT1},
        {"ExampleSNICbnoack", ExampleServerNameCbNOACK},
        {"ExampleSNICbAlert", ExampleServerNameCbALERT},
        {"ExampleKeyLogCb", ExampleKeyLogCb},
    };

    int len = sizeof(cbList) / sizeof(cbList[0]);
    for (int i = 0; i < len; i++) {
        if (strcmp(str, cbList[i].name) == 0) {
            return cbList[i].cb;
        }
    }
    return NULL;
}

void *GetExampleData(const char *str)
{
    const ExampleData cbList[] = {
        {"ExampleSNIArg", ExampleServerNameArg},
        {"ExampleAlpnData", ExampleAlpnData},
    };

    int len = sizeof(cbList) / sizeof(cbList[0]);
    for (int i = 0; i < len; i++) {
        if (strcmp(str, cbList[i].name) == 0) {
            return cbList[i].data();
        }
    }
    return NULL;
}
